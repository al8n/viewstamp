use bytes::Bytes;

use crate::{ClientId, Epoch, OpNumber, RequestNumber, Status, View};

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

/// A view this replica formed or adopted (the payload of [`Event::ViewChanged`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewChanged {
  view: View,
  is_primary: bool,
}

impl ViewChanged {
  /// Creates a view-changed record.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, is_primary: bool) -> Self {
    Self { view, is_primary }
  }

  /// The view this replica is now operating in.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// Whether this replica is the primary of the new view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_primary(&self) -> bool {
    self.is_primary
  }
}

/// A windowed peer-repair solicitation for the contiguous committed hole band `[lo, hi]` (the
/// payload of [`Event::RepairStarted`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairStarted {
  lo: OpNumber,
  hi: OpNumber,
}

impl RepairStarted {
  /// Creates a repair-started record.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(lo: OpNumber, hi: OpNumber) -> Self {
    Self { lo, hi }
  }

  /// The lowest op of the solicited hole band.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn lo(&self) -> OpNumber {
    self.lo
  }

  /// The highest op of the solicited hole band.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn hi(&self) -> OpNumber {
    self.hi
  }
}

/// A committed reconfiguration whose epoch swap became DURABLE (the payload of
/// [`Event::MembershipChanged`]). Emitted by `install_membership` when the `SwapEpoch` durable root
/// lands — never eagerly at commit — so an observer learns of the new configuration only once the
/// node can durably prove it (the durable-epoch-before-participate fence). Minimal here (op + new
/// epoch + new config_id) plus THIS node's role under the new configuration (`self_is_voter` /
/// `self_is_learner`, both false for a removed node) — learned purely from the committed membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipChanged {
  op: OpNumber,
  epoch: Epoch,
  config_id: u128,
  self_is_voter: bool,
  self_is_learner: bool,
}

impl MembershipChanged {
  /// Creates a membership-changed record.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    op: OpNumber,
    epoch: Epoch,
    config_id: u128,
    self_is_voter: bool,
    self_is_learner: bool,
  ) -> Self {
    Self {
      op,
      epoch,
      config_id,
      self_is_voter,
      self_is_learner,
    }
  }

  /// The committed `Body::Reconfigure` op whose durable swap installed the new configuration.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The new configuration epoch (the predecessor's epoch + 1).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The new configuration's lineage hash (`config_id`), chained from the predecessor.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// Whether THIS node is a voter in the new configuration (false if it was removed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn self_is_voter(&self) -> bool {
    self.self_is_voter
  }

  /// Whether THIS node is a (non-voting) learner in the new configuration (false if it was removed).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn self_is_learner(&self) -> bool {
    self.self_is_learner
  }
}

/// An application-facing event emitted by an `Endpoint`, drained via `poll_event`.
///
/// Observability only: every variant copies a few scalars at its emission chokepoint (no formatting,
/// no allocation beyond the payload it already holds), and NOTHING in the protocol depends on the
/// events being consumed — a driver forwards them to the embedder best-effort.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum Event {
  /// An operation was committed and applied to the state machine.
  Committed(Committed),
  /// This replica formed (as the new primary) or adopted (as a backup) a view.
  ViewChanged(ViewChanged),
  /// This replica's status changed (Normal / ViewChange / Recovering / RecoveringHead).
  StatusChanged(Status),
  /// A state-sync was armed: this replica learned of a cluster checkpoint it must fetch (the
  /// payload is the solicited target checkpoint op).
  StateSyncStarted(OpNumber),
  /// A state-sync completed: the synced checkpoint (the payload op) is installed and durable.
  StateSyncCompleted(OpNumber),
  /// A windowed peer-repair solicitation went out for a contiguous committed hole band.
  RepairStarted(RepairStarted),
  /// A checkpoint's root write landed: the checkpoint at the payload op is durable.
  CheckpointDurable(OpNumber),
  /// A committed reconfiguration's epoch swap became durable: the node now participates under the new
  /// configuration (epoch, voter set, quorums). Emitted at the durable `SwapEpoch` root, not at commit.
  MembershipChanged(MembershipChanged),
}

#[cfg(test)]
mod tests;

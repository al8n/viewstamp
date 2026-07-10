//! Wire-envelope conversions for the state-sync, windowed-repair, batching, learner-promotion,
//! block-store, and nack messages: [`RequestSync`], [`SyncCheckpoint`], [`RequestPrepareRange`],
//! [`RepairBatch`], [`PrepareBatch`], [`LearnerStatus`], [`EpochAhead`], [`RequestLearnerProof`],
//! [`LearnerProof`], the [`BlockAddress`] carried by
//! [`Message::RequestBlock`](crate::Message::RequestBlock), [`BlockResponse`], and [`Nack`].
//!
//! Each pair converts one direction, mirroring [`super::convert`] and [`super::messages_a`]:
//! `pb_*` builds the wire ([`pb`]) shape from a borrowed domain value; `*_from` consumes a wire
//! value and either returns the domain value or rejects it — through [`super::convert`]'s shared
//! helpers — for a wrong-length id/checksum/address, an out-of-range replica slot, or a malformed
//! log entry. `RequestBlock` is the one variant whose domain payload is not a wrapper struct: the
//! `Message` carries a bare [`BlockAddress`], so its pair converts the address directly.

use bytes::Bytes;

use super::{
  convert::{log_from, pb_log, replica_from, u128_bytes, u128_from},
  pb,
};
use crate::{
  BlockAddress, BlockResponse, Epoch, EpochAhead, LearnerProof, LearnerStatus, Nack, OpNumber,
  PrepareBatch, RepairBatch, RequestLearnerProof, RequestPrepareRange, RequestSync, SyncCheckpoint,
  View, codec::CodecError,
};

/// Converts a borrowed [`RequestSync`] into its wire form: the view/checkpoint_op/nonce scalars
/// and the recovery flag carried as-is, the replica narrowed to its wire width, and the config id
/// as 16 big-endian bytes.
pub(crate) fn pb_request_sync(m: &RequestSync) -> pb::RequestSync {
  pb::RequestSync {
    view: m.view().get(),
    checkpoint_op: m.checkpoint_op().get(),
    replica: u32::from(m.replica().get()),
    nonce: m.nonce(),
    recovery: m.recovery(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RequestSync`] into the domain [`RequestSync`]. Rejects a replica slot
/// above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn request_sync_from(w: pb::RequestSync) -> Result<RequestSync, CodecError> {
  Ok(RequestSync::new(
    View::with(w.view),
    OpNumber::with(w.checkpoint_op),
    replica_from(w.replica, "RequestSync.replica")?,
    w.nonce,
    w.recovery,
    u128_from(&w.config_id, "RequestSync.config_id")?,
  ))
}

/// Converts a borrowed [`SyncCheckpoint`] into its wire form: the view/checkpoint_op/epoch/nonce
/// scalars carried as-is, the replica narrowed to its wire width, the checkpoint id and config id
/// as 16 big-endian bytes each, and the snapshot and membership bodies carried as-is.
pub(crate) fn pb_sync_checkpoint(m: &SyncCheckpoint) -> pb::SyncCheckpoint {
  pb::SyncCheckpoint {
    view: m.view().get(),
    checkpoint_op: m.checkpoint_op().get(),
    checkpoint_id: u128_bytes(m.checkpoint_id()),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    replica: u32::from(m.replica().get()),
    nonce: m.nonce(),
    snapshot: m.snapshot_bytes(),
    membership: m.membership_bytes(),
    ..Default::default()
  }
}

/// Converts a wire [`pb::SyncCheckpoint`] into the domain [`SyncCheckpoint`], moving the snapshot
/// and membership `Bytes` out rather than copying them. Rejects a replica slot above
/// [`u16::MAX`], or a wrong-length checkpoint id or config id.
pub(crate) fn sync_checkpoint_from(w: pb::SyncCheckpoint) -> Result<SyncCheckpoint, CodecError> {
  Ok(SyncCheckpoint::new(
    View::with(w.view),
    OpNumber::with(w.checkpoint_op),
    u128_from(&w.checkpoint_id, "SyncCheckpoint.checkpoint_id")?,
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "SyncCheckpoint.config_id")?,
    replica_from(w.replica, "SyncCheckpoint.replica")?,
    w.nonce,
    w.snapshot,
    w.membership,
  ))
}

/// Converts a borrowed [`RequestPrepareRange`] into its wire form: the view/lo/hi scalars carried
/// as-is, the replica narrowed to its wire width, and the config id as 16 big-endian bytes.
pub(crate) fn pb_request_prepare_range(m: &RequestPrepareRange) -> pb::RequestPrepareRange {
  pb::RequestPrepareRange {
    view: m.view().get(),
    lo: m.lo().get(),
    hi: m.hi().get(),
    replica: u32::from(m.replica().get()),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RequestPrepareRange`] into the domain [`RequestPrepareRange`]. Rejects a
/// replica slot above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn request_prepare_range_from(
  w: pb::RequestPrepareRange,
) -> Result<RequestPrepareRange, CodecError> {
  Ok(RequestPrepareRange::new(
    View::with(w.view),
    OpNumber::with(w.lo),
    OpNumber::with(w.hi),
    replica_from(w.replica, "RequestPrepareRange.replica")?,
    u128_from(&w.config_id, "RequestPrepareRange.config_id")?,
  ))
}

/// Converts a borrowed [`RepairBatch`] into its wire form: the view/commit/checkpoint_op scalars
/// carried as-is, the config id as 16 big-endian bytes, and the log converted entry-by-entry.
pub(crate) fn pb_repair_batch(m: &RepairBatch) -> pb::RepairBatch {
  pb::RepairBatch {
    view: m.view().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    config_id: u128_bytes(m.config_id()),
    log: pb_log(m.log_slice()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RepairBatch`] into the domain [`RepairBatch`]. Rejects a wrong-length
/// config id or a malformed log entry (the first rejected entry short-circuits the whole log).
pub(crate) fn repair_batch_from(w: pb::RepairBatch) -> Result<RepairBatch, CodecError> {
  Ok(RepairBatch::new(
    View::with(w.view),
    OpNumber::with(w.commit),
    OpNumber::with(w.checkpoint_op),
    u128_from(&w.config_id, "RepairBatch.config_id")?,
    log_from(w.log)?,
  ))
}

/// Converts a borrowed [`PrepareBatch`] into its wire form: the view/commit/checkpoint_op/epoch
/// scalars carried as-is, the config id as 16 big-endian bytes, and the log converted
/// entry-by-entry.
pub(crate) fn pb_prepare_batch(m: &PrepareBatch) -> pb::PrepareBatch {
  pb::PrepareBatch {
    view: m.view().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    log: pb_log(m.log_slice()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::PrepareBatch`] into the domain [`PrepareBatch`]. Rejects a wrong-length
/// config id or a malformed log entry (the first rejected entry short-circuits the whole log).
pub(crate) fn prepare_batch_from(w: pb::PrepareBatch) -> Result<PrepareBatch, CodecError> {
  Ok(PrepareBatch::new(
    View::with(w.view),
    OpNumber::with(w.commit),
    OpNumber::with(w.checkpoint_op),
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "PrepareBatch.config_id")?,
    log_from(w.log)?,
  ))
}

/// Converts a borrowed [`LearnerStatus`] into its wire form: the durable_commit_min/durable_op/
/// epoch scalars carried as-is, the replica narrowed to its wire width, and the config id as 16
/// big-endian bytes.
pub(crate) fn pb_learner_status(m: &LearnerStatus) -> pb::LearnerStatus {
  pb::LearnerStatus {
    replica: u32::from(m.replica().get()),
    durable_commit_min: m.durable_commit_min().get(),
    durable_op: m.durable_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::LearnerStatus`] into the domain [`LearnerStatus`]. Rejects a replica
/// slot above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn learner_status_from(w: pb::LearnerStatus) -> Result<LearnerStatus, CodecError> {
  Ok(LearnerStatus::new(
    replica_from(w.replica, "LearnerStatus.replica")?,
    OpNumber::with(w.durable_commit_min),
    OpNumber::with(w.durable_op),
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "LearnerStatus.config_id")?,
  ))
}

/// Converts a borrowed [`EpochAhead`] into its wire form: the epoch and checkpoint_op scalars
/// carried as-is.
pub(crate) fn pb_epoch_ahead(m: &EpochAhead) -> pb::EpochAhead {
  pb::EpochAhead {
    epoch: m.epoch().get(),
    checkpoint_op: m.checkpoint_op().get(),
    ..Default::default()
  }
}

/// Converts a wire [`pb::EpochAhead`] into the domain [`EpochAhead`]. Infallible: this is the one
/// variant with no id/checksum/address or replica field to reject.
pub(crate) fn epoch_ahead_from(w: pb::EpochAhead) -> Result<EpochAhead, CodecError> {
  Ok(EpochAhead::new(
    Epoch::new(w.epoch),
    OpNumber::with(w.checkpoint_op),
  ))
}

/// Converts a borrowed [`RequestLearnerProof`] into its wire form: the at_op/nonce/epoch scalars
/// carried as-is, the soliciting replica (`from`) narrowed to its wire width, and the config id
/// as 16 big-endian bytes.
pub(crate) fn pb_request_learner_proof(m: &RequestLearnerProof) -> pb::RequestLearnerProof {
  pb::RequestLearnerProof {
    from: u32::from(m.from().get()),
    at_op: m.at_op().get(),
    nonce: m.nonce(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RequestLearnerProof`] into the domain [`RequestLearnerProof`]. Rejects a
/// `from` replica slot above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn request_learner_proof_from(
  w: pb::RequestLearnerProof,
) -> Result<RequestLearnerProof, CodecError> {
  Ok(RequestLearnerProof::new(
    replica_from(w.from, "RequestLearnerProof.from")?,
    OpNumber::with(w.at_op),
    w.nonce,
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "RequestLearnerProof.config_id")?,
  ))
}

/// Converts a borrowed [`LearnerProof`] into its wire form: the nonce/frontier/epoch scalars
/// carried as-is, the replica narrowed to its wire width, and the config id as 16 big-endian
/// bytes.
pub(crate) fn pb_learner_proof(m: &LearnerProof) -> pb::LearnerProof {
  pb::LearnerProof {
    replica: u32::from(m.replica().get()),
    nonce: m.nonce(),
    frontier: m.frontier().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::LearnerProof`] into the domain [`LearnerProof`]. Rejects a replica slot
/// above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn learner_proof_from(w: pb::LearnerProof) -> Result<LearnerProof, CodecError> {
  Ok(LearnerProof::new(
    replica_from(w.replica, "LearnerProof.replica")?,
    w.nonce,
    OpNumber::with(w.frontier),
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "LearnerProof.config_id")?,
  ))
}

/// Narrows a wire 16-byte content address to a [`BlockAddress`], rejecting via the shared
/// [`u128_from`] length check any byte length but exactly 16 — a [`BlockAddress`] is itself a
/// 16-byte big-endian digest, the same canonical shape every other id/checksum field uses, so the
/// existing length check applies unchanged (the `u128`/`to_be_bytes` round trip is bijective).
fn block_address_from(b: &Bytes, what: &'static str) -> Result<BlockAddress, CodecError> {
  u128_from(b, what).map(|v| BlockAddress::from_bytes(v.to_be_bytes()))
}

/// Converts a borrowed [`BlockAddress`] into its wire [`pb::RequestBlock`] form: the address's 16
/// bytes copied as-is. The domain [`Message::RequestBlock`](crate::Message::RequestBlock) variant
/// carries the address directly (no wrapper struct), so this pair converts the address itself.
pub(crate) fn pb_request_block(addr: &BlockAddress) -> pb::RequestBlock {
  pb::RequestBlock {
    addr: Bytes::copy_from_slice(addr.as_bytes()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RequestBlock`] into the domain [`BlockAddress`]. Rejects a wrong-length
/// address.
pub(crate) fn request_block_from(w: pb::RequestBlock) -> Result<BlockAddress, CodecError> {
  block_address_from(&w.addr, "RequestBlock.addr")
}

/// Converts a borrowed [`BlockResponse`] into its wire form: the address's 16 bytes copied as-is,
/// and the block payload copied into the `optional bytes` slot when present (`None` maps to wire
/// absence, preserving the presence/absence distinction).
pub(crate) fn pb_block_response(m: &BlockResponse) -> pb::BlockResponse {
  pb::BlockResponse {
    addr: Bytes::copy_from_slice(m.addr().as_bytes()),
    block: m.block().map(Bytes::copy_from_slice),
    ..Default::default()
  }
}

/// Converts a wire [`pb::BlockResponse`] into the domain [`BlockResponse`], moving the block
/// `Bytes` out rather than copying it and preserving its `None`/`Some(..)` presence exactly (the
/// proto3 explicit-presence `optional bytes` maps directly onto the domain's `Option<Bytes>`).
/// Rejects a wrong-length address.
pub(crate) fn block_response_from(w: pb::BlockResponse) -> Result<BlockResponse, CodecError> {
  let addr = block_address_from(&w.addr, "BlockResponse.addr")?;
  Ok(BlockResponse::new(addr, w.block))
}

/// Converts a borrowed [`Nack`] into its wire form: the view/op scalars carried as-is, the
/// replica narrowed to its wire width, and the config id as 16 big-endian bytes.
pub(crate) fn pb_nack(m: &Nack) -> pb::Nack {
  pb::Nack {
    view: m.view().get(),
    op: m.op().get(),
    replica: u32::from(m.replica().get()),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::Nack`] into the domain [`Nack`]. Rejects a replica slot above
/// [`u16::MAX`] or a wrong-length config id.
pub(crate) fn nack_from(w: pb::Nack) -> Result<Nack, CodecError> {
  Ok(Nack::new(
    View::with(w.view),
    OpNumber::with(w.op),
    replica_from(w.replica, "Nack.replica")?,
    u128_from(&w.config_id, "Nack.config_id")?,
  ))
}

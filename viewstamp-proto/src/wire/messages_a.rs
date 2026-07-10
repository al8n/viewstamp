//! Wire-envelope conversions for the client-facing, normal-protocol, view-change, and recovery
//! messages: [`Request`], [`Prepare`], [`PrepareOk`], [`Reply`], [`Commit`], [`StartViewChange`],
//! [`DoViewChange`], [`StartView`], [`GetView`], [`RequestPrepare`], [`Recovery`], and
//! [`RecoveryResponse`].
//!
//! Each pair converts one direction, mirroring [`super::convert`]: `pb_*` builds the wire ([`pb`])
//! shape from a borrowed domain value; `*_from` consumes a wire value and either returns the domain
//! value or rejects it — through [`super::convert`]'s shared helpers — for a wrong-length
//! id/checksum, an out-of-range replica slot, or a malformed log entry.

use super::{
  convert::{log_from, pb_log, replica_from, u128_bytes, u128_from},
  pb,
};
use crate::{
  ClientId, Commit, DoViewChange, Epoch, GetView, OpNumber, Prepare, PrepareOk, Recovery,
  RecoveryResponse, Reply, Request, RequestNumber, RequestPrepare, StartView, StartViewChange,
  View, codec::CodecError,
};

/// Converts a borrowed [`Request`] into its wire form: the client id as 16 big-endian bytes, the
/// request number and body carried as-is.
pub(crate) fn pb_request(m: &Request) -> pb::Request {
  pb::Request {
    client: u128_bytes(m.client().get()),
    request: m.request().get(),
    body: m.body_bytes(),
    ..Default::default()
  }
}

/// Converts a wire [`pb::Request`] into the domain [`Request`], moving the body `Bytes` out rather
/// than copying it. Rejects a wrong-length client id.
pub(crate) fn request_from(w: pb::Request) -> Result<Request, CodecError> {
  Ok(Request::new(
    ClientId::new(u128_from(&w.client, "Request.client")?),
    RequestNumber::with(w.request),
    w.body,
  ))
}

/// Converts a borrowed [`Prepare`] into its wire form: the view/op/commit/checkpoint_op/epoch and
/// request scalars carried as-is, the config id and client id as 16 big-endian bytes each, and the
/// body carried as-is.
pub(crate) fn pb_prepare(m: &Prepare) -> pb::Prepare {
  pb::Prepare {
    view: m.view().get(),
    op: m.op().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    client: u128_bytes(m.client().get()),
    request: m.request().get(),
    body: m.body_bytes(),
    ..Default::default()
  }
}

/// Converts a wire [`pb::Prepare`] into the domain [`Prepare`], moving the body `Bytes` out rather
/// than copying it. Rejects a wrong-length config id or client id.
pub(crate) fn prepare_from(w: pb::Prepare) -> Result<Prepare, CodecError> {
  Ok(Prepare::new(
    View::with(w.view),
    OpNumber::with(w.op),
    OpNumber::with(w.commit),
    OpNumber::with(w.checkpoint_op),
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "Prepare.config_id")?,
    ClientId::new(u128_from(&w.client, "Prepare.client")?),
    RequestNumber::with(w.request),
    w.body,
  ))
}

/// Converts a borrowed [`PrepareOk`] into its wire form: the view/op/checkpoint_op/epoch scalars
/// carried as-is, the replica narrowed to its wire width, and the prepare checksum and config id as
/// 16 big-endian bytes each.
pub(crate) fn pb_prepare_ok(m: &PrepareOk) -> pb::PrepareOk {
  pb::PrepareOk {
    view: m.view().get(),
    op: m.op().get(),
    replica: u32::from(m.replica().get()),
    checkpoint_op: m.checkpoint_op().get(),
    prepare_checksum: u128_bytes(m.prepare_checksum()),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::PrepareOk`] into the domain [`PrepareOk`]. Rejects a replica slot above
/// [`u16::MAX`], or a wrong-length prepare checksum or config id.
pub(crate) fn prepare_ok_from(w: pb::PrepareOk) -> Result<PrepareOk, CodecError> {
  Ok(PrepareOk::new(
    View::with(w.view),
    OpNumber::with(w.op),
    replica_from(w.replica, "PrepareOk.replica")?,
    OpNumber::with(w.checkpoint_op),
    u128_from(&w.prepare_checksum, "PrepareOk.prepare_checksum")?,
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "PrepareOk.config_id")?,
  ))
}

/// Converts a borrowed [`Reply`] into its wire form: the view and request number carried as-is,
/// the client id as 16 big-endian bytes, and the body carried as-is.
pub(crate) fn pb_reply(m: &Reply) -> pb::Reply {
  pb::Reply {
    view: m.view().get(),
    client: u128_bytes(m.client().get()),
    request: m.request().get(),
    body: m.body_bytes(),
    ..Default::default()
  }
}

/// Converts a wire [`pb::Reply`] into the domain [`Reply`], moving the body `Bytes` out rather than
/// copying it. Rejects a wrong-length client id.
pub(crate) fn reply_from(w: pb::Reply) -> Result<Reply, CodecError> {
  Ok(Reply::new(
    View::with(w.view),
    ClientId::new(u128_from(&w.client, "Reply.client")?),
    RequestNumber::with(w.request),
    w.body,
  ))
}

/// Converts a borrowed [`Commit`] into its wire form: the view/commit/checkpoint_op/epoch scalars
/// carried as-is and the config id as 16 big-endian bytes.
pub(crate) fn pb_commit(m: &Commit) -> pb::Commit {
  pb::Commit {
    view: m.view().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::Commit`] into the domain [`Commit`]. Rejects a wrong-length config id.
pub(crate) fn commit_from(w: pb::Commit) -> Result<Commit, CodecError> {
  Ok(Commit::new(
    View::with(w.view),
    OpNumber::with(w.commit),
    OpNumber::with(w.checkpoint_op),
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "Commit.config_id")?,
  ))
}

/// Converts a borrowed [`StartViewChange`] into its wire form: the view and epoch carried as-is,
/// the replica narrowed to its wire width, and the config id as 16 big-endian bytes.
pub(crate) fn pb_start_view_change(m: &StartViewChange) -> pb::StartViewChange {
  pb::StartViewChange {
    view: m.view().get(),
    replica: u32::from(m.replica().get()),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::StartViewChange`] into the domain [`StartViewChange`]. Rejects a replica
/// slot above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn start_view_change_from(
  w: pb::StartViewChange,
) -> Result<StartViewChange, CodecError> {
  Ok(StartViewChange::new(
    View::with(w.view),
    replica_from(w.replica, "StartViewChange.replica")?,
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "StartViewChange.config_id")?,
  ))
}

/// Converts a borrowed [`DoViewChange`] into its wire form: the view/log_view/op/commit/
/// checkpoint_op/epoch scalars carried as-is, the replica narrowed to its wire width, the config id
/// as 16 big-endian bytes, and the log converted entry-by-entry.
pub(crate) fn pb_do_view_change(m: &DoViewChange) -> pb::DoViewChange {
  pb::DoViewChange {
    view: m.view().get(),
    log_view: m.log_view().get(),
    op: m.op().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    replica: u32::from(m.replica().get()),
    log: pb_log(m.log_slice()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::DoViewChange`] into the domain [`DoViewChange`]. Rejects a replica slot
/// above [`u16::MAX`], a wrong-length config id, or a malformed log entry (the first rejected entry
/// short-circuits the whole log).
pub(crate) fn do_view_change_from(w: pb::DoViewChange) -> Result<DoViewChange, CodecError> {
  Ok(
    DoViewChange::new(
      View::with(w.view),
      View::with(w.log_view),
      OpNumber::with(w.op),
      OpNumber::with(w.commit),
      Epoch::new(w.epoch),
      u128_from(&w.config_id, "DoViewChange.config_id")?,
      replica_from(w.replica, "DoViewChange.replica")?,
      log_from(w.log)?,
    )
    .with_checkpoint_op(OpNumber::with(w.checkpoint_op)),
  )
}

/// Converts a borrowed [`StartView`] into its wire form: the view/op/commit/checkpoint_op/epoch
/// scalars carried as-is, the replica narrowed to its wire width, the config id as 16 big-endian
/// bytes, and the log converted entry-by-entry.
pub(crate) fn pb_start_view(m: &StartView) -> pb::StartView {
  pb::StartView {
    view: m.view().get(),
    op: m.op().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    replica: u32::from(m.replica().get()),
    log: pb_log(m.log_slice()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::StartView`] into the domain [`StartView`]. Rejects a replica slot above
/// [`u16::MAX`], a wrong-length config id, or a malformed log entry (the first rejected entry
/// short-circuits the whole log).
pub(crate) fn start_view_from(w: pb::StartView) -> Result<StartView, CodecError> {
  Ok(
    StartView::new(
      View::with(w.view),
      OpNumber::with(w.op),
      OpNumber::with(w.commit),
      Epoch::new(w.epoch),
      u128_from(&w.config_id, "StartView.config_id")?,
      replica_from(w.replica, "StartView.replica")?,
      log_from(w.log)?,
    )
    .with_checkpoint_op(OpNumber::with(w.checkpoint_op)),
  )
}

/// Converts a borrowed [`GetView`] into its wire form: the view/nonce/epoch scalars carried as-is,
/// the replica narrowed to its wire width, and the config id as 16 big-endian bytes.
pub(crate) fn pb_get_view(m: &GetView) -> pb::GetView {
  pb::GetView {
    view: m.view().get(),
    replica: u32::from(m.replica().get()),
    nonce: m.nonce(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::GetView`] into the domain [`GetView`]. Rejects a replica slot above
/// [`u16::MAX`] or a wrong-length config id.
pub(crate) fn get_view_from(w: pb::GetView) -> Result<GetView, CodecError> {
  Ok(GetView::new(
    View::with(w.view),
    replica_from(w.replica, "GetView.replica")?,
    w.nonce,
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "GetView.config_id")?,
  ))
}

/// Converts a borrowed [`RequestPrepare`] into its wire form: the view and op carried as-is, the
/// replica narrowed to its wire width, and the config id as 16 big-endian bytes.
pub(crate) fn pb_request_prepare(m: &RequestPrepare) -> pb::RequestPrepare {
  pb::RequestPrepare {
    view: m.view().get(),
    op: m.op().get(),
    replica: u32::from(m.replica().get()),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RequestPrepare`] into the domain [`RequestPrepare`]. Rejects a replica
/// slot above [`u16::MAX`] or a wrong-length config id.
pub(crate) fn request_prepare_from(w: pb::RequestPrepare) -> Result<RequestPrepare, CodecError> {
  Ok(RequestPrepare::new(
    View::with(w.view),
    OpNumber::with(w.op),
    replica_from(w.replica, "RequestPrepare.replica")?,
    u128_from(&w.config_id, "RequestPrepare.config_id")?,
  ))
}

/// Converts a borrowed [`Recovery`] into its wire form: the nonce and epoch carried as-is, the
/// replica narrowed to its wire width, and the config id as 16 big-endian bytes.
pub(crate) fn pb_recovery(m: &Recovery) -> pb::Recovery {
  pb::Recovery {
    replica: u32::from(m.replica().get()),
    nonce: m.nonce(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::Recovery`] into the domain [`Recovery`]. Rejects a replica slot above
/// [`u16::MAX`] or a wrong-length config id.
pub(crate) fn recovery_from(w: pb::Recovery) -> Result<Recovery, CodecError> {
  Ok(Recovery::new(
    replica_from(w.replica, "Recovery.replica")?,
    w.nonce,
    Epoch::new(w.epoch),
    u128_from(&w.config_id, "Recovery.config_id")?,
  ))
}

/// Converts a borrowed [`RecoveryResponse`] into its wire form: the view/op/commit/checkpoint_op/
/// epoch/nonce scalars carried as-is, the replica narrowed to its wire width, the config id as 16
/// big-endian bytes, and the log converted entry-by-entry.
pub(crate) fn pb_recovery_response(m: &RecoveryResponse) -> pb::RecoveryResponse {
  pb::RecoveryResponse {
    view: m.view().get(),
    op: m.op().get(),
    commit: m.commit().get(),
    checkpoint_op: m.checkpoint_op().get(),
    epoch: m.epoch().get(),
    config_id: u128_bytes(m.config_id()),
    replica: u32::from(m.replica().get()),
    nonce: m.nonce(),
    log: pb_log(m.log_slice()),
    ..Default::default()
  }
}

/// Converts a wire [`pb::RecoveryResponse`] into the domain [`RecoveryResponse`]. Rejects a replica
/// slot above [`u16::MAX`], a wrong-length config id, or a malformed log entry (the first rejected
/// entry short-circuits the whole log).
pub(crate) fn recovery_response_from(
  w: pb::RecoveryResponse,
) -> Result<RecoveryResponse, CodecError> {
  Ok(
    RecoveryResponse::new(
      View::with(w.view),
      OpNumber::with(w.op),
      OpNumber::with(w.commit),
      Epoch::new(w.epoch),
      u128_from(&w.config_id, "RecoveryResponse.config_id")?,
      replica_from(w.replica, "RecoveryResponse.replica")?,
      w.nonce,
      log_from(w.log)?,
    )
    .with_checkpoint_op(OpNumber::with(w.checkpoint_op)),
  )
}

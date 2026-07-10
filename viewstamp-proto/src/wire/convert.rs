//! Domain <-> wire-envelope conversions for prepared-log entries and successor-membership
//! payloads — the shared machinery every per-message-variant conversion builds on.
//!
//! Each pair converts one direction: `pb_*` builds the wire ([`pb`]) shape from a borrowed domain
//! value; `*_from` consumes a wire value and either returns the domain value or rejects it (a
//! wire-only shape the domain can't represent — an absent oneof, an out-of-range count, a
//! wrong-length id/checksum).

use std::{boxed::Box, vec::Vec};

use bytes::Bytes;

use super::pb;
use crate::{
  ClientId, MemberId, OpNumber, PreparedEntry, ReconfigurePayload, ReplicaId, RequestNumber,
  codec::CodecError, message::Body,
};

/// Maps a wire-conversion rejection (a wrong-length id/checksum, an out-of-range count, an absent
/// oneof) onto a [`CodecError::Malformed`], naming the offending field or bound in `what` (e.g.
/// `"Prepare.config_id"`, `"PreparedEntry.body_state"`).
#[cfg_attr(not(tarpaulin), inline)]
pub(crate) fn malformed(what: &'static str) -> CodecError {
  CodecError::Malformed { what }
}

/// Encodes `v` as the canonical 16-byte big-endian wire form shared by every id/checksum field (a
/// [`ClientId`], [`MemberId`], `body_checksum`, or `config_id`).
#[cfg_attr(not(tarpaulin), inline)]
pub(crate) fn u128_bytes(v: u128) -> Bytes {
  Bytes::copy_from_slice(&v.to_be_bytes())
}

/// Decodes a 16-byte big-endian id/checksum back into a `u128`, rejecting via [`malformed`] any
/// byte length but exactly 16.
#[cfg_attr(not(tarpaulin), inline)]
pub(crate) fn u128_from(b: &Bytes, what: &'static str) -> Result<u128, CodecError> {
  let raw: [u8; 16] = b.as_ref().try_into().map_err(|_| malformed(what))?;
  Ok(u128::from_be_bytes(raw))
}

/// Narrows a wire replica slot to a [`ReplicaId`], rejecting via [`malformed`] a value above
/// [`u16::MAX`].
#[cfg_attr(not(tarpaulin), inline)]
pub(crate) fn replica_from(v: u32, what: &'static str) -> Result<ReplicaId, CodecError> {
  u16::try_from(v)
    .map(ReplicaId::new)
    .map_err(|_| malformed(what))
}

/// Converts one domain [`PreparedEntry`] into its wire form: the op/request scalars carried
/// as-is, the client id as 16 big-endian bytes, and the body-state oneof filled from the entry's
/// [`Body`].
pub(crate) fn pb_entry(e: &PreparedEntry) -> pb::PreparedEntry {
  let body_state = match e.body_state() {
    Body::Present(bytes) => pb::prepared_entry::BodyState::Present(bytes.clone()),
    Body::Repairing(checksum) => {
      pb::prepared_entry::BodyState::RepairingChecksum(u128_bytes(*checksum))
    }
    Body::Reconfigure(payload) => {
      pb::prepared_entry::BodyState::Reconfigure(Box::new(pb_reconfigure(payload)))
    }
  };
  pb::PreparedEntry {
    op: e.op().get(),
    client: u128_bytes(e.client().get()),
    request: e.request().get(),
    body_state: Some(body_state),
    ..Default::default()
  }
}

/// Converts a wire [`pb::PreparedEntry`] into the domain [`PreparedEntry`], moving its `Bytes`
/// payload out rather than copying it. Rejects via [`malformed`] a wrong-length client id or
/// `Repairing` checksum, or an absent `body_state` (every entry carries exactly one body state on
/// the wire).
pub(crate) fn entry_from(w: pb::PreparedEntry) -> Result<PreparedEntry, CodecError> {
  let op = OpNumber::with(w.op);
  let client = ClientId::new(u128_from(&w.client, "PreparedEntry.client")?);
  let request = RequestNumber::with(w.request);
  match w.body_state {
    Some(pb::prepared_entry::BodyState::Present(body)) => {
      Ok(PreparedEntry::new(op, client, request, body))
    }
    Some(pb::prepared_entry::BodyState::RepairingChecksum(checksum)) => {
      let checksum = u128_from(&checksum, "PreparedEntry.repairing_checksum")?;
      Ok(PreparedEntry::repairing(op, client, request, checksum))
    }
    Some(pb::prepared_entry::BodyState::Reconfigure(payload)) => {
      let payload = reconfigure_from(*payload)?;
      Ok(PreparedEntry::reconfigure(op, client, request, payload))
    }
    None => Err(malformed("PreparedEntry.body_state")),
  }
}

/// Converts a domain log slice into its wire form, one [`pb_entry`] per entry.
pub(crate) fn pb_log(log: &[PreparedEntry]) -> Vec<pb::PreparedEntry> {
  log.iter().map(pb_entry).collect()
}

/// Converts a wire log into the domain form, one [`entry_from`] per entry; the first rejected
/// entry short-circuits the whole log. Rejects via [`malformed`] a log longer than the protocol
/// maximum ([`crate::message::MAX_HEADER_ONLY_BAND_DEPTH`] — the deepest header-only band any
/// single view-change carrier can legitimately hold) BEFORE converting a single entry: a valid
/// peer never sends a longer log in one message, so this bounds the allocation the entry-by-entry
/// conversion below would otherwise perform on a hostile (or corrupt) over-long count.
pub(crate) fn log_from(w: Vec<pb::PreparedEntry>) -> Result<Vec<PreparedEntry>, CodecError> {
  if w.len() > crate::message::MAX_HEADER_ONLY_BAND_DEPTH {
    return Err(malformed("Message.log"));
  }
  w.into_iter().map(entry_from).collect()
}

/// Converts a domain [`ReconfigurePayload`] into its wire form: the voting/learner counts widened
/// to their wire scalar width, and each member id plus the pinned predecessor id as 16 big-endian
/// bytes.
pub(crate) fn pb_reconfigure(p: &ReconfigurePayload) -> pb::ReconfigurePayload {
  pb::ReconfigurePayload {
    replica_count: u32::from(p.replica_count()),
    learner_count: u32::from(p.learner_count()),
    members: p.members().iter().map(|m| u128_bytes(m.get())).collect(),
    prev_config_id: u128_bytes(p.prev_config_id()),
    ..Default::default()
  }
}

/// The protocol's absolute ceiling on `ReconfigurePayload.members.len()`: every member occupies a
/// [`ReplicaId`] (`u16`) slot, so a successor whose `replica_count + learner_count` exceeds
/// [`u16::MAX`] can never validate — [`crate::MembershipError::TooManyNodes`] rejects it,
/// regardless of the voting/learner split. This is therefore the TIGHTEST bound that holds for
/// EVERY structurally-valid successor (not a looser one invented here): a wire count above it can
/// never validate at [`ReconfigurePayload::to_membership`], so it is rejected below, before the
/// per-member conversion allocates.
const MAX_RECONFIGURE_MEMBERS: usize = u16::MAX as usize;

/// Converts a wire [`pb::ReconfigurePayload`] into the domain [`ReconfigurePayload`], rejecting
/// via [`malformed`] a `members` list longer than [`MAX_RECONFIGURE_MEMBERS`], a voting/learner
/// count that overflows its domain width ([`u8`]/[`u16`]), or a member/predecessor id whose byte
/// length isn't the canonical 16.
pub(crate) fn reconfigure_from(
  w: pb::ReconfigurePayload,
) -> Result<ReconfigurePayload, CodecError> {
  if w.members.len() > MAX_RECONFIGURE_MEMBERS {
    return Err(malformed("ReconfigurePayload.members"));
  }
  let replica_count =
    u8::try_from(w.replica_count).map_err(|_| malformed("ReconfigurePayload.replica_count"))?;
  let learner_count =
    u16::try_from(w.learner_count).map_err(|_| malformed("ReconfigurePayload.learner_count"))?;
  let prev_config_id = u128_from(&w.prev_config_id, "ReconfigurePayload.prev_config_id")?;
  let members = w
    .members
    .iter()
    .map(|m| u128_from(m, "ReconfigurePayload.members").map(MemberId::new))
    .collect::<Result<Vec<_>, _>>()?
    .into_boxed_slice();
  Ok(ReconfigurePayload::new(
    replica_count,
    learner_count,
    members,
    prev_config_id,
  ))
}

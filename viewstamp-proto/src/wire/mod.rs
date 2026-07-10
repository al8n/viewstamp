//! The wire envelope: buffa-generated protobuf types and their conversions to and
//! from the domain structs.
//!
//! `proto/viewstamp/v1/messages.proto` is the NORMATIVE schema (WIRE.md references
//! it); `build.rs` generates the types here via buffa. The domain types never change
//! shape for the wire's sake — encoding converts INTO the generated types and
//! decoding converts OUT of them. `encode_message`/`decode_message` are the public
//! choke point every transport and the simulation harness sends/receives through.

use bytes::Bytes;

use crate::{Message, codec::CodecError};
// The trait's provided methods (`encode_to_bytes`, `DecodeOptions::decode`'s bound) — imported
// anonymously since the trait shares its name with the domain `Message` enum imported above.
use buffa::Message as _;

mod generated {
  // The generated zero-copy `*View` accessors carry many single-use / elided
  // lifetime parameters that trip the workspace's `rust_2018_idioms` and
  // `single_use_lifetimes` warn-lints; both are hard errors under `-D warnings`
  // and are buffa's codegen shape, not ours to rewrite.
  #![allow(clippy::wrong_self_convention)]
  #![allow(rust_2018_idioms)]
  #![allow(single_use_lifetimes)]
  include!(concat!(env!("OUT_DIR"), "/viewstamp_wire_generated.rs"));
}
pub(crate) use generated::viewstamp::v1 as pb;

mod convert;
mod messages_a;
mod messages_b;

/// The unknown-field allowance for decoding a [`Message`] envelope.
///
/// A well-formed envelope carries ZERO unknown fields: cross-version peers are fenced at the
/// handshake, so a peer speaking this schema never legitimately sends one. buffa's own default
/// allowance is 1,000,000, which would let a hostile frame packed with minimal unknown fields
/// materialize up to that many `UnknownField` entries (tens of MiB transient) before the frame is
/// rejected. 16 is generous forward-compat headroom over the "never happens" case while capping
/// that allocation to a bounded, negligible amount.
const MAX_UNKNOWN_FIELDS: usize = 16;

/// Builds the wire [`pb::Message`] envelope for one domain [`Message`]: an exhaustive match over
/// every variant (no wildcard, so a new variant fails to compile here until it is handled) filling
/// the `Message.body` oneof from the matching per-variant `pb_*` conversion.
pub(crate) fn pb_message(msg: &Message) -> pb::Message {
  use pb::message::Body;
  let body = match msg {
    Message::Request(m) => Body::from(messages_a::pb_request(m)),
    Message::Prepare(m) => Body::from(messages_a::pb_prepare(m)),
    Message::PrepareOk(m) => Body::from(messages_a::pb_prepare_ok(m)),
    Message::Reply(m) => Body::from(messages_a::pb_reply(m)),
    Message::Commit(m) => Body::from(messages_a::pb_commit(m)),
    Message::StartViewChange(m) => Body::from(messages_a::pb_start_view_change(m)),
    Message::DoViewChange(m) => Body::from(messages_a::pb_do_view_change(m)),
    Message::StartView(m) => Body::from(messages_a::pb_start_view(m)),
    Message::GetView(m) => Body::from(messages_a::pb_get_view(m)),
    Message::RequestPrepare(m) => Body::from(messages_a::pb_request_prepare(m)),
    Message::Recovery(m) => Body::from(messages_a::pb_recovery(m)),
    Message::RecoveryResponse(m) => Body::from(messages_a::pb_recovery_response(m)),
    Message::RequestSync(m) => Body::from(messages_b::pb_request_sync(m)),
    Message::SyncCheckpoint(m) => Body::from(messages_b::pb_sync_checkpoint(m)),
    Message::RequestPrepareRange(m) => Body::from(messages_b::pb_request_prepare_range(m)),
    Message::RepairBatch(m) => Body::from(messages_b::pb_repair_batch(m)),
    Message::PrepareBatch(m) => Body::from(messages_b::pb_prepare_batch(m)),
    Message::LearnerStatus(m) => Body::from(messages_b::pb_learner_status(m)),
    Message::EpochAhead(m) => Body::from(messages_b::pb_epoch_ahead(m)),
    Message::RequestLearnerProof(m) => Body::from(messages_b::pb_request_learner_proof(m)),
    Message::LearnerProof(m) => Body::from(messages_b::pb_learner_proof(m)),
    Message::RequestBlock(addr) => Body::from(messages_b::pb_request_block(addr)),
    Message::BlockResponse(m) => Body::from(messages_b::pb_block_response(m)),
    Message::Nack(m) => Body::from(messages_b::pb_nack(m)),
  };
  pb::Message {
    body: Some(body),
    ..Default::default()
  }
}

/// Converts a decoded wire [`pb::Message`] into the domain [`Message`]: an exhaustive match over
/// every `Message.body` oneof arm (no wildcard) routing to the matching per-variant `*_from`
/// conversion, each of which owns its own field-level validation. Rejects via [`convert::malformed`]
/// an envelope whose body is absent — the wire's "no known message" case, parity with the prior
/// codec's unknown-tag reject.
fn message_from(wire: pb::Message) -> Result<Message, CodecError> {
  use pb::message::Body;
  let body = wire
    .body
    .ok_or_else(|| convert::malformed("Message.body"))?;
  Ok(match body {
    Body::Request(m) => Message::Request(messages_a::request_from(*m)?),
    Body::Prepare(m) => Message::Prepare(messages_a::prepare_from(*m)?),
    Body::PrepareOk(m) => Message::PrepareOk(messages_a::prepare_ok_from(*m)?),
    Body::Reply(m) => Message::Reply(messages_a::reply_from(*m)?),
    Body::Commit(m) => Message::Commit(messages_a::commit_from(*m)?),
    Body::StartViewChange(m) => Message::StartViewChange(messages_a::start_view_change_from(*m)?),
    Body::DoViewChange(m) => Message::DoViewChange(messages_a::do_view_change_from(*m)?),
    Body::StartView(m) => Message::StartView(messages_a::start_view_from(*m)?),
    Body::GetView(m) => Message::GetView(messages_a::get_view_from(*m)?),
    Body::RequestPrepare(m) => Message::RequestPrepare(messages_a::request_prepare_from(*m)?),
    Body::Recovery(m) => Message::Recovery(messages_a::recovery_from(*m)?),
    Body::RecoveryResponse(m) => Message::RecoveryResponse(messages_a::recovery_response_from(*m)?),
    Body::RequestSync(m) => Message::RequestSync(messages_b::request_sync_from(*m)?),
    Body::SyncCheckpoint(m) => Message::SyncCheckpoint(messages_b::sync_checkpoint_from(*m)?),
    Body::RequestPrepareRange(m) => {
      Message::RequestPrepareRange(messages_b::request_prepare_range_from(*m)?)
    }
    Body::RepairBatch(m) => Message::RepairBatch(messages_b::repair_batch_from(*m)?),
    Body::PrepareBatch(m) => Message::PrepareBatch(messages_b::prepare_batch_from(*m)?),
    Body::LearnerStatus(m) => Message::LearnerStatus(messages_b::learner_status_from(*m)?),
    Body::EpochAhead(m) => Message::EpochAhead(messages_b::epoch_ahead_from(*m)?),
    Body::RequestLearnerProof(m) => {
      Message::RequestLearnerProof(messages_b::request_learner_proof_from(*m)?)
    }
    Body::LearnerProof(m) => Message::LearnerProof(messages_b::learner_proof_from(*m)?),
    Body::RequestBlock(m) => Message::RequestBlock(messages_b::request_block_from(*m)?),
    Body::BlockResponse(m) => Message::BlockResponse(messages_b::block_response_from(*m)?),
    Body::Nack(m) => Message::Nack(messages_b::nack_from(*m)?),
  })
}

/// Maps a buffa structural decode failure onto the crate's [`CodecError`] surface.
///
/// A caller only ever needs to distinguish two outcomes: the frame ended before a complete
/// envelope could be read ([`CodecError::Truncated`]), or it did not (every other buffa
/// [`DecodeError`](buffa::DecodeError) — an invalid wire type, an overlong varint, a bad recursion
/// depth, an exceeded unknown-field allowance, ... — collapses to [`CodecError::Malformed`]). The
/// caller-visible behavior is identical either way (reject the frame), so the finer buffa-internal
/// distinctions aren't worth a dedicated `CodecError` variant per case.
fn map_decode_err(e: buffa::DecodeError) -> CodecError {
  match e {
    buffa::DecodeError::UnexpectedEof => CodecError::Truncated {
      // buffa's `UnexpectedEof` is a bare marker with no byte-count payload — unlike this crate's
      // own `Reader` (see `codec.rs`), which tracks an exact expected/remaining pair per read, the
      // internal read site that hit end-of-buffer, and by how much, is not exposed to a
      // `Message`-level caller. Both fields are set to the explicit "unknown" sentinel `0`; the
      // `Truncated` variant itself, not its numbers, carries the meaningful signal here.
      expected: 0,
      got: 0,
    },
    _ => CodecError::Malformed {
      what: "wire envelope",
    },
  }
}

/// Encodes a [`Message`] into its protobuf wire envelope — the crate-public boundary between the
/// domain [`Message`] enum and the bytes a transport sends.
///
/// Every variant is written to its `Message.body` oneof arm (the envelope always carries a body),
/// then buffa serializes it canonically: fields in ascending field-number order, a proto3-default
/// scalar omitted rather than written as zero. Encoding the same [`Message`] value always produces
/// byte-identical output (see the `golden_byte_vectors` test) and never fails: every domain value
/// already satisfies the wire's shape, so there is nothing for encoding to reject.
pub fn encode_message(msg: &Message) -> Bytes {
  pb_message(msg).encode_to_bytes()
}

/// Decodes a [`Message`] from its protobuf wire envelope — the inverse of [`encode_message`].
///
/// Unknown fields are tolerated up to a small bound and rejected past it, so a hostile flood of
/// unknown fields cannot force an unbounded transient allocation (a well-formed envelope carries
/// none — cross-version peers are fenced before any consensus traffic flows, so this is
/// forward-compatibility headroom, not a feature any current peer exercises).
///
/// # Zero-copy
///
/// `frame` is decoded through buffa's owned-[`Bytes`] path: every `bytes` field in the envelope (a
/// `Prepare`/`Reply` body, a `SyncCheckpoint` snapshot, a log entry's payload, …) comes out as an
/// O(1) refcount slice of `frame`'s allocation, never a byte copy. The returned [`Message`] keeps
/// `frame`'s backing allocation alive for as long as any such field does.
///
/// # Errors
///
/// - [`CodecError::Truncated`] if `frame` ends before a complete envelope can be read.
/// - [`CodecError::Malformed`] if `frame` violates the protobuf wire grammar, omits the
///   envelope's body, or decodes to a value the domain type cannot represent (a wrong-length
///   id/checksum, an out-of-range count, an absent required oneof).
pub fn decode_message(mut frame: Bytes) -> Result<Message, CodecError> {
  let wire = buffa::DecodeOptions::new()
    .with_unknown_field_limit(MAX_UNKNOWN_FIELDS)
    .decode::<pb::Message>(&mut frame)
    .map_err(map_decode_err)?;
  message_from(wire)
}

#[cfg(test)]
mod tests;

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
/// Cross-version peers are fenced at the handshake (`HELLO_VERSION`), so within one wire era a
/// SAME-version peer's envelope carries ZERO unknown fields. The handshake fences STRUCTURAL and
/// semantic wire eras, though — NOT additive growth WITHIN an era: a newer peer may add a
/// `Message.body` oneof variant (a whole new message) that an older peer decodes cleanly but does not
/// recognize, seeing it as one unknown field with the body oneof left unset. That envelope surfaces
/// as [`CodecError::UnknownMessage`] and every transport DROPS it (the stream skips the frame and
/// stays open; QUIC drops the datagram), never mistaking a newer peer for a corrupt one. This
/// allowance is the headroom that keeps such an additive envelope decodable rather than treating its
/// one unknown field as an attack: up to 16 unknown fields are tolerated; a frame carrying MORE — or
/// any framing / wire-grammar / integrity fault — is [`CodecError::Malformed`] and terminates a
/// stream conn. buffa's own default allowance is 1,000,000, which would let a hostile frame packed
/// with minimal unknown fields materialize up to that many `UnknownField` entries (tens of MiB
/// transient) before the frame is rejected; 16 caps that allocation to a bounded, negligible amount
/// while leaving generous additive headroom.
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
    Message::RequestHealthProof(m) => Body::from(messages_b::pb_request_health_proof(m)),
    Message::HealthProof(m) => Body::from(messages_b::pb_health_proof(m)),
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
/// conversion, each of which owns its own field-level validation. An envelope whose body oneof is
/// ABSENT after a clean, bounded parse names no message this build knows — a FORWARD-COMPATIBLE body
/// a newer peer added, or the degenerate zero-field envelope — and surfaces as the distinct
/// [`CodecError::UnknownMessage`] (dropped by transports), NOT [`CodecError::Malformed`]. This is the
/// ONLY site that produces `UnknownMessage`, and it is reached only AFTER buffa's bounded decode has
/// accepted the wire grammar, so a truncation / grammar violation / unknown-field flood can never
/// arrive here (each is `Truncated`/`Malformed` upstream). The absent-body arm cannot narrow "no
/// known body" to "a newer body was seen": the generated `pb::Message` retains no witness of a
/// skipped unknown field, so a zero-field envelope classifies identically and is likewise dropped —
/// documented and acceptable (it carries nothing, and no current peer sends it).
fn message_from(wire: pb::Message) -> Result<Message, CodecError> {
  use pb::message::Body;
  let body = wire.body.ok_or(CodecError::UnknownMessage)?;
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
    Body::RequestHealthProof(m) => {
      Message::RequestHealthProof(messages_b::request_health_proof_from(*m)?)
    }
    Body::HealthProof(m) => Message::HealthProof(messages_b::health_proof_from(*m)?),
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
///
/// This is one side of the anti-flood / forward-compat boundary: an unknown-field FLOOD (more than
/// `MAX_UNKNOWN_FIELDS`) is a buffa-stage fault and is `Malformed` here — terminal on a stream conn —
/// whereas an envelope that decodes WITHIN the allowance but names an unknown body is the newer-peer
/// case classified downstream in [`message_from`] as [`CodecError::UnknownMessage`] (dropped, not
/// terminal). The flood is bounded BEFORE that classification can be reached, so a flood can never
/// launder itself into the drop-and-survive disposition.
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
    // The anti-flood / forward-compat boundary, made explicit rather than folded into the wildcard:
    // an unknown-field flood past `MAX_UNKNOWN_FIELDS` fires INSIDE buffa (before a body is
    // assembled) and is `Malformed` — terminal on a stream conn. It therefore never reaches
    // `message_from`'s absent-body arm, so it can never be reclassified as a droppable, forward-
    // compatible `UnknownMessage`. Same disposition as the wildcard below; called out on its own so
    // the boundary is visible at the value level, not only in prose.
    buffa::DecodeError::UnknownFieldLimitExceeded => CodecError::Malformed {
      what: "wire envelope",
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
/// unknown fields cannot force an unbounded transient allocation. A SAME-version peer's envelope
/// carries no unknown field; the bounded headroom exists so that a NEWER peer's additive
/// `Message.body` variant — which an older peer sees as one unknown field with the body oneof left
/// unset — still decodes, then surfaces as the forward-compatible [`CodecError::UnknownMessage`] that
/// transports drop (see `MAX_UNKNOWN_FIELDS` and the `# Errors` section below).
///
/// # Zero-copy
///
/// `frame` is decoded through buffa's owned-[`Bytes`] path: every `bytes` field in the envelope (a
/// `Prepare`/`Reply` body, a `SyncCheckpoint` snapshot, a log entry's payload, …) comes out as an
/// O(1) refcount slice of `frame`'s allocation, never a byte copy. The returned [`Message`] keeps
/// `frame`'s backing allocation alive for as long as any such field does.
///
/// # Bounds
///
/// `frame` itself is capped at `MAX_FRAME_LEN` bytes (`DecodeOptions::with_max_message_size`),
/// explicitly bounding buffa's input reader to the frame cap rather than trusting its 2 GiB
/// default — defense-in-depth atop the frame layer's own cap, in case `decode_message` is ever
/// reached on a buffer the frame layer did not itself size-check. A `log` (`repeated
/// PreparedEntry`) or `ReconfigurePayload.members` count above the PROTOCOL's own maximum is
/// rejected at the wire→domain conversion (`convert::log_from` / `convert::reconfigure_from`)
/// before it drives further allocation — a valid peer never sends more. Neither bound closes
/// amplification WITHIN the frame cap by an authenticated but Byzantine/compromised peer (e.g.
/// many minimal repeated submessages materializing more transient memory than the wire bytes alone
/// suggest): fully closing that would need a pre-scan of the wire bytes, which is out of
/// viewstamp's non-Byzantine (crash-fault) threat model — the same stance taken everywhere else a
/// validated peer is trusted not to be malicious.
///
/// # Errors
///
/// - [`CodecError::Truncated`] if `frame` ends before a complete envelope can be read.
/// - [`CodecError::Malformed`] if `frame` violates the protobuf wire grammar (an invalid wire type,
///   an overlong varint, an unknown-field FLOOD past the allowance), decodes to a value the domain
///   type cannot represent (a wrong-length id/checksum, an out-of-range count, an absent required
///   oneof), or exceeds a bound described above.
/// - [`CodecError::UnknownMessage`] if `frame` decodes cleanly and within every bound but names no
///   `Message.body` this build recognizes — a FORWARD-COMPATIBLE message from a newer peer, or the
///   degenerate zero-field envelope. This is NOT a corruption signal: a transport DROPS such a frame
///   and keeps the connection live (the stream skips it; QUIC drops the datagram), never terminating
///   the peer for speaking a newer additive schema.
pub fn decode_message(mut frame: Bytes) -> Result<Message, CodecError> {
  let wire = buffa::DecodeOptions::new()
    .with_max_message_size(crate::message::MAX_FRAME_LEN as usize)
    .with_unknown_field_limit(MAX_UNKNOWN_FIELDS)
    .decode::<pb::Message>(&mut frame)
    .map_err(map_decode_err)?;
  message_from(wire)
}

#[cfg(test)]
mod tests;

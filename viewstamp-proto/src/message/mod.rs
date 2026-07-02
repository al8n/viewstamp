//! Wire message types for the Viewstamped Replication protocol.

use bytes::{BufMut, Bytes, BytesMut};
use std::{boxed::Box, vec::Vec};

use crate::{
  ClientId, Epoch, MemberId, Membership, MembershipError, OpNumber, Recipient, ReplicaId,
  RequestNumber, View, WIRE_VERSION,
  codec::{CodecError, Reader, write_bytes_u32},
};

/// The minimum encoded length of one [`PreparedEntry`] in a log slice: `op` (`u64`) + `client`
/// (`u128`) + `request` (`u64`) + a body-state tag (`u8`) + the cheapest body-state payload. The
/// cheapest is a `Present` empty body (a `u32` length prefix = `4`, total `8 + 16 + 8 + 1 + 4`),
/// which is smaller than a `Repairing` 16-byte checksum and than a `Reconfigure` payload (`replica_count`
/// `u8` + `learner_count` `u16` + a `u32` member-count prefix = `7`, before any members), so this is the
/// floor used to reject a hostile log-slice element count before parsing (see [`Reader::seq_len`]).
const PREPARED_ENTRY_MIN_LEN: usize = 8 + 16 + 8 + 1 + 4;

/// Wire body-state discriminant for a [`PreparedEntry`] in a log slice: `0` = [`Body::Present`] (a
/// `u32`-length-prefixed body follows), `1` = [`Body::Repairing`] (a 16-byte `u128` `body_checksum`
/// follows, no bytes), `2` = [`Body::Reconfigure`] (a [`ReconfigurePayload`] — the successor
/// membership — follows). One source of truth shared by [`write_log`] (writes it) and [`read_log`]
/// (dispatches on it).
const BODY_TAG_PRESENT: u8 = 0;
const BODY_TAG_REPAIRING: u8 = 1;
const BODY_TAG_RECONFIGURE: u8 = 2;

/// The maximum encoded message length the transport framing admits (16 MiB). The single source of
/// truth for the frame cap: the (feature-gated) transport re-exports this as
/// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN), and the always-available byte-bounded
/// repair serve ([`Endpoint::on_request_prepare_range`](crate::Endpoint)) reads it directly — so the
/// serve's budget and the transport's cap can never drift. Lives in the base crate (not behind a
/// feature) so the proto core (and the VOPR, which runs without the transport) can size repair batches
/// against the very cap the wire enforces.
pub(crate) const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Bytes [`Message::encode`] prepends before any variant body: [`WIRE_VERSION`](crate::WIRE_VERSION)
/// (`u16`) then the variant discriminant tag (`u8`).
const ENCODE_HEADER_LEN: usize = 2 + 1;
/// The `u32` length prefix [`crate::codec::write_bytes_u32`] writes before a `Bytes` payload.
const BYTES_LEN_PREFIX: usize = 4;

#[cfg(feature = "tcp")]
/// Fixed bytes a [`Request`] encoding wraps around its body: the [`ENCODE_HEADER_LEN`] message header,
/// then `client` (`u128`) + `request` (`u64`), then the body's [`BYTES_LEN_PREFIX`]. So a body of `b`
/// bytes encodes to `REQUEST_ENCODE_OVERHEAD + b`. Derived from the exact widths
/// [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::Request`] arm.
pub const REQUEST_ENCODE_OVERHEAD: usize = ENCODE_HEADER_LEN + 16 + 8 + BYTES_LEN_PREFIX;

#[cfg(feature = "tcp")]
/// Fixed bytes a [`Prepare`] encoding wraps around the SAME client body once the primary replicates it
/// to backups: the [`ENCODE_HEADER_LEN`] message header, then `view` + `op` + `commit` + `checkpoint_op`
/// (four `u64`s) + the strict epoch-policy pair `epoch` (`u64`) + `config_id` (`u128`) + `client`
/// (`u128`) + `request` (`u64`), then the body's [`BYTES_LEN_PREFIX`]. So the same `b`-byte client body
/// that arrived as a `Request` leaves as a `Prepare` of `PREPARE_ENCODE_OVERHEAD + b` bytes. Derived
/// from the exact widths [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::Prepare`]
/// arm. This is strictly larger than [`REQUEST_ENCODE_OVERHEAD`] (a `Prepare` carries the extra
/// consensus header fields), but it is NOT the worst hop the body sees — the log-slice carriers below
/// wrap it in more — so it is only one input to [`MAX_REQUEST_BODY_OVERHEAD`].
pub const PREPARE_ENCODE_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 8 + 8 + 8 + 16 + 16 + 8 + BYTES_LEN_PREFIX;

/// Fixed bytes a [`Reply`] encoding wraps around its body: the `ENCODE_HEADER_LEN` message header,
/// then `view` (`u64`) + `client` (`u128`) + `request` (`u64`), then the body's `BYTES_LEN_PREFIX`.
/// So a reply body of `b` bytes encodes to `REPLY_ENCODE_OVERHEAD + b`. Derived from the exact widths
/// [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::Reply`] arm. The `Reply` is
/// the ONLY carrier of a reply body on the wire (the checkpoint envelope also embeds cached reply
/// bodies, but that envelope is chunk-transferable and so unbounded by any single frame), so this is
/// the binding overhead behind [`max_reply_body_len`].
pub const REPLY_ENCODE_OVERHEAD: usize = ENCODE_HEADER_LEN + 8 + 16 + 8 + BYTES_LEN_PREFIX;

/// The largest reply body a [`crate::StateMachine::apply`] may return: a reply of this many bytes
/// encodes as a [`Reply`] of exactly `MAX_FRAME_LEN`, the largest frame the transport will send or
/// accept. One byte more and the encoded `Reply` exceeds the frame cap — the transport refuses the
/// send, the client never hears the result, and since the op is ALREADY COMMITTED there is no
/// in-protocol recovery (the request cannot be re-executed; the cached over-bound reply re-fails on
/// every resend). The bound is therefore an EMBEDDER OBLIGATION documented on
/// [`crate::StateMachine::apply`] and debug-asserted at both apply sites, mirroring how
/// `max_request_body_len()` bounds the request body at driver submit.
pub const fn max_reply_body_len() -> usize {
  MAX_FRAME_LEN as usize - REPLY_ENCODE_OVERHEAD
}

/// Fixed bytes that wrap ONE client body inside a single [`Body::Present`] [`PreparedEntry`] within a
/// log slice (the per-element framing [`write_log`] emits around the body): `op` (`u64`) + `client`
/// (`u128`) + `request` (`u64`) + the body-state tag (`u8`, [`BODY_TAG_PRESENT`]), then the body's
/// [`BYTES_LEN_PREFIX`]. The same client body that arrived as a `Request` and replicated as a `Prepare`
/// is re-encoded as one of these entries when it rides a `DoViewChange` / `StartView` /
/// `RecoveryResponse` log at view change or recovery. Derived from the exact widths [`write_log`] /
/// [`Message::encoded_len`]'s `log(..)` write per `Present` entry.
const LOG_ENTRY_BODY_OVERHEAD: usize = 8 + 16 + 8 + 1 + BYTES_LEN_PREFIX;

/// The `u32` element-count prefix [`write_log`] writes before the entries of a log slice.
const LOG_COUNT_PREFIX: usize = 4;

/// Fixed bytes a [`RepairBatch`] encoding wraps around its served log slice, BEFORE the per-entry
/// framing: the [`ENCODE_HEADER_LEN`] message header, then `view` + `commit` + `checkpoint_op` (three
/// `u64`s) + the agnostic `config_id` (`u128`), then the log slice's [`LOG_COUNT_PREFIX`]. The
/// byte-bounded serve ([`Endpoint::on_request_prepare_range`](crate::Endpoint)) subtracts this from
/// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN) to get the budget for the per-entry payloads
/// it accumulates, so the produced `RepairBatch` never exceeds the frame cap. Derived from the exact
/// widths [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::RepairBatch`] arm.
pub(crate) const REPAIR_BATCH_CARRIER_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 8 + 16 + LOG_COUNT_PREFIX;

#[cfg(feature = "tcp")]
/// Fixed bytes a [`RepairBatch`] encoding wraps around ONE client body when that body is the sole
/// [`Body::Present`] entry served: the [`REPAIR_BATCH_CARRIER_OVERHEAD`] carrier framing plus one
/// [`LOG_ENTRY_BODY_OVERHEAD`] per-entry framing. Since the view-change log carriers are
/// header-only (see [`Endpoint::log_entries`](crate::Endpoint)), the `RepairBatch` repair serve is THE
/// binding BODY carrier — a committed op's full body travels the wire as a single-entry
/// `RepairBatch` (the windowed peer-repair answer), so a max-size body must fit one of these. This is
/// the largest of the three body carriers (a one-entry `RepairBatch` carries more framing than a bare
/// `Prepare`), so it sets [`MAX_REQUEST_BODY_OVERHEAD`].
const REPAIR_BATCH_BODY_OVERHEAD: usize = REPAIR_BATCH_CARRIER_OVERHEAD + LOG_ENTRY_BODY_OVERHEAD;

/// Fixed bytes a [`PrepareBatch`] encoding wraps around its retransmitted log slice, BEFORE the
/// per-entry framing: the [`ENCODE_HEADER_LEN`] message header, then `view` + `commit` +
/// `checkpoint_op` (three `u64`s) + the strict epoch-policy pair `epoch` (`u64`) + `config_id`
/// (`u128`), then the log slice's [`LOG_COUNT_PREFIX`]. The primary's byte-bounded prepare retransmit
/// ([`Endpoint::primary_timeouts`](crate::Endpoint) via its `prepare` timer) subtracts this from
/// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN) to get the budget for the per-entry
/// payloads each batch accumulates, so a produced `PrepareBatch` never exceeds the frame cap. Derived
/// from the exact widths [`Message::encode`]/[`Message::encoded_len`] write for the
/// [`Message::PrepareBatch`] arm.
pub(crate) const PREPARE_BATCH_CARRIER_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 8 + 8 + 16 + LOG_COUNT_PREFIX;

#[cfg(feature = "tcp")]
/// Fixed bytes a [`PrepareBatch`] encoding wraps around ONE client body when that body is the sole
/// [`Body::Present`] entry retransmitted: the [`PREPARE_BATCH_CARRIER_OVERHEAD`] carrier framing
/// plus one [`LOG_ENTRY_BODY_OVERHEAD`] per-entry framing — byte-identical to
/// [`REPAIR_BATCH_BODY_OVERHEAD`] (the two batch carriers share the envelope + per-entry layout).
/// A committed-band op's full body also rides the retransmit as a one-entry `PrepareBatch`, so a
/// max-size body must fit one of these; it TIES the `RepairBatch` carrier as the binding input to
/// [`MAX_REQUEST_BODY_OVERHEAD`], leaving the bound unchanged.
const PREPARE_BATCH_BODY_OVERHEAD: usize = PREPARE_BATCH_CARRIER_OVERHEAD + LOG_ENTRY_BODY_OVERHEAD;

/// The exact number of bytes one [`Body::Present`] [`PreparedEntry`] of `body_len` body bytes
/// contributes to a `write_log` slice: the per-entry framing [`LOG_ENTRY_BODY_OVERHEAD`] plus the body
/// bytes themselves. Used by the byte-bounded repair serve to accumulate a served prefix without
/// exceeding the frame budget (one source of truth with [`write_log`]'s `Present` arm).
#[cfg_attr(not(tarpaulin), inline(always))]
pub(crate) const fn present_entry_encoded_len(body_len: usize) -> usize {
  LOG_ENTRY_BODY_OVERHEAD + body_len
}

/// The exact encoded size of one HEADER-ONLY ([`Body::Repairing`]) [`PreparedEntry`] in a log slice:
/// `op` (`u64`) + `client` (`u128`) + `request` (`u64`) + the body-state tag (`u8`,
/// [`BODY_TAG_REPAIRING`]) + the 16-byte `body_checksum` (`u128`), NO body bytes. The view-change log
/// carriers (`DoViewChange` / `StartView` / `RecoveryResponse`) emit EVERY entry header-only (see
/// [`Endpoint::log_entries`](crate::Endpoint)), so a whole uncheckpointed band of `d` ops encodes to a
/// fixed `d * PER_HEADER_ENTRY_BYTES + carrier framing` regardless of body sizes — the property
/// [`crate::config::MAX_CHECKPOINT_OPS`] is capped against so even the deepest band fits the frame.
pub(crate) const PER_HEADER_ENTRY_BYTES: usize = 8 + 16 + 8 + 1 + 16;

/// The MAXIMUM header-only band depth (op count) that fits one view-change log carrier under the frame
/// cap, by construction: the frame budget less the largest carrier framing, divided by the fixed
/// per-header-entry size. The carrier framing is the largest of the three strict log carriers — a
/// `DoViewChange` (header + `view`/`log_view`/`op`/`commit`/`checkpoint_op` five `u64`s + the strict
/// `epoch` `u64` + `config_id` `u128` + `replica` `u16` + [`LOG_COUNT_PREFIX`]) and a
/// `RecoveryResponse` (header + four `u64`s + `epoch` `u64` + `config_id` `u128` + `replica` `u16` +
/// `nonce` `u64` + [`LOG_COUNT_PREFIX`]) tie at the larger framing; we use a generous fixed `80`-byte
/// allowance that exceeds either (each is `73`). [`crate::config::MAX_CHECKPOINT_OPS`] is capped so the
/// deepest achievable band `(checkpoint_op .. op]` stays at/below this, making a header-only carrier
/// sub-cap by construction; [`Endpoint::log_entries`](crate::Endpoint) also `debug_assert`s the band
/// against it. The strict carrier grows +24 bytes (epoch + config_id); the per-entry log bytes are
/// UNCHANGED (only the carrier framing grew), so [`PER_HEADER_ENTRY_BYTES`] stays the same.
pub(crate) const MAX_HEADER_ONLY_BAND_DEPTH: usize =
  (MAX_FRAME_LEN as usize - 80) / PER_HEADER_ENTRY_BYTES;

#[cfg(feature = "tcp")]
/// `const` max of two `usize`s ([`usize::max`] is not yet `const` in this MSRV).
const fn max_usize(a: usize, b: usize) -> usize {
  if a > b { a } else { b }
}

#[cfg(feature = "tcp")]
/// The WORST-CASE encoding overhead a single client request body incurs over EVERY message that carries
/// it on its way through the cluster, so a body bounded by `MAX_FRAME_LEN - MAX_REQUEST_BODY_OVERHEAD`
/// encodes to at most the frame cap on its tightest carrier and is therefore deliverable on every hop it
/// causes. The same body bytes are wrapped, in turn, by:
///
/// - the [`Request`] the client sends ([`REQUEST_ENCODE_OVERHEAD`] = 31; AGNOSTIC-NEITHER, no
///   epoch-policy fields),
/// - the [`Prepare`] the primary replicates ([`PREPARE_ENCODE_OVERHEAD`] = 87; STRICT, +24 for
///   `epoch` + `config_id`),
/// - and — once the op is logged — a single [`Body::Present`] [`PreparedEntry`] inside a
///   [`RepairBatch`] ([`REPAIR_BATCH_BODY_OVERHEAD`] = 84; AGNOSTIC, +16 for `config_id`), the windowed
///   peer-repair answer that ships a committed op's full body, or inside a [`PrepareBatch`]
///   ([`PREPARE_BATCH_BODY_OVERHEAD`] = 92; STRICT, +24), the primary's batched retransmit of the
///   un-acked window.
///
/// The view-change log carriers (`DoViewChange` / `StartView` / `RecoveryResponse`) are NOT in
/// this list: they carry every entry HEADER-ONLY (see [`Endpoint::log_entries`](crate::Endpoint)),
/// so they ship NO client body — the binding BODY carriers are the batch slices. The BINDING max is
/// therefore the STRICT `PrepareBatch` carrier (92): the epoch-policy matrix makes it strictly larger
/// than the agnostic `RepairBatch` (84), so the two batch carriers no longer tie — `PrepareBatch` alone
/// is the worst hop, exceeding the `Prepare` hop (87) by the single-entry log framing it wraps the body
/// in. Bounding by `Prepare` alone would let a max-size body retransmitted as a one-entry `PrepareBatch`
/// encode past the frame cap and be dropped, leaving a single max-body committed op unrepairable. The
/// transport's `max_request_body_len()` subtracts exactly this from
/// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN); each batch's per-entry byte cap then
/// guarantees a single served entry (a max body) lands exactly on the cap.
pub const MAX_REQUEST_BODY_OVERHEAD: usize = max_usize(
  max_usize(REQUEST_ENCODE_OVERHEAD, PREPARE_ENCODE_OVERHEAD),
  max_usize(REPAIR_BATCH_BODY_OVERHEAD, PREPARE_BATCH_BODY_OVERHEAD),
);

/// A client request to the primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Request {
  /// Creates a client request.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      client,
      request,
      body,
    }
  }

  /// The issuing client.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The per-client monotonic request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application payload as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application payload as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Primary → backups: replicate a prepared operation. Carries the primary's
/// current commit number (piggybacked) and its latest durable `checkpoint_op` (the state-sync
/// trigger signal — `Commit`/`PrepareOk` carry it too, so a lagging backup that only ever sees a
/// `Prepare` from a fresh primary still learns the cluster's checkpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepare {
  view: View,
  op: OpNumber,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Prepare {
  /// Creates a prepare. `epoch` + `config_id` are the sender's active configuration (the STRICT
  /// epoch-policy pair every consensus carrier carries).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)] // the wire layout, in canonical field order
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    epoch: Epoch,
    config_id: u128,
    client: ClientId,
    request: RequestNumber,
    body: Bytes,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op,
      epoch,
      config_id,
      client,
      request,
      body,
    }
  }

  /// The view in which this prepare was created.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The op number assigned to this operation.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The primary's commit number at send time.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number of the sender's latest durable checkpoint (the state-sync trigger signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The issuing client.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The client request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application payload as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application payload as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Backup → primary: acknowledge a prepared op.
///
/// The vote is CONTENT-ADDRESSED by the prepare's full IDENTITY: it carries the `prepare_checksum` over
/// `(client, request, body_checksum)` of the operation this replica holds at `op`, so the primary counts
/// it toward a commit quorum only if it matches the operation the primary is itself driving at that op
/// (`on_prepare_ok`). This mirrors TigerBeetle's `(op, prepare_checksum)` vote namespace: a stale ack for
/// an op number that was truncated and re-minted for a DIFFERENT operation — even one with the same body
/// bytes — has a different identity and is dropped, never counted, closing the op-reuse vote-forging
/// class by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOk {
  view: View,
  op: OpNumber,
  replica: ReplicaId,
  checkpoint_op: OpNumber,
  prepare_checksum: u128,
  epoch: Epoch,
  config_id: u128,
}

impl PrepareOk {
  /// Creates a prepare acknowledgement. `prepare_checksum` is the operation IDENTITY content address
  /// (`prepare_identity` over `(client, request, body_checksum)`) of the operation the acking replica
  /// holds at `op` — the address the primary's `on_prepare_ok` matches the vote against before counting
  /// it. `epoch` + `config_id` are the sender's active configuration (the STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)] // the wire layout, in canonical field order
  pub const fn new(
    view: View,
    op: OpNumber,
    replica: ReplicaId,
    checkpoint_op: OpNumber,
    prepare_checksum: u128,
    epoch: Epoch,
    config_id: u128,
  ) -> Self {
    Self {
      view,
      op,
      replica,
      checkpoint_op,
      prepare_checksum,
      epoch,
      config_id,
    }
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The view of the acknowledged prepare.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number acknowledged.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The acknowledging replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The op number of the sender's latest durable checkpoint (the quorum signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The operation IDENTITY content address (`prepare_identity` over `(client, request, body_checksum)`)
  /// of the op this replica holds at `op` — the address the primary matches against the operation it is
  /// driving at that op before counting the vote.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn prepare_checksum(&self) -> u128 {
    self.prepare_checksum
  }
}

/// Primary → client: the result of a committed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
  view: View,
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Reply {
  /// Creates a client reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(view: View, client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      view,
      client,
      request,
      body,
    }
  }

  /// The view that produced the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The client the reply is for.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The request number this reply answers.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application result as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application result as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Primary → backups: commit heartbeat advancing the commit number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
  view: View,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
}

impl Commit {
  /// Creates a commit heartbeat. `epoch` + `config_id` are the sender's active configuration (the
  /// STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    epoch: Epoch,
    config_id: u128,
  ) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
      epoch,
      config_id,
    }
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The primary's commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number of the primary's latest durable checkpoint (the quorum signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }
}

/// Settled member → a strictly-LOWER-epoch peer: a minimal cross-epoch catch-up HINT. It carries the
/// responder's current `epoch` + `checkpoint_op` and NOTHING else — no view, no vote/lead/quorum
/// authority, no op/commit/log content. It is a pure SIGNAL: "a configuration ahead of yours exists;
/// here is the cluster checkpoint to cross to."
///
/// The need: a reconfiguration that REMOVES the old primary (or shifts slots) makes the honest E+1
/// primary a DIFFERENT retained voter — possibly one a stale laggard cannot even bind on the live
/// transport (its `MemberId` is absent from the laggard's old membership), or whose higher-epoch
/// heartbeat never reaches the laggard. The stranded laggard then keeps sending FUTILE old-epoch
/// traffic (its `primary_idle` view-change SVC/DVC) to the RETAINED voters it CAN bind — but those
/// drop it as epoch-inadmissible, so the laggard never gets the higher-epoch trigger it needs. A
/// retained voter ANSWERS that strictly-lower-epoch message with this hint, so the laggard PULLS a
/// trigger back from a BINDABLE retained peer it already knows; it never needs to bind the new primary.
///
/// It carries NO authority a forged one could abuse: the laggard acts on it ONLY as a rate-limited
/// sync TRIGGER ([`Endpoint::maybe_request_cross_epoch_catchup`](crate::Endpoint)) — the forced
/// cross-epoch peer-fetch it drives is crossing-required and self-verifying (the fetched
/// `SyncCheckpoint`'s `checkpoint_id` + the successor's `config_id` hash-chain are checked in
/// `apply_sync`), so a forged hint installs no unvouched state. It is rate-limited by construction
/// (one hint per inbound stale message; the laggard's own stale traffic is timer-bounded) and
/// self-terminating (the laggard crosses and stops emitting stale traffic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochAhead {
  epoch: Epoch,
  checkpoint_op: OpNumber,
}

impl EpochAhead {
  /// Creates a cross-epoch catch-up hint advertising the responder's current `epoch` and the cluster
  /// `checkpoint_op` to cross to.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(epoch: Epoch, checkpoint_op: OpNumber) -> Self {
    Self {
      epoch,
      checkpoint_op,
    }
  }

  /// The responder's current configuration epoch (strictly ahead of the recipient's).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The cluster checkpoint op the recipient must cross to (the forced peer-fetch target).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }
}

/// Learner → current configuration members: a NON-VOTING progress report of the learner's DURABLE
/// frontier. It carries NO quorum/vote authority — it is never counted toward any commit, view-change,
/// or recovery quorum; it only lets the primary learn how far a learner has durably caught up so the
/// learner-promote gate ([`Endpoint::propose_membership`](crate::Endpoint)) can require an exact
/// catch-up before minting the `PromoteLearner` Reconfigure op (catch-up-then-promote, the safety gate
/// in the reconfiguration design: a behind new-voter's low-frontier `DoViewChange` could push the
/// nack-truncation crossing down and truncate a committed-but-not-yet-widely-replicated op).
///
/// `durable_commit_min` is the learner's CONTIGUOUS APPLIED FRONTIER (`commit_min`) — the highest op
/// below which there is NO hole — NOT its durable known-committed frontier (`commit_max`): a sparse-band
/// recovered learner can KNOW a high commit point while a missing / `Repairing` committed op below it
/// still blocks apply, and the promote gate must admit it only once it durably HOLDS the whole prefix
/// it will vote on. The applied frontier is durably recoverable (every applied op was durably appended
/// before apply and lives below `commit_max`), so a crash can never make a learner claim more than it
/// can reconstruct. `durable_op` is the durable WAL head (`op_head`), a backstop the receiver caps the
/// reported frontier with. It is CONFIG-SCOPED progress, carrying the STRICT epoch-policy pair (`epoch` +
/// `config_id`) so it is admitted only from a member of the SAME configuration (a foreign-config
/// learner's progress is not this primary's to act on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LearnerStatus {
  replica: ReplicaId,
  durable_commit_min: OpNumber,
  durable_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
}

impl LearnerStatus {
  /// Creates a learner progress report. `replica` is the sender's own slot; `durable_commit_min` is its
  /// CONTIGUOUS APPLIED FRONTIER (`commit_min`, not the durable known-committed `commit_max` — see the
  /// type docs) and `durable_op` is its durable WAL head; `epoch` + `config_id` are the sender's active
  /// configuration (the STRICT epoch-policy pair). Carries no vote.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    replica: ReplicaId,
    durable_commit_min: OpNumber,
    durable_op: OpNumber,
    epoch: Epoch,
    config_id: u128,
  ) -> Self {
    Self {
      replica,
      durable_commit_min,
      durable_op,
      epoch,
      config_id,
    }
  }

  /// The reporting learner's slot.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The reporting learner's CONTIGUOUS APPLIED FRONTIER (`commit_min`) — the highest op below which it
  /// has NO hole, hence durably holds every op of the prefix and recovers to at least it after a crash.
  /// NOT the durable known-committed frontier (`commit_max`), which can exceed it past a repair hole.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn durable_commit_min(&self) -> OpNumber {
    self.durable_commit_min
  }

  /// The reporting learner's DURABLE head op (its durable WAL head).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn durable_op(&self) -> OpNumber {
    self.durable_op
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }
}

/// Primary → a target learner: a FRESH-PROOF SOLICITATION the primary issues at
/// [`PromoteLearner`](crate::SingleVoterDelta) propose time. It carries NO quorum/vote authority — it
/// is a request, never a vote — and asks the learner: "prove you durably hold the contiguous committed
/// prefix through `at_op`, NOW."
///
/// The promote gate ([`Endpoint::propose_membership`](crate::Endpoint)) is SAFETY-critical: a learner
/// it admits into the voting set must already durably hold the full committed prefix it will vote on,
/// or the successor view-change quorum can drop a committed op. A learner's self-reported frontier
/// ([`LearnerStatus`]) is unsafe to gate on directly, because a crash/disk-fault honestly REGRESSES
/// the frontier while a stale-high accumulated value survives. So the gate re-grounds the safety input
/// in the learner's durable storage AT PROPOSE TIME with this round-trip instead: the primary issues a
/// challenge bound to `(nonce, at_op, epoch, config_id)`, and only a matching fresh [`LearnerProof`]
/// reporting a frontier `>= at_op` lets the promotion mint. `at_op` is the primary's current head (the
/// prospective Reconfigure op's predecessor frontier); `nonce` is a per-incarnation freshness token
/// binding the reply; `epoch` + `config_id` are the proposer's active configuration (the STRICT
/// epoch-policy pair), so a learner answers only for its live config and a cross-epoch reply never
/// satisfies a later mint. `from` is the primary's own slot (the standard sender binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLearnerProof {
  from: ReplicaId,
  at_op: OpNumber,
  nonce: u64,
  epoch: Epoch,
  config_id: u128,
}

impl RequestLearnerProof {
  /// Creates a learner-proof challenge. `from` is the soliciting primary's own slot; `at_op` is the
  /// head the learner must prove it durably holds the contiguous committed prefix through; `nonce` is
  /// the per-incarnation freshness token; `epoch` + `config_id` are the proposer's active configuration
  /// (the STRICT epoch-policy pair). Carries no vote.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    from: ReplicaId,
    at_op: OpNumber,
    nonce: u64,
    epoch: Epoch,
    config_id: u128,
  ) -> Self {
    Self {
      from,
      at_op,
      nonce,
      epoch,
      config_id,
    }
  }

  /// The soliciting primary's own slot.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn from(&self) -> ReplicaId {
    self.from
  }

  /// The head the learner must prove it durably holds the contiguous committed prefix through.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn at_op(&self) -> OpNumber {
    self.at_op
  }

  /// The per-incarnation freshness token binding the matching [`LearnerProof`] reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The proposer's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The proposer's configuration lineage id (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }
}

/// Target learner → the soliciting primary: the FRESH-PROOF REPLY answering a [`RequestLearnerProof`].
/// It carries NO quorum/vote authority — it is a reply, never a vote — and reports the learner's
/// contiguous applied frontier (`commit()` == `commit_min`, the hole-free durably-recoverable prefix)
/// RECOMPUTED FROM DURABLE STATE AT REPLY TIME.
///
/// Computing `frontier` fresh is the load-bearing property (see [`RequestLearnerProof`]): a
/// just-crashed learner answers with its regressed (lower) frontier, and a learner mid-crash never
/// answers at all — so no remembered high-water survives the fault that invalidated it. `nonce` is
/// echoed verbatim from the challenge so the primary binds the reply to the exact outstanding
/// challenge; `epoch` + `config_id` are the learner's active configuration (the STRICT epoch-policy
/// pair), so a cross-epoch reply never validates against a later mint. `replica` is the learner's own
/// slot (the standard sender binding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LearnerProof {
  replica: ReplicaId,
  nonce: u64,
  frontier: OpNumber,
  epoch: Epoch,
  config_id: u128,
}

impl LearnerProof {
  /// Creates a learner-proof reply. `replica` is the answering learner's own slot; `nonce` is echoed
  /// from the challenge; `frontier` is the learner's CONTIGUOUS APPLIED FRONTIER (`commit_min`)
  /// recomputed from durable state at reply time; `epoch` + `config_id` are the learner's active
  /// configuration (the STRICT epoch-policy pair). Carries no vote.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    replica: ReplicaId,
    nonce: u64,
    frontier: OpNumber,
    epoch: Epoch,
    config_id: u128,
  ) -> Self {
    Self {
      replica,
      nonce,
      frontier,
      epoch,
      config_id,
    }
  }

  /// The answering learner's own slot.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness token echoed from the soliciting [`RequestLearnerProof`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The learner's CONTIGUOUS APPLIED FRONTIER (`commit_min`) recomputed from durable state at reply
  /// time — the highest op below which it has NO hole, hence durably holds every op of the prefix and
  /// recovers to at least it after a crash.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn frontier(&self) -> OpNumber {
    self.frontier
  }

  /// The learner's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The learner's configuration lineage id (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }
}

/// The successor membership carried by a consensus-layer `Body::Reconfigure` op: the full member
/// list plus the voting/learner split (`replica_count` + `learner_count`), PLUS the `config_id` of the
/// PREDECESSOR configuration the successor chains from. The proposing primary computes the successor
/// once (via [`Membership::apply_delta`](crate::Membership)) at propose time and encodes the RESULT
/// here, so every replica installs the IDENTICAL successor at commit with no re-computation.
///
/// The successor's own `epoch`/`config_id` are NOT carried — each committer chains them from the
/// predecessor via [`Self::to_membership`]. But the PREDECESSOR `config_id` IS carried (`prev_config_id`)
/// and is LOAD-BEARING for consensus safety: the successor `(epoch, config_id)` derivation chains off
/// the predecessor (`epoch+1`, `config_id = hash(.., prev_config_id)`), so it is correct ONLY when the
/// committer chains from the EXACT predecessor this op was proposed against. A committer at a DIFFERENT
/// configuration (e.g. one that already installed this op's swap, then had its `commit_min` regress
/// below the op via a state-sync/recovery install and re-reached it) would otherwise chain off the WRONG
/// (already-successor) configuration and derive a FORKED grand-successor — a divergent membership swap of
/// the one committed reconfiguration. Pinning `prev_config_id` lets the commit path GATE the swap on
/// `self.membership.config_id() == prev_config_id`, so it stages exactly once, off the right predecessor,
/// on every replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconfigurePayload {
  replica_count: u8,
  learner_count: u16,
  members: Box<[MemberId]>,
  /// The `config_id` of the predecessor configuration this successor chains from — the proposer's
  /// current `config_id` at propose time. Identifies the EXACT predecessor (it hashes the predecessor's
  /// epoch + members + its own predecessor), so the commit-time gate `self.membership.config_id() ==
  /// prev_config_id` admits the swap only off that one configuration.
  prev_config_id: u128,
}

impl ReconfigurePayload {
  /// Creates a payload from the raw successor parts (the voting count, the learner count, the full
  /// member list) and the predecessor `config_id` the successor chains from. The structural invariants
  /// are NOT re-validated here — the proposing primary builds this from a
  /// [`Membership`](crate::Membership) the [`apply_delta`](crate::Membership::apply_delta) path already
  /// validated, and the decode boundary re-checks them via [`Self::to_membership`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    replica_count: u8,
    learner_count: u16,
    members: Box<[MemberId]>,
    prev_config_id: u128,
  ) -> Self {
    Self {
      replica_count,
      learner_count,
      members,
      prev_config_id,
    }
  }

  /// Captures the successor membership's voting/learner split and member list from a built
  /// [`Membership`](crate::Membership), plus the `prev_config_id` of the predecessor it chains from
  /// (the proposer's current `config_id`). The successor's own `epoch`/`config_id` are re-derived from
  /// the predecessor at install time; the predecessor id is pinned so every committer chains off the
  /// SAME predecessor (see the type docs).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn from_membership(m: &Membership, prev_config_id: u128) -> Self {
    Self {
      replica_count: m.replica_count(),
      learner_count: m.learner_count(),
      members: m.members_slice().into(),
      prev_config_id,
    }
  }

  /// The number of voting replicas in the successor configuration.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica_count(&self) -> u8 {
    self.replica_count
  }

  /// The number of non-voting learner replicas in the successor configuration.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn learner_count(&self) -> u16 {
    self.learner_count
  }

  /// The successor member list, indexed by [`ReplicaId`](crate::ReplicaId) slot.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn members(&self) -> &[MemberId] {
    &self.members
  }

  /// The `config_id` of the predecessor configuration this successor chains from — pinned at propose
  /// time so every committer derives the successor off the SAME predecessor (see the type docs). The
  /// commit path gates the swap on `self.membership.config_id() == prev_config_id`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn prev_config_id(&self) -> u128 {
    self.prev_config_id
  }

  /// Rebuilds the full successor [`Membership`](crate::Membership), supplying the `epoch` and
  /// `config_id` the committing replica derives from its predecessor configuration (the payload itself
  /// carries neither — see the type docs). Re-validates the structural invariants (non-zero
  /// `replica_count`, the 64-voter cap, member-count agreement, no duplicate members), returning a
  /// [`MembershipError`](crate::MembershipError) if the decoded successor is structurally invalid.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn to_membership(
    &self,
    epoch: Epoch,
    config_id: u128,
  ) -> Result<Membership, MembershipError> {
    Membership::from_durable_parts(
      epoch,
      self.replica_count,
      self.learner_count,
      self.members.to_vec(),
      config_id,
    )
  }

  /// Reconstruct the successor [`Membership`](crate::Membership) for the supplied `(epoch, config_id)`
  /// AND VERIFY that the carried parts genuinely hash to that `config_id` — the cross-epoch state-sync
  /// install gate ("never install an unverifiable configuration"). Unlike [`Self::to_membership`] (the
  /// durable-root decode path, which trusts the checksum-protected `config_id`), a state-sync answer
  /// crosses the network from a peer at a configuration the laggard cannot otherwise admit, so its
  /// claimed `config_id` is RECOMPUTED from `(epoch, replica_count, learner_count, members,
  /// prev_config_id)` (the payload pins the predecessor id) and checked against `config_id`. Returns
  /// [`MembershipError::ForkedConfigId`](crate::MembershipError) on mismatch (a forged / corrupt /
  /// wrong-lineage successor) and the structural [`MembershipError`](crate::MembershipError) variants on
  /// an invalid member set — the caller installs ONLY on `Ok`.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn to_membership_verified(
    &self,
    epoch: Epoch,
    config_id: u128,
  ) -> Result<Membership, MembershipError> {
    let recomputed = Membership::recompute_config_id(
      epoch,
      self.replica_count,
      self.learner_count,
      &self.members,
      self.prev_config_id,
    );
    if recomputed != config_id {
      return Err(MembershipError::ForkedConfigId);
    }
    self.to_membership(epoch, config_id)
  }

  /// The canonical wire encoding of this payload (`replica_count`, `learner_count`, then the member
  /// list) as owned [`Bytes`] — the body a proposing primary stores in the WAL and carries in the
  /// `Prepare` for a `Body::Reconfigure` op. Identical to what [`write_reconfigure`] emits, so the
  /// op's `body_checksum` (an `fnv1a_128` over the same bytes) matches `fnv1a_128(encode_body())` by
  /// construction.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn encode_body(&self) -> Bytes {
    let mut buf = Vec::with_capacity(1 + 2 + 4 + self.members.len() * 16 + 16);
    write_reconfigure(&mut buf, self);
    Bytes::from(buf)
  }

  /// Decodes the canonical wire body [`Self::encode_body`] produced back into a `ReconfigurePayload`.
  /// The backup-side `on_prepare` recognizes a [`ClientId::RECONFIGURATION`](crate::ClientId)
  /// `Prepare` and round-trips its flat `body` bytes through here to store a typed `Body::Reconfigure`
  /// log entry — so the committed op carries ONE representation (`Body::Reconfigure`) on the primary
  /// AND every backup, and commit-time recognition is a `match`, never a re-decode. The member-count
  /// prefix is validated against the remaining bytes before any allocation (a hostile count cannot
  /// drive an unbounded pre-allocation), and any trailing bytes are rejected (`finish`).
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn decode_body(bytes: &[u8]) -> Result<Self, CodecError> {
    let mut r = Reader::new(bytes);
    let payload = read_reconfigure(&mut r)?;
    r.finish()?;
    Ok(payload)
  }

  /// The canonical `body_checksum` of this Reconfigure op: an `fnv1a_128` over the payload's canonical
  /// encoding (`replica_count`, `learner_count`, then the member list), so two DISTINCT successor
  /// memberships content-address differently and a Reconfigure op folds into
  /// [`prepare_identity`](crate::storage) like any op.
  #[cfg_attr(not(tarpaulin), inline)]
  fn body_checksum(&self) -> u128 {
    crate::storage::fnv1a_128(&self.encode_body())
  }
}

/// A log entry's body is `Present` (the bytes are held), `Repairing` (only the durable canonical
/// `body_checksum` is known; the bytes must be peer-repaired), or `Reconfigure` (a consensus-layer
/// membership-change op carrying the full successor membership).
///
/// Body-independent durable headers let a committed op's EXISTENCE survive a torn-body storage
/// fault: the op stays in the log as a `Repairing` slot carrying just its canonical `body_checksum`,
/// and the commit path holds at it (soliciting the body from a peer) exactly as it does for a
/// wholly-missing slot. This ONE type is shared by the endpoint's in-memory `LogEntry` and the wire
/// [`PreparedEntry`], so a `Repairing` op carried through a `DoViewChange`/`StartView` is adopted
/// repair-pending — its op number is taken (never re-minted) and its body is fetched from a peer.
///
/// A `Reconfigure` body rides the replicated log like a client op (committed under the OLD epoch; the
/// epoch swap fires at commit), but its content is the successor [`ReconfigurePayload`] rather than an
/// opaque client body — so it carries no client bytes (`as_present` is `None`) and its
/// `body_checksum` folds the successor membership into the operation identity. Not `Copy` — `Present`
/// carries a [`Bytes`] and `Reconfigure` a boxed member list.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref)]
#[try_unwrap(ref)]
pub enum Body {
  /// The body bytes are held.
  Present(Bytes),
  /// The body is absent (torn / not-yet-repaired); only the durable canonical `body_checksum` is
  /// known. The bytes must be peer-repaired before the op can apply.
  ///
  /// Constructed in production by `recover` (a committed/kept op whose WAL read came back body-faulty
  /// — durable header, torn/rotted body — is retained header-only as this hole, so its existence
  /// survives the fault and the commit path peer-repairs the body on demand).
  Repairing(u128),
  /// A consensus-layer reconfiguration op carrying the full successor membership. Replicated and
  /// committed under the old epoch like a client op; at commit it triggers the epoch swap. Carries no
  /// client bytes — its content is the [`ReconfigurePayload`].
  Reconfigure(ReconfigurePayload),
}

impl Body {
  /// The body bytes when [`Present`](Body::Present), else `None` (a `Repairing` slot has no bytes
  /// yet, and a `Reconfigure` op carries a membership, not client bytes).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_present(&self) -> Option<&[u8]> {
    match self {
      Body::Present(bytes) => Some(bytes),
      Body::Repairing(_) | Body::Reconfigure(_) => None,
    }
  }

  /// The successor membership when [`Reconfigure`](Body::Reconfigure), else `None`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_reconfigure(&self) -> Option<&ReconfigurePayload> {
    match self {
      Body::Reconfigure(payload) => Some(payload),
      Body::Present(_) | Body::Repairing(_) => None,
    }
  }

  /// The canonical WIRE body bytes of this entry when it is BODY-BEARING — the held bytes when
  /// [`Present`](Body::Present), the `encode_body()` of the successor membership when
  /// [`Reconfigure`](Body::Reconfigure) — else `None` for a header-only [`Repairing`](Body::Repairing)
  /// slot (which carries only its `body_checksum`).
  ///
  /// This is the SINGLE abstraction every body-transport / storage path routes through (prepare
  /// retransmit, repair serve, the new-primary adopted-tail re-append, the header-only-adoption local-body
  /// preserve, the faulted-append retry): a `Reconfigure` op is body-bearing exactly like a client op — its
  /// successor-membership bytes are what the WAL stores and a `Prepare` carries, and
  /// `fnv1a_128(body_bytes())` equals [`body_checksum`](Self::body_checksum) by construction, so a peer
  /// reconstructing a [`ClientId::RECONFIGURATION`](crate::ClientId) prepare from these bytes rebuilds the
  /// identical typed `Body::Reconfigure`. Pattern-matching only `Body::Present` on such a path would treat
  /// a `Reconfigure` entry as carrying no body — dropping or failing to transmit the reconfiguration
  /// payload. ONLY `Repairing` is body-less (it is itself awaiting peer-repair).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn body_bytes(&self) -> Option<Bytes> {
    match self {
      Body::Present(bytes) => Some(bytes.clone()),
      Body::Reconfigure(payload) => Some(payload.encode_body()),
      Body::Repairing(_) => None,
    }
  }

  /// `true` iff this entry is BODY-BEARING — it has wire body bytes to transmit / store
  /// ([`Present`](Body::Present) or [`Reconfigure`](Body::Reconfigure)); `false` for a header-only
  /// [`Repairing`](Body::Repairing) slot. The predicate companion of [`body_bytes`](Self::body_bytes) for
  /// the call sites that only need to SKIP a header-only hole, not extract its bytes.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_body_bearing(&self) -> bool {
    !self.is_repairing()
  }

  /// The canonical `body_checksum` of this op — total: computed from the bytes when
  /// [`Present`](Body::Present), the stored durable checksum when [`Repairing`](Body::Repairing), or
  /// derived from the successor membership when [`Reconfigure`](Body::Reconfigure).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_checksum(&self) -> u128 {
    match self {
      Body::Present(bytes) => crate::storage::fnv1a_128(bytes),
      Body::Repairing(checksum) => *checksum,
      Body::Reconfigure(payload) => payload.body_checksum(),
    }
  }
}

/// One log entry carried in a `DoViewChange`/`StartView` (the prepared op). Its `Body` is either
/// `Present` (the bytes) or `Repairing` (only the durable `body_checksum`; the body is fetched from a
/// peer after adoption). A `Repairing` entry exists ONLY to carry a body-faulty-but-header-durable
/// committed op through a view change so its op number is never re-minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEntry {
  op: OpNumber,
  client: ClientId,
  request: RequestNumber,
  body: Body,
}

impl PreparedEntry {
  /// Creates a prepared-log entry whose body bytes are held (a `Body::Present` entry) — the common
  /// case (every path that knows the body builds one of these).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(op: OpNumber, client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      op,
      client,
      request,
      body: Body::Present(body),
    }
  }

  /// Creates a header-only (`Body::Repairing`) prepared-log entry carrying only the op's durable
  /// `body_checksum` — a body-faulty committed op whose existence is carried through the view change
  /// so its op number is taken (never re-minted); the body is peer-repaired after adoption.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn repairing(
    op: OpNumber,
    client: ClientId,
    request: RequestNumber,
    body_checksum: u128,
  ) -> Self {
    Self {
      op,
      client,
      request,
      body: Body::Repairing(body_checksum),
    }
  }

  /// Creates a consensus-layer reconfiguration prepared-log entry (`Body::Reconfigure`) carrying the
  /// full successor membership. The op keeps a `(client, request)` identity — minted by the proposing
  /// primary for dedup/content-addressing — like any op.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn reconfigure(
    op: OpNumber,
    client: ClientId,
    request: RequestNumber,
    payload: ReconfigurePayload,
  ) -> Self {
    Self {
      op,
      client,
      request,
      body: Body::Reconfigure(payload),
    }
  }

  /// The op number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The issuing client.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The client request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The entry's body-state — `Present` (bytes held) or `Repairing`
  /// (header-only, body peer-repaired after adoption).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn body_state(&self) -> &Body {
    &self.body
  }

  /// `true` iff this entry is header-only (`Body::Repairing`) — its body must be peer-repaired.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_repairing(&self) -> bool {
    self.body.is_repairing()
  }

  /// `true` iff this entry is a consensus-layer reconfiguration op (`Body::Reconfigure`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_reconfigure(&self) -> bool {
    self.body.is_reconfigure()
  }

  /// The opaque application payload as a slice when the body is `Present`, else
  /// `None` (a `Repairing` entry carries no bytes — only its `body_checksum`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> Option<&[u8]> {
    self.body.as_present()
  }

  /// The canonical `body_checksum` of this op — total: from the bytes when
  /// `Present`, or the stored durable checksum when `Repairing`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_checksum(&self) -> u128 {
    self.body.body_checksum()
  }

  /// Consumes the entry into its `(op, client, request, body)` parts, MOVING the decoded
  /// `Body::Present` bytes out rather than copying them — the consuming counterpart of the borrow
  /// accessors, for callers (e.g. the `RepairBatch` fill path) that own the entry and would otherwise
  /// re-copy a body the decode boundary already owns.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_parts(self) -> (OpNumber, ClientId, RequestNumber, Body) {
    (self.op, self.client, self.request, self.body)
  }
}

/// Backup → all: "leave the current view" (TB exit_view). `view` is the view to ENTER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartViewChange {
  view: View,
  replica: ReplicaId,
  epoch: Epoch,
  config_id: u128,
}

impl StartViewChange {
  /// Creates a StartViewChange. `epoch` + `config_id` are the sender's active configuration (the
  /// STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, replica: ReplicaId, epoch: Epoch, config_id: u128) -> Self {
    Self {
      view,
      replica,
      epoch,
      config_id,
    }
  }

  /// The view this replica proposes to enter.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The sending replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }
}

/// Replica → prospective new primary (TB join_view): the sender's full log + position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoViewChange {
  view: View,
  log_view: View,
  op: OpNumber,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
  replica: ReplicaId,
  log: Vec<PreparedEntry>,
}

impl DoViewChange {
  /// Creates a DoViewChange with no checkpoint floor advertised (`checkpoint_op` 0 — the
  /// never-checkpointed sender's form). A sender with a durable-checkpoint-vouched log floor chains
  /// [`Self::with_checkpoint_op`]. `epoch` + `config_id` are the sender's active configuration (the
  /// STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)] // the wire layout, in canonical field order
  pub fn new(
    view: View,
    log_view: View,
    op: OpNumber,
    commit: OpNumber,
    epoch: Epoch,
    config_id: u128,
    replica: ReplicaId,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      log_view,
      op,
      commit,
      checkpoint_op: OpNumber::new(),
      epoch,
      config_id,
      replica,
      log,
    }
  }

  /// Sets the advertised checkpoint floor (see [`Self::checkpoint_op`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn with_checkpoint_op(mut self, checkpoint_op: OpNumber) -> Self {
    self.checkpoint_op = checkpoint_op;
    self
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The view being entered.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The latest view in which the sender changed its head log.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn log_view(&self) -> View {
    self.log_view
  }

  /// The sender's head op.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The sender's commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The durable-checkpoint-vouched floor of the carried log: every op at/below it that `log_slice`
  /// omits is folded into SOME durable cluster checkpoint (the sender's own, or a canonical donor's
  /// it learned at a prior floored adoption), so an omitted op `<= checkpoint_op` is checkpoint-
  /// subsumed — state-sync territory, never a repairable-by-prepare hole. `select_canonical_log`
  /// takes the canonical generation's MAX as the union floor: checkpoint-subsumed ops do not ride
  /// the view change, which is what keeps the floored union's carrier under the frame cap.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The sending replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The sender's in-memory log as a slice — the OFFSET tail `(checkpoint .. op]` for a
  /// recover-from-checkpoint / state-synced sender (its committed prefix lives in its SM snapshot),
  /// or dense `[1..=op]` otherwise. The new primary's `select_canonical_log` is offset-aware and
  /// UNIONs these across DVCs, so an offset slice drops no committed op at view change.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the log vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// New primary → all backups (TB view): the canonical log + new view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartView {
  view: View,
  op: OpNumber,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
  replica: ReplicaId,
  log: Vec<PreparedEntry>,
}

impl StartView {
  /// Creates a StartView with no checkpoint floor advertised (`checkpoint_op` 0). A primary with a
  /// durable-checkpoint-vouched log floor chains [`Self::with_checkpoint_op`]. `epoch` + `config_id`
  /// are the sender's active configuration (the STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)] // the wire layout, in canonical field order
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    epoch: Epoch,
    config_id: u128,
    replica: ReplicaId,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op: OpNumber::new(),
      epoch,
      config_id,
      replica,
      log,
    }
  }

  /// Sets the advertised checkpoint floor (see [`Self::checkpoint_op`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn with_checkpoint_op(mut self, checkpoint_op: OpNumber) -> Self {
    self.checkpoint_op = checkpoint_op;
    self
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The new view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The canonical head op.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The canonical commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The durable-checkpoint-vouched floor of the carried canonical log: every op at/below it that
  /// `log_slice` omits is folded into a durable cluster checkpoint (the new primary's own, or a
  /// canonical DVC donor's — the union floor `select_canonical_log` applied). An adopter below this
  /// floor trims its own retained sub-floor band (checkpoint-subsumed — must not be re-carried) and
  /// records the floor so its force-sync escalation can recover the sub-floor gap from a snapshot.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The new primary.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The canonical log as a slice — the new primary's UNIONed offset tail `(min_floor .. op]`,
  /// which an adopter merges with its own preserved committed ops (it is not necessarily dense
  /// `[1..=op]` if the primary itself checkpointed/state-synced).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the log vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// Lagging backup → prospective primary (TB get_view): request the current `StartView`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetView {
  view: View,
  replica: ReplicaId,
  nonce: u64,
  epoch: Epoch,
  config_id: u128,
}

impl GetView {
  /// Creates a GetView. `epoch` + `config_id` are the sender's active configuration (the STRICT
  /// epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    replica: ReplicaId,
    nonce: u64,
    epoch: Epoch,
    config_id: u128,
  ) -> Self {
    Self {
      view,
      replica,
      nonce,
      epoch,
      config_id,
    }
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The view being requested.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The requesting replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// Freshness nonce echoed in the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// Replica → peers (TB request_prepare): solicit a single committed op whose body this replica read
/// back permanently faulty (bit-rot / torn) from its own durable WAL. A replica holding a hole at a
/// committed op `op` (below its head, above its applied frontier) broadcasts this; any peer that
/// holds `op` answers with the [`Prepare`] carrying it. The repair fills the hole so the replica can
/// resume applying its committed prefix in order — it NEVER advances its commit past the hole until
/// the op arrives. The view is carried for routing/freshness; the op's committed content is
/// view-independent, so a reply from any view that holds `op` is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPrepare {
  view: View,
  op: OpNumber,
  replica: ReplicaId,
  config_id: u128,
}

impl RequestPrepare {
  /// Creates a RequestPrepare for the missing committed op `op`. `config_id` is the sender's active
  /// configuration lineage (the AGNOSTIC epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, op: OpNumber, replica: ReplicaId, config_id: u128) -> Self {
    Self {
      view,
      op,
      replica,
      config_id,
    }
  }

  /// The sender's configuration lineage id (the agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The requester's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number being requested (a committed op missing locally).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The requesting replica (the reply is addressed back to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }
}

/// Replica → peers (the windowed analogue of [`RequestPrepare`]): solicit a CONTIGUOUS RUN of
/// committed ops `[lo, hi]` this replica is missing/repairing below its head, in ONE message. A
/// far-behind replica that adopted a deep header-only band (e.g. a view-change carrier carried the
/// whole uncheckpointed log as header-only `Repairing` holes) would, with the per-op [`RequestPrepare`]
/// path, need one round trip per op — never converging in a calm window. This range request lets a
/// holder serve a BYTE-BOUNDED PREFIX of the run as one [`RepairBatch`]; the requester re-solicits the
/// unserved tail on the next pass. Broadcast like [`RequestPrepare`]; the view is carried for
/// routing/freshness only — a committed op's content is view-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPrepareRange {
  view: View,
  lo: OpNumber,
  hi: OpNumber,
  replica: ReplicaId,
  config_id: u128,
}

impl RequestPrepareRange {
  /// Creates a RequestPrepareRange for the contiguous missing committed run `[lo, hi]`. `config_id` is
  /// the sender's active configuration lineage (the AGNOSTIC epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    lo: OpNumber,
    hi: OpNumber,
    replica: ReplicaId,
    config_id: u128,
  ) -> Self {
    Self {
      view,
      lo,
      hi,
      replica,
      config_id,
    }
  }

  /// The sender's configuration lineage id (the agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The requester's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The low (inclusive) op of the requested run.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn lo(&self) -> OpNumber {
    self.lo
  }

  /// The high (inclusive) op of the requested run.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn hi(&self) -> OpNumber {
    self.hi
  }

  /// The requesting replica (the [`RepairBatch`] reply is addressed back to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }
}

/// Recovering replica → all (TB recovery): solicit the canonical head when the local head slot is
/// permanently faulty. A `RecoveringHead` replica that cannot trust its own durable head broadcasts
/// this; peers answer with a [`RecoveryResponse`]. The `nonce` is a freshness token echoed back so a
/// stale response (from a prior recovery attempt) is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
  replica: ReplicaId,
  nonce: u64,
  epoch: Epoch,
  config_id: u128,
}

impl Recovery {
  /// Creates a Recovery solicitation. `epoch` + `config_id` are the sender's active configuration (the
  /// STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(replica: ReplicaId, nonce: u64, epoch: Epoch, config_id: u128) -> Self {
    Self {
      replica,
      nonce,
      epoch,
      config_id,
    }
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The recovering replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// Freshness nonce echoed in the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// Replica → recovering replica (TB recovery response): the sender's view, position, and — from the
/// view's primary — its canonical log + head + commit, so a `RecoveringHead` replica can re-establish
/// a head it cannot read locally. A non-primary answers with only its view + echoed `nonce` (empty
/// `log`, zero `op`/`commit`): it has no authority to hand out a canonical head, but its view lets the
/// recovering replica learn the current generation. The `nonce` echoes the soliciting [`Recovery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResponse {
  view: View,
  op: OpNumber,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
  replica: ReplicaId,
  nonce: u64,
  log: Vec<PreparedEntry>,
}

impl RecoveryResponse {
  /// Creates a RecoveryResponse. The primary fills `op`/`commit`/`log` from its canonical state and
  /// chains [`Self::with_checkpoint_op`] for its vouched log floor; a backup passes `op = commit = 0`
  /// and an empty `log` (view + nonce only, no floor). `epoch` + `config_id` are the sender's active
  /// configuration (the STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)] // the wire layout, in canonical field order
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    epoch: Epoch,
    config_id: u128,
    replica: ReplicaId,
    nonce: u64,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op: OpNumber::new(),
      epoch,
      config_id,
      replica,
      nonce,
      log,
    }
  }

  /// Sets the advertised checkpoint floor (see [`Self::checkpoint_op`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn with_checkpoint_op(mut self, checkpoint_op: OpNumber) -> Self {
    self.checkpoint_op = checkpoint_op;
    self
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The responder's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The canonical head op (from the primary; `0` from a backup).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The canonical commit number (from the primary; `0` from a backup).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The durable-checkpoint-vouched floor of the carried canonical log (`0` from a backup) — the
  /// same semantics as [`StartView::checkpoint_op`]: an omitted op at/below it is checkpoint-
  /// subsumed, so the recovering adopter trims its own retained sub-floor band and records the
  /// floor for its force-sync escalation.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The responding replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness nonce echoed from the soliciting [`Recovery`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The canonical log as a slice (empty from a backup) — a primary's UNIONed offset tail
  /// `(min_floor .. op]`, merged by the adopter with its own preserved committed ops; not
  /// necessarily dense `[1..=op]`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the log vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// Holder → requester (the windowed analogue of a repair-serve [`Prepare`]): a BYTE-BOUNDED PREFIX of
/// the contiguous committed run a [`RequestPrepareRange`] solicited. Structurally a [`StartView`]
/// WITHOUT a head `op` — it carries the holder's `commit` and `checkpoint_op` (so the requester learns
/// fresh commit/checkpoint progress) plus a `log` of `Body::Present` [`PreparedEntry`]s, one per
/// served op. The server walks the requested run and accumulates entries it holds `Present` UNTIL the
/// running encoded size would exceed the frame cap (it serves a PREFIX, never an unbounded batch); the
/// requester re-solicits the unserved tail. Each entry is verified + made durable INDIVIDUALLY by the
/// requester (one `fill_repair` per entry — identical safety to the per-op path), so a batch is purely
/// a pipelining of the per-op fill, never a relaxation of its verification or durability barrier. Not
/// `Copy` (it carries owned entry bodies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairBatch {
  view: View,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  config_id: u128,
  log: Vec<PreparedEntry>,
}

impl RepairBatch {
  /// Creates a RepairBatch carrying the served prefix `log` of a solicited committed run. `config_id`
  /// is the sender's active configuration lineage (the AGNOSTIC epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    config_id: u128,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
      config_id,
      log,
    }
  }

  /// The sender's configuration lineage id (the agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The responder's current view (routing/freshness; a committed op's content is view-independent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The responder's commit number (so the requester also learns fresh commit progress — the
  /// committed-vouch each served entry rides on, exactly as a repair-serve `Prepare`'s `commit` does).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number of the responder's latest durable checkpoint (the state-sync trigger signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The served prefix as a slice — the `Body::Present` entries the holder fit under the frame cap,
  /// in ascending op order (a sub-run of the solicited `[lo, hi]`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the served-entry vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// Primary → all backups (the BATCHED retransmit form of [`Prepare`]): a byte-bounded run of the
/// FIRST un-acked ops `(commit, ...]` the primary's prepare-retransmit timer re-broadcasts as ONE
/// frame instead of one `Prepare` per op. Structurally a [`RepairBatch`] with head-append semantics:
/// it carries the primary's `view`, `commit`, and `checkpoint_op` (the envelope every per-op
/// `Prepare` would have carried) plus a `log` of `Body::Present` [`PreparedEntry`]s in ascending op
/// order. The sender accumulates entries until the running encoded size would exceed the frame cap
/// and then starts another batch, so the whole retransmit window always ships, in one or more
/// sub-cap frames. The receiver reconstructs the per-op [`Prepare`] from the envelope + each entry
/// and feeds it through the ordinary `on_prepare` ingress, so every per-op gate (view/role, sync
/// drop, ring window, band cap, buffer window, re-ack identity) re-evaluates per entry — batching
/// changes the framing, never the semantics. Not `Copy` (it carries owned entry bodies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareBatch {
  view: View,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  epoch: Epoch,
  config_id: u128,
  log: Vec<PreparedEntry>,
}

impl PrepareBatch {
  /// Creates a PrepareBatch carrying the retransmitted run `log` of un-acked ops. `epoch` +
  /// `config_id` are the sender's active configuration (the STRICT epoch-policy pair).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    epoch: Epoch,
    config_id: u128,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
      epoch,
      config_id,
      log,
    }
  }

  /// The sender's configuration epoch (the strict epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The sender's configuration lineage id (the strict/agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The view in which these prepares were created (the view each reconstructed [`Prepare`] carries).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The primary's commit number at send time (each reconstructed [`Prepare`]'s piggybacked commit).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number of the sender's latest durable checkpoint (the state-sync trigger signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The retransmitted run as a slice — the `Body::Present` entries the primary fit under the
  /// frame cap, in ascending op order.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the retransmitted-entry vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// Lagging replica → peers (state-sync solicitation): "my checkpoint is stale; send me the latest
/// checkpoint". Broadcast (like `RequestPrepare`/`Recovery`) when a replica learns the cluster has
/// checkpointed PAST its own WAL head — it cannot catch its tail by retransmit/peer-repair because
/// the ops below the cluster checkpoint may already be pruned at the source. Any `Normal` replica
/// whose durable checkpoint is strictly newer answers with a [`SyncCheckpoint`]. `checkpoint_op` is
/// the requester's CURRENT (stale) checkpoint, so a peer can cheaply skip answering if it has nothing
/// newer; `nonce` is a freshness token echoed in the reply (a stale reply from a prior solicitation is
/// ignored). `view` is carried for routing/freshness only — a committed checkpoint's content is
/// view-independent, so a reply from any view that holds a newer checkpoint is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestSync {
  view: View,
  checkpoint_op: OpNumber,
  replica: ReplicaId,
  nonce: u64,
  recovery: bool,
  config_id: u128,
}

impl RequestSync {
  /// Creates a RequestSync advertising the requester's current (stale) `checkpoint_op`. `recovery` is
  /// the EQUAL-CHECKPOINT block-repair flag (see [`recovery`](Self::recovery)); ordinary state-sync
  /// leaves it `false`. `config_id` is the sender's active configuration lineage (the AGNOSTIC
  /// epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    checkpoint_op: OpNumber,
    replica: ReplicaId,
    nonce: u64,
    recovery: bool,
    config_id: u128,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      replica,
      nonce,
      recovery,
      config_id,
    }
  }

  /// The sender's configuration lineage id (the agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The requester's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The requester's CURRENT (stale) checkpoint op — a peer answers only if it has something newer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The requesting replica (the [`SyncCheckpoint`] reply is addressed back to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// Freshness nonce echoed in the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// `true` iff this is an EQUAL-CHECKPOINT block-repair request — the requester's own copy of
  /// `checkpoint_op`'s block DAG is unusable (a recovery peer-fetch whose durable snapshot read back
  /// corrupt, or an owed SM-reconstruct re-pulling a synced checkpoint's faulted DAG). A peer at an
  /// EQUAL `checkpoint_op` serves such a request (the requester needs the clean blocks even at the same
  /// op); an ordinary (`false`) state-sync request is served only by a strictly-newer checkpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn recovery(&self) -> bool {
    self.recovery
  }
}

/// Peer → lagging replica (state-sync response): the latest durable checkpoint — its op, its content
/// id, and the small frame-bounded envelope produced by the proto's `encode_checkpoint` (the bound op
/// plus the SM and session-table DAG roots, as one `Bytes`). The envelope is ALWAYS within one frame;
/// the SM state and session table it names are fetched block-by-block over the content-addressed
/// `RequestBlock`/`BlockResponse` path. The requester MUST verify `checkpoint_id ==
/// checkpoint_id(snapshot)` (a content hash) BEFORE restoring, then `sm.restore` + restore the session
/// table + set `commit_min == commit_max == checkpoint_op`. `nonce` echoes the soliciting
/// [`RequestSync`] (a stale reply is dropped). Not `Copy` (it carries owned `Bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCheckpoint {
  view: View,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  epoch: Epoch,
  config_id: u128,
  replica: ReplicaId,
  nonce: u64,
  snapshot: Bytes,
  membership: Bytes,
}

impl SyncCheckpoint {
  /// Creates a SyncCheckpoint carrying the durable checkpoint snapshot envelope. `config_id` is the
  /// sender's active configuration lineage (the AGNOSTIC epoch-policy field), `epoch` its configuration
  /// version, and `membership` the canonical `ReconfigurePayload::encode_body` of the sender's CURRENT
  /// configuration — the configuration the served snapshot reflects. A cross-epoch state-sync (the
  /// requester's `config_id` differs from the carried one) reconstructs and installs that successor
  /// configuration from `(epoch, config_id, membership)`; a same-config sync leaves `membership` unread.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)]
  pub fn new(
    view: View,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    epoch: Epoch,
    config_id: u128,
    replica: ReplicaId,
    nonce: u64,
    snapshot: Bytes,
    membership: Bytes,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      checkpoint_id,
      epoch,
      config_id,
      replica,
      nonce,
      snapshot,
      membership,
    }
  }

  /// The sender's configuration lineage id (the agnostic epoch-policy field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The sender's configuration version (the epoch the carried [`Self::membership`] installs at). Paired
  /// with `config_id`, it lets a cross-epoch laggard reconstruct the successor `Membership` the
  /// served snapshot reflects.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The responder's current view (routing/freshness; the checkpoint content is view-independent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number at which this checkpoint was taken (the new `checkpoint_op` for the requester).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The content id of the snapshot — the requester verifies `checkpoint_id(snapshot) == this` before
  /// restoring (the load-bearing integrity gate).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_id(&self) -> u128 {
    self.checkpoint_id
  }

  /// The responding replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness nonce echoed from the soliciting [`RequestSync`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The opaque checkpoint snapshot envelope as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn snapshot(&self) -> &[u8] {
    &self.snapshot
  }

  /// The opaque checkpoint snapshot envelope as a cloned [`Bytes`] handle.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn snapshot_bytes(&self) -> Bytes {
    self.snapshot.clone()
  }

  /// The canonical `ReconfigurePayload::encode_body` of the sender's configuration (the one the
  /// served snapshot reflects), as a slice. A cross-epoch laggard decodes it via
  /// `ReconfigurePayload::decode_body` and reconstructs the successor `Membership` via
  /// [`ReconfigurePayload::to_membership`]; a same-config sync leaves it unread.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership(&self) -> &[u8] {
    &self.membership
  }

  /// The carried membership encoding as a cloned [`Bytes`] handle.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership_bytes(&self) -> Bytes {
    self.membership.clone()
  }
}

/// The donor's answer to a [`Message::RequestBlock`]: either the block bytes are present or the
/// donor does not hold the block at that address.
///
/// Wire encoding: `addr` (16 bytes, big-endian), a 1-byte presence flag (`1` = present, `0` = absent),
/// then — present only — a `u32`-length-prefixed block payload. The `Option<Bytes>` shape is the
/// canonical wire exception for an unambiguous absent-vs-present distinction: `None` is not the same as
/// `Some(Bytes::new())`, so the presence flag carries it explicitly rather than overloading length 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockResponse {
  addr: crate::BlockAddress,
  block: Option<Bytes>,
}

impl BlockResponse {
  /// Constructs a block-response carrying `addr` and an optional block payload (`None` = absent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(addr: crate::BlockAddress, block: Option<Bytes>) -> Self {
    Self { addr, block }
  }

  /// The content address the requester named.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn addr(&self) -> crate::BlockAddress {
    self.addr
  }

  /// The block bytes when the donor holds them, or `None` when absent.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn block(&self) -> Option<&[u8]> {
    self.block.as_deref()
  }

  /// `true` when the donor holds the block (`block` is `Some`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_present(&self) -> bool {
    self.block.is_some()
  }

  /// `true` when the donor does not hold the block (`block` is `None`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_absent(&self) -> bool {
    self.block.is_none()
  }
}

/// A Viewstamped Replication protocol message.
///
/// Client traffic is not a separate API: a request arrives as `Message::Request`
/// from a `Peer::Client`, and a reply leaves as `Message::Reply` to that client.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum Message {
  /// A client request.
  Request(Request),
  /// A prepare from the primary.
  Prepare(Prepare),
  /// A prepare acknowledgement.
  PrepareOk(PrepareOk),
  /// A reply to a client.
  Reply(Reply),
  /// A commit heartbeat.
  Commit(Commit),
  /// Start a view change.
  StartViewChange(StartViewChange),
  /// Do a view change (to the new primary).
  DoViewChange(DoViewChange),
  /// Start the new view (from the new primary).
  StartView(StartView),
  /// Request the current view (catch-up).
  GetView(GetView),
  /// Solicit a single committed op whose local copy read back faulty (peer fault-repair).
  RequestPrepare(RequestPrepare),
  /// Solicit the canonical head (a `RecoveringHead` replica whose head slot is faulty).
  Recovery(Recovery),
  /// Answer a `Recovery` with the canonical head (from the primary) or just the current view.
  RecoveryResponse(RecoveryResponse),
  /// Solicit the latest durable checkpoint (a replica whose checkpoint is below the cluster's).
  RequestSync(RequestSync),
  /// Answer a `RequestSync` with the latest durable checkpoint (snapshot + op + content id).
  SyncCheckpoint(SyncCheckpoint),
  /// Solicit a contiguous run of missing committed ops `[lo, hi]` (windowed peer fault-repair).
  RequestPrepareRange(RequestPrepareRange),
  /// Answer a `RequestPrepareRange` with a byte-bounded prefix of the solicited run.
  RepairBatch(RepairBatch),
  /// Retransmit a byte-bounded batch of the primary's first un-acked prepares (one frame, not one
  /// `Prepare` per op).
  PrepareBatch(PrepareBatch),
  /// A learner's NON-VOTING durable-frontier progress report (drives the catch-up-then-promote gate;
  /// counted toward no quorum).
  LearnerStatus(LearnerStatus),
  /// A minimal cross-epoch catch-up HINT from a settled member to a strictly-lower-epoch peer (epoch +
  /// checkpoint_op only; no view/vote/op content) — pulls a stranded laggard's catch-up trigger back
  /// from a BINDABLE retained voter.
  EpochAhead(EpochAhead),
  /// A primary's fresh-proof SOLICITATION to a target learner at `PromoteLearner` propose time ("prove
  /// you durably hold the committed prefix through `at_op`, now"); no quorum authority.
  RequestLearnerProof(RequestLearnerProof),
  /// A target learner's fresh-proof REPLY (its contiguous applied frontier, recomputed from durable
  /// state at reply time), gating the catch-up-then-promote mint; no quorum authority.
  LearnerProof(LearnerProof),
  /// Solicit the block at a content address from a peer that holds the block store.
  RequestBlock(crate::BlockAddress),
  /// Answer a `RequestBlock`: either the block bytes or an absent signal (the donor does not hold
  /// this address).
  BlockResponse(BlockResponse),
}

impl Message {
  /// The stable variant name of this message (serialization-stable; used in diagnostics and the
  /// emission-chokepoint assert). One source of truth for the message's kind string.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind_str(&self) -> &'static str {
    match self {
      Self::Request(_) => "Request",
      Self::Prepare(_) => "Prepare",
      Self::PrepareOk(_) => "PrepareOk",
      Self::Reply(_) => "Reply",
      Self::Commit(_) => "Commit",
      Self::StartViewChange(_) => "StartViewChange",
      Self::DoViewChange(_) => "DoViewChange",
      Self::StartView(_) => "StartView",
      Self::GetView(_) => "GetView",
      Self::RequestPrepare(_) => "RequestPrepare",
      Self::Recovery(_) => "Recovery",
      Self::RecoveryResponse(_) => "RecoveryResponse",
      Self::RequestSync(_) => "RequestSync",
      Self::SyncCheckpoint(_) => "SyncCheckpoint",
      Self::RequestPrepareRange(_) => "RequestPrepareRange",
      Self::RepairBatch(_) => "RepairBatch",
      Self::PrepareBatch(_) => "PrepareBatch",
      Self::LearnerStatus(_) => "LearnerStatus",
      Self::EpochAhead(_) => "EpochAhead",
      Self::RequestLearnerProof(_) => "RequestLearnerProof",
      Self::LearnerProof(_) => "LearnerProof",
      Self::RequestBlock(_) => "RequestBlock",
      Self::BlockResponse(_) => "BlockResponse",
    }
  }

  /// True iff this message ADVERTISES AN AUTHORITATIVE / PARTICIPATORY VIEW — i.e. it carries the
  /// sender's `self.view` as an authority claim (a primary head / heartbeat / repair-serve, a recovery
  /// head answer, a checkpoint serve) OR as a vote the recipient counts toward forming/committing in
  /// that view. Such a message must NEVER leave a replica whose current view is not yet DURABLE on its
  /// own superblock (`pending_sb.is_some()`), because `self.view` is then the not-yet-persisted view a
  /// crash would roll back — the durable-view-before-participate invariant. This is the
  /// GATED set the single emission chokepoint ([`Endpoint::emit`](crate::Endpoint)) asserts on; it
  /// equals the set the VOPR durable-view checker flags.
  ///
  /// The complement — `StartViewChange` (a REQUEST to change view, not a vote), the solicitations
  /// (`GetView`/`RequestPrepare`/`Recovery`/`RequestSync`), and the client-facing `Request`/`Reply`
  /// (view-independent) — may be emitted while a view write is in flight, so they return `false`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn advertises_authoritative_view(&self) -> bool {
    match self {
      // Primary append broadcast / retransmit, AND the `on_request_prepare` repair serve — advertises
      // `self.view` as the authoritative view of the op.
      Self::Prepare(_)
      // A backup's VOTE the primary counts toward a COMMIT quorum (carries `self.view`).
      | Self::PrepareOk(_)
      // The primary's heartbeat / commit-advance authority broadcast (carries `self.view`).
      | Self::Commit(_)
      // A VOTE the prospective primary counts toward FORMING the new view.
      | Self::DoViewChange(_)
      // The new primary's "I am the canonical primary of view V" head broadcast.
      | Self::StartView(_)
      // The PRIMARY's recovery-handshake answer (the head-bearing equivalent of a StartView).
      | Self::RecoveryResponse(_)
      // The state-sync serve advertises `self.view`.
      | Self::SyncCheckpoint(_)
      // The windowed repair serve advertises `self.view` exactly as the per-op repair-serve `Prepare`
      // does (it is the batched form of the same answer): the server emits it only when Normal +
      // durable-view (`on_request_prepare_range` self-gates like `on_request_prepare`), so gating it at
      // the `emit` chokepoint keeps it in lockstep with `Prepare` rather than carving an exception.
      | Self::RepairBatch(_)
      // The primary's batched prepare retransmit advertises `self.view` exactly as each per-op
      // retransmit `Prepare` it replaces does (`primary_timeouts` skips the retransmit tick while
      // `pending_sb` holds, the same gate the per-op form rode).
      | Self::PrepareBatch(_) => true,
      // Solicitations / requests-to-change / client-facing — view-independent, never an authority claim.
      Self::Request(_)
      | Self::Reply(_)
      | Self::StartViewChange(_)
      | Self::GetView(_)
      | Self::RequestPrepare(_)
      // The windowed solicitation is a request-for-repair, not an authority claim (like `RequestPrepare`).
      | Self::RequestPrepareRange(_)
      | Self::Recovery(_)
      | Self::RequestSync(_)
      // A learner's progress report carries NO vote/lead authority — it advertises no participatory
      // view, so it may be emitted while a view write is in flight (it is config-scoped, not view-scoped).
      | Self::LearnerStatus(_)
      // A cross-epoch hint carries NO view at all — it is a pure catch-up signal (epoch + checkpoint_op),
      // never an authority claim, so it advertises no participatory view.
      | Self::EpochAhead(_)
      // The learner-proof challenge + reply are CONFIG-scoped, not view-scoped: a no-authority
      // solicitation and a no-vote reply that gate a reconfiguration proposal, never a view-bearing
      // vote/lead/serve. They claim no participatory view (emittable while a view write is in flight).
      | Self::RequestLearnerProof(_)
      | Self::LearnerProof(_)
      // Block solicitation + reply carry no view authority (content-addressed data plane).
      | Self::RequestBlock(_)
      | Self::BlockResponse(_) => false,
    }
  }

  /// The stable wire discriminant tag for each variant, matching declaration order. One source of
  /// truth shared by [`Self::encode`] (writes it) and [`Self::decode`] (dispatches on it); the
  /// `match` is EXHAUSTIVE (no wildcard) so a future 25th variant fails to compile until it is
  /// assigned a tag here.
  #[cfg_attr(not(tarpaulin), inline)]
  const fn tag(&self) -> u8 {
    match self {
      Self::Request(_) => 0,
      Self::Prepare(_) => 1,
      Self::PrepareOk(_) => 2,
      Self::Reply(_) => 3,
      Self::Commit(_) => 4,
      Self::StartViewChange(_) => 5,
      Self::DoViewChange(_) => 6,
      Self::StartView(_) => 7,
      Self::GetView(_) => 8,
      Self::RequestPrepare(_) => 9,
      Self::Recovery(_) => 10,
      Self::RecoveryResponse(_) => 11,
      Self::RequestSync(_) => 12,
      Self::SyncCheckpoint(_) => 13,
      Self::RequestPrepareRange(_) => 14,
      Self::RepairBatch(_) => 15,
      // Tags 16/17/18 are retired: the over-frame chunked state-sync (`SyncCheckpointMeta` /
      // `RequestSyncChunk` / `SyncChunk`) was replaced by the content-addressed block fetch.
      Self::PrepareBatch(_) => 19,
      Self::LearnerStatus(_) => 20,
      Self::EpochAhead(_) => 21,
      Self::RequestLearnerProof(_) => 22,
      Self::LearnerProof(_) => 23,
      Self::RequestBlock(_) => 24,
      Self::BlockResponse(_) => 25,
    }
  }

  /// Encodes this message to a versioned, canonical, self-describing byte vector for the wire.
  ///
  /// Layout: [`WIRE_VERSION`](crate::WIRE_VERSION) (`u16` BE), then the variant's discriminant tag
  /// (`u8`), then the variant's fields in canonical order — all scalars big-endian, every `Bytes`
  /// payload + snapshot envelope `u32`-length-prefixed, every `Vec<PreparedEntry>` log slice a
  /// `u32` count followed by each entry (`op`/`client`/`request`, a body-state tag, then a
  /// length-prefixed body for `Present` or a 16-byte `body_checksum` for `Repairing`).
  /// Nested [`crate::Header`]s (none appear in messages today) would reuse the fixed-size
  /// `Header::encode`. The `match` over every variant is EXHAUSTIVE (no wildcard), preserving the
  /// codebase's exhaustive-`Message`-match property.
  pub fn encode(&self) -> Bytes {
    // Pre-size to the exact encoded length ([`Self::encoded_len`], pinned to `encode().len()` by
    // test) so an MB-scale Prepare/SyncCheckpoint encodes into one allocation instead of paying
    // doubling-realloc copies.
    let mut out = BytesMut::with_capacity(self.encoded_len());
    out.put_u16(WIRE_VERSION);
    out.put_u8(self.tag());
    match self {
      Self::Request(m) => {
        out.put_u128(m.client.get());
        out.put_u64(m.request.get());
        write_bytes_u32(&mut out, &m.body);
      }
      Self::Prepare(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
        out.put_u128(m.client.get());
        out.put_u64(m.request.get());
        write_bytes_u32(&mut out, &m.body);
      }
      Self::PrepareOk(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u16(m.replica.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.prepare_checksum);
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::Reply(m) => {
        out.put_u64(m.view.get());
        out.put_u128(m.client.get());
        out.put_u64(m.request.get());
        write_bytes_u32(&mut out, &m.body);
      }
      Self::Commit(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::StartViewChange(m) => {
        out.put_u64(m.view.get());
        out.put_u16(m.replica.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::DoViewChange(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.log_view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
        out.put_u16(m.replica.get());
        write_log(&mut out, &m.log);
      }
      Self::StartView(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
        out.put_u16(m.replica.get());
        write_log(&mut out, &m.log);
      }
      Self::GetView(m) => {
        out.put_u64(m.view.get());
        out.put_u16(m.replica.get());
        out.put_u64(m.nonce);
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::RequestPrepare(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u16(m.replica.get());
        out.put_u128(m.config_id);
      }
      Self::Recovery(m) => {
        out.put_u16(m.replica.get());
        out.put_u64(m.nonce);
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::RecoveryResponse(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
        out.put_u16(m.replica.get());
        out.put_u64(m.nonce);
        write_log(&mut out, &m.log);
      }
      Self::RequestSync(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u16(m.replica.get());
        out.put_u64(m.nonce);
        out.put_u8(m.recovery as u8);
        out.put_u128(m.config_id);
      }
      Self::SyncCheckpoint(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.checkpoint_id);
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
        out.put_u16(m.replica.get());
        out.put_u64(m.nonce);
        write_bytes_u32(&mut out, &m.snapshot);
        write_bytes_u32(&mut out, &m.membership);
      }
      Self::RequestPrepareRange(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.lo.get());
        out.put_u64(m.hi.get());
        out.put_u16(m.replica.get());
        out.put_u128(m.config_id);
      }
      Self::RepairBatch(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.config_id);
        write_log(&mut out, &m.log);
      }
      Self::PrepareBatch(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
        write_log(&mut out, &m.log);
      }
      Self::LearnerStatus(m) => {
        out.put_u16(m.replica.get());
        out.put_u64(m.durable_commit_min.get());
        out.put_u64(m.durable_op.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::EpochAhead(m) => {
        out.put_u64(m.epoch.get());
        out.put_u64(m.checkpoint_op.get());
      }
      Self::RequestLearnerProof(m) => {
        out.put_u16(m.from.get());
        out.put_u64(m.at_op.get());
        out.put_u64(m.nonce);
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::LearnerProof(m) => {
        out.put_u16(m.replica.get());
        out.put_u64(m.nonce);
        out.put_u64(m.frontier.get());
        out.put_u64(m.epoch.get());
        out.put_u128(m.config_id);
      }
      Self::RequestBlock(addr) => {
        out.put_slice(addr.as_bytes());
      }
      Self::BlockResponse(m) => {
        out.put_slice(m.addr.as_bytes());
        match &m.block {
          Some(bytes) => {
            out.put_u8(1);
            write_bytes_u32(&mut out, bytes);
          }
          None => {
            out.put_u8(0);
          }
        }
      }
    }
    out.freeze()
  }

  /// The exact number of bytes [`Self::encode`] would produce for this message, computed WITHOUT
  /// encoding (no allocation/copy). It sums the same fixed-width scalars, length-prefixed payloads,
  /// and log slices that `encode` writes, so the transport can preflight a message against its
  /// frame cap before paying for a full encode of an oversized one. The `#[cfg(test)]`
  /// `encoded_len() == encode().len()` equivalence assertion below pins the two together so they
  /// cannot drift; if a future field changes `encode`, update both.
  pub fn encoded_len(&self) -> usize {
    // Shared per-encoding prefix: WIRE_VERSION (u16) + the variant discriminant tag (u8).
    const HEADER: usize = 2 + 1;
    // Fixed-width scalar widths as `encode` writes them.
    const U64: usize = 8;
    const U128: usize = 16;
    const U16: usize = 2;
    const U8: usize = 1;
    // A `write_bytes_u32` payload is a u32 length prefix plus the bytes.
    fn bytes_u32(len: usize) -> usize {
      4 + len
    }
    // A `write_log` slice is a u32 count plus, per entry, op(u64) + client(u128) + request(u64), a
    // body-state tag (u8), and its payload — a length-prefixed body (Present), a u128 checksum
    // (Repairing), or a Reconfigure payload (replica_count u8 + learner_count u16 + a u32-count-prefixed
    // member list of 16-byte ids + the trailing prev_config_id u128).
    fn log(log: &[PreparedEntry]) -> usize {
      let mut n = 4;
      for e in log {
        let body = match &e.body {
          Body::Present(body) => bytes_u32(body.len()),
          Body::Repairing(_) => U128,
          Body::Reconfigure(p) => U8 + U16 + 4 + p.members().len() * U128 + U128,
        };
        n += U64 + U128 + U64 + U8 + body;
      }
      n
    }
    // The epoch-policy matrix widths: a STRICT carrier adds `epoch` (u64) + `config_id` (u128); an
    // AGNOSTIC carrier adds `config_id` (u128); `Request`/`Reply` add neither. Spelled out per arm in
    // canonical field order so this preflight stays byte-identical to `encode`.
    let body = match self {
      Self::Request(m) => U128 + U64 + bytes_u32(m.body.len()),
      Self::Prepare(m) => U64 + U64 + U64 + U64 + U64 + U128 + U128 + U64 + bytes_u32(m.body.len()),
      Self::PrepareOk(_) => U64 + U64 + U16 + U64 + U128 + U64 + U128,
      Self::Reply(m) => U64 + U128 + U64 + bytes_u32(m.body.len()),
      Self::Commit(_) => U64 + U64 + U64 + U64 + U128,
      Self::StartViewChange(_) => U64 + U16 + U64 + U128,
      Self::DoViewChange(m) => U64 + U64 + U64 + U64 + U64 + U64 + U128 + U16 + log(&m.log),
      Self::StartView(m) => U64 + U64 + U64 + U64 + U64 + U128 + U16 + log(&m.log),
      Self::GetView(_) => U64 + U16 + U64 + U64 + U128,
      Self::RequestPrepare(_) => U64 + U64 + U16 + U128,
      Self::Recovery(_) => U16 + U64 + U64 + U128,
      Self::RecoveryResponse(m) => U64 + U64 + U64 + U64 + U64 + U128 + U16 + U64 + log(&m.log),
      Self::RequestSync(_) => U64 + U64 + U16 + U64 + U8 + U128,
      Self::SyncCheckpoint(m) => {
        U64
          + U64
          + U128
          + U64
          + U128
          + U16
          + U64
          + bytes_u32(m.snapshot.len())
          + bytes_u32(m.membership.len())
      }
      Self::RequestPrepareRange(_) => U64 + U64 + U64 + U16 + U128,
      Self::RepairBatch(m) => U64 + U64 + U64 + U128 + log(&m.log),
      Self::PrepareBatch(m) => U64 + U64 + U64 + U64 + U128 + log(&m.log),
      Self::LearnerStatus(_) => U16 + U64 + U64 + U64 + U128,
      Self::EpochAhead(_) => U64 + U64,
      Self::RequestLearnerProof(_) => U16 + U64 + U64 + U64 + U128,
      Self::LearnerProof(_) => U16 + U64 + U64 + U64 + U128,
      // addr (16 bytes fixed)
      Self::RequestBlock(_) => 16,
      // addr (16) + presence flag (u8=1) + optional block (u32 length prefix + bytes)
      Self::BlockResponse(m) => 16 + 1 + m.block.as_deref().map_or(0, |b| 4 + b.len()),
    };
    HEADER + body
  }

  /// Decodes a message produced by [`Self::encode`], bounds-checked and panic-free on any
  /// truncated / corrupt / adversarial input.
  ///
  /// Rejects (never panics): an unknown leading version ([`CodecError::UnknownVersion`]), an
  /// unknown variant tag ([`CodecError::UnknownTag`]), a buffer that ends mid-field
  /// ([`CodecError::Truncated`]), a body/log length prefix exceeding the remaining bytes
  /// ([`CodecError::LengthOverflow`]), or trailing bytes after the variant
  /// ([`CodecError::TrailingBytes`]). The tag dispatch covers the 24 known tags, with any other
  /// byte falling through to [`CodecError::UnknownTag`] — adding a 25th variant means adding its
  /// discriminant tag + a decode arm here (the encode `match` will not compile until the variant
  /// is handled, preserving the exhaustive-`Message`-match property).
  pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
    let mut r = Reader::new(buf);
    let version = r.u16()?;
    if version != WIRE_VERSION {
      return Err(CodecError::UnknownVersion(version));
    }
    let tag = r.u8()?;
    let msg = match tag {
      0 => Self::Request(Request {
        client: read_client(&mut r)?,
        request: read_request(&mut r)?,
        body: read_body(&mut r)?,
      }),
      1 => Self::Prepare(Prepare {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
        client: read_client(&mut r)?,
        request: read_request(&mut r)?,
        body: read_body(&mut r)?,
      }),
      2 => Self::PrepareOk(PrepareOk {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        prepare_checksum: r.u128()?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      3 => Self::Reply(Reply {
        view: read_view(&mut r)?,
        client: read_client(&mut r)?,
        request: read_request(&mut r)?,
        body: read_body(&mut r)?,
      }),
      4 => Self::Commit(Commit {
        view: read_view(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      5 => Self::StartViewChange(StartViewChange {
        view: read_view(&mut r)?,
        replica: read_replica(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      6 => Self::DoViewChange(DoViewChange {
        view: read_view(&mut r)?,
        log_view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
        replica: read_replica(&mut r)?,
        log: read_log(&mut r)?,
      }),
      7 => Self::StartView(StartView {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
        replica: read_replica(&mut r)?,
        log: read_log(&mut r)?,
      }),
      8 => Self::GetView(GetView {
        view: read_view(&mut r)?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      9 => Self::RequestPrepare(RequestPrepare {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
        config_id: r.u128()?,
      }),
      10 => Self::Recovery(Recovery {
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      11 => Self::RecoveryResponse(RecoveryResponse {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        log: read_log(&mut r)?,
      }),
      12 => Self::RequestSync(RequestSync {
        view: read_view(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        recovery: read_bool(&mut r)?,
        config_id: r.u128()?,
      }),
      13 => Self::SyncCheckpoint(SyncCheckpoint {
        view: read_view(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        checkpoint_id: r.u128()?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        snapshot: read_body(&mut r)?,
        membership: read_body(&mut r)?,
      }),
      14 => Self::RequestPrepareRange(RequestPrepareRange {
        view: read_view(&mut r)?,
        lo: read_op(&mut r)?,
        hi: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
        config_id: r.u128()?,
      }),
      15 => Self::RepairBatch(RepairBatch {
        view: read_view(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        config_id: r.u128()?,
        log: read_log(&mut r)?,
      }),
      // Tags 16/17/18 are retired (see `tag`); a peer on this wire version never emits them, so they
      // fall through to the unknown-tag error below.
      19 => Self::PrepareBatch(PrepareBatch {
        view: read_view(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
        log: read_log(&mut r)?,
      }),
      20 => Self::LearnerStatus(LearnerStatus {
        replica: read_replica(&mut r)?,
        durable_commit_min: read_op(&mut r)?,
        durable_op: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      21 => Self::EpochAhead(EpochAhead {
        epoch: read_epoch(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
      }),
      22 => Self::RequestLearnerProof(RequestLearnerProof {
        from: read_replica(&mut r)?,
        at_op: read_op(&mut r)?,
        nonce: r.u64()?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      23 => Self::LearnerProof(LearnerProof {
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        frontier: read_op(&mut r)?,
        epoch: read_epoch(&mut r)?,
        config_id: r.u128()?,
      }),
      24 => Self::RequestBlock(read_block_address(&mut r)?),
      25 => {
        let addr = read_block_address(&mut r)?;
        let flag = r.u8()?;
        let block = match flag {
          0 => None,
          1 => Some(read_body(&mut r)?),
          _ => {
            return Err(CodecError::UnknownTag(flag));
          }
        };
        Self::BlockResponse(BlockResponse { addr, block })
      }
      other => return Err(CodecError::UnknownTag(other)),
    };
    r.finish()?;
    Ok(msg)
  }
}

// ── per-field readers (narrow a bounds-checked scalar to its newtype) + log slice codec ──

#[cfg_attr(not(tarpaulin), inline)]
fn read_view(r: &mut Reader<'_>) -> Result<View, CodecError> {
  Ok(View::with(r.u64()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_block_address(r: &mut Reader<'_>) -> Result<crate::BlockAddress, CodecError> {
  let bytes: [u8; 16] = r.take(16)?.try_into().expect("take(16) yields 16 bytes");
  Ok(crate::BlockAddress::from_bytes(bytes))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_op(r: &mut Reader<'_>) -> Result<OpNumber, CodecError> {
  Ok(OpNumber::with(r.u64()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_epoch(r: &mut Reader<'_>) -> Result<Epoch, CodecError> {
  Ok(Epoch::new(r.u64()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_request(r: &mut Reader<'_>) -> Result<RequestNumber, CodecError> {
  Ok(RequestNumber::with(r.u64()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_client(r: &mut Reader<'_>) -> Result<ClientId, CodecError> {
  Ok(ClientId::new(r.u128()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_replica(r: &mut Reader<'_>) -> Result<ReplicaId, CodecError> {
  Ok(ReplicaId::new(r.u16()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_bool(r: &mut Reader<'_>) -> Result<bool, CodecError> {
  // Canonical encoding: exactly one byte representation per value. A non-0/1 byte is a malformed frame,
  // not a truthy value (accepting any-nonzero would break decode∘encode identity + the `TrailingBytes`
  // canonical-form discipline the rest of the codec enforces).
  match r.u8()? {
    0 => Ok(false),
    1 => Ok(true),
    other => Err(CodecError::InvalidBool(other)),
  }
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_body(r: &mut Reader<'_>) -> Result<Bytes, CodecError> {
  Ok(Bytes::copy_from_slice(r.bytes_u32()?))
}

/// Writes a [`ReconfigurePayload`] in canonical form: `replica_count` (`u8`), `learner_count` (`u16`),
/// then a `u32`-count-prefixed member list (each [`MemberId`] a 16-byte big-endian `u128`). One source
/// of truth for both the wire encoding ([`write_log`]'s `Reconfigure` arm) and the payload's
/// `body_checksum`, so a Reconfigure op's identity is exactly its on-wire content.
fn write_reconfigure(out: &mut impl BufMut, payload: &ReconfigurePayload) {
  out.put_u8(payload.replica_count);
  out.put_u16(payload.learner_count);
  out.put_u32(payload.members.len() as u32);
  for m in payload.members.iter() {
    out.put_u128(m.get());
  }
  out.put_u128(payload.prev_config_id);
}

/// Reads a [`ReconfigurePayload`] written by [`write_reconfigure`]. The member-count prefix is
/// validated against the remaining bytes ([`Reader::seq_len`] with a 16-byte element size) before any
/// allocation, so a hostile count cannot drive an unbounded pre-allocation. The trailing
/// `prev_config_id` (the pinned predecessor) follows the member list.
fn read_reconfigure(r: &mut Reader<'_>) -> Result<ReconfigurePayload, CodecError> {
  let replica_count = r.u8()?;
  let learner_count = r.u16()?;
  let count = r.seq_len(16)?;
  let mut members = Vec::with_capacity(count);
  for _ in 0..count {
    members.push(MemberId::new(r.u128()?));
  }
  let prev_config_id = r.u128()?;
  Ok(ReconfigurePayload::new(
    replica_count,
    learner_count,
    members.into_boxed_slice(),
    prev_config_id,
  ))
}

/// Writes a `Vec<PreparedEntry>` log slice: a `u32` element count, then each entry as
/// `op`(u64) `client`(u128) `request`(u64) + a body-state tag (u8) + its payload — a
/// length-prefixed body for [`Body::Present`], a 16-byte `body_checksum` for [`Body::Repairing`]
/// (no bytes), or a [`ReconfigurePayload`] for [`Body::Reconfigure`] (the successor membership). A
/// `Repairing` entry carries a body-faulty committed op's existence through a view change so its op
/// number is never re-minted; a `Reconfigure` entry carries a membership-change op.
fn write_log(out: &mut impl BufMut, log: &[PreparedEntry]) {
  out.put_u32(log.len() as u32);
  for e in log {
    out.put_u64(e.op.get());
    out.put_u128(e.client.get());
    out.put_u64(e.request.get());
    match &e.body {
      Body::Present(body) => {
        out.put_u8(BODY_TAG_PRESENT);
        write_bytes_u32(out, body);
      }
      Body::Repairing(checksum) => {
        out.put_u8(BODY_TAG_REPAIRING);
        out.put_u128(*checksum);
      }
      Body::Reconfigure(payload) => {
        out.put_u8(BODY_TAG_RECONFIGURE);
        write_reconfigure(out, payload);
      }
    }
  }
}

/// Reads a `Vec<PreparedEntry>` log slice written by [`write_log`]. The element count is validated
/// against the remaining bytes ([`Reader::seq_len`] with [`PREPARED_ENTRY_MIN_LEN`]) before any
/// allocation, so a hostile count cannot drive an unbounded pre-allocation; each entry's body-state
/// tag selects a `u32`-length-prefixed body ([`Body::Present`], length-checked individually), a
/// 16-byte checksum ([`Body::Repairing`]), or a [`ReconfigurePayload`] ([`Body::Reconfigure`], whose
/// member count is length-checked). An unknown body-state tag is rejected as
/// [`CodecError::UnknownTag`].
fn read_log(r: &mut Reader<'_>) -> Result<Vec<PreparedEntry>, CodecError> {
  let count = r.seq_len(PREPARED_ENTRY_MIN_LEN)?;
  let mut log = Vec::with_capacity(count);
  for _ in 0..count {
    let op = read_op(r)?;
    let client = read_client(r)?;
    let request = read_request(r)?;
    let body = match r.u8()? {
      BODY_TAG_PRESENT => Body::Present(read_body(r)?),
      BODY_TAG_REPAIRING => Body::Repairing(r.u128()?),
      BODY_TAG_RECONFIGURE => Body::Reconfigure(read_reconfigure(r)?),
      other => return Err(CodecError::UnknownTag(other)),
    };
    log.push(PreparedEntry {
      op,
      client,
      request,
      body,
    });
  }
  Ok(log)
}

/// A message the state machine wants the driver to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
  to: Recipient,
  msg: Message,
}

impl Outgoing {
  /// Creates an outgoing message.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(to: Recipient, msg: Message) -> Self {
    Self { to, msg }
  }

  /// The destination set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn to(&self) -> Recipient {
    self.to
  }

  /// A reference to the message.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn msg_ref(&self) -> &Message {
    &self.msg
  }

  /// Consumes the outgoing wrapper and returns the message.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_msg(self) -> Message {
    self.msg
  }
}

#[cfg(test)]
mod tests;

//! Wire message types for the Viewstamped Replication protocol.

use bytes::{BufMut, Bytes, BytesMut};
use std::vec::Vec;

use crate::codec::{CodecError, Reader, write_bytes_u32};
use crate::{ClientId, OpNumber, Recipient, ReplicaId, RequestNumber, View, WIRE_VERSION};

/// The minimum encoded length of one [`PreparedEntry`] in a log slice: `op` (`u64`) + `client`
/// (`u128`) + `request` (`u64`) + a body-state tag (`u8`) + the cheapest body-state payload. The
/// cheapest is a `Present` empty body (a `u32` length prefix = `4`, total `8 + 16 + 8 + 1 + 4`),
/// which is smaller than a `Repairing` 16-byte checksum, so this is the floor used to reject a hostile
/// log-slice element count before parsing (see [`Reader::seq_len`]).
const PREPARED_ENTRY_MIN_LEN: usize = 8 + 16 + 8 + 1 + 4;

/// Wire body-state discriminant for a [`PreparedEntry`] in a log slice: `0` = [`Body::Present`] (a
/// `u32`-length-prefixed body follows), `1` = [`Body::Repairing`] (a 16-byte `u128` `body_checksum`
/// follows, no bytes). One source of truth shared by [`write_log`] (writes it) and [`read_log`]
/// (dispatches on it).
const BODY_TAG_PRESENT: u8 = 0;
const BODY_TAG_REPAIRING: u8 = 1;

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
/// (four `u64`s) + `client` (`u128`) + `request` (`u64`), then the body's [`BYTES_LEN_PREFIX`]. So the
/// same `b`-byte client body that arrived as a `Request` leaves as a `Prepare` of
/// `PREPARE_ENCODE_OVERHEAD + b` bytes. Derived from the exact widths
/// [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::Prepare`] arm. This is strictly
/// larger than [`REQUEST_ENCODE_OVERHEAD`] (a `Prepare` carries the extra consensus header fields), but
/// it is NOT the worst hop the body sees — the log-slice carriers below wrap it in more — so it is only
/// one input to [`MAX_REQUEST_BODY_OVERHEAD`].
pub const PREPARE_ENCODE_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 8 + 8 + 16 + 8 + BYTES_LEN_PREFIX;

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
/// `u64`s), then the log slice's [`LOG_COUNT_PREFIX`]. The byte-bounded serve
/// ([`Endpoint::on_request_prepare_range`](crate::Endpoint)) subtracts this from
/// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN) to get the budget for the per-entry payloads
/// it accumulates, so the produced `RepairBatch` never exceeds the frame cap. Derived from the exact
/// widths [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::RepairBatch`] arm.
pub(crate) const REPAIR_BATCH_CARRIER_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 8 + LOG_COUNT_PREFIX;

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
/// `checkpoint_op` (three `u64`s), then the log slice's [`LOG_COUNT_PREFIX`]. The primary's
/// byte-bounded prepare retransmit ([`Endpoint::primary_timeouts`](crate::Endpoint) via its
/// `prepare` timer) subtracts this from [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN)
/// to get the budget for the per-entry payloads each batch accumulates, so a produced
/// `PrepareBatch` never exceeds the frame cap. Derived from the exact widths
/// [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::PrepareBatch`] arm.
pub(crate) const PREPARE_BATCH_CARRIER_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 8 + LOG_COUNT_PREFIX;

#[cfg(feature = "tcp")]
/// Fixed bytes a [`PrepareBatch`] encoding wraps around ONE client body when that body is the sole
/// [`Body::Present`] entry retransmitted: the [`PREPARE_BATCH_CARRIER_OVERHEAD`] carrier framing
/// plus one [`LOG_ENTRY_BODY_OVERHEAD`] per-entry framing — byte-identical to
/// [`REPAIR_BATCH_BODY_OVERHEAD`] (the two batch carriers share the envelope + per-entry layout).
/// A committed-band op's full body also rides the retransmit as a one-entry `PrepareBatch`, so a
/// max-size body must fit one of these; it TIES the `RepairBatch` carrier as the binding input to
/// [`MAX_REQUEST_BODY_OVERHEAD`], leaving the bound unchanged.
const PREPARE_BATCH_BODY_OVERHEAD: usize = PREPARE_BATCH_CARRIER_OVERHEAD + LOG_ENTRY_BODY_OVERHEAD;

/// Fixed bytes a [`SyncCheckpoint`] encoding wraps around its checkpoint envelope: the
/// [`ENCODE_HEADER_LEN`] message header, then `view` + `checkpoint_op` (two `u64`s) + `checkpoint_id`
/// (`u128`) + `replica` (`u8`) + `nonce` (`u64`), then the envelope's [`BYTES_LEN_PREFIX`]. Derived
/// from the exact widths [`Message::encode`]/[`Message::encoded_len`] write for the
/// [`Message::SyncCheckpoint`] arm. The state-sync serve branches on
/// `MAX_FRAME_LEN - SYNC_CHECKPOINT_CARRIER_OVERHEAD` ([`max_unchunked_snapshot_len`]): an envelope
/// at/under it ships as ONE `SyncCheckpoint` (the unchunked fast path, byte-tight against the frame
/// cap), a larger one ships chunked ([`SyncCheckpointMeta`] → [`RequestSyncChunk`] → [`SyncChunk`]) so
/// no serve can ever exceed the frame cap.
pub(crate) const SYNC_CHECKPOINT_CARRIER_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 16 + 1 + 8 + BYTES_LEN_PREFIX;

/// The largest checkpoint envelope that ships UNCHUNKED — as one [`SyncCheckpoint`] of exactly
/// `MAX_FRAME_LEN` at this size. The state-sync donor branches here: an envelope at/under this
/// length is served whole (the existing single-message fast path); a larger one is announced with a
/// [`SyncCheckpointMeta`] and pulled chunk-by-chunk ([`RequestSyncChunk`] → [`SyncChunk`]), so a
/// snapshot of any size remains state-sync-servable. Not a tunable: derived entirely from the frame
/// cap and the `SyncCheckpoint` carrier framing.
pub const fn max_unchunked_snapshot_len() -> usize {
  MAX_FRAME_LEN as usize - SYNC_CHECKPOINT_CARRIER_OVERHEAD
}

/// Fixed bytes a [`SyncChunk`] encoding wraps around its chunk payload: the [`ENCODE_HEADER_LEN`]
/// message header, then `view` + `checkpoint_op` (two `u64`s) + `checkpoint_id` (`u128`) +
/// `total_len` + `offset` (two `u64`s) + `replica` (`u8`) + `nonce` (`u64`), then the payload's
/// [`BYTES_LEN_PREFIX`] — 64 bytes. Derived from the exact widths
/// [`Message::encode`]/[`Message::encoded_len`] write for the [`Message::SyncChunk`] arm.
pub(crate) const SYNC_CHUNK_CARRIER_OVERHEAD: usize =
  ENCODE_HEADER_LEN + 8 + 8 + 16 + 8 + 8 + 1 + 8 + BYTES_LEN_PREFIX;

/// The chunk size of the chunked state-sync transfer: the largest payload a [`SyncChunk`] can carry
/// with its encoding landing exactly on `MAX_FRAME_LEN` (max-fill, pinned exact by test). Every
/// chunk but the last carries exactly this many bytes, so a transfer of `total_len` bytes completes
/// in `ceil(total_len / SYNC_CHUNK_LEN)` stop-and-wait round trips. Not a tunable: derived entirely
/// from the frame cap and the `SyncChunk` carrier framing.
pub const SYNC_CHUNK_LEN: usize = MAX_FRAME_LEN as usize - SYNC_CHUNK_CARRIER_OVERHEAD;

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
/// per-header-entry size. The carrier framing is the largest of the three log carriers — a
/// `DoViewChange` (header + `view`/`log_view`/`op`/`commit`/`checkpoint_op` five `u64`s + `replica`
/// `u8` + [`LOG_COUNT_PREFIX`]) and a `RecoveryResponse` (header + four `u64`s + `replica` `u8` +
/// `nonce` `u64` + [`LOG_COUNT_PREFIX`]) tie at the larger framing; we use a generous fixed `64`-byte
/// allowance that exceeds either (each is `48`). [`crate::config::MAX_CHECKPOINT_OPS`] is capped so the
/// deepest achievable band `(checkpoint_op .. op]` stays at/below this, making a header-only carrier
/// sub-cap by construction; [`Endpoint::log_entries`](crate::Endpoint) also `debug_assert`s the band
/// against it.
pub(crate) const MAX_HEADER_ONLY_BAND_DEPTH: usize =
  (MAX_FRAME_LEN as usize - 64) / PER_HEADER_ENTRY_BYTES;

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
/// - the [`Request`] the client sends ([`REQUEST_ENCODE_OVERHEAD`] = 31),
/// - the [`Prepare`] the primary replicates ([`PREPARE_ENCODE_OVERHEAD`] = 63),
/// - and — once the op is logged — a single [`Body::Present`] [`PreparedEntry`] inside a
///   [`RepairBatch`] ([`REPAIR_BATCH_BODY_OVERHEAD`] = 68), the windowed peer-repair answer that ships
///   a committed op's full body, or inside a [`PrepareBatch`] ([`PREPARE_BATCH_BODY_OVERHEAD`],
///   byte-identical at 68), the primary's batched retransmit of the un-acked window.
///
/// The view-change log carriers (`DoViewChange` / `StartView` / `RecoveryResponse`) are NOT in
/// this list: they carry every entry HEADER-ONLY (see [`Endpoint::log_entries`](crate::Endpoint)),
/// so they ship NO client body — the binding BODY carriers are the batch slices. The BINDING max
/// is therefore the tied `RepairBatch`/`PrepareBatch` pair (68), which exceeds the `Prepare` hop (63)
/// by the single-entry log framing they wrap the body in. Bounding by `Prepare` alone (63) would let a
/// max-size body served as a one-entry batch encode to `MAX_FRAME_LEN + 5` and be dropped on the
/// repair/retransmit path, leaving a single max-body committed op unrepairable. The transport's
/// `max_request_body_len()` subtracts exactly this from
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
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Prepare {
  /// Creates a prepare.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    client: ClientId,
    request: RequestNumber,
    body: Bytes,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op,
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
}

impl PrepareOk {
  /// Creates a prepare acknowledgement. `prepare_checksum` is the operation IDENTITY content address
  /// (`prepare_identity` over `(client, request, body_checksum)`) of the operation the acking replica
  /// holds at `op` — the address the primary's `on_prepare_ok` matches the vote against before counting it.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    op: OpNumber,
    replica: ReplicaId,
    checkpoint_op: OpNumber,
    prepare_checksum: u128,
  ) -> Self {
    Self {
      view,
      op,
      replica,
      checkpoint_op,
      prepare_checksum,
    }
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
}

impl Commit {
  /// Creates a commit heartbeat.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, commit: OpNumber, checkpoint_op: OpNumber) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
    }
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

/// A log entry's body is either `Present` (the bytes are held) or `Repairing` (only the durable
/// canonical `body_checksum` is known; the bytes must be peer-repaired).
///
/// Body-independent durable headers let a committed op's EXISTENCE survive a torn-body storage
/// fault: the op stays in the log as a `Repairing` slot carrying just its canonical `body_checksum`,
/// and the commit path holds at it (soliciting the body from a peer) exactly as it does for a
/// wholly-missing slot. This ONE type is shared by the endpoint's in-memory `LogEntry` and the wire
/// [`PreparedEntry`], so a `Repairing` op carried through a `DoViewChange`/`StartView` is adopted
/// repair-pending — its op number is taken (never re-minted) and its body is fetched from a peer. Not
/// `Copy` — `Present` carries a [`Bytes`].
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
}

impl Body {
  /// The body bytes when [`Present`](Body::Present), else `None` (a `Repairing` slot has no bytes
  /// yet).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_present(&self) -> Option<&[u8]> {
    match self {
      Body::Present(bytes) => Some(bytes),
      Body::Repairing(_) => None,
    }
  }

  /// The canonical `body_checksum` of this op — total: computed from the bytes when
  /// [`Present`](Body::Present), or the stored durable checksum when [`Repairing`](Body::Repairing).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_checksum(&self) -> u128 {
    match self {
      Body::Present(bytes) => crate::storage::fnv1a_128(bytes),
      Body::Repairing(checksum) => *checksum,
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
}

impl StartViewChange {
  /// Creates a StartViewChange.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, replica: ReplicaId) -> Self {
    Self { view, replica }
  }

  /// The view this replica proposes to enter.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
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
  replica: ReplicaId,
  log: Vec<PreparedEntry>,
}

impl DoViewChange {
  /// Creates a DoViewChange with no checkpoint floor advertised (`checkpoint_op` 0 — the
  /// never-checkpointed sender's form). A sender with a durable-checkpoint-vouched log floor chains
  /// [`Self::with_checkpoint_op`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    log_view: View,
    op: OpNumber,
    commit: OpNumber,
    replica: ReplicaId,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      log_view,
      op,
      commit,
      checkpoint_op: OpNumber::new(),
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
  replica: ReplicaId,
  log: Vec<PreparedEntry>,
}

impl StartView {
  /// Creates a StartView with no checkpoint floor advertised (`checkpoint_op` 0). A primary with a
  /// durable-checkpoint-vouched log floor chains [`Self::with_checkpoint_op`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    replica: ReplicaId,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op: OpNumber::new(),
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
}

impl GetView {
  /// Creates a GetView.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, replica: ReplicaId, nonce: u64) -> Self {
    Self {
      view,
      replica,
      nonce,
    }
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
}

impl RequestPrepare {
  /// Creates a RequestPrepare for the missing committed op `op`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, op: OpNumber, replica: ReplicaId) -> Self {
    Self { view, op, replica }
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
}

impl RequestPrepareRange {
  /// Creates a RequestPrepareRange for the contiguous missing committed run `[lo, hi]`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(view: View, lo: OpNumber, hi: OpNumber, replica: ReplicaId) -> Self {
    Self {
      view,
      lo,
      hi,
      replica,
    }
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
}

impl Recovery {
  /// Creates a Recovery solicitation.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(replica: ReplicaId, nonce: u64) -> Self {
    Self { replica, nonce }
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
  replica: ReplicaId,
  nonce: u64,
  log: Vec<PreparedEntry>,
}

impl RecoveryResponse {
  /// Creates a RecoveryResponse. The primary fills `op`/`commit`/`log` from its canonical state and
  /// chains [`Self::with_checkpoint_op`] for its vouched log floor; a backup passes `op = commit = 0`
  /// and an empty `log` (view + nonce only, no floor).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    replica: ReplicaId,
    nonce: u64,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op: OpNumber::new(),
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
  log: Vec<PreparedEntry>,
}

impl RepairBatch {
  /// Creates a RepairBatch carrying the served prefix `log` of a solicited committed run.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
      log,
    }
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
  log: Vec<PreparedEntry>,
}

impl PrepareBatch {
  /// Creates a PrepareBatch carrying the retransmitted run `log` of un-acked ops.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
      log,
    }
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
}

impl RequestSync {
  /// Creates a RequestSync advertising the requester's current (stale) `checkpoint_op`. `recovery` is
  /// set only on the recovery peer-fetch escalation (a replica whose OWN durable checkpoint snapshot
  /// read back permanently corrupt) — there a peer at the SAME `checkpoint_op` must still serve, since
  /// the requester's local bytes are unusable; ordinary state-sync leaves it `false` (a peer answers
  /// only with something strictly newer).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    checkpoint_op: OpNumber,
    replica: ReplicaId,
    nonce: u64,
    recovery: bool,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      replica,
      nonce,
      recovery,
    }
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

  /// `true` iff this is a RECOVERY peer-fetch (the requester's own durable checkpoint snapshot is
  /// permanently unreadable). A peer at an EQUAL `checkpoint_op` serves a recovery request (the
  /// requester needs the snapshot bytes even at the same op); an ordinary (`false`) state-sync request
  /// is served only by a strictly-newer checkpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn recovery(&self) -> bool {
    self.recovery
  }
}

/// Peer → lagging replica (state-sync response): the latest durable checkpoint — its op, its content
/// id, and the opaque snapshot envelope (the client-session table + `sm.snapshot()` produced by the
/// proto's `encode_checkpoint`, modelled as one `Bytes`). Ships whole only when the envelope fits one
/// frame (at most [`max_unchunked_snapshot_len`] bytes); a larger envelope travels chunked
/// ([`SyncCheckpointMeta`] → [`RequestSyncChunk`] → [`SyncChunk`]) and the verified reassembly
/// re-enters the receive path as exactly this message. The requester MUST verify
/// `checkpoint_id == checkpoint_id(snapshot)` (a content hash) BEFORE
/// restoring — never restore a corrupt/mismatched checkpoint — then `sm.restore` + restore the session
/// table + set `commit_min == commit_max == checkpoint_op`. `nonce` echoes the soliciting
/// [`RequestSync`] (a stale reply is dropped). Not `Copy` (it carries owned `Bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCheckpoint {
  view: View,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  replica: ReplicaId,
  nonce: u64,
  snapshot: Bytes,
}

impl SyncCheckpoint {
  /// Creates a SyncCheckpoint carrying the durable checkpoint snapshot envelope.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn new(
    view: View,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    replica: ReplicaId,
    nonce: u64,
    snapshot: Bytes,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      checkpoint_id,
      replica,
      nonce,
      snapshot,
    }
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
}

/// Donor → lagging replica (the chunked state-sync announce): the donor's latest durable checkpoint
/// is TOO LARGE to ship as one [`SyncCheckpoint`] (its envelope exceeds
/// [`max_unchunked_snapshot_len`]), so the donor announces it — op, content id, and the envelope's
/// `total_len` — and the requester PULLS it chunk-by-chunk ([`RequestSyncChunk`] → [`SyncChunk`]).
/// `total_len` descends from a VERIFIED checkpoint read (the donor hashes the read bytes against its
/// durable root before announcing), so the receiver can size its reassembly buffer to exactly the
/// envelope it will verify. `nonce` echoes the soliciting `RequestSync` (a stale announce is
/// dropped); `view` is routing/freshness only — committed checkpoint content is view-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCheckpointMeta {
  view: View,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  total_len: u64,
  replica: ReplicaId,
  nonce: u64,
}

impl SyncCheckpointMeta {
  /// Creates a chunked-transfer announce for the checkpoint `(checkpoint_op, checkpoint_id)` whose
  /// envelope is `total_len` bytes.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    total_len: u64,
    replica: ReplicaId,
    nonce: u64,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      checkpoint_id,
      total_len,
      replica,
      nonce,
    }
  }

  /// The donor's current view (routing/freshness; the checkpoint content is view-independent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number at which the announced checkpoint was taken.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The content id of the announced envelope — the transfer is PINNED by `(checkpoint_op, this)`,
  /// and the assembled bytes must hash to it before anything reaches the install path.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_id(&self) -> u128 {
    self.checkpoint_id
  }

  /// The announced envelope's total length in bytes (from a VERIFIED donor read).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn total_len(&self) -> u64 {
    self.total_len
  }

  /// The announcing replica (chunk requests are addressed to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness nonce echoed from the soliciting `RequestSync`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// Lagging replica → donor (the chunked state-sync pull): request the chunk of the pinned checkpoint
/// envelope starting at `offset`. One outstanding request at a time (stop-and-wait, self-clocked:
/// the next request is sent on chunk accept); the `sync_solicit` timer re-sends the current request
/// as the ARQ. `(checkpoint_op, checkpoint_id)` pin the exact content being pulled, so a donor whose
/// checkpoint has since advanced can keep serving the pinned (immutable, committed) envelope from
/// its cache, and chunks from DIFFERENT donors of the same pinned content are interchangeable.
/// `nonce` is the requester's live sync nonce, echoed in the [`SyncChunk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestSyncChunk {
  view: View,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  offset: u64,
  replica: ReplicaId,
  nonce: u64,
}

impl RequestSyncChunk {
  /// Creates a chunk request for the pinned checkpoint `(checkpoint_op, checkpoint_id)` at `offset`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(
    view: View,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    offset: u64,
    replica: ReplicaId,
    nonce: u64,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      checkpoint_id,
      offset,
      replica,
      nonce,
    }
  }

  /// The requester's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The pinned checkpoint op being pulled.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The pinned envelope content id being pulled.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_id(&self) -> u128 {
    self.checkpoint_id
  }

  /// The byte offset into the envelope this request asks the donor to serve from.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn offset(&self) -> u64 {
    self.offset
  }

  /// The requesting replica (the [`SyncChunk`] reply is addressed back to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The requester's live sync nonce, echoed in the [`SyncChunk`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// Donor → lagging replica (the chunked state-sync payload): one chunk of the pinned checkpoint
/// envelope, answering a [`RequestSyncChunk`]. Every chunk repeats `(checkpoint_op, checkpoint_id,
/// total_len)` so it is statelessly self-describing — the receiver rejects any chunk that does not
/// match its pinned transfer, and a dup/reordered chunk (its `offset` is not the staged frontier) is
/// inert. The payload is at most [`SYNC_CHUNK_LEN`] bytes by construction (a max-fill chunk encodes
/// to exactly the frame cap), so the chunked path can never produce an oversized frame. Not `Copy`
/// (it carries owned `Bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncChunk {
  view: View,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  total_len: u64,
  offset: u64,
  replica: ReplicaId,
  nonce: u64,
  bytes: Bytes,
}

impl SyncChunk {
  /// Creates a chunk of the pinned checkpoint `(checkpoint_op, checkpoint_id)`: the envelope bytes
  /// at `offset .. offset + bytes.len()` of a `total_len`-byte envelope.
  #[cfg_attr(not(tarpaulin), inline(always))]
  #[allow(clippy::too_many_arguments)] // the wire layout, in canonical field order
  pub const fn new(
    view: View,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    total_len: u64,
    offset: u64,
    replica: ReplicaId,
    nonce: u64,
    bytes: Bytes,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      checkpoint_id,
      total_len,
      offset,
      replica,
      nonce,
      bytes,
    }
  }

  /// The donor's current view (routing/freshness; the chunk content is view-independent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The pinned checkpoint op this chunk belongs to.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The pinned envelope content id this chunk belongs to.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_id(&self) -> u128 {
    self.checkpoint_id
  }

  /// The envelope's total length (repeated on every chunk — statelessly self-describing).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn total_len(&self) -> u64 {
    self.total_len
  }

  /// The byte offset of this chunk within the envelope.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn offset(&self) -> u64 {
    self.offset
  }

  /// The serving replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness nonce echoed from the soliciting [`RequestSyncChunk`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The chunk payload as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn bytes(&self) -> &[u8] {
    &self.bytes
  }

  /// The chunk payload as a cloned [`Bytes`] handle.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn bytes_owned(&self) -> Bytes {
    self.bytes.clone()
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
  /// Announce an over-frame checkpoint for chunked transfer (op, content id, total length).
  SyncCheckpointMeta(SyncCheckpointMeta),
  /// Solicit one chunk of an announced checkpoint envelope at a byte offset.
  RequestSyncChunk(RequestSyncChunk),
  /// Answer a `RequestSyncChunk` with one chunk of the pinned checkpoint envelope.
  SyncChunk(SyncChunk),
  /// Retransmit a byte-bounded batch of the primary's first un-acked prepares (one frame, not one
  /// `Prepare` per op).
  PrepareBatch(PrepareBatch),
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
      Self::SyncCheckpointMeta(_) => "SyncCheckpointMeta",
      Self::RequestSyncChunk(_) => "RequestSyncChunk",
      Self::SyncChunk(_) => "SyncChunk",
      Self::PrepareBatch(_) => "PrepareBatch",
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
      // The chunked-transfer serves are the SAME state-sync answer split across messages — the
      // announce and each chunk advertise `self.view` exactly as the whole `SyncCheckpoint` does, so
      // they ride the same emit gate (a donor never serves while its view write is in flight).
      | Self::SyncCheckpointMeta(_)
      | Self::SyncChunk(_)
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
      // The chunk pull is a solicitation, exactly like the `RequestSync` it follows.
      | Self::RequestSyncChunk(_) => false,
    }
  }

  /// The stable wire discriminant tag for each variant, matching declaration order. One source of
  /// truth shared by [`Self::encode`] (writes it) and [`Self::decode`] (dispatches on it); the
  /// `match` is EXHAUSTIVE (no wildcard) so a future 21st variant fails to compile until it is
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
      Self::SyncCheckpointMeta(_) => 16,
      Self::RequestSyncChunk(_) => 17,
      Self::SyncChunk(_) => 18,
      Self::PrepareBatch(_) => 19,
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
        out.put_u128(m.client.get());
        out.put_u64(m.request.get());
        write_bytes_u32(&mut out, &m.body);
      }
      Self::PrepareOk(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u8(m.replica.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.prepare_checksum);
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
      }
      Self::StartViewChange(m) => {
        out.put_u64(m.view.get());
        out.put_u8(m.replica.get());
      }
      Self::DoViewChange(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.log_view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u8(m.replica.get());
        write_log(&mut out, &m.log);
      }
      Self::StartView(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u8(m.replica.get());
        write_log(&mut out, &m.log);
      }
      Self::GetView(m) => {
        out.put_u64(m.view.get());
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
      }
      Self::RequestPrepare(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u8(m.replica.get());
      }
      Self::Recovery(m) => {
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
      }
      Self::RecoveryResponse(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.op.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
        write_log(&mut out, &m.log);
      }
      Self::RequestSync(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
        out.put_u8(m.recovery as u8);
      }
      Self::SyncCheckpoint(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.checkpoint_id);
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
        write_bytes_u32(&mut out, &m.snapshot);
      }
      Self::RequestPrepareRange(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.lo.get());
        out.put_u64(m.hi.get());
        out.put_u8(m.replica.get());
      }
      Self::RepairBatch(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        write_log(&mut out, &m.log);
      }
      Self::SyncCheckpointMeta(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.checkpoint_id);
        out.put_u64(m.total_len);
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
      }
      Self::RequestSyncChunk(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.checkpoint_id);
        out.put_u64(m.offset);
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
      }
      Self::SyncChunk(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.checkpoint_op.get());
        out.put_u128(m.checkpoint_id);
        out.put_u64(m.total_len);
        out.put_u64(m.offset);
        out.put_u8(m.replica.get());
        out.put_u64(m.nonce);
        write_bytes_u32(&mut out, &m.bytes);
      }
      Self::PrepareBatch(m) => {
        out.put_u64(m.view.get());
        out.put_u64(m.commit.get());
        out.put_u64(m.checkpoint_op.get());
        write_log(&mut out, &m.log);
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
    const U8: usize = 1;
    // A `write_bytes_u32` payload is a u32 length prefix plus the bytes.
    fn bytes_u32(len: usize) -> usize {
      4 + len
    }
    // A `write_log` slice is a u32 count plus, per entry, op(u64) + client(u128) + request(u64), a
    // body-state tag (u8), and its payload — a length-prefixed body (Present) or a u128 checksum
    // (Repairing).
    fn log(log: &[PreparedEntry]) -> usize {
      let mut n = 4;
      for e in log {
        let body = match &e.body {
          Body::Present(body) => bytes_u32(body.len()),
          Body::Repairing(_) => U128,
        };
        n += U64 + U128 + U64 + U8 + body;
      }
      n
    }
    let body = match self {
      Self::Request(m) => U128 + U64 + bytes_u32(m.body.len()),
      Self::Prepare(m) => U64 + U64 + U64 + U64 + U128 + U64 + bytes_u32(m.body.len()),
      Self::PrepareOk(_) => U64 + U64 + U8 + U64 + U128,
      Self::Reply(m) => U64 + U128 + U64 + bytes_u32(m.body.len()),
      Self::Commit(_) => U64 + U64 + U64,
      Self::StartViewChange(_) => U64 + U8,
      Self::DoViewChange(m) => U64 + U64 + U64 + U64 + U64 + U8 + log(&m.log),
      Self::StartView(m) => U64 + U64 + U64 + U64 + U8 + log(&m.log),
      Self::GetView(_) => U64 + U8 + U64,
      Self::RequestPrepare(_) => U64 + U64 + U8,
      Self::Recovery(_) => U8 + U64,
      Self::RecoveryResponse(m) => U64 + U64 + U64 + U64 + U8 + U64 + log(&m.log),
      Self::RequestSync(_) => U64 + U64 + U8 + U64 + U8,
      Self::SyncCheckpoint(m) => U64 + U64 + U128 + U8 + U64 + bytes_u32(m.snapshot.len()),
      Self::RequestPrepareRange(_) => U64 + U64 + U64 + U8,
      Self::RepairBatch(m) => U64 + U64 + U64 + log(&m.log),
      Self::SyncCheckpointMeta(_) => U64 + U64 + U128 + U64 + U8 + U64,
      Self::RequestSyncChunk(_) => U64 + U64 + U128 + U64 + U8 + U64,
      Self::SyncChunk(m) => U64 + U64 + U128 + U64 + U64 + U8 + U64 + bytes_u32(m.bytes.len()),
      Self::PrepareBatch(m) => U64 + U64 + U64 + log(&m.log),
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
  /// ([`CodecError::TrailingBytes`]). The tag dispatch covers the 20 known tags, with any other
  /// byte falling through to [`CodecError::UnknownTag`] — adding a 21st variant means adding its
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
      }),
      5 => Self::StartViewChange(StartViewChange {
        view: read_view(&mut r)?,
        replica: read_replica(&mut r)?,
      }),
      6 => Self::DoViewChange(DoViewChange {
        view: read_view(&mut r)?,
        log_view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
        log: read_log(&mut r)?,
      }),
      7 => Self::StartView(StartView {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
        log: read_log(&mut r)?,
      }),
      8 => Self::GetView(GetView {
        view: read_view(&mut r)?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
      }),
      9 => Self::RequestPrepare(RequestPrepare {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
      }),
      10 => Self::Recovery(Recovery {
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
      }),
      11 => Self::RecoveryResponse(RecoveryResponse {
        view: read_view(&mut r)?,
        op: read_op(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
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
      }),
      13 => Self::SyncCheckpoint(SyncCheckpoint {
        view: read_view(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        checkpoint_id: r.u128()?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        snapshot: read_body(&mut r)?,
      }),
      14 => Self::RequestPrepareRange(RequestPrepareRange {
        view: read_view(&mut r)?,
        lo: read_op(&mut r)?,
        hi: read_op(&mut r)?,
        replica: read_replica(&mut r)?,
      }),
      15 => Self::RepairBatch(RepairBatch {
        view: read_view(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        log: read_log(&mut r)?,
      }),
      16 => Self::SyncCheckpointMeta(SyncCheckpointMeta {
        view: read_view(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        checkpoint_id: r.u128()?,
        total_len: r.u64()?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
      }),
      17 => Self::RequestSyncChunk(RequestSyncChunk {
        view: read_view(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        checkpoint_id: r.u128()?,
        offset: r.u64()?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
      }),
      18 => Self::SyncChunk(SyncChunk {
        view: read_view(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        checkpoint_id: r.u128()?,
        total_len: r.u64()?,
        offset: r.u64()?,
        replica: read_replica(&mut r)?,
        nonce: r.u64()?,
        bytes: read_body(&mut r)?,
      }),
      19 => Self::PrepareBatch(PrepareBatch {
        view: read_view(&mut r)?,
        commit: read_op(&mut r)?,
        checkpoint_op: read_op(&mut r)?,
        log: read_log(&mut r)?,
      }),
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
fn read_op(r: &mut Reader<'_>) -> Result<OpNumber, CodecError> {
  Ok(OpNumber::with(r.u64()?))
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
  Ok(ReplicaId::new(r.u8()?))
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_bool(r: &mut Reader<'_>) -> Result<bool, CodecError> {
  Ok(r.u8()? != 0)
}

#[cfg_attr(not(tarpaulin), inline)]
fn read_body(r: &mut Reader<'_>) -> Result<Bytes, CodecError> {
  Ok(Bytes::copy_from_slice(r.bytes_u32()?))
}

/// Writes a `Vec<PreparedEntry>` log slice: a `u32` element count, then each entry as
/// `op`(u64) `client`(u128) `request`(u64) + a body-state tag (u8) + its payload — a
/// length-prefixed body for [`Body::Present`], or a 16-byte `body_checksum` for [`Body::Repairing`]
/// (no bytes). A `Repairing` entry carries a body-faulty committed op's existence through a view
/// change so its op number is never re-minted.
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
    }
  }
}

/// Reads a `Vec<PreparedEntry>` log slice written by [`write_log`]. The element count is validated
/// against the remaining bytes ([`Reader::seq_len`] with [`PREPARED_ENTRY_MIN_LEN`]) before any
/// allocation, so a hostile count cannot drive an unbounded pre-allocation; each entry's body-state
/// tag selects a `u32`-length-prefixed body ([`Body::Present`], length-checked individually) or a
/// 16-byte checksum ([`Body::Repairing`]). An unknown body-state tag is rejected as
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
mod tests {
  use super::*;
  use crate::{ClientId, OpNumber, ReplicaId, RequestNumber, View};

  #[test]
  fn commit_and_prepare_ok_carry_checkpoint_op() {
    let c = Commit::new(View::with(1), OpNumber::with(5), OpNumber::with(4));
    assert_eq!(c.checkpoint_op(), OpNumber::with(4));
    let ok = PrepareOk::new(
      View::with(1),
      OpNumber::with(5),
      ReplicaId::new(2),
      OpNumber::with(4),
      0x1234_5678_9abc_def0_1122_3344_5566_7788,
    );
    assert_eq!(ok.checkpoint_op(), OpNumber::with(4));
    // The vote is content-addressed: it carries the operation-identity checksum verbatim.
    assert_eq!(
      ok.prepare_checksum(),
      0x1234_5678_9abc_def0_1122_3344_5566_7788
    );
  }

  #[test]
  fn prepare_ok_prepare_checksum_round_trips_through_the_wire_codec() {
    // The content-addressed vote field must survive encode→decode unchanged (a u128 edge value),
    // since the primary's `on_prepare_ok` matches it against the operation it is driving at that op.
    let ok = Message::PrepareOk(PrepareOk::new(
      View::with(7),
      OpNumber::with(9),
      ReplicaId::new(3),
      OpNumber::with(4),
      u128::MAX,
    ));
    let back = Message::decode(&ok.encode()).expect("round-trips");
    assert_eq!(back, ok);
    let p = back.unwrap_prepare_ok();
    assert_eq!(p.prepare_checksum(), u128::MAX);
    assert_eq!(p.op(), OpNumber::with(9));
  }

  #[test]
  fn prepare_carries_checkpoint_op() {
    let p = Prepare::new(
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(4),
      OpNumber::with(2), // checkpoint_op
      ClientId::new(7),
      RequestNumber::with(5),
      Bytes::from_static(b"x"),
    );
    assert_eq!(p.checkpoint_op(), OpNumber::with(2));
  }

  #[test]
  fn construct_and_match() {
    let m = Message::Prepare(Prepare::new(
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::copy_from_slice(&[1, 2, 3]),
    ));
    match m {
      Message::Prepare(p) => assert_eq!(p.op(), OpNumber::with(1)),
      _ => panic!("wrong variant"),
    }
  }

  #[test]
  fn view_change_messages_construct_and_predicate() {
    use crate::ReplicaId;
    let svc = Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2)));
    assert!(svc.is_start_view_change());
    let dvc = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(1),
      ReplicaId::new(2),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"x"),
      )],
    ));
    assert_eq!(dvc.unwrap_do_view_change().op(), OpNumber::with(3));
  }

  #[test]
  fn recovery_messages_construct_and_round_trip() {
    use crate::ReplicaId;
    // A RecoveringHead replica broadcasts Recovery{replica, nonce}.
    let rec = Message::Recovery(Recovery::new(ReplicaId::new(2), 0xABCD));
    assert!(rec.is_recovery());
    let r = rec.unwrap_recovery();
    assert_eq!(r.replica(), ReplicaId::new(2));
    assert_eq!(r.nonce(), 0xABCD);

    // The primary's RecoveryResponse carries its view + head + commit + canonical log, echoing nonce.
    let resp = Message::RecoveryResponse(RecoveryResponse::new(
      View::with(3),
      OpNumber::with(5),
      OpNumber::with(4),
      ReplicaId::new(0),
      0xABCD,
      std::vec![PreparedEntry::new(
        OpNumber::with(5),
        ClientId::new(7),
        RequestNumber::with(5),
        bytes::Bytes::from_static(b"e"),
      )],
    ));
    assert!(resp.is_recovery_response());
    let rr = resp.unwrap_recovery_response();
    assert_eq!(rr.view(), View::with(3));
    assert_eq!(rr.op(), OpNumber::with(5));
    assert_eq!(rr.commit(), OpNumber::with(4));
    assert_eq!(rr.replica(), ReplicaId::new(0));
    assert_eq!(rr.nonce(), 0xABCD);
    assert_eq!(rr.log_slice().len(), 1);
    assert_eq!(rr.into_log().len(), 1);
  }

  #[test]
  fn request_prepare_constructs_and_round_trips() {
    use crate::ReplicaId;
    // A replica holding a faulty committed op `op` broadcasts RequestPrepare{view, op, replica}.
    let m = Message::RequestPrepare(RequestPrepare::new(
      View::with(2),
      OpNumber::with(7),
      ReplicaId::new(3),
    ));
    assert!(m.is_request_prepare());
    let rp = m.unwrap_request_prepare();
    assert_eq!(rp.view(), View::with(2));
    assert_eq!(rp.op(), OpNumber::with(7));
    assert_eq!(rp.replica(), ReplicaId::new(3));
  }

  #[test]
  fn sync_messages_construct_and_round_trip() {
    use crate::ReplicaId;
    // A lagging replica solicits with its CURRENT (stale) checkpoint + a nonce.
    let rq = Message::RequestSync(RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      false,
    ));
    assert!(rq.is_request_sync());
    let r = rq.unwrap_request_sync();
    assert_eq!(r.view(), View::with(4));
    assert_eq!(r.checkpoint_op(), OpNumber::with(2));
    assert_eq!(r.replica(), ReplicaId::new(3));
    assert_eq!(r.nonce(), 0xBEEF);
    assert!(!r.recovery(), "ordinary state-sync request");
    // A recovery peer-fetch sets the flag (a peer at an EQUAL checkpoint serves it).
    let rec = RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      true,
    );
    assert!(rec.recovery());

    // The peer answers with the newer checkpoint: op, id, opaque snapshot, echoed nonce.
    let snap = Bytes::from_static(b"snapshot-envelope");
    let sc = Message::SyncCheckpoint(SyncCheckpoint::new(
      View::with(4),
      OpNumber::with(8),
      0x1234_5678_9abc,
      ReplicaId::new(0),
      0xBEEF,
      snap.clone(),
    ));
    assert!(sc.is_sync_checkpoint());
    let s = sc.unwrap_sync_checkpoint();
    assert_eq!(s.view(), View::with(4));
    assert_eq!(s.checkpoint_op(), OpNumber::with(8));
    assert_eq!(s.checkpoint_id(), 0x1234_5678_9abc);
    assert_eq!(s.replica(), ReplicaId::new(0));
    assert_eq!(s.nonce(), 0xBEEF);
    assert_eq!(s.snapshot(), b"snapshot-envelope");
    assert_eq!(s.snapshot_bytes(), snap);
  }

  #[test]
  fn advertises_authoritative_view_is_exactly_the_gated_set() {
    use crate::ReplicaId;
    let body = Bytes::from_static(b"x");
    let entry = || {
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone(),
      )
    };
    // The GATED set (a view-advertising authority / participation message) — must return `true`.
    let gated: std::vec::Vec<Message> = std::vec![
      Message::Prepare(Prepare::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone()
      )),
      Message::PrepareOk(PrepareOk::new(
        View::with(1),
        OpNumber::with(1),
        ReplicaId::new(2),
        OpNumber::with(0),
        0
      )),
      Message::Commit(Commit::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0)
      )),
      Message::DoViewChange(DoViewChange::new(
        View::with(1),
        View::with(0),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(2),
        std::vec![entry()]
      )),
      Message::StartView(StartView::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(0),
        std::vec![entry()]
      )),
      Message::RecoveryResponse(RecoveryResponse::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(0),
        0,
        std::vec![entry()]
      )),
      Message::SyncCheckpoint(SyncCheckpoint::new(
        View::with(1),
        OpNumber::with(2),
        0,
        ReplicaId::new(0),
        0,
        body.clone()
      )),
      Message::RepairBatch(RepairBatch::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0),
        std::vec![entry()]
      )),
      // The batched prepare retransmit advertises `self.view` exactly like each per-op `Prepare`
      // it replaces.
      Message::PrepareBatch(PrepareBatch::new(
        View::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        std::vec![entry()]
      )),
      // The chunked state-sync serves advertise `self.view` exactly like the whole SyncCheckpoint.
      Message::SyncCheckpointMeta(SyncCheckpointMeta::new(
        View::with(1),
        OpNumber::with(2),
        0,
        64,
        ReplicaId::new(0),
        0
      )),
      Message::SyncChunk(SyncChunk::new(
        View::with(1),
        OpNumber::with(2),
        0,
        64,
        0,
        ReplicaId::new(0),
        0,
        body.clone()
      )),
    ];
    for m in &gated {
      assert!(
        m.advertises_authoritative_view(),
        "{} must be gated",
        m.kind_str()
      );
    }
    // The NON-gated set (solicitations / requests-to-change / client-facing) — must return `false`.
    let ungated: std::vec::Vec<Message> = std::vec![
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone()
      )),
      Message::Reply(Reply::new(
        View::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone()
      )),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
      Message::GetView(GetView::new(View::with(1), ReplicaId::new(2), 0)),
      Message::RequestPrepare(RequestPrepare::new(
        View::with(1),
        OpNumber::with(1),
        ReplicaId::new(2)
      )),
      Message::Recovery(Recovery::new(ReplicaId::new(2), 0)),
      Message::RequestSync(RequestSync::new(
        View::with(1),
        OpNumber::with(0),
        ReplicaId::new(2),
        0,
        false
      )),
      Message::RequestPrepareRange(RequestPrepareRange::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(2),
        ReplicaId::new(2)
      )),
      // The chunk pull is a solicitation, like the RequestSync it follows.
      Message::RequestSyncChunk(RequestSyncChunk::new(
        View::with(1),
        OpNumber::with(2),
        0,
        0,
        ReplicaId::new(2),
        0
      )),
    ];
    for m in &ungated {
      assert!(
        !m.advertises_authoritative_view(),
        "{} must NOT be gated",
        m.kind_str()
      );
    }
    // Every variant is covered exactly once across the two sets (no Message kind missed).
    assert_eq!(
      gated.len() + ungated.len(),
      20,
      "all 20 Message variants are classified"
    );
    assert_eq!(
      Message::Commit(Commit::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0)
      ))
      .kind_str(),
      "Commit"
    );
  }

  #[test]
  fn backup_recovery_response_carries_no_log() {
    use crate::ReplicaId;
    // A non-primary's RecoveryResponse carries only its view + nonce (no canonical log/head/commit).
    let rr = RecoveryResponse::new(
      View::with(3),
      OpNumber::new(),
      OpNumber::new(),
      ReplicaId::new(2),
      0xFEED,
      std::vec![],
    );
    assert!(rr.log_slice().is_empty());
    assert_eq!(rr.nonce(), 0xFEED);
    assert_eq!(rr.view(), View::with(3));
  }

  // ── wire codec: all 20 Message variants ──

  use crate::codec::CodecError;

  fn entry(op: u64, body: &[u8]) -> PreparedEntry {
    PreparedEntry::new(
      OpNumber::with(op),
      ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
      RequestNumber::with(op),
      Bytes::copy_from_slice(body),
    )
  }

  /// One representative [`Message`] per variant, deliberately exercising the edge cases each
  /// variant's codec must handle: an EMPTY body (`Request`), a POPULATED body (`Prepare`/`Reply`/
  /// `SyncCheckpoint`/`SyncChunk`), an EMPTY log slice (`StartView`), a POPULATED multi-entry log
  /// (`DoViewChange`/`RecoveryResponse`), the `recovery` bool both ways, and `u64::MAX`/`u128::MAX`
  /// edge scalars. Covers all 20 tags so the round-trip + fuzz tests sweep the whole surface.
  fn one_of_each_variant() -> std::vec::Vec<Message> {
    std::vec![
      Message::Request(Request::new(
        ClientId::new(u128::MAX),
        RequestNumber::with(0),
        Bytes::new(), // empty body edge
      )),
      Message::Prepare(Prepare::new(
        View::with(1),
        OpNumber::with(u64::MAX),
        OpNumber::with(2),
        OpNumber::with(3),
        ClientId::new(7),
        RequestNumber::with(9),
        Bytes::from_static(b"prepare-body"),
      )),
      Message::PrepareOk(PrepareOk::new(
        View::with(4),
        OpNumber::with(5),
        ReplicaId::new(255),
        OpNumber::with(6),
        0xCAFE_F00D_DEAD_BEEF_0102_0304_0506_0708,
      )),
      Message::Reply(Reply::new(
        View::with(2),
        ClientId::new(8),
        RequestNumber::with(3),
        Bytes::from_static(b"reply-body"),
      )),
      Message::Commit(Commit::new(
        View::with(4),
        OpNumber::with(9),
        OpNumber::with(7),
      )),
      Message::StartViewChange(StartViewChange::new(View::with(11), ReplicaId::new(2))),
      Message::DoViewChange(
        DoViewChange::new(
          View::with(3),
          View::with(2),
          OpNumber::with(6),
          OpNumber::with(4),
          ReplicaId::new(6),
          // Populated: an empty-body Present entry, a populated Present entry, AND a header-only
          // Repairing entry (op 6, body_checksum only) — exercises both body-state wire tags.
          std::vec![
            entry(4, b""),
            entry(5, b"hi"),
            PreparedEntry::repairing(
              OpNumber::with(6),
              ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
              RequestNumber::with(6),
              0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
            ),
          ],
        )
        .with_checkpoint_op(OpNumber::with(3)), // non-zero advertised floor — round-trips
      ),
      Message::StartView(
        StartView::new(
          View::with(7),
          OpNumber::with(0),
          OpNumber::with(0),
          ReplicaId::new(0),
          std::vec![], // empty log slice edge
        )
        .with_checkpoint_op(OpNumber::with(u64::MAX)), // edge scalar floor — round-trips
      ),
      Message::GetView(GetView::new(View::with(5), ReplicaId::new(3), u64::MAX)),
      Message::RequestPrepare(RequestPrepare::new(
        View::with(2),
        OpNumber::with(7),
        ReplicaId::new(3),
      )),
      Message::Recovery(Recovery::new(ReplicaId::new(9), 0xABCD)),
      Message::RecoveryResponse(
        RecoveryResponse::new(
          View::with(3),
          OpNumber::with(5),
          OpNumber::with(4),
          ReplicaId::new(0),
          0xBEEF,
          std::vec![entry(5, b"e")],
        )
        .with_checkpoint_op(OpNumber::with(2)), // non-zero advertised floor — round-trips
      ),
      Message::RequestSync(RequestSync::new(
        View::with(4),
        OpNumber::with(2),
        ReplicaId::new(3),
        0xBEEF,
        true, // recovery flag set
      )),
      Message::SyncCheckpoint(SyncCheckpoint::new(
        View::with(4),
        OpNumber::with(8),
        u128::MAX,
        ReplicaId::new(0),
        0xBEEF,
        Bytes::from_static(b"snapshot-envelope"),
      )),
      Message::RequestPrepareRange(RequestPrepareRange::new(
        View::with(2),
        OpNumber::with(7),
        OpNumber::with(70),
        ReplicaId::new(3),
      )),
      Message::RepairBatch(RepairBatch::new(
        View::with(4),
        OpNumber::with(9),
        OpNumber::with(7),
        // Populated: an empty-body Present entry, a populated Present entry, AND a header-only
        // Repairing entry — exercises both body-state wire tags inside the batch log slice.
        std::vec![
          entry(7, b""),
          entry(8, b"hi"),
          PreparedEntry::repairing(
            OpNumber::with(9),
            ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
            RequestNumber::with(9),
            0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
          ),
        ],
      )),
      Message::SyncCheckpointMeta(SyncCheckpointMeta::new(
        View::with(4),
        OpNumber::with(8),
        u128::MAX,
        u64::MAX, // edge scalar total_len — round-trips
        ReplicaId::new(0),
        0xBEEF,
      )),
      Message::RequestSyncChunk(RequestSyncChunk::new(
        View::with(4),
        OpNumber::with(8),
        u128::MAX,
        u64::MAX, // edge scalar offset — round-trips
        ReplicaId::new(3),
        0xBEEF,
      )),
      Message::SyncChunk(SyncChunk::new(
        View::with(4),
        OpNumber::with(8),
        u128::MAX,
        17,
        0,
        ReplicaId::new(0),
        0xBEEF,
        Bytes::from_static(b"snapshot-envelope"),
      )),
      Message::PrepareBatch(PrepareBatch::new(
        View::with(4),
        OpNumber::with(9),
        OpNumber::with(7),
        // Populated: an empty-body Present entry, a populated Present entry, AND a header-only
        // Repairing entry — exercises both body-state wire tags inside the batch log slice (the
        // sender never emits a Repairing entry, but the codec must round-trip any well-formed one).
        std::vec![
          entry(10, b""),
          entry(11, b"hi"),
          PreparedEntry::repairing(
            OpNumber::with(12),
            ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
            RequestNumber::with(12),
            0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
          ),
        ],
      )),
    ]
  }

  #[test]
  fn encoded_len_matches_encode_len_for_every_variant() {
    // The preflight size must exactly equal the encoded length for every variant (incl. empty and
    // populated bodies/log slices), so the transport's pre-encode frame-cap check can never disagree
    // with the bytes a subsequent encode would actually produce.
    for m in one_of_each_variant() {
      assert_eq!(
        m.encoded_len(),
        m.encode().len(),
        "encoded_len() must equal encode().len() for {}",
        m.kind_str()
      );
    }
    // Also the recovery=false RequestSync, whose bool is the only field that differs by value.
    let rq = Message::RequestSync(RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      false,
    ));
    assert_eq!(rq.encoded_len(), rq.encode().len());
  }

  #[test]
  fn max_reply_body_len_is_tight_against_the_reply_carrier() {
    // The reply-size contract is tight to the byte: a reply body of exactly `max_reply_body_len()`
    // encodes as a `Reply` of exactly `MAX_FRAME_LEN` (deliverable), and one byte more exceeds the
    // cap (the transport refuses the send — unrecoverable for an already-committed op, which is why
    // `StateMachine::apply` carries the bound as an embedder obligation).
    let reply_of = |len: usize| {
      Message::Reply(Reply::new(
        View::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        Bytes::from(std::vec![0u8; len]),
      ))
    };
    let max = max_reply_body_len();
    let cap = MAX_FRAME_LEN as usize;
    assert_eq!(
      reply_of(max).encode().len(),
      cap,
      "a max-size reply body lands exactly on MAX_FRAME_LEN"
    );
    assert!(
      reply_of(max + 1).encode().len() > cap,
      "one byte over the max pushes the Reply past the frame cap"
    );
    // The overhead const matches the Reply encode arm widths (header 3 + view 8 + client 16 +
    // request 8 + body length prefix 4).
    assert_eq!(REPLY_ENCODE_OVERHEAD, 39);
    assert_eq!(reply_of(0).encode().len(), REPLY_ENCODE_OVERHEAD);
  }

  #[test]
  fn chunked_sync_carriers_are_tight_against_the_frame_cap() {
    // The chunked-transfer frame arithmetic, pinned by REAL encodings (not just the modelled
    // consts): a max-fill SyncChunk lands EXACTLY on MAX_FRAME_LEN (so the chunked path can never
    // produce an oversized frame, and the chunk size wastes nothing), one byte more exceeds it, and
    // the unchunked threshold is byte-tight on the SyncCheckpoint carrier (an envelope of exactly
    // `max_unchunked_snapshot_len()` ships whole at exactly the cap; one more byte forces chunking).
    let cap = MAX_FRAME_LEN as usize;
    let chunk_of = |len: usize| {
      Message::SyncChunk(SyncChunk::new(
        View::with(1),
        OpNumber::with(8),
        0xFEED,
        len as u64,
        0,
        ReplicaId::new(0),
        0xBEEF,
        Bytes::from(std::vec![0u8; len]),
      ))
    };
    assert_eq!(SYNC_CHUNK_CARRIER_OVERHEAD, 64);
    assert_eq!(chunk_of(0).encode().len(), SYNC_CHUNK_CARRIER_OVERHEAD);
    assert_eq!(
      chunk_of(SYNC_CHUNK_LEN).encode().len(),
      cap,
      "a max-fill SyncChunk lands exactly on MAX_FRAME_LEN"
    );
    assert!(
      chunk_of(SYNC_CHUNK_LEN + 1).encode().len() > cap,
      "one byte over the chunk size exceeds the frame cap"
    );

    let checkpoint_of = |len: usize| {
      Message::SyncCheckpoint(SyncCheckpoint::new(
        View::with(1),
        OpNumber::with(8),
        0xFEED,
        ReplicaId::new(0),
        0xBEEF,
        Bytes::from(std::vec![0u8; len]),
      ))
    };
    assert_eq!(
      checkpoint_of(max_unchunked_snapshot_len()).encode().len(),
      cap,
      "an envelope of exactly the unchunked threshold ships whole at exactly the cap"
    );
    assert!(
      checkpoint_of(max_unchunked_snapshot_len() + 1)
        .encode()
        .len()
        > cap,
      "one byte over the threshold cannot ship whole — the donor must chunk it"
    );

    // The two fixed-size chunked-transfer messages are small constants (52 bytes each).
    let meta = Message::SyncCheckpointMeta(SyncCheckpointMeta::new(
      View::with(1),
      OpNumber::with(8),
      0xFEED,
      1,
      ReplicaId::new(0),
      0xBEEF,
    ));
    let pull = Message::RequestSyncChunk(RequestSyncChunk::new(
      View::with(1),
      OpNumber::with(8),
      0xFEED,
      0,
      ReplicaId::new(2),
      0xBEEF,
    ));
    assert_eq!(meta.encode().len(), 52);
    assert_eq!(pull.encode().len(), 52);
  }

  #[test]
  fn prepare_batch_is_tight_against_the_frame_cap() {
    // The batched-retransmit frame arithmetic, pinned by REAL encodings (not just the modelled
    // consts): the carrier const matches the encode arm widths, a max-fill one-entry PrepareBatch
    // lands EXACTLY on MAX_FRAME_LEN, one byte more exceeds it, and a multi-entry batch whose
    // per-entry costs sum exactly to the budget also lands exactly on the cap — so the retransmit
    // accumulator (budget = MAX_FRAME_LEN - PREPARE_BATCH_CARRIER_OVERHEAD, cost =
    // present_entry_encoded_len) can never produce an oversized frame, and wastes nothing.
    let cap = MAX_FRAME_LEN as usize;
    let batch_of = |entries: std::vec::Vec<PreparedEntry>| {
      Message::PrepareBatch(PrepareBatch::new(
        View::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        entries,
      ))
    };
    let entry_of = |op: u64, len: usize| {
      PreparedEntry::new(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::from(std::vec![0u8; len]),
      )
    };
    // The carrier const matches the encode arm widths (header 3 + view/commit/checkpoint_op 24 +
    // log count prefix 4) — an empty batch encodes to exactly the carrier.
    assert_eq!(PREPARE_BATCH_CARRIER_OVERHEAD, 31);
    assert_eq!(
      batch_of(std::vec![]).encode().len(),
      PREPARE_BATCH_CARRIER_OVERHEAD
    );
    let budget = cap - PREPARE_BATCH_CARRIER_OVERHEAD;
    // Max-fill single entry: a body whose entry cost is exactly the budget lands exactly on the cap
    // (the first-entry-progress case — one such op still ships); one byte more exceeds it.
    let max = budget - present_entry_encoded_len(0);
    assert_eq!(
      batch_of(std::vec![entry_of(1, max)]).encode().len(),
      cap,
      "a max-fill one-entry PrepareBatch lands exactly on MAX_FRAME_LEN"
    );
    assert!(
      batch_of(std::vec![entry_of(1, max + 1)]).encode().len() > cap,
      "one byte over the max pushes the PrepareBatch past the frame cap"
    );
    // Multi-entry max-fill: two entries whose costs sum exactly to the budget land exactly on the
    // cap — the running-cost accumulation models the encoding to the byte across entries.
    let half = budget / 2;
    let (a, b) = (
      half - present_entry_encoded_len(0),
      (budget - half) - present_entry_encoded_len(0),
    );
    assert_eq!(
      present_entry_encoded_len(a) + present_entry_encoded_len(b),
      budget
    );
    assert_eq!(
      batch_of(std::vec![entry_of(1, a), entry_of(2, b)])
        .encode()
        .len(),
      cap,
      "two entries summing exactly to the budget land exactly on MAX_FRAME_LEN"
    );
  }

  /// The transport's `max_request_body_len()` is the largest client body deliverable on EVERY message
  /// that can carry it, and it is tight to the byte. The view-change log carriers
  /// (`DoViewChange` / `StartView` / `RecoveryResponse`) are HEADER-ONLY (they ship no body — see
  /// `Endpoint::log_entries`), so the SAME body bytes travel only as the `Request` the client sends, the
  /// `Prepare` the primary replicates, and — once the op is logged — a single `Body::Present`
  /// `PreparedEntry` inside a `RepairBatch` (the windowed peer-repair answer) or a `PrepareBatch` (the
  /// primary's batched retransmit; byte-identical framing). This proves, via the ACTUAL
  /// `encode().len()` (real messages, not just the modelled `encoded_len()`), that a body of exactly
  /// the bound fits `MAX_FRAME_LEN` on ALL of those carriers, that the BINDING carriers are the tied
  /// single-entry `RepairBatch`/`PrepareBatch` (each lands EXACTLY on the cap), that one byte more
  /// pushes each past the cap, and — separately — that a header-only `DoViewChange` is INSENSITIVE to
  /// body size (a whole band of max-body ops stays far under cap as fixed-size headers). Enumerating
  /// every carrier here means a future message that wraps the body in MORE framing fails this test
  /// until the bound accounts for it.
  #[cfg(feature = "tcp")]
  #[test]
  fn max_request_body_len_is_tight_against_every_body_carrier() {
    use crate::{MAX_FRAME_LEN, max_request_body_len};

    let max = max_request_body_len();
    let cap = MAX_FRAME_LEN as usize;

    let client = ClientId::new(7);
    let request = RequestNumber::with(1);

    // Each closure builds a real message that carries a body of `len` bytes. The `RepairBatch` and
    // `PrepareBatch` wrap it in a single-entry `Body::Present` log slice — the worst case for one
    // maximal body (a multi-entry batch only spreads more fixed framing across more bodies; the
    // byte-bounded serve/retransmit never exceeds the cap).
    let body_of = |len: usize| Bytes::from(std::vec![0u8; len]);
    let request_of = |len: usize| Message::Request(Request::new(client, request, body_of(len)));
    let prepare_of = |len: usize| {
      Message::Prepare(Prepare::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        client,
        request,
        body_of(len),
      ))
    };
    let repair_batch_of = |len: usize| {
      Message::RepairBatch(RepairBatch::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0),
        std::vec![PreparedEntry::new(
          OpNumber::with(1),
          client,
          request,
          body_of(len),
        )],
      ))
    };
    let prepare_batch_of = |len: usize| {
      Message::PrepareBatch(PrepareBatch::new(
        View::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        std::vec![PreparedEntry::new(
          OpNumber::with(1),
          client,
          request,
          body_of(len),
        )],
      ))
    };

    // Every BODY carrier of a max-size body, paired with its builder, checked by its REAL encoded length.
    let carriers: [(&str, &dyn Fn(usize) -> Message); 4] = [
      ("Request", &request_of),
      ("Prepare", &prepare_of),
      ("RepairBatch", &repair_batch_of),
      ("PrepareBatch", &prepare_batch_of),
    ];

    // At the max: every body carrier fits the frame cap (the bound is the MAX over all per-carrier
    // overheads, so the body fits the tightest carrier and a fortiori the rest).
    let mut tightest = 0usize;
    for (name, build) in carriers {
      let encoded = build(max).encode().len();
      assert!(
        encoded <= cap,
        "a max-size body carried by {name} must fit the frame cap: {encoded} > {cap}"
      );
      tightest = tightest.max(encoded);
    }
    // Tight: the tightest carrier sits EXACTLY at the cap, so the bound wastes nothing. The
    // single-entry `RepairBatch` and `PrepareBatch` tie as this binding max — each larger than the
    // `Prepare` hop by the per-entry log framing.
    assert_eq!(
      tightest, cap,
      "the tightest body carrier lands exactly on MAX_FRAME_LEN at the max body"
    );
    let rb_at = repair_batch_of(max).encode().len();
    assert_eq!(
      rb_at, cap,
      "a one-entry RepairBatch is a binding body carrier and lands exactly on MAX_FRAME_LEN"
    );
    let pb_at = prepare_batch_of(max).encode().len();
    assert_eq!(
      pb_at, cap,
      "a one-entry PrepareBatch ties it and lands exactly on MAX_FRAME_LEN"
    );

    // One byte more: the BINDING carriers (`RepairBatch`/`PrepareBatch`) exceed the cap, so the
    // transport would drop them. The smaller-overhead carriers (`Request`, `Prepare`) may still fit at
    // max+1 — it is enough that the binding ones do not, which is exactly why the bound subtracts the
    // LARGEST per-carrier overhead.
    let rb_over = repair_batch_of(max + 1).encode().len();
    assert!(
      rb_over > cap,
      "one byte over the max must push a one-entry RepairBatch past the frame cap: {rb_over} <= {cap}"
    );
    let pb_over = prepare_batch_of(max + 1).encode().len();
    assert!(
      pb_over > cap,
      "one byte over the max must push a one-entry PrepareBatch past the frame cap: {pb_over} <= {cap}"
    );

    // The header-only view-change carriers are INSENSITIVE to body size: a `DoViewChange` whose entry is
    // header-only (`Repairing`) encodes the same whether the op's body is empty or `max` bytes — it ships
    // only the 16-byte `body_checksum`. So a max-body op rides a view change far under the frame cap, the
    // whole point of the header-only carrier. (The DEEP-band fit is bounded separately by
    // `MAX_HEADER_ONLY_BAND_DEPTH` / the `MAX_CHECKPOINT_OPS` cap.)
    let header_only_dvc = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      ReplicaId::new(0),
      std::vec![PreparedEntry::repairing(
        OpNumber::with(1),
        client,
        request,
        0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
      )],
    ));
    assert!(
      header_only_dvc.encode().len() < cap / 2,
      "a header-only DoViewChange entry is body-size-insensitive and well under the frame cap"
    );
  }

  #[test]
  fn every_variant_round_trips_through_the_wire_codec() {
    let all = one_of_each_variant();
    assert_eq!(all.len(), 20, "every Message variant is represented");
    for m in &all {
      let bytes = m.encode();
      let back = Message::decode(&bytes).expect("round-trip decodes");
      assert_eq!(&back, m, "decode(encode(m)) == m for {}", m.kind_str());
      // The encoding leads with the wire version then the variant tag.
      assert_eq!(
        &bytes[..2],
        &crate::WIRE_VERSION.to_be_bytes(),
        "leads with WIRE_VERSION"
      );
    }
    // Also exercise an ordinary state-sync (recovery = false) so both bool encodings round-trip.
    let rq = Message::RequestSync(RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      false,
    ));
    assert_eq!(Message::decode(&rq.encode()).unwrap(), rq);
  }

  #[test]
  fn commit_golden_bytes_pin_the_wire_layout() {
    // A small variant pinned exactly: WIRE_VERSION(u16) ++ tag 4 ++ view ++ commit ++ checkpoint_op.
    let c = Message::Commit(Commit::new(
      View::with(4),
      OpNumber::with(9),
      OpNumber::with(7),
    ));
    let expected: std::vec::Vec<u8> = std::vec![
      0, 3, 4, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 7,
    ];
    assert_eq!(c.encode(), expected, "Commit wire layout is pinned");
  }

  #[test]
  fn do_view_change_golden_bytes_pin_the_nested_log_layout() {
    // A nested variant pinned exactly: header (ver 3 + tag 6), scalars (incl. the advertised
    // checkpoint floor after the commit), then a 1-entry log slice (count=1, op, client, request,
    // body-state tag 0 = Present, length-prefixed body "hi").
    let dvc = Message::DoViewChange(
      DoViewChange::new(
        View::with(3),
        View::with(2),
        OpNumber::with(5),
        OpNumber::with(4),
        ReplicaId::new(6),
        std::vec![PreparedEntry::new(
          OpNumber::with(5),
          ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
          RequestNumber::with(9),
          Bytes::from_static(b"hi"),
        )],
      )
      .with_checkpoint_op(OpNumber::with(3)),
    );
    let expected: std::vec::Vec<u8> = std::vec![
      0, 3, 6, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
      0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 3, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6,
      7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 2, 104, 105,
    ];
    assert_eq!(dvc.encode(), expected, "DoViewChange wire layout is pinned");
  }

  #[test]
  fn do_view_change_golden_bytes_pin_a_repairing_entry() {
    // The header-only (Repairing) entry layout pinned exactly: same scalars (incl. the advertised
    // checkpoint floor after the commit), then body-state tag 1 = Repairing, followed by the
    // 16-byte body_checksum (NO length-prefixed body).
    let dvc = Message::DoViewChange(
      DoViewChange::new(
        View::with(3),
        View::with(2),
        OpNumber::with(5),
        OpNumber::with(4),
        ReplicaId::new(6),
        std::vec![PreparedEntry::repairing(
          OpNumber::with(5),
          ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
          RequestNumber::with(9),
          0x1112_1314_1516_1718_191A_1B1C_1D1E_1F20,
        )],
      )
      .with_checkpoint_op(OpNumber::with(3)),
    );
    let expected: std::vec::Vec<u8> = std::vec![
      0, 3, 6, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
      0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 3, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6,
      7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 9, 1, 17, 18, 19, 20, 21, 22, 23,
      24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    assert_eq!(
      dvc.encode(),
      expected,
      "DoViewChange Repairing-entry wire layout is pinned"
    );
    // And it round-trips, preserving the op/client/request/checksum with no body bytes.
    let back = Message::decode(&dvc.encode()).expect("round-trips");
    let e = &back.unwrap_do_view_change().into_log()[0];
    assert!(e.is_repairing(), "decoded back as a Repairing entry");
    assert_eq!(e.op(), OpNumber::with(5));
    assert_eq!(
      e.client(),
      ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10)
    );
    assert_eq!(e.request(), RequestNumber::with(9));
    assert_eq!(e.body(), None, "a Repairing entry carries no bytes");
    assert_eq!(e.body_checksum(), 0x1112_1314_1516_1718_191A_1B1C_1D1E_1F20);
  }

  #[test]
  fn decode_rejects_bad_version_unknown_tag_and_truncation_without_panicking() {
    let bytes = Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
    ))
    .encode();
    // Empty / too-short to even hold the version → Truncated.
    assert!(matches!(
      Message::decode(&[]),
      Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
      Message::decode(&[0]),
      Err(CodecError::Truncated { .. })
    ));
    // A bad leading version → UnknownVersion.
    let mut badver = bytes.to_vec();
    badver[1] = 9;
    assert!(matches!(
      Message::decode(&badver),
      Err(CodecError::UnknownVersion(9))
    ));
    // An unknown variant tag (99) → UnknownTag.
    let mut badtag = bytes.to_vec();
    badtag[2] = 99;
    assert!(matches!(
      Message::decode(&badtag),
      Err(CodecError::UnknownTag(99))
    ));
    // Truncating a variant mid-field → Truncated (never an OOB panic).
    assert!(matches!(
      Message::decode(&bytes[..bytes.len() - 1]),
      Err(CodecError::Truncated { .. })
    ));
    // Trailing bytes after a fully-decoded variant → TrailingBytes.
    let mut over = bytes.to_vec();
    over.push(0);
    assert!(matches!(
      Message::decode(&over),
      Err(CodecError::TrailingBytes(1))
    ));
  }

  #[test]
  fn decode_rejects_an_oversized_length_prefix_without_panicking() {
    // A SyncCheckpoint's snapshot length prefix overstated past the buffer → LengthOverflow, not
    // an out-of-range slice.
    let sc = Message::SyncCheckpoint(SyncCheckpoint::new(
      View::with(1),
      OpNumber::with(1),
      0,
      ReplicaId::new(0),
      0,
      Bytes::from_static(b"abc"),
    ));
    let mut bytes = sc.encode().to_vec();
    // The snapshot length prefix is the last 4 bytes before the 3 body bytes.
    let n = bytes.len();
    bytes[n - 7..n - 3].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert!(matches!(
      Message::decode(&bytes),
      Err(CodecError::LengthOverflow { .. })
    ));

    // A DoViewChange whose log COUNT is absurd → LengthOverflow, caught before allocating.
    let dvc = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(0),
      ReplicaId::new(0),
      std::vec![entry(1, b"x")],
    ));
    let mut d = dvc.encode().to_vec();
    // Locate the log count:
    // ver(2)+tag(1)+view(8)+log_view(8)+op(8)+commit(8)+checkpoint_op(8)+replica(1) = 44.
    d[44..48].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert!(matches!(
      Message::decode(&d),
      Err(CodecError::LengthOverflow { .. })
    ));
  }

  #[test]
  fn decode_never_panics_on_truncations_or_random_bytes() {
    // Fuzz-style no-panic sweep: every prefix of every variant's encoding, plus a pseudo-random
    // stream of growing length (with a valid version/tag header sometimes prepended), must always
    // yield a typed error — never a panic / out-of-range index.
    for m in one_of_each_variant() {
      let enc = m.encode();
      for n in 0..=enc.len() {
        let _ = Message::decode(&enc[..n]);
      }
    }
    let mut x = 0x1357_9bdfu32;
    for len in 0..600usize {
      let mut v = std::vec::Vec::with_capacity(len + 3);
      // Sometimes prepend a well-formed version + a random tag to drive deeper into the parsers.
      if len % 3 == 0 {
        v.extend_from_slice(&crate::WIRE_VERSION.to_be_bytes());
        v.push((len as u8) % 16);
      }
      for _ in 0..len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
      }
      let _ = Message::decode(&v); // must not panic
    }
  }
}

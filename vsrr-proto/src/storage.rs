//! Pluggable durable-storage contract: value types + the `Wal`/`Superblock` traits.
//!
//! The proto owns no log; it orchestrates consensus over a user-supplied `Wal` +
//! `Superblock` (wired in M3.1). All faults surface as data (`SlotStatus::Faulty`,
//! `WalDone::Fault`) — never as panics; the proto verifies `Header` checksums itself.

use std::vec::Vec;

use bytes::Bytes;

use crate::codec::{CodecError, Reader};
use crate::{ClientId, OpNumber, RequestNumber, View};

/// On-disk header format version (bumped on any wire/disk layout change).
pub const HEADER_VERSION: u16 = 1;

/// The canonical-body length of an encoded [`Header`]: the six checksummed fields, each
/// widened to a big-endian `u128` (the exact bytes [`Header`]'s checksum hashes). These are
/// the bytes shared between [`Header::encode`] and the checksum, so the on-disk checksum can
/// never disagree with the codec output.
const HEADER_CANONICAL_LEN: usize = 6 * 16;

/// The fixed on-disk size of an encoded [`Header`]. Layout: the stored `checksum` (16 bytes,
/// big-endian) followed by the canonical body (the six checksummed fields, each a big-endian
/// `u128`), zero-padded to this sector-friendly fixed width. The trailing reserved bytes are
/// written as zero and ignored
/// on decode, leaving room for future fields without a length change (a real WAL writes
/// fixed-size header slots). `16 (checksum) + 96 (canonical) = 112`, padded to `128`.
pub const HEADER_ENCODED_LEN: usize = 128;

/// Correlation id matching a submitted storage op to its completion.
///
/// **Lifetime contract (load-bearing for a driver that retains a completion-correlation table).**
/// `OpId`s are unique only WITHIN a single `Endpoint` instance's lifetime: both `Endpoint::new` and
/// `Endpoint::recover` RESTART the sequence (the first storage op after a crash + `recover` reuses
/// `OpId(1)`). This is safe for the proto itself — a fresh `recover` issues no writes whose stale
/// completions could alias, and the in-memory sim drops in-flight ops on crash — but a driver keeping
/// a `user_data → op` table (e.g. an io_uring `user_data` map) ACROSS a RESTART-IN-PLACE (the endpoint
/// rebuilt via `recover` WITHOUT tearing down the underlying io_uring fd) could collide a stale
/// completion's `OpId(1)` with the new endpoint's `OpId(1)`. A driver that retains such a table across
/// endpoint re-creation MUST therefore DRAIN or CANCEL all in-flight storage ops before constructing
/// the new endpoint, so no pre-restart completion is delivered against a post-restart `OpId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OpId(u64);
impl OpId {
  /// Creates an `OpId`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(n: u64) -> Self {
    Self(n)
  }

  /// The underlying value.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn get(self) -> u64 {
    self.0
  }
}

/// Per-WAL-slot status (the present/nack tracking, derived by the impl).
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant, derive_more::Display)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum SlotStatus {
  /// No entry has occupied this slot.
  Empty,
  /// An append is in flight (submitted, not yet durable).
  Dirty,
  /// A durable, checksum-valid entry.
  Clean,
  /// Read back corrupt/absent — present-but-unusable (nacked in view change).
  Faulty,
}
impl SlotStatus {
  /// The stable lowercase slug for this status.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Empty => "empty",
      Self::Dirty => "dirty",
      Self::Clean => "clean",
      Self::Faulty => "faulty",
    }
  }
}

/// Checksummed, versioned WAL-entry header (a small fixed-size all-`Copy` value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
  version: u16,
  checksum: u128,
  op: OpNumber,
  view: View,
  client: ClientId,
  request: RequestNumber,
  body_checksum: u128,
}
impl Header {
  /// Creates a header for `body`, computing the body + header checksums.
  pub fn new(
    op: OpNumber,
    view: View,
    client: ClientId,
    request: RequestNumber,
    body: &[u8],
  ) -> Self {
    let body_checksum = fnv1a_128(body);
    let mut h = Self {
      version: HEADER_VERSION,
      checksum: 0,
      op,
      view,
      client,
      request,
      body_checksum,
    };
    h.checksum = h.compute_checksum();
    h
  }

  /// The header format version.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn version(&self) -> u16 {
    self.version
  }

  /// The header checksum.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checksum(&self) -> u128 {
    self.checksum
  }

  /// The operation number this entry records.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The view in which this entry was written.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The client that submitted this operation.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The client request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The checksum of the body bytes.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn body_checksum(&self) -> u128 {
    self.body_checksum
  }

  /// Whether this header + `body` are self-consistent (header checksum valid AND body matches).
  pub fn verify(&self, body: &[u8]) -> bool {
    self.checksum == self.compute_checksum() && self.body_checksum == fnv1a_128(body)
  }

  /// Writes the CANONICAL body of this header — the six checksummed fields, each widened to a
  /// big-endian `u128`, in the fixed order `version, op, view, client, request, body_checksum`
  /// — into `out`. This is the single source of truth shared by BOTH `compute_checksum`
  /// (which hashes exactly these bytes) AND [`Self::encode`] (which embeds them after the stored
  /// checksum), so the on-disk checksum can never disagree with the codec output. The order +
  /// `u128` widening match the original ad-hoc checksum loop verbatim, so the checksum VALUE is
  /// unchanged for already-persisted data. Exactly [`HEADER_CANONICAL_LEN`] bytes are appended.
  fn write_canonical(&self, out: &mut Vec<u8>) {
    for word in [
      self.version as u128,
      self.op.get() as u128,
      self.view.get() as u128,
      self.client.get(),
      self.request.get() as u128,
      self.body_checksum,
    ] {
      out.extend_from_slice(&word.to_be_bytes());
    }
  }

  fn compute_checksum(&self) -> u128 {
    // Hash exactly the canonical body bytes — the same bytes [`Self::encode`] embeds — so the
    // codec output and the checksum are derived from one definition (audit P3).
    let mut buf = Vec::with_capacity(HEADER_CANONICAL_LEN);
    self.write_canonical(&mut buf);
    fnv1a_128(&buf)
  }

  /// Encodes this header as a FIXED-SIZE [`HEADER_ENCODED_LEN`]-byte buffer (sector-friendly for
  /// a real WAL). Layout: the stored `checksum` (16 bytes, big-endian) then the canonical body
  /// (`write_canonical`), zero-padded to the fixed width. The canonical body bytes are EXACTLY
  /// what the header checksum (`compute_checksum`) hashes, so a decode can re-verify integrity.
  /// Total (panic-free): `16 + 96` content bytes + reserved zero padding.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn encode(&self) -> [u8; HEADER_ENCODED_LEN] {
    let mut buf = Vec::with_capacity(HEADER_ENCODED_LEN);
    buf.extend_from_slice(&self.checksum.to_be_bytes());
    self.write_canonical(&mut buf);
    buf.resize(HEADER_ENCODED_LEN, 0); // reserved tail (future fields), written as zero
    buf
      .try_into()
      .expect("buffer is resized to exactly HEADER_ENCODED_LEN")
  }

  /// Decodes a fixed-size [`HEADER_ENCODED_LEN`]-byte header buffer, bounds-checked and
  /// panic-free on any truncated / corrupt / adversarial input.
  ///
  /// Rejects (never panics) a short buffer ([`CodecError::Truncated`]) or an unknown
  /// `version` ([`CodecError::UnknownVersion`]). The decoded `checksum` is the value the
  /// writer stored; it is NOT re-validated here (a faulty WAL slot is faults-as-data the proto
  /// checks via [`Self::verify`]) — but the round-trip identity holds: `decode(h.encode()) == h`,
  /// and the re-derived checksum equals the stored one for an intact buffer. The trailing
  /// reserved padding is ignored. Accepts a buffer of EXACTLY [`HEADER_ENCODED_LEN`] bytes;
  /// trailing bytes beyond that are [`CodecError::TrailingBytes`].
  pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
    let mut r = Reader::new(buf);
    let checksum = r.u128()?;
    // The canonical body widens EVERY field to a big-endian u128 (that is what the checksum
    // hashes), so the leading `version` occupies a full 16-byte word here too. Read it widened
    // and narrow to u16: a value that does not fit u16 — or is not HEADER_VERSION — is a corrupt
    // or foreign buffer and is rejected as UnknownVersion (saturating the report at u16::MAX).
    let version_raw = r.u128()?;
    let version = u16::try_from(version_raw).unwrap_or(u16::MAX);
    if version_raw != HEADER_VERSION as u128 {
      return Err(CodecError::UnknownVersion(version));
    }
    // Read each remaining widened word and narrow back to the field's native type (the high bits
    // are always zero for a value this codec produced).
    let op = OpNumber::with(r.u128()? as u64);
    let view = View::with(r.u128()? as u64);
    let client = ClientId::new(r.u128()?);
    let request = RequestNumber::with(r.u128()? as u64);
    let body_checksum = r.u128()?;
    // Consume + ignore the reserved zero padding, then assert nothing trails the fixed slot.
    r.take(HEADER_ENCODED_LEN.saturating_sub(16 + HEADER_CANONICAL_LEN))?;
    r.finish()?;
    Ok(Self {
      version,
      checksum,
      op,
      view,
      client,
      request,
      body_checksum,
    })
  }
}

/// The durable VSR root written to the superblock. Invariants checked ⇒ `try_new`.
///
/// Carries — alongside `(view, log_view, commit, checkpoint_op, checkpoint_id)` — the CANONICAL
/// [`Header`]s of the un-checkpointed COMMITTED band `(checkpoint_op .. commit]`, TigerBeetle's
/// `vsr_headers` mechanism. These are written atomically with the view/commit they describe (one
/// struct, one root write) and let `recover` independently verify each committed-band WAL slot against
/// the canonical body checksum — a slot whose own (self-consistent) header kept a STALE superseded
/// body is then DETECTED and routed to peer-repair instead of blindly re-derived from the WAL. The set
/// is SPARSE (codex R12-F1): one header per committed-band op the writer HELD, so a repair hole omits
/// only that op while later held ops keep their headers (recovery verifies each held op individually
/// rather than dropping a whole suffix below one hole). The band is bounded by `Config::checkpoint_ops`
/// (post-checkpoint GC keeps `commit - checkpoint_op` within ~one checkpoint interval), so the list
/// stays small. Holding a `Vec` makes this `Clone` but not `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsrState {
  view: View,
  log_view: View,
  /// The KNOWN-committed frontier — VSR's commit-number `k`, the highest op the writer KNOWS is
  /// committed cluster-wide (the replica's `commit_max`), which `recover` reads back as `commit_max`
  /// (codex R9-F1/R10-F2). It may exceed the writer's locally-APPLIED `commit_min`: a replica held at a
  /// stale/faulty repair hole knows op N is committed yet has not applied it, and the root must record N
  /// so a re-recovered replica's DoViewChange does not under-report the frontier.
  commit: OpNumber,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  /// Canonical headers for the committed band `(checkpoint_op .. commit]` — a SPARSE, op-ascending set
  /// holding ONE header per committed-band op the writer actually HELD (codex R12-F1). A repair hole —
  /// or a hole in `(commit_min, commit]` when the writer's applied frontier lags — simply OMITS that
  /// op's header; a held op above it keeps its own (so the list may be SHORTER than the full band AND
  /// may contain gaps; see [`Self::try_new`], which validates in-range strictly-ascending ops but allows
  /// gaps). Private; read via [`Self::committed_headers_slice`]. The per-entry `body_checksum` is the
  /// load-bearing field recovery checks the WAL against.
  committed_headers: Vec<Header>,
}

impl Default for VsrState {
  /// The fresh-cluster root — delegates to [`VsrState::new`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
  }
}

impl VsrState {
  /// Creates a durable root, validating `log_view <= view` and `commit >= checkpoint_op`.
  ///
  /// `committed_headers` are the canonical headers of the committed band `(checkpoint_op .. commit]` —
  /// a SPARSE canonical-header set over the committed-band ops the writer actually HELD, ordered by op
  /// (codex R12-F1). It is NOT required to be contiguous: a repair hole the writer had simply omits that
  /// op's header, and a LATER held op keeps its own header (so recovery can verify each held op
  /// individually rather than dropping a whole suffix because of one lower hole). The set is VALIDATED,
  /// not silently truncated — every header's op must be in `(checkpoint_op .. commit]` and the ops must
  /// be STRICTLY INCREASING (gaps allowed; no duplicates, no descents); a header out of that range, a
  /// duplicate, or a descent is REJECTED (so a valid sparse list is never quietly shortened). An empty
  /// band (`commit == checkpoint_op`) yields an empty list.
  pub fn try_new(
    view: View,
    log_view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    committed_headers: Vec<Header>,
  ) -> Result<Self, VsrStateError> {
    if log_view.get() > view.get() {
      return Err(VsrStateError::LogViewAboveView);
    }
    if commit.get() < checkpoint_op.get() {
      return Err(VsrStateError::CommitBelowCheckpoint);
    }
    // Validate the SPARSE in-band header set (codex R12-F1): every op strictly in `(checkpoint_op ..
    // commit]`, in STRICTLY-INCREASING op order — GAPS ARE ALLOWED (a hole the writer held is simply
    // omitted; a held op above it keeps its header). Reject (never silently truncate) an out-of-range,
    // duplicate, or descending op, so the stored band remains a trustworthy per-op canonical-identity set
    // recovery indexes by op. `prev` tracks the last accepted op (starting at `checkpoint_op`, so the
    // first header must be strictly above it — the strict-increase check subsumes the lower-bound check).
    let mut prev = checkpoint_op.get();
    for h in &committed_headers {
      let op = h.op().get();
      if op <= prev {
        // Either at/below the checkpoint (the first iteration) or not strictly above the previous op (a
        // duplicate or a descent). The first case is an out-of-band-below header; the rest are ordering.
        return Err(if prev == checkpoint_op.get() {
          VsrStateError::HeaderOutOfBand
        } else {
          VsrStateError::HeadersNotAscending
        });
      }
      if op > commit.get() {
        return Err(VsrStateError::HeaderOutOfBand);
      }
      prev = op;
    }
    Ok(Self {
      view,
      log_view,
      commit,
      checkpoint_op,
      checkpoint_id,
      committed_headers,
    })
  }

  /// The fresh-cluster root (all zero, no committed-band headers).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new() -> Self {
    Self {
      view: View::new(),
      log_view: View::new(),
      commit: OpNumber::new(),
      checkpoint_op: OpNumber::new(),
      checkpoint_id: 0,
      committed_headers: Vec::new(),
    }
  }

  /// The current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The view in which the log was last written.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn log_view(&self) -> View {
    self.log_view
  }

  /// The KNOWN-committed frontier (VSR's commit-number `k`) — the highest op known committed
  /// cluster-wide when this root was written (the writer's `commit_max`). `recover` reads this as
  /// `commit_max`; it may exceed the locally-applied `commit_min` (a held repair hole), so it must not
  /// be confused with the applied frontier.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number at which the latest checkpoint was taken.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// An opaque id for the latest checkpoint (e.g. a content hash).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_id(&self) -> u128 {
    self.checkpoint_id
  }

  /// The canonical headers for the un-checkpointed committed band `(checkpoint_op .. commit]` — a SPARSE,
  /// op-ascending set with ONE header per committed-band op the writer HELD (TigerBeetle's `vsr_headers`;
  /// codex R12-F1). Recovery verifies each committed-band WAL slot against the matching header's
  /// [`Header::body_checksum`]: a held slot whose own self-consistent header kept a stale superseded body
  /// mismatches the canonical checksum and is routed to peer-repair rather than re-derived from the WAL,
  /// while a known-committed op with NO header (one the writer did not hold) is dropped + peer-repaired.
  /// May be SHORTER than the full band AND contain gaps when the caller had repair holes (each held op
  /// keeps its header regardless of a lower hole; [`Self::try_new`] allows gaps).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn committed_headers_slice(&self) -> &[Header] {
    &self.committed_headers
  }

  /// Encodes this durable root to a length-prefixed, versioned byte vector (the superblock
  /// on-disk form). Layout (all scalars big-endian): [`WIRE_VERSION`](crate::WIRE_VERSION) `u16`,
  /// then `view`/`log_view` (`u64` each), `commit`/`checkpoint_op` (`u64` each), `checkpoint_id`
  /// (`u128`), then the committed-band header set as a `u32` count followed by that many
  /// fixed-size [`Header::encode`] blocks (one [`HEADER_ENCODED_LEN`]-byte block per header). The
  /// scalar field order matches the [`Self::try_new`] parameter order. Variable-length because the
  /// header set is sparse + bounded by one checkpoint interval.
  pub fn encode(&self) -> Vec<u8> {
    let mut out =
      Vec::with_capacity(2 + 8 * 4 + 16 + 4 + self.committed_headers.len() * HEADER_ENCODED_LEN);
    out.extend_from_slice(&crate::WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&self.view.get().to_be_bytes());
    out.extend_from_slice(&self.log_view.get().to_be_bytes());
    out.extend_from_slice(&self.commit.get().to_be_bytes());
    out.extend_from_slice(&self.checkpoint_op.get().to_be_bytes());
    out.extend_from_slice(&self.checkpoint_id.to_be_bytes());
    out.extend_from_slice(&(self.committed_headers.len() as u32).to_be_bytes());
    for h in &self.committed_headers {
      out.extend_from_slice(&h.encode());
    }
    out
  }

  /// Decodes a durable root produced by [`Self::encode`], bounds-checked and panic-free on any
  /// truncated / corrupt / adversarial input.
  ///
  /// Rejects (never panics): a short buffer ([`CodecError::Truncated`]), an unknown leading
  /// version ([`CodecError::UnknownVersion`]), a header-count prefix that overruns the buffer
  /// ([`CodecError::LengthOverflow`]), trailing bytes after the last header
  /// ([`CodecError::TrailingBytes`]), or a per-header decode error. The decoded fields are
  /// re-validated through [`Self::try_new`], so a corrupt root whose fields break the VSR
  /// invariants surfaces as [`CodecError::InvalidVsrState`] rather than constructing an illegal
  /// state — i.e. `decode` returns ONLY roots `try_new` would have accepted.
  pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
    let mut r = Reader::new(buf);
    let version = r.u16()?;
    if version != crate::WIRE_VERSION {
      return Err(CodecError::UnknownVersion(version));
    }
    let view = View::with(r.u64()?);
    let log_view = View::with(r.u64()?);
    let commit = OpNumber::with(r.u64()?);
    let checkpoint_op = OpNumber::with(r.u64()?);
    let checkpoint_id = r.u128()?;
    // Reject an oversized header count before allocating: each header is a fixed block, so a
    // count that could not fit is a corrupt length, not an honestly-short tail.
    let count = r.seq_len(HEADER_ENCODED_LEN)?;
    let mut committed_headers = Vec::with_capacity(count);
    for _ in 0..count {
      committed_headers.push(Header::decode(r.take(HEADER_ENCODED_LEN)?)?);
    }
    r.finish()?;
    // Re-validate the invariants (log_view <= view, commit >= checkpoint_op, in-band ascending
    // headers): a corrupt root that breaks them is rejected, not silently constructed.
    Ok(Self::try_new(
      view,
      log_view,
      commit,
      checkpoint_op,
      checkpoint_id,
      committed_headers,
    )?)
  }
}

/// Error constructing a [`VsrState`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VsrStateError {
  /// `log_view` exceeded `view`.
  #[error("log_view exceeds view")]
  LogViewAboveView,
  /// `commit` was below `checkpoint_op`.
  #[error("commit is below the checkpoint op")]
  CommitBelowCheckpoint,
  /// A committed-band header's op fell outside `(checkpoint_op .. commit]`.
  #[error("a committed-band header op is outside (checkpoint_op .. commit]")]
  HeaderOutOfBand,
  /// The committed-band headers were not in strictly-ascending op order (a duplicate or a descent).
  #[error("committed-band header ops are not strictly ascending")]
  HeadersNotAscending,
}

/// A successful WAL read result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOk {
  id: OpId,
  header: Header,
  body: Bytes,
}
impl ReadOk {
  /// Creates a read result.
  pub fn new(id: OpId, header: Header, body: Bytes) -> Self {
    Self { id, header, body }
  }

  /// The correlation id of the storage op that produced this result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> OpId {
    self.id
  }

  /// The WAL entry header.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn header(&self) -> Header {
    self.header
  }

  /// The operation number from the entry header.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.header.op()
  }

  /// The body bytes as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The body bytes as a cloned [`Bytes`] handle.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Completion of a submitted `Wal` op.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum WalDone {
  /// An append became durable.
  Appended(OpId),
  /// A read returned a valid entry.
  ReadOk(ReadOk),
  /// A read found no entry at that slot.
  Absent(OpId),
  /// A storage-level fault (or proto-detected corruption).
  Fault(OpId),
}

/// A successful checkpoint read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRead {
  id: OpId,
  op: OpNumber,
  snapshot: Bytes,
}
impl CheckpointRead {
  /// Creates a checkpoint read result.
  pub fn new(id: OpId, op: OpNumber, snapshot: Bytes) -> Self {
    Self { id, op, snapshot }
  }

  /// The correlation id of the storage op that produced this result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> OpId {
    self.id
  }

  /// The op number at which this checkpoint was taken.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The snapshot bytes as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn snapshot(&self) -> &[u8] {
    &self.snapshot
  }

  /// The snapshot bytes as a cloned [`Bytes`] handle.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn snapshot_bytes(&self) -> Bytes {
    self.snapshot.clone()
  }
}

/// Completion of a submitted `Superblock` op.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum SuperblockDone {
  /// A superblock/checkpoint write became durable.
  Wrote(OpId),
  /// A checkpoint read returned its snapshot.
  CheckpointRead(CheckpointRead),
  /// A storage-level fault.
  Fault(OpId),
}

/// A pluggable write-ahead log. The implementation owns all log bytes and a header
/// index; the proto orchestrates consensus over it. Sync methods serve consensus
/// decisions; `submit_*` queue durability work whose completions arrive via `poll`.
///
/// **Poll-ordering / durability-visibility contract (load-bearing for append-before-ack).** The
/// synchronous views ([`op_head`](Wal::op_head), [`header`](Wal::header), and a
/// [`SlotStatus::Clean`] from [`status`](Wal::status)) MUST reflect ONLY durably-COMPLETED appends —
/// NEVER an in-flight one (a slot whose [`submit_append`](Wal::submit_append) has been issued but
/// whose [`WalDone::Appended`] has not yet been delivered by [`poll`](Wal::poll)). Concretely, for
/// an append that is submitted but not yet completed:
/// - [`op_head`](Wal::op_head) MUST NOT count it, [`header`](Wal::header) at its op MUST report the
///   PRIOR durable header (or `None` if the slot was empty), and [`status`](Wal::status) MUST report
///   [`SlotStatus::Dirty`] — never [`Clean`](SlotStatus::Clean).
/// - A [`submit_read`](Wal::submit_read) of that slot MUST resolve to [`WalDone::Absent`] (or the
///   PRIOR durable bytes, if the slot held a completed entry) — NEVER the in-flight bytes.
///
/// This is load-bearing for append-before-ack (codex R7-F1): the proto's head (`self.op`) advances
/// at SUBMIT, but the ack/vote it owes is deferred until the matching [`WalDone::Appended`]. A driver
/// that advanced [`op_head`](Wal::op_head) (or flipped a slot to [`Clean`](SlotStatus::Clean)) on
/// SUBMIT rather than on COMPLETION would silently let a `PrepareOk` be cast for a not-yet-durable op,
/// breaking the invariant — so the "only-durable" rule above is a CONTRACT, not an implementation
/// detail. Append completions ([`WalDone::Appended`]) are correlated by [`OpId`] and MAY arrive in
/// ANY order — a real proactor (io_uring with several SQEs in flight) reorders completions — so the
/// proto MUST NOT assume FIFO completion; the synchronous views above MUST stay consistent with
/// "only-durable" regardless of the order completions are drained in.
///
/// **Capacity / back-pressure contract (the M3.2b WAL-wrap shape).** [`capacity`](Wal::capacity) is
/// the total number of slots the log can hold (`u64::MAX` ⇒ effectively unbounded; the default).
/// `submit_*` stay INFALLIBLE — they return `()` and never signal "queue full" — so the back-pressure
/// model is **the proto's job, not the driver's** (TigerBeetle-faithful: the WAL is a fixed ring and
/// the replica stalls op-assignment before it would wrap): the proto MUST NOT
/// [`submit_append`](Wal::submit_append) an op that would require more than [`capacity`](Wal::capacity)
/// un-pruned slots to be live at once (it stalls assigning the next op until a
/// [`prune`](Wal::prune) frees room — the M3.2b wrap-stall). A conforming driver MAY
/// `debug_assert`/panic if the proto violates this (submits past `capacity()` un-pruned slots); it is
/// NOT required to grow, queue, or reject the append. The M3.2b PRIMARY stall is now implemented
/// (`Endpoint::on_request` refuses to mint op `K+1` when `(K+1) - prune_floor > capacity()`), so a
/// bounded backend physically wraps op `K`'s slot only after `K` is checkpoint-subsumed on a quorum.
///
/// **Liveness constraint on a bounded `capacity()`.** The stall self-RELEASES as the quorum checkpoint
/// rises (which lifts the prune floor and frees slots), so `capacity()` MUST exceed one checkpoint
/// interval plus the in-flight pipeline depth — concretely `capacity() > config.checkpoint_ops() +
/// pipeline_headroom`. With a ring smaller than (or equal to) a checkpoint interval the un-pruned
/// window `(floor, op]` cannot reach the next checkpoint boundary before it would wrap, so the stall
/// would never release and the primary would WEDGE. A backend that reports a fixed `capacity()` is
/// responsible for honouring this (the sim's bounded mode picks `n` well above `checkpoint_ops`; an
/// M4 disk driver must size its WAL ring the same way).
pub trait Wal {
  /// The highest op number held.
  fn op_head(&self) -> OpNumber;
  /// The header at `op`, or `None` if absent or known-faulty.
  fn header(&self, op: OpNumber) -> Option<Header>;
  /// The slot status for `op` (the present/nack signal).
  fn status(&self, op: OpNumber) -> SlotStatus;
  /// The total WAL slot capacity — the maximum number of un-pruned slots that can be live at once
  /// (`u64::MAX` ⇒ effectively unbounded). The proto observes this to stall op-assignment before it
  /// would wrap a fixed ring (the M3.2b back-pressure model); see the trait-level capacity contract.
  /// Defaults to `u64::MAX` (unbounded) so a backend with no fixed bound need not override it.
  fn capacity(&self) -> u64 {
    u64::MAX
  }
  /// Submit a durable append of `(header, body)` at `op`. Completion via [`Wal::poll`]. INFALLIBLE
  /// (returns `()`): the proto guarantees it never submits past [`capacity`](Wal::capacity) un-pruned
  /// slots (see the trait-level capacity contract), so a backend MAY assume room exists.
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes);
  /// Submit a read of `op`'s entry. Completion via [`Wal::poll`].
  fn submit_read(&mut self, id: OpId, op: OpNumber);
  /// Drop all slots strictly above `op` (view-change tail truncation).
  fn truncate(&mut self, above: OpNumber);
  /// Free all slots strictly below `op` (post-checkpoint GC).
  fn prune(&mut self, below: OpNumber);
  /// Drain the next completed op, if any. Completions for appends ([`WalDone::Appended`]) MAY be
  /// delivered in ANY order relative to their submission (a real proactor reorders); see the
  /// trait-level poll-ordering contract.
  fn poll(&mut self) -> Option<WalDone>;
}

/// A pluggable durable root (superblock). Writes the VSR state and checkpoint
/// snapshots atomically; completions arrive via [`Superblock::poll`].
///
/// **Root-write ordering contract (load-bearing for VSR safety).** The durable root is a single
/// serialized writer: when several [`submit_write`](Superblock::submit_write) calls are
/// outstanding, their completions MUST be delivered in submission order, and once they have all
/// completed the durable [`state`](Superblock::state) MUST equal the LAST-submitted root. The proto
/// can briefly have a checkpoint root write and a view-change root write in flight together — it
/// drops the *logical* checkpoint tracker on a view change but cannot un-submit an already-issued
/// write — and relies on this ordering so the later (view-change) root wins rather than a stale
/// checkpoint root rolling back the durable view/commit. A backend with a single fsync'd superblock
/// slot satisfies this naturally (as TigerBeetle's does); one that completes root writes out of
/// order would violate VSR safety.
///
/// **Writes MUST NOT surface a [`SuperblockDone::Fault`] (audit finding C).** A `Fault` completion is
/// reserved for a READ ([`submit_read_checkpoint`](Superblock::submit_read_checkpoint)) — recovery /
/// state-sync treat a checkpoint-read fault as faults-as-data (retry within budget, then peer-fetch).
/// An implementation MUST make a [`submit_write`](Superblock::submit_write) /
/// [`submit_write_checkpoint`](Superblock::submit_write_checkpoint) durable, RETRYING internally until
/// it succeeds, and complete it ONLY with [`SuperblockDone::Wrote`]; it must never report a write as
/// faulted. The proto has no recovery path for a faulted root/checkpoint write outside the recover
/// loop — `on_sb_done` treats a write-`Fault` it sees in Normal as not-produced-by-our-backends and
/// drops it defensively (it does not retry it), so a backend that DID surface one would silently lose
/// that durable write. (The durable root is the single source of truth a crash recovers from; a write
/// that is allowed to "fail" without the proto re-issuing it has no owner.)
pub trait Superblock {
  /// The current durable root (the last root write that has completed).
  fn state(&self) -> VsrState;
  /// Submit an atomic write of the durable root. Completions are delivered in submission order
  /// relative to other `submit_write` calls (see the trait-level root-write ordering contract). MUST
  /// complete only as [`SuperblockDone::Wrote`] — never [`SuperblockDone::Fault`]; the implementation
  /// retries internally until durable (see the trait-level write-fault contract).
  fn submit_write(&mut self, id: OpId, state: VsrState);
  /// Submit a write of a checkpoint snapshot at `op`. MUST complete only as [`SuperblockDone::Wrote`]
  /// — never [`SuperblockDone::Fault`] (see the trait-level write-fault contract).
  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes);
  /// Submit a read of the latest checkpoint snapshot.
  fn submit_read_checkpoint(&mut self, id: OpId);
  /// Drain the next completed op, if any.
  fn poll(&mut self) -> Option<SuperblockDone>;
}

/// The content id of a checkpoint snapshot: a deterministic FNV-1a-128 hash of its bytes.
/// `VsrState::checkpoint_id` stores this; recovery + state-sync compare against it.
#[cfg_attr(not(tarpaulin), inline(always))]
pub fn checkpoint_id(snapshot: &[u8]) -> u128 {
  fnv1a_128(snapshot)
}

// ── deterministic FNV-1a-128 (no_std, no deps) ──
const FNV_OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
const FNV_PRIME: u128 = 0x0000000001000000000000000000013B;

fn fnv1a_128(bytes: &[u8]) -> u128 {
  fnv1a_128_mix(FNV_OFFSET, bytes)
}

fn fnv1a_128_mix(mut acc: u128, bytes: &[u8]) -> u128 {
  for &b in bytes {
    acc ^= b as u128;
    acc = acc.wrapping_mul(FNV_PRIME);
  }
  acc
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ClientId, OpNumber, RequestNumber, View};

  #[test]
  fn checkpoint_id_is_deterministic_and_sensitive() {
    let a = checkpoint_id(b"snapshot-bytes");
    assert_eq!(a, checkpoint_id(b"snapshot-bytes"), "deterministic");
    assert_ne!(
      a,
      checkpoint_id(b"snapshot-byteS"),
      "a flipped byte changes the id"
    );
    assert_ne!(a, checkpoint_id(b""), "empty differs from non-empty");
  }

  #[test]
  fn header_checksum_detects_corruption() {
    let h = Header::new(
      OpNumber::with(1),
      View::with(0),
      ClientId::new(7),
      RequestNumber::with(1),
      b"hello",
    );
    assert!(h.verify(b"hello"));
    assert!(!h.verify(b"hellp")); // a flipped body byte fails verification
    assert_eq!(h.version(), HEADER_VERSION);

    // A tampered header field (without recomputing the checksum) must also fail verify.
    let mut tampered = h;
    tampered.op = OpNumber::with(2);
    assert!(
      !tampered.verify(b"hello"),
      "a tampered header field must fail verify"
    );
  }

  #[test]
  fn vsr_state_rejects_bad_invariants() {
    assert!(
      VsrState::try_new(
        View::with(1),
        View::with(2),
        OpNumber::with(0),
        OpNumber::with(0),
        0,
        std::vec::Vec::new(),
      )
      .is_err()
    );
    assert!(
      VsrState::try_new(
        View::with(2),
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(3),
        0,
        std::vec::Vec::new(),
      )
      .is_err()
    );
    let s = VsrState::try_new(
      View::with(3),
      View::with(3),
      OpNumber::with(5),
      OpNumber::with(4),
      99,
      std::vec::Vec::new(),
    )
    .unwrap();
    assert_eq!(s.commit(), OpNumber::with(5));
    assert_eq!(s.checkpoint_id(), 99);
    assert!(s.committed_headers_slice().is_empty());
  }

  #[test]
  fn vsr_state_keeps_a_sparse_in_band_header_set_verbatim() {
    // Build canonical headers for ops in the committed band above checkpoint_op = 2, commit = 5.
    let mk = |op: u64| {
      Header::new(
        OpNumber::with(op),
        View::with(1),
        ClientId::new(1),
        RequestNumber::with(op),
        &[op as u8],
      )
    };
    // A contiguous full band (3,4,5) is kept verbatim.
    let s = VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(2),
      0,
      std::vec![mk(3), mk(4), mk(5)],
    )
    .unwrap();
    assert_eq!(s.committed_headers_slice().len(), 3);
    assert_eq!(s.committed_headers_slice()[0].op(), OpNumber::with(3));

    // A GAP after op 3 (3, then 5 — op 4 a hole) is now KEPT verbatim (codex R12-F1): the held op 5
    // above the op-4 hole retains its canonical header so recovery can verify it individually.
    let holed = VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(2),
      0,
      std::vec![mk(3), mk(5)],
    )
    .unwrap();
    assert_eq!(
      holed
        .committed_headers_slice()
        .iter()
        .map(|h| h.op().get())
        .collect::<std::vec::Vec<_>>(),
      std::vec![3, 5],
      "the sparse set (gap at op 4) is kept verbatim, not truncated at the gap"
    );

    // A header ABOVE commit is REJECTED (only the committed band is persisted): commit = 3, op 4 > commit.
    assert_eq!(
      VsrState::try_new(
        View::with(1),
        View::with(1),
        OpNumber::with(3),
        OpNumber::with(2),
        0,
        std::vec![mk(3), mk(4)],
      ),
      Err(VsrStateError::HeaderOutOfBand)
    );
  }

  #[test]
  fn vsr_state_accepts_a_sparse_in_band_header_set_but_rejects_a_malformed_one() {
    // codex R12-F1: the committed-band header set is now a SPARSE canonical-header set over the held
    // committed ops, NOT a contiguous prefix. `try_new` ACCEPTS an in-range, strictly-increasing set
    // even with GAPS (a held op above a lower hole keeps its header), but REJECTS an out-of-range,
    // non-ascending, or duplicate set rather than silently truncating a valid sparse list.
    let mk = |op: u64| {
      Header::new(
        OpNumber::with(op),
        View::with(1),
        ClientId::new(1),
        RequestNumber::with(op),
        &[op as u8],
      )
    };
    // ACCEPT: a sparse set [op1, op3] with commit = 3, checkpoint = 0 — the gap at op 2 is allowed and
    // BOTH headers are kept verbatim (op 3 is a held canonical op above the op-2 hole).
    let sparse = VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(3),
      OpNumber::new(),
      0,
      std::vec![mk(1), mk(3)],
    )
    .unwrap();
    assert_eq!(
      sparse
        .committed_headers_slice()
        .iter()
        .map(|h| h.op().get())
        .collect::<std::vec::Vec<_>>(),
      std::vec![1, 3],
      "a sparse in-band set is kept verbatim (the gap at op 2 is allowed)"
    );

    // REJECT: an op AT/BELOW the checkpoint (out of band below).
    assert_eq!(
      VsrState::try_new(
        View::with(1),
        View::with(1),
        OpNumber::with(5),
        OpNumber::with(2),
        0,
        std::vec![mk(2), mk(3)], // op 2 == checkpoint_op — must be strictly above it
      ),
      Err(VsrStateError::HeaderOutOfBand)
    );
    // REJECT: an op ABOVE commit (out of band above).
    assert_eq!(
      VsrState::try_new(
        View::with(1),
        View::with(1),
        OpNumber::with(3),
        OpNumber::new(),
        0,
        std::vec![mk(1), mk(4)], // op 4 > commit 3
      ),
      Err(VsrStateError::HeaderOutOfBand)
    );
    // REJECT: a non-ascending set (op 3 then op 1).
    assert_eq!(
      VsrState::try_new(
        View::with(1),
        View::with(1),
        OpNumber::with(5),
        OpNumber::new(),
        0,
        std::vec![mk(3), mk(1)],
      ),
      Err(VsrStateError::HeadersNotAscending)
    );
    // REJECT: a duplicate op (op 3 twice) — not strictly increasing.
    assert_eq!(
      VsrState::try_new(
        View::with(1),
        View::with(1),
        OpNumber::with(5),
        OpNumber::new(),
        0,
        std::vec![mk(3), mk(3)],
      ),
      Err(VsrStateError::HeadersNotAscending)
    );
  }

  #[test]
  fn slot_status_as_str_and_predicates() {
    assert_eq!(SlotStatus::Faulty.as_str(), "faulty");
    assert!(SlotStatus::Clean.is_clean());
  }

  #[test]
  fn wal_done_variants() {
    let r = ReadOk::new(
      OpId::new(1),
      Header::new(
        OpNumber::with(1),
        View::new(),
        ClientId::new(1),
        RequestNumber::with(1),
        b"x",
      ),
      bytes::Bytes::from_static(b"x"),
    );
    let d = WalDone::ReadOk(r);
    assert!(d.is_read_ok());
    assert_eq!(d.unwrap_read_ok().op(), OpNumber::with(1));
  }

  // ── disk codec (audit P0): Header + VsrState ──

  use crate::codec::CodecError;

  fn mk_header(op: u64, view: u64, client: u128, req: u64, body: &[u8]) -> Header {
    Header::new(
      OpNumber::with(op),
      View::with(view),
      ClientId::new(client),
      RequestNumber::with(req),
      body,
    )
  }

  #[test]
  fn header_round_trips_including_edge_values() {
    for h in [
      Header::new(
        OpNumber::new(),
        View::new(),
        ClientId::new(0),
        RequestNumber::new(),
        b"",
      ),
      mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body"),
      mk_header(u64::MAX, u64::MAX, u128::MAX, u64::MAX, b"max-edge-values"),
    ] {
      let bytes = h.encode();
      assert_eq!(bytes.len(), HEADER_ENCODED_LEN, "fixed-size encoding");
      let back = Header::decode(&bytes).expect("round-trip decodes");
      assert_eq!(back, h, "decode(encode(h)) == h");
    }
  }

  #[test]
  fn header_decode_re_derives_the_same_checksum_and_shares_canonical_bytes() {
    let h = mk_header(
      7,
      3,
      0x1234_5678_9abc_def0_1122_3344_5566_7788,
      9,
      b"payload",
    );
    let bytes = h.encode();
    // The decoded header carries the stored checksum unchanged …
    let back = Header::decode(&bytes).expect("decodes");
    assert_eq!(back.checksum(), h.checksum(), "stored checksum preserved");
    // … and is self-consistent (re-derived checksum == stored) on its original body.
    assert!(back.verify(b"payload"), "decoded header verifies");
    // The encoded buffer's canonical region (after the 16-byte checksum, before the reserved
    // padding) is EXACTLY the bytes compute_checksum hashes — i.e. the codec and the checksum
    // share one definition (audit P3): hashing the embedded canonical region reproduces the
    // checksum the writer stored.
    let canonical = &bytes[16..16 + HEADER_CANONICAL_LEN];
    assert_eq!(
      fnv1a_128(canonical),
      h.checksum(),
      "the encoded canonical bytes are what the checksum hashes"
    );
  }

  #[test]
  fn header_checksum_value_is_unchanged_by_the_canonical_refactor() {
    // Pin the checksum of a fixed input: if write_canonical ever reorders/rewidens a field
    // (changing the on-disk checksum for already-persisted data), this golden value FAILS,
    // surfacing the format break the task said to STOP on.
    let h = mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body");
    assert_eq!(
      h.checksum(),
      0xe72c_624b_7c30_e993_d822_b02e_38c3_c2d9,
      "the canonical refactor must not change an existing checksum value"
    );
  }

  #[test]
  fn header_golden_bytes_pin_the_layout() {
    // A future field reorder / layout change FAILS this exact-bytes assertion (format-stability
    // guard): checksum(16) ++ version|op|view|client|request|body_checksum (each u128 BE) ++
    // reserved zero padding, totalling HEADER_ENCODED_LEN.
    let h = mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body");
    let expected: [u8; HEADER_ENCODED_LEN] = [
      231, 44, 98, 75, 124, 48, 233, 147, 216, 34, 176, 46, 56, 195, 194, 217, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 105, 137, 79, 111, 118, 117, 114, 119, 184, 6, 233,
      126, 145, 224, 157, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(h.encode(), expected, "Header wire layout is pinned");
  }

  #[test]
  fn header_decode_rejects_truncation_and_bad_version_without_panicking() {
    let good = mk_header(1, 1, 1, 1, b"x").encode();
    // A short buffer → Truncated, never a panic.
    assert!(matches!(
      Header::decode(&good[..HEADER_ENCODED_LEN - 1]),
      Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
      Header::decode(&[]),
      Err(CodecError::Truncated { .. })
    ));
    // Trailing bytes beyond the fixed slot → TrailingBytes.
    let mut over = good.to_vec();
    over.push(0);
    assert!(matches!(
      Header::decode(&over),
      Err(CodecError::TrailingBytes(1))
    ));
    // A bad version → UnknownVersion. The version is the widened u128 at bytes 16..32 (after the
    // 16-byte checksum); its significant low byte is index 31. Setting it to 9 makes version_raw
    // = 9 (fits u16), so the report is UnknownVersion(9).
    let mut badver = good;
    badver[31] = 9;
    assert!(matches!(
      Header::decode(&badver),
      Err(CodecError::UnknownVersion(9))
    ));
    // A version whose widened word does not even fit u16 (a high byte set) saturates the report
    // at u16::MAX rather than panicking.
    let mut hugever = good;
    hugever[16] = 1; // top byte of the u128 version word
    assert!(matches!(
      Header::decode(&hugever),
      Err(CodecError::UnknownVersion(u16::MAX))
    ));
  }

  #[test]
  fn header_decode_never_panics_on_arbitrary_short_or_random_bytes() {
    // Fuzz-style no-panic loop over truncations + a pseudo-random stream: every length-checked
    // read returns an error, so no input panics / indexes out of range.
    let good = mk_header(3, 3, 3, 3, b"abc").encode();
    for n in 0..=HEADER_ENCODED_LEN + 4 {
      let mut v = good.to_vec();
      v.truncate(n.min(v.len()));
      while v.len() < n {
        v.push((n as u8).wrapping_mul(31));
      }
      let _ = Header::decode(&v); // must not panic
    }
    let mut x = 0x1234_5678u32;
    for len in 0..300usize {
      let mut v = std::vec::Vec::with_capacity(len);
      for _ in 0..len {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
      }
      let _ = Header::decode(&v); // must not panic
    }
  }

  #[test]
  fn vsr_state_round_trips_empty_and_populated() {
    // Empty committed-band header set.
    let empty = VsrState::new();
    assert_eq!(
      VsrState::decode(&empty.encode()).expect("empty round-trips"),
      empty
    );
    // Populated, sparse (gap at op 4), with edge scalar values.
    let populated = VsrState::try_new(
      View::with(u64::MAX),
      View::with(u64::MAX - 1),
      OpNumber::with(9),
      OpNumber::with(2),
      u128::MAX,
      std::vec![mk_header(3, 1, 7, 3, b"a"), mk_header(5, 1, 7, 5, b"bb")],
    )
    .unwrap();
    let back = VsrState::decode(&populated.encode()).expect("populated round-trips");
    assert_eq!(back, populated, "decode(encode(state)) == state");
    assert_eq!(
      back
        .committed_headers_slice()
        .iter()
        .map(|h| h.op().get())
        .collect::<std::vec::Vec<_>>(),
      std::vec![3, 5],
      "the sparse header set survives the round-trip verbatim"
    );
  }

  #[test]
  fn vsr_state_golden_bytes_pin_the_layout() {
    let h = mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body");
    let st = VsrState::try_new(
      View::with(4),
      View::with(2),
      OpNumber::with(7),
      OpNumber::with(5),
      0xAABB_CCDD,
      std::vec![h],
    )
    .unwrap();
    let expected: std::vec::Vec<u8> = std::vec![
      0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0,
      0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 187, 204, 221, 0, 0, 0, 1, 231, 44, 98, 75,
      124, 48, 233, 147, 216, 34, 176, 46, 56, 195, 194, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 9, 105, 137, 79, 111, 118, 117, 114, 119, 184, 6, 233, 126, 145, 224,
      157, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(st.encode(), expected, "VsrState wire layout is pinned");
  }

  #[test]
  fn vsr_state_decode_rejects_corruption_without_panicking() {
    let st = VsrState::try_new(
      View::with(4),
      View::with(2),
      OpNumber::with(7),
      OpNumber::with(5),
      0xAABB_CCDD,
      std::vec![mk_header(6, 1, 1, 6, b"z")],
    )
    .unwrap();
    let good = st.encode();
    // Truncation WITHIN the fixed scalar prefix (before the header count) → Truncated (a scalar
    // read ran off the end). `&[]` likewise fails the very first u16 read.
    assert!(matches!(
      VsrState::decode(&good[..40]),
      Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
      VsrState::decode(&[]),
      Err(CodecError::Truncated { .. })
    ));
    // Dropping the last byte leaves the count (1) promising a 128-byte header where only 127
    // remain — a length/count prefix exceeding the remaining bytes → LengthOverflow.
    assert!(matches!(
      VsrState::decode(&good[..good.len() - 1]),
      Err(CodecError::LengthOverflow { .. })
    ));
    // Bad leading version → UnknownVersion.
    let mut badver = good.clone();
    badver[1] = 7;
    assert!(matches!(
      VsrState::decode(&badver),
      Err(CodecError::UnknownVersion(7))
    ));
    // A header-count prefix that overruns the buffer → LengthOverflow (not an OOB slice). The
    // count u32 sits at offset 2+8+8+8+8+16 = 50.
    let mut huge = good.clone();
    huge[50..54].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert!(matches!(
      VsrState::decode(&huge),
      Err(CodecError::LengthOverflow { .. })
    ));
    // Trailing bytes after the last header → TrailingBytes.
    let mut over = good.clone();
    over.push(0);
    assert!(matches!(
      VsrState::decode(&over),
      Err(CodecError::TrailingBytes(1))
    ));
    // A structurally-valid buffer whose decoded fields break the invariants (log_view > view) is
    // rejected as InvalidVsrState rather than constructing an illegal root. Build it by hand: an
    // empty-header root with log_view = 5 > view = 4.
    let mut bad = std::vec::Vec::new();
    bad.extend_from_slice(&crate::WIRE_VERSION.to_be_bytes());
    bad.extend_from_slice(&4u64.to_be_bytes()); // view
    bad.extend_from_slice(&5u64.to_be_bytes()); // log_view > view
    bad.extend_from_slice(&0u64.to_be_bytes()); // commit
    bad.extend_from_slice(&0u64.to_be_bytes()); // checkpoint_op
    bad.extend_from_slice(&0u128.to_be_bytes()); // checkpoint_id
    bad.extend_from_slice(&0u32.to_be_bytes()); // header count
    assert!(matches!(
      VsrState::decode(&bad),
      Err(CodecError::InvalidVsrState(_))
    ));
  }

  #[test]
  fn vsr_state_decode_never_panics_on_random_bytes() {
    // Fuzz-style no-panic loop: a pseudo-random byte stream of growing length must always yield
    // a typed error, never a panic / OOB index.
    let good = VsrState::try_new(
      View::with(2),
      View::with(2),
      OpNumber::with(3),
      OpNumber::with(1),
      9,
      std::vec![mk_header(2, 2, 2, 2, b"q")],
    )
    .unwrap()
    .encode();
    for n in 0..=good.len() + 2 {
      let _ = VsrState::decode(&good[..n.min(good.len())]); // truncations
    }
    let mut x = 0xDEAD_BEEFu32;
    for len in 0..400usize {
      let mut v = std::vec::Vec::with_capacity(len);
      for _ in 0..len {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        v.push((x >> 16) as u8);
      }
      let _ = VsrState::decode(&v); // must not panic
    }
  }
}

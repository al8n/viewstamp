//! Pluggable durable-storage contract: value types + the `Wal`/`Superblock` traits.
//!
//! The proto owns no log; it orchestrates consensus over a user-supplied `Wal` +
//! `Superblock` (wired in M3.1). All faults surface as data (`SlotStatus::Faulty`,
//! `WalDone::Fault`) — never as panics; the proto verifies `Header` checksums itself.

use std::vec::Vec;

use bytes::Bytes;

use crate::{ClientId, OpNumber, RequestNumber, View};

/// On-disk header format version (bumped on any wire/disk layout change).
pub const HEADER_VERSION: u16 = 1;

/// Correlation id matching a submitted storage op to its completion.
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

  fn compute_checksum(&self) -> u128 {
    let mut acc = FNV_OFFSET;
    for word in [
      self.version as u128,
      self.op.get() as u128,
      self.view.get() as u128,
      self.client.get(),
      self.request.get() as u128,
      self.body_checksum,
    ] {
      acc = fnv1a_128_mix(acc, &word.to_be_bytes());
    }
    acc
  }
}

/// The durable VSR root written to the superblock. Invariants checked ⇒ `try_new`.
///
/// Carries — alongside `(view, log_view, commit, checkpoint_op, checkpoint_id)` — the CANONICAL
/// [`Header`]s of the un-checkpointed COMMITTED band `(checkpoint_op .. commit]`, TigerBeetle's
/// `vsr_headers` mechanism. These are written atomically with the view/commit they describe (one
/// struct, one root write) and let `recover` independently verify each committed-band WAL slot against
/// the canonical body checksum — a slot whose own (self-consistent) header kept a STALE superseded
/// body is then DETECTED and routed to peer-repair instead of blindly re-derived from the WAL. The
/// band is bounded by `Config::checkpoint_ops` (post-checkpoint GC keeps `commit - checkpoint_op`
/// within ~one checkpoint interval), so the list stays small. Holding a `Vec` makes this `Clone` but
/// not `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsrState {
  view: View,
  log_view: View,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  /// Canonical headers for the committed band `(checkpoint_op .. commit]`, CONTIGUOUS and ordered by
  /// op (a possible repair hole truncates the list at the first gap; see [`Self::try_new`]). Private;
  /// read via [`Self::committed_headers`]. The per-entry `body_checksum` is the load-bearing field
  /// recovery checks the WAL against.
  committed_headers: Vec<Header>,
}
impl VsrState {
  /// Creates a durable root, validating `log_view <= view` and `commit >= checkpoint_op`.
  ///
  /// `committed_headers` are the canonical headers of the committed band `(checkpoint_op .. commit]`,
  /// ordered by op and CONTIGUOUS from `checkpoint_op + 1`. To keep the stored list trustworthy this
  /// constructor KEEPS only the contiguous, in-band prefix: it walks `checkpoint_op + 1, +2, …` and
  /// stops at the first op that is missing, out of order, or above `commit` (a repair hole in the
  /// caller's log truncates the band there — what is recorded is always a contiguous canonical prefix,
  /// never a list with holes). Headers strictly above `commit` are dropped (only the committed band is
  /// persisted). An empty band (`commit == checkpoint_op`) yields an empty list.
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
    // Keep only the contiguous in-band prefix `checkpoint_op + 1 .. ` (stop at the first gap / any op
    // above `commit`). The caller derives these from its log in op order; this guard makes the stored
    // band self-consistently contiguous regardless of a caller hole, so recovery can index it by op.
    let mut headers = committed_headers;
    let mut expected = checkpoint_op.get();
    let kept = headers
      .iter()
      .take_while(|h| {
        expected += 1;
        h.op().get() == expected && expected <= commit.get()
      })
      .count();
    headers.truncate(kept);
    Ok(Self {
      view,
      log_view,
      commit,
      checkpoint_op,
      checkpoint_id,
      committed_headers: headers,
    })
  }

  /// The fresh-cluster root (all zero, no committed-band headers).
  pub const fn initial() -> Self {
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

  /// The highest committed op number.
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

  /// The canonical headers for the un-checkpointed committed band `(checkpoint_op .. commit]`, ordered
  /// by op and contiguous from `checkpoint_op + 1` (TigerBeetle's `vsr_headers`). Recovery verifies
  /// each committed-band WAL slot against the matching header's [`Header::body_checksum`]: a slot whose
  /// own self-consistent header kept a stale superseded body mismatches the canonical checksum and is
  /// routed to peer-repair rather than re-derived from the WAL. May be SHORTER than the full band if
  /// the caller had a repair hole (the list is truncated at the first gap by [`Self::try_new`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn committed_headers(&self) -> &[Header] {
    &self.committed_headers
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
pub trait Wal {
  /// The highest op number held.
  fn op_head(&self) -> OpNumber;
  /// The header at `op`, or `None` if absent or known-faulty.
  fn header(&self, op: OpNumber) -> Option<Header>;
  /// The slot status for `op` (the present/nack signal).
  fn status(&self, op: OpNumber) -> SlotStatus;
  /// Submit a durable append of `(header, body)` at `op`. Completion via [`Wal::poll`].
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes);
  /// Submit a read of `op`'s entry. Completion via [`Wal::poll`].
  fn submit_read(&mut self, id: OpId, op: OpNumber);
  /// Drop all slots strictly above `op` (view-change tail truncation).
  fn truncate(&mut self, above: OpNumber);
  /// Free all slots strictly below `op` (post-checkpoint GC).
  fn prune(&mut self, below: OpNumber);
  /// Drain the next completed op, if any.
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
pub trait Superblock {
  /// The current durable root (the last root write that has completed).
  fn state(&self) -> VsrState;
  /// Submit an atomic write of the durable root. Completions are delivered in submission order
  /// relative to other `submit_write` calls (see the trait-level root-write ordering contract).
  fn submit_write(&mut self, id: OpId, state: VsrState);
  /// Submit a write of a checkpoint snapshot at `op`.
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
    assert!(s.committed_headers().is_empty());
  }

  #[test]
  fn vsr_state_keeps_only_the_contiguous_in_band_header_prefix() {
    // Build canonical headers for ops 3,4,5 (the committed band above checkpoint_op = 2, commit = 5).
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
    assert_eq!(s.committed_headers().len(), 3);
    assert_eq!(s.committed_headers()[0].op(), OpNumber::with(3));

    // A GAP after op 3 (3, then 5 — op 4 missing) truncates at the gap: only op 3 is kept, so the
    // stored band is always a contiguous canonical prefix recovery can index by op.
    let holed = VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(2),
      0,
      std::vec![mk(3), mk(5)],
    )
    .unwrap();
    assert_eq!(holed.committed_headers().len(), 1);
    assert_eq!(holed.committed_headers()[0].op(), OpNumber::with(3));

    // Headers ABOVE commit are dropped (only the committed band is persisted): commit = 3 keeps op 3.
    let capped = VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(3),
      OpNumber::with(2),
      0,
      std::vec![mk(3), mk(4)],
    )
    .unwrap();
    assert_eq!(capped.committed_headers().len(), 1);
    assert_eq!(capped.committed_headers()[0].op(), OpNumber::with(3));
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
}

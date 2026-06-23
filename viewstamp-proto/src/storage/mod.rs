//! Pluggable durable-storage contract: value types + the `Wal`/`Superblock` traits.
//!
//! The proto owns no log; it orchestrates consensus over a user-supplied `Wal` +
//! `Superblock`. All faults surface as data (`SlotStatus::Faulty`,
//! `WalDone::Fault`) — never as panics; the proto verifies `Header` checksums itself.
//!
//! # Embedder contract
//!
//! This section consolidates the safety requirements a durable backend must honor. Each clause is
//! documented in full on the trait item it binds (linked per clause); every one is load-bearing —
//! the adversarial simulator demonstrates committed-op losses under backends that violate them.
//! The in-memory fixtures in `viewstamp-simulation` are the reference implementations.
//!
//! ## Completion means durable
//!
//! A [`WalDone::Appended`] or [`SuperblockDone::Wrote`] completion asserts the write has reached
//! STABLE storage — the `fsync`/`fdatasync` (or `O_DSYNC`-equivalent) covering it has returned —
//! not merely a kernel page cache or a device's volatile write cache. The proto acks, votes, and
//! reports durable views on the strength of these completions (append-before-ack,
//! durable-view-before-participate), so a completion delivered before true durability lets a
//! client-acked committed op vanish in a crash. Conversely the SYNCHRONOUS views must lag the
//! completions: [`Wal::op_head`], [`Wal::header`], and a [`SlotStatus::Clean`] from
//! [`Wal::status`] reflect only durably-COMPLETED appends, never an in-flight one (the
//! poll-ordering contract on [`Wal`]). Append completions may be drained in any order; root-write
//! completions must not be (see below).
//!
//! ## Writes never `Fault`
//!
//! `Fault` is a READ verdict. [`Wal::submit_append`] MUST complete only as [`WalDone::Appended`];
//! [`Superblock::submit_write`] / [`Superblock::submit_write_checkpoint`] MUST complete only as
//! [`SuperblockDone::Wrote`]. A backend retries internally — or fail-stops the process — until the
//! write is durable; it never reports a write as faulted. The proto has no owner for a "failed"
//! durable write: an append-`Fault` is degraded defensively to a resubmit (costing a retry, with
//! no liveness promise under a backend that keeps faulting), and a root-write `Fault` would be
//! silently dropped — i.e. that durable write would be LOST. A checkpoint READ
//! ([`Superblock::submit_read_checkpoint`]) is the one superblock op that may fault:
//! recovery/state-sync treat it as faults-as-data (retry within budget, then peer-fetch).
//!
//! ## Headers survive their bodies
//!
//! WAL slot headers MUST be durable INDEPENDENTLY of their bodies (redundant or
//! atomically-replaced header storage, TigerBeetle-style), so a body-level fault — a torn write,
//! bit-rot — on a completed append can never lose the header. A body-damaged slot still reports
//! its header via [`Wal::header`] and surfaces the damage as a body-level verdict
//! ([`SlotStatus::Faulty`]; a [`WalDone::BodyFaulty`] carrying the durable header), never as a
//! vanished append. The surviving header is what proves a committed op EXISTS at its op number
//! (pinning its canonical identity via [`Header::body_checksum`]) so the body can be peer-repaired;
//! a backend whose body fault also loses the header re-opens a committed-op-LOSS class: the op's
//! existence is forgotten, its number can be re-minted across a view change, and a client-acked op
//! silently disappears. Full statement: the header-durability contract on [`Wal`].
//!
//! ## Root writes are serialized and crash-atomic
//!
//! The durable root is a single serialized writer: [`Superblock::submit_write`] completions are
//! delivered in submission order, and once all outstanding writes complete, the durable
//! [`Superblock::state`] equals the LAST-submitted root (full statement: the root-write ordering
//! contract on [`Superblock`]). Each individual root write must also be crash-ATOMIC: a crash
//! mid-write leaves either the old root or the new root readable — never a torn hybrid, never
//! nothing. The canonical shape (two copies suffice for a single serialized writer):
//!
//! 1. Keep TWO fixed root slots, A and B. The durable root is, at every instant, the newest slot
//!    that verifies.
//! 2. Wrap the encoded root ([`VsrState::encode`]) in a backend envelope carrying a CHECKSUM over
//!    the encoded bytes and a monotonically increasing sequence number. (The encoded root does not
//!    checksum itself; the envelope is the backend's.)
//! 3. Write each new root over the OLDER slot — never in place over the slot holding the current
//!    root — then fsync that slot (data plus metadata, if allocation changed) BEFORE delivering
//!    [`SuperblockDone::Wrote`].
//! 4. On open, read both slots, discard any whose checksum fails to verify, and adopt the
//!    survivor with the higher sequence number.
//!
//! A torn in-progress write then corrupts only the older slot's copy and the checksum routes the
//! next open to the intact root. The shape to avoid is a SINGLE in-place-overwritten root slot: a
//! torn write there destroys the old root and the new one together. With one serialized writer the
//! A/B alternation needs no further coordination; a backend that overlaps root writes or completes
//! them out of order violates VSR safety (a stale checkpoint root could roll back the durable
//! view/commit a later view-change root recorded).
//!
//! ## Checkpoint snapshots read back content-identical
//!
//! [`Superblock::submit_read_checkpoint`] must return, byte-identically, the envelope of the last
//! durably completed [`Superblock::submit_write_checkpoint`]. The snapshot is content-addressed:
//! the root stores [`checkpoint_id`] (an FNV-1a-128 of the envelope bytes) and recovery +
//! state-sync verify the read-back bytes against it, so a checkpoint that reads back altered is
//! detected and treated as faulty (retry, then peer-fetch) rather than restored. The proto itself
//! sequences checkpoint durability before visibility — the snapshot write completes durably
//! BEFORE the root write naming it is submitted — so a backend honoring completion-means-durable
//! can never expose a root that points at a checkpoint a crash erased.
//!
//! ## Drain in-flight ops before re-creating an endpoint
//!
//! [`OpId`]s are unique only within one `Endpoint` incarnation: `Endpoint::new` and
//! `Endpoint::recover` RESTART the sequence. A driver that rebuilds the endpoint over the same
//! live storage handles (a restart-in-place) MUST first drain or cancel every in-flight storage
//! op, so no pre-restart completion is delivered against a post-restart `OpId` it would alias. A
//! real crash satisfies this by construction — in-flight ops die with the process. Full
//! statement: the lifetime contract on [`OpId`].

use std::vec::Vec;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
  ClientId, Epoch, MemberId, OpNumber, RequestNumber, View,
  codec::{CodecError, Reader},
  membership::{Membership, MembershipError},
};

/// On-disk header format version (bumped on any wire/disk layout change).
pub const HEADER_VERSION: u16 = 1;

/// On-disk superblock-root ([`VsrState`]) format version — the version NEW roots are written with, and
/// the high end of the layout-compatible range [`VsrState::decode`] accepts. The superblock root carries
/// its OWN version, like the disk [`Header`]'s [`HEADER_VERSION`], INDEPENDENT of the message
/// [`WIRE_VERSION`](crate::WIRE_VERSION): a version names a disk LAYOUT, and it moves ONLY when the
/// `VsrState` layout itself changes — never as collateral from a message-format change.
///
/// The committed-band-header root layout was byte-identical from the first release through version `3`,
/// but the pre-decoupling code led the root with the shared `WIRE_VERSION`, which bumped `1 → 2 → 3` for
/// MESSAGE-only changes (the `DoViewChange`/`PreparedEntry` Repairing wire, then the `PrepareOk` field).
/// So that ONE pre-membership root layout exists tagged `1`, `2`, AND `3`. Version `4` is the FIRST real
/// `VsrState` LAYOUT change: it APPENDS a durable epoch + membership tail after the v3 body. Version `5`
/// APPENDS a further tail — the recent-prior `config_id` lineage (the superseded ancestor ids that widen
/// cross-epoch catch-up admission) — so a node recovering into a post-reconfiguration epoch RESTORES the
/// predecessor ids rather than dropping them, and a retained old-epoch laggard's catch-up is still
/// admitted after the new-epoch donors restart. Version `6` APPENDS one final scalar — `config_install_op`,
/// the op of the last reconfigure that produced this root's membership — so a recovered donor restores it
/// and the cross-epoch state-sync SERVE gate (`checkpoint_op >= config_install_op`) survives a restart:
/// without it a donor that recovered into a swapped-but-not-yet-checkpointed window would re-attach its
/// successor membership to a checkpoint BELOW the reconfigure op, letting a laggard install the new epoch
/// without the committed prefix through that op.
/// [`VsrState::decode`] dispatches on the leading version — `1..=3` parse the pre-membership layout
/// (bridged to `epoch = 0`, no membership), `4` parses that body plus the epoch/membership tail, `5`
/// parses that plus the lineage tail, and `6` parses that plus the `config_install_op` scalar — so NO
/// persisted root is stranded and a message-only `WIRE_VERSION` bump still can never invalidate a root. A
/// future `VsrState` layout change bumps this again and extends that per-version dispatch.
pub const SUPERBLOCK_VERSION: u16 = 6;

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
    Self::from_parts(op, view, client, request, fnv1a_128(body))
  }

  /// Creates a header from a PRECOMPUTED `body_checksum`, without the body bytes. Used when the body
  /// is absent but its canonical checksum is durably known (a body-`Repairing` log entry), so the
  /// header still records the op's canonical identity. Computes only the header self-checksum; the
  /// `body_checksum` is taken as given. Equivalent to [`Header::new`] when
  /// `body_checksum == fnv1a_128(body)`.
  pub fn from_parts(
    op: OpNumber,
    view: View,
    client: ClientId,
    request: RequestNumber,
    body_checksum: u128,
  ) -> Self {
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
  fn write_canonical(&self, out: &mut impl BufMut) {
    for word in [
      self.version as u128,
      self.op.get() as u128,
      self.view.get() as u128,
      self.client.get(),
      self.request.get() as u128,
      self.body_checksum,
    ] {
      out.put_u128(word);
    }
  }

  fn compute_checksum(&self) -> u128 {
    // Hash exactly the canonical body bytes — the same bytes [`Self::encode`] embeds — so the
    // codec output and the checksum are derived from one definition.
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
/// is SPARSE: one header per committed-band op the writer HELD, so a repair hole omits
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
  ///. It may exceed the writer's locally-APPLIED `commit_min`: a replica held at a
  /// stale/faulty repair hole knows op N is committed yet has not applied it, and the root must record N
  /// so a re-recovered replica's DoViewChange does not under-report the frontier.
  commit: OpNumber,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  /// Canonical headers for the committed band `(checkpoint_op .. commit]` — a SPARSE, op-ascending set
  /// holding ONE header per committed-band op the writer actually HELD. A repair hole —
  /// or a hole in `(commit_min, commit]` when the writer's applied frontier lags — simply OMITS that
  /// op's header; a held op above it keeps its own (so the list may be SHORTER than the full band AND
  /// may contain gaps; see [`Self::try_new`], which validates in-range strictly-ascending ops but allows
  /// gaps). Private; read via [`Self::committed_headers_slice`]. The per-entry `body_checksum` is the
  /// load-bearing field recovery checks the WAL against.
  committed_headers: Vec<Header>,
  /// The current configuration epoch (high-order to `view` in `(epoch, view)` leadership). A legacy
  /// pre-membership root decodes to `0`.
  epoch: Epoch,
  /// The PREVIOUS epoch's number — the durable backward link of the `config_id` lineage chain that lets
  /// the ingress check whether a foreign `config_id` is an in-lineage ancestor. Equals `epoch` at
  /// genesis / for a legacy-bridged root.
  prev_epoch: Epoch,
  /// The active membership (who votes, who leads, the lineage `config_id`). `None` ONLY for a
  /// legacy (v1-3) root that predates membership — `recover` fills it from the caller's `Config`. A
  /// v4/v5 root always carries `Some`, and when present its [`Membership::epoch`] equals `self.epoch`
  /// (enforced by [`Self::try_new_v4`]).
  membership: Option<Membership>,
  /// The recent-prior `config_id` lineage — the superseded ancestor `config_id`s (most-recent-first)
  /// that a node retains in-memory to widen cross-epoch catch-up admission (`Endpoint::in_lineage`).
  /// Persisted in a v5 root so a node recovering into a post-reconfiguration epoch RESTORES these ids
  /// instead of dropping them: without it, the recovered node would seed its in-memory lineage with only
  /// the CURRENT `config_id`, so a retained old-epoch laggard whose catch-up still carries the
  /// predecessor `config_id` would be REJECTED after the new-epoch donors restart — stranding it
  /// (a liveness loss). A v1-4 root carries none (decoded as empty); for a no-reconfiguration cluster the
  /// ring is genesis-only, so recovery's seeding is unchanged. The `config_id` is a content hash chained
  /// from the previous config's id, which a single root cannot recompute — so the lineage MUST be carried
  /// durably, exactly like the membership's own `config_id`. Bounded by the small in-memory ring.
  prior_config_ids: Vec<u128>,
  /// The op of the last reconfigure that produced this root's [`Membership`] — the commit-first SwapEpoch
  /// root for a live single-change, or the offline-restart point for an offline reconfiguration; genesis
  /// (`0`) when no reconfiguration has occurred. A recovered donor restores it so the cross-epoch
  /// state-sync SERVE gate — attach the successor membership to a sync answer ONLY when
  /// `checkpoint_op >= config_install_op` — holds across a restart. Without it a donor recovered into a
  /// swapped-but-not-yet-checkpointed window (its checkpoint is BELOW the reconfigure op) would re-attach
  /// its E+1 membership to a checkpoint at op `M < N`, letting a laggard install E+1 at frontier `M`
  /// WITHOUT the committed prefix through the reconfigure op `N` (an XI-b violation, the same premise the
  /// NORMAL commit-first path enforces). A v1-5 root has no durable `config_install_op` and decodes to the
  /// root's own `checkpoint_op` (so the gate is trivially satisfied — the pre-fix serve behaviour); for a
  /// no-reconfiguration cluster it is genesis, unchanged.
  config_install_op: OpNumber,
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
  ///. It is NOT required to be contiguous: a repair hole the writer had simply omits that
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
    // Validate the SPARSE in-band header set: every op strictly in `(checkpoint_op ..
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
      epoch: Epoch::new(0),
      prev_epoch: Epoch::new(0),
      membership: None,
      prior_config_ids: Vec::new(),
      // A legacy / membership-less root has no reconfiguration of its own; default `config_install_op` to
      // its `checkpoint_op` (the membership it carries — if any — is reflected as of this checkpoint), so
      // the cross-epoch serve gate `checkpoint_op >= config_install_op` is trivially satisfied. A v4/v5
      // root decoded WITHOUT the v6 tail re-validates through here / `try_new_v4` and so inherits the same
      // `checkpoint_op` default (the pre-fix serve behaviour, never withholding a v4/v5 donor's membership).
      config_install_op: checkpoint_op,
    })
  }

  /// Creates a v5 durable root carrying the configuration epoch + the active [`Membership`] + the
  /// recent-prior `config_id` lineage. (Named `try_new_v4` for the membership-carrying root family; the
  /// emitted root is tagged with the current [`SUPERBLOCK_VERSION`].)
  ///
  /// Validates the same consensus-frontier invariants as [`Self::try_new`] (`log_view <= view`,
  /// `commit >= checkpoint_op`, an in-band strictly-ascending committed-header set) AND the
  /// epoch-consistency invariant `membership.epoch() == epoch` — a v4/v5 root's scalar epoch and its
  /// membership's own epoch are two views of one fact and must agree, so a mismatch is a bug, not a
  /// representable state. The committed-header rules are identical to `try_new`; see it for the SPARSE
  /// set's contract.
  ///
  /// `prior_config_ids` are the superseded ancestor `config_id`s (most-recent-first) the writer retained
  /// for cross-epoch catch-up admission; they are carried VERBATIM (a `config_id` is a content hash a
  /// single root cannot recompute) and restored into the recovered node's in-memory lineage. For a
  /// no-reconfiguration cluster they are all the genesis id (a harmless self-duplicate).
  ///
  /// `config_install_op` is the op of the last reconfigure that produced `membership` (the commit-first
  /// SwapEpoch root's reconfigure op for a live single-change, the offline-restart point for an offline
  /// reconfiguration, genesis `0` when none). It is carried durably so a recovered donor restores the
  /// cross-epoch serve gate (`checkpoint_op >= config_install_op`); it is NOT cross-checked against the
  /// consensus frontier (a swapped-but-not-yet-checkpointed root legitimately has `config_install_op`
  /// ABOVE its `checkpoint_op` — that is the exact window the gate protects).
  #[allow(clippy::too_many_arguments)]
  pub fn try_new_v4(
    view: View,
    log_view: View,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    committed_headers: Vec<Header>,
    epoch: Epoch,
    prev_epoch: Epoch,
    membership: Membership,
    prior_config_ids: Vec<u128>,
    config_install_op: OpNumber,
  ) -> Result<Self, VsrStateError> {
    if membership.epoch() != epoch {
      return Err(VsrStateError::MembershipEpochMismatch {
        root: epoch.get(),
        membership: membership.epoch().get(),
      });
    }
    // Reuse the scalar/header validation, then attach the epoch + membership + lineage tail (the legacy
    // constructor leaves epoch = 0 / membership = None / empty lineage, so set them on the validated value).
    let mut state = Self::try_new(
      view,
      log_view,
      commit,
      checkpoint_op,
      checkpoint_id,
      committed_headers,
    )?;
    state.epoch = epoch;
    state.prev_epoch = prev_epoch;
    state.membership = Some(membership);
    state.prior_config_ids = prior_config_ids;
    state.config_install_op = config_install_op;
    Ok(state)
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
      epoch: Epoch::new(0),
      prev_epoch: Epoch::new(0),
      membership: None,
      prior_config_ids: Vec::new(),
      config_install_op: OpNumber::new(),
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
  /// op-ascending set with ONE header per committed-band op the writer HELD (TigerBeetle's `vsr_headers`).
  /// Recovery verifies each committed-band WAL slot against the matching header's
  /// [`Header::body_checksum`]: a held slot whose own self-consistent header kept a stale superseded body
  /// mismatches the canonical checksum and is routed to peer-repair rather than re-derived from the WAL,
  /// while a known-committed op with NO header (one the writer did not hold) is dropped + peer-repaired.
  /// May be SHORTER than the full band AND contain gaps when the caller had repair holes (each held op
  /// keeps its header regardless of a lower hole; [`Self::try_new`] allows gaps).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn committed_headers_slice(&self) -> &[Header] {
    &self.committed_headers
  }

  /// The current configuration epoch (high-order to `view`). A legacy pre-membership root reads `0`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The previous epoch — the durable backward link of the `config_id` lineage. Equals [`Self::epoch`]
  /// at genesis / for a legacy-bridged root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn prev_epoch(&self) -> Epoch {
    self.prev_epoch
  }

  /// The active [`Membership`] of a v4 root.
  ///
  /// # Panics
  ///
  /// Panics if this root carries no membership — i.e. a legacy (v1-3) root decoded through the
  /// migration bridge, whose membership `recover` has not yet supplied from the caller's `Config`. Use
  /// [`Self::membership_opt`] when a root may be legacy-bridged.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership(&self) -> &Membership {
    self
      .membership
      .as_ref()
      .expect("v4 root carries a membership; a legacy-bridged root must be filled by recover first")
  }

  /// The active [`Membership`], or `None` for a legacy (v1-3) root that predates membership (filled by
  /// `recover` from the caller's `Config`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership_opt(&self) -> Option<&Membership> {
    self.membership.as_ref()
  }

  /// The recent-prior `config_id` lineage (superseded ancestor ids, most-recent-first) carried by a v5
  /// root. Empty for a v1-4 root (no durable lineage tail) — `recover` then seeds the in-memory ring with
  /// the current `config_id` (the pre-v5 behaviour). Read by `recover` to restore the in-memory lineage
  /// so a retained old-epoch laggard's cross-epoch catch-up is still admitted after the donors restart.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn prior_config_ids(&self) -> &[u128] {
    &self.prior_config_ids
  }

  /// The op of the last reconfigure that produced this root's [`Membership`] (genesis `0` when none). A
  /// recovered donor restores it so the cross-epoch state-sync serve gate (`checkpoint_op >=
  /// config_install_op`) holds across a restart. A v1-5 root has no durable value and reads its own
  /// `checkpoint_op` (the pre-v6 serve behaviour).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_install_op(&self) -> OpNumber {
    self.config_install_op
  }

  /// Encodes this durable root to a length-prefixed, versioned byte vector (the superblock
  /// on-disk form). Layout (all scalars big-endian): [`SUPERBLOCK_VERSION`] `u16`,
  /// then `view`/`log_view` (`u64` each), `commit`/`checkpoint_op` (`u64` each), `checkpoint_id`
  /// (`u128`), then the committed-band header set as a `u32` count followed by that many
  /// fixed-size [`Header::encode`] blocks (one [`HEADER_ENCODED_LEN`]-byte block per header). That
  /// is the byte-identical v1-3 body; a v4 root APPENDS the epoch + membership tail after it:
  /// `epoch:u64 | prev_epoch:u64 | membership_present:u8`, then — iff present — `config_id:u128 |
  /// epoch:u64 | replica_count:u8 | learner_count:u16 | member_count:u32 | members:(u128 each)`. A v5 root
  /// APPENDS one further tail after that — the recent-prior lineage: `prior_config_count:u32 |
  /// prior_config_ids:(u128 each)`. A v6 root APPENDS one final scalar after that — `config_install_op:u64`
  /// (the op that produced this root's membership). The scalar field order matches the [`Self::try_new`] /
  /// [`Self::try_new_v4`] parameter order. Variable-length because the header set, the member list, and the
  /// lineage are all bounded but not fixed.
  pub fn encode(&self) -> Bytes {
    let members_len = self
      .membership
      .as_ref()
      .map_or(0, |m| m.members_slice().len());
    let mut out = BytesMut::with_capacity(
      2 + 8 * 4 + 16 + 4 + self.committed_headers.len() * HEADER_ENCODED_LEN
      // The appended v4 tail: epoch + prev_epoch + present-flag, plus the membership block when present.
        + 8 + 8 + 1
        + self.membership.as_ref().map_or(0, |_| 16 + 8 + 1 + 2 + 4 + members_len * 16)
      // The appended v5 tail: the lineage count + its ids; then the v6 tail: config_install_op (u64).
        + 4 + self.prior_config_ids.len() * 16
        + 8,
    );
    out.put_u16(SUPERBLOCK_VERSION);
    out.put_u64(self.view.get());
    out.put_u64(self.log_view.get());
    out.put_u64(self.commit.get());
    out.put_u64(self.checkpoint_op.get());
    out.put_u128(self.checkpoint_id);
    out.put_u32(self.committed_headers.len() as u32);
    for h in &self.committed_headers {
      out.put_slice(&h.encode());
    }
    // The appended v4 tail. `epoch`/`prev_epoch` are always written; the membership is gated by a
    // present-flag so a legacy-bridged root (membership = None) round-trips as a v5-tagged root.
    out.put_u64(self.epoch.get());
    out.put_u64(self.prev_epoch.get());
    match &self.membership {
      None => out.put_u8(0),
      Some(m) => {
        out.put_u8(1);
        out.put_u128(m.config_id());
        out.put_u64(m.epoch().get());
        out.put_u8(m.replica_count());
        out.put_u16(m.learner_count());
        out.put_u32(m.members_slice().len() as u32);
        for member in m.members_slice() {
          out.put_u128(member.get());
        }
      }
    }
    // The appended v5 tail: the recent-prior `config_id` lineage (a `u32` count then the ids). Always
    // written for a v5 root — an empty lineage is a count-0 block, so it round-trips uniformly whether or
    // not a membership is present.
    out.put_u32(self.prior_config_ids.len() as u32);
    for &id in &self.prior_config_ids {
      out.put_u128(id);
    }
    // The appended v6 tail: `config_install_op` (the op that produced this root's membership). Always
    // written for a v6 root — a fixed `u64` so it round-trips uniformly whether or not a membership is
    // present.
    out.put_u64(self.config_install_op.get());
    out.freeze()
  }

  /// Decodes a durable root produced by [`Self::encode`], bounds-checked and panic-free on any
  /// truncated / corrupt / adversarial input.
  ///
  /// Dispatches on the leading version: `1..=3` parse the pre-membership layout (bridged to
  /// `epoch = 0`, no membership); `4` parses that body plus the appended epoch/membership tail; `5` adds
  /// the lineage tail; `6` adds the `config_install_op` scalar.
  /// Rejects (never panics): a short buffer ([`CodecError::Truncated`]), an unknown leading version
  /// ([`CodecError::UnknownVersion`]), a header-count / member-count prefix that overruns the buffer
  /// ([`CodecError::LengthOverflow`]), a `membership_present` flag that is neither 0 nor 1
  /// ([`CodecError::InvalidMembershipPresent`]), trailing bytes after the fully-decoded root
  /// ([`CodecError::TrailingBytes`]), or a per-header decode error. The decoded fields are
  /// re-validated through [`Self::try_new`] (v1-3) / [`Self::try_new_v4`] (v4), so a corrupt root
  /// whose fields break the VSR or membership invariants surfaces as [`CodecError::InvalidVsrState`]
  /// rather than constructing an illegal state — i.e. `decode` returns ONLY roots those constructors
  /// would have accepted.
  pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
    let mut r = Reader::new(buf);
    let version = r.u16()?;
    // Dispatch on the leading version. `1..=3` are the ONE pre-membership layout (the pre-decoupling
    // coupling stamped it with 1, 2, AND 3): they share a body and bridge to `epoch = 0` with no
    // membership. `4` parses that same body PLUS the appended epoch/membership tail. A version outside
    // `1..=SUPERBLOCK_VERSION` is rejected CLEAN (never misparsed) — a future layout extends this dispatch.
    if version == 0 || version > SUPERBLOCK_VERSION {
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
    if version <= 3 {
      // A legacy (v1-3) root ends after the committed-band headers — there is no epoch/membership/lineage
      // tail.
      r.finish()?;
      // Re-validate the invariants (log_view <= view, commit >= checkpoint_op, in-band ascending
      // headers): a corrupt root that breaks them is rejected, not silently constructed.
      return Ok(Self::try_new(
        view,
        log_view,
        commit,
        checkpoint_op,
        checkpoint_id,
        committed_headers,
      )?);
    }
    // v4+: the appended epoch/membership tail. `epoch`/`prev_epoch` are always present; the membership is
    // gated by a present-flag (0 = a legacy-bridged root re-saved as v4/v5; 1 = a real membership block).
    let epoch = Epoch::new(r.u64()?);
    let prev_epoch = Epoch::new(r.u64()?);
    let membership = match r.u8()? {
      0 => None,
      1 => {
        // The stored `config_id` is read straight back — it chains from the PREVIOUS config's id, which
        // a single durable root does not retain, so it CANNOT be recomputed here. The superblock's
        // crash-atomic checksummed envelope protects these bytes (exactly as it protects `checkpoint_id`),
        // and `Membership::from_durable_parts` validates structure while TRUSTING this id.
        let config_id = r.u128()?;
        let membership_epoch = Epoch::new(r.u64()?);
        let replica_count = r.u8()?;
        let learner_count = r.u16()?;
        // Each member is a fixed 16-byte `u128`; reject an oversized count before allocating.
        let member_count = r.seq_len(16)?;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
          members.push(MemberId::new(r.u128()?));
        }
        Some(Membership::from_durable_parts(
          membership_epoch,
          replica_count,
          learner_count,
          members,
          config_id,
        )?)
      }
      other => return Err(CodecError::InvalidMembershipPresent(other)),
    };
    // v5+: the appended lineage tail (a `u32` count then the superseded ancestor `config_id`s). A v4 root
    // ends after the membership block — its lineage is empty (recover then seeds from the current id).
    // Each id is a fixed 16-byte `u128`, so an oversized count is rejected before allocating.
    let prior_config_ids = if version >= 5 {
      let lineage_count = r.seq_len(16)?;
      let mut ids = Vec::with_capacity(lineage_count);
      for _ in 0..lineage_count {
        ids.push(r.u128()?);
      }
      ids
    } else {
      Vec::new()
    };
    // v6+: the appended `config_install_op` scalar (the op that produced this root's membership). A v1-5
    // root has none — default to `checkpoint_op` so the cross-epoch serve gate `checkpoint_op >=
    // config_install_op` is trivially satisfied (the pre-v6 serve behaviour: a recovered v4/v5 donor never
    // withholds its membership). Reading it AFTER the lineage keeps the per-version dispatch additive.
    let config_install_op = if version >= 6 {
      OpNumber::with(r.u64()?)
    } else {
      checkpoint_op
    };
    r.finish()?;
    match membership {
      // A v4/v5/v6 root with a real membership re-validates through `try_new_v4` (which adds the
      // epoch-consistency check `membership.epoch() == epoch` on top of the scalar/header invariants).
      Some(membership) => Ok(Self::try_new_v4(
        view,
        log_view,
        commit,
        checkpoint_op,
        checkpoint_id,
        committed_headers,
        epoch,
        prev_epoch,
        membership,
        prior_config_ids,
        config_install_op,
      )?),
      // A v4/v5/v6-tagged root that carries no membership (a legacy root re-saved): scalar/header
      // re-validation only, with the durable epoch/prev_epoch (and any lineage + config_install_op) carried
      // through. A membership-less root has no config chain, so its lineage is normally empty; carried for
      // fidelity.
      None => {
        let mut state = Self::try_new(
          view,
          log_view,
          commit,
          checkpoint_op,
          checkpoint_id,
          committed_headers,
        )?;
        state.epoch = epoch;
        state.prev_epoch = prev_epoch;
        state.prior_config_ids = prior_config_ids;
        state.config_install_op = config_install_op;
        Ok(state)
      }
    }
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
  /// A v4 root's scalar `epoch` disagreed with its own membership's [`Membership::epoch`]; the two are
  /// one fact and must agree.
  #[error("root epoch {root} != membership epoch {membership}")]
  MembershipEpochMismatch {
    /// The root's scalar epoch.
    root: u64,
    /// The membership's own epoch.
    membership: u64,
  },
  /// A decoded v4 membership block violated the [`Membership`] structural invariants (zero
  /// `replica_count`, too many voters, a member-count mismatch, or a duplicate member). Carries the
  /// underlying [`MembershipError`].
  #[error("decoded membership is invalid: {0}")]
  InvalidMembership(#[from] MembershipError),
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

/// A durable read whose header self-checksum verifies but whose body failed verification
/// (torn / bit-rot) or is absent — the op EXISTS and its identity is known; only the body
/// needs peer-repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyFaulty {
  id: OpId,
  header: Header,
}
impl BodyFaulty {
  /// Creates a body-faulty result.
  pub const fn new(id: OpId, header: Header) -> Self {
    Self { id, header }
  }

  /// The correlation id of the storage op that produced this result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> OpId {
    self.id
  }

  /// The WAL entry header (durable and self-verified).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn header(&self) -> Header {
    self.header
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
  /// A durable read whose header verifies but whose body failed verification or is absent.
  BodyFaulty(BodyFaulty),
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
/// This is load-bearing for append-before-ack: the proto's head (`self.op`) advances
/// at SUBMIT, but the ack/vote it owes is deferred until the matching [`WalDone::Appended`]. A driver
/// that advanced [`op_head`](Wal::op_head) (or flipped a slot to [`Clean`](SlotStatus::Clean)) on
/// SUBMIT rather than on COMPLETION would silently let a `PrepareOk` be cast for a not-yet-durable op,
/// breaking the invariant — so the "only-durable" rule above is a CONTRACT, not an implementation
/// detail. Append completions ([`WalDone::Appended`]) are correlated by [`OpId`] and MAY arrive in
/// ANY order — a real proactor (io_uring with several SQEs in flight) reorders completions — so the
/// proto MUST NOT assume FIFO completion; the synchronous views above MUST stay consistent with
/// "only-durable" regardless of the order completions are drained in.
///
/// **Header-durability contract (load-bearing for committed-op survival).** Slot HEADERS MUST be
/// durable INDEPENDENTLY of their bodies — redundant or atomically-replaced header storage,
/// TigerBeetle-style — such that a body-level fault (a torn write, bit-rot) on a completed append
/// can never lose the header. A slot whose body is torn/rotted MUST still report its header via
/// [`header`](Wal::header) and surface the damage as a body-level verdict ([`SlotStatus::Faulty`]
/// from [`status`](Wal::status); a [`WalDone::BodyFaulty`] carrying the durable header from a read)
/// — never vanish as if the append had not happened. The keep-header-only recovery shape
/// (`Body::Repairing`) depends on this: the surviving header is what proves a committed op EXISTS
/// at its op number (and pins its canonical identity) so the body can be peer-repaired. A backend
/// whose body fault also loses the header reintroduces a committed-op-LOSS class: the op's
/// existence is forgotten, its number can be re-minted across a view change, and a client-acked
/// committed op silently disappears.
///
/// **Capacity / back-pressure contract.** [`capacity`](Wal::capacity) is
/// the total number of slots the log can hold (`u64::MAX` ⇒ effectively unbounded; the default).
/// `submit_*` stay INFALLIBLE — they return `()` and never signal "queue full" — so the back-pressure
/// model is **the proto's job, not the driver's** (TigerBeetle-faithful: the WAL is a fixed ring and
/// the replica stalls op-assignment before it would wrap): the proto MUST NOT
/// [`submit_append`](Wal::submit_append) an op that would require more than [`capacity`](Wal::capacity)
/// un-pruned slots to be live at once (it stalls assigning the next op until a
/// [`prune`](Wal::prune) frees room). A conforming driver MAY
/// `debug_assert`/panic if the proto violates this (submits past `capacity()` un-pruned slots); it is
/// NOT required to grow, queue, or reject the append. The primary stall is implemented
/// (`Endpoint::on_request` refuses to mint op `K+1` when `(K+1) - prune_floor > capacity()`), so a
/// bounded backend physically wraps op `K`'s slot only after `K` is checkpoint-subsumed on a quorum.
///
/// **Liveness constraint on a bounded `capacity()`.** The stall self-RELEASES as the quorum checkpoint
/// rises (which lifts the prune floor and frees slots), so `capacity()` MUST exceed one checkpoint
/// interval plus the in-flight pipeline depth — concretely `capacity() > config.checkpoint_ops() +
/// pipeline_headroom`. With a ring smaller than (or equal to) a checkpoint interval the un-pruned
/// window `(floor, op]` cannot reach the next checkpoint boundary before it would wrap, so the stall
/// would never release and the primary would WEDGE. A backend that reports a fixed `capacity()` is
/// responsible for honouring this (the sim's bounded mode picks `n` well above `checkpoint_ops`; a
/// disk driver must size its WAL ring the same way).
pub trait Wal {
  /// The highest op number held.
  fn op_head(&self) -> OpNumber;
  /// The durable header at `op`, or `None` ONLY if the slot holds no completed append (never
  /// written, or truncated / pruned / ring-wrapped away). A body-faulty slot MUST still report its
  /// header — headers are durable independently of bodies (the trait-level header-durability
  /// contract); only [`status`](Wal::status)/reads convey the body fault.
  fn header(&self, op: OpNumber) -> Option<Header>;
  /// The slot status for `op` (the present/nack signal).
  fn status(&self, op: OpNumber) -> SlotStatus;
  /// The total WAL slot capacity — the maximum number of un-pruned slots that can be live at once
  /// (`u64::MAX` ⇒ effectively unbounded). The proto observes this to stall op-assignment before it
  /// would wrap a fixed ring; see the trait-level capacity contract.
  /// Defaults to `u64::MAX` (unbounded) so a backend with no fixed bound need not override it.
  fn capacity(&self) -> u64 {
    u64::MAX
  }
  /// Submit a durable append of `(header, body)` at `op`. Completion via [`Wal::poll`]. INFALLIBLE
  /// (returns `()`): the proto guarantees it never submits past [`capacity`](Wal::capacity) un-pruned
  /// slots (see the trait-level capacity contract), so a backend MAY assume room exists.
  ///
  /// **MUST complete as [`WalDone::Appended`] — never [`WalDone::Fault`].** Mirrors the
  /// [`Superblock`] write contract: the implementation retries (or fail-stops) internally until the
  /// append is durable; `Fault` is a READ verdict. A `Fault` completion for an append is an embedder
  /// contract violation — the endpoint degrades it defensively to a re-submit of the same append
  /// (so a transiently-faulting backend costs a retry, not a leaked in-flight ack), but no liveness
  /// is promised under a backend that keeps faulting its appends.
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
/// **Writes MUST NOT surface a [`SuperblockDone::Fault`].** A `Fault` completion is
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

pub(crate) fn fnv1a_128(bytes: &[u8]) -> u128 {
  fnv1a_128_mix(FNV_OFFSET, bytes)
}

fn fnv1a_128_mix(mut acc: u128, bytes: &[u8]) -> u128 {
  for &b in bytes {
    acc ^= b as u128;
    acc = acc.wrapping_mul(FNV_PRIME);
  }
  acc
}

/// The content address of an operation's full IDENTITY — the namespace a `PrepareOk` vote is counted
/// in. It is `(client, request, body_checksum)`: EXACTLY the committed identity `recover` compares
/// (`classify_committed_slot`), with the op number supplied by the `inflight`/log map key and the view
/// deliberately excluded (a committed op's identity is view-independent). Two DISTINCT operations that
/// share body bytes — the same `body_checksum` under a different `(client, request)` — therefore have
/// DIFFERENT identities, so a stale vote for an op number truncated and re-minted for a different
/// request cannot be miscounted. `body_checksum` ALONE left that same-body op-reuse hole open.
pub(crate) fn prepare_identity(
  client: ClientId,
  request: RequestNumber,
  body_checksum: u128,
) -> u128 {
  let acc = fnv1a_128_mix(FNV_OFFSET, &client.get().to_be_bytes());
  let acc = fnv1a_128_mix(acc, &request.get().to_be_bytes());
  fnv1a_128_mix(acc, &body_checksum.to_be_bytes())
}

#[cfg(test)]
mod tests;

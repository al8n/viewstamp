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
//! ## Writes never `Fault` — and cannot say so
//!
//! `Fault` is a READ verdict, and the id namespaces are SPLIT so that is a type-level fact rather
//! than a rule to obey. A submitted write is named by a [`WriteId`] ([`Wal::submit_append`],
//! [`Superblock::submit_write`], [`Superblock::submit_write_checkpoint`]) and the only completions
//! carrying one are [`WalDone::Appended`], [`WalDone::Cancelled`], and [`SuperblockDone::Wrote`];
//! every fault/verdict variant carries a [`ReadId`]. So there is no way to report a terminal write
//! failure: a backend that cannot make a write durable retries internally, or fail-stops the process.
//! The proto has no owner for a "failed" durable write — a lost root write is a lost durable state,
//! and a lost append is an ack/vote the endpoint owes forever. A checkpoint READ
//! ([`Superblock::submit_read_checkpoint`]) is the one superblock op that may fault:
//! recovery/state-sync treat it as faults-as-data (retry within budget, then peer-fetch).
//!
//! ## Every submitted op completes exactly once — and released slots stay theirs until it does
//!
//! Every [`Wal::submit_append`] resolves exactly once: [`WalDone::Appended`] (landed durably),
//! [`WalDone::Cancelled`] (discarded after submission, can no longer land), or membership in the
//! synchronous cancellation list [`Wal::truncate`]/[`Wal::prune`] return (then no async completion
//! follows). A truncate/prune does NOT have to cancel an already-issued write — it usually cannot —
//! but it must never SWALLOW one: the un-cancelled write may land late into its released slot (a
//! tolerated, recovery-re-classified resurrection) and its completion must still be delivered,
//! because that completion is the endpoint's only witness that the write has QUIESCED. The endpoint
//! defers every re-append that would touch the same physical slot (the same op, or its ring alias
//! `op ± k·capacity`) until that witness arrives — so a swallowed completion wedges the slot, and a
//! premature slot reuse below the backend (handing an un-quiesced write's extent to a DIFFERENT op)
//! lets stale bytes overwrite an acked op: the committed-value-loss class the fence exists to close.
//! Bounded backends place op `N` at ring slot `N mod` [`Wal::capacity`] (the placement the
//! ring-window guard and recovery geometry already assume). Full statement: the exactly-once clause
//! on [`Wal::submit_append`] + the cancellation contracts on [`Wal::truncate`]/[`Wal::prune`].
//!
//! Every [`Wal::submit_read`] resolves exactly once too — as [`WalDone::ReadOk`],
//! [`WalDone::BodyFaulty`], [`WalDone::Absent`], or [`WalDone::Fault`] — and a read can never be
//! cancelled synchronously (truncate/prune return [`WriteId`]s), so releasing its slot changes only
//! the verdict it will carry. The obligation binds however LATE the device is: recovery WAITS on
//! every read it submits — a read that has not completed is outstanding, never failed — and spends
//! its retry budget only on delivered failure verdicts, so a swallowed completion wedges the
//! recovery that is waiting on it. A backend that wants a wall-clock bound on that wait MAY resolve
//! an excessively slow read as a delivered [`WalDone::Fault`] instead (its own latency policy — see
//! [`Wal::submit_read`]). Full statement: the exactly-once clause on [`Wal::submit_read`]. A
//! checkpoint read carries the same obligation ([`Superblock::submit_read_checkpoint`], under the
//! superblock's stricter exactly-once contract).
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
//! ## Completions from a previous endpoint are refused, not aliased
//!
//! Every `Endpoint::new` and `Endpoint::recover` takes a fresh INCARNATION, and [`OpId`] carries it
//! alongside the sequence number. A completion minted by a previous incarnation therefore cannot
//! equal any id the current endpoint minted, and the endpoint refuses it at a single choke point
//! before consulting any correlation table.
//!
//! This matters for a driver that rebuilds the endpoint over the same LIVE storage handles — a
//! restart-in-place, where the io_uring fd or thread pool below the endpoint is never torn down and
//! still owes completions for the dead instance's submissions. What the refusal provides is
//! CORRELATION safety: a late completion is INERT — it can never release an ack, cast a vote, or
//! retire a table entry of the successor. What it does NOT provide is physical cancellation:
//! refusing the receipt does not unsend the write, and the dead instance's bytes can still land in
//! their slot at any moment until the backend completes them.
//!
//! So the two facts a completion carries have different lifetimes, and only one of them is the
//! endpoint's. The quiesce fact — which physical slots still owe a landing — belongs to the MEDIUM,
//! and it lives in the [`Storage`] session, which owns the handles and every such fact for the
//! medium's whole in-process life. A rebuilt endpoint threads the SAME session, so it inherits
//! every slot-quiescence witness and defers its conflicting re-appends behind a dead predecessor's
//! outstanding writes exactly as the predecessor would have; the session settles those writes off
//! the very completions the choke refuses. The superblock's half of the same inheritance is the
//! ROOT TIMELINE: the session holds every in-flight root write with the exact state it will make
//! durable, the successor recovers AT the timeline's last root (never below a state the medium is
//! already guaranteed to reach), defers its own root write behind a predecessor's outstanding one,
//! and advances its durable-view witness only off the landings the session settles — so an
//! inherited root landing under the successor can never be followed by a root that rewinds the
//! durable view or the checkpoint pointer. The alternative — a fresh ledger over a live medium,
//! which cannot see the slots it must not write and lets an abandoned write land OVER a slot the
//! successor re-appended and acked — is unrepresentable: the handles are inside the session until
//! [`Storage::into_parts`] proves the medium quiet. A real crash discharges the same obligation
//! differently: in-flight ops die with the process, up to the device-latency window in which a
//! write already at the device can still land after process death (a bounded exposure this threat
//! model accepts, not a zero one). Full statement: the contract on [`OpId`].

use std::vec::Vec;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{
  ClientId, Epoch, MemberId, OpNumber, RequestNumber, View,
  codec::{CodecError, Reader},
  membership::{Membership, MembershipError},
};

mod session;
pub use session::Storage;
pub(crate) use session::{
  AppendSubmission, CheckpointSubmission, RootRole, SbPolled, SettledCancellation, WalPolled,
};

/// On-disk header format version (bumped on any wire/disk layout change).
pub const HEADER_VERSION: u16 = 1;

/// On-disk superblock-root ([`VsrState`]) format version — the version every NEW root is written
/// with, and the ONLY version [`VsrState::decode`] accepts. The superblock root carries its OWN
/// version, like the disk [`Header`]'s [`HEADER_VERSION`], INDEPENDENT of the message wire format
/// (whose cross-peer fence is the transport hello, once per connection) — a message-format-only
/// change never invalidates a persisted root.
///
/// The version names the durable-format CONTRACT: the byte layout AND the invariant set the writer
/// enforced over everything the root vouches for — in particular that every membership the store
/// ever installed passed the voter-admission fence (`propose_membership`'s rejection, the
/// prepare/vote screens, and `commit_reconfigure`'s refusal of a brand-new voter). Decode is
/// EXACT-MATCH: a root stamped with any other version fails ([`CodecError::UnknownVersion`]), so a
/// store written under a different contract is never recovered, never serves state-sync, and never
/// seeds an offline restart — the one supported path for such a store is a re-format. This closes
/// the one shape no runtime predicate can re-check: a configuration an unfenced writer already
/// INSTALLED into a durable root would otherwise re-enter through recovery (which must trust the
/// root's membership — it has no predecessor to diff against) and could then be served to a laggard
/// whose cross-epoch install verifies only the `config_id` hash chain. Refusing the bytes at the
/// single parse point turns that exclusion from an operational assumption into a structural
/// property.
///
/// A contract change — a layout change OR a strengthening of the writer-enforced invariants — bumps
/// this constant, atomically invalidating every store written under the previous contract.
///
/// Version `9` names the CLIENT-SESSION contract: a v9 writer's session DAG (reached through the
/// root's `checkpoint_sessions_root`) records each cached reply as a terminal OUTCOME — a bounded
/// body, or the refusal that replaces an over-bound one — so a recovered table can resend exactly
/// what the client was originally sent. Earlier roots' session records can only express a body, so
/// a table restored from one could not distinguish "no reply cached" from "the reply was refused",
/// and a resend after recovery would answer a request differently than the pre-crash primary did.
/// Version `2` additionally strengthened the `config_install_op` invariant: a writer from `2`
/// onward records the VERBATIM producing op of the root's membership (the committed reconfigure op,
/// or the donor-carried op a crossing validated — never a checkpoint-frontier approximation), so a
/// recovered root's value can be re-served as exact, where a version-`1` root's slot may instead
/// hold the crossing checkpoint frontier its writer approximated with. Decode refuses every
/// superseded numbering (`UnknownVersion`) rather than recovering a store written under a weaker
/// contract; the one supported path for such a store is a re-format. The superseded words are
/// `1..=8`: the shared-constant era stamped `1`, an early split numbering ran `3..=8`, a later
/// generation reset to `1`, and the `config_install_op` era stamped `2` — so `9` collides with no
/// writer generation at all.
pub const SUPERBLOCK_VERSION: u16 = 9;

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
/// Two parts, and the pairing is what makes the id unambiguous: an **incarnation** identifying the
/// `Endpoint` instance that minted it, and a **sequence number** unique within that instance. Every
/// `Endpoint::new` and `Endpoint::recover` takes a fresh incarnation, so two endpoints over the same
/// storage never mint equal ids even though both sequence from 1.
///
/// **Foreign completions are rejected, not aliased.** An endpoint dispatches a completion only when
/// its incarnation matches the endpoint's own; a completion minted by a previous incarnation is
/// refused wholesale at a single choke point before any correlation table is consulted. That closes
/// the CORRELATION half of the restart-in-place hazard: a driver that rebuilds the endpoint over
/// live storage handles — without tearing down the io_uring fd or thread pool beneath it — can
/// deliver a pre-restart completion into the new endpoint, and it lands on nothing: it releases no
/// ack, casts no vote, retires no table entry. It does NOT close the PHYSICAL half: refusing the
/// completion cancels nothing, so the dead instance's write can still land in its slot. That half
/// is closed by the [`Storage`] session instead, which settles every completion in its medium
/// ledger — foreign or own, keyed by the FULL `(incarnation, sequence)` pair so no incarnation's
/// sequence can alias another's — BEFORE the endpoint's choke judges correlation. The successor
/// therefore inherits the slot-quiescence witnesses and defers its conflicting re-appends behind a
/// predecessor's outstanding write; and on the superblock it inherits the ROOT TIMELINE the same
/// way — it recovers at the last submitted root, defers its own root write behind a predecessor's
/// outstanding one, and lifts its durable-view witness only as the session settles each landing —
/// which is why a rebuild threading the same session needs no pre-rebuild drain for SAFETY.
///
/// The id never reaches disk or the wire; a backend treats it as an opaque token to echo back.
///
/// Deliberately UNORDERED (no `Ord`): an incarnation records process-assignment order, not a
/// meaningful order over ids, so an ordered-by-id collection would smuggle in a process-order
/// dependence — correlation tables key on the sequence number instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpId {
  incarnation: u64,
  seq: u64,
}
impl OpId {
  /// Creates an `OpId` from the minting endpoint's incarnation and a sequence number unique within
  /// it. Endpoints mint their own; a backend echoes what it was handed rather than building one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(incarnation: u64, seq: u64) -> Self {
    Self { incarnation, seq }
  }

  /// The incarnation of the `Endpoint` instance that minted this id. A completion carrying any other
  /// incarnation belongs to a dead endpoint and is refused.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn incarnation(self) -> u64 {
    self.incarnation
  }

  /// The sequence number, unique within the minting incarnation. Correlation tables key on this,
  /// since past the incarnation check every id in hand belongs to the current endpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn seq(self) -> u64 {
    self.seq
  }
}

/// The correlation id of a submitted WRITE: a [`Wal::submit_append`], a [`Superblock::submit_write`],
/// or a [`Superblock::submit_write_checkpoint`].
///
/// **Why writes and reads carry different types.** A write ends exactly one way — durably
/// ([`WalDone::Appended`], [`SuperblockDone::Wrote`]) or, for an append the backend discarded after
/// submission, [`WalDone::Cancelled`]. It can never end as a fault or a read verdict: a backend that
/// cannot make a write durable retries internally or fail-stops the process (the write-fault
/// contracts on [`Wal`] and [`Superblock`]), because the proto has no owner for a "failed" durable
/// write. Every fault/verdict variant carries a [`ReadId`] instead, so "this WRITE faulted" is not a
/// value that can be constructed — the contract is enforced by the type rather than defended against
/// at the completion router.
///
/// Wraps an [`OpId`], so a write id carries the same incarnation + sequence pairing and is refused by
/// the same incarnation choke when it names a dead endpoint. Write ids and read ids are minted from
/// ONE sequence counter per incarnation: the correlation tables key on the SEQUENCE alone, so a
/// second counter would let a read's sequence alias a live write's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WriteId(OpId);

impl WriteId {
  /// Creates a `WriteId` from the minting endpoint's incarnation and a sequence number unique within
  /// it. Endpoints mint their own; a backend echoes what it was handed rather than building one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(incarnation: u64, seq: u64) -> Self {
    Self(OpId::new(incarnation, seq))
  }

  /// The underlying untyped [`OpId`] — what [`WalDone::id`]/[`SuperblockDone::id`] report, so the
  /// incarnation choke reads every completion's id through one path regardless of its kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op_id(self) -> OpId {
    self.0
  }

  /// The incarnation of the `Endpoint` instance that minted this id (see [`OpId::incarnation`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn incarnation(self) -> u64 {
    self.0.incarnation()
  }

  /// The sequence number, unique within the minting incarnation (see [`OpId::seq`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn seq(self) -> u64 {
    self.0.seq()
  }
}

/// The correlation id of a submitted READ: a [`Wal::submit_read`] or a
/// [`Superblock::submit_read_checkpoint`].
///
/// Reads are where faults live — a torn body, bit-rot, an unreadable checkpoint slot — and the proto
/// treats every one as data (retry within budget, then peer-repair / peer-fetch). So the fault and
/// not-found verdicts ([`WalDone::Fault`], [`WalDone::Absent`], [`WalDone::BodyFaulty`],
/// [`SuperblockDone::Fault`]) carry a `ReadId`, distinct from the [`WriteId`] the durable-completion
/// variants carry. The two types cannot be exchanged, so a verdict can never name a submitted write
/// (see [`WriteId`] for why that report has no owner).
///
/// Wraps an [`OpId`] on the same terms as [`WriteId`]: same incarnation + sequence pairing, same
/// incarnation choke, and the SAME per-incarnation sequence counter as write ids — the correlation
/// tables key on the sequence alone, so read and write sequences must not be able to collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReadId(OpId);

impl ReadId {
  /// Creates a `ReadId` from the minting endpoint's incarnation and a sequence number unique within
  /// it. Endpoints mint their own; a backend echoes what it was handed rather than building one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(incarnation: u64, seq: u64) -> Self {
    Self(OpId::new(incarnation, seq))
  }

  /// The underlying untyped [`OpId`] — what [`WalDone::id`]/[`SuperblockDone::id`] report, so the
  /// incarnation choke reads every completion's id through one path regardless of its kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op_id(self) -> OpId {
    self.0
  }

  /// The incarnation of the `Endpoint` instance that minted this id (see [`OpId::incarnation`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn incarnation(self) -> u64 {
    self.0.incarnation()
  }

  /// The sequence number, unique within the minting incarnation (see [`OpId::seq`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn seq(self) -> u64 {
    self.0.seq()
  }
}

/// The correlation id of an issued BLOCK JOB (a [`BlockJob`](crate::BlockJob) drained via
/// [`Storage::poll_block_job`] and answered via `Endpoint::on_block_done`).
///
/// The third id namespace beside [`WriteId`] and [`ReadId`]: block jobs are neither WAL/superblock
/// writes nor reads, and giving them their own type keeps a job completion from ever naming a
/// storage submission (or vice versa). Wraps an [`OpId`] on the same terms — the same incarnation +
/// sequence pairing, the same single incarnation choke refusing a dead endpoint's completions, and
/// the SAME per-incarnation sequence counter, so a job's sequence can never alias a live write's or
/// read's in any table keyed by sequence alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(OpId);

impl JobId {
  /// Creates a `JobId` from the minting endpoint's incarnation and a sequence number unique within
  /// it. Endpoints mint their own; an executor echoes what it was handed rather than building one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(incarnation: u64, seq: u64) -> Self {
    Self(OpId::new(incarnation, seq))
  }

  /// The underlying untyped [`OpId`] — what the incarnation choke reads, so every completion's id
  /// flows through one path regardless of its kind.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op_id(self) -> OpId {
    self.0
  }

  /// The incarnation of the `Endpoint` instance that minted this id (see [`OpId::incarnation`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn incarnation(self) -> u64 {
    self.0.incarnation()
  }

  /// The sequence number, unique within the minting incarnation (see [`OpId::seq`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn seq(self) -> u64 {
    self.0.seq()
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
    self.verify_header() && self.body_checksum == fnv1a_128(body)
  }

  /// Whether this header ALONE is self-consistent — the stored header checksum matches the canonical
  /// fields. The body-less counterpart of [`Self::verify`], for decisions made from a durable header
  /// WITHOUT its body (the recovery exhaustion resolver keeps a header-only op as a `Body::Repairing`
  /// identity): a bit-rotted header whose `op` field survived the placement check must not be trusted
  /// as an identity witness — peer repair validates the full `(client, request, body_checksum)`, so a
  /// smuggled garbage identity would be an unfillable hole.
  pub fn verify_header(&self) -> bool {
    self.checksum == self.compute_checksum()
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
  /// The current configuration epoch (high-order to `view` in `(epoch, view)` leadership). A
  /// membership-less root carries `0` ([`Self::try_new`]'s default).
  epoch: Epoch,
  /// The PREVIOUS epoch's number — the durable backward link of the `config_id` lineage chain that lets
  /// the ingress check whether a foreign `config_id` is an in-lineage ancestor. Equals `epoch` at
  /// genesis / for a membership-less root.
  prev_epoch: Epoch,
  /// The active membership (who votes, who leads, the lineage `config_id`). `None` ONLY for a
  /// membership-less root (the [`Self::try_new`] shape) — `recover` fills it from the caller's
  /// `Config`. When present its [`Membership::epoch`] equals `self.epoch` (enforced by
  /// [`Self::try_new_v4`]).
  membership: Option<Membership>,
  /// The recent-prior `config_id` lineage — the superseded ancestor `config_id`s (most-recent-first)
  /// that a node retains in-memory to widen cross-epoch catch-up admission (`Endpoint::in_lineage`).
  /// Persisted so a node recovering into a post-reconfiguration epoch RESTORES these ids
  /// instead of dropping them: without it, the recovered node would seed its in-memory lineage with only
  /// the CURRENT `config_id`, so a retained old-epoch laggard whose catch-up still carries the
  /// predecessor `config_id` would be REJECTED after the new-epoch donors restart — stranding it
  /// (a liveness loss). For a no-reconfiguration cluster the
  /// ring is genesis-only, so recovery's seeding is unchanged. The `config_id` is a content hash chained
  /// from the previous config's id, which a single root cannot recompute — so the lineage MUST be carried
  /// durably, exactly like the membership's own `config_id`. Bounded by the small in-memory ring.
  prior_config_ids: Vec<u128>,
  /// The op of the last reconfigure that produced this root's [`Membership`] — the commit-first SwapEpoch
  /// root for a live single-change, or the offline-restart point for an offline reconfiguration; genesis
  /// (`0`) when no reconfiguration has occurred. A cross-epoch state-sync crossing root records the
  /// DONOR-CARRIED producing op VERBATIM (validated at/below the synced frontier), never the crossing
  /// frontier itself, so the value stays the real reconfigure op through any number of crossings — the
  /// landing-driven `MembershipChanged` reports it, and a recovered node re-serves it. A recovered donor
  /// restores it so the cross-epoch state-sync SERVE gate — attach the successor membership to a sync
  /// answer ONLY when `checkpoint_op >= config_install_op` — holds across a restart. Without it a donor
  /// recovered into a swapped-but-not-yet-checkpointed window (its checkpoint is BELOW the reconfigure
  /// op) would re-attach its E+1 membership to a checkpoint at op `M < N`, letting a laggard install E+1
  /// at frontier `M` WITHOUT the committed prefix through the reconfigure op `N` (an XI-b violation, the
  /// same premise the NORMAL commit-first path enforces). [`Self::try_new`] defaults it to the root's own
  /// `checkpoint_op` (a membership-less root has no reconfiguration of its own, so the gate is
  /// trivially satisfied); for a no-reconfiguration cluster it is genesis.
  config_install_op: OpNumber,
  /// The writer's vouched carried-log floor: every op at/below it is folded into a checkpoint SOMEWHERE
  /// in the cluster (the writer's own, or an adoption-learned cluster floor), so the writer's carriers
  /// legitimately omit those ops and its carrier span is bounded by `op − log_floor`. Persisted so a
  /// recovered node RESTORES an adoption-learned floor instead of restarting at its own `checkpoint_op`
  /// and re-learning it from the next carrier/Commit — closing the un-synced crash window where the
  /// restarted node's own carrier could exceed the frame-fit span while its WAL still holds the
  /// pre-adoption band. Never below `checkpoint_op` ([`Self::with_log_floor`] validates; the plain
  /// constructors default it TO `checkpoint_op` — the own checkpoint always vouches its own
  /// prefix).
  log_floor: OpNumber,
  /// The writer's configured checkpoint interval ([`Config::checkpoint_ops`](crate::Config)) — half of
  /// the WAL-GEOMETRY pair recovery validates a restart against (the recovery scan window is derived
  /// from it, so a restart under a smaller interval would clip the scan below a committed tail). `0`
  /// means "not recorded" — the un-stamped constructor shape (no persisting writer produces one; a
  /// validated `Config`'s interval is nonzero): recovery REFUSES a non-virgin root carrying it
  /// ([`RecoverError::GeometryNotRecorded`](crate::RecoverError)). Set via
  /// [`Self::with_wal_geometry`]; the plain constructors leave it unrecorded.
  checkpoint_ops: u64,
  /// The slot capacity of the writer's WAL backend ([`Wal::capacity`]; `u64::MAX` = an unbounded
  /// backend, itself a pinned value a later BOUNDED report must not contradict) — the other half of
  /// the geometry pair. `0` means "not recorded" — the un-stamped constructor shape (no persisting
  /// writer produces one: an endpoint's capacity is observed at recovery or declared nonzero at
  /// construction): recovery REFUSES a non-virgin root carrying it
  /// ([`RecoverError::GeometryNotRecorded`](crate::RecoverError)). Set via [`Self::with_wal_geometry`].
  wal_capacity: u64,
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
      // A membership-less root has no reconfiguration of its own; default `config_install_op` to
      // its `checkpoint_op`, so the cross-epoch serve gate `checkpoint_op >= config_install_op` is
      // trivially satisfied.
      config_install_op: checkpoint_op,
      // The floor a root vouches with no adoption evidence recorded: its own checkpoint. A writer
      // with a higher adoption-learned floor raises it via `with_log_floor`.
      log_floor: checkpoint_op,
      // Geometry unrecorded until the writer stamps it (`with_wal_geometry`). Recovery refuses a
      // NON-virgin root left unstamped (fail-closed), so every persisting writer stamps before
      // submitting.
      checkpoint_ops: 0,
      wal_capacity: 0,
    })
  }

  /// Stamp the WAL-GEOMETRY pair this root vouches — the writer's configured
  /// [`Config::checkpoint_ops`](crate::Config) and its backend's [`Wal::capacity`] — so a later
  /// recovery can refuse a restart under different geometry (which would silently move the recovery
  /// scan window and can clip a committed tail out of it). Not validated here: `0` is the "not
  /// recorded" sentinel the un-stamped constructor shape and the all-zero virgin root carry, and
  /// the check lives at the single consumer (recovery), which refuses a non-virgin root carrying an
  /// unrecorded half ([`RecoverError::GeometryNotRecorded`](crate::RecoverError)). Every persisting
  /// writer stamps both halves nonzero.
  #[must_use]
  pub const fn with_wal_geometry(mut self, checkpoint_ops: u64, wal_capacity: u64) -> Self {
    self.checkpoint_ops = checkpoint_ops;
    self.wal_capacity = wal_capacity;
    self
  }

  /// Raise this root's vouched carried-log floor to `log_floor` — an adoption-learned cluster floor the
  /// writer carries above its own `checkpoint_op` (see the field's doc). Validated, not clamped: a floor
  /// below the root's `checkpoint_op` contradicts "the own checkpoint always vouches its own prefix"
  /// (every production writer raises the floor to at least its checkpoint), so it is a writer bug or a
  /// corrupt decode, rejected as [`VsrStateError::LogFloorBelowCheckpoint`].
  ///
  /// # Errors
  /// [`VsrStateError::LogFloorBelowCheckpoint`] if `log_floor < self.checkpoint_op()`.
  pub fn with_log_floor(mut self, log_floor: OpNumber) -> Result<Self, VsrStateError> {
    if log_floor.get() < self.checkpoint_op.get() {
      return Err(VsrStateError::LogFloorBelowCheckpoint);
    }
    self.log_floor = log_floor;
    Ok(self)
  }

  /// Creates a durable root carrying the configuration epoch + the active [`Membership`] + the
  /// recent-prior `config_id` lineage. (Named `try_new_v4` for the membership-carrying root family —
  /// [`Self::try_new`] builds the membership-less shape; the emitted root is tagged with the current
  /// [`SUPERBLOCK_VERSION`].)
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
    // Reuse the scalar/header validation, then attach the epoch + membership + lineage tail (the
    // membership-less constructor leaves epoch = 0 / membership = None / empty lineage, so set them
    // on the validated value).
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
      log_floor: OpNumber::new(),
      checkpoint_ops: 0,
      wal_capacity: 0,
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

  /// The writer's vouched carried-log floor (never below [`Self::checkpoint_op`]; see the field's
  /// doc). `recover` restores it — capped at the recovered head, whose WAL is the only carrier
  /// evidence that survived the crash — instead of restarting the floor at the own checkpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn log_floor(&self) -> OpNumber {
    self.log_floor
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
  pub const fn committed_headers_slice(&self) -> &[Header] {
    self.committed_headers.as_slice()
  }

  /// The current configuration epoch (high-order to `view`). A membership-less root reads `0`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The previous epoch — the durable backward link of the `config_id` lineage. Equals [`Self::epoch`]
  /// at genesis / for a membership-less root.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn prev_epoch(&self) -> Epoch {
    self.prev_epoch
  }

  /// The active [`Membership`] of a membership-bearing root.
  ///
  /// # Panics
  ///
  /// Panics if this root carries no membership — i.e. a membership-less root whose membership
  /// `recover` has not yet supplied from the caller's `Config`. Use [`Self::membership_opt`] when a
  /// root may be membership-less.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership(&self) -> &Membership {
    self
      .membership
      .as_ref()
      .expect("a membership-bearing root; a membership-less root must be filled by recover first")
  }

  /// The active [`Membership`], or `None` for a membership-less root (filled by `recover` from the
  /// caller's `Config`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn membership_opt(&self) -> Option<&Membership> {
    self.membership.as_ref()
  }

  /// The recent-prior `config_id` lineage (superseded ancestor ids, most-recent-first). Empty when
  /// no reconfiguration has occurred — `recover` then seeds the in-memory ring with the current
  /// `config_id`. Read by `recover` to restore the in-memory lineage so a retained old-epoch
  /// laggard's cross-epoch catch-up is still admitted after the donors restart.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn prior_config_ids(&self) -> &[u128] {
    self.prior_config_ids.as_slice()
  }

  /// The op of the last reconfigure that produced this root's [`Membership`] (genesis `0` when none). A
  /// recovered donor restores it so the cross-epoch state-sync serve gate (`checkpoint_op >=
  /// config_install_op`) holds across a restart. A membership-less root reads its own
  /// `checkpoint_op` ([`Self::try_new`]'s default — the gate trivially satisfied).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_install_op(&self) -> OpNumber {
    self.config_install_op
  }

  /// The checkpoint interval this root's writer was configured with
  /// ([`Config::checkpoint_ops`](crate::Config)) — half of the WAL-geometry pair recovery validates a
  /// restart against. `0` = not recorded (an un-stamped root): recovery refuses a non-virgin root
  /// carrying it ([`RecoverError::GeometryNotRecorded`](crate::RecoverError)).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_ops(&self) -> u64 {
    self.checkpoint_ops
  }

  /// The slot capacity of this root's writer's WAL backend ([`Wal::capacity`];
  /// `u64::MAX` = unbounded) — the other half of the geometry pair. `0` = not recorded (an
  /// un-stamped root): recovery refuses a non-virgin root carrying it
  /// ([`RecoverError::GeometryNotRecorded`](crate::RecoverError)).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn wal_capacity(&self) -> u64 {
    self.wal_capacity
  }

  /// Encodes this durable root to a length-prefixed, versioned byte vector (the superblock
  /// on-disk form). Layout (all scalars big-endian): [`SUPERBLOCK_VERSION`] `u16`, then
  /// `view`/`log_view` (`u64` each), `commit`/`checkpoint_op` (`u64` each), `checkpoint_id`
  /// (`u128`), the committed-band header set as a `u32` count followed by that many fixed-size
  /// [`Header::encode`] blocks (one [`HEADER_ENCODED_LEN`]-byte block per header), the epoch pair
  /// `epoch:u64 | prev_epoch:u64`, a `membership_present:u8` flag then — iff present —
  /// `config_id:u128 | epoch:u64 | replica_count:u8 | learner_count:u16 | member_count:u32 |
  /// members:(u128 each)`, the recent-prior lineage `prior_config_count:u32 | prior_config_ids:
  /// (u128 each)`, the scalars `config_install_op:u64` (the op that produced this root's
  /// membership) and `log_floor:u64` (the writer's vouched carried-log floor), and the WAL-geometry
  /// pair `checkpoint_ops:u64 | wal_capacity:u64`. The scalar field order matches the
  /// [`Self::try_new`] / [`Self::try_new_v4`] parameter order. Variable-length because the header
  /// set, the member list, and the lineage are all bounded but not fixed.
  pub fn encode(&self) -> Bytes {
    let members_len = self
      .membership
      .as_ref()
      .map_or(0, |m| m.members_slice().len());
    let mut out = BytesMut::with_capacity(
      2 + 8 * 4 + 16 + 4 + self.committed_headers.len() * HEADER_ENCODED_LEN
      // The epoch pair + present-flag, plus the membership block when present.
        + 8 + 8 + 1
        + self.membership.as_ref().map_or(0, |_| 16 + 8 + 1 + 2 + 4 + members_len * 16)
      // The lineage count + its ids; then the config_install_op + log_floor scalars and the
      // checkpoint_ops + wal_capacity geometry pair, a u64 each.
        + 4 + self.prior_config_ids.len() * 16
        + 8 + 8 + 8 + 8,
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
    // The epoch pair. `epoch`/`prev_epoch` are always written; the membership is gated by a
    // present-flag so a membership-less root (the [`Self::try_new`] shape) round-trips.
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
    // The recent-prior `config_id` lineage (a `u32` count then the ids). An empty lineage is a
    // count-0 block, so it round-trips uniformly whether or not a membership is present.
    out.put_u32(self.prior_config_ids.len() as u32);
    for &id in &self.prior_config_ids {
      out.put_u128(id);
    }
    // `config_install_op` (the op that produced this root's membership) — a fixed `u64`, uniform
    // whether or not a membership is present.
    out.put_u64(self.config_install_op.get());
    // `log_floor` (the writer's vouched carried-log floor) — a fixed `u64`, uniform like the
    // previous scalar.
    out.put_u64(self.log_floor.get());
    // The WAL-geometry pair (`checkpoint_ops` then `wal_capacity`), two fixed `u64`s. `0` = not
    // recorded, carried verbatim.
    out.put_u64(self.checkpoint_ops);
    out.put_u64(self.wal_capacity);
    out.freeze()
  }

  /// Decodes a durable root produced by [`Self::encode`], bounds-checked and panic-free on any
  /// truncated / corrupt / adversarial input.
  ///
  /// Accepts EXACTLY the current [`SUPERBLOCK_VERSION`] — the durable-format contract this build
  /// writes — and parses the single current layout. Rejects (never panics): any other leading
  /// version ([`CodecError::UnknownVersion`] — the durable-format fence; see the constant's doc), a
  /// short buffer ([`CodecError::Truncated`]), a header-count / member-count / lineage-count prefix
  /// that overruns the buffer ([`CodecError::LengthOverflow`]), a `membership_present` flag that is
  /// neither 0 nor 1 ([`CodecError::InvalidMembershipPresent`]), trailing bytes after the
  /// fully-decoded root ([`CodecError::TrailingBytes`]), or a per-header decode error. The decoded
  /// fields are re-validated through [`Self::try_new`] / [`Self::try_new_v4`], so a corrupt root
  /// whose fields break the VSR or membership invariants surfaces as [`CodecError::InvalidVsrState`]
  /// rather than constructing an illegal state — i.e. `decode` returns ONLY roots those
  /// constructors would have accepted.
  pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
    let mut r = Reader::new(buf);
    // EXACT-MATCH version gate: only the current durable-format contract is accepted. Any other
    // leading version — older, newer, or a superseded numbering — is refused CLEAN, never parsed.
    let version = r.u16()?;
    if version != SUPERBLOCK_VERSION {
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
    // The epoch/membership tail. `epoch`/`prev_epoch` are always present; the membership is gated
    // by a present-flag (0 = a membership-less root, the [`Self::try_new`] shape; 1 = a real
    // membership block).
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
    // The lineage tail (a `u32` count then the superseded ancestor `config_id`s). Each id is a
    // fixed 16-byte `u128`, so an oversized count is rejected before allocating.
    let lineage_count = r.seq_len(16)?;
    let mut prior_config_ids = Vec::with_capacity(lineage_count);
    for _ in 0..lineage_count {
      prior_config_ids.push(r.u128()?);
    }
    // `config_install_op` (the op that produced this root's membership) and `log_floor` (the
    // writer's vouched carried-log floor; validated through `with_log_floor` below, so a corrupt
    // scalar below the checkpoint is rejected, never constructed).
    let config_install_op = OpNumber::with(r.u64()?);
    let log_floor = OpNumber::with(r.u64()?);
    // The WAL-geometry pair (`checkpoint_ops` then `wal_capacity`). Decode stays FAITHFUL and
    // judgment-free: `0` (= not recorded) is carried verbatim to the single consumer, recovery's
    // geometry fence, which REFUSES a non-virgin root with either half unrecorded
    // (`RecoverError::GeometryNotRecorded`); only a fully-virgin root (`VsrState::new()`) proceeds,
    // into the wiped-voter fail-stop.
    let (checkpoint_ops, wal_capacity) = (r.u64()?, r.u64()?);
    r.finish()?;
    match membership {
      // A root with a real membership re-validates through `try_new_v4` (which adds the
      // epoch-consistency check `membership.epoch() == epoch` on top of the scalar/header invariants).
      Some(membership) => Ok(
        Self::try_new_v4(
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
        )?
        .with_log_floor(log_floor)?
        .with_wal_geometry(checkpoint_ops, wal_capacity),
      ),
      // A root that carries no membership (the [`Self::try_new`] shape — one written before any
      // reconfiguration produced a durable membership): scalar/header re-validation only, with the
      // durable epoch/prev_epoch (and any lineage + config_install_op + log_floor + geometry)
      // carried through. A membership-less root has no config chain, so its lineage is normally
      // empty; carried for fidelity.
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
        Ok(
          state
            .with_log_floor(log_floor)?
            .with_wal_geometry(checkpoint_ops, wal_capacity),
        )
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
  /// `log_floor` was below `checkpoint_op` — the own checkpoint always vouches its own prefix, so a
  /// lower floor is a writer bug or a corrupt decode, never a representable state.
  #[error("log_floor is below checkpoint_op")]
  LogFloorBelowCheckpoint,
}

/// A successful WAL read result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOk {
  id: ReadId,
  header: Header,
  body: Bytes,
}
impl ReadOk {
  /// Creates a read result.
  pub fn new(id: ReadId, header: Header, body: Bytes) -> Self {
    Self { id, header, body }
  }

  /// The correlation id of the read that produced this result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> ReadId {
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
  id: ReadId,
  header: Header,
}
impl BodyFaulty {
  /// Creates a body-faulty result.
  pub const fn new(id: ReadId, header: Header) -> Self {
    Self { id, header }
  }

  /// The correlation id of the read that produced this result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> ReadId {
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
  Appended(WriteId),
  /// A read returned a valid entry.
  ReadOk(ReadOk),
  /// A read found no entry at that slot.
  Absent(ReadId),
  /// A READ-level fault: a storage fault or proto-detected corruption on a
  /// [`submit_read`](Wal::submit_read). It carries a [`ReadId`], so it can never name a submitted
  /// APPEND — an append has no faulted ending (see the write-fault contract on
  /// [`submit_append`](Wal::submit_append)).
  Fault(ReadId),
  /// A durable read whose header verifies but whose body failed verification or is absent.
  BodyFaulty(BodyFaulty),
  /// An append the backend cancelled AFTER submission: its bytes never became durable and can no
  /// longer land. This is the ASYNCHRONOUS cancellation report (e.g. a proactor whose cancel request
  /// resolves at completion time, io_uring-style); a backend that can discard a queued write DURING
  /// [`Wal::truncate`]/[`Wal::prune`] reports it synchronously via their return value instead, and
  /// MUST NOT also deliver this. Legal ONLY for an append whose op the endpoint has RELEASED (above a
  /// truncation head or below a prune floor) — cancelling a live append the endpoint still owes an
  /// ack/vote for is a contract violation (the endpoint degrades it to a re-submit, mirroring the
  /// [`WalDone::Fault`] shape, so a spuriously-cancelling backend costs a retry, not a wedge). Never
  /// report a cancelled append as [`Appended`](WalDone::Appended) (a false durability claim that could
  /// release a vote for bytes that never landed). Reporting it as a fault is not expressible:
  /// [`Fault`](WalDone::Fault) names a READ.
  Cancelled(WriteId),
}

impl WalDone {
  /// The correlation id this completion answers, whichever variant carries it, as the untyped
  /// [`OpId`]. The endpoint reads it at one choke point to refuse completions minted by a previous
  /// incarnation, before any correlation table is consulted — a check that turns only on the
  /// incarnation, so it is uniform over write and read completions alike.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> OpId {
    match self {
      Self::Appended(id) | Self::Cancelled(id) => id.op_id(),
      Self::Absent(id) | Self::Fault(id) => id.op_id(),
      Self::ReadOk(r) => r.id().op_id(),
      Self::BodyFaulty(b) => b.id().op_id(),
    }
  }
}

/// A successful checkpoint read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRead {
  id: ReadId,
  op: OpNumber,
  snapshot: Bytes,
}
impl CheckpointRead {
  /// Creates a checkpoint read result.
  pub fn new(id: ReadId, op: OpNumber, snapshot: Bytes) -> Self {
    Self { id, op, snapshot }
  }

  /// The correlation id of the read that produced this result.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> ReadId {
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
  /// A superblock/checkpoint write became durable — the only ending a write has.
  Wrote(WriteId),
  /// A checkpoint read returned its snapshot.
  CheckpointRead(CheckpointRead),
  /// A READ-level fault: a storage fault on a
  /// [`submit_read_checkpoint`](Superblock::submit_read_checkpoint). It carries a [`ReadId`], so it
  /// can never name a root or checkpoint WRITE — a write has no faulted ending (see the write-fault
  /// contract on [`Superblock`]).
  Fault(ReadId),
}

impl SuperblockDone {
  /// The correlation id this completion answers, whichever variant carries it, as the untyped
  /// [`OpId`]. Read at the same choke point as [`WalDone::id`], so a foreign-incarnation completion
  /// is refused before any correlation table is consulted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn id(&self) -> OpId {
    match self {
      Self::Wrote(id) => id.op_id(),
      Self::Fault(id) => id.op_id(),
      Self::CheckpointRead(r) => r.id().op_id(),
    }
  }
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
/// detail. Completions ([`WalDone::Appended`] for an append, the four read verdicts for a read) are
/// correlated by [`OpId`] and MAY arrive in ANY order — a real proactor (io_uring with several SQEs
/// in flight) reorders completions — so the proto MUST NOT assume FIFO completion; the synchronous
/// views above MUST stay consistent with "only-durable" regardless of the order completions are
/// drained in. The freedom is ordering ONLY, never delivery: every submitted op resolves exactly
/// once. An APPEND resolves as [`WalDone::Appended`], [`WalDone::Cancelled`], or membership in the
/// synchronous cancellation list [`truncate`](Wal::truncate)/[`prune`](Wal::prune) return — see the
/// exactly-once clause on [`submit_append`](Wal::submit_append), which the endpoint's
/// slot-quiescence fence (defer a re-append to a physical slot until the slot's prior write
/// completes) depends on. A READ resolves as exactly one of its four verdicts, with no synchronous
/// ending available to it at all — see the exactly-once clause on
/// [`submit_read`](Wal::submit_read), which the endpoint's recovery depends on: it WAITS on every
/// read it submits, so a completion that never arrives wedges the wait.
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
/// interval: with a ring at or below the interval the un-pruned window `(floor, op]` cannot reach the
/// next checkpoint boundary before it would wrap, so the stall would never release and the primary
/// would WEDGE. That hard floor is published as
/// [`Config::minimum_wal_capacity`](crate::Config::minimum_wal_capacity) and ENFORCED —
/// [`Endpoint::recover`](crate::Endpoint) refuses a backend reporting less
/// ([`RecoverError::WalCapacityBelowMinimum`](crate::RecoverError)). At exactly the floor the primary
/// single-steps near each boundary, so size several intervals plus pipeline headroom above it (the
/// sim's bounded mode uses 3-6 intervals; a disk driver sizes its WAL ring the same way).
pub trait Wal {
  /// The highest op number held. Advisory: `recover()` does NOT trust this scalar — it derives the
  /// written extent by scanning [`header`](Wal::header) over the effective ring (a stored scalar can
  /// bit-rot in either direction; the ring's own durable headers are the witness). It remains the
  /// live-node self-report (e.g. the learner status frontier, which the promote-time challenge
  /// re-verifies).
  fn op_head(&self) -> OpNumber;
  /// The durable header at `op`, or `None` ONLY if the slot holds no completed append (never
  /// written, or truncated / pruned / ring-wrapped away). A body-faulty slot MUST still report its
  /// header — headers are durable independently of bodies (the trait-level header-durability
  /// contract); only [`status`](Wal::status)/reads convey the body fault. The backend may return the
  /// header AS STORED, without validating it: the proto self-verifies before trusting one
  /// ([`Header::verify`] on every body read; [`Header::verify_header`] before any header-only identity
  /// decision), treating an inconsistent header as faults-as-data.
  fn header(&self, op: OpNumber) -> Option<Header>;
  /// The slot status for `op` (the present/nack signal).
  fn status(&self, op: OpNumber) -> SlotStatus;
  /// The total WAL slot capacity — the maximum number of un-pruned slots that can be live at once.
  /// The proto observes this to stall op-assignment before it would wrap a fixed ring, to guard a
  /// backup's head-extend append the same way, and to bound `recover()`'s tail read window at the
  /// provable ring maximum `checkpoint_op + capacity` (a bit-rotted `op_head` scalar is capped there
  /// instead of trusted); see the trait-level capacity contract.
  ///
  /// Defaults to `u64::MAX` — the "no fixed ring" sentinel for a backend with no bound of its own. The
  /// proto then IMPOSES its own finite ring (a few checkpoint intervals plus the pipeline) at those same
  /// enforcement points, so the recovery geometry stays sound for every backend: a ring-less backend
  /// sees this only as deliberate append backpressure when checkpointing stalls far behind
  /// (TigerBeetle's flow control — and strictly better than unbounded WAL growth during such a stall).
  ///
  /// **Cross-incarnation stability.** The reported value MUST be stable across restarts of the same
  /// store: the recovery scan window AND a bounded backend's physical op→slot placement are both derived
  /// from it, so reopening a store under a different capacity silently moves committed slots out of the
  /// scan window (and relocates every ring slot) — a committed-loss hazard no scan can detect. A backend
  /// that must resize its ring performs an explicit offline migration (rewrite the slots under the new
  /// placement, then report the new value). Recovery enforces this: the durable root pins the geometry
  /// pair ([`VsrState::wal_capacity`] / [`VsrState::checkpoint_ops`]) and
  /// [`Endpoint::recover`](crate::Endpoint::recover) REFUSES a restart whose live values differ
  /// ([`RecoverError`](crate::RecoverError)), and also refuses a capacity below
  /// [`Config::minimum_wal_capacity`](crate::Config::minimum_wal_capacity) (the documented liveness
  /// floor, otherwise the primary would wedge at the first un-releasable mint stall).
  fn capacity(&self) -> u64 {
    u64::MAX
  }
  /// Submit a durable append of `(header, body)` at `op`. Completion via [`Wal::poll`]. INFALLIBLE
  /// (returns `()`): the proto guarantees it never submits past [`capacity`](Wal::capacity) un-pruned
  /// slots (see the trait-level capacity contract), so a backend MAY assume room exists.
  ///
  /// **An append has no faulted ending.** It takes a [`WriteId`], and the only completions that
  /// carry one are [`WalDone::Appended`] and [`WalDone::Cancelled`] — there is no way to report a
  /// terminal write failure, by construction. `Fault` is a READ verdict over a [`ReadId`]. Mirrors
  /// the [`Superblock`] write contract: an implementation that cannot make the append durable
  /// retries internally, or fail-stops the process; it never hands the proto a failure it has no
  /// owner for.
  ///
  /// **Exactly-once completion (load-bearing for the slot-quiescence fence).** EVERY submitted append
  /// resolves exactly once: as [`WalDone::Appended`] (its bytes landed durably), as
  /// [`WalDone::Cancelled`] (the backend discarded it after submission — its bytes can no longer
  /// land), or synchronously via the cancellation list a [`truncate`](Wal::truncate)/
  /// [`prune`](Wal::prune) returns (then NO async completion follows). An intervening truncate/prune
  /// does NOT exempt an append it could not cancel: an un-cancelled write to a released slot may
  /// still land late (the documented lazy-truncate resurrection shape), and its completion MUST
  /// still be delivered — that completion is the endpoint's ONLY portable witness that the write has
  /// QUIESCED (a Sans-I/O core cannot cancel a device write), and the endpoint holds every
  /// conflicting re-append to that physical slot until it arrives. A swallowed completion therefore
  /// wedges the slot's replacement append forever; delivering it is a liveness requirement, not a
  /// courtesy.
  fn submit_append(&mut self, id: WriteId, op: OpNumber, header: Header, body: Bytes);
  /// Submit a read of `op`'s entry. Completion via [`Wal::poll`]: [`WalDone::ReadOk`] with the
  /// entry, [`WalDone::BodyFaulty`] with the durable header alone, [`WalDone::Absent`] for a slot
  /// holding no completed append, or [`WalDone::Fault`]. Reads are where faults live — the proto
  /// treats every one as data (retry on delivered failures within budget, then peer-repair).
  ///
  /// **Exactly-once completion (load-bearing for the recovery wait).** EVERY submitted read
  /// resolves exactly once, as one of those four verdicts — the read half of what the exactly-once
  /// clause on [`submit_append`](Wal::submit_append) requires of a write. No synchronous ending
  /// substitutes for it: [`truncate`](Wal::truncate)/[`prune`](Wal::prune) return [`WriteId`]s, so
  /// a read can never appear in a cancellation list, and releasing a read's slot changes only the
  /// VERDICT it will carry — a backend that has already dropped the slot resolves it
  /// [`WalDone::Absent`], one still holding the bytes may resolve it [`WalDone::ReadOk`], and
  /// either ending is safe (recovery re-classifies whatever the verdict delivers). The proto WAITS
  /// on every read it submits: a read that has not completed is outstanding, never failed —
  /// recovery's retry budget spends only on DELIVERED failure verdicts, never on elapsed time, and
  /// no recovery transition settles while a submitted read still owes its completion. A swallowed
  /// completion therefore wedges the recovery waiting on it — delivering the ending is a liveness
  /// requirement, not a courtesy.
  ///
  /// **Latency policy is the backend's, never the proto's.** The proto holds no clock against a
  /// read and imposes no deadline — a slow medium is simply waited on. A backend MAY bound the
  /// wait itself by resolving an excessively slow read as a delivered [`WalDone::Fault`] (its own
  /// wall-clock policy: a device timeout, an I/O-scheduler deadline); the proto consumes that
  /// fault exactly like any other delivered failure — it spends one unit of the retry budget, and
  /// exhaustion escalates to peer repair. This is an implementation choice the exactly-once clause
  /// already admits (`Fault` is one of the four endings), not a proto requirement: a backend that
  /// never bounds a read is equally conforming, and either way the read resolves exactly once.
  ///
  /// A synthesized `Fault` IS that read's one completion, so a backend that bounds a read MUST NOT
  /// also deliver its real ending later under the same [`ReadId`] — a timeout wrapper that leaves
  /// the underlying I/O running owes the proto one verdict for that id, not two. Recovery is
  /// defensive about it regardless: the fault retires the id from the read fence, and
  /// `on_recover_wal_done` drops any completion whose id the fence no longer holds, so a late
  /// duplicate is ignored by construction — but suppressing it is the backend's obligation, not
  /// something to rely on the handler for.
  ///
  /// This repository ships no [`Wal`] implementation — the drivers are generic over one — so any
  /// wall-clock bound on a recovery read is the embedder's to supply. Without one there is no
  /// bound anywhere: a read the backend never answers holds its recovery open indefinitely.
  ///
  /// Unlike an append's, a read's completion carries no physical-write fact: it frees no slot and
  /// releases no deferred re-append, so what a swallowed one wedges is the waiting recovery, not
  /// the slot. Read completions correlate by [`ReadId`] and MAY be delivered in ANY order relative
  /// to their submission.
  fn submit_read(&mut self, id: ReadId, op: OpNumber);
  /// Drop all slots strictly above `above` (view-change tail truncation), returning the `WriteId`s of
  /// any in-flight appends this call CANCELLED — submissions the backend can prove will now neither
  /// land nor complete (e.g. writes still in its own queue, never issued to the device). A returned id
  /// receives NO further completion; the endpoint retires its bookkeeping on the spot. After a restart
  /// in place the backend may still hold writes a PREVIOUS endpoint incarnation submitted, so the
  /// returned list may name a previous incarnation's writes; the endpoint ignores those.
  ///
  /// # Contract
  /// Takes effect SYNCHRONOUSLY on the synchronous views ([`Wal::op_head`] / [`Wal::header`]) — Phase-1
  /// `recover` and the ring-window math read them immediately after — AND acts as an ORDERING BARRIER for
  /// any append submitted AFTER it. An implementation that queues the truncate as a lazy async trim and
  /// completes it AFTER a later head-extending `submit_append` to the same slots would destroy freshly
  /// appended, already-acked ops — a committed-loss / false-vote hazard. The endpoint always truncates the
  /// tail BEFORE re-appending the canonical head (`start_view_as_new_primary` / `adopt_canonical_head`), so
  /// honoring this ordering is required. CRASH-durability MAY be lazy: a resurrected stale tail above the
  /// authoritative head is re-classified (view / canonical checks) and self-heals into `RecoveringHead`, so
  /// the drop need not be persisted synchronously — only REORDERING it relative to later appends is fatal.
  ///
  /// **What truncate does NOT promise: cancelling already-issued writes.** An append already at the
  /// device (an io_uring SQE in flight) cannot be portably retracted; it may land AFTER this call —
  /// briefly resurrecting a dropped slot — and its completion still arrives (the exactly-once
  /// contract on [`submit_append`](Wal::submit_append)). The endpoint tolerates the late landing
  /// (recovery re-classifies a stale resurrected tail) and defers every conflicting re-append to that
  /// physical slot until the old write's completion proves it quiesced, so a backend has NO
  /// obligation to cancel — only to (a) report what it DID cancel in the return value and (b) keep
  /// its placement discipline: a bounded backend stores op `N` at ring slot `N mod`
  /// [`capacity`](Wal::capacity) (the placement the ring-window guard and the recovery scan geometry
  /// already assume), and NO backend may reuse the physical extent of an un-quiesced write for a
  /// DIFFERENT op (a ring-less backend recycling storage must quiesce it first — ordinary allocator
  /// discipline for an extent with outstanding I/O).
  ///
  /// **Submitted READS are untouched.** The return value names writes ([`WriteId`]), so this call
  /// cannot cancel a read at all: an outstanding read of a slot it releases still resolves, on its
  /// own, exactly once (the clause on [`submit_read`](Wal::submit_read)) — as [`WalDone::Absent`]
  /// once the slot is gone, or with the released bytes if the backend already had them. Recovery
  /// re-classifies whatever the verdict delivers, so either ending is safe; SWALLOWING the read
  /// because its slot was released is not.
  fn truncate(&mut self, above: OpNumber) -> Vec<WriteId>;
  /// Free all slots strictly below `below` (post-checkpoint GC), returning the `WriteId`s of any
  /// in-flight appends this call CANCELLED — same semantics as the [`truncate`](Wal::truncate) return
  /// value (a returned id receives no further completion, the list may name a previous incarnation's
  /// writes, and the endpoint ignores those).
  ///
  /// # Contract
  /// Like [`Wal::truncate`]: takes effect SYNCHRONOUSLY on the synchronous views and must not be reordered
  /// with subsequently-submitted appends. Freeing a slot the endpoint has not moved past is a contract
  /// violation — the endpoint only prunes strictly below a checkpoint-subsumed floor (`run_gc`). Crash
  /// durability may be lazy (a resurrected pruned slot below the checkpoint is inert — the SM snapshot owns
  /// that prefix). And like truncate, prune need NOT cancel an already-issued write below the floor —
  /// the write may land late into its freed slot (inert: the checkpoint subsumes that prefix) and its
  /// completion must still be delivered; what prune must NEVER do is hand that slot's physical extent
  /// to a DIFFERENT op while the old write is un-quiesced. A bounded ring honors this for free through
  /// its `op mod capacity` placement plus the endpoint-side fence (the endpoint defers the aliasing
  /// re-append `op + capacity` until the old write's completion); a recycling backend must honor it
  /// explicitly. And like truncate, prune touches no submitted READ: an outstanding read of a freed
  /// slot still resolves exactly once on its own terms (see [`Wal::truncate`]).
  fn prune(&mut self, below: OpNumber) -> Vec<WriteId>;
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
/// **A write has no faulted ending.** [`submit_write`](Superblock::submit_write) and
/// [`submit_write_checkpoint`](Superblock::submit_write_checkpoint) take a [`WriteId`], and the only
/// completion carrying one is [`SuperblockDone::Wrote`] — there is no way to report a terminal write
/// failure, by construction. An implementation MUST make the write durable, RETRYING internally until
/// it succeeds, or fail-stop the process. `Fault` is reserved for a READ
/// ([`submit_read_checkpoint`](Superblock::submit_read_checkpoint)) and carries a [`ReadId`] —
/// recovery / state-sync treat a checkpoint-read fault as faults-as-data (retry within budget, then
/// peer-fetch). The asymmetry is not a convenience: the durable root is the single source of truth a
/// crash recovers from, and a root write that is allowed to "fail" without the proto re-issuing it has
/// no owner — that durable write would simply be LOST.
///
/// **Every completion is delivered exactly once (load-bearing for the fail-stop fences).** Each
/// submitted op — a root write, a checkpoint write, a checkpoint read — resolves as EXACTLY ONE
/// completion from [`poll`](Superblock::poll): never zero (the write-fault contract above already
/// forbids a lost ending), and never more than one. For ROOT writes specifically this is not a
/// hygiene rule: the storage session accounts every root completion against its submission-order
/// timeline, and that ledger is what makes the effective root — the state the medium is guaranteed
/// to converge to — readable at all. A completion the ledger cannot account for (a `Wrote` whose id
/// was never submitted, a DUPLICATE delivery of an already-settled root, or a root completing out
/// of submission order) is treated as an untrusted medium and the process FAIL-STOPS: these are
/// hard failures in every build profile, not recoverable errors, because consensus over a ledger of
/// write facts that no longer matches the device risks silent durable-state corruption. A retry
/// layer between the device and this trait must therefore deduplicate before delivering. Note the
/// deliberate asymmetry with the WAL channel: a duplicate [`WalDone::Appended`] settles to a no-op
/// in the append ledger and is ignored by the endpoint (append completions may also reorder, per
/// the WAL's poll-ordering contract), whereas the superblock's ordering and exactly-once
/// obligations are strict — the durable root is a single serialized timeline, and every relaxation
/// the WAL channel tolerates is one this channel cannot.
pub trait Superblock {
  /// The current durable root (the last root write that has completed).
  fn state(&self) -> VsrState;
  /// Submit an atomic write of the durable root. Completions are delivered in submission order
  /// relative to other `submit_write` calls (see the trait-level root-write ordering contract). It
  /// completes only as [`SuperblockDone::Wrote`] — the [`WriteId`] admits no other ending; the
  /// implementation retries internally until durable (see the trait-level write-fault contract).
  fn submit_write(&mut self, id: WriteId, state: VsrState);
  /// Submit a write of a checkpoint snapshot at `op`. Completes only as [`SuperblockDone::Wrote`],
  /// on the same terms as [`submit_write`](Superblock::submit_write) (see the trait-level write-fault
  /// contract).
  fn submit_write_checkpoint(&mut self, id: WriteId, op: OpNumber, snapshot: Bytes);
  /// Submit a read of the checkpoint snapshot the CURRENT durable root names — the snapshot written at
  /// [`state`](Superblock::state)'s `checkpoint_op`, NOT merely the last snapshot write submitted.
  ///
  /// **A staged-but-unrooted snapshot MUST NOT become the read-back checkpoint** (load-bearing for VSR
  /// safety). A [`submit_write_checkpoint`](Superblock::submit_write_checkpoint) whose matching durable
  /// root ([`submit_write`](Superblock::submit_write)) has not yet completed is NOT yet the durable
  /// checkpoint; serving it would return a checkpoint the durable root does not name. So a recovery read
  /// MUST satisfy `read.op == state().checkpoint_op()`. This is what makes it safe for the proto to
  /// abandon an in-flight state-sync re-persist before its root is staged (a view change supersedes it):
  /// the abandoned snapshot write may still complete in the store, but with no matching root it must
  /// never be read back against a durable root naming the PRIOR checkpoint — which would make local
  /// recovery reject its own (still-valid) durable checkpoint by op/id mismatch and force a needless peer
  /// fetch. A backend keyed by checkpoint op (as the test fixture is, and as TigerBeetle's single rooted
  /// superblock slot is by construction) satisfies this naturally; one that returns the last-written
  /// snapshot regardless of which root is durable would violate it.
  ///
  /// This is the ONE superblock op that may fault: it completes as
  /// [`SuperblockDone::CheckpointRead`] or [`SuperblockDone::Fault`], both over its [`ReadId`].
  fn submit_read_checkpoint(&mut self, id: ReadId);
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

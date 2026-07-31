//! The storage session: the owner whose lifetime is the medium's.
//!
//! Every fact in this module exists because it outlives an [`Endpoint`](crate::Endpoint): a
//! submitted write is a physical fact about the medium, not about the endpoint that submitted it,
//! and it stays a fact across any number of endpoint rebuilds until its completion (or a
//! synchronous cancellation) proves it quiesced. The session owns the [`Wal`] and [`Superblock`]
//! handles together with every such fact, so the slot-quiescence fence, the root timeline, and the
//! in-flight checkpoint-envelope ledger survive an endpoint rebuild by construction instead of by a
//! caller remembering to carry them.
//!
//! # Every queue the session fronts is admission-bounded at its submission chokepoint
//!
//! The session is the only route to every backend submission, so each lane's bound is enforced
//! where the lane is entered — never trusted to the callers' discipline, which endpoint rebuilds
//! and abandoned correlations reset. Each entry below states its bound FOR THE DEFAULT
//! CONFIGURATION first; where a tighter bound exists only under a particular configuration, the
//! condition is named explicitly, because a bound that silently assumes a non-default
//! configuration is not a bound:
//!
//! - **appends** — two independent gates at one choke ([`Storage::submit_append`]):
//!   - the *session append quota*: at most [`Storage::append_quota`] in-flight appends over the
//!     medium — `2 × (IMPLIED_RING_INTERVALS × checkpoint_ops + MAX_PIPELINE)`, derived from the
//!     durable root's recorded checkpoint interval and deliberately independent of
//!     [`Wal::capacity`] ([`AppendSubmission::QuotaExhausted`] refuses the rest, retryably). This
//!     is THE default-configuration bound: it holds for the default ring-less backend
//!     (`capacity == u64::MAX`), for a bounded ring of any size, and across state-sync
//!     generations — the append ownership an install abandons still occupies the quota until the
//!     write quiesces, so accumulation over repeated sync-forward cycles is capped here;
//!   - the *slot-quiescence fence*: at most one in-flight write per physical ring slot
//!     ([`AppendSubmission::SlotFenced`]). On a bounded backend this additionally caps the ledger
//!     at the ring capacity — tighter than the quota only when `capacity` is below it. On the
//!     DEFAULT ring-less backend distinct ops never alias, so the fence bounds NOTHING there; it
//!     is a write-ordering guard, and the quota above is the only append bound.
//! - **durable roots** — the CONSTANT-depth timeline: at most one root with the backend
//!   ([`Storage::submit_root`] parks the rest in queue order), at most [`MAX_INFLIGHT_ROOTS`]
//!   entries on the whole timeline (asserted at the submission choke in every profile) —
//!   supersession forfeits a live correlation's replaced root ([`Storage::forfeit_root`]) and
//!   endpoint construction collapses every parked leftover of the dead incarnations
//!   ([`Storage::collapse_parked_roots`]), so the depth never scales with the rebuild count.
//!   Unconditional: the constant holds in every configuration;
//! - **checkpoint envelopes** — the one-outstanding fence: at most one envelope write on the
//!   medium ([`Storage::submit_checkpoint`] returns [`CheckpointSubmission::EnvelopeFenced`]
//!   otherwise). Unconditional;
//! - **block jobs** — the lane front's per-kind admission quotas (one image capture, one frontier
//!   walk, the serve cap), which cap the lane's total depth at the serve cap plus a small
//!   per-obligation constant. Unconditional: the quotas are compile-time constants.
//!
//! Each bound is a CONSTANT for a given deployment — independent of ops, views, time, and the
//! endpoint rebuild count (the append quota scales only with the configured checkpoint interval,
//! fixed at format time and fenced by recovery) — and each has a per-tick oracle in the
//! simulation (the backend asserts and the boundedness checker), so a caller change that would
//! re-open a lane trips a sweep instead of growing quietly.

use std::{
  collections::{BTreeMap, BTreeSet, VecDeque},
  vec::Vec,
};

use bytes::Bytes;

use crate::{
  JobId, OpNumber,
  block_job::{BlockJob, BlockJobDone, BlockJobKind},
  state_machine::StateMachine,
};

use super::{Header, ReadId, Superblock, SuperblockDone, VsrState, Wal, WalDone, WriteId};

mod lane;

use lane::LaneFront;

#[cfg(test)]
mod tests;

/// The session key of an in-flight write: the full `(incarnation, sequence)` pair.
///
/// The endpoint's correlation tables key by sequence alone (past its incarnation choke every id in
/// hand is its own), but the session outlives endpoints and sequences restart at 1 in each
/// incarnation — so the medium ledger must key by the full pair or a successor's write could alias
/// a predecessor's.
type SessionKey = (u64, u64);

/// The CONSTANT depth cap of the durable-root timeline, asserted at the submission choke:
/// the submitted front (at most one root is ever with the backend — possibly a dead
/// predecessor's, owed to the medium until it lands) plus the live endpoint's two awaited
/// roots (its one durable-view write and its one checkpoint root — each a single-slot
/// correlation whose re-submission forfeits the root it supersedes).
///
/// Independent of the endpoint rebuild count by construction: a rebuild collapses every parked
/// root of the dead incarnations at endpoint construction ([`Storage::collapse_parked_roots`]),
/// so dead incarnations contribute at most the submitted front. A fourth entry therefore has no
/// author — it is a caller that either leaked a correlation or grew a third one — and the
/// submission assert refuses it fail-stop rather than letting a leak grow the timeline (and this
/// ledger, each entry cloning a header-bearing state) by one root per view-change window.
const MAX_INFLIGHT_ROOTS: usize = 3;

#[cfg_attr(not(tarpaulin), inline(always))]
fn key(id: WriteId) -> SessionKey {
  (id.incarnation(), id.seq())
}

/// The verdict of a fenced append submission: either the bytes went to the backend, or an
/// un-quiesced older write holds the physical slot and the caller must park the submission until
/// the session reports that slot freed.
///
/// The fence is this return value, not a predicate consulted beforehand: there is no way to reach
/// [`Wal::submit_append`] through the session without receiving — and having to handle — the
/// verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an unhandled fence verdict drops the append silently — park it for release"]
pub(crate) enum AppendSubmission {
  /// The append was submitted; its write is now in the session ledger until it quiesces.
  Submitted,
  /// An un-quiesced older write (this endpoint's or a dead predecessor's) occupies the physical
  /// slot; nothing was submitted, and the submission's bytes come back to the caller to park
  /// until the session reports the slot freed.
  SlotFenced {
    /// The refused submission's header, returned for parking.
    header: Header,
    /// The refused submission's body, returned for parking.
    body: Bytes,
  },
  /// The session append quota is exhausted: [`Storage::append_quota`] writes are already in
  /// flight over this medium, across every endpoint incarnation and state-sync generation that
  /// ever wrote it. Nothing was submitted; the bytes come back to the caller to park until ANY
  /// in-flight append quiesces and frees quota headroom. Unlike [`Self::SlotFenced`] the refusal
  /// is not keyed to this op's slot — the blockers are arbitrary older writes — so the release
  /// trigger is aggregate headroom, not the slot's own quiescence.
  QuotaExhausted {
    /// The refused submission's header, returned for parking.
    header: Header,
    /// The refused submission's body, returned for parking.
    body: Bytes,
  },
}

/// The verdict of a fenced checkpoint-envelope submission: either the envelope went to the
/// backend, or an earlier envelope write still holds the medium and nothing was submitted.
///
/// The fence is this return value, not a predicate consulted beforehand: there is no way to reach
/// [`Superblock::submit_write_checkpoint`] through the session without receiving — and having to
/// handle — the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an unhandled EnvelopeFenced verdict drops the checkpoint silently — drop the staged \
              step and let the cadence re-force it"]
pub(crate) enum CheckpointSubmission {
  /// The envelope was submitted; its write is now in the session ledger until it completes.
  Submitted,
  /// An earlier checkpoint-envelope write — this endpoint's or an orphan a dead correlation left —
  /// is still outstanding; nothing was submitted. The caller drops its staged checkpoint and its
  /// cadence re-forces one once the outstanding write completes and leaves the ledger.
  EnvelopeFenced,
}

/// One synchronously-cancelled append reported by a [`Wal::truncate`]/[`Wal::prune`], already
/// settled in the session ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettledCancellation {
  /// The cancelled write's id — any incarnation's.
  pub(crate) id: WriteId,
  /// The op whose physical slot this cancellation freed: the slot a fence-deferred re-append may
  /// now take. Always `Some` past the settle choke — an id the ledger never saw is a backend
  /// contract violation the settle fail-stops on — but kept optional so the settle can build the
  /// record before it judges the id.
  pub(crate) freed_slot: Option<u64>,
}

/// One drained WAL completion, with the medium fact it settled.
///
/// Settlement happens inside [`Storage::poll_wal`], before the caller sees the completion at all:
/// the quiesce fact (medium-scoped, any incarnation's) and the correlation fact (endpoint-scoped,
/// judged later by the incarnation choke) travel the same channel but have different lifetimes,
/// and unbundling them here is what lets a successor endpoint learn that a dead predecessor's
/// write quiesced from a completion it must otherwise refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalPolled {
  /// The completion, to be routed through the endpoint's incarnation choke unchanged.
  pub(crate) done: WalDone,
  /// The op whose physical slot this completion quiesced ([`WalDone::Appended`] or
  /// [`WalDone::Cancelled`] of a ledgered write — any incarnation's), freeing it for a
  /// fence-deferred re-append. `None` for reads and for ids the ledger never saw.
  pub(crate) freed_slot: Option<u64>,
}

/// One drained superblock completion, with the medium fact it settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SbPolled {
  /// The completion, to be routed through the endpoint's incarnation choke unchanged.
  pub(crate) done: SuperblockDone,
  /// The root write this completion landed, with the exact state it made durable — any
  /// incarnation's. `Some` exactly when the completion retired the FRONT of the session's root
  /// queue (roots land in submission order; the single-serialized-writer contract). A successor
  /// endpoint reads an inherited landing from here — the refused foreign completion itself carries
  /// no state.
  pub(crate) landed_root: Option<(WriteId, VsrState)>,
}

/// The storage session: owns the [`Wal`] and [`Superblock`] handles together with every physical
/// write fact that outlives an endpoint — the in-flight append ledger (the slot-quiescence fence's
/// witness set), the in-flight root writes with the exact states they will make durable (the root
/// timeline), the in-flight checkpoint-envelope writes, and the block lane's front (its job queue,
/// its admission quotas, and its issue-order witness).
///
/// **One session per store, for the store's whole in-process lifetime.** Construct it once over
/// quiesced handles — freshly formatted, or freshly opened after a process start — and thread
/// `&mut Storage` through every endpoint entry point. An endpoint rebuild (`Endpoint::recover`
/// over the same session) inherits every fence and every queued block job automatically, because
/// none of them were the endpoint's to lose.
///
/// **A fresh ledger over a live store is unrepresentable.** The constructor consumes the handles;
/// while anything is in flight they cannot come back out ([`Self::into_parts`] refuses); and the
/// only route to [`Wal::submit_append`]/[`Superblock::submit_write`], or to the block lane's
/// queue, is through the recording methods here. So a second session over the same handles — the
/// construction in which a reborn ledger forgets what the store still owes — cannot be written:
/// the handles to build it with are inside the first session until the first session proves the
/// store quiet.
///
/// The block lane's front rides here for exactly that reason. Its queue and the quotas that bound
/// its depth are one object with one lifetime, so an endpoint rebuild can neither drop a queued job
/// while inheriting its weight nor start a fresh quota over a queue that never drained; and because
/// the front is reachable only through this session, "a fresh front over a live lane" is as
/// unsayable as a fresh append ledger. The lane's own half — the store, the worker, and the
/// [`BlockJobCursor`](crate::BlockJobCursor) that witnesses EXECUTION order — stays with the
/// driver's lane, which owns the store and cannot hand it back.
///
/// What no in-process type can seal: a second `W` aliasing the same OS resource (two `File`s onto
/// one path, a second process on one WAL directory). That single operational assumption — one
/// live handle pair per store — belongs to the embedder's `Wal`/`Superblock` implementation
/// (`flock` or equivalent), and it is the only one left outside the type system.
pub struct Storage<W, B, S: StateMachine> {
  wal: W,
  sb: B,
  /// EVERY in-flight physical WAL append over this medium: full id → op. Entered at submit,
  /// removed only when the write QUIESCES — its completion arrives ([`WalDone::Appended`]/
  /// [`WalDone::Cancelled`]; an append has no other ending) or a [`Wal::truncate`]/[`Wal::prune`]
  /// reports it synchronously cancelled. This is the slot-quiescence fence's witness set:
  /// [`Self::submit_append`] refuses a second in-flight write for any ring slot listed here (same
  /// op, or its ring alias `op ± k·capacity`), across every endpoint incarnation that ever wrote
  /// this medium — completion reordering can never let abandoned old bytes land OVER a replacement
  /// some endpoint already acked.
  ///
  /// Its SIZE is bounded by the session append quota ([`Self::append_quota`]), enforced at the
  /// same choke: on the default ring-less backend the fence alone bounds nothing (distinct ops
  /// never alias), and state-sync deliberately abandons append OWNERSHIP while these physical
  /// facts survive, so without the quota each append → lag → sync-forward cycle would grow this
  /// ledger — and the backend's write queue — without any time-independent bound.
  wal_writes: BTreeMap<SessionKey, u64>,
  /// The CANONICAL SLOTS the in-flight appends occupy — `op` on a ring-less backend, `op mod
  /// capacity` on a bounded one — kept in lockstep with [`Self::wal_writes`] (inserted at submit,
  /// removed at each quiesce). The fence predicate is a membership probe here, so admission costs
  /// `O(log n)` instead of scanning the whole ledger per submission. At most one in-flight write
  /// per canonical slot exists (the fence's own guarantee), so a set — not a multiset — is
  /// sufficient, and a collision on insert is a session logic error, asserted in every profile.
  wal_slots: BTreeSet<u64>,
  /// The session append quota, derived ONCE from the durable root's recorded checkpoint interval
  /// (`0` = not yet derived; [`Self::submit_append`] derives it before the first admission and
  /// [`Self::append_quota`] derives it on read). See [`Self::append_quota`] for the value and why
  /// it is capacity-independent. Stable for the session's lifetime: the geometry it derives from
  /// is pinned at format time and recovery refuses a restart under a different interval.
  append_quota: u64,
  /// EVERY in-flight durable-root write, in queue order, each with the exact [`VsrState`] it
  /// will make durable. The single-serialized-writer contract delivers their completions in this
  /// order, so the BACK entry is the root the medium is guaranteed to converge to — the effective
  /// root ([`Self::effective_root`]) — and the FRONT is the next landing. Holding the submitted
  /// states here is what makes the effective root readable off ONE timeline: a root writer that
  /// paired an in-memory scalar with a freshly-read durable half could mint a pair no checkpoint
  /// ever had whenever an inherited root landed in between, and a rebuilt endpoint that baselined
  /// on the landed root instead of the back of this queue would come up BELOW a state the medium
  /// is already guaranteed to reach.
  ///
  /// Only the FRONT is ever WITH the backend ([`Self::roots_submitted`] counts the submitted
  /// prefix — at most one entry): every later submission is PARKED, deferred in queue order until
  /// the landings ahead of it settle, so a conforming backend that is merely slow holds one root
  /// write, never a backlog. Parked or submitted, an entry is a committed point on the timeline:
  /// the effective root includes it, and quiescence ([`Self::has_inflight`],
  /// [`Self::into_parts`]) waits for it — unless it is FORFEITED: supersession removes a live
  /// correlation's replaced parked root the moment nothing awaits it ([`Self::forfeit_root`]),
  /// and endpoint construction collapses every parked leftover of the dead incarnations
  /// ([`Self::collapse_parked_roots`] — a rebuild is the one moment "no live correlation awaits
  /// any parked entry" is a structural fact rather than a caller promise). Together those keep
  /// the timeline at a CONSTANT depth — the front plus the live endpoint's two awaited roots,
  /// never a function of the rebuild count — and [`Self::submit_root`] asserts that cap
  /// ([`MAX_INFLIGHT_ROOTS`]) in every profile, so a caller that leaks a correlation is refused
  /// fail-stop instead of growing this ledger by one header-bearing state per view-change window.
  roots: VecDeque<(WriteId, VsrState)>,
  /// How many entries at the FRONT of [`Self::roots`] have been handed to
  /// [`Superblock::submit_write`] — `0` or `1`, never more: the physical root pipeline is one
  /// deep ([`Self::submit_root`]'s gate), so the backend can never accumulate a backlog of this
  /// session's roots however slowly it completes them. Always a prefix: submission order is queue
  /// order, so a parked entry can never overtake the front. Entries at/after this index are
  /// parked and are submitted by [`Self::poll_sb`] as the landings ahead of them settle.
  roots_submitted: usize,
  /// EVERY in-flight checkpoint-envelope write: full id → the checkpoint op it stages. Tracked so
  /// quiescence ([`Self::has_inflight`], [`Self::into_parts`]) covers the envelope leg of a
  /// checkpoint exactly as it covers appends and roots. CONTENT safety needs no fence — the
  /// durable root stores the envelope's content hash, so a lost same-slot race is DETECTED at the
  /// next recovery (checksum mismatch → peer fetch) rather than silently restored — but
  /// BOUNDEDNESS does: an entry here was handed to the backend at submission (envelopes are never
  /// parked), so an orphan — a `SyncRepersist` correlation a view transition dropped at its
  /// envelope step, or a dead incarnation's write — is owed to the medium and cannot be forfeited;
  /// it drains only at its completion. Admission is therefore the only available bound, and
  /// [`Self::submit_checkpoint`] enforces it: at most ONE envelope write outstanding, ever. The
  /// superblock's completion-order contract covers root writes only, so without the fence a
  /// conforming backend slow on envelope writes alone would let every view-change window orphan
  /// one more envelope — each entry retaining its full snapshot bytes — while later durable-view
  /// roots complete around them and re-open the endpoint's own staging gates.
  checkpoints: BTreeMap<SessionKey, u64>,
  /// The block lane's front: every job issued over this store and not yet completed, the quotas
  /// they occupy, and the order they must execute in.
  lane: LaneFront<S>,
}

impl<W, B, S: StateMachine> Storage<W, B, S> {
  /// Opens the session over `wal` and `sb`, taking ownership. The ONLY constructor.
  ///
  /// The handles must be QUIESCED: freshly formatted ([`format`](crate::format) confirms its
  /// genesis root synchronously), or freshly opened after a process start (a crash took the
  /// previous process's in-flight ops with it, up to the device-latency window the storage
  /// contract states). Handles that carry un-quiesced writes from a live predecessor can only come
  /// from [`Self::into_parts`], which refuses exactly that state.
  pub fn new(wal: W, sb: B) -> Self {
    Self {
      wal,
      sb,
      wal_writes: BTreeMap::new(),
      wal_slots: BTreeSet::new(),
      append_quota: 0,
      roots: VecDeque::new(),
      roots_submitted: 0,
      checkpoints: BTreeMap::new(),
      lane: LaneFront::new(),
    }
  }

  /// Hands the raw handles back — only when nothing is in flight on the store.
  ///
  /// # Errors
  /// Returns `Err(self)` unchanged while any append, root write, checkpoint-envelope write, or
  /// block job is still outstanding: releasing the handles then would let a successor session (or
  /// bare trait calls) write over slots the store still owes completions for, and would drop a
  /// queued job while the lane's cursor still expects it — the reborn-ledger shape this type exists
  /// to make unrepresentable.
  // The `Err` variant IS the session, handed back untouched so the caller keeps draining it. Boxing
  // it to shrink the variant would allocate on the one path whose whole purpose is to return the
  // caller's own value unchanged.
  #[allow(clippy::result_large_err)]
  pub fn into_parts(self) -> Result<(W, B), Self> {
    if self.has_inflight() {
      return Err(self);
    }
    Ok((self.wal, self.sb))
  }

  /// Whether the store still owes any completion: an append, a root write, a checkpoint-envelope
  /// write, or a block job issued through this session and not yet completed — whichever endpoint
  /// incarnation issued it.
  pub fn has_inflight(&self) -> bool {
    !self.wal_writes.is_empty()
      || !self.roots.is_empty()
      || !self.checkpoints.is_empty()
      || self.lane.owes_completion()
  }

  /// Takes the next block-storage job the endpoint has issued, or `None` when none is queued.
  ///
  /// The driver executes it with [`execute_block_job`](crate::execute_block_job) on its storage
  /// lane and feeds the result back through `Endpoint::on_block_done`. Jobs MUST be executed, and
  /// their completions delivered, SERIALLY IN THE ORDER THEY ARE POLLED — see the
  /// [job seam contract](crate::BlockJob) for why that order is a storage-safety obligation and how
  /// a violation is caught.
  ///
  /// Taken from the session rather than from the endpoint because the queue is the LANE's: a job
  /// issued by an endpoint that has since been replaced is still owed by the lane, still executes,
  /// and still releases the quota it claimed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_block_job(&mut self) -> Option<BlockJob<S>> {
    self.lane.poll()
  }

  /// Queue a block job the endpoint has issued, claiming the lane quota its kind occupies. The ONLY
  /// route into the lane's queue.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn enqueue_block_job(&mut self, id: JobId, kind: BlockJobKind<S>) {
    self.lane.enqueue(id, kind);
  }

  /// Settle a block-job completion against the lane's issue-order witness and quotas, before the
  /// endpoint judges correlation. See [`LaneFront::settle`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn settle_block_job(&mut self, done: &BlockJobDone<S>) {
    self.lane.settle(done);
  }

  /// Whether the lane already owes an un-consumed image capture — the capture site's admission
  /// gate.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn materialize_owed(&self) -> bool {
    self.lane.materialize_owed()
  }

  /// How many `Serve` jobs the lane owes completions for — the serve cap's admission count.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn serves_outstanding(&self) -> usize {
    self.lane.serves_outstanding()
  }

  /// Whether the lane already owes a frontier walk — the walk's admission gate.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn walk_owed(&self) -> bool {
    self.lane.walk_owed()
  }

  /// The WAL's synchronous views (`op_head`/`header`/`status`/`capacity`). Read-only: every
  /// mutation routes through the session's recording methods.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn wal(&self) -> &W {
    &self.wal
  }

  /// The superblock's synchronous view (`state`). Read-only: every mutation routes through the
  /// session's recording methods.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn sb(&self) -> &B {
    &self.sb
  }

  /// The number of durable-root writes on the in-flight timeline — the submitted front plus every
  /// parked entry behind it. Never exceeds [`MAX_INFLIGHT_ROOTS`]: the submission choke asserts
  /// the constant cap, supersession forfeits replaced roots, and endpoint construction collapses
  /// the dead incarnations' parked leftovers.
  ///
  /// Exposed for the simulation boundedness checker, which independently re-asserts the constant
  /// per tick. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn roots_in_flight(&self) -> usize {
    self.roots.len()
  }

  /// The number of in-flight physical WAL appends over this medium — every endpoint incarnation's,
  /// across every state-sync generation. Never exceeds [`Self::append_quota`]: the quota gate at
  /// [`Self::submit_append`] refuses further admissions (retryably) while this many writes are
  /// outstanding.
  ///
  /// Exposed for the simulation boundedness checker, which independently re-asserts the bound per
  /// tick. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn wal_appends_in_flight(&self) -> usize {
    self.wal_writes.len()
  }

  /// The number of in-flight checkpoint-envelope writes — `0` or `1`, never more: the envelope
  /// fence ([`Self::submit_checkpoint`]) refuses a second submission while one is outstanding.
  ///
  /// The endpoint's staging gates read it to defer a checkpoint start while an orphaned envelope
  /// drains (any entry here with no live correlation is an orphan — a live correlation and a bare
  /// staging gate cannot coexist), and the simulation boundedness checker asserts the constant
  /// bound per tick. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn checkpoints_in_flight(&self) -> usize {
    self.checkpoints.len()
  }

  /// The number of block jobs the lane owes completions for — queued or executing, every kind.
  ///
  /// Bounded by the per-kind admission quotas plus the obligations that issue the unquota'd
  /// kinds: at most one image capture and one frontier walk (the lane's own quotas), the serve
  /// cap, and a small constant of flush/sweep/reconstruct jobs (each issued under a single-slot
  /// endpoint obligation and serialized by the lane's own drain). Exposed for the simulation
  /// boundedness checker, which asserts a constant bound per tick — the oracle that the lane's
  /// depth is genuinely capped rather than argued. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn block_jobs_in_flight(&self) -> usize {
    self.lane.outstanding_len()
  }

  /// Test-only escape hatch to the raw WAL handle, for fixture knobs (staging, landing order,
  /// fault injection). Never part of the public surface: a `&mut W` in embedder hands would let an
  /// append bypass the ledger.
  #[cfg(test)]
  pub(crate) fn wal_mut(&mut self) -> &mut W {
    &mut self.wal
  }

  /// Test-only escape hatch to the raw superblock handle. See [`Self::wal_mut`].
  #[cfg(test)]
  pub(crate) fn sb_mut(&mut self) -> &mut B {
    &mut self.sb
  }
}

impl<W: Wal, B: Superblock, S: StateMachine> Storage<W, B, S> {
  /// The CANONICAL SLOT `op` occupies under this medium's capacity: `op` itself on a ring-less
  /// backend (`capacity == u64::MAX` — every op has its own location, per the trait's extent-reuse
  /// clause), `op mod capacity` on a bounded one (the trait-level placement contract). Two ops
  /// alias exactly when their canonical slots are equal, so the fence's witness set can be a slot
  /// SET probed in `O(log n)` rather than a per-submission scan of the whole ledger.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn canonical_slot(&self, op: u64) -> u64 {
    let capacity = self.wal.capacity();
    if capacity == u64::MAX {
      op
    } else {
      op % capacity
    }
  }

  /// Whether some in-flight physical write targets `op`'s ring slot — ANY incarnation's. The fence
  /// predicate: while true, a new append to `op` must be parked, because append completions may
  /// reorder and submitting now could let the old bytes land LAST, leaving the durable slot
  /// holding a value no live ack/vote named.
  pub(crate) fn slot_write_in_flight(&self, op: u64) -> bool {
    self.wal_slots.contains(&self.canonical_slot(op))
  }

  /// The session append quota: the ceiling on in-flight appends over this medium, every endpoint
  /// incarnation and state-sync generation combined — twice the proto-imposed ring
  /// (`2 × (IMPLIED_RING_INTERVALS × checkpoint_ops + MAX_PIPELINE)`), derived from the durable
  /// root's recorded checkpoint interval (an un-stamped fixture root derives the pipeline-only
  /// floor). Twice, because one implied ring bounds a single generation's legitimate in-flight
  /// window, and a sync-forward legitimately opens a fresh window while the abandoned one is
  /// still quiescing — so healthy operation, including one full-window handover, never meets the
  /// quota, while unbounded cross-generation accumulation is refused at the second full window.
  ///
  /// Deliberately INDEPENDENT of [`Wal::capacity`]: a bounded ring already gets the tighter
  /// per-slot fence bound when its capacity is below this value, and a huge finite ring must not
  /// inflate the quota into vacuity — the whole point is a bound that holds for EVERY backend,
  /// the default ring-less one included. Derived here rather than handed in by the endpoint so
  /// the bound can never depend on a caller remembering to install it.
  ///
  /// Exposed for the simulation boundedness checker, which asserts
  /// [`Self::wal_appends_in_flight`] `<=` this per tick. Not part of the stable API.
  #[doc(hidden)]
  pub fn append_quota(&self) -> u64 {
    if self.append_quota != 0 {
      return self.append_quota;
    }
    crate::endpoint::session_append_quota(self.sb.state().checkpoint_ops())
  }

  /// Fenced append submission — the ONLY route to [`Wal::submit_append`]. Either records the write
  /// in the session ledger and submits it, or refuses it with the bytes handed back for parking:
  /// [`AppendSubmission::SlotFenced`] when an un-quiesced older write (this endpoint's or a dead
  /// predecessor's) holds the physical slot, [`AppendSubmission::QuotaExhausted`] when the
  /// session append quota ([`Self::append_quota`]) is spent. The slot fence is judged FIRST: a
  /// same-slot refusal must carry the slot-keyed release trigger even under quota pressure, or
  /// its waiter would miss the exact quiescence that frees its slot.
  pub(crate) fn submit_append(
    &mut self,
    id: WriteId,
    op: OpNumber,
    header: Header,
    body: Bytes,
  ) -> AppendSubmission {
    if self.slot_write_in_flight(op.get()) {
      return AppendSubmission::SlotFenced { header, body };
    }
    if self.append_quota == 0 {
      self.append_quota = self.append_quota();
    }
    if self.wal_writes.len() as u64 >= self.append_quota {
      return AppendSubmission::QuotaExhausted { header, body };
    }
    self.wal.submit_append(id, op, header, body);
    self.wal_writes.insert(key(id), op.get());
    let vacant = self.wal_slots.insert(self.canonical_slot(op.get()));
    // One in-flight write per canonical slot is the fence's own guarantee, checked just above, so
    // an occupied slot here is a session logic error — the two witness structures diverged, and a
    // fence over an untrustworthy witness set risks exactly the stale-landing overwrite it exists
    // to prevent. Fail-stop in every profile, like the other medium-trust violations.
    assert!(
      vacant,
      "an admitted append's canonical slot was already occupied: op {op:?}"
    );
    AppendSubmission::Submitted
  }

  /// Submit a WAL read. Reads carry no physical-write fact — a dead incarnation's read completes
  /// into the choke and mutates nothing — so the session only forwards them.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn submit_wal_read(&mut self, id: ReadId, op: OpNumber) {
    self.wal.submit_read(id, op);
  }

  /// Truncate the WAL above `above`, settling every synchronously-cancelled append — any
  /// incarnation's — in the session ledger before the caller sees it. Each entry reports the slot
  /// it freed so the caller can release a fence-deferred re-append.
  pub(crate) fn truncate(&mut self, above: OpNumber) -> Vec<SettledCancellation> {
    let cancelled = self.wal.truncate(above);
    self.settle_cancellations(cancelled)
  }

  /// Prune the WAL below `below`, settling every synchronously-cancelled append — any
  /// incarnation's — exactly as [`Self::truncate`] does.
  pub(crate) fn prune(&mut self, below: OpNumber) -> Vec<SettledCancellation> {
    let cancelled = self.wal.prune(below);
    self.settle_cancellations(cancelled)
  }

  fn settle_cancellations(&mut self, cancelled: Vec<WriteId>) -> Vec<SettledCancellation> {
    cancelled
      .into_iter()
      .map(|id| {
        let freed_slot = self.retire_wal_write(id);
        // Every append over this medium was recorded at submission, whichever endpoint submitted
        // it — so an id the ledger never saw is the backend cancelling an append it was never
        // handed. Enforced in every profile: a backend inventing write facts is a medium whose
        // ledger can no longer be trusted, and consensus over an untrusted ledger risks silent
        // durable-state corruption — fail-stop is the crash-fault model's safe outcome.
        assert!(
          freed_slot.is_some(),
          "a backend cancelled an append id the session never submitted: {id:?}"
        );
        SettledCancellation { id, freed_slot }
      })
      .collect()
  }

  /// Retire one in-flight append from the ledger — completion or synchronous cancellation alike —
  /// returning the op whose canonical slot it freed (`None` for an id the ledger never saw). The
  /// ONLY removal route, so the slot set can never drift from the ledger it indexes.
  fn retire_wal_write(&mut self, id: WriteId) -> Option<u64> {
    let op = self.wal_writes.remove(&key(id))?;
    let slot = self.canonical_slot(op);
    let occupied = self.wal_slots.remove(&slot);
    // The insert at admission is unconditional for every ledgered write, so a missing slot here
    // is the same witness-set divergence the admission assert refuses — fail-stop in every
    // profile before the fence answers another admission off the diverged set.
    assert!(
      occupied,
      "a retiring append's canonical slot was not occupied: op {op}"
    );
    Some(op)
  }

  /// Drain the next WAL completion, settling its medium fact first: a completed append — ANY
  /// incarnation's — leaves the ledger here, and the freed slot rides alongside the completion so
  /// the caller can release a fence-deferred re-append even when the completion itself is refused
  /// as foreign. There is no unsettled way to see a completion.
  pub(crate) fn poll_wal(&mut self) -> Option<WalPolled> {
    let done = self.wal.poll()?;
    let freed_slot = match &done {
      WalDone::Appended(id) | WalDone::Cancelled(id) => self.retire_wal_write(*id),
      _ => None,
    };
    Some(WalPolled { done, freed_slot })
  }

  /// The EFFECTIVE root: the state of the last root on the timeline — the BACK of the root queue
  /// if any root is still in flight (submitted or parked), else the durable root. This is the state
  /// the medium is guaranteed to converge to once the queue drains (root completions arrive in
  /// submission order and the last-submitted root wins), so it is the sound recovery baseline for
  /// every field a rebuilt endpoint's own root writes stamp FROM LIVE MEMORY (`view`/`log_view`/
  /// `commit`): a successor that baselined those on the landed root instead would come up BELOW a
  /// state already owed to the medium, and its own root writes would then rewind the durable
  /// view/commit the moment an inherited root landed under it. The remaining root fields (the
  /// checkpoint pair and the configuration block) are instead COPIED FORWARD from here by every
  /// root writer, so a rebuilt endpoint holds them at the LANDED root — what a crash actually
  /// recovers — without its writes ever rewinding the timeline.
  /// Invariant during any window in which no root is submitted or forfeited: landings drain the
  /// queue's front without moving the back, and when the queue empties the durable root EQUALS the
  /// last-submitted one — so this value is stable across the drain, never a snapshot of a moment.
  /// A forfeiture ([`Self::forfeit_root`]) can retire the back itself: the value then steps back
  /// to the previous timeline point, which is sound for the same reason the drain is — the
  /// forfeited state was never handed to the medium, so the medium now converges to the new back,
  /// and every later writer re-derives from it under the same no-rewind asserts.
  ///
  /// What it deliberately does NOT claim: that this state is durable YET. Across a process death
  /// the in-flight tail dies with the process, so an endpoint recovering here must keep its
  /// DURABLE-view witness on the landed root and lift it only as the landings arrive.
  pub(crate) fn effective_root(&self) -> VsrState {
    match self.roots.back() {
      Some((_, state)) => state.clone(),
      None => self.sb.state(),
    }
  }

  /// The checkpoint pair `(checkpoint_op, checkpoint_id)` of the effective root
  /// ([`Self::effective_root`]), projected without cloning the full state. Both halves come off ONE
  /// root value on one timeline, which is the whole point: a root writer pairing an in-memory op
  /// with a freshly-read durable id can mint a pair no checkpoint ever had the moment an inherited
  /// root lands between the two reads. By the single-serialized-writer contract every in-flight
  /// root lands before anything submitted after it, so a new root carrying this pair can never
  /// rewind the durable checkpoint.
  pub(crate) fn effective_checkpoint_pair(&self) -> (OpNumber, u128) {
    match self.roots.back() {
      Some((_, state)) => (state.checkpoint_op(), state.checkpoint_id()),
      None => {
        let state = self.sb.state();
        (state.checkpoint_op(), state.checkpoint_id())
      }
    }
  }

  /// Submit a durable-root write, recording `(id, state)` on the root timeline. The ONLY route to
  /// [`Superblock::submit_write`] past genesis.
  ///
  /// While ANY root is outstanding — this incarnation's or a dead predecessor's — the submission
  /// is PARKED: recorded on the timeline but not yet handed to the backend, and submitted by the
  /// session itself, in queue order, as the landings ahead of it settle ([`Self::poll_sb`]). One
  /// physical root write in flight is the whole pipeline. The gate is what keeps a conforming but
  /// arbitrarily slow backend from accumulating a write backlog: the backend owes completions in
  /// order but owes them at no particular time, so a submitter that stacked a root per view-change
  /// window would otherwise grow the backend's queue — and this ledger, each entry cloning a
  /// header-bearing state — without bound. It also subsumes the cross-incarnation fence: with one
  /// write ever out, a successor's root can never interleave with a dead predecessor's
  /// outstanding one. An endpoint may still have a checkpoint root and a view-change root in
  /// flight together — ordered delivery and last-submitted-wins hold exactly as before, with the
  /// order now enforced by the queue rather than trusted to the backend's serialization — and a
  /// stacked root a later submission supersedes is removed by [`Self::forfeit_root`] the moment
  /// its correlation ends, which is what bounds the queue itself.
  pub(crate) fn submit_root(&mut self, id: WriteId, state: VsrState) {
    // The no-rewind invariants ENFORCED at the submission choke, in every build profile. The
    // asserts run BEFORE `Superblock::submit_write`, so a violating root is REFUSED — it never
    // reaches the medium — and the refusal is fail-stop rather than a recoverable error because
    // the caller's correlation state (`pending_sb`/`pending_checkpoint`) already assumes the
    // submission: continuing past a refusal would leave the endpoint awaiting a completion that
    // can never arrive, a silent permanent wedge — strictly worse than a crash the fault model
    // already tolerates (a panicking replica is one of the f crash faults; a LANDED rewind is a
    // cluster-wide durable-state loss no restart repairs). Every root writer baselines on the
    // effective root (recovery) and sources its checkpoint/configuration halves from it (the live
    // writers), so a rewinding root is a caller bug — unreachable by construction — and this
    // choke is the backstop that keeps it so under release schedules, where the simulator runs.
    // The view check is the durable-view-monotonicity invariant at its choke point: landings
    // arrive in queue order, so a view-monotone queue is exactly a never-regressing durable view.
    let effective = self.effective_root();
    assert!(
      state.view() >= effective.view(),
      "a durable-root write would rewind the durable view ({} below effective {})",
      state.view().get(),
      effective.view().get(),
    );
    assert!(
      state.checkpoint_op() >= effective.checkpoint_op(),
      "a durable-root write would rewind the checkpoint pointer ({} below effective {})",
      state.checkpoint_op().get(),
      effective.checkpoint_op().get(),
    );
    // The epoch/configuration half is monotone for the same reason the view is: landings arrive in
    // queue order, so a root carrying an epoch below the timeline's would republish a superseded
    // configuration underneath a swap the medium already guaranteed — the durable-membership rewind
    // a crash then recovers. Every root writer sources this half from the timeline (recovery
    // baselines the configuration on the landed root and copies an in-flight successor forward at
    // submit), so a regression here is a caller bug, not a reachable state.
    assert!(
      state.epoch() >= effective.epoch(),
      "a durable-root write would rewind the durable epoch ({} below effective {})",
      state.epoch().get(),
      effective.epoch().get(),
    );
    // At an UNCHANGED epoch the configuration is immutable: every configuration change advances
    // the epoch by construction, so a root carrying the same epoch as the timeline's but a
    // different membership would publish a divergent configuration with no epoch to order the two
    // — a lateral rewind the epoch check alone cannot see. Scoped to both roots membership-bearing
    // (a membership-less root carries no configuration to diverge from).
    assert!(
      state.epoch() != effective.epoch()
        || match (state.membership_opt(), effective.membership_opt()) {
          (Some(new), Some(cur)) => new.config_id() == cur.config_id(),
          _ => true,
        },
      "a durable-root write would replace the configuration at an unchanged epoch ({})",
      state.epoch().get(),
    );
    // Scoped to a membership-BEARING effective root: a membership-less root carries no
    // configuration history, so its `config_install_op` is a checkpoint-op alias (the decode
    // default), not an install record a later root could rewind.
    assert!(
      effective.membership_opt().is_none()
        || state.config_install_op() >= effective.config_install_op(),
      "a durable-root write would rewind the configuration install op ({} below effective {})",
      state.config_install_op().get(),
      effective.config_install_op().get(),
    );
    if self.roots.is_empty() {
      self.sb.submit_write(id, state.clone());
      self.roots_submitted = 1;
    }
    self.roots.push_back((id, state));
    // The constant depth cap, enforced AT the choke in every profile: the push above is refused
    // (fail-stop, like the no-rewind asserts — the caller's correlation state already assumes the
    // submission) rather than admitted as a fourth entry no live correlation can account for. See
    // [`MAX_INFLIGHT_ROOTS`] for why three is the whole timeline.
    assert!(
      self.roots.len() <= MAX_INFLIGHT_ROOTS,
      "the durable-root timeline exceeded its constant depth ({} > {MAX_INFLIGHT_ROOTS}) — a \
       submitter leaked a root correlation instead of forfeiting or collapsing it",
      self.roots.len(),
    );
  }

  /// Hand the next queued root to the backend once nothing is outstanding. Runs after every root
  /// settlement, so the one-deep pipeline refills the moment its slot frees — the same release
  /// discipline as a fence-deferred append.
  fn release_next_root(&mut self) {
    if self.roots_submitted == 0
      && let Some((id, state)) = self.roots.front().cloned()
    {
      self.sb.submit_write(id, state);
      self.roots_submitted = 1;
    }
  }

  /// Remove a PARKED root whose submitter has ended its correlation — superseded it with a newer
  /// submission, or abandoned it without one. A no-op for the submitted front (an outstanding
  /// write is owed to the medium and must land) and for an id the queue no longer holds (already
  /// landed).
  ///
  /// Removal is sound exactly because the entry is parked and disowned. The backend never saw the
  /// write, so nothing physical exists for quiescence to wait on; no completion can ever name it
  /// (only submitted writes complete) and its owner awaits none (this call IS the correlation's
  /// end), so nothing strands. And the landing sequence stays monotone: the queue is monotone in
  /// every no-rewind dimension by the submission asserts, and removing one entry leaves a
  /// subsequence, so no retained landing rewinds another. The back itself may be removed — the
  /// effective root then steps back to the previous entry, which is again the state the medium
  /// converges to, because the forfeited state was never handed to the medium and every later
  /// writer re-derives from the post-removal effective root under the same asserts.
  pub(crate) fn forfeit_root(&mut self, id: WriteId) {
    if let Some(at) = self
      .roots
      .iter()
      .skip(self.roots_submitted)
      .position(|(qid, _)| *qid == id)
    {
      self.roots.remove(self.roots_submitted + at);
    }
  }

  /// Remove EVERY parked root from the timeline — the endpoint-construction collapse, called by
  /// `Endpoint::recover` before it baselines on this session. The submitted front (if any) stays:
  /// it is with the backend and owed to the medium until it lands.
  ///
  /// At endpoint construction every parked entry is DISOWNED as a structural fact, not a caller
  /// promise: the session serves one endpoint at a time, the constructing one has minted nothing
  /// yet, so whoever submitted a parked root is dead and awaits nothing. Removal is then sound
  /// entry-by-entry for exactly [`Self::forfeit_root`]'s reasons — the backend never saw the
  /// write, no completion can ever name it, and the retained entries are a subsequence of a
  /// monotone queue, so no landing rewinds another. The effective root steps back to the
  /// submitted front (or the landed root), which is precisely what a crash restart would recover
  /// PLUS the still-owed front — every promise the dead incarnation made was gated on landings,
  /// never on parked writes, so nothing durable-licensed is retracted.
  ///
  /// This collapse is what makes the timeline's constant depth ([`MAX_INFLIGHT_ROOTS`])
  /// independent of the rebuild count: without it, every incarnation that died awaiting roots
  /// behind a slow front would leave its parked pair queued, and a driver rebuilding endpoints
  /// faster than the backend lands roots would grow the timeline — and the backend's eventual
  /// service queue — without bound, each entry holding a full header-bearing state.
  pub(crate) fn collapse_parked_roots(&mut self) {
    self.roots.truncate(self.roots_submitted);
  }

  /// Fenced checkpoint-envelope submission — the ONLY route to
  /// [`Superblock::submit_write_checkpoint`]. Either records the write in the envelope ledger and
  /// submits it, or reports the medium fenced by an earlier envelope write (this endpoint's or an
  /// orphan a dead correlation left) and submits nothing.
  ///
  /// One outstanding envelope is the whole lane. Unlike a root, an envelope is never parked — the
  /// write goes to the backend at submission — and unlike a parked root it cannot be forfeited
  /// once disowned: an orphaned envelope is owed to the medium until its completion drains it. So
  /// the bound has to hold at admission, and it has to hold HERE rather than in the callers'
  /// staging gates: those gates read endpoint correlation state, which a view transition or an
  /// endpoint rebuild resets while the session's ledger still carries the orphan. The refusal is
  /// deferral, not loss — the caller drops its staged step exactly as it does for a failed flush,
  /// and its cadence re-forces the checkpoint once the outstanding write completes; the blocks the
  /// dropped step named are content-addressed, so the re-forced attempt re-derives them
  /// byte-identically.
  pub(crate) fn submit_checkpoint(
    &mut self,
    id: WriteId,
    op: OpNumber,
    snapshot: Bytes,
  ) -> CheckpointSubmission {
    if !self.checkpoints.is_empty() {
      return CheckpointSubmission::EnvelopeFenced;
    }
    self.sb.submit_write_checkpoint(id, op, snapshot);
    self.checkpoints.insert(key(id), op.get());
    CheckpointSubmission::Submitted
  }

  /// Submit a checkpoint read. Reads carry no physical-write fact; the session only forwards them.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn submit_checkpoint_read(&mut self, id: ReadId) {
    self.sb.submit_read_checkpoint(id);
  }

  /// Drain the next superblock completion, settling its medium fact first: a root landing — ANY
  /// incarnation's — pops the front of the root timeline and rides alongside the completion with
  /// the exact state it made durable, so a successor endpoint can adopt an inherited landing even
  /// though the completion itself is refused as foreign. An envelope landing leaves the envelope
  /// ledger the same way. Each root settlement also refills the one-deep root pipeline: the next
  /// parked root — a later write of this incarnation's, or a successor's deferred behind a dead
  /// predecessor's — is handed to the backend the moment the landing frees the slot.
  pub(crate) fn poll_sb(&mut self) -> Option<SbPolled> {
    let done = self.sb.poll()?;
    let landed_root = match &done {
      SuperblockDone::Wrote(id) => {
        // Only a SUBMITTED root can land, so the front matches only within the submitted prefix
        // (a parked front has never been with the backend and no completion can name it).
        if self.roots_submitted > 0 && self.roots.front().is_some_and(|(fid, _)| fid == id) {
          self.roots_submitted -= 1;
          let landed = self.roots.pop_front();
          self.release_next_root();
          landed
        } else if self.checkpoints.remove(&key(*id)).is_some() {
          None
        } else if let Some(at) = self.roots.iter().position(|(fid, _)| fid == id) {
          // With one root outstanding, a completion matching the queue anywhere but the submitted
          // front can only name a PARKED root — a write the backend was never handed — or arrive
          // against a desynced submitted count; either shape is a backend violation. Settle it
          // anyway so the ledger drains — including refilling the pipeline exactly as the
          // in-order arm does, else the parked roots would strand with nothing left to release
          // them (`has_inflight` true forever, `into_parts` refused forever) — then surface the
          // violation, in every profile: out-of-order root landings break the
          // last-submitted-wins convergence every effective-root read stands on, so continuing
          // would be consensus over a medium whose durable root is no longer the one the timeline
          // promised. The settle precedes the panic so the ledger is coherent at the panic point.
          if at < self.roots_submitted {
            self.roots_submitted -= 1;
          }
          self.roots.remove(at);
          self.release_next_root();
          panic!("a root write completed out of submission order: {id:?} at queue position {at}");
        } else {
          // A completion for a write the session never submitted — the same untrusted-medium
          // fail-stop as the cancellation arm above.
          panic!("a superblock write completed that the session never submitted: {id:?}");
        }
      }
      _ => None,
    };
    Some(SbPolled { done, landed_root })
  }
}

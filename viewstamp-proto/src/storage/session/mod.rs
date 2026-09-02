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
//! - **durable roots** — the per-ROLE slots: at most one root with the backend (the front cell,
//!   owed to the medium until it lands) plus one PARKED cell per correlation role ([`RootRole`] —
//!   the endpoint's durable-view write and its checkpoint root, each a single-slot correlation).
//!   A same-role resubmission OVERWRITES its parked cell, so supersession is the submission
//!   itself rather than a release call the submitter owes, and the timeline's depth is the
//!   cardinality of those containers ([`MAX_INFLIGHT_ROOTS`]) — never a function of caller
//!   discipline or the endpoint rebuild count. Unconditional: the constant holds in every
//!   configuration;
//! - **checkpoint envelopes** — the one-outstanding fence: at most one envelope write on the
//!   medium ([`Storage::submit_checkpoint`] returns [`CheckpointSubmission::EnvelopeFenced`]
//!   otherwise). Unconditional;
//! - **block jobs** — the lane front's per-kind SLOTS: one cell per job kind but `Serve`, plus a
//!   serve set checked against the outstanding-serve cap, so the lane's depth is the cardinality
//!   of those containers ([`Storage::block_jobs_bound`]) rather than a claim about the state that
//!   issued the jobs. Unconditional, and — the reason the slots exist — independent of the
//!   endpoint rebuild count: the state an issue site would otherwise be bounded by is reset when
//!   the endpoint is rebuilt, while the cells belong to the session.
//!
//! Each bound is a CONSTANT for a given deployment — independent of ops, views, time, and the
//! endpoint rebuild count (the append quota scales only with the configured checkpoint interval,
//! fixed at format time and fenced by recovery) — and each has a per-tick oracle in the
//! simulation (the backend asserts and the boundedness checker), so a caller change that would
//! re-open a lane trips a sweep instead of growing quietly.
//!
//! The rule the lanes share, stated once so a fifth lane has something to be measured against: a
//! session container is either KEYED by a finite, session-owned key space (the root roles, the
//! block-job kinds, the one envelope lane) or COUNTED at its own choke against a session-derived
//! ceiling (the append quota, the serve cap — the two whose correlata are not enumerable).
//! Nothing mechanical stops a new unbounded container from compiling; what this module maintains
//! is that it contains zero counterexamples, so a deviation is conspicuous in review — and any
//! new container must name its key space or ceiling here and ship with a per-tick arm in the
//! simulation's boundedness checker.
//!
//! # Each choke counts its own refusals
//!
//! A depth oracle alone cannot tell a bound that HOLDS from one that is never reached: a fence
//! removed from an admission path leaves every depth arm green, because nothing was refused and
//! nothing accumulated. So each choke also counts what it turned away —
//! [`Storage::appends_slot_fenced`], [`Storage::appends_quota_refused`],
//! [`Storage::envelopes_fenced`] — and the simulation sweeps assert on those counts. Each choke's
//! expected reading differs, and the difference is the point:
//!
//! - the SLOT fence is asserted to FIRE. Within one endpoint generation it is unreachable (the
//!   endpoint refuses a duplicate append for an op it already has in flight), so what reaches it is
//!   the cross-generation case a view transition opens — the endpoint drops its own bookkeeping
//!   while the physical write stays with the device. That is precisely the case the fence exists
//!   for, so a sweep in which it never fires is a sweep testing nothing here;
//! - the APPEND QUOTA is asserted NOT to fire. Its ceiling sits above every legitimate in-flight
//!   window, so a refusal is a healthy append stalled, not a bound working;
//! - the ENVELOPE fence is asserted NOT to fire either, for a third reason: the endpoint's staging
//!   gates defer while the lane is occupied and nothing can enter it between those gates and the
//!   submission, so this fence is a structural backstop for a future caller rather than a live
//!   path. The assertion pins that claim — if a new caller ever reaches the backstop, a sweep says
//!   so instead of the refusal passing unnoticed.
//!
//! The block lane reads the same way. Its per-kind slots refuse nothing that a fail-stop does not
//! already catch, so the only outcomes worth counting are the two the sweep's slot resolves on its
//! own — [`Storage::sweeps_coalesced`] and [`Storage::sweeps_dropped`] — and both are asserted to
//! stay `0` for the envelope fence's reason: every sweep is issued from the completion of a job the
//! same lane already delivered, so the slot it finds is free.
//!
//! The counts are session-lifetime, so an endpoint rebuild cannot reset the evidence.

use std::{
  collections::{BTreeMap, BTreeSet},
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

use lane::{LaneFront, MAX_BLOCK_JOBS_IN_FLIGHT};

#[cfg(test)]
mod tests;

/// The session key of an in-flight write: the full `(incarnation, sequence)` pair.
///
/// The endpoint's correlation tables key by sequence alone (past its incarnation choke every id in
/// hand is its own), but the session outlives endpoints and sequences restart at 1 in each
/// incarnation — so the medium ledger must key by the full pair or a successor's write could alias
/// a predecessor's.
type SessionKey = (u64, u64);

/// The correlation ROLE a durable-root write answers — the parked cell it occupies while an
/// earlier root is with the backend. The two variants are not a modeling choice: the endpoint
/// holds exactly two root correlations, each a single `Option` (`pending_sb` for its durable-view
/// write, `pending_checkpoint`'s await-root step for its checkpoint root), so every submission
/// maps onto exactly one cell, and a same-role resubmission is by construction a SUPERSESSION of
/// whatever its cell holds — the one correlation of that role now awaits the new write, so
/// nothing can ever await or complete the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRole {
  /// The durable-view / epoch-swap root the endpoint's `pending_sb` correlation awaits.
  DurableView,
  /// The checkpoint root the endpoint's `pending_checkpoint` correlation awaits.
  Checkpoint,
}

/// How many parked cells the root timeline holds: one per [`RootRole`].
const PARKED_ROOT_ROLES: usize = 2;

impl RootRole {
  /// The parked cell this role occupies.
  const fn cell(self) -> usize {
    match self {
      Self::DurableView => 0,
      Self::Checkpoint => 1,
    }
  }
}

/// The CONSTANT depth of the durable-root timeline: the submitted front (at most one root is
/// ever with the backend — possibly a dead predecessor's, owed to the medium until it lands)
/// plus one parked cell per correlation role.
///
/// A cardinality of the containers, not a discipline: a fourth concurrent root has no cell to
/// occupy — a same-role resubmission overwrites its cell instead of queueing behind it — so the
/// depth cannot scale with the rebuild count, the view-change rate, or any caller's memory of
/// what it once submitted. The simulation's boundedness checker re-asserts the depth per tick
/// against its OWN independently specified constant, and separately pins
/// [`Storage::roots_bound`] equal to it — so a future representation change is caught by the
/// count arm if a schedule exceeds the contract, and by the equality arm the moment this
/// constant moves at all.
const MAX_INFLIGHT_ROOTS: usize = 1 + PARKED_ROOT_ROLES;

/// One entry on the durable-root timeline: a submitted root write, the exact state it will make
/// durable, and the session-owned stamp that orders it against every other submission.
struct RootEntry {
  /// The correlation role the write was submitted under. Carried onto the landing so the
  /// endpoint can classify a completion whose correlation no longer exists: the id alone says
  /// nothing once `pending_sb`/`pending_checkpoint` have moved on, and the state alone cannot
  /// distinguish a checkpoint root (whose frontier the endpoint may owe a catch-up for) from a
  /// view root that merely copied the same frontier forward.
  role: RootRole,
  /// The write's id — any incarnation's.
  id: WriteId,
  /// The exact [`VsrState`] the write will make durable.
  state: VsrState,
  /// The submission stamp: minted from [`Storage::next_root_stamp`] at the submission choke,
  /// strictly increasing across every submission of the session's lifetime — every endpoint
  /// incarnation's. The highest stamp on the timeline is therefore the LAST-submitted root (the
  /// effective root) and the lowest is the next to release, and both orders survive any number
  /// of endpoint rebuilds because the mint is the session's, not any endpoint's.
  stamp: u64,
}

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
  /// The root write this completion landed — its submission role, its id, and the exact state
  /// it made durable — any incarnation's. `Some` exactly when the completion retired the FRONT
  /// of the session's root timeline — the one root write with the backend. A parked cell can
  /// never produce a landing (the backend was never handed its write), so this is the ONLY
  /// channel an uncorrelated landing reaches an endpoint through — the refused foreign
  /// completion itself carries no state, and a live endpoint's correlation tables no longer
  /// name a root whose correlation ended without an abandon. The role rides along because the
  /// endpoint's landing absorb classifies by it: a checkpoint-role landing can advance the
  /// durable checkpoint past what the endpoint applied, a view-role landing never does.
  pub(crate) landed_root: Option<(RootRole, WriteId, VsrState)>,
}

/// The storage session: owns the [`Wal`] and [`Superblock`] handles together with every physical
/// write fact that outlives an endpoint — the in-flight append ledger (the slot-quiescence fence's
/// witness set), the in-flight root writes with the exact states they will make durable (the root
/// timeline), the in-flight checkpoint-envelope writes, and the block lane's front (its job queue,
/// its per-kind slots, and its issue-order witness).
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
/// The block lane's front rides here for exactly that reason. Its queue and the slots that bound
/// its depth are one object with one lifetime, so an endpoint rebuild can neither drop a queued job
/// while inheriting its weight nor free a slot over a queue that never drained; and because
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
  /// The one durable-root write WITH the backend — the front of the root timeline, owed to the
  /// medium until it lands. The physical root pipeline is one deep: a conforming backend that is
  /// merely slow holds this one write, never a backlog, and with one write ever out a
  /// successor's root can never interleave with a dead predecessor's outstanding one. Holding
  /// the submitted state here (and in every parked cell) is what makes the effective root
  /// readable off ONE timeline: a root writer that paired an in-memory scalar with a
  /// freshly-read durable half could mint a pair no checkpoint ever had whenever an inherited
  /// root landed in between, and a rebuilt endpoint that baselined on the landed root instead of
  /// the timeline's latest entry would come up BELOW a state the medium is already guaranteed to
  /// reach.
  ///
  /// Always the LOWEST stamp on the timeline ([`Self::release_next_root`] promotes the
  /// lowest-stamp parked entry, and everything parked afterwards is stamped higher), which is
  /// what keeps the effective root stable across a landing: retiring the minimum never moves the
  /// maximum unless it was the only entry — and then the durable root EQUALS the departed front.
  /// Once here an entry is irrevocable: abandonment touches only parked cells, because the
  /// backend was handed this write and its landing is a medium fact no correlation's end can
  /// retract.
  root_front: Option<RootEntry>,
  /// The PARKED durable-root writes — recorded on the timeline but not yet handed to the
  /// backend — one cell per correlation role, indexed by [`RootRole::cell`]. Parked or
  /// submitted, an entry is a committed point on the timeline: the effective root includes it
  /// and quiescence ([`Self::has_inflight`], [`Self::into_parts`]) waits for it, unless it
  /// leaves its cell without landing — a same-role resubmission OVERWRITES it (supersession is
  /// the submission itself: the endpoint's one correlation of that role now awaits the new
  /// write, so nothing can ever await or complete the old one), its submitter explicitly
  /// disowns it ([`Self::abandon_root`]), or endpoint construction collapses it with every other
  /// parked leftover of the dead incarnations ([`Self::collapse_parked_roots`]).
  ///
  /// The cells are the timeline's bound. A missed abandonment cannot grow anything: the stale
  /// entry sits in the one cell its role owns until the next same-role submission replaces it or
  /// [`Self::release_next_root`] promotes it and it lands — safe either way, because the entry
  /// passed the no-rewind asserts at its submission and everything submitted after it was
  /// asserted against it (a wasted write, still monotone). That is the failure mode the cells
  /// buy: the depth growth a leaked correlation once fed — and the every-profile fail-stop that
  /// refused it on an otherwise healthy replica — are both unrepresentable, because there is no
  /// fourth cell to grow into.
  parked_roots: [Option<RootEntry>; PARKED_ROOT_ROLES],
  /// The submission-stamp mint for [`RootEntry::stamp`]: the next stamp to hand out, advanced at
  /// every root submission. Session-owned so the order it defines spans endpoint rebuilds. A
  /// `u64` cannot wrap here in any store's lifetime — each stamp is minted for one physical
  /// superblock write.
  next_root_stamp: u64,
  /// EVERY in-flight checkpoint-envelope write: full id → the checkpoint op it stages. Tracked so
  /// quiescence ([`Self::has_inflight`], [`Self::into_parts`]) covers the envelope leg of a
  /// checkpoint exactly as it covers appends and roots. CONTENT safety needs no fence — the
  /// durable root stores the envelope's content hash, so a lost same-slot race is DETECTED at the
  /// next recovery (checksum mismatch → peer fetch) rather than silently restored — but
  /// BOUNDEDNESS does: an entry here was handed to the backend at submission (envelopes are never
  /// parked), so an orphan — a `SyncRepersist` correlation a view transition dropped at its
  /// envelope step, or a dead incarnation's write — is owed to the medium and cannot be abandoned;
  /// it drains only at its completion. Admission is therefore the only available bound, and
  /// [`Self::submit_checkpoint`] enforces it: at most ONE envelope write outstanding, ever. The
  /// superblock's completion-order contract covers root writes only, so without the fence a
  /// conforming backend slow on envelope writes alone would let every view-change window orphan
  /// one more envelope — each entry retaining its full snapshot bytes — while later durable-view
  /// roots complete around them and re-open the endpoint's own staging gates.
  checkpoints: BTreeMap<SessionKey, u64>,
  /// Observability counter: how many append submissions the SLOT-QUIESCENCE fence refused
  /// ([`AppendSubmission::SlotFenced`]), across every endpoint incarnation that wrote this medium.
  /// A refusal is a deferral, never a loss — the caller parks the bytes and the slot's quiescence
  /// re-drives them — so a growing count means the fence is genuinely engaging under contention,
  /// not that anything is stuck. Its VALUE is the fence's non-vacuity witness: a fence that never
  /// refuses is a fence whose regression no sweep would notice. Session-lifetime, like every fact
  /// here: an endpoint rebuild does not reset it, only a fresh session over the store does.
  /// Exposed via [`Self::appends_slot_fenced`].
  appends_slot_fenced: u64,
  /// Observability counter: how many append submissions the session APPEND QUOTA refused
  /// ([`AppendSubmission::QuotaExhausted`]) — the ledger already at [`Self::append_quota`] when the
  /// submission arrived. Same lifecycle and same deferral semantics as [`Self::appends_slot_fenced`],
  /// but the reading is the mirror image: the quota is sized so healthy operation (including one
  /// full-window sync handover) never meets it, so a NON-ZERO count on an unstressed run says the
  /// quota is refusing legitimate appends, while a zero count says the ceiling stayed clear of the
  /// live window. Exposed via [`Self::appends_quota_refused`].
  appends_quota_refused: u64,
  /// Observability counter: how many checkpoint-envelope submissions the one-outstanding fence
  /// refused ([`CheckpointSubmission::EnvelopeFenced`]) — a second envelope offered while one write
  /// was still with the medium, this endpoint's or an orphan a dead correlation left. Same
  /// lifecycle and deferral semantics as [`Self::appends_slot_fenced`]: the caller drops its staged
  /// step and its cadence re-forces one once the outstanding write drains. Exposed via
  /// [`Self::envelopes_fenced`].
  envelopes_fenced: u64,
  /// Observability counter: how many parked roots a same-role resubmission OVERWROTE — the
  /// supersessions the cells perform structurally, where a removal call once had to be paired
  /// with the replacing submission. A growing count is healthy view-change churn outrunning a
  /// slow backend (each overwrite is one root write the medium never had to take); the counter
  /// exists so that traffic is observable at all, because no depth arm can see an overwrite — it
  /// leaves the timeline exactly as deep as it found it. Session-lifetime, like every count
  /// here. Exposed via [`Self::roots_superseded`].
  roots_superseded: u64,
  /// Observability counter: how many parked roots their submitter explicitly abandoned —
  /// [`Self::abandon_root`] found the named root still parked and cleared its cell. Read as an
  /// EFFICIENCY witness, not a bound: a cleared cell saves the medium one wasted (safe) landing,
  /// and a missed or mismatched abandonment costs exactly that landing and nothing else.
  /// Exposed via [`Self::roots_abandoned`].
  roots_abandoned: u64,
  /// The block lane's front: every job issued over this store and not yet completed, the per-kind
  /// slots they occupy, and the order they must execute in.
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
      root_front: None,
      parked_roots: [const { None }; PARKED_ROOT_ROLES],
      next_root_stamp: 0,
      checkpoints: BTreeMap::new(),
      appends_slot_fenced: 0,
      appends_quota_refused: 0,
      envelopes_fenced: 0,
      roots_superseded: 0,
      roots_abandoned: 0,
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
      || self.roots_in_flight() != 0
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
  /// and still releases the slot it took.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_block_job(&mut self) -> Option<BlockJob<S>> {
    self.lane.poll()
  }

  /// Queue a block job the endpoint has issued, taking the lane slot its kind occupies. The ONLY
  /// route into the lane's queue. See [`LaneFront::enqueue`] for what happens to a kind whose slot
  /// is already taken — a fail-stop for every kind but the sweep, which the lane absorbs.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn enqueue_block_job(&mut self, id: JobId, kind: BlockJobKind<S>) {
    self.lane.enqueue(id, kind);
  }

  /// Settle a block-job completion against the lane's issue-order witness and slots, before the
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

  /// Whether the lane already owes a durability barrier — the staging site's admission gate.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn flush_owed(&self) -> bool {
    self.lane.flush_owed()
  }

  /// Whether the lane already owes a reconstruct — the two reconstruct sites' admission gate.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn restore_owed(&self) -> bool {
    self.lane.restore_owed()
  }

  /// How many `Serve` jobs the lane owes completions for — the serve cap's admission count.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn serves_outstanding(&self) -> usize {
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

  /// The number of durable-root writes on the in-flight timeline — the submitted front plus
  /// every parked cell. Never exceeds [`MAX_INFLIGHT_ROOTS`], and that is a cardinality of the
  /// containers this method counts (one front cell, one parked cell per role) rather than a
  /// discipline any caller maintains.
  ///
  /// Exposed for the simulation boundedness checker, which re-asserts the constant per tick —
  /// the tripwire for a future representation change, since the containers themselves cannot
  /// express a deeper timeline today. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn roots_in_flight(&self) -> usize {
    usize::from(self.root_front.is_some()) + self.parked_roots.iter().flatten().count()
  }

  /// The root timeline's CONSTANT depth cap: the front cell plus the parked cells. Exposed so
  /// the simulation boundedness checker can pin this reported value EQUAL to its own
  /// independently specified contract — the checker's count arm asserts against its constant
  /// (a bound read from the session could never fail with the count it bounds), and this
  /// accessor is what lets the equality arm flag a container change (or a stale checker
  /// contract) even on a schedule that never fills the cells. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn roots_bound(&self) -> usize {
    MAX_INFLIGHT_ROOTS
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
  /// Never exceeds [`Self::block_jobs_bound`]: every kind but `Serve` takes one of the lane's
  /// per-kind slots, and the serves are held in a set checked against the outstanding-serve cap.
  /// Exposed for the simulation boundedness checker, which asserts the bound per tick — the oracle
  /// that the depth the containers make impossible is genuinely never reached. Not part of the
  /// stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn block_jobs_in_flight(&self) -> usize {
    self.lane.outstanding_len()
  }

  /// The lane's CONSTANT depth cap: one job of each single-slot kind plus the outstanding-serve
  /// cap. Independent of ops, views, time, configuration, and the endpoint rebuild count — both
  /// terms are compile-time constants of the lane's own containers.
  ///
  /// Exposed so the simulation boundedness checker asserts [`Self::block_jobs_in_flight`] against
  /// the SAME constant the lane admits by, rather than a transcribed copy that could drift from
  /// it. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn block_jobs_bound(&self) -> usize {
    MAX_BLOCK_JOBS_IN_FLIGHT
  }

  /// How many sweeps the lane coalesced into one still queued — the newer live-root list replacing
  /// the older in place. Read as an INERTNESS witness, like [`Self::envelopes_fenced`]: every sweep
  /// is issued from the completion of a job the same lane already delivered, so the slot a sweep
  /// finds is free and the sweeps assert this stays `0`. A non-zero value means a sweep site now
  /// genuinely offers a second sweep while one is queued — the coalescing keeps that safe, but it
  /// is a re-reading of the issue sites rather than a bound doing its job. Not part of the stable
  /// API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn sweeps_coalesced(&self) -> u64 {
    self.lane.sweeps_coalesced()
  }

  /// How many sweeps the lane dropped behind one the driver had already taken — the window in
  /// which the queued payload can no longer be reached. Read exactly like
  /// [`Self::sweeps_coalesced`], and unreachable for the same reason. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn sweeps_dropped(&self) -> u64 {
    self.lane.sweeps_dropped()
  }

  /// How many append submissions the slot-quiescence fence refused (see the field). The fence's
  /// non-vacuity witness: the simulation sweeps assert it goes `> 0`, so a change that turned the
  /// fence into dead code — an admission path that stopped consulting it, or a schedule that
  /// stopped producing same-slot contention — fails loudly instead of staying green on a guard
  /// that never fires. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn appends_slot_fenced(&self) -> u64 {
    self.appends_slot_fenced
  }

  /// How many append submissions the session append quota refused (see the field). Read as the
  /// quota's ADEQUACY witness rather than a non-vacuity one: the ceiling is sized above every
  /// legitimate in-flight window, so a healthy run leaves this at `0` and the simulation sweeps
  /// assert exactly that — a quota that started refusing under an ordinary schedule would be
  /// stalling appends the medium could have taken. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn appends_quota_refused(&self) -> u64 {
    self.appends_quota_refused
  }

  /// How many checkpoint-envelope submissions the one-outstanding fence refused (see the field).
  /// The witness for what the two submit sites already claim in prose: their staging gates defer
  /// while the lane is occupied and nothing can enter it in between, so this fence is a structural
  /// backstop for a future caller, not a live path. The sweeps assert it stays `0` — a non-zero
  /// value means a caller now genuinely offers a second envelope while one is with the medium, and
  /// that is a re-evaluation of the gates rather than a bound doing its job. Not part of the stable
  /// API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn envelopes_fenced(&self) -> u64 {
    self.envelopes_fenced
  }

  /// How many parked roots a same-role resubmission overwrote (see the field). Read as churn
  /// observability, never a refusal count: an overwrite admits the new root and disowns the old
  /// one in the same write, so nothing is deferred and nothing grows — this is the only trace
  /// the supersession leaves. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn roots_superseded(&self) -> u64 {
    self.roots_superseded
  }

  /// How many parked roots their submitter explicitly abandoned (see the field): the efficiency
  /// witness for the abandonment calls, whose only stake is a saved (safe) landing. Not part of
  /// the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn roots_abandoned(&self) -> u64 {
    self.roots_abandoned
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
      self.appends_slot_fenced += 1;
      return AppendSubmission::SlotFenced { header, body };
    }
    if self.append_quota == 0 {
      self.append_quota = self.append_quota();
    }
    if self.wal_writes.len() as u64 >= self.append_quota {
      self.appends_quota_refused += 1;
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

  /// The latest-submitted root still on the timeline: the HIGHEST-STAMP entry among the front
  /// and the parked cells, `None` when the timeline is drained. Stamps are minted in submission
  /// order, so the maximum is exactly the entry a submission-ordered queue would hold at its
  /// back.
  fn latest_root(&self) -> Option<&RootEntry> {
    self
      .root_front
      .iter()
      .chain(self.parked_roots.iter().flatten())
      .max_by_key(|entry| entry.stamp)
  }

  /// The EFFECTIVE root: the state of the last root submitted to the timeline — the
  /// highest-stamp entry across the front and parked cells ([`Self::latest_root`]) if any root
  /// is still in flight, else the durable root. This is the state the medium is guaranteed to
  /// converge to once the timeline drains (roots are released to the backend in stamp order and
  /// the last-submitted root wins), so it is the sound recovery baseline for
  /// every field a rebuilt endpoint's own root writes stamp FROM LIVE MEMORY (`view`/`log_view`/
  /// `commit`): a successor that baselined those on the landed root instead would come up BELOW a
  /// state already owed to the medium, and its own root writes would then rewind the durable
  /// view/commit the moment an inherited root landed under it. The remaining root fields (the
  /// checkpoint pair and the configuration block) are instead COPIED FORWARD from here by every
  /// root writer, so a rebuilt endpoint holds them at the LANDED root — what a crash actually
  /// recovers — without its writes ever rewinding the timeline.
  ///
  /// Invariant during any window in which no root is submitted, superseded, or abandoned: the
  /// front holds the LOWEST stamp on the timeline (promotion takes the minimum, and everything
  /// parked afterwards is stamped higher), so a landing retires the minimum and never moves the
  /// highest-stamp entry this value reads — unless the front was the ONLY entry, in which case
  /// the timeline empties and the durable root EQUALS the state that just landed. Either way the
  /// value is stable across the drain, never a snapshot of a moment. A supersession or an
  /// abandonment can retire the highest-stamp entry itself: the value then steps back to the
  /// previous timeline point, which is sound for the same reason the drain is — the retired
  /// state was never handed to the medium, so the medium now converges to the new latest entry,
  /// and every later writer re-derives from it under the same no-rewind asserts.
  ///
  /// What it deliberately does NOT claim: that this state is durable YET. Across a process death
  /// the in-flight tail dies with the process, so an endpoint recovering here must keep its
  /// DURABLE-view witness on the landed root and lift it only as the landings arrive.
  pub(crate) fn effective_root(&self) -> VsrState {
    match self.latest_root() {
      Some(entry) => entry.state.clone(),
      None => self.sb.state(),
    }
  }

  /// The checkpoint pair `(checkpoint_op, checkpoint_id)` of the effective root
  /// ([`Self::effective_root`]), projected without cloning the full state. Both halves come off ONE
  /// root value on one timeline, which is the whole point: a root writer pairing an in-memory op
  /// with a freshly-read durable id can mint a pair no checkpoint ever had the moment an inherited
  /// root lands between the two reads. Roots are released in stamp order and land in release
  /// order, so every in-flight root lands before anything submitted after it, and a new root
  /// carrying this pair can never rewind the durable checkpoint.
  pub(crate) fn effective_checkpoint_pair(&self) -> (OpNumber, u128) {
    match self.latest_root() {
      Some(entry) => (entry.state.checkpoint_op(), entry.state.checkpoint_id()),
      None => {
        let state = self.sb.state();
        (state.checkpoint_op(), state.checkpoint_id())
      }
    }
  }

  /// Submit a durable-root write for `role`'s correlation, recording `(id, state)` on the root
  /// timeline. The ONLY route to [`Superblock::submit_write`] past genesis.
  ///
  /// While ANY root is outstanding — this incarnation's or a dead predecessor's — the submission
  /// is PARKED in `role`'s cell: recorded on the timeline but not yet handed to the backend, and
  /// promoted by the session itself, in stamp (= submission) order, as the landings ahead of it
  /// settle ([`Self::poll_sb`]). One
  /// physical root write in flight is the whole pipeline. The gate is what keeps a conforming but
  /// arbitrarily slow backend from accumulating a write backlog: the backend owes completions in
  /// order but owes them at no particular time, so a submitter that stacked a root per view-change
  /// window would otherwise grow the backend's queue — and this ledger, each entry cloning a
  /// header-bearing state — without bound. It also subsumes the cross-incarnation fence: with one
  /// write ever out, a successor's root can never interleave with a dead predecessor's
  /// outstanding one. An endpoint may still have a checkpoint root and a view-change root in
  /// flight together — ordered delivery and last-submitted-wins hold exactly as before, with the
  /// order enforced by the stamps rather than trusted to the backend's serialization.
  ///
  /// A submission whose role's cell is already occupied OVERWRITES it — that is the
  /// supersession: the endpoint's one correlation of this role now awaits the new write, so
  /// nothing can ever await or complete the overwritten one, and the disowned entry leaves the
  /// timeline in the same act that replaces it. There is no removal call to pair with this
  /// submission and none to miss; the cell admits one entry per role, so the timeline's depth is
  /// the containers' cardinality ([`MAX_INFLIGHT_ROOTS`]) on every schedule, including the ones
  /// where a correlation-ending path forgot to abandon its root.
  pub(crate) fn submit_root(&mut self, role: RootRole, id: WriteId, state: VsrState) {
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
    // arrive in stamp order, so a view-monotone timeline is exactly a never-regressing durable
    // view.
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
    // stamp order, so a root carrying an epoch below the timeline's would republish a superseded
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
    // The stamp mint: submission order, session-owned so it survives endpoint rebuilds. (A u64
    // cannot wrap here in any store's lifetime — each stamp is minted for one physical
    // superblock write.)
    let stamp = self.next_root_stamp;
    self.next_root_stamp += 1;
    let cell = &mut self.parked_roots[role.cell()];
    if cell.is_some() {
      self.roots_superseded += 1;
    }
    *cell = Some(RootEntry {
      role,
      id,
      state,
      stamp,
    });
    self.release_next_root();
  }

  /// Hand the LOWEST-STAMP parked root to the backend once nothing is outstanding — the
  /// promotion that keeps release order equal to submission order. Runs after every submission
  /// and after every root settlement, so the one-deep pipeline refills the moment its slot
  /// frees — the same release discipline as a fence-deferred append.
  fn release_next_root(&mut self) {
    if self.root_front.is_some() {
      return;
    }
    if let Some(cell) = self
      .parked_roots
      .iter_mut()
      .filter(|cell| cell.is_some())
      .min_by_key(|cell| cell.as_ref().map(|entry| entry.stamp))
      && let Some(entry) = cell.take()
    {
      self.sb.submit_write(entry.id, entry.state.clone());
      self.root_front = Some(entry);
    }
  }

  /// Clear `role`'s parked cell if it still holds `id` — the caller's declaration that the
  /// correlation which submitted that root has ended without a successor, so nothing will ever
  /// await or complete it. A no-op when the cell holds anything else: the submitted front never
  /// occupies a parked cell (an outstanding write is owed to the medium and must land), and an
  /// id the cell no longer holds was already superseded, collapsed, or promoted.
  ///
  /// Nothing rests on this call being made, made once, or made with the right arguments — that
  /// is its demotion from the removal discipline the parked cells replaced. A missed or
  /// mismatched abandonment leaves one stale parked entry in its role's cell, where the next
  /// same-role submission overwrites it or [`Self::release_next_root`] promotes it and it lands.
  /// That is safe, but each half of the safety lives at its own layer. THIS layer holds the
  /// timeline half: the entry passed the no-rewind asserts at its submission and every entry
  /// after it was asserted against it, so the wasted landing rewinds nothing and the cells hold
  /// the depth constant. What this layer CANNOT hold is the state the landing establishes: a
  /// disowned root still advances the medium (a checkpoint root carries a frontier the endpoint
  /// never advanced its own pointer for), and the write's role rides the landing
  /// ([`SbPolled::landed_root`]) precisely so the ENDPOINT half — the uncorrelated-landing
  /// absorb in `Endpoint::on_sb_done` — can absorb those facts and, for a checkpoint-role
  /// landing past what the endpoint applied, reconcile before participating further. What a
  /// matching call buys is efficiency — the medium is saved one wasted landing — and the id
  /// guard is what makes every mis-call degrade to that stale-entry outcome instead of clearing
  /// a cell some LIVE correlation still awaits, which would strand its await forever.
  ///
  /// Removal is sound exactly because the entry is parked and disowned. The backend never saw
  /// the write, so nothing physical exists for quiescence to wait on; no completion can ever
  /// name it (only submitted writes complete) and its owner awaits none (this call IS the
  /// correlation's end), so nothing strands. And the landing sequence stays monotone: the
  /// timeline is monotone in every no-rewind dimension by the submission asserts, and removing
  /// one entry leaves a subsequence, so no retained landing rewinds another. The highest-stamp
  /// entry itself may be cleared — the effective root then steps back to the previous timeline
  /// point ([`Self::effective_root`]), which every later writer re-derives from under the same
  /// asserts.
  pub(crate) fn abandon_root(&mut self, role: RootRole, id: WriteId) {
    let cell = &mut self.parked_roots[role.cell()];
    if cell.as_ref().is_some_and(|entry| entry.id == id) {
      *cell = None;
      self.roots_abandoned += 1;
    }
  }

  /// Remove EVERY parked root from the timeline — the endpoint-construction collapse, called by
  /// `Endpoint::recover` before it baselines on this session. The submitted front (if any) stays:
  /// it is with the backend and owed to the medium until it lands.
  ///
  /// At endpoint construction every parked entry is DISOWNED as a structural fact, not a caller
  /// promise: the session serves one endpoint at a time, the constructing one has minted nothing
  /// yet, so whoever submitted a parked root is dead and awaits nothing. Removal is then sound
  /// entry-by-entry for exactly [`Self::abandon_root`]'s reasons — the backend never saw the
  /// write, no completion can ever name it, and the retained entries are a subsequence of a
  /// monotone timeline, so no landing rewinds another. The effective root steps back to the
  /// submitted front (or the landed root), which is precisely what a crash restart would recover
  /// PLUS the still-owed front — every promise the dead incarnation made was gated on landings,
  /// never on parked writes, so nothing durable-licensed is retracted.
  ///
  /// The collapse is a BASELINE-SEMANTICS choice, not a bound: the cells hold the timeline at
  /// its constant depth with or without it (a dead incarnation's parked root occupies the same
  /// role cell a live one's would, and the successor's first same-role submission overwrites
  /// it). What the collapse decides is what the successor baselines ON and what the medium
  /// eventually HOLDS: without it, construction would baseline the effective root on — and the
  /// release would eventually land — a state only a dead endpoint ever promised to write.
  /// Collapsing keeps the successor's starting point at exactly what a crash restart would
  /// produce, plus the front the medium still owes either way.
  pub(crate) fn collapse_parked_roots(&mut self) {
    for cell in &mut self.parked_roots {
      *cell = None;
    }
  }

  /// Fenced checkpoint-envelope submission — the ONLY route to
  /// [`Superblock::submit_write_checkpoint`]. Either records the write in the envelope ledger and
  /// submits it, or reports the medium fenced by an earlier envelope write (this endpoint's or an
  /// orphan a dead correlation left) and submits nothing.
  ///
  /// One outstanding envelope is the whole lane. Unlike a root, an envelope is never parked — the
  /// write goes to the backend at submission — and unlike a parked root it cannot be abandoned
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
      self.envelopes_fenced += 1;
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
  /// incarnation's — retires the front of the root timeline and rides alongside the completion
  /// with the exact state it made durable, so a successor endpoint can adopt an inherited landing
  /// even though the completion itself is refused as foreign. An envelope landing leaves the
  /// envelope ledger the same way. Each root settlement also refills the one-deep root pipeline:
  /// the lowest-stamp parked root — a later write of this incarnation's, or a successor's
  /// deferred behind a dead predecessor's — is handed to the backend the moment the landing
  /// frees the slot.
  pub(crate) fn poll_sb(&mut self) -> Option<SbPolled> {
    let done = self.sb.poll()?;
    let landed_root = match &done {
      SuperblockDone::Wrote(id) => {
        // Only the front is ever WITH the backend, so only the front can land (a parked cell's
        // write was never handed over and no completion can legitimately name it).
        if let Some(front) = self.root_front.take_if(|entry| entry.id == *id) {
          self.release_next_root();
          Some((front.role, front.id, front.state))
        } else if self.checkpoints.remove(&key(*id)).is_some() {
          None
        } else if let Some(cell) = self
          .parked_roots
          .iter_mut()
          .find(|cell| cell.as_ref().is_some_and(|entry| entry.id == *id))
        {
          // A completion naming a PARKED root is a backend violation however it arose: the
          // backend was never handed this write. Settle it anyway so the ledger drains — clear
          // the cell and refill the pipeline, else the entry would strand with nothing left to
          // retire it (`has_inflight` true forever, `into_parts` refused forever) — then
          // surface the violation, in every profile: a root landing outside the front breaks
          // the last-submitted-wins convergence every effective-root read stands on, so
          // continuing would be consensus over a medium whose durable root is no longer the one
          // the timeline promised. The settle precedes the panic so the ledger is coherent at
          // the panic point. The release is expected to no-op — a parked cell is only ever
          // occupied behind a live front — but it stays so this settle drains the ledger even
          // if that occupancy fact is ever broken by a second bug.
          *cell = None;
          self.release_next_root();
          panic!("a parked root write completed that was never handed to the backend: {id:?}");
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

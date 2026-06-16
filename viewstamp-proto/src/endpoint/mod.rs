use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;

use crate::{
  ClientId, Commit, Config, DoViewChange, Epoch, Event, Header, Instant, MemberId, Membership,
  Message, OpNumber, Outgoing, Peer, Prepare, PrepareOk, Prng, Recipient, ReplicaId, Reply,
  RequestNumber, SlotStatus, StateMachine, Status, Superblock, SuperblockDone, View, Wal, WalDone,
};

mod checkpoint;
mod forfeit;
mod normal;
mod reconfig;
mod recovery;
mod repair;
mod state_sync;
mod view_change;

pub use reconfig::{Reconfig, ReconfigError, RestartOnly, prepare_restart};
pub use recovery::{Recovered, Retired};

/// What the endpoint does when a submitted WAL append completes. Append-before-ack: the vote/ack a
/// completion owes is always deferred to `on_wal_done`, never cast before the op is durable. A
/// peer-repair fill (see `fill_repair`) owes NO ack, but is still a DURABILITY BARRIER — its apply +
/// hole-clear + exposure wait for the append via `Pending::RepairFill`.
///
/// Not `Copy`: [`Pending::RepairFill`] carries the repaired [`LogEntry`] (a [`Body::Present`] body) so
/// the staged op is inserted into `self.log` only once its append is durable — never staged into the
/// in-memory log while non-durable (which would expose / apply it before the barrier).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
  /// A normal-path prepare append (a backup's `on_prepare`, or the primary's own `on_request`); on
  /// completion, record the ack/own-vote for this op (`send_prepare_ok` on a backup; own inflight bit
  /// + `try_commit` on the primary).
  Ack(OpNumber),
  /// A new primary's view-change ADOPTION append: an uncommitted-tail op it learned
  /// from the DVC quorum and must re-drive. On completion, set the OWN inflight vote for this op and
  /// `try_commit` — the own vote must never precede its WAL append (append-before-ack).
  AdoptVote(OpNumber),
  /// A backup's view-change ADOPTION append: an uncommitted-tail op it learned from a
  /// `StartView`/`RecoveryResponse`. On completion, send the deferred `PrepareOk` — no `PrepareOk` is
  /// sent for an adopted op before its WAL append is durable (append-before-ack).
  AdoptAck(OpNumber),
  /// A peer-repair fill append: the canonical body for a committed repair hole, staged
  /// to durability before it is applied or exposed. It owes NO ack/vote (peer repair is not a vote) —
  /// instead, on completion `on_wal_done` inserts the carried [`LogEntry`] into `self.log`, removes the
  /// repair hole, and only THEN `advance_commit`s. The body rides in the variant (not `self.log`) so a
  /// non-durable repaired op is never exposed in a `DoViewChange`/`StartView`/checkpoint nor applied by
  /// a concurrently-triggered `advance_commit` before its WAL append lands.
  RepairFill(RepairFill),
}

/// The `(op, body)` payload of a staged peer-repair fill awaiting durability,
/// extracted from the `Pending::RepairFill` variant so its two fields are named + accessor-wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RepairFill {
  op: OpNumber,
  entry: LogEntry,
}

impl RepairFill {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn new(op: OpNumber, entry: LogEntry) -> Self {
    Self { op, entry }
  }

  /// The op number of the staged repair fill.
  #[cfg_attr(not(tarpaulin), inline(always))]
  const fn op(&self) -> OpNumber {
    self.op
  }

  /// Consumes the payload, yielding the canonical log entry to insert once the append is durable.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn into_entry(self) -> LogEntry {
    self.entry
  }
}

impl Pending {
  /// The op number this pending append is for (every variant carries one).
  #[cfg_attr(not(tarpaulin), inline(always))]
  const fn op(&self) -> OpNumber {
    match self {
      Pending::Ack(op) | Pending::AdoptVote(op) | Pending::AdoptAck(op) => *op,
      Pending::RepairFill(rf) => rf.op(),
    }
  }
}

/// What the endpoint does once its pending durable-view (superblock) write completes.
/// Private + unit-only: a transition records the participation to run *after* the new view is
/// durable. Keyed by the minted `OpId` in `pending_sb`; a superseded (older-view) completion is
/// ignored. Mirrors `Pending`/`on_wal_done` (append-before-ack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingSbAction {
  SendDoViewChange,
  StartViewAsPrimary,
  AdoptedStartView,
}

/// Which of a checkpoint's two superblock writes is outstanding. Kept SEPARATE from
/// `PendingSbAction` (durable-view writes) and matched by its own minted `OpId`, so a durable-view
/// write completion and a checkpoint write completion never alias on the single `OpId`-match
/// dispatch (`on_sb_done`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointStep {
  /// The snapshot write is in flight; on its completion, write the new `VsrState` root.
  AwaitSnapshot(crate::OpId),
  /// The `VsrState` root write is in flight; on its completion, the checkpoint is durable.
  AwaitRoot(crate::OpId),
}

/// Why an in-flight checkpoint root is being written — the typed completion discriminator the
/// `on_sb_done` root-completion arm `match`es on to route the now-durable checkpoint. Carried INSIDE
/// the `PendingCheckpoint` completion token so the routing is a `match` over a
/// sum, NOT a bool beside the struct: there is no ambient `sync` flag left to confuse with
/// `self.sync.is_some()` (the footgun that bit once — a sync can be merely SOLICITED, with no staged
/// install, while an ORDINARY checkpoint completes; routing on `self.sync` would then misroute that
/// ordinary completion to the install branch, never advancing `checkpoint_op` and clearing the
/// solicited sync → a state-sync livelock). Kept SEPARATE from the durable-VIEW tracker `pending_sb`:
/// this is a checkpoint-ROOT write (the view IS durable; only the checkpoint is being written, so it
/// does NOT block participation), whereas `pending_sb` is a durable-view write that DOES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointKind {
  /// An ordinary [`Endpoint::maybe_checkpoint`]: the root completion advances `checkpoint_op` + GCs,
  /// leaving any concurrently-SOLICITED sync intact (this root is not its re-persist).
  Ordinary,
  /// A STATE-SYNC re-persist staged by [`Endpoint::apply_sync`]:
  /// the root completion INSTALLS the synced state (or, on the recovery eager-install path, finds it
  /// already installed) + runs the sync completion bookkeeping.
  SyncRepersist,
}

/// Staging for an in-flight checkpoint, sequencing the two superblock writes. Holds the target op
/// (the committed+applied boundary the snapshot reflects), its content id, which step is outstanding,
/// and WHY it is being written ([`CheckpointKind`]). While `Some`, no second checkpoint and no
/// durable-view write may start (and any view-change transition drops it — see the view-change
/// exclusion in the status transitions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingCheckpoint {
  /// The op the snapshot reflects (`commit_min` at trigger time): the new `checkpoint_op` once durable.
  target_op: OpNumber,
  /// The FNV-1a-128 content id of the snapshot envelope (stored in the durable `VsrState` root).
  checkpoint_id: u128,
  /// Which superblock write is currently outstanding.
  step: CheckpointStep,
  /// Why this checkpoint root is being written (the typed completion discriminator). The `on_sb_done`
  /// root-completion arm `match`es on this to route the now-durable checkpoint — see [`CheckpointKind`].
  kind: CheckpointKind,
}

/// In-flight state-sync bookkeeping. `Some` while a lagging replica is awaiting (or
/// re-soliciting) a `SyncCheckpoint` for a `RequestSync` it broadcast — and continues to hold while
/// the synced checkpoint's two superblock writes are being made durable. `None` otherwise. Holds the
/// highest cluster `checkpoint_op` this replica has LEARNED it is behind (the target — a SyncCheckpoint
/// that does not advance us past it is ignored) plus the freshness nonce. Cleared only once the synced
/// checkpoint's durable root write completes (so a crash mid-persist re-solicits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncState {
  /// The cluster `checkpoint_op` we learned we are behind (from a Commit/Prepare/PrepareOk). We only
  /// adopt a SyncCheckpoint whose `checkpoint_op >= this`.
  target: OpNumber,
  /// Freshness nonce echoed in the SyncCheckpoint (a per-attempt bump of `self.nonce`).
  nonce: u64,
  /// `true` when this sync was raised by the force-sync escalation ([`Endpoint::maybe_force_sync`])
  /// rather than the ordinary `> self.op` trigger. On the forced path the synced checkpoint may sit at
  /// or BELOW our head (we hold a tail above a pruned committed hole), so `apply_sync` relaxes its
  /// release-active assert from `checkpoint_op > self.op` to the true safety invariant
  /// `checkpoint_op >= commit_min` (never rewind the applied frontier).
  forced: bool,
}

/// What a completed state-sync serve-read ships to its requester. Recorded per requester in
/// `sync_serving` at submit time; the completion ([`Endpoint::serve_sync_checkpoint`]) dispatches on
/// it after the read passes the donor integrity gates (op-match + durable-id match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeKind {
  /// Answer a `RequestSync`: ship the whole `SyncCheckpoint` when the envelope fits one frame, else
  /// announce it with a `SyncCheckpointMeta` and let the requester pull chunks.
  Offer,
  /// Answer a `RequestSyncChunk` whose pinned checkpoint matched the durable root but the donor's
  /// serve cache was cold (e.g. the donor restarted mid-transfer): re-read the snapshot, then ship
  /// the chunk at this byte offset.
  Chunk {
    /// The byte offset the requester asked for.
    offset: u64,
  },
}

/// One in-flight checkpoint serve-read — the value of `sync_serving`, keyed by REQUESTER replica
/// index. Carries the read's correlation id, the latest echoed nonce (a repeat solicitation only
/// refreshes this in place), and what the completion ships ([`ServeKind`], likewise refreshed in
/// place so the single completion answers the LATEST solicitation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncServe {
  /// The serve-read's `OpId` (matches the completion back to this entry).
  read: u64,
  /// The latest nonce the requester solicited with (echoed in the answer).
  nonce: u64,
  /// What the completion ships.
  kind: ServeKind,
}

/// The donor-side cache of the last VERIFIED checkpoint serve-read: the snapshot bytes a completed
/// `submit_read_checkpoint` returned AFTER they passed the donor integrity gate (hash equals the
/// durable root id at that op), kept so a chunked transfer's pulls are served by zero-copy slicing
/// instead of one superblock re-read + re-hash per chunk. Deliberately NOT invalidated when the
/// donor's own checkpoint advances: the cached content is a committed checkpoint — immutable
/// cluster-wide — so a mid-transfer receiver pinned to it can finish pulling the OLD checkpoint
/// while the donor moves on (the keep-serving property that closes the transfer-restart livelock on
/// the donor side). Replaced lazily by the next verified serve-read; volatile, so a crash clears it
/// (a cold-cache chunk request then re-reads via [`ServeKind::Chunk`]).
#[derive(Debug)]
struct SyncDonating {
  /// The op of the cached checkpoint (the transfer pin's first half).
  checkpoint_op: OpNumber,
  /// The content id of the cached envelope (the transfer pin's second half).
  checkpoint_id: u128,
  /// The verified envelope bytes (chunks are zero-copy slices of this).
  snapshot: Bytes,
}

/// The receiver side of ONE chunked checkpoint transfer: the pinned content identity
/// `(checkpoint_op, checkpoint_id, total_len)` a `SyncCheckpointMeta` announced, the donor the next
/// pull is addressed to, and the staged in-order prefix assembled so far. `Some` exactly while a
/// chunked pull is in progress — always under an outstanding `sync` (the invariant
/// `sync_transfer ⟹ sync`, asserted beside `pending_install ⟹ sync`): every path that clears
/// `sync` clears this with it, and an abort (overflow / hash mismatch / superseding announce /
/// forced-target raise past the pin) drops ONLY this, keeping `sync` armed so the solicit timer
/// re-announces. The pin is by CONTENT, not by donor: chunks of the pinned `(op, id)` from ANY
/// member are interchangeable (non-Byzantine id-match ⇒ content-match), so a donor crash
/// mid-transfer costs a re-announce, not the staged prefix. Memory is bounded by one `Option` of
/// exactly `total_len` bytes — the same allocation the install itself requires — where `total_len`
/// is a wire claim admitted only under [`Config::max_sync_envelope_len`](crate::Config) and a
/// fallible reservation (an honest donor derives it from a verified checkpoint read, but the
/// receiver does not trust that). Volatile: a crash clears it for free.
#[derive(Debug)]
struct SyncTransfer {
  /// The pinned checkpoint op (first half of the content pin).
  checkpoint_op: OpNumber,
  /// The pinned envelope content id (second half of the content pin); the assembled bytes must
  /// hash to it before anything reaches the install path.
  checkpoint_id: u128,
  /// The announced envelope length; `staged` grows append-only to exactly this.
  total_len: u64,
  /// The peer the next chunk pull is addressed to (re-pinned on announce/chunk — the freshest
  /// live server).
  donor: ReplicaId,
  /// The in-order assembled prefix (`staged.len()` is the next offset to pull).
  staged: std::vec::Vec<u8>,
}

/// The DEFERRED INSTALL of a verified, staged `SyncCheckpoint`.
/// [`Endpoint::apply_sync`] STAGES the durable re-persist (the two superblock writes) and records this
/// payload; the DESTRUCTIVE install — restore the SM/sessions, advance `commit_min`/`commit_max`/`op`
/// to the synced point, prune the WAL, advance `checkpoint_op` — runs ATOMICALLY in
/// [`Endpoint::install_sync`] only once the sync ROOT (step 2) is durable, so there is no window where
/// the band is pruned / the commit advanced while `checkpoint_op` is still stale. `Some` exactly across
/// the STAGE→root window; cleared on install AND on any cancellation (view change / step-down) that
/// clears `sync`. Carries the OWNED decoded snapshot content (the borrow into the wire envelope does not
/// outlive the message) so the install reconstructs the synced state without re-decoding.
#[derive(Debug)]
pub(crate) struct PendingInstall {
  /// The synced checkpoint op (== the op BOUND into the snapshot) the install advances to.
  checkpoint_op: OpNumber,
  /// The decoded client-session table to install (`self.clients`).
  sessions: BTreeMap<u128, Session>,
  /// The decoded SM snapshot tail to `restore` (an owned zero-copy slice of the wire envelope).
  sm_tail: Bytes,
  /// The forced-sync held-tail decision captured at STAGE (`checkpoint_op < self.op`): the band
  /// `(checkpoint_op .. self.op]` is PRESERVED on install rather than discarded (safety, adversarial schedule).
  /// `self.op` is frozen across the window (`on_prepare` drops while `sync.is_some()`), so this decision
  /// is identical at install time.
  held_tail: bool,
}

/// The ViewChange-only collection state — reified as `Endpoint::view_change: Option<ViewChangeCollection>`
/// so the coupling "these are meaningless outside `Status::ViewChange`" is TYPE-enforced rather than
/// prose: the field is `Some` for EXACTLY the lifetime of `Status::ViewChange` and `None`
/// in every other status, so a Normal/Recovering replica simply cannot hold (or read) garbage DVC /
/// catch-up state. The two ViewChange entries ([`Endpoint::enter_view_change`], [`Endpoint::catch_up_to_view`])
/// CONSTRUCT it (via [`ViewChangeCollection::entering`]); the four ViewChange exits — the two
/// new-primary/adopt completions plus the catch-up/idle escalations — `take()` it back to `None` as
/// status returns to Normal. The `assert_invariants` clause `view_change.is_some() == is_view_change()`
/// freezes the coupling at every handler exit.
///
/// Scope NOTE (the deliberate split): the SVC-collection fields `svc_from`/`svc_target` are
/// NOT folded in here — they are live in `Status::Normal` too (a backup that proposed a view change off
/// its idle timer, or a primary forfeiting, accumulates `svc_from` toward the quorum and re-broadcasts
/// `svc_target` while STILL Normal, only entering `ViewChange` once the SVC quorum forms — see
/// `propose_next_view`/`join_svc`/the Normal-backup `svc_message` retransmit). They span the
/// status boundary, so they stay flat; only the genuinely ViewChange-confined state is reified.
#[derive(Debug)]
struct ViewChangeCollection {
  /// Prospective primary: collected DoViewChange messages, keyed by replica index. Empty for a
  /// catching-up replica (it solicits a `StartView`, never collects DVCs).
  dvc_from: BTreeMap<ReplicaId, DoViewChange>,
  /// Prospective primary: the canonical log has been formed this view (the DVC quorum was reached and
  /// `start_view_as_new_primary` ran). Gates `on_do_view_change` against re-forming a finished view.
  dvc_quorum: bool,
  /// `true` when this replica is merely catching up to an existing newer view (the higher-view rule)
  /// rather than driving a new view change — it sends GetView, not SVC/DVC. Set by `catch_up_to_view`;
  /// the steady self-driven entry leaves it `false`.
  catching_up: bool,
}

impl ViewChangeCollection {
  /// A fresh collection for a replica ENTERING `Status::ViewChange`: no DVCs collected, no quorum yet,
  /// and `catching_up` per the entry kind (`true` for the higher-view catch-up entry, `false` for the
  /// self-driven SVC-quorum entry). Replaces the old per-field `dvc_from.clear()` / `dvc_quorum = false`
  /// / `catching_up = …` reset, now that these three live behind one Option.
  fn entering(catching_up: bool) -> Self {
    Self {
      dvc_from: BTreeMap::new(),
      dvc_quorum: false,
      catching_up,
    }
  }
}

const PREPARE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
/// The primary PIPELINE cap: the maximum number of accepted-but-uncommitted ops (`(commit_min, op]`)
/// the primary holds in flight. `on_request` STALLS a new client request that would exceed it
/// (sibling of the WAL-ring / carrier-band stalls — the client retransmits; admission releases as
/// commits advance), and the prepare retransmit re-broadcasts at most the FIRST
/// [`PREPARE_RETRANSMIT_WINDOW`] of these per tick. Without the cap the window can legally grow to
/// the carrier-band bound (~342k ops), and the 100ms retransmit would re-broadcast the WHOLE window
/// with full bodies every tick — unbounded CPU/bandwidth on a slow quorum. TigerBeetle pipelines 8
/// prepares; ours is far larger because requests are not yet batched (one client request = one op),
/// so a deep pipeline is the only way many clients keep the primary busy — 1024 bounds the
/// retransmit working set while leaving room for over a thousand concurrent clients.
const MAX_PIPELINE: u64 = 1024;
/// How many un-committed ops the primary's prepare-retransmit timer re-broadcasts per tick: the
/// FIRST `K` ops of `(commit_min, op]` (the lowest — the ones the commit is waiting on). Ops above
/// the window are not starved: commits advance `commit_min` (sliding the window up), and a backup
/// missing a HIGHER op it knows committed pulls it itself via the tail-gap solicitation
/// ([`TAIL_GAP_WINDOW`], driven on every Commit/Prepare heartbeat) — the retransmit only has to keep
/// the quorum fed at the commit frontier, not re-ship the whole pipeline every 100ms.
const PREPARE_RETRANSMIT_WINDOW: u64 = 64;
const COMMIT_HEARTBEAT: core::time::Duration = core::time::Duration::from_millis(50);
const PRIMARY_IDLE: core::time::Duration = core::time::Duration::from_millis(200);
const VC_MESSAGE_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
const VIEW_CHANGE_STATUS: core::time::Duration = core::time::Duration::from_millis(500);
/// Body-aware nack-truncation: the VIRTUAL-TIME grace a new primary gives a *repair-or-truncate
/// candidate* — a header-only `Repairing` op ABOVE `commit*` that NO canonical-quorum donor holds
/// `Present` (so its body is absent on the collected quorum). The keep-vs-truncate decision is locally
/// undecidable (a committed op whose body-holders are merely unreachable looks byte-identical to a
/// genuinely-uncommitted no-body op), so the new primary repairs the candidate AND arms this deadline:
/// if a `Present` body arrives first the op is KEPT (it was committed after all); only if the grace
/// elapses with the body still absent is the uncommitted tail truncated.
///
/// **Why VIRTUAL time, not tick/view counts**: a liveness window must gate on the
/// virtual clock, never on tick counts or view-change counts — under a churn schedule those advance at
/// wildly varying virtual rates, so a count-gated window can truncate before a reachable holder ever had
/// a virtual-time chance to answer.
///
/// **Why this length is safe** (it must be long enough that an eventually-connected `Present` holder
/// answers a `RequestPrepare` first, robust to a view-change storm): a committed op's body is WAL-durable
/// on a write-quorum, so within `f` faults ≥1 holder exists and — once reachable — answers on the
/// `REPAIR_RETRANSMIT` (100ms) cadence. `10 × VIEW_CHANGE_STATUS` (5s) spans ~10 view-change escalation
/// cycles and ~50 repair retransmits, far more than enough for a healed partition's holder to reply
/// before the deadline — so a committed op is never truncated within `f`. It also comfortably exceeds the
/// simulator's `CALM_MIN_VIRTUAL` (3s) calm-window span, so a body-faulty COMMITTED op (always carried
/// `<= commit*`, hence never a candidate) and the rare genuinely-uncommitted candidate both heal/cancel
/// inside a calm window before this fires. A genuinely body-absent uncommitted op (no holder anywhere)
/// has no one to answer, so the deadline elapses and it is truncated — restoring liveness.
const REPAIR_OR_TRUNCATE_GRACE: core::time::Duration = core::time::Duration::from_millis(5_000);
/// Forfeit: how long the checkpoint-lag forfeit condition must
/// hold CONTINUOUSLY before a stuck primary actually steps down (the anti-storm grace timer). Sits
/// above `PRIMARY_IDLE` (200ms) — so a *silent* primary is failed over first by a backup's idle VC,
/// and forfeit handles only the *alive-but-stuck* case where the primary keeps heartbeating yet
/// cannot make checkpoint progress — and below `VIEW_CHANGE_STATUS` (500ms) — so a forfeit resolves
/// before a redundant idle-driven view change escalates. A primary that catches up within the grace
/// window disarms and never forfeits (a transient lag cannot trigger it).
const FORFEIT_GRACE: core::time::Duration = core::time::Duration::from_millis(300);
/// Recovery (`Status::Recovering`): how often the recover-read timer re-submits any still
/// pending/faulty WAL-tail reads. Covers a real async driver that drops a completion, and the
/// transient-clears-on-retry case where a `Fault` only resolves on a later read.
const RECOVER_READ_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
/// Recovery: per-slot read-retry budget. A `Fault`/`Absent`/checksum-mismatch on a WAL-tail read is
/// re-submitted up to this many times (transient faults clear within the budget); once exhausted the
/// slot is classed *permanently* faulty, which drives the `Normal`-vs-`RecoveringHead` decision.
const RECOVER_READ_RETRIES: u8 = 8;
/// RecoveringHead (`Status::RecoveringHead`): how often the replica re-broadcasts its `Recovery`
/// solicitation while waiting for the canonical head. A permanently-faulty head cannot be repaired
/// from local disk, so the replica keeps soliciting a peer until a `RecoveryResponse`/`StartView`
/// re-establishes its head.
const RECOVER_HEAD_SOLICIT: core::time::Duration = core::time::Duration::from_millis(100);
/// RecoveringHead re-formation gate (G1): how many `RECOVER_HEAD_SOLICIT` windows must elapse with no
/// peer re-establishing the head before a post-reconfiguration replica MAY escalate from
/// `RecoveringHead` into a view change. This MUST comfortably exceed the round-trip latency for a LIVE
/// `Normal` quorum to answer a `Recovery` (a `RecoveryResponse`/`StartView`): the escalation exists
/// only for the all-`RecoveringHead` wedge where NO node is `Normal` to answer, so a legitimately-slow recovery
/// against a healthy cluster must be answered first and never reach this threshold (validated by the
/// axis-off byte-identity net). Several windows of slack — generous on purpose, since the escalation
/// is gated additionally on `epoch > prev_epoch` (off-axis-unsatisfiable) and a co-recovering quorum.
const RECOVER_HEAD_REFORM_ATTEMPTS: u8 = 6;
/// Peer fault-repair: how often a replica holding a permanently-faulty committed-op hole re-broadcasts
/// `RequestPrepare` for each unrepaired op, until a peer answers with the missing `Prepare`. Mirrors
/// the recover-read retransmit cadence; the commit is HELD below the hole until the op arrives.
const REPAIR_RETRANSMIT: core::time::Duration = core::time::Duration::from_millis(100);
/// State-sync (`Status::Normal`): how often a lagging replica re-broadcasts its `RequestSync`
/// solicitation while awaiting a `SyncCheckpoint` (and while the adopted checkpoint is being made
/// durable). Mirrors the other solicitation cadences; cleared once the synced checkpoint is durable.
const SYNC_SOLICIT: core::time::Duration = core::time::Duration::from_millis(100);
/// Peer fault-repair tail-gap (`Status::Normal` backup): the maximum number of `RequestPrepare`s
/// [`Endpoint::request_tail_gap`] emits per call — the size of the catch-up window it solicits above
/// its head toward `commit_max`. Bounds the work per heartbeat: `request_tail_gap` runs on every
/// `Commit`/`Prepare`, so a genuine gap is closed incrementally across heartbeats (each one advances
/// the head, sliding the window up). Without this cap a single bogus/large `commit_max` (learned from
/// one incoming `Commit`/`Prepare`) would push `commit_max - head` requests into `outgoing` in one
/// call — unbounded CPU/memory in the Sans-I/O core. A genuinely far-behind backup (the gap spans
/// many windows) catches up via state-sync, not tail-gap, so a modest window suffices; sized at a few
/// pipeline depths so steady-state catch-up never needs more than one window.
const TAIL_GAP_WINDOW: u64 = 64;
/// Recovery (`recover()`): the maximum number of WAL-tail slots ABOVE the durable committed frontier
/// `recover()` will bookkeep + submit a read for in ONE pass — the size of the uncommitted-tail window
/// it materializes above `commit_max` (the full committed band `(checkpoint_op .. commit_max]` is ALWAYS
/// read; the cap bounds only the uncommitted tail above it). Bounds the synchronous work
/// of constructing a `Recovering` replica: `recover()` inserts a dense-cache entry and submits one read
/// per tail slot, so without a cap a corrupt/buggy `Wal` reporting a huge `op_head` (e.g. `u64::MAX` from
/// bit-rot in the head slot) would force unbounded CPU / allocation / outgoing reads before the async
/// fault-handling loop ever runs. The committed frontier (`state.commit()`) cannot be inflated this way —
/// `VsrState` is checksum-validated and `commit_max` is at most the real committed frontier — so reading
/// the full committed band is always bounded by genuine, quorum-bounded progress. A real uncommitted tail
/// is the small un-checkpointed pipeline above the committed frontier (a handful to a few hundred ops), so
/// this generous power-of-two bound never clips a legitimate recovery while capping a pathological head to a
/// fixed budget. A head BEYOND the window means this replica cannot synchronously read its whole tail in
/// one pass: the slots above `commit_max + RECOVER_TAIL_WINDOW` are left unread (recovered incrementally
/// as the primary re-announces them, or — if the head slot itself is unreadable — via the
/// `RecoveringHead`/peer head-fault path), never billions of reads.
const RECOVER_TAIL_WINDOW: u64 = 8192;
/// Peer fault-repair BELOW-head window ([`Endpoint::request_repair_run`]): the maximum number of ops a
/// single `RequestPrepareRange` solicits — the size of the contiguous below-head `Repairing`/missing
/// band it requests per call. The sibling of [`TAIL_GAP_WINDOW`] for the below-head path: where
/// `request_tail_gap` windows ABOVE-head gaps, this windows the below-head committed band a deep
/// header-only adoption (a view-change carrier carrying the whole uncheckpointed log as `Repairing`
/// holes) installs — so it is repaired PIPELINED (one range request → one byte-bounded `RepairBatch`
/// serving up to a frame's worth of ops) rather than one op per round trip. The server independently
/// caps the served PREFIX by the frame byte budget ([`Endpoint::on_request_prepare_range`]), so this op
/// count is only the solicitation breadth; a genuinely deep band is closed across a few passes (each
/// answered batch fills a run and the next pass re-solicits from the new lowest hole). Sized like
/// `TAIL_GAP_WINDOW` (a few pipeline depths) — large enough that the calm-window convergence the
/// header-only carriers depend on needs only a handful of passes, small enough to bound the work per
/// `advance_commit` hole-arm call in the Sans-I/O core.
const REPAIR_WINDOW: u64 = 64;
/// Higher-view catch-up plausibility bound ([`Endpoint::catch_up_to_view`]): the maximum number of
/// views an advertised `Prepare`/`PrepareOk`/`Commit` view may sit AHEAD of the local view and still
/// drive the bare-scalar catch-up; a claim further ahead is dropped as implausible.
///
/// **Why a bound exists.** The higher-view rule adopts the CLAIMED view scalar wholesale (then
/// validates it by soliciting that view's primary via GetView), so a single buggy in-threat-model
/// peer whose view field is corrupted to `u64::MAX` would drive every receiver through
/// `catch_up_to_view(u64::MAX)` — stranding it in `ViewChange` at the top of the view space, where
/// no genuine primary exists, every real cluster message is "stale" (`< self.view`), and the
/// `view+1` escalation can only saturate. One corrupt scalar permanently ejects the replica from
/// every future quorum. Rejecting the absurd claim at ingress keeps the replica Normal in its real
/// view, where it continues to serve — degradation equivalent to ignoring a garbage message.
///
/// **Why `2^32` rejects only the absurd, never a legitimate jump.** A legitimate view advance is a
/// completed view change: an SVC/DVC quorum round in which `quorum_view_change` replicas each
/// persist the new view durably before participating. Views therefore advance at
/// message-round-trip + storage-write cadence, never per-CPU-cycle: the fastest sustained
/// escalation a replica drives is one view per `VC_MESSAGE_RETRANSMIT`/`VIEW_CHANGE_STATUS` period
/// (100–500 ms), putting `2^32` consecutive view changes at ~13–68 YEARS of view-changing with zero
/// normal operation — and even a fantastical 1 ms-per-view-change cluster would need ~50 days. No
/// deployment earns a `2^32` view gap; a corrupted scalar claims one in a single message. The
/// margin to the forgery (`u64::MAX` is ~`2^31` bounds above any reachable view) is ~9 decimal
/// orders of magnitude, so the constant needs no tuning.
///
/// **A genuinely-lagging replica still converges.** Any earnable lag is below the bound, so its
/// catch-up is untouched. The clamp gates ONLY the bare-scalar trigger sites; the validated
/// adoption vehicles — `on_start_view` / `on_recovery_response`, which require the sender to BE
/// `config.primary(m.view())` and carry the canonical log — stay unclamped and adopt any higher
/// view, and a `StartView` is broadcast to ALL backups at every view formation, so even a replica
/// that somehow sat out an above-bound stretch re-joins at the cluster's next view change rather
/// than wedging.
const MAX_VIEW_JUMP: u64 = 1 << 32;

/// In-flight recovery read-bookkeeping for a `Status::Recovering`/`RecoveringHead` replica.
///
/// `recover()` builds the dense log cache from headers only (bodies empty), submits the WAL-tail +
/// checkpoint reads, and stashes one of these. `handle_storage` then verifies each `ReadOk`'s
/// checksum, fills the body, retries `Fault`/`Absent`/checksum-mismatch, and — once every read is
/// satisfied — transitions to `Normal` (tail consistent) or `RecoveringHead` (head permanently
/// faulty). Private to `endpoint.rs`; never crosses the API boundary, so no accessors. All maps are
/// bounded by the WAL-tail length (bounded by the checkpoint-interval headroom).
#[derive(Debug, Default)]
struct RecoverState {
  /// Ops whose body read is still outstanding → remaining retry budget. Non-empty ⇒ reads in flight.
  pending: BTreeMap<u64, u8>,
  /// Maps an in-flight read's `OpId` → the op it reads, so a `Fault`/`Absent` completion (which
  /// carries only the `OpId`) is attributed to the right slot.
  reads: BTreeMap<u64, u64>,
  /// Ops that read back permanently faulty/absent (retry budget exhausted). Drives the
  /// `Normal`-vs-`RecoveringHead` decision in `recover_progress`.
  faulty: std::collections::BTreeSet<u64>,
  /// The in-flight checkpoint-read `OpId` (`Some` until the snapshot is restored), or `None` if no
  /// checkpoint exists / it is already restored.
  checkpoint: Option<u64>,
  /// Remaining retry budget for the checkpoint read (the per-op `pending` analog). A transient
  /// checkpoint-read `Fault` is re-submitted within this budget; once exhausted — the durable root
  /// names a snapshot that is PERMANENTLY unreadable or permanently inconsistent with the root (wrong
  /// op/hash/unparsable on EVERY read) — the replica cannot restore its SM from its OWN disk and
  /// escalates to a peer fetch (see `awaiting_peer_checkpoint`), never panics on storage-controlled
  /// bytes.
  checkpoint_retries: u8,
  /// `true` once the local checkpoint read EXHAUSTED its budget: the replica's own durable
  /// checkpoint snapshot is permanently unreadable/inconsistent, so it has escalated to FETCHING the
  /// checkpoint from a peer via state-sync (a forced `sync` is armed + a `RequestSync` solicited).
  /// While set, `recover_progress` will NOT complete recovery (the SM is not yet restored), and
  /// `handle_message` accepts a `SyncCheckpoint` (mirroring how `RecoveringHead` accepts `StartView`);
  /// a verified one restores the SM via `apply_sync` and completes recovery to `Normal`. Cleared on
  /// that success (alongside `recover = None`).
  awaiting_peer_checkpoint: bool,
  /// The CANONICAL operation identity of the persisted committed band `(checkpoint_op ..
  /// persisted_commit]` (op → `(client, request, body_checksum)`), seeded in `recover` from the durable
  /// `VsrState`'s `committed_headers` (TigerBeetle's `vsr_headers`). A committed op's identity is the
  /// FULL `(op, client, request, body)` tuple — NOT body bytes alone: two clients can submit identical
  /// payload bytes, so a body-only check would trust a stale superseded slot that kept the same body
  /// under a DIFFERENT `client`/`request`. When a committed-band tail read self-verifies,
  /// `on_recover_wal_done` checks its `(client, request, body_checksum)` against the entry here: ANY
  /// mismatch means the WAL slot is STALE/superseded (a stale-body hazard, OR a same-body
  /// different-identity slot whose own header is internally consistent), so the slot is DROPPED and
  /// routed to peer-repair (the fault-repair path) instead of being re-derived from the WAL. The `view` is
  /// deliberately NOT part of the identity here: `committed_band_headers()` rewrites each entry's view to
  /// the current root view, so the persisted view is not the op's original view — comparing it would
  /// spuriously mismatch every band entry. Ops NOT present here (above the persisted band, or with no
  /// recorded canonical header) are trusted from the WAL as before. Bounded by the band length
  /// (~checkpoint_ops).
  canonical: BTreeMap<u64, (ClientId, RequestNumber, u128)>,
  /// G1 of the `RecoveringHead` re-formation gate: how many `Recovery` solicitation windows have
  /// elapsed in THIS incarnation without a peer re-establishing the head (incremented, saturating,
  /// once per `recover_head_timeouts` tick). A coordinated offline all-restart can leave a voting
  /// quorum in `RecoveringHead` with no `Normal` node to answer — a permanent wedge; once this
  /// matures past `RECOVER_HEAD_REFORM_ATTEMPTS` (so a legitimately-slow recovery against a LIVE
  /// quorum has had ample time to be answered first), the escalation is allowed to fire. Dropped with
  /// `RecoverState` at `recover = None`; a fresh `recover()` resets it, so each incarnation re-counts
  /// from zero. NEVER hashed/serialized/emitted.
  reform_attempts: u8,
  /// G2 of the `RecoveringHead` re-formation gate: a PER-WINDOW voter-slot bitset (same shape as
  /// `svc_from`) of the OTHER voters seen concurrently soliciting `Recovery` while we are in
  /// `RecoveringHead`. It is a SNAPSHOT, not an OR-accumulator across windows: `recover_head_timeouts`
  /// reads it and then CLEARS it for the next solicitation window, so a since-recovered peer's stale
  /// bit cannot linger toward the quorum (decisive in a 3-voter cluster). Set by the `RecoveringHead`
  /// `Message::Recovery` tally arm with ZERO emission. Dropped with `RecoverState` at `recover =
  /// None`; reset by a fresh `recover()`. NEVER hashed/serialized/emitted.
  peers_recovering: u64,
}

/// The body-state of a log entry — `Present` (bytes held) or `Repairing` (header-only, body
/// peer-repaired). ONE type shared with the wire [`crate::PreparedEntry`], so a `Repairing` op
/// carried through a `DoViewChange`/`StartView` keeps its op number (never re-minted). Defined in
/// [`crate::message`]; re-used here as the in-memory `LogEntry`'s body.
pub(crate) use crate::message::Body;

/// One entry in the in-memory log (persistence arrives in a later milestone). Its [`Body`] is either
/// `Present` (the bytes) or `Repairing` (only the durable `body_checksum`, awaiting peer-repair).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LogEntry {
  client: ClientId,
  request: RequestNumber,
  body: Body,
}

impl LogEntry {
  /// A log entry whose body bytes are held — the common case (every path that knows the body builds
  /// one of these). Wraps `body` as [`Body::Present`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn present(client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      client,
      request,
      body: Body::Present(body),
    }
  }
}

/// Primary-side tracking of an in-flight prepare awaiting a prepare_ok quorum.
#[derive(Debug, Clone)]
struct Inflight {
  /// Bitset of replica indices that have acked (the primary sets its own bit).
  oks: u64,
  committed: bool,
  /// The operation IDENTITY content address — `prepare_identity(client, request, body_checksum)` — of
  /// the operation the primary is currently driving at this op. A `PrepareOk` is counted into `oks`
  /// ONLY if its `prepare_checksum` matches this, the content address that makes the op-number-keyed
  /// commit rule sound across truncate-and-reuse: a stale vote for a reused op number — even one whose
  /// body bytes happen to match — carries a different `(client, request)`, so a different identity, and
  /// is dropped. Seeded at every inflight-creation site from the operation being driven (the minted
  /// request on `on_request`; the adopted entry on view-change adoption — for a `Repairing` entry from
  /// its stored canonical checksum, which the eventual peer-repaired `Present` body matches).
  prepare_checksum: u128,
}

/// Per-client session for at-most-once semantics.
#[derive(Debug, Clone, Default)]
struct Session {
  /// Highest request number accepted (assigned an op or committed).
  request: RequestNumber,
  /// Cached `(request_number, reply_body)` of the latest committed request.
  reply: Option<(RequestNumber, Bytes)>,
  /// The op number of this client's last APPLIED request — the deterministic last-activity stamp the
  /// session-cap eviction orders victims by ([`crate::MAX_CLIENT_SESSIONS`]). `0` means PROVISIONAL:
  /// the row was minted off the consensus path (a primary's accept-time insert, a new primary's
  /// view-change watermark backfill) and no applied op has touched it yet. Provisional rows exist
  /// only on the replica that minted them, so the eviction logic treats them as INVISIBLE — never a
  /// victim, never counted toward the cap — which is what keeps the apply-time eviction decisions
  /// identical across primary and backups despite the primary's accept-ahead rows; they become
  /// applied (and visible) the moment their client's op applies, identically everywhere.
  last_op: OpNumber,
}

/// Absolute timer deadlines, armed per role by `arm_timers`.
#[derive(Debug, Clone, Default)]
struct Timers {
  /// Normal primary: retransmit un-acked prepares.
  prepare: Option<Instant>,
  /// Normal primary: commit heartbeat.
  commit: Option<Instant>,
  /// Normal backup: no Prepare/Commit from the primary → start a view change.
  primary_idle: Option<Instant>,
  /// ViewChange: retransmit own StartViewChange.
  svc_message: Option<Instant>,
  /// ViewChange: retransmit own DoViewChange.
  dvc_message: Option<Instant>,
  /// ViewChange: escalate to the next view if the change has not completed.
  view_change_status: Option<Instant>,
  /// ViewChange (catch-up): retransmit GetView.
  get_view_message: Option<Instant>,
  /// Recovering: re-submit any still-pending/faulty WAL-tail (and checkpoint) reads. Drives the
  /// recover loop to termination under a transient fault whose completion was dropped or whose retry
  /// only clears on a later read.
  recover_retry: Option<Instant>,
  /// RecoveringHead: re-broadcast the `Recovery` solicitation. A replica whose durable head slot is
  /// permanently faulty cannot recover from its own disk; it solicits the canonical head from a peer
  /// (the primary answers with a `RecoveryResponse`) and retries on this cadence until it adopts a
  /// head (via that response or a `StartView`) and returns to Normal.
  recover_head: Option<Instant>,
  /// Normal: re-broadcast `RequestPrepare` for each op in the pending-repair set (a committed-op hole
  /// read back permanently faulty). Armed only while `repair` is non-empty; cleared when the last
  /// hole is filled. Active in BOTH primary and backup roles — either may hold a hole after recovery.
  repair_retry: Option<Instant>,
  /// Normal (state-sync): re-broadcast `RequestSync` while a sync is outstanding (awaiting a
  /// `SyncCheckpoint` or persisting the adopted one); with a chunked transfer pinned it doubles as
  /// the stop-and-wait ARQ (re-send the one outstanding chunk pull first, then re-broadcast). Armed
  /// only while `sync.is_some()`; cleared once the synced checkpoint is durable.
  sync_solicit: Option<Instant>,
  /// Normal primary: the forfeit GRACE timer. `Some(deadline)` while a `Normal` primary has
  /// observed the checkpoint-lag / unfillable-committed-hole forfeit condition but has not yet stepped
  /// down — the condition must persist until `deadline` (armed `now + FORFEIT_GRACE`) before the
  /// primary forfeits, so a transient lag cannot trigger a view change (anti-storm). Disarmed (`None`)
  /// the moment the primary catches up, when it actually forfeits, and on every view-change transition
  /// (a fresh generation re-evaluates). Only ever set on the primary path (`maybe_forfeit`); a backup
  /// never arms it. UNLIKE the role timers, `arm_timers` PRESERVES this across its `Timers::default()`
  /// reset (it is a heartbeat-path deadline a Normal primary keeps ticking while it appends new ops),
  /// so a steady client load does not keep re-zeroing the grace window.
  forfeit_armed: Option<Instant>,
  /// Normal primary: the body-aware nack-truncation GRACE timer. `Some(deadline)` while this new
  /// primary holds a *repair-or-truncate candidate* — a header-only `Repairing` op ABOVE `commit*` that
  /// no canonical-quorum donor held `Present` (its body absent on the collected DVC quorum). Armed by
  /// [`Endpoint::start_view_as_new_primary`] (`now + REPAIR_OR_TRUNCATE_GRACE`); the candidate is
  /// repaired meanwhile (`request_repair`). DISARMED the moment a `Present` body fills the last
  /// candidate (the op was committed after all — see the `RepairFill` arm of `on_wal_done`), on the
  /// deadline (the still-body-absent uncommitted tail is then truncated — see
  /// [`Endpoint::repair_or_truncate_timeouts`]), and on every view-change transition (a fresh
  /// generation re-evaluates from scratch — `reset_for_view_transition`). Only ever set on the
  /// new-primary path; a backup never arms it. Like [`Timers::forfeit_armed`], `arm_timers` PRESERVES
  /// it across its `Timers::default()` reset (it is a deadline that must survive the durable-view-write
  /// / forfeit windows the role-timer re-arm passes through), so its lifecycle is owned solely by the
  /// arm/disarm sites above, not by the role re-arm.
  repair_or_truncate: Option<Instant>,
}

/// The thirteen scheduled timers, as an enumerable kind. Used by [`Endpoint::serviceable_now`] (the
/// single source of truth for "will the CURRENT (status, substate) actually SERVICE this timer if it
/// fires?") so [`Endpoint::poll_timeout`] can filter to only-serviceable deadlines — making the
/// timer-wedge spin (a `poll_timeout`-driven driver re-returning a stale, never-serviced deadline)
/// impossible by construction. `ALL` enumerates every kind for the filter + the
/// `handle_timeout` no-orphan assert; `as_str` names it for that assert's diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerKind {
  Prepare,
  Commit,
  PrimaryIdle,
  SvcMessage,
  DvcMessage,
  ViewChangeStatus,
  GetViewMessage,
  RecoverRetry,
  RecoverHead,
  RepairRetry,
  SyncSolicit,
  /// The forfeit grace timer ([`Timers::forfeit_armed`]), serviced (via `maybe_forfeit`) on the same
  /// Normal-primary heartbeat path as `commit`/`prepare`.
  ForfeitArmed,
  /// The body-aware nack-truncation grace timer ([`Timers::repair_or_truncate`]), serviced (via
  /// [`Endpoint::repair_or_truncate_timeouts`]) on the Normal-primary heartbeat path — gated, like
  /// `commit`/`prepare`/`forfeit_armed`, on `participates_as_primary() && !pending_forfeit` (it must
  /// not truncate while the view write is in flight or the primary is stepping down).
  RepairOrTruncate,
}

impl TimerKind {
  /// Every timer kind, so `poll_timeout`'s filter and `handle_timeout`'s no-orphan assert iterate the
  /// complete set (a new timer added to [`Timers`] must be added here, to `arm`-edness, and to
  /// `serviceable_now`).
  const ALL: [TimerKind; 13] = [
    TimerKind::Prepare,
    TimerKind::Commit,
    TimerKind::PrimaryIdle,
    TimerKind::SvcMessage,
    TimerKind::DvcMessage,
    TimerKind::ViewChangeStatus,
    TimerKind::GetViewMessage,
    TimerKind::RecoverRetry,
    TimerKind::RecoverHead,
    TimerKind::RepairRetry,
    TimerKind::SyncSolicit,
    TimerKind::ForfeitArmed,
    TimerKind::RepairOrTruncate,
  ];

  /// A stable name for the no-orphan-due `debug_assert` diagnostic in `handle_timeout`.
  const fn as_str(self) -> &'static str {
    match self {
      TimerKind::Prepare => "prepare",
      TimerKind::Commit => "commit",
      TimerKind::PrimaryIdle => "primary_idle",
      TimerKind::SvcMessage => "svc_message",
      TimerKind::DvcMessage => "dvc_message",
      TimerKind::ViewChangeStatus => "view_change_status",
      TimerKind::GetViewMessage => "get_view_message",
      TimerKind::RecoverRetry => "recover_retry",
      TimerKind::RecoverHead => "recover_head",
      TimerKind::RepairRetry => "repair_retry",
      TimerKind::SyncSolicit => "sync_solicit",
      TimerKind::ForfeitArmed => "forfeit_armed",
      TimerKind::RepairOrTruncate => "repair_or_truncate",
    }
  }
}

/// The Sans-I/O Viewstamped Replication state machine for one replica.
///
/// Push inputs with `handle_*`; pull outputs with `poll_*` (drain each to `None`
/// per wake). Every state-advancing entry takes a non-decreasing `now`.
///
/// # The durable-before-effect principle (the module invariant)
///
/// THE invariant of this module — the through-line behind the durable-before-effect fixes and
/// the frontier-mutation discipline — is: **an irreversible or externally-observable effect happens ONLY
/// AFTER the durable record that justifies it has landed.** A crash must never roll back to a state the
/// cluster already acted on. It is enforced STRUCTURALLY, each member at a single chokepoint, so a new
/// call site cannot bypass it (the asserts are detection; the chokepoints are prevention):
///
/// - **Authoritative emit** ⇐ durable view. A view-advertising participation message is pushed only
///   when `self.view` is durable (no `pending_sb` write in flight): `emit` is the sole egress point and
///   asserts it (durable-view-before-participate).
/// - **State-machine restore + band prune** ⇐ durable synced root. A state-sync's destructive install
///   (SM restore, commit/op advance, WAL prune) is DEFERRED behind `pending_install` until the synced
///   checkpoint root is durable (`on_sb_done` → `install_sync`), so a view change in the window cancels
///   cleanly with no pruned-but-stale band (durable-before-install).
/// - **`checkpoint_op` advance** ⇐ durable checkpoint root. `advance_checkpoint_op` is the sole
///   non-constructor writer and is MONOTONE — it gates the irreversible `wal.prune` in `run_gc` /
///   `install_sync`, so a rewind would prune a band a durable root still claims to cover.
/// - **`commit_min` advance** ⇐ applied op. `set_commit_min` is the sole non-constructor writer and is
///   MONOTONE — the applied frontier never rewinds (an applied op is immutable).
/// - **Destructive cache/WAL drop** ⇒ committed op survives. Every site that removes/truncates/prunes a
///   log or WAL entry asserts via `assert_committed_survives` that the dropped op is folded into a
///   checkpoint, tracked for peer-repair, or provably uncommitted — so no committed op is ever lost.
/// - **Ack/vote** ⇐ durable append (append-before-ack). A `PrepareOk`/own-vote is cast only once the op's
///   WAL append is durable: the `appending` set is the single gate (`send_prepare_ok` checks it), and
///   every completion's deferred ack is cast from `on_wal_done` via the `Pending` action.
///
/// The exit-time `assert_invariants` backstops the `(status × sub-state-flag)` coupling that these
/// members assume, so any future drift trips deterministically across the suite + the VOPR sweep.
#[derive(Debug)]
pub struct Endpoint<S> {
  config: Config,
  /// The active, epoch-versioned cluster configuration: who votes, who leads, the quorum sizes, and
  /// this node's slot. The single source of truth for quorum/primary/voter decisions (the static
  /// per-node parameters stay on [`Config`]). For PR1 (offline restart only) this is fixed per incarnation — it
  /// changes only across an offline restart — so no runtime-mutation machinery rides it here.
  membership: Membership,
  /// The PREVIOUS epoch — the durable backward link of the `config_id` lineage, carried so every
  /// durable-root write persists the membership as a v4 root (epoch = `membership.epoch()`,
  /// prev_epoch = this) rather than dropping it to a legacy root. Set from the recovered root (a v4
  /// root's own `prev_epoch`, or the membership epoch for a legacy bridge); at genesis it equals the
  /// membership epoch. Fixed per incarnation (the offline-restart capability changes the configuration only across a restart).
  prev_epoch: Epoch,
  status: Status,
  view: View,
  /// Head op (most recently prepared locally).
  op: OpNumber,
  /// Highest op durably applied to the state machine (applied frontier).
  commit_min: OpNumber,
  /// Highest op known committed cluster-wide (may exceed locally-held + applied ops).
  ///
  /// A re-learnable HINT, not a monotone invariant: re-learned via `advance_commit`'s `max` on the
  /// next Commit/Prepare, and a forced state-sync (`maybe_force_sync`) resets it to the synced
  /// `checkpoint_op`. Do NOT add a monotonicity assert on it — a forced sync may regress it.
  commit_max: OpNumber,
  /// Latest view in which this replica changed its head log.
  /// Invariants: `log_view <= view`; `log_view == view` when status==Normal.
  log_view: View,
  /// SVC collection: bitset of replicas that sent StartViewChange for `view+1` (includes our own bit
  /// once we propose). Live in `Status::Normal` TOO, not just ViewChange — a backup proposing off its
  /// idle timer (or a forfeiting primary) accumulates this toward the SVC quorum WHILE STILL Normal,
  /// only transitioning once the quorum forms — so it stays flat (NOT in `view_change`, which is
  /// `None` in Normal). See [`ViewChangeCollection`].
  svc_from: u64,
  /// SVC collection: the highest view this replica is currently collecting StartViewChanges for. Like
  /// `svc_from`, live in `Status::Normal` too (the Normal SVC-accumulation / forfeit-retransmit
  /// window), so it stays flat alongside it.
  svc_target: View,
  /// The ViewChange-only collection state (DVC collection + the catch-up discriminant), reified behind
  /// an `Option` so it is `Some` for EXACTLY the lifetime of `Status::ViewChange` and `None` otherwise
  /// (the `assert_invariants` `view_change.is_some() == is_view_change()` coupling). See
  /// [`ViewChangeCollection`] for why the SVC fields above are deliberately NOT folded in.
  view_change: Option<ViewChangeCollection>,
  /// Freshness nonce tagging this incarnation's solicitations (`GetView`/`Recovery`/`RequestSync`),
  /// drawn once from the seed-keyed prng (then bumped per fresh sync handshake). Only as fresh as
  /// the constructor `seed`: a reused seed re-mints the same nonce, letting a delayed
  /// previous-incarnation response pass the freshness checks — hence the per-incarnation-entropy
  /// contract on [`Self::new`]/[`Self::recover`]'s `seed` parameter.
  nonce: u64,
  /// In-memory log, keyed by op number.
  ///
  /// Trimmed by post-checkpoint GC ([`Self::run_gc`]) to the un-checkpointed tail
  /// `(prune_floor .. head]`; bounded by `O(checkpoint_ops + pipeline)`.
  log: BTreeMap<u64, LogEntry>,
  /// Primary pipeline: op → ack tracking.
  ///
  /// Trimmed by post-checkpoint GC ([`Self::run_gc`]) to the un-checkpointed tail
  /// `(prune_floor .. head]`; bounded by `O(checkpoint_ops + pipeline)`.
  inflight: BTreeMap<u64, Inflight>,
  /// Backup reorder buffer: future prepares awaiting contiguity.
  ///
  /// Bounded on insert: `on_prepare` buffers only an op within [`TAIL_GAP_WINDOW`] of the head
  /// (anything further is dropped — the primary's retransmit redelivers it once the head catches
  /// up), so at most one tail-gap window of frame-sized bodies is ever held. Trimmed below the
  /// prune floor by post-checkpoint GC ([`Self::run_gc`]); cleared on view transitions.
  buffer: BTreeMap<u64, Prepare>,
  /// Client session table.
  ///
  /// Bounded by [`Config::max_client_sessions`] APPLIED sessions (deterministic apply-time eviction
  /// past the cap — see [`crate::MAX_CLIENT_SESSIONS`] for the contract) plus at most a pipeline of
  /// PROVISIONAL accept-time rows (`last_op == 0`, primary-local, dropped at view transitions);
  /// intentionally NOT trimmed by GC (dropping a live session risks an at-most-once dedup miss) —
  /// captured in each checkpoint envelope instead so a recover/state-sync restores it.
  clients: BTreeMap<u128, Session>,
  sm: S,
  outgoing: VecDeque<Outgoing>,
  events: VecDeque<Event>,
  timers: Timers,
  /// Monotonic source of storage correlation ids.
  next_op_id: u64,
  /// Outstanding storage submissions awaiting completion.
  pending: BTreeMap<u64, Pending>,
  /// Op numbers with an in-flight WAL append — the single source of truth for "is op N durable yet?"
  ///. An op is INSERTED here when a votable append is submitted (`on_request`,
  /// `append_prepare`, `adopt_append`) and REMOVED in `on_wal_done` once that op's append completes.
  /// `send_prepare_ok` is the choke point: a `PrepareOk` for op N may be emitted ONLY if N is NOT in
  /// this set (it is durable). This makes append-before-ack a SINGLE enforced gate, so the violation
  /// class cannot relocate again.
  /// A repair-fill append (`fill_repair`) is deliberately NOT tracked here — it owes no ack. Cleared
  /// wholesale alongside `pending` on every view-change / state-sync reset (those abandon in-flight
  /// appends; a late completion finds no `pending` entry and is ignored, so its op must not linger).
  appending: std::collections::BTreeSet<u64>,
  /// The deferred view-participation action awaiting a superblock write. Only one view-change
  /// is in flight at a time; a newer transition supersedes by overwriting this field.
  /// `on_sb_done` runs the action only when the completed `OpId` matches the stored one.
  pending_sb: Option<(crate::OpId, PendingSbAction)>,
  /// An in-flight checkpoint, sequencing its two superblock writes. Kept separate from `pending_sb`
  /// (their `OpId`s never alias). `None` unless a checkpoint is mid-sequence; a view-change drops it.
  pending_checkpoint: Option<PendingCheckpoint>,
  /// The op number of this replica's latest durable checkpoint (0 until the first checkpoint
  /// goes durable). Carried on `Commit` and `PrepareOk` as the checkpoint-quorum signal.
  checkpoint_op: OpNumber,
  /// The durable-checkpoint-vouched floor of this replica's carried log: every op at/below it that
  /// `self.log` omits is folded into SOME durable cluster checkpoint — this replica's own
  /// (`raise_log_floor` tracks `advance_checkpoint_op`), or a canonical donor's learned when a
  /// FLOORED canonical log was adopted (`select_canonical_log`'s union floor / the
  /// `StartView`/`RecoveryResponse`-carried floor). MONOTONE (each source is), and `>= checkpoint_op`
  /// always. Three readers:
  /// - the view-change carriers advertise it (`DoViewChange`/`StartView`/`RecoveryResponse`
  ///   `checkpoint_op`), so a receiver can treat an omitted sub-floor op as checkpoint-subsumed;
  /// - the carrier SPAN gate ([`Self::band_at_capacity`]) bounds `op - log_floor`, which is what
  ///   makes the next view change's floored union fit one frame (its span is at most the head
  ///   donor's gated span);
  /// - the force-sync floor ([`Self::max_peer_checkpoint_op`]) includes it, so a sub-floor repair
  ///   hole escalates to state-sync even after a view transition cleared `peer_checkpoint`.
  ///
  /// NOT persisted: a crash in the adopt→state-sync window recovers with `log_floor =` the durable
  /// `checkpoint_op` (the adoption-learned floor is re-learned from the next carrier / Commit).
  /// Deliberately NOT cleared by `reset_for_view_transition` — it is a vouched durable fact about
  /// the cluster, not per-generation in-flight state.
  log_floor: OpNumber,
  /// Per-replica last-reported `checkpoint_op` (keyed by replica index), filled by the primary from
  /// incoming `PrepareOk` (and recorded on backups from `Commit`, harmlessly). The primary derives
  /// [`quorum_checkpoint_op`](Self::quorum_checkpoint_op) from this to gate WAL/session GC: it never
  /// frees an op a `quorum` of replicas has not yet checkpointed. Bounded by `replica_count` (<= 64);
  /// cleared on every view-change transition (a new generation re-establishes the pipeline, so old
  /// reports are stale — clearing keeps the primary conservative until fresh `PrepareOk`s arrive).
  peer_checkpoint: BTreeMap<ReplicaId, OpNumber>,
  /// CACHED [`Self::quorum_checkpoint_op`] (the quorum-th order statistic over
  /// `self.checkpoint_op` + the `peer_checkpoint` reports). The uncached computation allocates +
  /// sorts per call, and `prune_floor()` reads it on EVERY client request (the WAL-stall check), so
  /// it is recomputed only at the mutation sites — [`Self::record_peer_checkpoint`],
  /// [`Self::advance_checkpoint_op`], and the view-transition `peer_checkpoint` clear — via
  /// [`Self::recompute_quorum_checkpoint`], and read O(1) everywhere else.
  quorum_checkpoint: OpNumber,
  /// Active only while `status` is `Recovering`/`RecoveringHead`: the in-flight recovery-read
  /// bookkeeping (see [`RecoverState`]). Cleared to `None` by the `→ Normal` recovery transition
  /// (`recover_progress`); structurally `None` in every other status, since a recovering replica does
  /// not participate in consensus (the `handle_message` guard) and so cannot enter a view change
  /// while recovering.
  recover: Option<RecoverState>,
  /// Peer fault-repair: committed ops whose body read back PERMANENTLY faulty (bit-rot / torn)
  /// from this replica's own durable WAL and must be re-fetched from a peer (`RequestPrepare` →
  /// `Prepare`). An op lands here when the recover loop classes a non-head committed slot permanently
  /// faulty (it is dropped from the dense `log` cache so it cannot be applied with a wrong/empty body)
  /// or when the apply path (`commit_op`/`advance_commit`) finds a committed op's body missing. While
  /// an op is in this set the commit is HELD strictly below it (ops apply in order; a hole at op `N`
  /// stops the apply at `N-1`); the `repair_retry` timer re-solicits each op until a verified
  /// `Prepare` fills it. Bounded by the WAL-tail length (same bound as `recover`/`log`). Structurally
  /// empty once every committed op below the head is present; cleared wholesale when an adopted
  /// canonical log (StartView / new-primary selection) supplies the full committed prefix.
  repair: std::collections::BTreeSet<u64>,
  /// State-sync: `Some` while this replica is catching up a stale checkpoint via the
  /// `RequestSync` → `SyncCheckpoint` handshake — set when the trigger fires (it learned the cluster
  /// checkpointed past its WAL head), held through the durable re-persist of the adopted checkpoint,
  /// and cleared on the persist's root-write completion. While `Some`, ordinary tail-apply paths are
  /// not relied upon to catch up (the needed ops are below the cluster checkpoint and may be pruned);
  /// the `sync_solicit` timer re-broadcasts until a valid `SyncCheckpoint` is applied + made durable.
  sync: Option<SyncState>,
  /// State-sync deferred install: the staged-but-not-yet-installed
  /// synced checkpoint. `Some` exactly between `apply_sync` STAGING the durable re-persist and the sync
  /// ROOT going durable (`on_sb_done` → `install_sync`); `None` otherwise. While `Some`, the replica
  /// keeps its OLD (consistent, if stale) in-memory + durable state — the SM is NOT yet restored and
  /// `commit_min`/`op`/`checkpoint_op` are NOT advanced, so a view change in this window finds the old
  /// state intact and cleanly cancels the install (no pruned-but-stale window). The
  /// apply loop (`advance_commit`) is suppressed while this is `Some` so no op is applied over the
  /// soon-to-be-replaced SM (load-bearing for the recovery peer-fetch path, whose SM is unrestored here).
  pending_install: Option<PendingInstall>,
  /// State-sync peer side: in-flight checkpoint reads this replica issued to SERVE peers'
  /// `RequestSync`s / cold-cache `RequestSyncChunk`s, keyed by REQUESTER replica index →
  /// [`SyncServe`] (the serve-read `OpId`, the latest echoed nonce, and what the completion ships).
  /// Keying by requester makes the bound STRUCTURAL — at most one serve-read in flight per distinct
  /// requester (<= `replica_count` entries), so a buggy peer's solicit burst cannot stack N
  /// concurrent checkpoint reads each shipping a full snapshot. A repeat solicitation while that
  /// requester's serve is outstanding only REFRESHES the echoed nonce + serve kind in place (the
  /// completion then answers the LATEST solicitation), issuing no second read. When the read
  /// completes (`on_sb_done` → `serve_sync_checkpoint`, matched by the recorded `OpId`), the durable
  /// snapshot is shipped per its [`ServeKind`] — the whole `SyncCheckpoint` when it fits one frame, a
  /// `SyncCheckpointMeta` announce when it does not, or one `SyncChunk` for a cold-cache pull; a
  /// `Fault` drops the entry silently (the requester re-solicits; another peer answers). Cleared per
  /// entry on completion/fault.
  sync_serving: BTreeMap<ReplicaId, SyncServe>,
  /// The donor-side serve cache ([`SyncDonating`]): the last VERIFIED checkpoint serve-read, kept so
  /// chunk pulls slice it zero-copy instead of re-reading + re-hashing the superblock per chunk.
  /// `None` until the first verified serve-read (or after a crash — volatile); survives the donor's
  /// own checkpoint advance (committed content is immutable, so a pinned mid-transfer receiver can
  /// finish pulling the old checkpoint).
  sync_donating: Option<SyncDonating>,
  /// The receiver side of an in-progress chunked checkpoint transfer ([`SyncTransfer`]). `Some`
  /// exactly while pulling an announced over-frame checkpoint; always paired under `sync`
  /// (`sync_transfer ⟹ sync`, see `assert_invariants`) and cleared wherever `sync` is.
  sync_transfer: Option<SyncTransfer>,
  /// Test/observability counter: how many times a state-sync has fully applied on this
  /// replica — incremented when an `apply_sync`'s durable re-persist completes (the root write lands
  /// in `on_sb_done`, the synced checkpoint becomes durable, and the replica resumes as a Normal
  /// backup). Lets the state-sync sim gate assert NON-VACUITY (the laggard genuinely state-synced
  /// rather than catching up op-by-op via retransmit). Never reset; monotone across this process's
  /// lifetime (a fresh `new`/`recover` after a crash starts it back at 0, which is correct — the
  /// gate counts syncs since the laggard's restart). Exposed only via `state_syncs_applied()`.
  state_syncs_applied: u64,
  /// Test/observability counter: the subset of `state_syncs_applied` that were raised by the
  /// FORCE-sync escalation ([`Self::maybe_force_sync`]) rather than the ordinary `> self.op` trigger —
  /// incremented in the same `on_sb_done` arm as `state_syncs_applied` when the completing sync carried
  /// `forced: true`. Lets the force-sync sim gate prove the FORCED path specifically fired (not just an
  /// ordinary state-sync), since both route through `apply_sync` and would otherwise be indistinguishable
  /// via `state_syncs_applied` alone. Same lifecycle as `state_syncs_applied` (reset to 0 on `new`/`recover`).
  forced_syncs_applied: u64,
  /// Test/observability counter: how many CHUNKED checkpoint transfers this replica completed —
  /// incremented when an assembled transfer's bytes hash to the pinned `checkpoint_id` (the whole
  /// envelope arrived intact over `SyncCheckpointMeta`/`SyncChunk` and re-enters the ordinary
  /// `SyncCheckpoint` path). Lets the large-snapshot sim gate assert NON-VACUITY (the CHUNKED path
  /// genuinely carried the sync, not the single-frame fast path). Same lifecycle as the other
  /// observability counters (reset to 0 on `new`/`recover`); exposed only via
  /// `sync_chunk_transfers_completed()`.
  sync_chunk_transfers_completed: u64,
  /// Test/observability counter: how many client requests this replica DROPPED at op-assignment
  /// because minting the next op would overflow the bounded WAL ring — the physical stall-before-wrap
  /// ([`Self::on_request`]). `0` whenever the WAL is unbounded (`capacity() == u64::MAX`, the default),
  /// so it is inert for every existing gate; the bounded-WAL sim gate asserts it goes `> 0` to prove
  /// the stall genuinely engaged (rather than the ring being vacuously under-filled). Same lifecycle as
  /// the other observability counters (reset to 0 on `new`/`recover`). Exposed only via `wal_stalls()`.
  wal_stalls: u64,
  /// Test/observability counter: how many times this BACKUP fell BELOW its bounded-WAL
  /// ring window on a head-extending `Prepare` — the append was REFUSED (it would overwrite an
  /// un-pruned slot) with state-sync to the cluster checkpoint as the recovery
  /// ([`Self::maybe_sync_below_ring_window`] armed a forced sync, or one was already outstanding —
  /// typically armed moments earlier in the SAME delivery by `advance_commit`'s force-sync off the
  /// carried commit/floor). `0` whenever the WAL is unbounded (the default) or for an in-quorum backup
  /// (its checkpoint tracks the quorum, so no overflow). The bounded-WAL sim gate asserts it goes `> 0`
  /// to prove the connected below-ring-window guard genuinely engaged (vs the ordinary `> self.op`
  /// state-sync trigger alone). Same lifecycle as the other observability counters (reset to 0 on
  /// `new`/`recover`); exposed only via `below_ring_window_syncs()`.
  below_ring_window_syncs: u64,
  /// Test/observability counter: how many canonical-log selections actually FLOORED the union —
  /// [`Self::select_canonical_log`] dropped at least one canonical-donor entry at/below the vouched
  /// checkpoint floor `floor*` (the floored-union path doing real work). `0` while every selection's
  /// floor sits below all carried entries (the floor vacuously inert); the sim gate asserts it goes
  /// `> 0` across a sweep to prove the floored-union path genuinely fired. Same lifecycle as the
  /// other observability counters (reset to 0 on `new`/`recover`); exposed only via `unions_floored()`.
  unions_floored: u64,
  /// Test/observability counter: how many NON-EMPTY [`RepairBatch`](crate::RepairBatch)es this
  /// replica served answering peers' `RequestPrepareRange`s ([`Self::on_request_prepare_range`]) —
  /// the windowed bulk-repair channel genuinely shipping bodies (a solicit that falls silent or is
  /// gated off does not count). The sim gate asserts it goes `> 0` to prove the bulk-repair serve
  /// path fired (vs every repair flowing through the per-op `RequestPrepare`). Same lifecycle as the
  /// other observability counters (reset to 0 on `new`/`recover`); exposed only via
  /// `repair_batches_served()`.
  repair_batches_served: u64,
  /// Test/observability counter: how many NON-EMPTY [`PrepareBatch`](crate::PrepareBatch)es this
  /// PRIMARY sent re-broadcasting its first un-acked window ([`Self::primary_timeouts`]'s prepare
  /// retransmit) — the batched retransmit channel genuinely shipping bodies (a tick whose window is
  /// empty, or whose every windowed op is a skipped hole, does not count). The sim gate asserts it
  /// goes `> 0` to prove the retransmit path fired batched (vs every retransmit flowing as per-op
  /// `Prepare`s). Same lifecycle as the other observability counters (reset to 0 on
  /// `new`/`recover`); exposed only via `prepare_batches_sent()`.
  prepare_batches_sent: u64,
  /// Test/observability counter: how many header-only carrier slices this replica built via
  /// [`Self::log_entries`] — the single chokepoint every `DoViewChange`/`StartView`/
  /// `RecoveryResponse` emission's log payload flows through. The sim gate asserts it goes `> 0` to
  /// prove the header-only carrier path genuinely fired across a sweep. Same lifecycle as the other
  /// observability counters (reset to 0 on `new`/`recover`); exposed only via
  /// `header_only_carriers_emitted()`.
  header_only_carriers_emitted: u64,
  /// Test/observability counter: how many client sessions this replica EVICTED at apply time —
  /// inserting a newly-applied client past the [`Config::max_client_sessions`] cap deterministically
  /// removed the session with the oldest `last_op` (see [`crate::MAX_CLIENT_SESSIONS`] for the
  /// contract). Replica-deterministic by construction (eviction runs in the applied op stream), so
  /// it advances identically on every replica across the same applied prefix. Lets the client-churn
  /// sim lane assert NON-VACUITY (the cap genuinely engaged). Same lifecycle as the other
  /// observability counters (reset to 0 on `new`/`recover`); exposed only via `sessions_evicted()`.
  sessions_evicted: u64,
  /// Deferred-forfeit flag: set when [`Self::maybe_force_sync`] would have force-synced
  /// but we are the PRIMARY — a primary MUST NOT force-sync, as that resets `self.op` to the checkpoint
  /// (below its head) and lets it re-issue new client requests at REUSED op numbers in the same view,
  /// which backups re-ack from their old entries WITHOUT comparing bodies → committed-state divergence.
  /// Instead the primary steps DOWN: this flag makes the next primary tick ([`Self::primary_timeouts`])
  /// forfeit (a caught-up replica then leads and the subsumed hole is recovered via that primary's
  /// ordinary checkpoint flow). Cleared on every view-change/primacy transition (alongside
  /// `forfeit_armed`) so a stale flag never carries into a fresh generation. A backup leaves this
  /// `false` and force-syncs as before. Private; never crosses the API boundary.
  pending_forfeit: bool,
}

impl<S> Endpoint<S> {
  /// Creates a fresh endpoint in `Status::Normal`, view 0, for the genesis `membership`.
  ///
  /// The static per-node parameters come from `config`; the active cluster configuration (the
  /// quorum/primary/voter logic + this node's slot) comes from `membership`. The local member
  /// ([`Config::local`]) MUST occupy a slot in `membership` — asserted at construction (release too).
  ///
  /// **`seed` must carry fresh entropy per incarnation**: the solicitation-freshness nonce is
  /// derived deterministically from it, so a process restarted with a reused seed re-mints the same
  /// nonce and a delayed response to the previous incarnation passes the freshness checks. See
  /// [`Self::recover`] (where the hazard is concrete) for the full contract.
  pub fn new(config: Config, membership: Membership, seed: u64, sm: S) -> Self {
    // A construction PRECONDITION enforced in RELEASE too (not merely debug): a fresh endpoint's local
    // member MUST occupy a slot in its own membership. `local_slot()` — used by `replica()`, the
    // timers, the ingress path, and the coordinator pump — resolves it via `slot_of` and would
    // otherwise `expect`-panic LATER on an already-installed, running node. A local member absent from
    // its GENESIS membership is a caller misconfiguration (a field-validated `Config` paired with the
    // wrong `Membership`), so it fails FAST at construction rather than mid-operation. (`recover`
    // treats ABSENCE as the distinct `Recovered::Retired` runtime outcome — a node REMOVED by a
    // reconfiguration — which is a legitimate state, not a misconfiguration.)
    assert!(
      membership.slot_of(config.local()).is_some(),
      "the local member {} must occupy a slot in its own membership",
      config.local(),
    );
    let nonce = Prng::new(seed).next_u64();
    // Genesis: the lineage has no predecessor, so prev_epoch == the (genesis) epoch.
    let prev_epoch = membership.epoch();
    Self {
      config,
      membership,
      prev_epoch,
      status: Status::Normal,
      view: View::new(),
      op: OpNumber::new(),
      commit_min: OpNumber::new(),
      commit_max: OpNumber::new(),
      log_view: View::new(),
      svc_from: 0,
      svc_target: View::new(),
      view_change: None,
      nonce,
      log: BTreeMap::new(),
      inflight: BTreeMap::new(),
      buffer: BTreeMap::new(),
      clients: BTreeMap::new(),
      sm,
      outgoing: VecDeque::new(),
      events: VecDeque::new(),
      timers: Timers::default(),
      next_op_id: 1,
      pending: BTreeMap::new(),
      appending: std::collections::BTreeSet::new(),
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::new(),
      log_floor: OpNumber::new(),
      peer_checkpoint: BTreeMap::new(),
      // Genesis: own checkpoint 0, no peer reports — the quorum-th order statistic is 0 (matches
      // `recompute_quorum_checkpoint` over this state, so the cache starts coherent).
      quorum_checkpoint: OpNumber::new(),
      recover: None,
      repair: std::collections::BTreeSet::new(),
      sync: None,
      pending_install: None,
      sync_serving: BTreeMap::new(),
      sync_donating: None,
      sync_transfer: None,
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      sync_chunk_transfers_completed: 0,
      wal_stalls: 0,
      below_ring_window_syncs: 0,
      unions_floored: 0,
      repair_batches_served: 0,
      prepare_batches_sent: 0,
      header_only_carriers_emitted: 0,
      sessions_evicted: 0,
      pending_forfeit: false,
    }
  }

  /// The current status.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn status(&self) -> Status {
    self.status
  }

  /// The current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The head op number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The commit number (applied frontier — highest op durably applied to the SM).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit_min
  }

  /// The highest op known committed cluster-wide (may exceed locally-held + applied ops).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit_max(&self) -> OpNumber {
    self.commit_max
  }

  /// The op number of this replica's latest durable checkpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The sole non-constructor writer of `self.checkpoint_op`. It gates an irreversible
  /// `wal.prune` in [`Self::run_gc`] / [`Self::install_sync`], so it MUST be monotone — a rewind would
  /// prune a band a durable root still claims to cover, losing committed ops on a later recover). Both
  /// advance sites (the ordinary-checkpoint and the state-sync re-persist root completions in
  /// `on_sb_done`) route here so the non-decreasing property is asserted in ONE place rather than left
  /// emergent. The `new` initial set is exempt (it SETS the genesis 0, it does not advance), as are the
  /// `#[cfg(test)]` state-injection helpers (they construct arbitrary states, bypassing the gate).
  fn advance_checkpoint_op(&mut self, to: OpNumber) {
    debug_assert!(
      to.get() >= self.checkpoint_op.get(),
      "checkpoint_op must not rewind (to {} < current {})",
      to.get(),
      self.checkpoint_op.get(),
    );
    self.checkpoint_op = to;
    // The own durable snapshot vouches every op `<= to` the log may omit, so the carried-log floor
    // keeps pace (it never falls below `checkpoint_op`).
    self.raise_log_floor(to);
    // The own checkpoint is an input of the cached quorum-th order statistic.
    self.recompute_quorum_checkpoint();
  }

  /// The sole writer of `self.log_floor` — MONOTONE by construction (`max`), so neither a stale
  /// adoption floor nor a lagging own checkpoint can lower a higher vouched floor. Raised by
  /// [`Self::advance_checkpoint_op`] (the own-snapshot source) and by the floored-adoption sites
  /// (`start_view_as_new_primary` with the union floor; `adopt_canonical_head` with the
  /// `StartView`/`RecoveryResponse`-carried floor).
  fn raise_log_floor(&mut self, to: OpNumber) {
    self.log_floor = self.log_floor.max(to);
  }

  /// The sole non-constructor writer of `self.commit_min` (the applied frontier). It NEVER rewinds —
  /// an applied op is immutable, so the commit pointer is monotone — and this is the ONE place that
  /// universal floor is asserted, rather than re-proven per site. Both ordinary advance sites (the
  /// `commit_min+1` apply loops in [`Self::commit_op`] / [`Self::advance_commit`]) and the state-sync
  /// install ([`Self::install_sync`], which advances to the synced checkpoint op) route here; the
  /// install KEEPS its own richer assert (it proves the same direction against the forced-vs-ordinary
  /// branch), so this just adds the universal monotone backstop. The `new` initial set is exempt (it
  /// SETS the genesis 0), as are the `#[cfg(test)]` state-injection helpers (arbitrary construction).
  fn set_commit_min(&mut self, to: OpNumber) {
    debug_assert!(
      to.get() >= self.commit_min.get(),
      "commit_min must not rewind (to {} < current {})",
      to.get(),
      self.commit_min.get(),
    );
    self.commit_min = to;
  }

  /// Cancel an outstanding FORCED sync once repair/commit has SATISFIED its target. A forced sync
  /// ([`Self::maybe_force_sync`]) is armed to recover a doomed committed hole `N` that became servable
  /// only as part of a peer checkpoint snapshot, targeting that snapshot's op (`>= N`). But the cheap
  /// ORDINARY repair path can still WIN the race: a peer's `Prepare` fills the hole via `fill_repair`,
  /// its WAL append lands, and `advance_commit` applies past the hole — moving `commit_min` to/PAST
  /// the forced-sync target. The hole the force-sync was working around is then FILLED + APPLIED, so the
  /// forced sync is NO LONGER NEEDED: keeping it armed only waits for a response we no longer want, and a
  /// DELAYED `SyncCheckpoint` for the now-stale target would otherwise reach `apply_sync` below the
  /// applied frontier (the `apply_sync` assert also defends).
  ///
  /// Called at the tail of the two apply loops ([`Self::advance_commit`] / [`Self::try_commit`]) — the
  /// only sites that advance `commit_min` by APPLYING ops. Gated on `pending_install.is_none()`: a forced
  /// sync that has already STAGED ([`Self::apply_sync`]) carries a `pending_install` and is mid durable
  /// re-persist (its `install_sync` advances `commit_min` to the synced point as it COMPLETES — that is
  /// the legitimate forced sync landing, NOT a satisfied-by-repair cancel), so we only cancel a
  /// PRE-stage forced sync, where cancelling is just clearing `sync` + its solicit timer (no staged
  /// install to unwind). An ORDINARY sync is never cancelled here — its `> self.op` trigger means
  /// `commit_min` (`<= self.op`) can never reach its target by ordinary apply.
  fn cancel_forced_sync_if_satisfied(&mut self) {
    if self.pending_install.is_some() {
      return; // a STAGED forced sync is completing via install_sync — not a repair-satisfied cancel.
    }
    if self
      .sync
      .is_some_and(|s| s.forced && s.target.get() <= self.commit_min.get())
    {
      self.sync = None;
      self.sync_transfer = None;
      self.timers.sync_solicit = None;
    }
  }

  /// Whether `op` is being re-fetched as a TRACKED repair hole — either an active peer-repair hole
  /// (`self.repair`) or a still-in-flight recovery faulty slot (`rec.faulty`, which `recover_progress`
  /// promotes to a `self.repair` hole on the `→ Normal` transition or drives the `RecoveringHead`
  /// head-relearn). In both cases the committed body is RE-SOLICITED, not lost — used as a survival
  /// witness by [`Self::assert_committed_survives`].
  fn is_tracked_for_repair(&self, op: u64) -> bool {
    self.repair.contains(&op)
      || self
        .recover
        .as_ref()
        .is_some_and(|r| r.faulty.contains(&op))
  }

  /// Assert dropping/overwriting `op` from the log cache / WAL cannot LOSE a committed op. The shared
  /// proof every destructive site re-derives, encoded once: a dropped op is safe iff it is
  /// - folded into the checkpoint whose snapshot justifies the drop (`op <= checkpoint_floor`) — its
  ///   value lives in that snapshot; or
  /// - being re-fetched as a TRACKED repair hole ([`Self::is_tracked_for_repair`]) — the committed value
  ///   is actively re-solicited (`RequestPrepare` → `Prepare`), so the drop is a cache eviction, not a
  ///   loss (the apply loop HOLDS the commit below it until the canonical body returns); or
  /// - provably UNCOMMITTED (`op > commit_max`, the highest op known committed cluster-wide) — nothing at
  ///   `op` was ever committed, so there is no committed value to lose.
  ///
  /// `checkpoint_floor` is the durable/just-restored checkpoint the SITE relies on, almost always
  /// `self.checkpoint_op`; the ONE exception is [`Self::install_sync`], where the deferred-advance
  /// keeps `self.checkpoint_op` at the OLD value until the caller records the new root, so the install
  /// passes its LOCAL synced checkpoint (the snapshot it just restored into the SM). Naming the floor
  /// per site keeps the witness exact and STRONG (no fall back to the weaker applied frontier).
  ///
  /// The historical committed-divergence failures all live at these sites. NOTE `commit_max`
  /// is a re-learnable HINT, so the `> commit_max` clause is the *loosest* uncommitted witness; the
  /// per-site safety arguments (quorum-intersection nack-truncation, the offset-tail materialization)
  /// remain the real proofs — this is the shared backstop that fires if a NEW destructive site drops a
  /// committed op that is neither checkpointed nor tracked-for-repair nor above the known-committed frontier.
  /// RELEASE-ACTIVE (`assert!`, not `debug_assert!`): the wide release VOPR sweep and every release build
  /// run this backstop, so no build can SILENTLY drop a committed op via a buggy destructive site (the
  /// debug-only form left the release wide sweep — the very net that found the storage-fault loss — blind
  /// to it). The `commit_max` frontier is a re-learnable hint a forced sync may regress, but that is sound
  /// HERE: content-addressed votes (`PrepareOk` carries the body checksum) make a truncate-and-reuse of an
  /// op above a regressed frontier non-divergent regardless, and every LEGITIMATE drop is checkpointed,
  /// tracked-for-repair, or above the CURRENT `commit_max` — each destructive site's own gate — so the
  /// witness is false-positive free while now guarding release builds too.
  fn assert_committed_survives(&self, op: u64, checkpoint_floor: u64) {
    assert!(
      op <= checkpoint_floor || self.is_tracked_for_repair(op) || op > self.commit_max.get(),
      "destructive op on committed op {} (checkpoint_floor {}, commit_max {}, not tracked-for-repair)",
      op,
      checkpoint_floor,
      self.commit_max.get(),
    );
  }

  /// The aggregate `(Status × sub-state-flag)` coupling check — TigerBeetle's `assert_main`, run at the
  /// END of every public entry point (`handle_message` / `handle_timeout` / `handle_storage`). The flag
  /// rules previously lived only as scattered prose at each set/clear site; encoding them as ONE
  /// handler-exit invariant makes any future drift (a transition that forgets to clear a flag, a new
  /// sub-state that violates the coupling) trip DETERMINISTICALLY across the whole suite + VOPR, exactly
  /// like the `serviceable_now` no-orphan-due assert does for timers. Each clause is verified to hold at
  /// every handler exit (the `new`/transition handlers re-establish the coupling before returning); this
  /// is detection, the per-site sets/clears remain the enforcement.
  #[cfg(debug_assertions)]
  fn assert_invariants(&self) {
    // (1) A deferred state-sync install belongs to an OUTSTANDING sync: `apply_sync` stages
    // `pending_install` and `sync` together, and every clear path drops `pending_install` no later than
    // `sync` (the deferred root completion `take()`s the install before clearing `sync`; the eager
    // recovery path `take()`s it at flip-to-Normal while `sync` rides on; the view-change resets drop
    // both). It also implies an in-flight checkpoint re-persist (`pending_checkpoint`) — the same
    // `apply_sync` submits the two-write checkpoint sequence that carries the install to durability.
    debug_assert!(
      self.pending_install.is_none() || self.sync.is_some(),
      "pending_install without an outstanding sync"
    );
    debug_assert!(
      self.pending_install.is_none() || self.pending_checkpoint.is_some(),
      "pending_install without its in-flight re-persist checkpoint"
    );
    // (1b) A chunked transfer likewise belongs to an OUTSTANDING sync: `on_sync_checkpoint_meta`
    // pins it only under a live nonce-matched `sync`, and every clear path drops it no later than
    // `sync` (aborts drop only the transfer, keeping `sync` armed to re-announce).
    debug_assert!(
      self.sync_transfer.is_none() || self.sync.is_some(),
      "sync_transfer without an outstanding sync"
    );
    // (2) The ViewChange-only collection (DVC + catch-up discriminant) exists for EXACTLY the lifetime
    // of `Status::ViewChange`: the two ViewChange entries (`enter_view_change` / `catch_up_to_view`)
    // construct it, and every exit to Normal (`adopt_canonical_head` / `start_view_as_new_primary`)
    // `take`s it. Reifying it as `Option<ViewChangeCollection>` makes the coupling TYPE-enforced (the
    // DVC/catch-up state simply cannot be held in any other status); this clause checks the Option's
    // presence tracks the status exactly — a strictly stronger form of the old `catching_up ⟹
    // ViewChange` prose. (The SVC bits stay flat: they are live in Normal too — see the struct fields.)
    debug_assert!(
      self.view_change.is_some() == self.status.is_view_change(),
      "view_change collection present iff Status::ViewChange (status {:?}, present {})",
      self.status,
      self.view_change.is_some(),
    );
    // (3) Both forfeit sub-states belong to a Normal PRIMARY that is stepping down: `forfeit_armed` is
    // armed only on the Normal-primary tick (`maybe_forfeit`), and `pending_forfeit` is latched only by
    // `forfeit` (a Normal-primary tick) or `defer_forfeit` (raised on a replica that is the primary of
    // its view). `forfeit` PROPOSES `view+1` without leaving Normal, so the latch coexists with
    // Normal-primary until the SVC quorum forms (the transition then clears it); every primacy/view
    // transition clears both. So at any handler exit a set forfeit sub-state ⟹ Normal-primary.
    debug_assert!(
      self.timers.forfeit_armed.is_none() || (self.status.is_normal() && self.is_primary()),
      "forfeit_armed off a Normal primary"
    );
    debug_assert!(
      !self.pending_forfeit || (self.status.is_normal() && self.is_primary()),
      "pending_forfeit off a Normal primary"
    );
    // (4) The monotone frontier bounds (the same chain `submit_durable_view`/`install_sync` document):
    // `commit_max >= commit_min >= checkpoint_op`. NOTE `op >= commit_max` is deliberately NOT asserted —
    // the tail-gap allows `commit_max > op` (a known-committed op this replica does not yet hold).
    debug_assert!(
      self.commit_max.get() >= self.commit_min.get(),
      "commit_max {} < commit_min {}",
      self.commit_max.get(),
      self.commit_min.get()
    );
    debug_assert!(
      self.commit_min.get() >= self.checkpoint_op.get(),
      "commit_min {} < checkpoint_op {}",
      self.commit_min.get(),
      self.checkpoint_op.get()
    );
    // (5) The applied frontier never exceeds the head (apply is forward and in-bounds): `op >= commit_min`.
    debug_assert!(
      self.op.get() >= self.commit_min.get(),
      "op {} < commit_min {}",
      self.op.get(),
      self.commit_min.get()
    );
    // (5b) The vouched log floor keeps pace with the own checkpoint (`advance_checkpoint_op` raises
    // it) and never exceeds the head: every adoption sets `op` to a head at/above the floor it
    // raises the floor to, and a state-sync install lands `op` at/above its (floor-raising) synced
    // checkpoint. `op >= log_floor` is what makes the carrier SPAN gate (`band_at_capacity`)
    // well-formed and the floored-union span bound inductive across view changes.
    debug_assert!(
      self.log_floor.get() >= self.checkpoint_op.get(),
      "log_floor {} < checkpoint_op {}",
      self.log_floor.get(),
      self.checkpoint_op.get()
    );
    debug_assert!(
      self.op.get() >= self.log_floor.get(),
      "op {} < log_floor {}",
      self.op.get(),
      self.log_floor.get()
    );
    // (6) The peer-checkpoint fetch is a Recovering sub-state: `escalate_checkpoint_to_peer_fetch` sets
    // it only on the Recovering checkpoint-read-exhausted path, and `recover` is structurally `None`
    // (hence `awaiting_peer_checkpoint()` false) in every non-recovering status.
    debug_assert!(
      !self.awaiting_peer_checkpoint() || self.status.is_recovering(),
      "awaiting_peer_checkpoint outside Recovering"
    );
  }

  /// Record a peer's reported `checkpoint_op` MONOTONICALLY: a peer's durable checkpoint never
  /// regresses, so a reordered/older report (a delayed `Commit`/`PrepareOk`, or a stale message
  /// after a partition heals) must never lower the value we hold. Keeping this monotone keeps the GC
  /// prune floor (`quorum_checkpoint_op`) and the force-sync/forfeit triggers that read it from
  /// moving backward — a regressing floor could spuriously un-fire the force-sync escalation. (T1)
  fn record_peer_checkpoint(&mut self, replica: ReplicaId, reported: OpNumber) {
    let prev = self
      .peer_checkpoint
      .get(&replica)
      .copied()
      .unwrap_or_else(OpNumber::new);
    self.peer_checkpoint.insert(replica, prev.max(reported));
    // A peer report is an input of the cached quorum-th order statistic.
    self.recompute_quorum_checkpoint();
  }

  /// The highest op a `quorum` of replicas (including self) has reported checkpointing.
  ///
  /// Returns the CACHED quorum-th order statistic (`Self::recompute_quorum_checkpoint` maintains it
  /// at the mutation sites — `record_peer_checkpoint`, `advance_checkpoint_op`, and the
  /// view-transition `peer_checkpoint` clear): the largest op `v` such that at least `quorum`
  /// replicas report a checkpoint `>= v`. The primary uses this as the floor below which WAL/session
  /// GC is safe (no op a quorum still needs is freed) — and `Self::prune_floor` reads it on EVERY
  /// client request (the WAL-stall check), which is why it is cached rather than allocated + sorted
  /// per call. Conservative by construction: an unheard peer counts as 0, so a fresh primary prunes
  /// nothing until enough fresh `PrepareOk`s arrive — it never frees an op too early.
  pub fn quorum_checkpoint_op(&self) -> OpNumber {
    // Cache-coherence drift guard: any future writer of `checkpoint_op`/`peer_checkpoint` that skips
    // the recompute trips deterministically across the suite.
    debug_assert!(
      self.quorum_checkpoint == self.compute_quorum_checkpoint_op(),
      "quorum_checkpoint cache is stale (cached {}, actual {}) — a checkpoint-report mutation site \
       skipped recompute_quorum_checkpoint",
      self.quorum_checkpoint.get(),
      self.compute_quorum_checkpoint_op().get(),
    );
    self.quorum_checkpoint
  }

  /// Recompute the cached [`Self::quorum_checkpoint_op`] from `self.checkpoint_op` + the
  /// `peer_checkpoint` reports. Called at every mutation site of those inputs (the only writers).
  fn recompute_quorum_checkpoint(&mut self) {
    self.quorum_checkpoint = self.compute_quorum_checkpoint_op();
  }

  /// The uncached quorum-th order statistic: sort the VOTING replicas' reported checkpoints (a voter's
  /// own durable checkpoint; unheard voters as 0) descending and take the `quorum`-th highest. The
  /// statistic is voter-only BY CONSTRUCTION — a non-voter never appears in it, so its (possibly high)
  /// checkpoint cannot lift the GC floor. On a voter self this yields exactly the voters (self + the
  /// other voters); on a non-voting member self the seed below is skipped and the iteration covers only
  /// the voters, so a learner — which populates no voter `peer_checkpoint` — computes ~0 (the safe
  /// conservative floor that frees nothing).
  fn compute_quorum_checkpoint_op(&self) -> OpNumber {
    let count = self.membership.replica_count();
    let mut cps: std::vec::Vec<u64> = std::vec::Vec::with_capacity(count as usize);
    let me = self.local_slot();
    if self.membership.is_voter(me) {
      cps.push(self.checkpoint_op.get()); // a voter counts its own durable checkpoint; a learner does not
    }
    for r in 0..count {
      let rid = ReplicaId::new(u16::from(r));
      if rid == me {
        continue; // a learner `me` is never in `0..count`, so this skips nothing — the seed above is what gates self
      }
      cps.push(self.peer_checkpoint.get(&rid).map_or(0, |c| c.get()));
    }
    cps.sort_unstable_by(|a, b| b.cmp(a)); // descending
    // On a voter `cps.len() == replica_count`; on a learner `cps.len() == replica_count` too (the seed
    // is skipped but no voter is). Either way `cps.len() >= quorum`, so `cps[quorum - 1]` is in bounds.
    OpNumber::with(cps[self.membership.quorum() - 1])
  }

  /// The highest `checkpoint_op` ANY single peer (or self) has reported — i.e. the newest durable
  /// checkpoint snapshot we know a `Normal` peer could ship us via `SyncCheckpoint`.
  ///
  /// Unlike [`Self::quorum_checkpoint_op`] (the quorum-th order statistic, used as the GC prune
  /// floor where a *quorum* must agree before freeing), this is the *maximum* over reporters. It is
  /// the correct floor for the force-sync escalation ([`Self::maybe_force_sync`]): a backup only ever
  /// records the PRIMARY's checkpoint (a backup hears `Commit` from the primary, never `PrepareOk`
  /// from other backups — those go to the primary), so on a backup `quorum_checkpoint_op` is
  /// structurally pinned to ~0 and the quorum-th floor can NEVER cross a hole. A single peer reporting
  /// `checkpoint_op >= N` already proves a servable snapshot `>= N` exists (it is the exact source the
  /// ordinary sync trusts, [`Self::maybe_request_sync`], which targets a *single* peer's reported
  /// checkpoint, integrity-gated by `on_sync_checkpoint`). Monotone (each `peer_checkpoint` entry is,
  /// via [`Self::record_peer_checkpoint`]), so the floor never regresses under reordering/partitions.
  ///
  /// Seeded from `log_floor` (`>= checkpoint_op`), not the own checkpoint alone: a FLOORED adoption
  /// proved a durable cluster checkpoint at the adopted floor exists (a canonical donor's), and that
  /// knowledge must survive the view transitions that clear `peer_checkpoint` — without it, a
  /// sub-floor adopter's force-sync floor could fall back below its own holes and the escalation
  /// would never fire (the hole is pruned everywhere, so `RequestPrepare` stays futile forever).
  fn max_peer_checkpoint_op(&self) -> OpNumber {
    let mut hi = self.checkpoint_op.max(self.log_floor);
    for cp in self.peer_checkpoint.values() {
      hi = hi.max(*cp);
    }
    hi
  }

  /// Whether this `Recovering` replica's OWN checkpoint read exhausted and it is now fetching the
  /// checkpoint from a peer. `false` in every other state (incl. when `recover` is `None`).
  fn awaiting_peer_checkpoint(&self) -> bool {
    self
      .recover
      .as_ref()
      .is_some_and(|r| r.awaiting_peer_checkpoint)
  }

  /// The latest view in which this replica changed its head log.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn log_view(&self) -> View {
    self.log_view
  }

  /// This replica's slot in the active [`Membership`] — where its stable [`MemberId`]
  /// ([`Config::local`]) resolves. Every quorum/primary/voter decision keys on this slot, so a
  /// reconfiguration that moves the node to a different slot is transparent to the call sites.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn replica(&self) -> ReplicaId {
    self.local_slot()
  }

  /// This replica's slot in the active membership: the slot its stable [`MemberId`]
  /// ([`Config::local`]) occupies. The single relocation target for the former `self.config.replica()`
  /// — every former local-slot read now routes through here.
  ///
  /// Infallible: [`Self::new`]/[`Self::recover`] only ever build an endpoint whose local member is in
  /// its own membership (the `new` debug-assert / the `recover` resolution), so the lookup always hits.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn local_slot(&self) -> ReplicaId {
    self
      .membership
      .slot_of(self.config.local())
      .expect("local member is in its own membership")
  }

  /// This node's stable [`MemberId`] ([`Config::local`]). The QUIC coordinator reads it to attest its
  /// own identity in the handshake preface and to self-reject a peer claiming this node's identity —
  /// both keyed on the stable member id, not the slot it currently occupies.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn local(&self) -> MemberId {
    self.config.local()
  }

  /// Resolve a member to its slot in the active [`Membership`], if present. The QUIC coordinator reads
  /// it to bind a peer that attested its stable [`MemberId`]: an in-membership member resolves to the
  /// routing slot it currently occupies, an absent one yields `None` (the coordinator then rejects the
  /// connection). Delegates to [`Membership::slot_of`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn slot_of(&self, who: MemberId) -> Option<ReplicaId> {
    self.membership.slot_of(who)
  }

  /// The cluster id this replica was configured for. The QUIC coordinator reads it to single-source
  /// the cluster used by its identity-binding cross-check (rather than carrying a duplicate field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn cluster(&self) -> u128 {
    self.config.cluster()
  }

  /// The number of voting replicas in the active membership. The QUIC coordinator reads it to
  /// single-source the configured membership: it rejects binding a peer whose attested replica index
  /// is outside `0..replica_count`, and it sizes the connection cap to the mutual-dial mesh — both
  /// without duplicating the count.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica_count(&self) -> u8 {
    self.membership.replica_count()
  }

  /// The total number of replicas in the active membership: the voting replicas plus the
  /// non-voting learners (`replica_count + learner_count`). Every replica id is in `0..node_count`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn node_count(&self) -> u16 {
    self.membership.node_count()
  }

  /// True iff `other` is a `config_id` in THIS replica's configuration lineage — the in-lineage
  /// admission test for the AGNOSTIC, view-independent serves/solicitations (the committed-content
  /// repair + state-sync messages, and the repair-serve arm of `Prepare`). Such a message carries no
  /// vote/lead authority — its content is verified independently downstream — so it is admitted from
  /// any config in the chain, letting a node catch up across an epoch boundary.
  ///
  /// PR1 retains only the CURRENT `config_id`, so same-`config_id` IS the lineage check: under an offline restart,
  /// every live node shares one configuration at any instant. The
  /// multi-epoch lineage chain (carrying superseded `config_id`s to admit live cross-epoch catch-up)
  /// is a later milestone.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn in_lineage(&self, other: u128) -> bool {
    other == self.membership.config_id()
  }

  /// True iff THIS replica is a non-voting learner (its own slot is `>= replica_count`). A learner
  /// applies the committed log but never acknowledges a prepare, never casts a view-change vote, and
  /// is never primary — it follows the cluster via the primary's broadcasts and catches up by
  /// soliciting state, exactly like a TigerBeetle standby.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_learner(&self) -> bool {
    self.membership.is_learner(self.local_slot())
  }

  /// Whether this replica is the primary of the current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_primary(&self) -> bool {
    self
      .membership
      .is_primary_slot(self.local_slot(), self.view)
  }

  /// The HARD bound on the raw session-table size at accept-time admission: the applied-session cap
  /// ([`Config::max_client_sessions`], enforced by deterministic apply-time eviction) plus one
  /// pipeline of PROVISIONAL accept-time rows (`last_op == 0`, bounded by the [`MAX_PIPELINE`]
  /// admission — each provisional row corresponds to an accepted in-flight op). `on_request` refuses
  /// to mint a NEW client row past this, so the table cannot grow without bound even before the
  /// apply-time eviction sees the new clients.
  fn session_table_hard_bound(&self) -> usize {
    self.config.max_client_sessions() as usize + MAX_PIPELINE as usize
  }

  /// True iff this replica may participate AS the primary right now: `Normal`, the primary of its
  /// view, AND its current view is already DURABLE (no pending superblock view write). The last
  /// clause is durable-view-before-participate: [`Self::start_view_as_new_primary`]
  /// sets `Normal` but DEFERS the StartView broadcast (and the rest of participation) to
  /// [`Self::start_view_participate`] on `on_sb_done`, so until that durable-view write lands the new
  /// view is not yet recoverable — a crash would regress out of it. Acting AS the primary in that
  /// window (answering a delayed/duplicate `GetView` with a `StartView`, a peer's `Recovery` with our
  /// canonical head, or heartbeating/retransmitting on the commit/prepare timers) would assert this
  /// replica's authority in a view it might never have durably entered → cross-view
  /// double-participation. Every such outbound PRIMARY path gates on this; the deferred
  /// `start_view_participate` already runs AFTER the view is durable, so it does not.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn participates_as_primary(&self) -> bool {
    self.status.is_normal() && self.is_primary() && self.pending_sb.is_none()
  }

  /// Read access to the state machine (for tests / observers).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn state_machine_ref(&self) -> &S {
    &self.sm
  }

  /// Whether this replica has ANY storage op (WAL append or superblock write/read) still in flight —
  /// a submitted [`Wal`]/[`Superblock`] op whose completion the driver still owes.
  ///
  /// `true` iff at least one of the durability-relevant pending sets is non-empty: the outstanding WAL
  /// appends (`pending`, plus its `appending` append-before-ack gate — a subset of `pending`, ORed for
  /// explicitness), the in-flight durable-view superblock write (`pending_sb`), the in-flight
  /// checkpoint write sequence (`pending_checkpoint`, and its deferred-install staging
  /// `pending_install` — which structurally implies `pending_checkpoint`), and the in-flight
  /// checkpoint READS this replica issued to serve peers' `RequestSync`s / cold-cache
  /// `RequestSyncChunk`s (`sync_serving` — a
  /// `submit_read_checkpoint` whose completion is still owed). It deliberately covers BOTH writes we
  /// owe durability for AND the serve-reads we issued, since both are storage completions the driver is
  /// still holding for this endpoint.
  ///
  /// A real driver uses this for graceful shutdown (do not tear down the proactor while a write the
  /// cluster may have acted on is un-acked) and for the restart-in-place drain (see the
  /// [`OpId`](crate::OpId) lifetime contract: a driver retaining a completion-correlation table across
  /// endpoint re-creation must drain/cancel all in-flight storage ops first, and this is the
  /// proto-side "am I quiesced?" signal). The in-flight RECOVERY reads (`recover`) are deliberately NOT
  /// included: they belong to a
  /// `Recovering`/`RecoveringHead` endpoint that is itself the product of `recover()` (not a quiesce
  /// target for a shutdown of a participating replica), and they resolve via `handle_storage`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn has_inflight_storage(&self) -> bool {
    !self.pending.is_empty()
      || !self.appending.is_empty()
      || self.pending_sb.is_some()
      || self.pending_checkpoint.is_some()
      || self.pending_install.is_some()
      || !self.sync_serving.is_empty()
  }

  /// The number of entries in this replica's in-memory `log` cache (the per-op tail cache).
  ///
  /// Exposed for the simulation boundedness checker: after post-checkpoint GC, this is bounded by
  /// `O(checkpoint_ops + pipeline)` — the un-checkpointed tail `(prune_floor .. head]` plus in-flight
  /// headroom. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_len(&self) -> usize {
    self.log.len()
  }

  /// The number of entries in this replica's primary pipeline (`inflight`) map.
  ///
  /// Exposed for the simulation boundedness checker (same bound argument as [`Self::log_len`]). Not
  /// part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn inflight_len(&self) -> usize {
    self.inflight.len()
  }

  /// The number of entries in this replica's client-session table (`clients`).
  ///
  /// Exposed for the simulation boundedness checker: `clients` is bounded by the active client set
  /// (one session per client), independent of op count. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn clients_len(&self) -> usize {
    self.clients.len()
  }

  /// Test-only: the smallest op number still held in the in-memory `log` cache, or `None` if empty.
  /// Used to assert GC trimmed the cache below the prune floor.
  #[cfg(test)]
  fn min_log_op(&self) -> Option<u64> {
    self.log.keys().next().copied()
  }

  /// Test-only: the number of buffered out-of-order prepares (proves the reorder-buffer bound).
  #[cfg(test)]
  fn buffer_len_for_test(&self) -> usize {
    self.buffer.len()
  }

  /// Test-only: the per-peer recorded checkpoint (0 if unheard). Proves T1 monotonicity directly.
  #[cfg(test)]
  fn peer_checkpoint_for_test(&self, replica: u8) -> u64 {
    self
      .peer_checkpoint
      .get(&ReplicaId::new(u16::from(replica)))
      .map_or(0, |c| c.get())
  }

  /// Test-only: directly seed a peer's reported checkpoint (bypassing a real PrepareOk/Commit), so a
  /// test can construct a quorum-checkpoint floor without driving full message flows. Goes through the
  /// MONOTONE recorder, so a lower injection cannot regress a higher recorded value.
  #[cfg(test)]
  fn inject_peer_checkpoint_for_test(&mut self, replica: u8, op: u64) {
    self.record_peer_checkpoint(ReplicaId::new(u16::from(replica)), OpNumber::with(op));
  }

  /// Test-only: set this replica's own durable `checkpoint_op` (the value the forfeit gate compares
  /// against `quorum_checkpoint_op()`), so a test can model a primary that is/ isn't keeping pace.
  /// Keeps the `log_floor >= checkpoint_op` coupling a real checkpoint advance maintains.
  #[cfg(test)]
  fn set_own_checkpoint_for_test(&mut self, op: u64) {
    self.checkpoint_op = OpNumber::with(op);
    self.raise_log_floor(OpNumber::with(op));
    self.recompute_quorum_checkpoint();
  }

  /// Test-only: is this `Recovering` replica awaiting a PEER checkpoint after its own checkpoint read
  /// exhausted (the peer-fetch escalation)?
  #[cfg(test)]
  fn awaiting_peer_checkpoint_for_test(&self) -> bool {
    self.awaiting_peer_checkpoint()
  }

  /// Test-only: is the forfeit grace timer currently armed?
  #[cfg(test)]
  fn forfeit_armed_for_test(&self) -> bool {
    self.timers.forfeit_armed.is_some()
  }

  /// Test-only: is the deferred-forfeit flag set (the safety step-down a primary raises instead of
  /// force-syncing — see `maybe_force_sync`)?
  #[cfg(test)]
  fn pending_forfeit_for_test(&self) -> bool {
    self.pending_forfeit
  }

  /// Test-only: raise the deferred-forfeit step-down exactly as the production `defer_forfeit` does
  /// (the step-down a primary takes off the force-sync / sync-checkpoint strand), so a regression can
  /// prove the body-aware truncation is gated OUT of the `pending_forfeit` window without driving a
  /// full force-sync. Inlined (not delegating to `defer_forfeit`) because this test-accessor impl block
  /// carries no `S: StateMachine` bound; kept byte-identical to that method (latch `pending_forfeit` +
  /// bootstrap the serviceable `svc_message` wake).
  #[cfg(test)]
  fn defer_forfeit_for_test(&mut self, now: Instant) {
    self.pending_forfeit = true;
    self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
  }

  /// Test-only: is a view-change/adoption superblock write still pending (`pending_sb` armed)? True
  /// exactly in the durable-view-before-participate window: after
  /// `start_view_as_new_primary` sets `Normal` but before `on_sb_done` lands the durable-view write.
  #[cfg(test)]
  fn pending_sb_for_test(&self) -> bool {
    self.pending_sb.is_some()
  }

  /// Test-only: stage a `pending_checkpoint` (bypassing the trigger), so the `on_request` defense guard
  /// (drop a client while a checkpoint-persist is in flight — the op-reset risk) can be exercised.
  #[cfg(test)]
  fn stage_pending_checkpoint_for_test(&mut self) {
    let id = self.mint_op_id();
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: self.commit_min,
      checkpoint_id: 0,
      step: CheckpointStep::AwaitSnapshot(id),
      kind: CheckpointKind::Ordinary, // models an ordinary checkpoint-persist in flight
    });
  }

  /// Test-only: the in-flight checkpoint's typed completion kind (the `on_sb_done` root-completion
  /// discriminator) — `Some(true)` for a [`CheckpointKind::SyncRepersist`], `Some(false)` for a
  /// [`CheckpointKind::Ordinary`], `None` when no checkpoint is in flight. Lets a regression test
  /// assert the STAGED kind directly (the typed discriminator that replaced the ambient `sync` bool),
  /// not just the downstream routing behavior.
  #[cfg(test)]
  fn pending_checkpoint_is_sync_for_test(&self) -> Option<bool> {
    self
      .pending_checkpoint
      .map(|pc| matches!(pc.kind, CheckpointKind::SyncRepersist))
  }

  /// Test-only: force this endpoint into a `Normal` state with the given head/commit/checkpoint and a
  /// set of pending-repair holes (with the repair-retry timer armed). Mirrors how the recover loop +
  /// apply path would leave a replica holding a committed-op hole below its head. Does NOT touch the
  /// `log` cache (the holes are, by construction, ABSENT from it — the apply path treats them as
  /// missing bodies), so the commit is genuinely held below the first hole.
  ///
  /// The supplied `repair` holes are modelled as COMMITTED holes (the helper's documented contract: "a
  /// committed-op hole below its head"), so `commit_max` is raised to cover the highest of them as well
  /// as `commit_min`. This keeps a hole `<= commit_max` — the property the forfeit gate (and the
  /// body-aware nack-truncation candidate test, which excludes `op <= commit_max`) read to tell a
  /// COMMITTED hole apart from an above-`commit_max` repair-or-truncate candidate. Without it a hole
  /// would read as `> commit_max` (an uncommitted candidate) and never gate the forfeit.
  #[cfg(test)]
  fn force_state_for_test(
    &mut self,
    view: u64,
    op: u64,
    commit_min: u64,
    checkpoint_op: u64,
    repair: &[u64],
  ) {
    self.status = Status::Normal;
    // Forcing a clean Normal state: the ViewChange-only collection must be absent (the
    // `view_change.is_some() == is_view_change()` coupling), so a test that reuses an endpoint which had
    // been in ViewChange does not carry a stale `Some` into the forced Normal scenario.
    self.view_change = None;
    self.view = View::with(view);
    self.log_view = View::with(view);
    self.op = OpNumber::with(op);
    self.commit_min = OpNumber::with(commit_min);
    let committed_frontier = repair
      .iter()
      .copied()
      .max()
      .unwrap_or(0)
      .max(commit_min)
      .max(self.commit_max.get());
    self.commit_max = OpNumber::with(committed_frontier);
    self.checkpoint_op = OpNumber::with(checkpoint_op);
    self.recompute_quorum_checkpoint();
    // Arbitrary-construction helper: keep the `log_floor >= checkpoint_op` coupling a real
    // checkpoint advance maintains (no adoption floor is being modelled here).
    self.log_floor = OpNumber::with(checkpoint_op);
    self.repair = repair.iter().copied().collect();
    if !self.repair.is_empty() {
      self.timers.repair_retry = Some(Instant::ZERO);
    }
  }

  /// Test-only: is `op` a pending-repair hole?
  #[cfg(test)]
  fn has_repair_hole_for_test(&self, op: u64) -> bool {
    self.repair.contains(&op)
  }

  /// Test-only: seed an in-memory `log` entry at `op` (a placeholder body), so the held-tail
  /// preservation of `apply_sync` can be observed (`force_state_for_test` deliberately leaves the
  /// cache empty). Does not touch the WAL.
  #[cfg(test)]
  fn seed_log_entry_for_test(&mut self, op: u64) {
    self.log.insert(
      op,
      LogEntry::present(ClientId::new(1), RequestNumber::with(op), Bytes::new()),
    );
  }

  /// Test-only: does the in-memory `log` cache hold `op`?
  #[cfg(test)]
  fn has_log_entry_for_test(&self, op: u64) -> bool {
    self.log.contains_key(&op)
  }

  /// Test-only: the outstanding sync's target op, or `None` if no sync is outstanding.
  #[cfg(test)]
  fn sync_target_for_test(&self) -> Option<u64> {
    self.sync.map(|s| s.target.get())
  }

  /// Test-only: is the outstanding sync a FORCED sync?
  #[cfg(test)]
  fn sync_is_forced_for_test(&self) -> bool {
    self.sync.is_some_and(|s| s.forced)
  }

  /// Test-only: the outstanding sync's nonce (panics if none) — to build a matching SyncCheckpoint.
  #[cfg(test)]
  fn sync_nonce_for_test(&self) -> u64 {
    self.sync.expect("a sync is outstanding").nonce
  }

  /// Test-only: arm a FORCED sync to `target` directly (bypassing the trigger), so the forced
  /// assert-relaxation in `apply_sync` can be exercised in isolation.
  #[cfg(test)]
  fn arm_forced_sync_for_test(&mut self, target: u64) {
    self.nonce = self.nonce.wrapping_add(1);
    self.sync = Some(SyncState {
      target: OpNumber::with(target),
      nonce: self.nonce,
      forced: true,
    });
  }

  /// Test/observability counter: how many state-syncs have fully applied + become durable on
  /// this replica since it was constructed. Incremented when an `apply_sync`'s durable re-persist
  /// completes (`on_sb_done` lands the synced checkpoint's root write). The state-sync sim gate uses
  /// this to assert NON-VACUITY — the laggard genuinely state-synced (>= 1) rather than catching up
  /// op-by-op via ordinary retransmit. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn state_syncs_applied(&self) -> u64 {
    self.state_syncs_applied
  }

  /// Test/observability counter: the subset of [`Self::state_syncs_applied`] raised by the
  /// FORCE-sync escalation ([`Self::maybe_force_sync`]) — a `Normal` replica that cleared a pruned
  /// committed hole below the quorum checkpoint and fetched the snapshot, instead of looping
  /// `RequestPrepare`. The focused force-sync sim gate uses this to prove the FORCED path fired
  /// specifically (`> 0`), distinguishing it from an ordinary `> self.op` state-sync. Not part of the
  /// stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn forced_syncs_applied(&self) -> u64 {
    self.forced_syncs_applied
  }

  /// Test/observability counter: how many CHUNKED checkpoint transfers this replica completed — an
  /// announced over-frame checkpoint was pulled chunk-by-chunk, assembled, and verified against the
  /// pinned content id (it then re-enters the ordinary `SyncCheckpoint` install path). The
  /// large-snapshot sim gate asserts it goes `>= 1` to prove the CHUNKED path genuinely carried the
  /// sync (vs the single-frame fast path). Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn sync_chunk_transfers_completed(&self) -> u64 {
    self.sync_chunk_transfers_completed
  }

  /// Test/observability: the donor a chunked transfer is currently pinned to, or `None` when no
  /// chunked pull is in progress. Lets the donor-crash sim variant target the live donor
  /// deterministically. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn sync_transfer_donor(&self) -> Option<u16> {
    self.sync_transfer.as_ref().map(|t| t.donor.get())
  }

  /// Test/observability counter: how many client requests this replica dropped at op-assignment
  /// because minting the next op would overflow the bounded WAL ring (the physical stall-before-wrap).
  /// `0` for an unbounded WAL (the default), so it is inert for existing gates; the bounded-WAL sim gate
  /// asserts it goes `> 0` to prove the stall genuinely engaged. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn wal_stalls(&self) -> u64 {
    self.wal_stalls
  }

  /// Test/observability counter: how many times this backup fell below its bounded-WAL
  /// ring window on a head-extending `Prepare` — the append refused (it would overwrite an un-pruned
  /// slot) with state-sync as the recovery, whether the guard armed the sync itself or one was already
  /// outstanding ([`Self::maybe_sync_below_ring_window`]). `0` for an unbounded WAL (the
  /// default) or an in-quorum backup; the bounded-WAL sim gate asserts it goes `> 0` to prove the
  /// connected below-ring-window guard engaged (distinct from the ordinary `> self.op` sync trigger
  /// alone). Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn below_ring_window_syncs(&self) -> u64 {
    self.below_ring_window_syncs
  }

  /// Test/observability counter: how many canonical-log selections actually FLOORED the union —
  /// [`Self::select_canonical_log`] dropped at least one canonical-donor entry at/below the vouched
  /// checkpoint floor `floor*`. The sim gate asserts it goes `> 0` across a sweep to prove the
  /// floored-union path did real work (not vacuously inert at floor 0). Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn unions_floored(&self) -> u64 {
    self.unions_floored
  }

  /// Test/observability counter: how many NON-EMPTY [`RepairBatch`](crate::RepairBatch)es this
  /// replica served answering peers' `RequestPrepareRange`s ([`Self::on_request_prepare_range`]).
  /// The sim gate asserts it goes `> 0` to prove the windowed bulk-repair serve path genuinely
  /// shipped bodies (vs every repair flowing per-op). Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn repair_batches_served(&self) -> u64 {
    self.repair_batches_served
  }

  /// Test/observability counter: how many NON-EMPTY [`PrepareBatch`](crate::PrepareBatch)es this
  /// primary sent re-broadcasting its first un-acked window ([`Self::primary_timeouts`]'s prepare
  /// retransmit). The sim gate asserts it goes `> 0` to prove the batched retransmit path genuinely
  /// shipped bodies (vs every retransmit flowing per-op). Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn prepare_batches_sent(&self) -> u64 {
    self.prepare_batches_sent
  }

  /// Test/observability counter: how many header-only carrier slices this replica built via
  /// [`Self::log_entries`] — the chokepoint every `DoViewChange`/`StartView`/`RecoveryResponse`
  /// emission's log payload flows through. The sim gate asserts it goes `> 0` to prove the
  /// header-only carrier path genuinely fired. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn header_only_carriers_emitted(&self) -> u64 {
    self.header_only_carriers_emitted
  }

  /// Test/observability counter: how many client sessions this replica EVICTED at apply time (the
  /// deterministic [`crate::MAX_CLIENT_SESSIONS`]-cap eviction — see that constant for the
  /// contract). Advances identically on every replica across the same applied prefix; the
  /// client-churn sim lane asserts it goes `> 0` to prove the cap genuinely engaged. Not part of the
  /// stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn sessions_evicted(&self) -> u64 {
    self.sessions_evicted
  }

  /// Test-only: the client session's request high-water (the at-most-once dedup watermark
  /// `on_request` compares against), or `None` if the client has no session row. Proves the watermark
  /// is NOT seeded for an uncommitted adopted tail op that is later truncated.
  #[cfg(test)]
  fn session_request_for_test(&self, client: u128) -> Option<u64> {
    self.clients.get(&client).map(|s| s.request.get())
  }

  /// Test-only: the cached `(request_number, reply_body)` a client session holds (the at-most-once
  /// reply cache a backup-turned-primary resends on a duplicate request). `None` if no session / no
  /// cached reply.
  #[cfg(test)]
  fn session_reply_for_test(&self, client: u128) -> Option<(u64, std::vec::Vec<u8>)> {
    self
      .clients
      .get(&client)
      .and_then(|s| s.reply.as_ref())
      .map(|(rn, body)| (rn.get(), body.to_vec()))
  }

  /// Test-only: the full session table as ordered `(client, watermark, last_op)` rows — the
  /// determinism witness the two-endpoint eviction test compares across a primary-path and a
  /// backup-path endpoint (identical applied prefixes must yield identical tables).
  #[cfg(test)]
  fn sessions_snapshot_for_test(&self) -> std::vec::Vec<(u128, u64, u64)> {
    self
      .clients
      .iter()
      .map(|(&c, s)| (c, s.request.get(), s.last_op.get()))
      .collect()
  }

  /// Test-only: populate the ENTIRE old-generation in-flight set that the view-transition sites tear
  /// down, so a transition test can prove every field is replaced/cleared. Sets each
  /// member to a NON-empty / armed sentinel: the SVC bits (`svc_from`), the ViewChange-only collection
  /// (a `Some(ViewChangeCollection)` carrying a sentinel DVC + `dvc_quorum = true` + `catching_up =
  /// true`), the in-flight storage submissions (`pending`/`appending`), the per-replica checkpoint
  /// reports (`peer_checkpoint`), the in-flight checkpoint (`pending_checkpoint`), the in-flight
  /// state-sync PAIR (`sync` + `pending_install`) and its `sync_solicit` timer, and the forfeit
  /// sub-state (`forfeit_armed` + `pending_forfeit`). Bypasses the real flows (it just plants
  /// sentinels); the transition under test must replace the collection (entry → fresh, exit → `None`)
  /// and clear the rest.
  #[cfg(test)]
  fn seed_old_generation_state_for_test(&mut self) {
    self.svc_from = 0b101;
    let mut dvc_from = BTreeMap::new();
    dvc_from.insert(
      ReplicaId::new(0),
      crate::DoViewChange::new(
        self.view,
        View::new(),
        OpNumber::with(1),
        OpNumber::new(),
        self.membership.epoch(),
        self.membership.config_id(),
        ReplicaId::new(0),
        std::vec::Vec::new(),
      ),
    );
    self.view_change = Some(ViewChangeCollection {
      dvc_from,
      dvc_quorum: true,
      catching_up: true,
    });
    self.pending.insert(7, Pending::Ack(OpNumber::with(1)));
    self.appending.insert(1);
    // Through the production recorder so the cached quorum statistic stays coherent.
    self.record_peer_checkpoint(ReplicaId::new(2), OpNumber::with(3));
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: self.commit_min,
      checkpoint_id: 0,
      step: CheckpointStep::AwaitSnapshot(crate::OpId::new(999)),
      kind: CheckpointKind::SyncRepersist,
    });
    self.sync = Some(SyncState {
      target: self.checkpoint_op,
      nonce: 0,
      forced: false,
    });
    self.pending_install = Some(PendingInstall {
      checkpoint_op: self.checkpoint_op,
      sessions: BTreeMap::new(),
      sm_tail: Bytes::new(),
      held_tail: false,
    });
    self.sync_transfer = Some(SyncTransfer {
      checkpoint_op: self.checkpoint_op,
      checkpoint_id: 0,
      total_len: 1,
      donor: ReplicaId::new(0),
      staged: std::vec::Vec::new(),
    });
    self.timers.sync_solicit = Some(Instant::ZERO);
    self.timers.forfeit_armed = Some(Instant::ZERO);
    self.pending_forfeit = true;
  }

  /// Test-only: is the entire old-generation in-flight set the view-transition sites tear down now
  /// empty/disarmed? The ViewChange-only collection is checked DVC-empty + quorum-false whether it was
  /// `take`n to `None` (an exit to Normal) or replaced by a fresh entry collection — the seeded
  /// sentinel DVC / quorum must not survive either way. Excludes `catching_up` (which the catch-up
  /// entry legitimately re-sets `true`) — the caller asserts that discriminant per transition. Freezes
  /// the D3 + Q1/Q2 invariant: NO old-generation collection state survives a view transition.
  #[cfg(test)]
  fn old_generation_state_cleared_for_test(&self) -> bool {
    self.svc_from == 0
      && self
        .view_change
        .as_ref()
        .is_none_or(|vc| vc.dvc_from.is_empty() && !vc.dvc_quorum)
      && self.pending.is_empty()
      && self.appending.is_empty()
      && self.peer_checkpoint.is_empty()
      && self.pending_checkpoint.is_none()
      && self.sync.is_none()
      && self.pending_install.is_none()
      && self.sync_transfer.is_none()
      && self.timers.sync_solicit.is_none()
      && self.timers.forfeit_armed.is_none()
      && !self.pending_forfeit
  }

  /// Test-only: the prospective-primary DVC collection (mutable), lazily creating an empty ViewChange
  /// collection if absent. The `select_canonical_log` UNIT tests drive the pure selection function on a
  /// freshly-`new`'d (Normal) endpoint without running a real ViewChange entry, so they seed the DVC map
  /// directly through this — sidestepping the production `dvc_from_mut`'s "ViewChange only" `expect`.
  #[cfg(test)]
  fn dvc_from_mut_for_test(&mut self) -> &mut BTreeMap<ReplicaId, DoViewChange> {
    &mut self
      .view_change
      .get_or_insert_with(|| ViewChangeCollection::entering(false))
      .dvc_from
  }

  /// Test-only: plant a `Some` ViewChange collection while keeping the current status, so an invariant
  /// test can violate the `view_change.is_some() == is_view_change()` coupling on a non-ViewChange
  /// replica (the old `catching_up = true` poke, now that the discriminant lives behind the Option).
  #[cfg(test)]
  fn force_view_change_present_for_test(&mut self) {
    self.view_change = Some(ViewChangeCollection::entering(true));
  }

  /// Mint a fresh storage correlation id.
  fn mint_op_id(&mut self) -> crate::OpId {
    let id = self.next_op_id;
    self.next_op_id += 1;
    crate::OpId::new(id)
  }

  /// The status-transition chokepoint: assigns `self.status` and emits
  /// [`Event::StatusChanged`] on an ACTUAL change (a same-status re-entry — e.g. a ViewChange
  /// escalating to the next view — emits nothing). Every production status write routes here so the
  /// observability event cannot be forgotten at a new transition site; the constructors set the
  /// initial status directly (construction is not a transition).
  fn set_status(&mut self, status: Status) {
    if self.status != status {
      self.status = status;
      self.events.push_back(Event::StatusChanged(status));
    }
  }

  /// Binds a message's SELF-CLAIMED sender to the authenticated transport peer `from` — the single
  /// ingress backstop mirroring the [`Self::emit`] egress chokepoint.
  ///
  /// viewstamp is a NON-Byzantine, crash-fault-tolerant VSR (like TigerBeetle) for a TRUSTED cluster:
  /// authenticating a replica message's sender is the DRIVER's job (it sets `from` to the
  /// authenticated transport peer, mirroring TigerBeetle's `message_bus.zig` `set_and_verify_peer`),
  /// and the proto TRUSTS `from`. This check is the cheap defense-in-depth complement: it rejects any
  /// message whose own claimed identity DISAGREES with `from`, so a BUGGY / misrouting driver (or a
  /// trivially-mislabeled message) cannot make a forged/misrouted message spoof a quorum VOTE
  /// (`PrepareOk`/`DoViewChange`/`StartViewChange` count the message BODY's claimed `replica()` toward
  /// a commit / view-change quorum — see `on_prepare_ok`/`on_do_view_change`/`on_start_view_change`).
  /// It is NOT cryptographic message authentication against a MALICIOUS sender (signatures, Byzantine
  /// fault tolerance) — that is explicitly OUT OF SCOPE (a BFT/blockchain concern).
  ///
  /// The per-kind bindings (each accessor verified against `message.rs`):
  /// - **Client-originated** — `Request` binds to `from == Peer::Client(r.client())`, OR a relay from
  ///   a VOTING replica (a non-voting member does not relay client writes).
  /// - **Self-identifying replica messages** (carry the sender's OWN `replica()` id) split by AUTHORITY:
  ///   - **Votes** bind to the VOTING set (`sender_is_voter`): `PrepareOk`/`StartViewChange`/
  ///     `DoViewChange` (the MUST-HAVE spoof guard). A learner-id sender is rejected — a vote from a
  ///     non-voting member must never reach the quorum bitset / vote maps.
  ///   - **Serves and solicitations of committed content** bind to the FULL membership
  ///     (`sender_is_member`): the solicitations `GetView`/`RequestPrepare`/`RequestPrepareRange`/
  ///     `Recovery`/`RequestSync`/`RequestSyncChunk`, and the serves `RecoveryResponse`/`SyncCheckpoint`/
  ///     `SyncCheckpointMeta`/`SyncChunk`. A non-voting member legitimately solicits committed state and
  ///     can serve committed content to others, so these bind to the self `replica()` over the full node
  ///     range — NOT `config.primary(view)`, which would drop an honest backup-originated serve, and not
  ///     the voting set, which would drop a learner soliciting/serving committed state. They carry
  ///     committed CONTENT verified independently (checksum + committed-vouch; checkpoint-id), not quorum
  ///     authority, so a member serving them is safe.
  /// - **Primary-authority broadcasts** (only the primary of the advertised view legitimately sends
  ///   them, and they carry NO self `replica()` to bind to) — bind to
  ///   `from == Peer::Replica(self.membership.primary(msg.view()))`: `Commit` and `StartView`. This also
  ///   closes a forged `Commit`/`StartView` from a non-primary.
  /// - **`Reply`** — replicas ignore it (the dispatch is a no-op), so this is a no-op: returns `true`.
  ///
  /// PATH-SENSITIVE (reported, not guessed): **`Prepare`** carries NO self `replica()`, so its binding
  /// is split by path. The normal head-advancing / re-ack `Prepare` comes ONLY
  /// from the primary of its view, so it binds to `config.primary(view)`. But a committed-op REPAIR
  /// serve (`on_request_prepare`) is legitimately sent by ANY `Normal` holder — incl. a
  /// BACKUP — carrying `self.view` (where `config.primary(view) != backup`), so binding it to
  /// `config.primary(view)` would DROP an honest backup repair-serve. The escape therefore ALSO accepts
  /// a `Prepare` whose op is one of our registered repair holes — but ONLY from a CONFIGURED replica
  /// `from` (an in-range `Peer::Replica`): a repair-serve is always a peer replica that holds the op,
  /// never a client / out-of-range id. The escape narrows the binding to the repair surface only;
  /// `on_prepare` then runs `fill_repair` (which body-checksums + commit>=op-vouches the serve) FIRST,
  /// and DROPS a hole-targeted `Prepare` that `fill_repair` declines BEFORE any view catch-up (the
  /// the hole-ownership guard), so neither a bad body nor a spurious catch-up can ride the
  /// escape. This leaves no spoof gap on the vote/quorum surface this check protects.
  fn sender_matches(&self, from: Peer, msg: &Message) -> bool {
    match msg {
      // Client-originated: accept from the issuing client OR relayed by a VOTING cluster replica. A
      // local-application client co-located with a backup reaches the primary only by forwarding its
      // request over the replica mesh, where the transport tags the frame with the RELAYING replica's id
      // (not the client's). Accepting that relay is safe in the non-Byzantine model: the sender is an
      // authenticated cluster member (mTLS over cluster-private roots), `on_request` serves a request ONLY
      // at the primary and dedups by client session (a relayed copy executes at most once), and a Request
      // carries no view/quorum authority to forge — it is strictly weaker than the replica's existing
      // consensus role. The relay binds to the VOTING set (`< replica_count`): a non-voting member does
      // not relay client writes — it has no client-ingress role. Out-of-range / non-member peers are
      // rejected by the bound.
      Message::Request(r) => {
        from == Peer::Client(r.client())
          || from
            .as_replica()
            .is_some_and(|id| id.get() < self.membership.replica_count() as u16)
      }
      // Self-identifying replica messages: the authenticated peer must be the claimed sender AND in the
      // appropriate range, split by AUTHORITY. Without the range check, `from == Peer::Replica(m.replica())`
      // accepts an out-of-range id (e.g. `Peer::Replica(99)` in a 3-replica cluster with `m.replica() == 99`)
      // — a non-member — whose self-consistent message then reaches the quorum / apply path (some
      // handlers, e.g. `on_prepare_ok`, range-check downstream, but `serve_sync_checkpoint`/`apply_sync`
      // did not, extending trust outside `Config`). Binding here closes it for ALL self-id messages.
      //
      // VOTES bind to the VOTING set (`sender_is_voter`): a vote from a non-voting member must never be
      // counted in any quorum bitset / vote map.
      Message::PrepareOk(m) => self.sender_is_voter(from, m.replica()),
      Message::StartViewChange(m) => self.sender_is_voter(from, m.replica()),
      Message::DoViewChange(m) => self.sender_is_voter(from, m.replica()),
      // SERVES and SOLICITATIONS of committed content bind to the FULL membership (`sender_is_member`):
      // a non-voting member legitimately solicits committed state AND can serve committed content to
      // others. They carry no quorum authority; the content is verified independently downstream. The
      // serves (`RecoveryResponse`/`SyncCheckpoint`/…) carry a self `replica()` AND a `view()` but may
      // come from ANY Normal member (a backup or a learner, not only the primary) — bind to the self id,
      // not `config.primary(view)`.
      Message::GetView(m) => self.sender_is_member(from, m.replica()),
      Message::RequestPrepare(m) => self.sender_is_member(from, m.replica()),
      Message::RequestPrepareRange(m) => self.sender_is_member(from, m.replica()),
      Message::Recovery(m) => self.sender_is_member(from, m.replica()),
      Message::RequestSync(m) => self.sender_is_member(from, m.replica()),
      Message::RecoveryResponse(m) => self.sender_is_member(from, m.replica()),
      Message::SyncCheckpoint(m) => self.sender_is_member(from, m.replica()),
      // The chunked state-sync trio all carry a self `replica()`: the announce + chunk are serves
      // from ANY Normal member (like `SyncCheckpoint`); the chunk pull is a solicitation (like
      // `RequestSync`). All bind to the claimed self id + the full membership range.
      Message::SyncCheckpointMeta(m) => self.sender_is_member(from, m.replica()),
      Message::RequestSyncChunk(m) => self.sender_is_member(from, m.replica()),
      Message::SyncChunk(m) => self.sender_is_member(from, m.replica()),
      // Primary-authority broadcasts (no self id): only the primary of the advertised view sends them.
      Message::Commit(m) => from == Peer::Replica(self.membership.primary(m.view())),
      Message::StartView(m) => from == Peer::Replica(self.membership.primary(m.view())),
      // `PrepareBatch` is the primary's BATCHED retransmit of its un-acked window — unlike the
      // path-sensitive `Prepare` it has NO repair-serve role (the windowed repair answer is
      // `RepairBatch`), so it binds strictly to `config.primary(view)` like `Commit`/`StartView`. A
      // batch from any other peer is forged/misrouted: each entry would otherwise reconstruct a
      // head-advancing `Prepare` that drives a backup's append + PrepareOk vote.
      Message::PrepareBatch(m) => from == Peer::Replica(self.membership.primary(m.view())),
      // `Prepare` is PATH-SENSITIVE. A NORMAL head-advancing / re-ack Prepare
      // comes ONLY from the primary of its advertised view — binding it to `config.primary(view)` closes
      // the gap where a misrouted non-primary replica Prepare drives a backup's normal append + PrepareOk.
      // But a committed-op REPAIR serve (answering our `RequestPrepare` for a hole in `self.repair`)
      // legitimately comes from ANY Normal holder, so ALSO accept a Prepare whose op is one of our
      // registered repair holes — but ONLY from a CONFIGURED MEMBER `from` (`< node_count`): a
      // repair-serve is always a peer replica that holds the committed op, NEVER a client or an
      // out-of-range id. A non-voting member holding a committed op can serve it (the escape carries no
      // quorum authority — `fill_repair` independently verifies the body). Without the member guard, an
      // authenticated `Peer::Client` (or an out-of-range `Peer::Replica`) whose forged/misrouted
      // Prepare's op happened to be one of our holes passed ingress and reached `fill_repair` (which
      // checks only commit>=op + `Header::verify` self-consistency, BEFORE any role check), so a
      // buggy/misrouting driver could fill a committed hole from a non-member peer. (`fill_repair` then
      // verifies the body — checksum + the commit>=op committed-vouch — and a hole-targeted Prepare it
      // DECLINES is dropped by the hole-ownership guard in `on_prepare` before any view catch-up, so the
      // `repair` escape cannot inject a bad body nor drive a spurious catch-up; a repair op is
      // `<= self.op`, so it cannot advance the head.)
      Message::Prepare(p) => {
        from == Peer::Replica(self.membership.primary(p.view()))
          || (matches!(from, Peer::Replica(r) if r.get() < self.membership.node_count())
            && self.repair.contains(&p.op().get()))
      }
      // `RepairBatch` is the windowed analogue of a repair-serve `Prepare`: it carries NO self
      // `replica()` (only a `view()`) and is legitimately sent by ANY Normal holder — incl. a BACKUP or a
      // non-voting member — so it binds to "any CONFIGURED member `from`" (`< node_count`), never a
      // client / out-of-range id. The serve is committed, view-independent content carrying no quorum
      // authority; binding it to `config.primary(view)` would drop an honest backup-originated batch. The
      // narrowing to a member peer is the same guard the `Prepare` repair escape uses; `fill_repair_batch`
      // then runs the per-entry `fill_repair` (placement `repair.contains(op)` + checksum +
      // committed-vouch) on EACH entry, so an unsolicited / forged batch is rejected entry-by-entry
      // exactly like a forged repair `Prepare` — no committed slot is filled from a non-member peer or an
      // unverified body.
      Message::RepairBatch(_) => {
        matches!(from, Peer::Replica(r) if r.get() < self.membership.node_count())
      }
      // `Reply` is ignored by replicas (dropped in the dispatch) — no-op.
      Message::Reply(_) => true,
    }
  }

  /// True iff `from` is the authenticated peer for the self-identifying `claimed` replica AND `claimed`
  /// is a VOTING replica (`< replica_count`). For messages that carry QUORUM / VOTE authority: a
  /// `claimed` outside the voting set — a non-voting member's id, or an out-of-range id — is REJECTED,
  /// so a vote can never reach a quorum bitset / vote map. (The bitset is also `u64`-indexed by the
  /// voter id, so admitting a high id would overflow the shift — another reason a vote stays
  /// voting-bounded.) The range check is the load-bearing half: without it, `from == Peer::Replica(claimed)`
  /// accepts a self-consistent message from a non-member `from` supplied by a buggy/misrouting driver.
  fn sender_is_voter(&self, from: Peer, claimed: ReplicaId) -> bool {
    claimed.get() < self.membership.replica_count() as u16 && from == Peer::Replica(claimed)
  }

  /// True iff `from` is the authenticated peer for the self-identifying `claimed` replica AND `claimed`
  /// is a CONFIGURED cluster MEMBER (`< node_count` — a voter OR a non-voting member). For messages that
  /// SERVE or SOLICIT committed content: a non-voting member legitimately solicits committed state and
  /// can serve committed content to others, so it is a valid sender; only an OUT-OF-RANGE id (a
  /// non-member, `>= node_count`) is rejected. These messages carry no quorum authority — the content is
  /// verified independently downstream — so admitting the full membership extends no trust the
  /// independent verification does not already gate. Centralized here so every such self-id message
  /// (`GetView`/`Recovery`/`RequestSync`/`SyncCheckpoint`/…) is membership-checked uniformly, not relying
  /// on each handler's own (inconsistent) downstream range check.
  fn sender_is_member(&self, from: Peer, claimed: ReplicaId) -> bool {
    claimed.get() < self.membership.node_count() && from == Peer::Replica(claimed)
  }

  /// The (epoch, config_id) AUTHORITY gate, layered ON TOP of [`Self::sender_matches`]: it admits a
  /// message to the dispatch only when its configuration claim entitles it to the AUTHORITY it would
  /// exercise. `sender_matches` answers "is `from` the slot that may send this kind?"; this answers
  /// "is the SENDER's configuration mine?". One place, every ingress path — the configuration analogue
  /// of the sender-binding chokepoint.
  ///
  /// The matrix (the message's vote/lead/serve authority):
  /// - **STRICT** — `Prepare`(normal head-advancing arm), `PrepareOk`, `Commit`, `StartViewChange`,
  ///   `DoViewChange`, `StartView`, `GetView`, `Recovery`, `RecoveryResponse`, `PrepareBatch`: the
  ///   message drives an APPEND / VOTE / VIEW-ADOPTION in MY configuration, so it is admitted only on
  ///   an exact `(epoch, config_id)` match. A foreign-epoch / foreign-config message contributes
  ///   NOTHING (dropped for authority) — a peer in a different configuration neither votes in mine nor
  ///   makes me adopt its view.
  /// - **AGNOSTIC** — `RequestPrepare`, `RequestPrepareRange`, `RepairBatch`, `RequestSync`,
  ///   `RequestSyncChunk`, `SyncCheckpoint`, `SyncCheckpointMeta`, `SyncChunk`: committed,
  ///   view-independent content carrying NO vote/lead authority (verified independently downstream —
  ///   checksum + committed-vouch / checkpoint-id), so it is admitted from any config IN MY LINEAGE
  ///   ([`Self::in_lineage`]), letting a node catch up across an epoch boundary.
  /// - **NEITHER** — `Request`, `Reply`: client-facing, carry no `(epoch, config_id)` — always
  ///   admitted here.
  ///
  /// PATH-SENSITIVE `Prepare`: the two arms (`on_prepare`) carry DIFFERENT authority. The repair-serve
  /// arm (the op is one of our `repair` holes) serves committed, view-independent content, so it is
  /// AGNOSTIC — gated here on `in_lineage(config_id)` only (the arm common to both `Prepare` paths in
  /// PR1, where in-lineage == same-config). The normal head-advancing arm (`from == primary`) DRIVES an
  /// append + a `PrepareOk` vote, so it is STRICT — but its EPOCH check cannot be made here without
  /// knowing the arm, so it is branched INSIDE `on_prepare` (an `epoch == self.epoch` guard on the
  /// normal arm, after the repair arm has had its chance). This central gate therefore admits a
  /// `Prepare` iff its `config_id` is in lineage; the normal arm then additionally proves the epoch.
  fn epoch_authority_admits(&self, msg: &Message) -> bool {
    match msg {
      // STRICT: exact (epoch, config_id) — drives append / vote / view-adoption in my configuration.
      Message::PrepareOk(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::Commit(m) => m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id()),
      Message::StartViewChange(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::DoViewChange(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::StartView(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::GetView(m) => m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id()),
      Message::Recovery(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::RecoveryResponse(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::PrepareBatch(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      // PATH-SENSITIVE `Prepare`: gate the config_id (common to both arms); the normal arm's epoch
      // check is branched inside `on_prepare`. A foreign-lineage Prepare is dead on BOTH arms.
      Message::Prepare(m) => self.in_lineage(m.config_id()),
      // AGNOSTIC: in-lineage only — committed, view-independent content with no vote/lead authority.
      Message::RequestPrepare(m) => self.in_lineage(m.config_id()),
      Message::RequestPrepareRange(m) => self.in_lineage(m.config_id()),
      Message::RepairBatch(m) => self.in_lineage(m.config_id()),
      Message::RequestSync(m) => self.in_lineage(m.config_id()),
      Message::RequestSyncChunk(m) => self.in_lineage(m.config_id()),
      Message::SyncCheckpoint(m) => self.in_lineage(m.config_id()),
      Message::SyncCheckpointMeta(m) => self.in_lineage(m.config_id()),
      Message::SyncChunk(m) => self.in_lineage(m.config_id()),
      // NEITHER: client-facing, no (epoch, config_id) to check.
      Message::Request(_) | Message::Reply(_) => true,
    }
  }
}

/// The state-machine-driving operations: the `handle_*` ingress/timeout/storage entry points and the
/// poll/timer machinery they reach. These transitively invoke `S::apply`/`snapshot`/`restore` (via the
/// submodule consensus methods), so — per the method-local-bounds rule — they carry `S: StateMachine`
/// here, while the pure accessors/observers above stay unconstrained (callable on any `Endpoint<S>`).
impl<S> Endpoint<S>
where
  S: StateMachine,
{
  /// Feeds an incoming protocol message. Runs `assert_invariants` at exit (TigerBeetle's `assert_main`)
  /// so the `(status × sub-state-flag)` coupling is re-checked after EVERY ingress, across all of
  /// `handle_message_inner`'s early-return paths.
  pub fn handle_message<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    self.handle_message_inner(now, wal, sb, from, msg);
    #[cfg(debug_assertions)]
    self.assert_invariants();
  }

  /// The body of [`Self::handle_message`]; see it for the exit-time invariant check that wraps this.
  fn handle_message_inner<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    from: Peer,
    msg: Message,
  ) {
    // Sender-binding backstop: drop any message whose self-claimed identity disagrees
    // with the authenticated `from`. Placed at the TOP — BEFORE the Recovering/RecoveringHead
    // early-returns — so it ALSO guards those states' message exceptions (a RecoveringHead adopting a
    // `StartView`/`RecoveryResponse`; a Recovering replica fetching a peer `SyncCheckpoint`), not only
    // the normal dispatch. This is the ingress analogue of the `emit` egress chokepoint: one place,
    // every path. See [`Self::sender_matches`] for the per-kind bindings + the `Prepare` exception.
    if !self.sender_matches(from, &msg) {
      return;
    }
    // Configuration-authority backstop, layered ON TOP of `sender_matches`: a message whose claimed
    // (epoch, config_id) does not entitle it to the AUTHORITY it would exercise contributes NOTHING.
    // STRICT messages (the vote/lead drivers) require an exact (epoch, config_id) match; AGNOSTIC
    // serves/solicitations require only an in-lineage `config_id`. Placed HERE — at the same ingress
    // chokepoint as `sender_matches`, BEFORE the Recovering/RecoveringHead exceptions — so a
    // foreign-configuration `StartView`/`RecoveryResponse` cannot drive a RecoveringHead's head
    // adoption, nor a foreign-lineage `SyncCheckpoint` an awaiting-checkpoint Recovering replica's
    // restore. `Prepare` is admitted here on its `config_id` lineage only; its STRICT normal-arm epoch
    // check is branched inside `on_prepare` (the repair-serve arm stays AGNOSTIC). See
    // [`Self::epoch_authority_admits`].
    if !self.epoch_authority_admits(&msg) {
      return;
    }
    // A Recovering replica does NOT process ANY consensus message: it is still draining its own
    // durable storage (the async `handle_storage` loop) and does not even know its true head yet, so
    // it casts no PrepareOk/vote/DVC and adopts no peer's view until it reaches Normal. This also
    // blocks the higher-view `catch_up_to_view` pre-checks inside the per-message handlers (which
    // would otherwise yank a recovering replica into ViewChange mid-recovery).
    //
    // The ONE exception: a replica whose OWN durable checkpoint read exhausted its budget cannot
    // restore its SM from disk and is FETCHING the checkpoint from a peer (`awaiting_peer_checkpoint`).
    // It must accept the answering `SyncCheckpoint` — mirroring how a `RecoveringHead` replica accepts
    // a `StartView` to learn its head — and, when the answer is too large for one frame, the chunked
    // form of the SAME answer (`SyncCheckpointMeta` + `SyncChunk`; the assembled envelope re-enters
    // `on_recover_sync_checkpoint`). Every other message is still dropped (it casts no ack/vote).
    if self.status.is_recovering() {
      if self.awaiting_peer_checkpoint() {
        match msg {
          Message::SyncCheckpoint(m) => self.on_recover_sync_checkpoint(now, wal, sb, m),
          Message::SyncCheckpointMeta(m) => self.on_sync_checkpoint_meta(now, m),
          Message::SyncChunk(m) => self.on_sync_chunk(now, wal, sb, m),
          _ => {}
        }
      }
      return;
    }
    // A RecoveringHead replica (its durable head slot is permanently faulty) is the ONE exception:
    // it cannot recover its head from its own disk, so it must LEARN the canonical head from an
    // authoritative peer. We relax the guard for EXACTLY the two head-learning messages — a
    // `StartView` (the new primary's full canonical log+head+commit) and a `RecoveryResponse` from
    // the primary (the recovery-handshake equivalent). It still does NOT participate: every other
    // message (Prepare/PrepareOk/Commit/SVC/DVC/GetView/Request) is dropped, so it casts no ack/vote
    // until adoption returns it to Normal.
    //
    // A peer's `Recovery` is the THIRD relaxed message — but it is TALLIED, not answered: a replica
    // that cannot read its own head has no canonical head to hand out, so it emits NOTHING here. It
    // records the soliciting VOTER's slot in `peers_recovering` (G2 of the re-formation gate), so the
    // `recover_head_timeouts` escalation can detect a co-recovering voting quorum (the all-`RecoveringHead` wedge:
    // an all-restart left a quorum in `RecoveringHead` with no `Normal` node to answer). This arm is
    // STRICTLY AFTER `sender_matches` + `epoch_authority_admits` above, so only an in-configuration
    // member is tallied; it is NOT on the `emit` egress path (zero emission → byte-identity safe).
    if self.status.is_recovering_head() {
      match msg {
        Message::StartView(m) => self.on_start_view(now, wal, sb, m),
        Message::RecoveryResponse(m) => self.on_recovery_response(now, wal, sb, m),
        Message::Recovery(m) => {
          // Tally a co-recovering VOTER (only a voter counts toward the voting quorum G2), with ZERO
          // emission. `sender_matches` already bound `from` to `m.replica()` and admitted the full
          // membership range, so re-check the VOTER subset here. The bit is keyed by the sender slot
          // (the `svc_from` shape); `recover_head_timeouts` reads then clears this set per window.
          if self.membership.is_voter(m.replica())
            && let Some(rec) = self.recover.as_mut()
          {
            rec.peers_recovering |= 1u64 << m.replica().get();
          }
        }
        _ => {}
      }
      return;
    }
    match msg {
      Message::Request(r) => self.on_request(now, wal, from, r),
      Message::Prepare(p) => self.on_prepare(now, wal, sb, p),
      Message::PrepareBatch(m) => self.on_prepare_batch(now, wal, sb, m),
      Message::PrepareOk(ok) => self.on_prepare_ok(now, sb, ok),
      Message::Commit(c) => self.on_commit(now, sb, c),
      Message::StartViewChange(m) => self.on_start_view_change(now, sb, m),
      Message::DoViewChange(m) => self.on_do_view_change(now, wal, sb, m),
      Message::StartView(m) => self.on_start_view(now, wal, sb, m),
      Message::GetView(m) => self.on_get_view(now, m),
      Message::RequestPrepare(m) => self.on_request_prepare(now, m),
      Message::RequestPrepareRange(m) => self.on_request_prepare_range(now, m),
      Message::Recovery(m) => self.on_recovery(now, m),
      Message::RecoveryResponse(m) => self.on_recovery_response(now, wal, sb, m),
      // State-sync: a peer's sync solicitation is answered from our durable checkpoint
      // (`on_request_sync`); a sync response is verified + applied (`on_sync_checkpoint`).
      Message::RequestSync(m) => self.on_request_sync(now, sb, m),
      Message::SyncCheckpoint(m) => self.on_sync_checkpoint(now, wal, sb, m),
      Message::RepairBatch(m) => self.on_repair_batch(now, wal, sb, m),
      // Chunked state-sync: a peer's chunk pull is served from the donor cache / a cold-cache read;
      // an announce pins (or re-pins) this replica's own transfer; a chunk extends it (the assembled
      // envelope re-enters the `SyncCheckpoint` path above).
      Message::RequestSyncChunk(m) => self.on_request_sync_chunk(now, sb, m),
      Message::SyncCheckpointMeta(m) => self.on_sync_checkpoint_meta(now, m),
      Message::SyncChunk(m) => self.on_sync_chunk(now, wal, sb, m),
      Message::Reply(_) => {}
    }
  }

  /// Fires any timers due at `now`, dispatching by status/role.
  pub fn handle_timeout<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    match self.status {
      Status::Normal if self.is_primary() => {
        self.primary_timeouts(now, sb);
        // Body-aware nack-truncation grace expiry: run AFTER the heartbeat, on the Normal-primary path.
        // It self-gates on `participates_as_primary() && !pending_forfeit` (matching
        // `serviceable_now(RepairOrTruncate)`), so it truncates only when the view is durable and the
        // primary is not stepping down; in those windows the deadline is preserved (non-serviceable, so
        // poll_timeout-filtered + ignored by the no-orphan assert — no spin).
        self.repair_or_truncate_timeouts(now, wal);
      }
      Status::Normal => {
        // backup: bootstrap + fire primary_idle, then re-arm THIS timer only so we
        // re-propose at the primary_idle cadence (not every tick). A non-voting learner never arms
        // primary_idle (`arm_primary_idle` is a no-op for it), so this whole proposal path stays inert:
        // it never proposes a view change and never retransmits an SVC — it only follows the primary.
        if self.timers.primary_idle.is_none() {
          self.arm_primary_idle(now);
        }
        if self.timers.primary_idle.is_some_and(|d| d <= now) {
          self.on_primary_idle(now, sb);
          self.arm_primary_idle(now);
        }
        // Once this backup has PROPOSED a view change off
        // its idle timeout (`on_primary_idle` -> `propose_next_view` -> `join_svc`), it ARMS `svc_message`
        // (the SVC retransmit) — but until a view-change quorum forms it stays Normal, and this branch
        // would otherwise service ONLY `primary_idle`, orphaning `svc_message` (`view_change_timeouts`,
        // which services it, runs only in ViewChange). A poll_timeout()-driven driver would then spin on
        // the unserviced `svc_message` deadline (100ms — EARLIER than `primary_idle`'s 200ms), never
        // re-broadcasting the StartViewChange under loss → no failover. So SERVICE `svc_message` here when
        // armed-and-due: re-broadcast the live `StartViewChange{svc_target}` on the VC_MESSAGE_RETRANSMIT
        // cadence (exactly as `view_change_timeouts` does), keeping the proposal alive until a quorum forms
        // or a heard primary clears the idle path. The `primary_idle` re-propose above is idempotent at
        // `view+1` (`propose_next_view` only raises the target), so any overlap is a harmless redundant
        // SVC; firing the retransmit only when DUE (and on a strictly later cadence boundary than the
        // 200ms idle) keeps the steady-state broadcast count minimal. Cleared when the backup leaves the
        // proposal: `note_primary_contact` does NOT disarm `svc_message`, but a heard primary that resets
        // `primary_idle` stops new proposals, and any real view-change transition re-arms timers afresh.
        if self.timers.svc_message.is_some_and(|d| d <= now) {
          self.push_svc(self.svc_target);
          self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
        }
      }
      Status::ViewChange => self.view_change_timeouts(now, sb),
      // Recovering re-submits any still-outstanding/faulty reads on its timer (termination under a
      // dropped completion / slow-clearing transient). RecoveringHead re-broadcasts its Recovery
      // solicitation until a peer hands it the canonical head.
      Status::Recovering => self.recover_timeouts(now, wal, sb),
      Status::RecoveringHead => self.recover_head_timeouts(now, sb),
    }
    // Peer fault-repair retransmit runs only in Normal (the only status that can solicit/serve a hole
    // and adopt the reply). It re-solicits every unrepaired committed-op hole until each is filled.
    if self.status.is_normal() {
      self.repair_timeouts(now);
      // State-sync re-solicitation likewise runs only in Normal: re-broadcast RequestSync while a
      // sync is outstanding (awaiting a SyncCheckpoint or persisting the adopted one).
      self.sync_timeouts(now);
    }
    // No-orphan-due invariant: after dispatch, NO serviceable timer may remain armed-and-due
    // (`serviceable_now(kind) && armed(kind) <= now`). `poll_timeout` returns only serviceable timers, so
    // every such timer either was just serviced (re-armed strictly forward, or cleared) or was never
    // serviceable (filtered out). If one is left armed-and-due, a poll_timeout()-driven driver would
    // re-return it next step and SPIN — exactly the timer-wedge this refactor closes. This fires
    // DETERMINISTICALLY (independent of the clock model) on any future arm/service drift, so the existing
    // test + VOPR suite now guard the whole class (the tick-driven sim cannot SEE the spin, but it CAN
    // trip this assert). The bound `now` is the `now` handlers re-armed against; a serviced timer re-arms
    // to `now + cadence > now`, so it is correctly not-due here.
    debug_assert!(
      !TimerKind::ALL
        .into_iter()
        .any(|kind| self.serviceable_now(kind) && self.armed(kind).is_some_and(|d| d <= now)),
      "handle_timeout left a serviceable timer armed-and-due (would spin a poll_timeout driver): {:?}",
      TimerKind::ALL
        .into_iter()
        .find(|&kind| self.serviceable_now(kind) && self.armed(kind).is_some_and(|d| d <= now))
        .map(TimerKind::as_str)
    );
    // Re-check the (status × sub-state-flag) coupling at every timeout exit (see `assert_invariants`).
    #[cfg(debug_assertions)]
    self.assert_invariants();
  }

  /// Drain completed storage ops and react.
  pub fn handle_storage<W: Wal, B: Superblock>(&mut self, now: Instant, wal: &mut W, sb: &mut B) {
    while let Some(done) = wal.poll() {
      self.on_wal_done(now, wal, sb, done);
    }
    while let Some(done) = sb.poll() {
      self.on_sb_done(now, wal, sb, done);
    }
    // Re-check the (status × sub-state-flag) coupling at every storage-drain exit (see
    // `assert_invariants`) — the async superblock/WAL completions are where the flag transitions land.
    #[cfg(debug_assertions)]
    self.assert_invariants();
  }

  /// Arms the `primary_idle` deadline — but never for a non-voting learner, which has no view-change
  /// vote to cast and so never proposes a view change on an idle primary. Centralizing the arm here
  /// keeps every site that defers the idle timeout (`note_primary_contact`, the `handle_timeout`
  /// bootstrap/re-arm, the `arm_timers` Normal-backup role arm) learner-aware through one predicate.
  fn arm_primary_idle(&mut self, now: Instant) {
    if !self.is_learner() {
      self.timers.primary_idle = Some(now + PRIMARY_IDLE);
    }
  }

  /// (Re)arms this replica's timers for its current role/status.
  fn arm_timers(&mut self, now: Instant) {
    // clear all, then set the ones for this role. PRESERVE the forfeit grace timer across the reset:
    // it is a Normal-primary heartbeat-path deadline that a stuck primary keeps ticking even as it
    // appends new client ops (which call `arm_timers`), so re-zeroing it here would let a steady client
    // load perpetually restart the grace window and the primary would never forfeit. The forfeit
    // lifecycle owns its own arm/disarm (`maybe_forfeit`/`forfeit`, the `primary_timeouts` forfeit
    // branch, and every view-change transition's `reset_for_view_transition`); `arm_timers` is a
    // role-timer (re)arm and must leave it exactly as it found it (matching the pre-fold behavior, when
    // `forfeit_armed` lived OUTSIDE `Timers` and `Timers::default()` could not touch it).
    let forfeit_armed = self.timers.forfeit_armed;
    // PRESERVE the body-aware nack-truncation grace across the role-timer reset for the same reason as
    // `forfeit_armed`: it is a deadline armed by `start_view_as_new_primary` that must survive the
    // durable-view-write window (which routes through `start_view_participate` → `arm_timers`) and any
    // client-append `arm_timers`, so re-zeroing it here would lose the candidate's truncation clock. Its
    // lifecycle is owned by the arm/fill-cancel/expiry/view-transition sites, never by this role re-arm.
    let repair_or_truncate = self.timers.repair_or_truncate;
    // PRESERVE an already-armed EARLIER `commit`/`prepare` deadline (the Normal-primary arm below
    // re-arms with `min(existing, now + interval)`): every accepted client request ends in
    // `arm_timers`, so re-arming to `now + interval` unconditionally lets a steady sub-interval
    // request cadence slide the prepare-retransmit deadline forever — one lost Prepare broadcast
    // under sustained load then never retransmits (the backups buffer the tail above the loss and
    // their commit wedges below it until the load pauses a full interval). The deadline may only
    // move EARLIER here; the forward re-arm after servicing belongs to `primary_timeouts` alone. No
    // stale deadline can leak across generations: every transition out of Normal-primary clears both
    // (this reset on the non-primary arms, plus the forfeit/pending-view retire branches), so a
    // preserved deadline always originates in the current Normal-primary stint.
    let prior_commit = self.timers.commit;
    let prior_prepare = self.timers.prepare;
    self.timers = Timers::default();
    self.timers.forfeit_armed = forfeit_armed;
    self.timers.repair_or_truncate = repair_or_truncate;
    match self.status {
      Status::Normal if self.is_primary() => {
        let commit = now + COMMIT_HEARTBEAT;
        self.timers.commit = Some(prior_commit.map_or(commit, |d| d.min(commit)));
        if self.commit_min.get() < self.op.get() {
          let prepare = now + PREPARE_RETRANSMIT;
          self.timers.prepare = Some(prior_prepare.map_or(prepare, |d| d.min(prepare)));
        }
      }
      Status::Normal => {
        self.arm_primary_idle(now);
      }
      Status::ViewChange if self.catching_up() => {
        self.timers.get_view_message = Some(now + VC_MESSAGE_RETRANSMIT);
        // A catching-up replica re-solicits StartView via `get_view_message`; only a voter also arms
        // `view_change_status`, the timer whose expiry ESCALATES a stalled catch-up into actively
        // driving the next view. A learner never escalates — it stays catching up until it adopts a
        // StartView — so it leaves `view_change_status` disarmed and follows the voters' change.
        if !self.is_learner() {
          self.timers.view_change_status = Some(now + VIEW_CHANGE_STATUS);
        }
      }
      Status::ViewChange => {
        self.timers.svc_message = Some(now + VC_MESSAGE_RETRANSMIT);
        self.timers.dvc_message = Some(now + VC_MESSAGE_RETRANSMIT);
        self.timers.view_change_status = Some(now + VIEW_CHANGE_STATUS);
      }
      // Recovering: re-submit any still-outstanding/faulty WAL-tail (+ checkpoint) reads on a cadence,
      // so the loop terminates even if a real async driver drops a completion or a transient fault
      // only clears on a later read.
      Status::Recovering => {
        self.timers.recover_retry = Some(now + RECOVER_READ_RETRANSMIT);
      }
      // RecoveringHead: re-broadcast the `Recovery` solicitation on a cadence. A permanently-faulty
      // head cannot be repaired from local disk, so the replica solicits the canonical head from a
      // peer until a `RecoveryResponse`/`StartView` re-establishes it (then adoption arms the Normal
      // timers).
      Status::RecoveringHead => {
        self.timers.recover_head = Some(now + RECOVER_HEAD_SOLICIT);
      }
    }
    // Peer fault-repair runs alongside the role timers: while a committed-op hole is outstanding AND we
    // are Normal, keep the repair-retry timer armed. The `is_normal()` gate MUST match `handle_timeout`'s
    // servicing gate (which runs `repair_timeouts` only while Normal): a `repair` hole is NOT cleared on
    // entering ViewChange/catch-up, so arming `repair_retry` in a non-Normal status would leave it
    // armed-but-never-serviced (`view_change_timeouts` ignores it), spinning a poll_timeout()-driven
    // driver on that stale deadline — the SAME timer-level wedge as the forfeit / pending-view cases
    //. Gating the ARM on the same condition as the SERVICE keeps the two in
    // lockstep, so no orphaned hole-timer can wake a non-Normal handler. (`arm_timers` clears all timers
    // first, so an inherited Normal `repair_retry` is dropped on the transition into ViewChange.) The
    // hole itself survives — it is re-solicited once Normal resumes (adoption clears it, or
    // `request_repair`/`repair_timeouts` re-arm `repair_retry` then).
    if self.status.is_normal() && !self.repair.is_empty() {
      self.timers.repair_retry = Some(now + REPAIR_RETRANSMIT);
    }
    // State-sync solicitation runs alongside the role timers: while a sync is outstanding (awaiting a
    // SyncCheckpoint or persisting the adopted one), keep re-soliciting. Only Normal triggers/serves a
    // sync, so a non-Normal status structurally carries no `sync` (it is cleared on durability).
    if self.sync.is_some() {
      self.timers.sync_solicit = Some(now + SYNC_SOLICIT);
    }
  }

  /// The single outbound-emission chokepoint. EVERY replica-originated message goes through here so the
  /// durable-view-before-participate invariant is enforced in ONE place: a view-advertising
  /// AUTHORITY / participation message (the gated set — [`Message::advertises_authoritative_view`]) must
  /// never be emitted while a durable-view write is in flight (`pending_sb.is_some()`), because
  /// `self.view` is then not yet durable and a crash rolls it back. This is the proto-side analogue of
  /// the VOPR durable-view checker, and the STRUCTURAL close of the class: a NEW emission site cannot
  /// bypass the per-site gates because it routes here. The `debug_assert!` is detection (it fails fast
  /// in every test/sim at the emission site, with zero release cost) — the per-site gates
  /// (`participates_as_primary`, the dvc gate, the
  /// `on_request_prepare` / `on_recovery` / `serve_sync_checkpoint` `pending_sb` drops) remain the
  /// PREVENTION; this assert proves they are COMPLETE.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn emit(&mut self, out: Outgoing) {
    debug_assert!(
      !out.msg_ref().advertises_authoritative_view() || self.pending_sb.is_none(),
      "durable-view-before-participate: emitted {} while a durable-view write is pending",
      out.msg_ref().kind_str(),
    );
    self.outgoing.push_back(out);
  }

  /// Pulls the next message to send, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_message(&mut self) -> Option<Outgoing> {
    self.outgoing.pop_front()
  }

  /// Pulls the next application event, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_event(&mut self) -> Option<Event> {
    self.events.pop_front()
  }

  /// The currently-armed deadline for `kind` (the single field accessor backing both the `poll_timeout`
  /// filter and the `handle_timeout` no-orphan assert). `None` if that timer is not armed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  const fn armed(&self, kind: TimerKind) -> Option<Instant> {
    match kind {
      TimerKind::Prepare => self.timers.prepare,
      TimerKind::Commit => self.timers.commit,
      TimerKind::PrimaryIdle => self.timers.primary_idle,
      TimerKind::SvcMessage => self.timers.svc_message,
      TimerKind::DvcMessage => self.timers.dvc_message,
      TimerKind::ViewChangeStatus => self.timers.view_change_status,
      TimerKind::GetViewMessage => self.timers.get_view_message,
      TimerKind::RecoverRetry => self.timers.recover_retry,
      TimerKind::RecoverHead => self.timers.recover_head,
      TimerKind::RepairRetry => self.timers.repair_retry,
      TimerKind::SyncSolicit => self.timers.sync_solicit,
      TimerKind::ForfeitArmed => self.timers.forfeit_armed,
      TimerKind::RepairOrTruncate => self.timers.repair_or_truncate,
    }
  }

  /// The SINGLE SOURCE OF TRUTH for "will the CURRENT (status, substate) actually SERVICE `kind` if it
  /// fires?" — i.e. does some branch of [`Self::handle_timeout`] act on this timer in this exact state?
  /// It MIRRORS `handle_timeout`'s status dispatch + the per-handler substate gates EXACTLY.
  /// [`Self::poll_timeout`] filters every armed timer through this so it can NEVER return a
  /// deadline the current state will not act on; the `debug_assert` at the end of `handle_timeout`
  /// enforces the converse (no serviceable timer is left armed-and-due) so any future arm/service drift
  /// trips deterministically (regardless of clock model — so the tick-driven VOPR catches it too). The
  /// timer-wedge spin class (a deadline-driven driver re-returning a stale, never-serviced deadline) is
  /// thereby closed by construction, not patched per-site.
  ///
  /// The table (each clause verified against the handler that services the timer):
  /// - `commit` / `prepare` / `forfeit_armed`: the Normal-primary HEARTBEAT path
  ///   (`primary_timeouts`) reaches the heartbeat/retransmit/`maybe_forfeit` ONLY when NOT stepping
  ///   down (`!pending_forfeit`) and the view IS durable (`pending_sb.is_none()`); both early-return
  ///   branches RETIRE these timers, so they are serviceable exactly on `participates_as_primary() &&
  ///   !pending_forfeit`.
  /// - `primary_idle`: the Normal-BACKUP branch.
  /// - `svc_message`: re-broadcast by the Normal-primary forfeit re-propose (`pending_forfeit`), by the
  ///   Normal-BACKUP idle-SVC retransmit, and by `view_change_timeouts` while not catching up.
  /// - `dvc_message`: `view_change_timeouts`, not catching up, AND the view is durable
  ///   (`pending_sb.is_none()`) — the DVC is a vote, so it must not be (re)cast before the view is
  ///   recoverable (durable-view-before-participate in the retransmit path).
  /// - `view_change_status`: `view_change_timeouts` (armed + serviced in BOTH catch-up and not).
  /// - `get_view_message`: `view_change_timeouts`, catching up.
  /// - `recover_retry`: `recover_timeouts` (Recovering).
  /// - `recover_head`: `recover_head_timeouts` (RecoveringHead).
  /// - `repair_retry`: `repair_timeouts` (Normal only — the `handle_timeout` gate).
  /// - `sync_solicit`: `sync_timeouts` (Normal ONLY). While `Recovering`+awaiting-peer the `RequestSync`
  ///   re-solicit rides the `recover_retry` deadline (`recover_timeouts`), NOT `sync_solicit` — so the
  ///   `sync_solicit` deadline itself is NOT serviced there and must be filtered out of `poll_timeout`
  ///   (a corrected entry vs. the draft table: had it been left "Recovering too", a `sync_solicit`
  ///   armed during the peer-fetch would have been the very spin this refactor forbids).
  fn serviceable_now(&self, kind: TimerKind) -> bool {
    match kind {
      // The Normal-primary heartbeat tick services these only when NOT forfeiting and the view is
      // durable; the `pending_forfeit` and `pending_sb` branches of `primary_timeouts` retire them.
      // `repair_or_truncate` (the body-aware truncation grace) rides the SAME gate: `handle_timeout`'s
      // Normal-primary arm runs `repair_or_truncate_timeouts` AFTER `primary_timeouts`, but that method
      // itself early-returns under `pending_forfeit`/`pending_sb` WITHOUT clearing the deadline (it must
      // survive both windows — a forfeiting / not-yet-durable primary must not truncate, but the
      // candidate is still pending). So it is serviceable exactly when `commit`/`prepare` are, and is
      // (like them) non-serviceable — hence poll_timeout-filtered and ignored by the no-orphan assert —
      // during those windows, where it is preserved for the post-window tick to act on.
      TimerKind::Commit
      | TimerKind::Prepare
      | TimerKind::ForfeitArmed
      | TimerKind::RepairOrTruncate => self.participates_as_primary() && !self.pending_forfeit,
      // A non-voting learner never proposes or escalates a view change, so the whole vote/idle timer
      // plane (`primary_idle`, `svc_message`, `dvc_message`, `view_change_status`) is non-serviceable
      // for it — it never arms them, and this keeps the no-orphan-due assert satisfied if a stale
      // deadline ever lingered. Its only view-change timer is `get_view_message` (the catch-up re-solicit).
      TimerKind::PrimaryIdle => self.status.is_normal() && !self.is_primary() && !self.is_learner(),
      // Three disjoint servicers (see the doc): forfeit re-propose, backup retransmit, or the
      // active view-change driver.
      TimerKind::SvcMessage => {
        !self.is_learner()
          && ((self.status.is_normal() && self.is_primary() && self.pending_forfeit)
            || (self.status.is_normal() && !self.is_primary())
            || (self.status.is_view_change() && !self.catching_up()))
      }
      // The DVC retransmit is a VOTE the new primary counts toward forming the view, so it is
      // serviceable only once this replica's view is DURABLE — durable-view-before-participate in the
      // retransmit path. `enter_view_change` arms `dvc_message` AND submits the
      // SendDoViewChange durable-view write (`pending_sb`), and the INITIAL DVC is sent by `on_sb_done`
      // when that write lands; gating the retransmit on `pending_sb.is_none()` keeps a slow async
      // superblock write from letting the retransmit cast the vote first (before the view is
      // recoverable). Kept in lockstep with the `view_change_timeouts` handler so the no-orphan-due
      // assert holds (an armed-and-due `dvc_message` during `pending_sb` is now non-serviceable, so the
      // assert ignores it and `poll_timeout` filters it out — no spin, no premature vote). The other
      // ViewChange retransmit timers stay ungated: `svc_message`/`view_change_status` re-broadcast a
      // *request-to-change* (an SVC), not a vote, and `get_view_message` is a catch-up READ that (by the
      // `catching_up` discriminant) never coexists with the SendDoViewChange `pending_sb` window.
      TimerKind::DvcMessage => {
        !self.is_learner()
          && self.status.is_view_change()
          && !self.catching_up()
          && self.pending_sb.is_none()
      }
      TimerKind::ViewChangeStatus => self.status.is_view_change() && !self.is_learner(),
      TimerKind::GetViewMessage => self.status.is_view_change() && self.catching_up(),
      TimerKind::RecoverRetry => self.status.is_recovering(),
      TimerKind::RecoverHead => self.status.is_recovering_head(),
      // `handle_timeout` runs `repair_timeouts`/`sync_timeouts` only while Normal.
      TimerKind::RepairRetry | TimerKind::SyncSolicit => self.status.is_normal(),
    }
  }

  /// The earliest SERVICEABLE timer deadline, if any.
  ///
  /// Returns the minimum over ONLY the timers the current (status, substate) will actually SERVICE
  /// (the internal `serviceable_now` predicate) — NOT over every armed timer. A deadline this returns is therefore
  /// always one that the next `handle_timeout` acts on (services/re-arms forward or clears), so a
  /// deadline-driven driver that advances virtual time to it and fires it ALWAYS makes progress: it can
  /// never re-return a stale, never-serviced deadline and spin (the timer-wedge class).
  /// Deadlines stay STATEFUL: this only FILTERS what is considered; it never resets a timer (the
  /// handlers own arming/clearing).
  pub fn poll_timeout(&self) -> Option<Instant> {
    TimerKind::ALL
      .into_iter()
      .filter(|&kind| self.serviceable_now(kind))
      .filter_map(|kind| self.armed(kind))
      .min()
  }

  /// Encodes the checkpoint op + client-session table + an SM snapshot into one checkpoint envelope.
  ///
  /// Layout: `checkpoint_op: u64 BE | sessions_len: u32 BE | repeat[ client: u128 BE | request: u64 BE
  /// | last_op: u64 BE | has_reply: u8 | (if has_reply) reply_request: u64 BE, reply_len: u32 BE,
  /// reply_bytes ] | sm_snapshot_bytes`. (The per-session `last_op` is the eviction-ordering stamp —
  /// see [`Session::last_op`]. The envelope has NO cross-version compatibility requirement pre-0.1:
  /// it is consumed only by peers running the same build, so extending the per-session record is a
  /// plain format change, not a migration.)
  ///
  /// **The leading `checkpoint_op` BINDS the op into the content hash (safety).** `checkpoint_id`
  /// is `hash(envelope)`, so a faulty/forged superblock cannot ship STALE snapshot bytes (whose real
  /// frontier is op A) under an OVERSTATED advertised `checkpoint_op = B > A`: the restore paths decode
  /// this leading op and reject the snapshot unless it equals the advertised op, closing the silent
  /// drop of committed ops in `(A, B]`.
  fn encode_checkpoint(op: OpNumber, sessions: &BTreeMap<u128, Session>, snapshot: &[u8]) -> Bytes {
    let mut out = std::vec::Vec::new();
    out.extend_from_slice(&op.get().to_be_bytes());
    out.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
    for (client, s) in sessions {
      out.extend_from_slice(&client.to_be_bytes());
      out.extend_from_slice(&s.request.get().to_be_bytes());
      out.extend_from_slice(&s.last_op.get().to_be_bytes());
      match &s.reply {
        Some((rn, body)) => {
          out.push(1);
          out.extend_from_slice(&rn.get().to_be_bytes());
          out.extend_from_slice(&(body.len() as u32).to_be_bytes());
          out.extend_from_slice(body);
        }
        None => out.push(0),
      }
    }
    out.extend_from_slice(snapshot);
    Bytes::from(out)
  }

  /// Decodes a checkpoint envelope produced by [`Self::encode_checkpoint`] into
  /// `(checkpoint_op, sessions, sm_snapshot_slice)`, or `None` if the bytes are malformed/truncated.
  ///
  /// **Fallible.** A checkpoint read may return a corrupted / stale / torn snapshot
  /// (recover or state-sync over a faulty superblock), so EVERY field access is bounds-checked
  /// (`env.get(..)?`) and returns `None` rather than panicking on an out-of-range index or a
  /// reply-length that overruns the buffer. Callers treat `None` as a FAULT (recover re-reads within
  /// its budget; state-sync rejects the snapshot and re-solicits) — never a restore. The integrity of
  /// the snapshot *content* (that it is the RIGHT checkpoint) is established separately by the
  /// `checkpoint_id` hash check at each call site; this method only guarantees safe *parsing*.
  ///
  /// The decoded `checkpoint_op` (the leading u64) is the op BOUND into the hash: every restore
  /// path verifies it equals the advertised `cr.op()` / `m.checkpoint_op()` BEFORE restoring, so an
  /// overstated advertised op over stale-but-consistent bytes is rejected rather than silently dropping
  /// the committed ops above the snapshot's real frontier.
  fn decode_checkpoint(env: &[u8]) -> Option<(OpNumber, BTreeMap<u128, Session>, &[u8])> {
    // Bounds-checked fixed-width reads: each returns `None` if `[i..i+N]` is out of range.
    fn take_u32(env: &[u8], i: &mut usize) -> Option<u32> {
      let bytes = env.get(*i..*i + 4)?;
      *i += 4;
      Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }
    fn take_u64(env: &[u8], i: &mut usize) -> Option<u64> {
      let bytes = env.get(*i..*i + 8)?;
      *i += 8;
      Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }
    fn take_u128(env: &[u8], i: &mut usize) -> Option<u128> {
      let bytes = env.get(*i..*i + 16)?;
      *i += 16;
      Some(u128::from_be_bytes(bytes.try_into().ok()?))
    }
    let mut i = 0usize;
    let checkpoint_op = OpNumber::with(take_u64(env, &mut i)?); // the BOUND op
    let count = take_u32(env, &mut i)? as usize;
    let mut sessions = BTreeMap::new();
    for _ in 0..count {
      let client = take_u128(env, &mut i)?;
      let request = crate::RequestNumber::with(take_u64(env, &mut i)?);
      let last_op = OpNumber::with(take_u64(env, &mut i)?);
      let has_reply = *env.get(i)?;
      i += 1;
      let reply = if has_reply == 1 {
        let rn = crate::RequestNumber::with(take_u64(env, &mut i)?);
        let len = take_u32(env, &mut i)? as usize;
        let body = Bytes::copy_from_slice(env.get(i..i + len)?);
        i += len;
        Some((rn, body))
      } else {
        None
      };
      sessions.insert(
        client,
        Session {
          request,
          reply,
          last_op,
        },
      );
    }
    // The remaining bytes are the SM snapshot tail (`i <= env.len()` is guaranteed by the checked
    // reads above, so this slice never panics).
    Some((checkpoint_op, sessions, &env[i..]))
  }

  /// Test-only: the checkpoint envelope this endpoint would encode for its CURRENT session table at
  /// `op` (empty SM snapshot) — the byte-level determinism witness (identical tables ⇒ identical
  /// envelope bytes ⇒ identical checkpoint ids).
  #[cfg(test)]
  fn encode_sessions_envelope_for_test(&self, op: u64) -> Bytes {
    Self::encode_checkpoint(OpNumber::with(op), &self.clients, &[])
  }
}

#[cfg(test)]
mod tests;

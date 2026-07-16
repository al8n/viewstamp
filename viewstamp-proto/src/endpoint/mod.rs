use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bytes::Bytes;

use crate::{
  BlockAddress, BlockStore, ClientId, Commit, Config, DoViewChange, Epoch, Event, Header, Instant,
  MemberId, Membership, Message, OpNumber, Outgoing, Peer, Prepare, PrepareOk, Prng, Recipient,
  ReplicaId, Reply, RequestNumber, SlotStatus, StateMachine, Status, Superblock, SuperblockDone,
  View, Wal, WalDone,
};

mod block_sync;
mod checkpoint;
mod forfeit;
mod normal;
mod reconfig;
mod reconfigure;
mod recovery;
mod repair;
mod session_blocks;
mod state_sync;
mod view_change;

pub use reconfig::{
  ProposeMembershipError, Reconfig, ReconfigError, RestartOnly, SingleChange, prepare_restart,
};
pub use recovery::{FormatError, RecoverError, Recovered, Retired, format};

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

/// An append held back by the slot-quiescence fence: its target ring slot still has an older
/// physical write in flight, so submitting it now would race the device — completions may reorder,
/// and the OLD bytes could land LAST, leaving the durable slot holding a value this replica's
/// ack/vote never named. The full submission (the deferred action `kind` plus the exact bytes) waits
/// in `Endpoint::deferred_appends` until the blocking write's completion proves the slot quiesced;
/// `release_deferred_append` then performs the real submit. The op number is the map key.
#[derive(Debug, Clone)]
struct DeferredAppend {
  kind: Pending,
  header: Header,
  body: Bytes,
}

/// What the endpoint does once its pending durable-view (superblock) write completes. A transition
/// records the participation to run *after* the new view is durable. Keyed by the minted `OpId` in
/// `pending_sb`; a superseded (older-view) completion is ignored. Mirrors `Pending`/`on_wal_done`
/// (append-before-ack).
///
/// NOT `Copy`: the [`Self::SwapEpoch`] variant carries the (boxed-member) successor [`Membership`] —
/// the new configuration a committed `Body::Reconfigure` op produced — so the durable root that
/// proves the swap and the in-memory install are driven from ONE staged value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingSbAction {
  SendDoViewChange,
  StartViewAsPrimary,
  AdoptedStartView,
  /// An operator-requested frontier seal ([`Endpoint::seal_committed_frontier`]): the write persists
  /// the current `commit_max` + committed-band headers and has no follow-up participation.
  Seal,
  /// A commit-first epoch swap: a `Body::Reconfigure` op committed under the OLD epoch, and this
  /// durable root carries the staged [`EpochSwap`] (NOT yet installed in memory). On completion
  /// `on_sb_done` calls [`Endpoint::install_membership`] — so the node advertises the new
  /// quorum/voter-set only AFTER a durable root proves the swap (the durable-epoch-before-
  /// participate fence). The swap is held here, not in `self.membership`, for exactly the
  /// STAGE→durable-root window.
  SwapEpoch(EpochSwap),
}

/// The `(reconfigure op, successor membership)` payload of a staged commit-first epoch swap,
/// extracted from the `PendingSbAction::SwapEpoch` variant (and backing `pending_swap`) so its two
/// fields are named + accessor-wrapped. The op number is the CAPTURED reconfigure op — NOT
/// `commit_min`, which advances past it while the primary keeps committing through the staging
/// window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EpochSwap {
  op: OpNumber,
  successor: Membership,
}

impl EpochSwap {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn new(op: OpNumber, successor: Membership) -> Self {
    Self { op, successor }
  }

  /// The captured reconfigure op number the staged swap installs at.
  #[cfg_attr(not(tarpaulin), inline(always))]
  const fn op(&self) -> OpNumber {
    self.op
  }

  /// The staged successor membership (the configuration the committed `Reconfigure` op produced).
  #[cfg_attr(not(tarpaulin), inline(always))]
  const fn successor(&self) -> &Membership {
    &self.successor
  }

  /// Consumes the staged swap, yielding the reconfigure op + the successor to install.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn into_parts(self) -> (OpNumber, Membership) {
    (self.op, self.successor)
  }
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
  /// A STATE-SYNC re-persist staged by [`Endpoint::apply_sync`]: the root completion INSTALLS the synced
  /// state + runs the sync completion bookkeeping (and, on the recovery peer-fetch path, then
  /// `complete_recovery` flips Recovering → Normal).
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
  /// The SM checkpoint DAG root this checkpoint's envelope names. Carried so the root completion can
  /// record it as the new `checkpoint_sm_root` (the live root the block GC marks from).
  sm_root: BlockAddress,
  /// The session-table DAG root this checkpoint's envelope names. Carried so the root completion can
  /// record it as the new `checkpoint_sessions_root` (the second live root the block GC marks from).
  sessions_root: BlockAddress,
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
  /// `true` when this sync is the CROSS-EPOCH crossing fetch: a laggard behind at the OLD epoch fetching the
  /// cluster checkpoint to cross into E+1. Armed by either of the two unified crossing armers
  /// ([`Endpoint::maybe_request_cross_epoch_catchup`]):
  /// - the NON-Normal recovery peer-fetch ([`Endpoint::enter_cross_epoch_peer_fetch`] — `Recovering`); or
  /// - the NORMAL-status SPECULATIVE arm (a behind-but-operational voter stays `Normal` and keeps processing
  ///   same-epoch traffic until the crossing lands — see [`Endpoint::cross_epoch_speculative_sync`]).
  ///
  /// Either way the fetch MUST complete by installing a strictly-higher epoch carrying the successor
  /// membership — it can NOT settle for a below-`target`, same-config, or empty-membership reply (which
  /// `apply_sync` would otherwise install with `successor = None`, exiting STILL at the old epoch). When
  /// set, `apply_sync` REJECTS any non-crossing reply (leaving `sync` armed so the solicit timer
  /// re-fetches), completing only on the `M >= N` successor-membership checkpoint that #1 guarantees
  /// exists; and the crossing install forces `held_tail = false` (the old-epoch tail above `M` is not in
  /// E+1's lineage). An ordinary / non-cross-epoch sync (`false`) keeps the existing empty-membership
  /// `successor = None` behavior byte-identical.
  require_cross_epoch: bool,
}

/// The single outstanding learner-promote-proof challenge the primary issued at
/// [`PromoteLearner`](crate::SingleVoterDelta) propose time — the FRESH safety input the
/// catch-up-then-promote gate ([`Endpoint::propose_membership`]) consumes instead of an accumulated
/// self-report. One at a time (single-writer reconfigure serializes proposals); a new proposal for a
/// different target/head overwrites it ([`Endpoint::learner_proof`] is set anew, re-drawing `nonce`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LearnerProofState {
  /// The learner being promoted (the stable [`MemberId`], so the challenge follows the member across a
  /// slot shift — though the gate re-validates the full `(target, at_op, nonce, epoch, config_id)`
  /// binding regardless).
  target: MemberId,
  /// The head the challenge was issued against (the proposer's `self.op` at challenge time). The mint
  /// re-validates `at_op >= self.op`: if the head advanced past the proven point the proof is stale and
  /// the gate re-challenges.
  at_op: OpNumber,
  /// The per-incarnation freshness token (a bump of `self.nonce`) binding the matching [`LearnerProof`]
  /// reply — a replayed old-nonce reply never validates.
  nonce: u64,
  /// The validated FRESH frontier the matching reply reported (`Some(f)`), or `None` until a matching
  /// [`LearnerProof`] lands. The gate mints only on `Some(f)` with `f >= self.op`; a missing reply (a
  /// crash mid-challenge) leaves this `None` → `ProofPending` persists → no unsafe promotion.
  proof: Option<OpNumber>,
}

/// One in-flight checkpoint serve-read — the value of `sync_serving`, keyed by REQUESTER replica
/// index. Carries the read's correlation id and the latest echoed nonce (a repeat solicitation only
/// refreshes the nonce in place, so the single completion answers the LATEST solicitation). The
/// completion always ships the whole small envelope as one `SyncCheckpoint` (the SM bytes are no
/// longer in the envelope, so the over-frame chunked path is gone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncServe {
  /// The serve-read's `OpId` (matches the completion back to this entry).
  read: u64,
  /// The latest nonce the requester solicited with (echoed in the answer).
  nonce: u64,
}

/// The receiver-side payload of an in-progress block-DAG state-sync transfer, held as
/// `block_fetch: Option<BlockFetch>` on the [`Endpoint`]: the verified [`SyncCheckpoint`] the laggard is
/// installing (carrying the inline `(checkpoint_op, sessions, sm_root)` header, replayed into
/// [`Endpoint::apply_sync`] once the DAG drains), and the [`BlockSync`] frontier walking the SM
/// checkpoint DAG rooted at `sm_root`. Held only while a block pull is in progress — always under an
/// outstanding `sync` (the invariant `block_fetch ⟹ sync`, asserted beside `pending_install ⟹ sync`):
/// every path that clears `sync` clears the fetch with it, and an abort (a malformed-DAG bound breach / a
/// superseding checkpoint) drops ONLY the fetch, keeping `sync` armed so the solicit timer re-solicits.
///
/// The pin is by CONTENT, not by donor: the SM blocks are content-addressed, so a block of the pinned
/// DAG from ANY member is interchangeable (a block whose bytes hash to the requested address is
/// genuine), and a donor crash mid-transfer costs a re-solicit, not the blocks already written (the
/// `BlockStore` is the durable, content-addressed cache — there is no separate staging buffer to lose).
/// A corrupt block is rejected on receipt by its hash and re-requested. Volatile: a crash clears it for
/// free (the partially-written blocks survive in the store and are simply re-discovered on the next sync).
#[derive(Debug)]
struct BlockFetch<S> {
  /// The verified checkpoint message being installed. Held verbatim so that, once the DAG rooted at its
  /// `sm_root` is fully present, it is replayed into `apply_sync` — running the IDENTICAL stage/install
  /// path (decode, bind-check, durable re-persist, cross-epoch successor) a single-frame arrival would,
  /// the only difference being that the SM blocks were fetched separately rather than carried inline.
  checkpoint: crate::SyncCheckpoint,
  /// The SM checkpoint DAG root (decoded from `checkpoint`'s envelope); the address the SM frontier walk
  /// is seeded at and the eventual `restore` entry point.
  sm_root: BlockAddress,
  /// The session-table DAG root (decoded from `checkpoint`'s envelope); the address the SESSION frontier
  /// walk is seeded at and the eventual `decode_sessions` entry point.
  sessions_root: BlockAddress,
  /// The peer the next block pull is addressed to (re-pinned on each `BlockResponse` — the freshest
  /// live server).
  donor: ReplicaId,
  /// The missing-block frontier walking the SM DAG rooted at `sm_root`, fetching only the blocks the
  /// store is missing (an unchanged subtree the laggard already holds is never re-pulled).
  block_sync: block_sync::BlockSync<block_sync::SmRefs<S>>,
  /// The missing-block frontier walking the SESSION-table DAG rooted at `sessions_root`. The fetch is
  /// complete (the checkpoint replayed into `apply_sync`) only when BOTH this and `block_sync` have
  /// drained — the install reconstructs the SM from `sm_root` AND the session table from `sessions_root`,
  /// so both DAGs must be fully present first.
  session_sync: block_sync::BlockSync<block_sync::SessionRefs>,
  /// Whether this fetch's pinned `checkpoint` actually PRESENTS a cross-epoch crossing — `true` iff the
  /// envelope carries a STRICTLY-foreign configuration with a NON-EMPTY successor membership (the same
  /// crossing-presentation test `apply_sync` keys on: `config_id != current && !membership.is_empty()`).
  /// A `BlockFetch` is armed BEFORE `apply_sync` verifies the carried membership, and the cross-epoch
  /// solicit admits below-target replies onto this path, so a SAME-CONFIG or EMPTY-membership reply
  /// (a donor serving its `M < N` checkpoint in the force-checkpoint window) arms a live fetch that is
  /// NOT a crossing. The crossing-answer predicates ([`Endpoint::stale_crossing_intent_clearable`] /
  /// [`Endpoint::crossing_is_pre_answer_speculative`]) read THIS, not the bare `block_fetch.is_some()`:
  /// a live non-crossing fetch must NOT shield a stale `cross_epoch_intent`, or a misrouted higher-epoch
  /// hint would stay shielded by non-crossing replies forever. Set at every arming site from the
  /// checkpoint metadata; preserved across the GC-pruned re-pin window (the fetch is kept live and only
  /// re-soliciting a fresh checkpoint, which re-arms through `begin_block_sync` with a freshly-computed
  /// bit).
  crossing_answered: bool,
  /// The pruned front this fetch has ALREADY re-solicited a fresh `SyncCheckpoint` for. When an
  /// active-donor `BlockResponse(absent)` for the outstanding front arrives (the donor GC-pruned that
  /// block), the absent arm re-solicits a fresh checkpoint per round trip — the only cadence fast enough
  /// to track a checkpointing-and-pruning donor. Without a bound, every DUPLICATE/DELAYED absent for the
  /// same front in the window before the fresh checkpoint re-seeds the frontier would re-broadcast
  /// `RequestSync`, turning one pruned block into an unbounded broadcast/read storm. This records the front
  /// already re-solicited: the arm fires AT MOST ONCE per front, skipping while `resolicited_front` already
  /// names it. The front is monotone within one fetch (the content-addressed DAG walk never returns to a
  /// prior address), so a single address suffices. It is born `None` and never cleared mid-life. Each
  /// arming site REPLACES `self.block_fetch` wholesale, so a fresh `BlockFetch` over a live one would reset
  /// the latch — but a DUPLICATE/DELAYED same-root checkpoint (a re-pin that does not advance the front)
  /// must NOT re-open re-solicitation, else an unbounded flood of same-root checkpoints (each trailed by a
  /// duplicate absent) would drive one re-solicit per delivered duplicate. So the latch is CARRIED FORWARD
  /// at construction across a SAME-root re-pin (equal `(sm_root, sessions_root)` — the identical
  /// content-addressed DAG, hence the same front), via [`Endpoint::carry_resolicit_latch`]; only a re-pin
  /// to a genuinely DIFFERENT root resets it to `None` (a new pin whose first absent must legitimately
  /// re-solicit). The carry is computed ONCE at construction — there is still no mid-life clear. Total
  /// re-solicits are thus O(distinct roots) = O(round-trips), even under an unbounded same-root flood.
  resolicited_front: Option<BlockAddress>,
}

/// The PRE-ROOT staging of a verified `SyncCheckpoint` whose re-persist root is not yet durable.
/// [`Endpoint::apply_sync`] STAGES the durable re-persist (the two superblock writes) and records this
/// payload; on the root completion ([`Endpoint::on_sb_done`]) the frontier advance — `checkpoint_op`,
/// `commit_min`/`commit_max`/`op`, the successor membership — runs UNCONDITIONALLY (the durable root is
/// the commit point, so in-memory moves in lockstep with it), and the SM-content restore follows as a
/// SEPARATELY-tracked retryable obligation ([`SmReconstruct`]). `Some` exactly across the STAGE→root
/// window; cleared on the root completion (it becomes either nothing, on a clean restore, or an
/// `SmReconstruct`, on a restore fault) AND on any PRE-ROOT cancellation (view change / step-down that
/// clears `sync`) — at which point NOTHING destructive has run, so the cancel is clean. Carries the
/// OWNED decoded snapshot content (the borrow into the wire envelope does not outlive the message) so the
/// install reconstructs the synced state without re-decoding.
#[derive(Debug, Clone)]
pub(crate) struct PendingInstall {
  /// The synced checkpoint op (== the op BOUND into the snapshot) the install advances to.
  checkpoint_op: OpNumber,
  /// The decoded session-table DAG root to reconstruct `self.clients` from. Like `sm_root`, the blocks
  /// reachable from it are guaranteed present in the `BlockStore` before the install runs (the block
  /// frontier drained BOTH roots first), and `install_sync` reads them through the verified view.
  sessions_root: BlockAddress,
  /// The decoded SM checkpoint DAG root to restore from. The blocks reachable from it are guaranteed
  /// present in the `BlockStore` before the install runs (the block frontier drained first).
  sm_root: BlockAddress,
  /// The forced-sync held-tail decision captured at STAGE (`checkpoint_op < self.op`): the band
  /// `(checkpoint_op .. self.op]` is PRESERVED on install rather than discarded (safety, adversarial schedule).
  /// `self.op` is frozen across the window (`on_prepare` drops while `sync.is_some()`), so this decision
  /// is identical at install time.
  held_tail: bool,
  /// The successor `Membership` to install when this is a CROSS-EPOCH state-sync (the synced `config_id`
  /// differs from the local one): reconstructed + VERIFIED in [`Endpoint::apply_sync`] from the carried
  /// `(epoch, config_id, membership)`, installed atomically with the durable sync root in the
  /// `SyncRepersist` completion (same side effects as [`Endpoint::install_membership`]). `None` for a
  /// SAME-config sync — the common case stays byte-identical (no membership change).
  successor: Option<Membership>,
  /// The VERIFIED predecessor `config_id` the carried successor chains from — the `prev_config_id` the
  /// `ReconfigurePayload` pinned, the value that made `to_membership_verified` succeed
  /// (`hash(successor_membership, this) == successor.config_id()`). `Some` exactly when `successor` is
  /// (a crossing install); `None` for a same-config sync. It is LOAD-BEARING for the lineage hash-chain
  /// across a MULTI-epoch skip: the crossing install + its durable root stamp the recent-prior ring as
  /// `[this, <laggard's own prior config_id>]` (the VERIFIED chain), NOT `[<laggard's current> , ..]`
  /// re-derived from the stale current config. So a later re-serve of the successor membership chains
  /// from THIS id and recomputes the SAME `config_id` a fresh laggard expects — without it, a direct
  /// E0→E2 crossing would re-serve E2 stamped with E0 as predecessor, and another laggard would reject
  /// the (mis-chained) crossing forever. For the common single-change E0→E1 case this equals the
  /// laggard's own current `config_id`, so the install is byte-identical to before.
  successor_prev_config_id: Option<u128>,
  /// The verified `SyncCheckpoint` this install was staged from, carried verbatim so the post-advance
  /// SM-reconstruct obligation ([`SmReconstruct`]) can RE-FETCH this checkpoint's bit-rotted block (the
  /// block that failed the verify-on-read restore) and retry against the same DAG. On a restore fault the
  /// frontier advance has already happened, so this is moved into the [`SmReconstruct`] obligation (the
  /// pre-root `pending_install` is consumed).
  checkpoint: crate::SyncCheckpoint,
  /// The AUTHENTICATED donor slot the block-fetch was pinned to (the slot the sender-binding check
  /// established this laggard routes to — NOT the donor's self-claimed, possibly-shifted `replica()`).
  /// The SM-reconstruct retry re-pulls the missing block from THIS slot.
  donor: ReplicaId,
}

/// The SM-CONTENT RECONSTRUCTION owed after a synced checkpoint `M`'s re-persist root is durable but the
/// verify-on-read `sm.restore` FAILED on a bit-rotted/missing block.
///
/// The instant M's root lands, [`Endpoint::on_sb_done`] advances the in-memory frontier to M
/// UNCONDITIONALLY (`checkpoint_op == commit_min == M`, matching the durable root); the SM content is the
/// one thing that may still be lagging (it holds the OLD checkpoint until `restore` succeeds). That
/// lag is THE recover-time shape: a cold restart sets `checkpoint_op = state.checkpoint_op()` and
/// reconstructs the SM lazily under the fixed pointer; this is its warm-path analogue, tracked here.
///
/// While `Some`, the obligation:
/// - re-pulls M's DAG from the pinned `donor` (a re-armed [`BlockFetch`] at `sm_root`, re-requesting the
///   block that failed to verify, which `write_block` overwrites) and retries `sm.restore` against the
///   UNCHANGED M pointer (no re-stage — M's root is already durable);
/// - GATES the SM: the node neither SERVES M's snapshot (it cannot — the SM is not M yet) nor APPLIES an
///   op against the un-restored SM, until reconstruction completes ([`Endpoint::sm_reconstruct_owed`]).
///
/// There is NO pointer to rewind (in-memory already equals durable at M), so unlike the staging
/// `pending_install` no teardown needs to PRESERVE it for safety — a view change leaves it intact only
/// for LIVENESS (to keep the retry alive). It clears when `restore` finally succeeds, OR when a
/// strictly-newer checkpoint `> M` is installed forward (which restores the SM to that newer point).
#[derive(Debug, Clone)]
pub(crate) struct SmReconstruct {
  /// The synced checkpoint op M the frontier already advanced to (== `self.checkpoint_op`). Carried so
  /// the obligation can prove its retry targets the durable checkpoint and a newer install supersedes it.
  checkpoint_op: OpNumber,
  /// The SM checkpoint DAG root the retry restores from.
  sm_root: BlockAddress,
  /// The session-table DAG root the retry reconstructs `self.clients` from. The post-root install reads
  /// BOTH DAGs through the verified view; a fault in EITHER (an SM block or a session block bit-rotted in
  /// the window before the destructive read) raises this obligation, and the retry re-pulls + re-reads
  /// both before declaring the install complete.
  sessions_root: BlockAddress,
  /// The verified `SyncCheckpoint` to replay once M's DAG re-drains — drives the reconstruct retry.
  checkpoint: crate::SyncCheckpoint,
  /// The AUTHENTICATED donor slot the re-armed block-fetch re-pulls the missing block from.
  donor: ReplicaId,
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
  /// the steady self-driven entry leaves it `false`. The discriminant is LOAD-BEARING for
  /// durable-view-before-participate and stays `true` for the posture's whole life: the catch-up view
  /// was adopted from a bare advertised scalar and never made durable, so the posture must never
  /// migrate into the DVC-casting regime (`TimerKind::DvcMessage` is serviceable only when this is
  /// `false`, and every `false` collection is installed by an entry that durably writes its view).
  /// The posture exits ONLY by adopting a validated view (`StartView`/`RecoveryResponse`, which write
  /// the view before participating), by an SVC-quorum `enter_view_change` (ditto), or by reverting to
  /// the durable view when validation never arrives.
  catching_up: bool,
  /// How many `view_change_status` windows this CATCH-UP posture has expired without validation
  /// (meaningful only while `catching_up`; saturating). The advertised view was adopted from one
  /// unvalidated scalar, so the posture is given a bounded validation window: while it runs, each
  /// expiry re-drives the escalation SVC (`propose_next_view` — a proposal, not a vote); at
  /// [`CATCH_UP_VALIDATION_WINDOWS`] with the view still above the durable one, the posture REVERTS
  /// to the durable view rather than stranding forever on a claim nobody can answer (a corrupted
  /// scalar names a view no primary serves: `GetView` goes unanswered, our SVCs for its successor
  /// are implausible to every peer, and all real cluster traffic reads as stale).
  catchup_windows: u8,
}

impl ViewChangeCollection {
  /// A fresh collection for a replica ENTERING `Status::ViewChange`: no DVCs collected, no quorum yet,
  /// and `catching_up` per the entry kind (`true` for the higher-view catch-up entry, `false` for the
  /// self-driven SVC-quorum entry). Replaces the old per-field `dvc_from.clear()` / `dvc_quorum = false`
  /// / `catching_up = …` reset, now that these live behind one Option.
  fn entering(catching_up: bool) -> Self {
    Self {
      dvc_from: BTreeMap::new(),
      dvc_quorum: false,
      catching_up,
      catchup_windows: 0,
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
/// How many `view_change_status` windows a CATCH-UP posture may expire unvalidated before it reverts
/// to the durable view. The catch-up view came from ONE unvalidated scalar (a `Prepare`/`PrepareOk`/
/// `Commit` view field — the higher-view rule), so the posture probes rather than commits: within the
/// window a REAL view answers (`GetView` retransmits every [`VC_MESSAGE_RETRANSMIT`], and a formed
/// view has a durable quorum able to answer) or the escalation SVC finds takers; a view nobody can
/// validate in `3 × 500ms` — ~15 probe rounds — is treated as the corrupted-scalar class
/// [`MAX_VIEW_JUMP`] defends against, and the replica returns to its durable view instead of
/// stranding until an operator restarts the process. Reverting is cheap-safe: the abandoned view was
/// never durable, the posture casts no vote (the `catching_up` discriminant never flips), and a real
/// view re-advertises itself on the next authoritative message, re-entering catch-up with answers
/// available.
const CATCH_UP_VALIDATION_WINDOWS: u8 = 3;
/// Forfeit: how long the checkpoint-lag forfeit condition must
/// hold CONTINUOUSLY before a stuck primary actually steps down (the anti-storm grace timer). Sits
/// above `PRIMARY_IDLE` (200ms) — so a *silent* primary is failed over first by a backup's idle VC,
/// and forfeit handles only the *alive-but-stuck* case where the primary keeps heartbeating yet
/// cannot make checkpoint progress — and below `VIEW_CHANGE_STATUS` (500ms) — so a forfeit resolves
/// before a redundant idle-driven view change escalates. A primary that catches up within the grace
/// window disarms and never forfeits (a transient lag cannot trigger it).
const FORFEIT_GRACE: core::time::Duration = core::time::Duration::from_millis(300);
/// The number of superseded `config_id`s retained in the recent-prior lineage ring
/// (`Endpoint::lineage`), which widens [`Endpoint::in_lineage`] to admit a bounded window of recent
/// ancestors. A live single-change commits ONE epoch at a time, so a legitimate replica that missed
/// the last reconfiguration lags by one epoch; two covers a node that also missed the one before. Past
/// this bound a config_id is treated as long-stale/forked and rejected — the AGNOSTIC catch-up
/// messages (`RequestSync`/`SyncCheckpoint`/repair serves) it would gate are bounded, not unlimited.
/// Two is the realistic single-change window; a larger window is a Tier-A/joint concern.
const LINEAGE_RING: usize = 2;
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
/// Learner progress (`Status::Normal` LEARNER): how often a non-voting learner re-broadcasts its
/// [`LearnerStatus`](crate::LearnerStatus) durable-frontier report to the cluster, so the primary's
/// catch-up-then-promote gate sees the learner advance. A status report carries no quorum authority and
/// is cheap; this cadence is the same order as the commit heartbeat (the learner reports about as often
/// as the primary heartbeats), so a promotion proposal sees a fresh frontier within a heartbeat or two.
const LEARNER_STATUS_CADENCE: core::time::Duration = core::time::Duration::from_millis(100);
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
/// How many checkpoint intervals the PROTO-IMPOSED WAL ring spans for a backend with no fixed ring of
/// its own ([`Wal::capacity`] `== u64::MAX`): [`effective_wal_capacity`] is then
/// `IMPLIED_RING_INTERVALS * checkpoint_ops + MAX_PIPELINE`. Sized generously — TigerBeetle's journal
/// spans about two checkpoint intervals plus its pipeline, so four intervals means even a checkpoint
/// lagging a whole extra interval never stalls a healthy cluster — while staying FINITE, which is the
/// property everything rests on: the ring is what bounds a bit-rotted `op_head` at recovery and what
/// the op-assignment stall + the backup ring-window guard enforce at append time.
const IMPLIED_RING_INTERVALS: u64 = 4;

/// The WAL's EFFECTIVE ring capacity — the single source of the ring geometry every capacity-derived
/// bound uses (the primary's op-assignment stall, the backup ring-window guard, and `recover()`'s tail
/// read ceiling): the backend's own [`Wal::capacity`], with the "no fixed ring" sentinel (`u64::MAX`)
/// replaced by a proto-imposed ring of [`IMPLIED_RING_INTERVALS`]` * checkpoint_ops + `[`MAX_PIPELINE`]
/// slots. Imposing a finite ring on a ring-less backend is what makes the recovery geometry sound for
/// EVERY backend: append-time enforcement guarantees `op_head <= checkpoint_op + effective` for honest
/// operation, so recovery can cap a bit-rotted `op_head` scalar at that provable maximum instead of
/// trusting it (reading to a corrupt `u64::MAX` head would hang/OOM at startup) — and, symmetrically,
/// no op a conforming replica legitimately holds can ever sit above the recovery read ceiling, so the
/// cap never clips a real tail. For a ring-less backend the imposed ring surfaces only as deliberate
/// append backpressure when checkpointing stalls far behind — TigerBeetle's flow control, and strictly
/// better than the unbounded WAL growth it replaces.
const fn effective_wal_capacity(capacity: u64, checkpoint_ops: u64) -> u64 {
  if capacity == u64::MAX {
    checkpoint_ops
      .saturating_mul(IMPLIED_RING_INTERVALS)
      .saturating_add(MAX_PIPELINE)
  } else {
    capacity
  }
}
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
  /// Ops whose body read is still outstanding → remaining ABSOLUTE retransmission budget. Non-empty ⇒
  /// reads in flight. Seeded ONCE per op at the Phase-1 submit (`RECOVER_READ_RETRIES`) and decremented
  /// ONLY by `recover_timeouts` (never reset, never touched by a completion); at zero the op is resolved
  /// from its durable header (`resolve_exhausted_tail_read`). A clean completion removes the op's entry.
  pending: BTreeMap<u64, u8>,
  /// Maps an in-flight read's `OpId` → the op it reads, so a `Fault`/`Absent` completion (which
  /// carries only the `OpId`) is attributed to the right slot. An op can have SEVERAL live ids at once:
  /// `recover_timeouts` re-submits ADDITIVELY (a fresh id without retiring the prior ones), so a late
  /// completion under any still-live id resolves the op; resolving an op retires ALL of its ids.
  reads: BTreeMap<u64, u64>,
  /// Ops that read back permanently FAULTY — a written slot that is torn/bit-rotted/misdirected (a
  /// definitive read fault or a retry-exhausted one). Drives the `Normal`-vs-`RecoveringHead` decision in
  /// `recover_progress`: a faulty HEAD cannot be trusted → RecoveringHead. Distinct from `absent` (a slot
  /// that was NEVER written), which is a phantom above the real head, not a fault.
  faulty: std::collections::BTreeSet<u64>,
  /// Ops that read back ABSENT — the WAL has no slot there (never written). These are the phantom tail an
  /// over-counted/bit-rotted `op_head` scalar reports above the highest slot the replica actually wrote.
  /// `recover_progress` caps `self.op` at the highest WRITTEN op (present or faulty) and DISCARDS the
  /// absents above it (a clean cap → Normal, never RecoveringHead — no committed op lives above the real
  /// head); an absent BELOW the real head is a genuine interior hole and is reclassified faulty (repaired
  /// on demand). Kept separate from `faulty` so a phantom tail never drives the head-fault decision.
  absent: std::collections::BTreeSet<u64>,
  /// The in-flight checkpoint-read `OpId` (`Some` until the snapshot is restored), or `None` if no
  /// checkpoint exists / it is already restored.
  checkpoint: Option<u64>,
  /// Whether the durable root this recovery started from was FORMATTED — written by [`format()`](crate::format) with a
  /// pinned nonzero `checkpoint_ops`, which an empty-consensus wipe cannot forge. Gates
  /// `complete_recovery`'s genesis-primary exemption: only a formatted store may resume Normal at
  /// view 0 as its primary; an unformatted store (fresh/wiped/legacy) abdicates instead, so the view
  /// change recovers any committed op a wiped member forgot from a surviving peer.
  formatted: bool,
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
  /// The IMMEDIATELY-PRECEDING solicitation window's `peers_recovering` snapshot (same `svc_from`
  /// shape). `recover_head_timeouts` ANDs it with the current `peers_recovering` so a voter counts
  /// toward G2 only if seen co-recovering in TWO CONSECUTIVE windows — a genuinely-wedged peer
  /// re-broadcasts every window (bit in both), while a single late stale `Recovery` from a
  /// since-recovered peer is in at most one window and the intersection drops it. Rolled forward each
  /// window. Dropped with `RecoverState` at `recover = None`; reset by a fresh `recover()`. NEVER
  /// hashed/serialized/emitted.
  peers_recovering_prev: u64,
}

/// The body-state of a log entry — `Present` (bytes held) or `Repairing` (header-only, body
/// peer-repaired). ONE type shared with the wire [`crate::PreparedEntry`], so a `Repairing` op
/// carried through a `DoViewChange`/`StartView` keeps its op number (never re-minted). Defined in
/// [`crate::message`]; re-used here as the in-memory `LogEntry`'s body.
pub(crate) use crate::message::Body;

/// One entry in the in-memory log (persistence arrives in a later milestone). Its [`Body`] is either
/// `Present` (the bytes) or `Repairing` (only the durable `body_checksum`, awaiting peer-repair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEntry {
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

  /// A consensus-layer reconfiguration log entry carrying the full successor membership. Wraps
  /// `payload` as [`Body::Reconfigure`]; the op keeps a `(client, request)` identity for
  /// dedup/content-addressing, minted by the proposing primary like any op. The proposing primary
  /// (`propose_membership`) builds it on its side; a backup rebuilds it from a
  /// [`ClientId::RECONFIGURATION`] prepare's decoded body (`log_entry_from_prepare`), so both hold the
  /// identical typed entry the commit-first epoch swap recognizes.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn reconfigure(
    client: ClientId,
    request: RequestNumber,
    payload: crate::message::ReconfigurePayload,
  ) -> Self {
    Self {
      client,
      request,
      body: Body::Reconfigure(payload),
    }
  }

  /// Build the in-memory entry for a committed op's `(client, request, body)` bytes, choosing the ONE
  /// typed representation every replica must hold (decision (a): a single representation everywhere). A
  /// [`ClientId::RECONFIGURATION`] body is the canonical successor-membership encoding — decode it back
  /// to a typed [`Body::Reconfigure`] so the commit-first epoch swap recognizes it; every other body is
  /// an opaque [`Body::Present`] client op. This is the SOLE reconstruction-from-bytes helper, shared by
  /// the normal-prepare append (`log_entry_from_prepare`), the repair fill, AND the recovery WAL read —
  /// so a RECONFIGURATION op never type-erases into a `Present` op on ANY ingress path (which would make
  /// `commit_reconfigure` miss it: the epoch swap silently never fires and the membership bytes are
  /// mis-applied to the state machine, re-minting / mis-typing the op number — a consensus divergence).
  ///
  /// A RECONFIGURATION body from a legitimate source always carries `encode_body()` output, which always
  /// decodes (the non-Byzantine contract; framing/durability checksums catch corruption first). A decode
  /// failure is therefore a bug — asserted in debug — and degrades in release to a `Body::Present` entry
  /// (the op is still held + acked, so the head never stalls; commit then treats it as an opaque op and
  /// stages NO epoch swap, never panicking on the bytes).
  #[cfg_attr(not(tarpaulin), inline)]
  fn from_committed_body(client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    if client == ClientId::RECONFIGURATION {
      match crate::message::ReconfigurePayload::decode_body(&body) {
        Ok(payload) => return Self::reconfigure(client, request, payload),
        Err(_e) => {
          debug_assert!(
            false,
            "a RECONFIGURATION op carried an undecodable reconfigure body ({_e:?}) — a \
             non-Byzantine source always supplies encode_body() output",
          );
        }
      }
    }
    Self::present(client, request, body)
  }

  /// The canonical WIRE body bytes when this entry is BODY-BEARING (`Present` bytes, or a `Reconfigure`
  /// op's `encode_body()`), else `None` for a header-only `Repairing` hole. The SINGLE accessor every
  /// body-transport / storage path on a held `LogEntry` routes through (prepare retransmit, repair serve,
  /// adopted-tail re-append, the header-only-adoption preserve, faulted-append retry) so a `Body::Reconfigure`
  /// op is transmitted/stored exactly like a client op — see [`Body::body_bytes`](crate::message::Body::body_bytes).
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn body_bytes(&self) -> Option<Bytes> {
    self.body.body_bytes()
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Session {
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
  /// Normal LEARNER: re-broadcast the [`LearnerStatus`](crate::LearnerStatus) progress report on a
  /// cadence so the primary learns how far this learner has durably caught up (the input to the
  /// catch-up-then-promote gate). Armed ONLY for a non-voting learner (`is_learner()`); a voter never
  /// reports progress (it participates directly). Idle-timer-style: re-armed every tick it fires.
  learner_status: Option<Instant>,
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
  /// The learner progress-report cadence ([`Timers::learner_status`]), serviced (via
  /// [`Endpoint::learner_status_timeouts`]) on the Normal-LEARNER path — only a non-voting learner ever
  /// arms or services it.
  LearnerStatus,
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
    TimerKind::LearnerStatus,
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
      TimerKind::LearnerStatus => "learner_status",
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
pub struct Endpoint<S, R = RestartOnly> {
  config: Config,
  /// The slot capacity of this node's WAL backend ([`Wal::capacity`]; `u64::MAX` = unbounded) —
  /// observed from the backend at recovery, or DECLARED by the caller at genesis construction
  /// ([`Self::with_reconfig`] takes no storage handles, so it cannot observe one). Stamped into
  /// every durable root as half of the WAL-GEOMETRY pair so the next recovery can refuse a restart
  /// under different geometry (which would silently move the recovery scan window off a committed
  /// tail). Always nonzero: `0` is the wire-level "unrecorded" sentinel a pre-v8 root decodes to,
  /// which recovery refuses on any non-virgin store — construction asserts it away so no live
  /// endpoint can ever write it.
  wal_capacity: u64,
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
  /// The bounded RECENT-PRIOR `config_id` ring — the superseded `config_id`s of the last
  /// [`LINEAGE_RING`] live single-changes, MOST-RECENT-FIRST, pushed by [`Self::install_membership`].
  /// It widens [`Self::in_lineage`] (which otherwise admits only the current `config_id`) to ALSO admit
  /// these recent ancestors, so a legitimate replica lagging the cluster by a bounded number of live
  /// reconfigurations can still be served the committed-content/state-sync messages that let it catch
  /// up ACROSS the epoch boundary — while a long-stale or FORKED `config_id` (never in this node's
  /// chain) stays rejected (config_id is the lineage discriminator). Single-change commits one epoch at
  /// a time, so the realistic catch-up window is 1-2 epochs; the ring is sized for that. Pre-genesis
  /// slots hold the genesis `config_id` (a harmless duplicate of the current id at genesis, admitting
  /// nothing extra). Private; never hashed/serialized/emitted.
  lineage: [u128; LINEAGE_RING],
  /// The op of the last reconfigure that produced [`Self::membership`] — the committed `Reconfigure` op a
  /// live single-change swaps at (the commit-first SwapEpoch root names it), the offline-restart point for
  /// an offline reconfiguration, or genesis (`0`) when no reconfiguration has occurred. Set by
  /// [`Self::install_membership`] when it carries a reconfigure op, and to the synced frontier by a
  /// cross-epoch state-sync install. It GATES the cross-epoch state-sync serve: a donor attaches its
  /// successor membership to a sync answer ONLY when `checkpoint_op >= config_install_op` — so a donor that
  /// has swapped to E+1 but whose checkpoint is still BELOW the reconfigure op `N` serves an EMPTY
  /// membership, and the laggard installs the SM frontier (op `M < N`) while KEEPING its current membership
  /// and catching the band up through `N` via the commit-first path (XI-b: a node reaches E+1 only once it
  /// durably holds the committed prefix THROUGH `N`). Persisted in the v6 durable root so a RECOVERED donor
  /// restores the gate. Fixed per incarnation under [`RestartOnly`]; advanced live under
  /// [`SingleChange`] (advanced live as each single-member change installs).
  config_install_op: OpNumber,
  status: Status,
  view: View,
  /// The highest view with a DURABLE witness — the view a crash-and-recover provably resumes at or
  /// above. Seeded from the recovered root at construction (genesis roots are view 0) and advanced
  /// exactly when a `pending_sb` root write COMPLETES (`on_sb_done`; every such root persists the
  /// view current at its submit, and view transitions supersede `pending_sb`, so completion-time
  /// `self.view` is the view the root carried). This is the ground truth
  /// durable-view-before-participate gates on: `self.view == self.durable_view` says the CURRENT
  /// view is recoverable, where [`Self::pending_durable_view`] can only say no view-changing write
  /// is in flight — vacuously true on a path that never submitted one (the catch-up posture adopts
  /// an advertised view in memory only, deliberately: a probe needs no durability). The DVC gates
  /// and the [`Self::emit`] fence assert the equality, so a vote or authority claim for a view with
  /// no durable witness is structurally unreachable no matter which path minted the view.
  ///
  /// Invariant: `durable_view <= view` (the durable root never runs ahead of the live view), with
  /// equality at every authoritative EMISSION (the [`Self::emit`] fence) — participation is what the
  /// witness gates, not status: an adoption may briefly hold the new view with its root write still
  /// in flight, and the per-site gates defer every vote/authority claim until the write lands.
  durable_view: View,
  /// Head op (most recently prepared locally).
  op: OpNumber,
  /// Highest op durably applied to the state machine (applied frontier).
  commit_min: OpNumber,
  /// The SM-CONTENT position witness: the op through which the in-memory state machine's content is
  /// current. Advanced ONLY by the SM-content operations themselves — a successful `sm.apply`
  /// (+1, via [`Self::note_sm_advanced`]; a committed `Reconfigure` op is accounted there too, its
  /// SM-effect being vacuous by design) and a successful `sm.restore` (wholesale, via
  /// [`Self::note_sm_restored`]) — NEVER by the consensus pointers. `commit_min` is written by the
  /// commit machinery and `sm_at` by the content machinery, so `assert_invariants` can cross-check
  /// the two independently-written frontiers: at every handler exit `sm_at == commit_min` unless a
  /// flagged behind-window is open (`sm_reconstruct` owed, or recovery rebuilding). This reifies
  /// "the SM's content is where the pointers say it is" — previously only the emergent negation of
  /// a three-flag disjunction spread across five modules — as one first-class witness, making any
  /// future path that applies over a stale SM or advances a pointer past un-restored content trip
  /// deterministically across the suite and the VOPR debug gate.
  sm_at: OpNumber,
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
  /// EVERY in-flight physical WAL append (`OpId` → op), entered at submit and removed ONLY when the
  /// write QUIESCES: its completion arrives ([`WalDone::Appended`]/[`WalDone::Fault`]/
  /// [`WalDone::Cancelled`]) or a [`Wal::truncate`]/[`Wal::prune`] reports it synchronously
  /// cancelled. Deliberately NOT generation state: view transitions, nack truncation, and GC clear
  /// `pending`/`appending` (abandoning the append LOGICALLY) but leave this map intact, because the
  /// PHYSICAL write is still with the device and its bytes can land at any moment until the backend
  /// says otherwise. This is the fence's witness set: `submit_or_defer_append` refuses to put a
  /// second write in flight for any ring slot listed here (same op, or its ring alias
  /// `op ± k·capacity`), so completion reordering can never let abandoned old bytes land OVER a
  /// replacement this replica already acked — the durable slot always ends holding the value the
  /// vote named.
  wal_writes: BTreeMap<u64, u64>,
  /// Appends held back by the slot-quiescence fence, keyed by op: the full submission (deferred
  /// action + exact bytes) waiting for the blocking older write in [`Self::wal_writes`] to quiesce.
  /// Usually one waiter per slot exists (the fence admits one in-flight + one deferred) — but on a
  /// bounded ring TWO waiters per slot CLASS are constructible (ops `K` and `K + capacity` both
  /// deferred behind one blocker, when the local checkpoint leads the quorum floor so `K` is already
  /// checkpoint-subsumed while `K + capacity` is admitted). [`Self::release_deferred_append`]'s
  /// ascending-key selection handles that corner: the subsumed lower op releases first and the LIVE
  /// higher op lands LAST, so the durable slot ends holding the value its vote names. GENERATION
  /// state, cleared/trimmed in lockstep with `pending`/`appending` (a deferred append abandoned by a
  /// view change / nack truncation / state-sync install / GC must not fire later); the votable kinds
  /// keep their `appending` mark while deferred, so the append-before-ack gate and the duplicate-
  /// append guards see them as in flight.
  deferred_appends: BTreeMap<u64, DeferredAppend>,
  /// The highest prune floor actually handed to the backend (`wal.prune(floor + 1)` ⇒ `floor`),
  /// monotone. Distinguishes a RELEASED op (at or below this floor, or above the live head) from a
  /// live one when a [`WalDone::Cancelled`] arrives: cancelling a released op's write is the
  /// backend's right; cancelling a live one is a contract violation degraded to a re-submit.
  wal_pruned: u64,
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
  /// The SM checkpoint DAG root of this replica's latest durable checkpoint — the live root the block
  /// GC marks from. `None` until the first checkpoint goes durable / is restored. Updated when a
  /// checkpoint root completes (an ordinary `force_checkpoint` produce, a state-sync re-persist
  /// install) and when recovery restores the SM from its own durable checkpoint. Best-effort
  /// (`None` simply skips block GC that cycle); it is NOT a safety input — the durable envelope's
  /// `sm_root` is the authority a crash re-reads.
  checkpoint_sm_root: Option<BlockAddress>,
  /// The SESSION-table DAG root of this replica's latest durable checkpoint — the SECOND live root the
  /// block GC marks from (alongside `checkpoint_sm_root`), so the session DAG's blocks are retained
  /// exactly as long as the SM DAG's. `None` until the first checkpoint goes durable / is restored;
  /// updated at the same sites as `checkpoint_sm_root`. Like it, best-effort, NOT a safety input — the
  /// durable envelope's `sessions_root` is the authority a crash re-reads.
  checkpoint_sessions_root: Option<BlockAddress>,
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
  /// Per-member last-reported `checkpoint_op`, keyed by the stable [`MemberId`] (resolved from the
  /// reporter's slot at ingest, exactly as [`Self::peer_progress`] is), filled by the primary from
  /// incoming `PrepareOk` (and recorded on backups from `Commit`, harmlessly). The primary derives
  /// [`quorum_checkpoint_op`](Self::quorum_checkpoint_op) from this to gate WAL/session GC: it never
  /// frees an op a `quorum` of replicas has not yet checkpointed. Bounded by `node_count` (<= 64
  /// voters + learners); cleared on every view-change transition (a new generation re-establishes the
  /// pipeline, so old reports are stale — clearing keeps the primary conservative until fresh
  /// `PrepareOk`s arrive).
  ///
  /// Keyed by the STABLE id, not the routing slot, so a slot-shifting reconfiguration
  /// ([`Self::install_membership`]) is transparent: a retained voter's report follows its `MemberId`
  /// across a slot shift (never misattributed to whoever now occupies its old slot), and a REMOVED
  /// member's report is structurally excluded from the GC / force-sync floors — its `MemberId` is no
  /// longer a current voter/member, so `compute_quorum_checkpoint_op` (voters-only) and
  /// `max_peer_checkpoint_op` (current-members-only) skip it. `install_membership` does NOT prune this
  /// map; the consumers intersect with the CURRENT membership, so a stale removed-member entry is inert
  /// (it can never lift a floor) and is cleared wholesale by the next view-transition reset.
  peer_checkpoint: BTreeMap<MemberId, OpNumber>,
  /// New-primary nack tally: for each repair-or-truncate candidate op (a header-only `Repairing` op above
  /// `commit_max` no canonical donor holds `Present`), the set of DISTINCT voters (by stable [`MemberId`])
  /// that have answered a `RequestPrepare` for it with a [`crate::Nack`] — proof they durably LACK the op.
  /// Once a candidate's set reaches [`Membership::quorum_nack_prepare`] (`f+1`) the op cannot have
  /// committed (a commit needs a write-quorum to hold it, and a write-quorum member keeps at least a
  /// header, so never nacks), and the uncommitted tail is truncated ([`Self::on_nack`]). Keyed by
  /// `MemberId` so a slot shift never double-counts; entries are dropped when a hole fills (a holder
  /// answered) and cleared wholesale by the view-transition reset (a fresh primary generation re-gathers).
  nack_from: BTreeMap<u64, BTreeSet<MemberId>>,
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
  /// The recovery FAULTY verdicts (`rec.faulty` — permanently unreadable/unprovable slots, the settled
  /// head possibly among them) at the moment the peer-checkpoint escape (`on_recover_sync_checkpoint`)
  /// abandoned local recovery for a staged install. The escape clears `recover` at staging (completion
  /// routing requires it), discarding the verdicts — but the `awaiting_peer_checkpoint` gate in
  /// `recover_progress` sits BEFORE its faulty-head → `RecoveringHead` decision, so without this carry
  /// the install completion would flip to `Normal` HOLDING an un-truthed head (an op with no identity
  /// anywhere: a later `Prepare` would be blind-re-acked and the DoViewChange would advertise an unheld
  /// head). The WHOLE set is carried, not just the head: the `RecoveringHead` reform-escalation gate
  /// (`committed_band_intact`) refuses same-epoch reformation while any COMMITTED-band faulty slot
  /// remains — a committed op this replica cannot vouch would be omitted from its DoViewChange — so
  /// the interior verdicts are as load-bearing as the head's. Replaced (never cleared) at the staging
  /// chokepoint only when the staging `rec.faulty` is non-empty — a re-fetch reply after an install
  /// error re-runs the staging with a fresh READ-FREE `RecoverState` and must not erase the original
  /// verdicts; consumed exactly once by `complete_state_sync`, which filters out what the installed
  /// checkpoint subsumed and routes to `RecoveringHead` — resuming the preempted decision, verdicts
  /// restored — when the head is among the survivors, and to the normal `complete_recovery` otherwise.
  /// Empty means none carried.
  sync_carried_faulty: std::collections::BTreeSet<u64>,
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
  /// The PERSISTENT cross-epoch crossing INTENT, decoupled from the transient [`SyncState`]: the
  /// highest hinted crossing `checkpoint_op` this node still has to REACH (cross the epoch boundary to),
  /// or `None` when no crossing is owed. Where [`SyncState::require_cross_epoch`] is the IN-FLIGHT
  /// sync's requirement — cleared the instant `on_sb_done` clears `self.sync` on an install — this is
  /// the GOAL that OUTLIVES the sync lifecycle: a higher-epoch trigger sets it
  /// ([`Endpoint::maybe_request_cross_epoch_catchup`]) alongside arming the sync, and a sync completing
  /// WITHOUT crossing re-arms the crossing AFRESH from it (`on_sb_done`'s sync re-persist arm). Without
  /// this, a higher-epoch trigger arriving AFTER an ordinary same-epoch sync has already STAGED its
  /// install (`pending_install` set, `successor` None) only rewrites the doomed `SyncState`: the staged
  /// same-epoch install still completes and clears `self.sync`, settling the node at the OLD epoch with
  /// NO crossing armed until ANOTHER trigger happens to arrive. Lifecycle: SET on a higher-epoch trigger
  /// (`= max(existing, hinted checkpoint)`); RE-ARMS the crossing on a non-crossing install completing
  /// while it is still `Some`; CLEARED on a SUCCESSFUL cross ([`Endpoint::install_sync`] installs a
  /// successor and
  /// advances the epoch — the goal is met) and on STALE same-epoch evidence
  /// ([`Endpoint::cancel_stale_cross_epoch_sync`] — a same-epoch operating witness proves the hint was
  /// stale; clearing here is what stops `on_sb_done` from re-arming a crossing for a bogus hint forever).
  /// IN-MEMORY only — deliberately NOT durable: the recovery checkpoint-debt machine + the cluster's
  /// higher-epoch heartbeats re-establish it after a crash, so a restarted laggard re-pins the crossing
  /// from the live signal rather than a stale persisted goal.
  cross_epoch_intent: Option<OpNumber>,
  /// State-sync deferred install: the verified-but-not-yet-installed synced checkpoint, RETAINED until it
  /// COMMITS. `Some` from the moment `apply_sync` retains the verified install (BEFORE its durability
  /// barrier) through the durable re-persist staging and until the sync ROOT goes durable (`on_sb_done` →
  /// `install_sync` consumes it); `None` otherwise. A flush fault during the barrier leaves it OWED-but-not-
  /// staged (no in-flight `pending_checkpoint`); the local solicit/recover cadence
  /// ([`Self::flush_and_stage_install`]) re-attempts the flush and stages once it succeeds. While `Some`,
  /// the replica keeps its OLD (consistent, if stale) in-memory + durable state — the SM is NOT yet restored
  /// and `commit_min`/`op`/`checkpoint_op` are NOT advanced, so a view change in this window finds the old
  /// state intact and cleanly cancels the install (no pruned-but-stale window). It is a LIVE GC ROOT: while
  /// it is owed, [`Self::gc_blocks`] marks both its DAG roots, so an intervening checkpoint GC never sweeps
  /// the drained blocks a still-owed flush will re-persist. The apply loop (`advance_commit`) is suppressed
  /// while this is `Some` so no op is applied over the soon-to-be-replaced SM (load-bearing for the recovery
  /// peer-fetch path, whose SM is unrestored here).
  pending_install: Option<PendingInstall>,
  /// State-sync peer side: in-flight checkpoint reads this replica issued to SERVE peers'
  /// `RequestSync`s, keyed by REQUESTER replica index → [`SyncServe`] (the serve-read `OpId`, the
  /// latest echoed nonce). Keying by requester makes the bound STRUCTURAL — at most one serve-read in
  /// flight per distinct requester (<= `replica_count` entries), so a buggy peer's solicit burst
  /// cannot stack N concurrent checkpoint reads. A repeat solicitation while that requester's serve is
  /// outstanding only REFRESHES the echoed nonce in place (the completion then answers the LATEST
  /// solicitation), issuing no second read. When the read completes (`on_sb_done` →
  /// `serve_sync_checkpoint`, matched by the recorded `OpId`), the small durable envelope (op +
  /// sessions + the SM root address) is shipped as one `SyncCheckpoint` (always frame-sized now that
  /// the SM bytes live in the block DAG, not the envelope); a `Fault` drops the entry silently (the
  /// requester re-solicits; another peer answers). The SM blocks themselves are served separately and
  /// statelessly via `RequestBlock` → `read_block`. Cleared per entry on completion/fault.
  sync_serving: BTreeMap<ReplicaId, SyncServe>,
  /// The receiver side of an in-progress block-DAG state-sync transfer (see [`BlockFetch`]): `None` while
  /// soliciting, `Some` once a verified `SyncCheckpoint` arms a live frontier pinned to a donor. Always
  /// paired under `sync` (`block_fetch ⟹ sync`, see `assert_invariants`) and cleared wherever `sync` is.
  /// On an active-donor ABSENT (the pinned block was GC-pruned at the donor) the fetch is KEPT LIVE and a
  /// fresh `SyncCheckpoint` is re-solicited IMMEDIATELY; the re-solicit re-seeds the frontier's front via
  /// `begin_block_sync`, so the live front address is the dedup witness — a duplicate absent for the same
  /// (still-pruned) front re-solicits another fresh checkpoint that advances the front within a round
  /// trip, and `handle_sync_checkpoint` is raise-only, so the re-solicits do not thrash. Because the live
  /// fetch is `is_some()` across the re-pin window, a crossing's "a donor has begun answering" signal
  /// (`crossing_is_pre_answer_speculative`) holds across it.
  block_fetch: Option<BlockFetch<S>>,
  /// The post-advance SM-content reconstruction owed for a synced checkpoint `M` whose re-persist root is
  /// durable (so `self.checkpoint_op == M`) but whose verify-on-read `sm.restore` FAILED — see
  /// [`SmReconstruct`]. `Some` exactly while the SM lags the (already-durable) checkpoint pointer; it
  /// GATES applying ops against / serving from the un-restored SM ([`Self::sm_reconstruct_owed`]) and is
  /// re-driven by the re-armed `Fetching` transfer + the serviced ARQ. There is no pointer to rewind while it is
  /// owed, so it carries NO safety floor (the [`SmReconstruct`] doc covers why teardowns may keep it for
  /// liveness only). Cleared when `restore` succeeds or a newer checkpoint installs forward.
  sm_reconstruct: Option<SmReconstruct>,
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
  /// Test/observability counter: how many block-DAG sync reads/transfers were ABORTED for exceeding
  /// `MAX_REACHABLE_BLOCKS` (a malformed / foreign / oversized DAG). The unit is ONE increment per aborted
  /// read/transfer — NOT per breached walk: a combined SM + session read whose BOTH sub-walks breach still
  /// counts once, because a single read/transfer aborts (the `on_block` loop returns on the first breach; the
  /// recovery-read match counts its `Err` arm once). The abort keeps `sync` armed so the solicit timer
  /// re-fetches — without this counter a persistently oversized DAG is a SILENT re-walk loop; the count makes
  /// it diagnosable. Same lifecycle as the other observability counters (reset to 0 on `new`/`recover`);
  /// exposed only via `dag_walks_capped()`.
  dag_walks_capped: u64,
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
  /// The single-writer reconfiguration latch for the PROPOSED-but-not-committed phase: `Some(op)` while
  /// a `Body::Reconfigure` op the primary minted is proposed but not yet committed, else `None`. Set by
  /// `propose_membership` on a successful mint; cleared at commit by `stage_epoch_swap` (the swap then
  /// rides `pending_swap` through install) OR by `reset_for_view_transition` when a view change abandons
  /// the proposing generation (an uncommitted proposal that gets truncated never commits, so the latch
  /// MUST release or a future propose is blocked forever). A [`SingleChange`] primary keeps at most ONE
  /// membership change in flight from propose THROUGH install: `propose_membership` refuses a second
  /// while this is `Some` OR a committed-but-not-installed swap is outstanding ([`Self::swap_in_flight`]).
  /// Private; never hashed/serialized/emitted.
  reconfigure_inflight: Option<OpNumber>,
  /// A committed `Body::Reconfigure` op's `(op number, SUCCESSOR membership)`, awaiting its durable
  /// `SwapEpoch` root. `Some` exactly across the commit→durable-root window: commit recognizes the
  /// Reconfigure op and latches the successor here (NOT in `self.membership` — the durable-epoch-before-
  /// participate fence), and the actual `submit_swap_epoch` durable-root write waits its turn behind any
  /// in-flight superblock write ([`Self::maybe_swap_epoch`], the same single-writer exclusion
  /// `maybe_checkpoint` uses). Cleared when the SwapEpoch root lands and `install_membership` runs. The
  /// CAPTURED op number is the reconfigure op itself — recorded at stage time, NOT re-derived from
  /// `commit_min` at install time, because the primary keeps committing client ops through the SwapEpoch
  /// window (the view stays durable through an epoch swap), so `commit_min` may have advanced PAST the
  /// reconfigure op by the time the root lands. The successor is identical on every replica (all commit
  /// at the identical OLD membership), so this is the pre-install staging of a convergent value; private,
  /// never hashed/serialized/emitted.
  pending_swap: Option<EpochSwap>,
  /// Re-entrancy guard for [`Self::maybe_pay_checkpoint_debt`]: `true` only WHILE that routine's own
  /// proactive `advance_commit` is on the stack. The debt routine is called from the commit-advance
  /// tails (`try_commit` / `advance_commit`) so the checkpoint debt re-checks every time commit moves;
  /// it itself calls `advance_commit` (to drive the committed band forward with NO traffic), which would
  /// re-enter the tail and recurse without bound. This flag makes the proactive advance a NO-OP while one
  /// is already in progress — the outer advance covers it. NOT a durable fact (it is always `false`
  /// between deliveries); private, never hashed/serialized/emitted.
  paying_checkpoint_debt: bool,
  /// Per-member DURABLE-frontier progress, keyed by the stable [`MemberId`]: the highest
  /// `durable_commit_min` a member has reported via a [`LearnerStatus`](crate::LearnerStatus). It
  /// carries NO quorum authority — it is NEVER read by any commit/view-change/recovery quorum — and is
  /// the SOLE state [`Self::on_learner_status`] mutates. It is a pure LIVENESS HINT, NOT a safety input:
  /// it indicates when a learner is worth challenging for a promote proof, but the learner-promote gate
  /// in [`Endpoint::propose_membership`](crate::Endpoint) does NOT gate the mint on it. The mint
  /// consumes a FRESH `RequestLearnerProof`/[`LearnerProof`] round-trip ([`Self::learner_proof`])
  /// instead — re-grounded in the learner's durable storage at propose time — because this accumulated
  /// max is unsound as a safety input: it banks a stale-high value that survives a crash/disk-fault that
  /// honestly REGRESSED the learner's frontier. Updated MONOTONE (`(*entry).max(reported)`); private,
  /// never hashed/serialized/emitted.
  peer_progress: BTreeMap<MemberId, OpNumber>,
  /// The single outstanding learner-promote-proof challenge (the FRESH safety input the
  /// catch-up-then-promote gate consumes), or `None` when no promotion challenge is outstanding. Set by
  /// [`Self::propose_membership`] on a `PromoteLearner` with no fresh proof (it draws a `nonce`, emits a
  /// `RequestLearnerProof`, and returns the retryable `ProofPending`); its `proof` is filled by the
  /// matching [`LearnerProof`] reply; and it is CONSUMED (set to `None`) at mint. CLEARED on a
  /// view-change/primacy transition ([`Self::reset_for_view_transition`]) and on an epoch swap
  /// ([`Self::install_membership`]) — it is transient promote state bound to the proposing generation
  /// and configuration; the `(epoch, config_id)` reply binding is the backstop. Private; never
  /// hashed/serialized/emitted, and inert off the reconfig+learner axis (never set on the no-reconfig
  /// schedule, so the off-axis digest is byte-identical).
  learner_proof: Option<LearnerProofState>,
  /// The zero-sized reconfiguration capability witness — the [`Reconfig`] type-state the
  /// (later) online-reconfiguration API gates on. `PhantomData<fn() -> R>` rather than
  /// `PhantomData<R>`: it is unconditionally `Send`/`Sync` (and covariant in `R`), so adding the
  /// marker can never alter `Endpoint`'s existing auto-traits whatever a future `R` becomes.
  _reconfig: core::marker::PhantomData<fn() -> R>,
}

/// The un-committed GENESIS state of a brand-new cluster member: the inputs a fresh [`Endpoint`]
/// needs, held BEFORE any durable genesis root exists. [`Endpoint::new`] / [`Endpoint::with_reconfig`]
/// return this instead of a runnable [`Endpoint`], so a member cannot begin participating without a
/// durable FORMAT witness. It is INERT — it exposes no request/operation surface; the only way forward
/// is [`Self::commit`], which writes the durable genesis root and yields the runnable [`Endpoint`].
///
/// This is the correct-by-construction core of the recovery contract: the ONLY public routes to a
/// runnable [`Endpoint`] are [`Self::commit`] (a NEW member, over a virgin store) and
/// [`Endpoint::recover`] (an EXISTING member, over its own durable store). Neither can produce a VOTER
/// whose durable root is empty, so a wiped or never-formatted voter can never silently re-enter the
/// voting set — the amnesia hazard where a replica that forgot its durable log re-votes across a view
/// change and lets a committed op number be re-decided, which [`Endpoint::recover`] fails-stops.
#[derive(Debug)]
#[must_use = "a Genesis is inert; call `commit` to write its durable genesis root and get the runnable Endpoint"]
pub struct Genesis<S, R = RestartOnly> {
  config: Config,
  membership: Membership,
  seed: u64,
  sm: S,
  wal_capacity: u64,
  /// The reconfiguration capability marker, carried so [`Self::commit`] can build an
  /// [`Endpoint`]`<S, R>`. `PhantomData<fn() -> R>` for the same unconditional `Send`/`Sync` reasons
  /// [`Endpoint`]'s own marker uses.
  _reconfig: core::marker::PhantomData<fn() -> R>,
}

impl<S, R: Reconfig> Genesis<S, R> {
  /// Commit this genesis to durable storage and return the runnable [`Endpoint`]. Writes the durable
  /// GENESIS ROOT — empty consensus state (view 0, op 0, no checkpoint) carrying the genesis membership
  /// and the WAL-GEOMETRY pair — via [`format`](crate::format), confirms it landed SYNCHRONOUSLY, then
  /// builds the in-memory [`Endpoint`] at genesis (view 0, `Status::Normal`): the identical in-memory
  /// state the pre-gate constructor produced, now backed by a durable format witness a later
  /// [`Endpoint::recover`] can trust (a formatted root carries a nonzero `checkpoint_ops` a wipe cannot
  /// forge, so recovery may resume this member while refusing an empty-rooted voter).
  ///
  /// This is the SOLE public route from a genesis member to a runnable [`Endpoint`]; an EXISTING member
  /// restarts via [`Endpoint::recover`] instead. Call it ONCE per store at cluster creation, over a
  /// VIRGIN store (before the first [`Endpoint::recover`]).
  ///
  /// The DECLARED WAL capacity (the `wal_capacity` this [`Genesis`] carries, from
  /// [`Endpoint::new`]/[`Endpoint::with_reconfig`]) MUST equal the backend's live [`Wal::capacity`]:
  /// [`format`](crate::format) pins the ACTUAL `wal.capacity()` into the durable genesis root, so a
  /// declared value that disagreed with the backend would produce a voter whose in-memory geometry
  /// contradicts its own durable root ([`FormatError::WalCapacityMismatch`], refused before any write).
  ///
  /// # Errors
  /// [`FormatError`] if the genesis cannot be committed, leaving the store UNCHANGED so the caller can
  /// fix the input and retry: [`FormatError::WalCapacityMismatch`] if the declared capacity differs from
  /// the backend's [`Wal::capacity`] (checked BEFORE the write, so nothing is pinned);
  /// [`FormatError::AlreadyInitialized`] if the store already carries a durable root (an existing member
  /// must [`recover`](Endpoint::recover), never re-genesis over live consensus state);
  /// [`FormatError::WalCapacityBelowMinimum`] if the backend is below the liveness floor (checked BEFORE
  /// the write, so nothing is pinned); or [`FormatError::WriteNotDurable`] if the genesis-root write did
  /// not complete synchronously.
  pub fn commit<W: Wal, B: Superblock>(
    self,
    wal: &W,
    sb: &mut B,
  ) -> Result<Endpoint<S, R>, FormatError> {
    // The declared capacity MUST match the backend `format` pins into the durable genesis root. A
    // mismatch would build a voter whose in-memory geometry disagrees with its own durable root — the
    // WAL laid out under one capacity while the next checkpoint/view root stamps the other — which can
    // later pass recovery's geometry fence yet scan under a layout different from the WAL's real one
    // (the hidden-committed-tail amnesia the fence exists to prevent). Refused BEFORE `format` submits
    // any write, so the store stays VIRGIN and the caller can re-declare and retry.
    let actual = wal.capacity();
    if self.wal_capacity != actual {
      return Err(FormatError::WalCapacityMismatch {
        declared: self.wal_capacity,
        actual,
      });
    }
    recovery::format(&self.config, &self.membership, wal, sb)?;
    // Build with the AUTHORITATIVE `wal.capacity()` `format` just pinned, not the caller-declared value.
    // The check above proved them equal, so this is defensive: the endpoint, the durable root, and the
    // backend all agree on the capacity even if that guard were ever removed.
    Ok(Endpoint::genesis_unchecked(
      self.config,
      self.membership,
      self.seed,
      self.sm,
      actual,
    ))
  }
}

impl<S> Endpoint<S, RestartOnly> {
  /// Begins genesis for a brand-new cluster member: returns the inert [`Genesis`] state that
  /// [`Genesis::commit`] turns into a runnable [`Endpoint`] (view 0, `Status::Normal`) by writing the
  /// durable genesis root. The ergonomic [`RestartOnly`] entry point (the DEFAULT capability), so a
  /// bare un-annotated `Endpoint::new(..)` yields a [`Genesis`]`<S, RestartOnly>`; a stronger
  /// capability is opted into explicitly via [`Self::with_reconfig`]
  /// (`Endpoint::<S, SingleChange>::with_reconfig(..)`).
  ///
  /// See [`Self::with_reconfig`] for the full `config` / `membership` / `wal_capacity` / `seed`
  /// contract and why genesis is a two-step gate (a runnable member requires a durable format witness).
  // Deliberately returns the [`Genesis`] type-state, not `Self`: a runnable `Endpoint` must not exist
  // without a durable format root, so `new` yields the inert genesis and `Genesis::commit` produces the
  // `Endpoint`.
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    wal_capacity: u64,
  ) -> Genesis<S, RestartOnly> {
    Self::with_reconfig(config, membership, seed, sm, wal_capacity)
  }
}

impl<S, R> Endpoint<S, R> {
  /// Begins genesis under an EXPLICIT reconfiguration capability marker `R`: returns the inert
  /// [`Genesis`] state that [`Genesis::commit`] turns into a runnable [`Endpoint`]`<S, R>` (view 0,
  /// `Status::Normal`) by writing the durable genesis root.
  ///
  /// The capability marker is part of the call (`Endpoint::<S, SingleChange>::with_reconfig(..)`),
  /// because a struct default type parameter does not participate in inference of an associated
  /// function's return type. The ergonomic [`Self::new`] is the [`RestartOnly`] entry point and
  /// defers here with `R = RestartOnly`, so every bare `Endpoint::new(..)` call resolves unannotated.
  ///
  /// **Genesis is a two-step gate, because a runnable member requires a durable format witness.** This
  /// takes no storage handles and establishes NO durability — it only packages the inputs. The runnable
  /// [`Endpoint`] is reached ONLY by [`Genesis::commit`], which writes the durable genesis root (over a
  /// virgin store), or — for an EXISTING member — by [`Self::recover`] over its own durable store. An
  /// existing member ALWAYS recovers, never re-constructs, so a store that ever held consensus state can
  /// never be silently discarded (the VSR amnesia hazard, where a replica that forgets its durable
  /// view/log re-votes across a view change and committed state diverges). The bundled drivers do
  /// exactly this. Recovery's genesis-primary decision is keyed on the durable FORMAT witness, which
  /// [`Genesis::commit`] writes.
  ///
  /// The static per-node parameters come from `config`; the active cluster configuration (the
  /// quorum/primary/voter logic + this node's slot) comes from `membership`. The local member
  /// ([`Config::local`]) MUST occupy a slot in `membership` — asserted when the endpoint is built (at
  /// [`Genesis::commit`]; release too).
  ///
  /// **`wal_capacity` declares the WAL backend this endpoint will run over** — the caller passes the
  /// backend's [`Wal::capacity`] (`u64::MAX` for an unbounded/ring-less backend). Because the genesis
  /// constructor observes no storage, the declaration is what every durable root this endpoint writes
  /// stamps as the capacity half of its WAL-GEOMETRY pair; the next recovery then validates the real
  /// backend against it and refuses a restart under different geometry (a mis-declaration is therefore
  /// fail-closed at the next boot, never silent). It MUST be nonzero — asserted when the endpoint is
  /// built (release too): `0` is the wire-level "unrecorded" sentinel a pre-v8 root decodes to, which
  /// recovery refuses on any non-virgin store, so a live endpoint must never write it.
  ///
  /// **`seed` must carry fresh entropy per incarnation**: the solicitation-freshness nonce is
  /// derived deterministically from it, so a process restarted with a reused seed re-mints the same
  /// nonce and a delayed response to the previous incarnation passes the freshness checks. See
  /// [`Self::recover`] (where the hazard is concrete) for the full contract.
  pub fn with_reconfig(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    wal_capacity: u64,
  ) -> Genesis<S, R>
  where
    R: Reconfig,
  {
    Genesis {
      config,
      membership,
      seed,
      sm,
      wal_capacity,
      _reconfig: core::marker::PhantomData,
    }
  }

  /// Builds the runnable in-memory genesis [`Endpoint`] WITHOUT writing a durable root — the shared
  /// core of [`Genesis::commit`] (which formats the store first) and proto-internal construct-and-drive
  /// unit tests that never recover. Kept `pub(crate)`: the public API reaches a runnable endpoint only
  /// via [`Genesis::commit`] (backed by a durable format witness) or [`Self::recover`], so an embedder
  /// can never mint a voter over a store with no durable root.
  ///
  /// The local member ([`Config::local`]) MUST occupy a slot in `membership`, and `wal_capacity` MUST be
  /// nonzero — both asserted here in RELEASE too.
  pub(crate) fn genesis_unchecked(
    config: Config,
    membership: Membership,
    seed: u64,
    sm: S,
    wal_capacity: u64,
  ) -> Self
  where
    R: Reconfig,
  {
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
    // A construction PRECONDITION enforced in RELEASE too: the declared backend capacity must be
    // nonzero — `0` is the wire-level "unrecorded" geometry sentinel recovery refuses on any
    // non-virgin store, so an endpoint born with it would write durable roots no later boot accepts.
    // A caller with no bounded ring passes `u64::MAX` (the `Wal::capacity` unbounded default).
    assert!(
      wal_capacity != 0,
      "wal_capacity must be nonzero: pass the backend's Wal::capacity() (u64::MAX for an unbounded backend)",
    );
    let nonce = Prng::new(seed).next_u64();
    // Genesis: the lineage has no predecessor, so prev_epoch == the (genesis) epoch and the prior-id
    // ring is seeded with the genesis config_id (a harmless duplicate of the current id — admitting
    // nothing extra until a real swap pushes a superseded id).
    let prev_epoch = membership.epoch();
    let lineage = [membership.config_id(); LINEAGE_RING];
    Self {
      config,
      // The caller-declared backend capacity (nonzero, asserted above) — stamped into every durable
      // root this endpoint writes; the next recovery validates the real backend against it.
      wal_capacity,
      membership,
      prev_epoch,
      lineage,
      // Genesis: no reconfiguration has produced the membership yet, so the cross-epoch serve gate
      // (`checkpoint_op >= config_install_op`) is trivially satisfied — the genesis membership is always
      // safe to serve.
      config_install_op: OpNumber::new(),
      status: Status::Normal,
      view: View::new(),
      // Genesis: view 0 is the durably-witnessed view — the committed genesis root carries it (and
      // the in-memory test seam models a formatted store the same way).
      durable_view: View::new(),
      op: OpNumber::new(),
      commit_min: OpNumber::new(),
      sm_at: OpNumber::new(),
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
      wal_writes: BTreeMap::new(),
      deferred_appends: BTreeMap::new(),
      wal_pruned: 0,
      appending: std::collections::BTreeSet::new(),
      pending_sb: None,
      pending_checkpoint: None,
      checkpoint_op: OpNumber::new(),
      checkpoint_sm_root: None,
      checkpoint_sessions_root: None,
      log_floor: OpNumber::new(),
      peer_checkpoint: BTreeMap::new(),
      nack_from: BTreeMap::new(),
      // Genesis: own checkpoint 0, no peer reports — the quorum-th order statistic is 0 (matches
      // `recompute_quorum_checkpoint` over this state, so the cache starts coherent).
      quorum_checkpoint: OpNumber::new(),
      recover: None,
      sync_carried_faulty: std::collections::BTreeSet::new(),
      repair: std::collections::BTreeSet::new(),
      sync: None,
      // No reconfiguration has been hinted: no crossing is owed (re-established by a higher-epoch trigger).
      cross_epoch_intent: None,
      pending_install: None,
      block_fetch: None,
      sm_reconstruct: None,
      sync_serving: BTreeMap::new(),
      state_syncs_applied: 0,
      forced_syncs_applied: 0,
      wal_stalls: 0,
      below_ring_window_syncs: 0,
      dag_walks_capped: 0,
      unions_floored: 0,
      repair_batches_served: 0,
      prepare_batches_sent: 0,
      header_only_carriers_emitted: 0,
      sessions_evicted: 0,
      pending_forfeit: false,
      reconfigure_inflight: None,
      pending_swap: None,
      paying_checkpoint_debt: false,
      peer_progress: BTreeMap::new(),
      learner_proof: None,
      _reconfig: core::marker::PhantomData,
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

  /// The op numbers of `Reconfigure` ops in this replica's COMMITTED log (`op <= commit`) still
  /// carried in the log (committed but above the checkpoint). A consensus-layer `Reconfigure` op is
  /// committed and numbered but NEVER applied to the state machine (it carries no client request), so
  /// an observer reconciling the committed op-number sequence against the applied stream must account
  /// for it from COMMIT — not only once its durable swap installs ([`Event::MembershipChanged`]).
  /// Empty unless a reconfiguration committed on this replica. Op numbers are the raw `u64` log keys.
  pub fn committed_reconfigure_op_numbers(&self) -> std::vec::Vec<u64> {
    let commit = self.commit_min.get();
    self
      .log
      .iter()
      .filter(|(op, e)| **op <= commit && matches!(e.body, Body::Reconfigure(_)))
      .map(|(op, _)| *op)
      .collect()
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

  /// One of the two sole advancers of the [`Self::sm_at`] SM-content witness: op `op`'s SM-effect
  /// has just been fully performed — an `sm.apply` returned, or a committed `Reconfigure` op was
  /// accounted (its SM-effect is vacuous by design: the epoch swap, not an apply, is its effect).
  /// Committed ops reach the SM strictly in order with no skips, so the witness is pinned to the
  /// exact successor — a double-apply, a skipped op, or an apply ordered before its predecessor
  /// trips here rather than surfacing as divergent SM state three views later.
  fn note_sm_advanced(&mut self, op: OpNumber) {
    debug_assert_eq!(
      op.get(),
      self.sm_at.get() + 1,
      "SM content advanced non-sequentially (op {} over sm_at {})",
      op.get(),
      self.sm_at.get(),
    );
    self.sm_at = op;
  }

  /// The other sole advancer of the [`Self::sm_at`] SM-content witness: a successful `sm.restore`
  /// replaced the SM's content wholesale with checkpoint `at`'s. Monotone — every restore site
  /// installs a checkpoint at/above the applied frontier (`install_sync` asserts `checkpoint_op >=
  /// commit_min`; recovery restores the durable root's own checkpoint into a fresh endpoint) — so a
  /// backward restore is a bug this catches, not a state to represent.
  fn note_sm_restored(&mut self, at: OpNumber) {
    debug_assert!(
      at.get() >= self.sm_at.get(),
      "SM content restored backward (to {} below sm_at {})",
      at.get(),
      self.sm_at.get(),
    );
    self.sm_at = at;
  }

  /// Install a committed reconfiguration's SUCCESSOR membership — the DESTRUCTIVE half of the
  /// commit-first epoch swap, run ONLY from [`Self::on_sb_done`]'s `SwapEpoch` arm once the durable
  /// root carrying `successor` has landed (the durable-epoch-before-participate fence — mirroring
  /// `start_view_participate` for the durable-view fence and `install_sync` for the durable-sync
  /// fence). After this the node advertises the NEW quorum/voter-set, justified by a durable root.
  ///
  /// The successor's `epoch` is the predecessor's `epoch + 1` and its `config_id` chains from the
  /// predecessor (both derived at commit via `self.membership.reconfigure`); `prev_epoch` becomes the
  /// OLD epoch — the durable backward link of the lineage that every future durable-root write
  /// persists. Recomputing the cached quorum-checkpoint floor is load-bearing: the membership feeds
  /// `compute_quorum_checkpoint_op` (it reads the voter slots `0..replica_count`), so a changed voter
  /// set must refresh the cache or the cached value drifts from the recomputed one (the
  /// `quorum_checkpoint_op` cache-coherence assert would fire). Emits [`Event::MembershipChanged`].
  ///
  /// **Lineage ring (hazard b).** The predecessor's `config_id` is pushed onto the bounded recent-prior
  /// ring ([`Self::lineage`], most-recent-first), so [`Self::in_lineage`] keeps admitting the
  /// AGNOSTIC catch-up traffic of a replica lagging by up to [`LINEAGE_RING`] live single-changes while
  /// still rejecting a forked/long-stale `config_id`.
  ///
  /// **Removed-leader abdication (hazard a).** Captured BEFORE the swap: was this node the primary of
  /// its view under the OLD membership? If so AND it is NOT a voter under the NEW membership (removed
  /// entirely, so its slot is absent, or — not expressible by a single delta but handled uniformly —
  /// demoted to a learner), it must go SILENT as primary: RETIRE the Normal-primary cadence (the commit
  /// heartbeat + the prepare retransmit + the forfeit grace) and CLEAR the deferred-forfeit latch.
  /// `abdicate_if_primary` does not suffice here — under the NEW membership `is_primary()` is already
  /// false (the node has no voter slot), so it early-returns; the cadence is retired directly. The
  /// cluster then elects an E+1 primary from the new voter set via the surviving backups' idle timers.
  /// Clearing the forfeit sub-states is also load-bearing for the `assert_invariants` coupling (both
  /// imply a Normal PRIMARY): a removed node is no longer the primary, so a leftover set flag would
  /// fire. A removed live node never durably participates again (its slot is gone); `recover` resolves
  /// an absent member to [`Recovered::Retired`] on a subsequent restart.
  ///
  /// This is the SOLE runtime mutator of `self.membership`, and that is what makes the XI-b CP overlap
  /// (exact-durable-catch-up) hold WITHOUT any extra per-emission gate. Every strict E+1 message
  /// (`Prepare`/`PrepareOk`/`Commit`/`DoViewChange`/`StartView`/`StartViewChange`) stamps
  /// `self.membership.epoch()` / `config_id()`, so a node stamps E+1 only AFTER this install — i.e.
  /// only after its durable SwapEpoch root proved the `Reconfigure` op committed, which (commit-first)
  /// means it holds the FULL E-committed prefix `<=` that op. So EVERY E+1 view-change-quorum member
  /// — retained or newly added — holds every E-committed op `o`, hence `o` rides
  /// `select_canonical_log`'s union and is never nack-truncated. The OLD-write-quorum-vs-NEW-view-
  /// change-quorum count bound is not ≥1 for a 3→2 shrink or a 3→4 grow, so this structural gate (not
  /// a count) is the load-bearing invariant; the `cp_overlap_*` reconfigure tests pin it.
  /// Re-key a slot-indexed voter bitset from this (PREDECESSOR) membership's slot layout to the
  /// `successor`'s, by stable [`MemberId`]: each set bit at OLD slot `s` is resolved to the member
  /// `self.membership.member_at(s)` cast it, then re-placed at that member's NEW voter slot
  /// `successor.slot_of(member)` — but ONLY if the member is still a VOTER under the successor. A bit
  /// for a member with no successor slot (REMOVED) or a non-voter successor slot (DEMOTED to learner) is
  /// DROPPED. An out-of-range OLD bit (no member) is also dropped. The result therefore counts ONLY
  /// votes of current-config voters, placed at their current slots — so a `count_ones()` against the
  /// successor quorum is sound.
  fn rekey_slot_bitset(&self, bits: u64, successor: &Membership) -> u64 {
    let mut remapped = 0u64;
    let mut rest = bits;
    while rest != 0 {
      let old_slot = rest.trailing_zeros() as u16;
      rest &= rest - 1; // clear the lowest set bit
      if let Some(member) = self.membership.member_at(ReplicaId::new(old_slot))
        && let Some(new_slot) = successor.slot_of(member)
        && successor.is_voter(new_slot)
      {
        remapped |= 1u64 << new_slot.get();
      }
    }
    remapped
  }

  /// Re-key every slot-indexed quorum accumulator that survives an in-place membership swap from this
  /// (PREDECESSOR) membership's slot layout to the `successor`'s, by stable [`MemberId`] (see
  /// [`Self::rekey_slot_bitset`]). Called from [`Self::install_membership`] BEFORE `self.membership` is
  /// replaced, so the OLD slot layout is still available to resolve each bit's caster.
  ///
  /// Two accumulators survive the commit-first SwapEpoch landing (a still-Normal primary, no view
  /// transition, the pipeline NOT cleared): the per-op commit-vote bitsets `inflight.*.oks` (a removed
  /// voter's stale ack must NOT count toward the successor commit quorum — that is the safety-critical
  /// case) and the StartViewChange bitset `svc_from` (live in Normal; a stale/misattributed SVC bit must
  /// not trip a spurious view change). Both become current-config-only after this. The already-committed
  /// prefix is untouched — only UNCOMMITTED inflight entries hold votes, and re-keying drops/relocates
  /// bits without changing the op set, so nothing at/below `commit_min` moves.
  fn rekey_slot_quorums_for_swap(&mut self, successor: &Membership) {
    let mut inflight = core::mem::take(&mut self.inflight);
    for inf in inflight.values_mut() {
      if !inf.committed {
        inf.oks = self.rekey_slot_bitset(inf.oks, successor);
      }
    }
    self.inflight = inflight;
    self.svc_from = self.rekey_slot_bitset(self.svc_from, successor);
  }

  fn install_membership(&mut self, reconfigure_op: Option<OpNumber>, successor: Membership) {
    // Capture the abdication precondition (hazard a) against the OLD membership, BEFORE the swap:
    // was this node the primary of its current view? (Robust to an already-absent local member.)
    let was_primary = self.is_primary();
    let prior_config_id = self.membership.config_id();
    // Drop any outstanding learner-promote-proof challenge across the epoch swap: it was minted under
    // the OLD configuration, so a pre-swap reply must never validate a post-swap mint. The reply's
    // `(epoch, config_id)` binding is the structural backstop (a proof for the predecessor config never
    // matches the successor); this is the explicit clear at the install boundary.
    self.learner_proof = None;
    self.prev_epoch = self.membership.epoch();
    let epoch = successor.epoch();
    let config_id = successor.config_id();
    // Re-key the slot-indexed quorum accumulators that SURVIVE this in-place swap (the commit-first
    // SwapEpoch landing runs on the still-Normal primary; `inflight`/`svc_from` are NOT cleared on the
    // retained-node path) through the predecessor->successor MemberId mapping, BEFORE swapping the
    // membership in (the re-key needs the OLD slot layout). A vote/SVC bit set under an OLD slot is
    // resolved to the stable member that cast it and re-placed at that member's NEW voter slot; a
    // REMOVED member's bit (no new voter slot) is DROPPED, and a slot SHIFT carries a retained voter's
    // bit to its new index. Without this, `try_commit` (`inflight.oks.count_ones() >= quorum`) would
    // count a removed voter's stale ack toward the NEW (possibly smaller) commit quorum and commit a
    // post-reconfiguration tail op WITHOUT a current-config write quorum — committed-op loss across the
    // E+1 view change. `svc_from` is the liveness sibling (a stale/misattributed StartViewChange bit
    // could trip a spurious view change); re-keying it the same way closes the whole class at the swap.
    // Mirrors the `peer_checkpoint` MemberId re-key; with no reconfiguration this never runs, so the
    // off-axis behavior is byte-identical.
    self.rekey_slot_quorums_for_swap(&successor);
    // Clear the nack-truncation tally at the swap: a membership change within a view resets the generation
    // the nack proof is scoped to. `nack_from` holds distinct voters that nacked a candidate under the OLD
    // configuration, and `on_nack` counts it against `quorum_nack_prepare()` — which the successor config
    // recomputes (a smaller voter set lowers `f+1`). Counting predecessor nacks against the successor
    // threshold is the exact hazard the `inflight.oks` re-key above closes for commit votes: it could
    // truncate a candidate without a current-config non-holder quorum. The nack tally is cheap to re-gather
    // (the candidates are re-solicited every repair round), so clear it rather than re-key — a fresh
    // generation under the new config re-accumulates. (Off the reconfiguration path this never runs, so the
    // behavior is byte-identical.)
    self.nack_from.clear();
    self.membership = successor;
    // Push the superseded config_id onto the recent-prior lineage ring (most-recent-first), so
    // `in_lineage` keeps admitting a bounded window of recent ancestors for live cross-epoch catch-up.
    self.push_lineage(prior_config_id);
    // Record the op that produced THIS membership so the cross-epoch state-sync serve gate
    // (`checkpoint_op >= config_install_op`) holds. A commit-first swap (`Some(op)`) names its committed
    // `Reconfigure` op `N` — until this node's checkpoint reaches `N` it must NOT serve E+1 to a laggard
    // (the laggard would install E+1 below `N`, without the committed prefix through `N`). A cross-epoch
    // state-sync install (`None`) sets it to the synced frontier separately in `install_sync` — that
    // frontier is at/above the donor's `N` (the donor served it only because its own checkpoint reached
    // `N`), so it is a safe, restart-survivable lower bound.
    if let Some(op) = reconfigure_op {
      self.config_install_op = op;
    }
    // The voter set changed, so the quorum-checkpoint inputs (which member holds each voter slot)
    // changed: refresh the cached order statistic the GC prune floor / force-sync trigger read. No
    // explicit prune of `peer_checkpoint` is needed — it is keyed by stable `MemberId`, and both floor
    // consumers (`compute_quorum_checkpoint_op` voters-only; `max_peer_checkpoint_op`
    // current-members-only) intersect with the new membership, so a removed member's stale report is
    // structurally excluded (it lifts no floor) and a retained voter's report follows its id across a
    // slot shift. The leftover removed-member entry is inert and is cleared by the next view-transition.
    self.recompute_quorum_checkpoint();
    // Removed-node goes silent (hazard a): a swap that drops THIS node from the voter set retires its
    // whole voter timer plane. An ex-primary abdicates its primary cadence (the cluster elects an E+1
    // primary from the new voter set via the surviving backups' idle timers); EVERY removed node (ex-
    // primary or ex-backup) also retires the backup idle/view-change plane. `local_slot_opt()` is `None`
    // when removed entirely; a learner slot is `>= replica_count`. Either way `is_voter` is false, and
    // `serviceable_now` already blocks servicing — this clears the armed deadlines for cleanliness.
    let still_voter = self
      .local_slot_opt()
      .is_some_and(|slot| self.membership.is_voter(slot));
    if !still_voter {
      if was_primary {
        self.retire_primary_cadence();
      }
      self.retire_backup_cadence();
      // A node fully REMOVED from the configuration (no slot at all — not merely demoted to a learner,
      // which keeps a slot and stays a non-voting participant) transitions to the structural `Retired`
      // state: the central ingress drops all its messages and it arms/services no timer, so it reaches
      // no voter path (nor any panicking `local_slot()`) by construction — the removed-member class
      // closed structurally rather than by per-gate patches.
      if self.local_slot_opt().is_none() {
        // Abandon the in-flight consensus pipeline before retiring: a removed node owes no ack/vote and
        // appends no more ops, so clear the pending WAL appends, their append-before-ack marks, and the
        // inflight vote bitsets. A straggling WAL completion then finds nothing and is dropped by the
        // `on_wal_done` Retired guard, so `has_inflight_storage()` settles (a graceful shutdown completes)
        // and no stale completion can reach `local_slot()`.
        self.pending.clear();
        self.appending.clear();
        self.deferred_appends.clear();
        self.inflight.clear();
        self.set_status(Status::Retired);
      }
    }
    // Emit MembershipChanged only for a commit-first swap (`Some` reconfigure op). A cross-epoch
    // state-sync install (`None`) has no LOCAL Reconfigure op to name — the laggard synced PAST it — so
    // naming the sync frontier (a client op) would misreport the consensus-layer applied gap to an
    // observer; the swap is observable via the sync completion + the installed membership, and the real
    // Reconfigure op is reported by the replicas that committed it directly. The observer still learns
    // THIS node's role under the new configuration purely from the committed membership.
    if let Some(op) = reconfigure_op {
      let self_is_learner = self
        .local_slot_opt()
        .is_some_and(|slot| self.membership.is_learner(slot));
      self
        .events
        .push_back(Event::MembershipChanged(crate::MembershipChanged::new(
          op,
          epoch,
          config_id,
          still_voter,
          self_is_learner,
        )));
    }
  }

  /// Push a just-superseded `config_id` onto the recent-prior lineage ring (most-recent-first): shift
  /// every retained id down one and drop the oldest, so the ring always holds the [`LINEAGE_RING`] most
  /// recent ancestors. Read by [`Self::in_lineage`] to widen AGNOSTIC-message admission across a small
  /// epoch gap. (A fixed-size shift, not a heap ring — [`LINEAGE_RING`] is tiny and `no_std`-friendly.)
  fn push_lineage(&mut self, superseded: u128) {
    self.lineage.copy_within(..LINEAGE_RING - 1, 1);
    self.lineage[0] = superseded;
  }

  /// The recent-prior lineage ring AS IT WOULD BE after pushing `superseded` (most-recent-first), without
  /// mutating `self.lineage`. Used to stamp a SwapEpoch durable root — which carries the SUCCESSOR
  /// membership but is written BEFORE `install_membership` runs the real `push_lineage` at `on_sb_done` —
  /// with the lineage that MATCHES the successor it carries (the just-superseded predecessor id shifted
  /// in), so a node recovering off that root restores the post-swap lineage exactly as the live install
  /// would have built it.
  fn lineage_after_push(&self, superseded: u128) -> std::vec::Vec<u128> {
    let mut ring = self.lineage;
    ring.copy_within(..LINEAGE_RING - 1, 1);
    ring[0] = superseded;
    ring.to_vec()
  }

  /// The recent-prior lineage ring AS IT WOULD BE after a CROSS-EPOCH crossing install that skipped one
  /// or more epochs, without mutating `self.lineage`. The crossing snapshot carried a successor that
  /// VERIFIED against `verified_prev` (the `prev_config_id` the `ReconfigurePayload` pinned), so the
  /// installed configuration's immediate predecessor is `verified_prev` — NOT the laggard's own current
  /// `config_id`, which on a MULTI-epoch skip is an EARLIER ancestor. So the ring becomes
  /// `[verified_prev, superseded, ..]` most-recent-first: push the laggard's just-superseded current
  /// (`superseded`), THEN push the verified immediate predecessor on top. A later re-serve of the
  /// successor membership thus chains from `verified_prev` and recomputes the SAME `config_id` a fresh
  /// laggard expects. For a SINGLE-epoch crossing (`verified_prev == superseded`) the extra push would
  /// duplicate the slot, so the caller takes the plain [`Self::lineage_after_push`] path — keeping the
  /// common E0→E1 case byte-identical. Used to stamp the SwapEpoch-analogue durable root for a sync
  /// crossing (the root is written BEFORE `install_sync` runs the live push), so a node recovering off
  /// that root restores the SAME verified chain the live crossing builds.
  fn lineage_after_crossing_push(
    &self,
    superseded: u128,
    verified_prev: u128,
  ) -> std::vec::Vec<u128> {
    let mut ring = self.lineage;
    ring.copy_within(..LINEAGE_RING - 1, 1);
    ring[0] = superseded;
    ring.copy_within(..LINEAGE_RING - 1, 1);
    ring[0] = verified_prev;
    ring.to_vec()
  }

  /// Retire the Normal-primary CADENCE — the commit heartbeat, the prepare retransmit, and the forfeit
  /// grace timer — and clear the deferred-forfeit latch. The removed-leader abdication
  /// ([`Self::install_membership`]) calls it when a swap drops this ex-primary from the voter set: it
  /// must go silent as primary so the surviving voters' idle timers elect an E+1 primary. This is the
  /// same timer-level effect the `primary_timeouts` `pending_forfeit`/`pending_sb` branches and
  /// `arm_timers`'s reset have, here driven by losing the primacy itself rather than by stepping down
  /// within the same configuration. Clearing the forfeit sub-states keeps the `assert_invariants`
  /// coupling (a set forfeit flag ⟹ a Normal PRIMARY) intact now that this node is no longer primary.
  fn retire_primary_cadence(&mut self) {
    self.timers.commit = None;
    self.timers.prepare = None;
    self.timers.forfeit_armed = None;
    self.pending_forfeit = false;
  }

  /// Retire the backup voter timer plane — the idle timer and the view-change vote/escalation timers a
  /// removed node must no longer service. Paired with `retire_primary_cadence` at the removal site so a
  /// node dropped from the voter set holds NO armed consensus deadline. `serviceable_now` already gates
  /// each on `is_voter()` (so a stale armed deadline would be non-serviceable, not a panic), but clearing
  /// them keeps the removed node's timer set empty — the removed-node-goes-silent invariant.
  fn retire_backup_cadence(&mut self) {
    self.timers.primary_idle = None;
    self.timers.svc_message = None;
    self.timers.dvc_message = None;
    self.timers.view_change_status = None;
  }

  /// Stage the SUCCESSOR membership of a just-committed `Body::Reconfigure` op for its durable epoch
  /// swap, the COMMIT-FIRST half of the swap. Latches `(reconfigure_op, successor)` in `pending_swap`
  /// (NOT in `self.membership` — the fence) and clears the single-writer reconfiguration latch, then
  /// tries to submit the SwapEpoch durable root immediately. Called from both apply sites
  /// ([`Self::commit_op`] on the primary, [`Self::advance_commit`] on a backup) the instant the op
  /// commits. The op is NOT applied to the state machine (it is consensus-layer) and the epoch is NOT
  /// advanced in memory yet. `reconfigure_op` is captured here (where `commit_min` is exactly at it) so
  /// the install-time `MembershipChanged` names the reconfigure op even after `commit_min` advances past
  /// it through the SwapEpoch window.
  fn stage_epoch_swap(
    &mut self,
    reconfigure_op: OpNumber,
    successor: Membership,
    sb: &mut impl Superblock,
  ) where
    S: StateMachine,
    R: Reconfig,
  {
    // DEFENSE IN DEPTH, ENFORCED IN RELEASE: never overwrite an already-staged successor. This branch is
    // UNREACHABLE by construction: `propose_membership` refuses a new reconfiguration while one is
    // outstanding (`has_pending_reconfigure`, which includes `pending_swap.is_some()`), so at most ONE
    // reconfiguration is ever committed-but-not-installed, and `stage_epoch_swap` runs EXACTLY once — the
    // instant `commit_min` (monotone) crosses the op, never re-entered afterward. A staged `pending_swap`
    // here would therefore mean the single-change-at-a-time gate was already violated (a second
    // `Reconfigure` committed before the first installed) — a latent bug, not a supported state. Overwriting
    // would CLOBBER the first's staged successor and lose it on the first `on_sb_done`, so we KEEP the
    // existing staged swap and refuse in RELEASE too (a debug-only assert vanishes in production, leaving the
    // clobber live). This is a FAIL-SAFE against an invariant break — NOT a recovery path: the refused op is
    // NOT re-staged (its `stage_epoch_swap` ran once and `commit_min` is already past it), so if this branch
    // ever fired the second change would simply not install until the gate bug that let it commit is fixed.
    debug_assert!(
      self.pending_swap.is_none(),
      "stage_epoch_swap would overwrite a staged successor for op {:?} with op {}",
      self.pending_swap.as_ref().map(|s| s.op().get()),
      reconfigure_op.get(),
    );
    if self.pending_swap.is_some() {
      return;
    }
    self.reconfigure_inflight = None;
    self.pending_swap = Some(EpochSwap::new(reconfigure_op, successor));
    self.maybe_swap_epoch(sb);
  }

  /// Is a committed-but-not-installed epoch swap outstanding — the COMMIT→INSTALL window of a live
  /// reconfiguration? `pending_swap` is `Some` for exactly that window (set when the `Reconfigure` op
  /// commits, cleared when its durable `SwapEpoch` root installs the successor), and it SURVIVES a view
  /// change (the committed change is not lost). The in-flight `SwapEpoch` root is a strict SUBSET of this
  /// window, so `pending_swap.is_some()` alone captures it; the explicit `pending_sb` SwapEpoch-action
  /// check is belt-and-suspenders for the single-change-at-a-time gate. Read by `propose_membership` so a
  /// second reconfiguration cannot be proposed across the epoch boundary while the first is installing.
  fn swap_in_flight(&self) -> bool {
    self.pending_swap.is_some()
      || matches!(self.pending_sb, Some((_, PendingSbAction::SwapEpoch(_))))
  }

  /// Is ANY membership change in flight — proposed-but-not-committed OR committed-but-not-installed —
  /// derived STRUCTURALLY from the log, the source of truth, not from the `reconfigure_inflight` latch
  /// that a view change clears. True iff EITHER:
  ///
  /// - a committed-but-not-installed swap is outstanding ([`Self::swap_in_flight`]: the `Reconfigure`
  ///   op committed and its `SwapEpoch` root is staged / in flight but not yet installed); OR
  /// - an UNCOMMITTED `Body::Reconfigure` entry sits in the log's tail `(commit_min, op]` — covering
  ///   both a normally-proposed-but-not-yet-committed reconfiguration AND one CARRIED canonical into a
  ///   new view by `start_view_as_new_primary` (where it rides the adopted log but has not re-committed,
  ///   so the latch is `None`). The proposal latch (`reconfigure_inflight`) is a fast-path BOOKKEEPING
  ///   hint that does not survive a view-change reset, so it is NOT the authority here — the log is.
  ///
  /// `propose_membership` rejects (`AlreadyInFlight`) whenever this holds, so the cluster never has two
  /// overlapping configuration changes racing across the epoch boundary even after a view change carries
  /// the first uncommitted change forward. The tail scan is bounded by the uncommitted-tail width
  /// `op - commit_min` (the pipeline depth, small), not the whole log.
  fn has_pending_reconfigure(&self) -> bool {
    if self.swap_in_flight() {
      return true;
    }
    let lo = self.commit_min.get() + 1;
    let hi = self.op.get();
    (lo..=hi).any(|op| {
      self
        .log
        .get(&op)
        .is_some_and(|entry| entry.body.as_reconfigure().is_some())
    })
  }

  /// Submit the staged SwapEpoch durable root IF the view is durable AND the superblock is free — the
  /// single-writer sequencing that keeps a SwapEpoch behind any in-flight superblock write (a concurrent
  /// checkpoint root, a durable-view write), the SAME exclusion `maybe_checkpoint` enforces. A SwapEpoch
  /// that commits while a checkpoint root is in flight WAITS its turn: `pending_swap` stays latched and
  /// the next free superblock slot — re-checked at the commit tails (alongside `maybe_checkpoint`) and
  /// from `on_sb_done` when any write completes — submits it. No-op if nothing is staged or a write is
  /// already in flight. The `(op, successor)` is CLONED into the pending action so `pending_swap` survives
  /// a supersession of the root write.
  ///
  /// DURABLE-VIEW GATE (`is_normal() && log_view == view`, exactly `maybe_checkpoint`'s gate): the
  /// SwapEpoch root persists `self.view` / `self.log_view`, so it must be minted only when that view is
  /// SETTLED and durable. A view change leaves `pending_swap` staged (the committed change is not lost —
  /// see `reset_for_view_transition`) but advances `self.view` ahead of `log_view`; submitting a SwapEpoch
  /// root THEN would persist a not-yet-durable view through the wrong path (bypassing the
  /// SendDoViewChange/StartView durable-view sequence the fence relies on). So the staged swap WAITS for
  /// the view to settle: it re-submits from `on_sb_done` once the durable-view root lands (status already
  /// Normal, `log_view == view`) and from the commit tails on the `catch_up_to_view` path that issues no
  /// durable-view write. This also covers the `start_view_as_new_primary` formation, where `advance_commit`
  /// can re-commit a carried `Reconfigure` op while status is still ViewChange — the swap defers here and
  /// fires once the new view is durable.
  fn maybe_swap_epoch(&mut self, sb: &mut impl Superblock)
  where
    S: StateMachine,
    R: Reconfig,
  {
    // STALE-SWAP GUARD (correct-by-construction): a staged swap installs ONLY if its successor still
    // chains from the LIVE configuration. The successor's `config_id` is `hash(successor parts,
    // predecessor config_id)`, where the pinned predecessor is the configuration this swap was staged
    // against. Recompute that hash chaining from THIS node's CURRENT `config_id`: it matches iff the
    // current membership IS still that predecessor. If the membership has ALREADY ADVANCED to this (or a
    // later) successor — a CROSS-EPOCH state-sync install (`install_membership(None, successor)`) crossed
    // the epoch boundary while the swap sat staged, or any other path superseded it — the recompute does
    // NOT match: the staged swap is STALE. Re-submitting it would mint a DUPLICATE SwapEpoch root stamped
    // with the already-advanced config as its OWN predecessor, push that config into the lineage ring a
    // second time, emit a bogus `MembershipChanged`, and evict legitimate older ancestors from the
    // bounded window — stranding laggards. So DROP the stale staged swap (never submit it) and clear it.
    // A legitimately staged swap that still chains from the live config matches and proceeds unchanged, so
    // the normal (non-crossed) path — and the off-axis no-reconfiguration path, where `pending_swap` is
    // always `None` — is byte-identical.
    if let Some(swap) = self.pending_swap.as_ref() {
      let successor = swap.successor();
      let chained = Membership::recompute_config_id(
        successor.epoch(),
        successor.replica_count(),
        successor.learner_count(),
        successor.members_slice(),
        self.membership.config_id(),
      );
      if chained != successor.config_id() {
        self.pending_swap = None;
        return;
      }
    }
    if !self.status.is_normal() || self.log_view.get() != self.view.get() {
      return; // the view is not settled/durable — a SwapEpoch root must not persist it
    }
    if self.pending_sb.is_some() || self.pending_checkpoint.is_some() {
      return; // a superblock write is in flight — the swap waits its turn
    }
    let Some(swap) = self.pending_swap.clone() else {
      return; // nothing staged
    };
    let (reconfigure_op, successor) = swap.into_parts();
    self.submit_swap_epoch(reconfigure_op, successor, sb);
  }

  /// Mint the SwapEpoch durable root carrying `successor` — a v4 root whose scalar epoch is the
  /// successor's epoch, whose `prev_epoch` is the CURRENT (predecessor) epoch, and whose membership is
  /// the successor — and arm the deferred install (`PendingSbAction::SwapEpoch`), carrying the
  /// `reconfigure_op` it will name. Unlike [`Self::durable_root`] (which stamps `self.membership`, the
  /// predecessor, still active here), this stamps the SUCCESSOR explicitly: the root proves the NEW
  /// configuration before it is installed in memory. The consensus frontier
  /// (`view`/`log_view`/`commit_max`/`checkpoint_op`/`checkpoint_id` + the committed-band headers) is
  /// carried UNCHANGED — a reconfiguration changes ONLY the configuration, never the replicated log.
  ///
  /// The checkpoint pair is `self.checkpoint_op` + the durable `checkpoint_id`: the install advances
  /// `self.checkpoint_op` in lockstep with its durable root, so it always equals
  /// `sb.state().checkpoint_op()` and this root can never rewind the durable checkpoint (structural
  /// no-rewind).
  fn submit_swap_epoch(
    &mut self,
    reconfigure_op: OpNumber,
    successor: Membership,
    sb: &mut impl Superblock,
  ) where
    S: StateMachine,
    R: Reconfig,
  {
    let checkpoint_id = sb.state().checkpoint_id();
    // The lineage this root carries is the POST-swap ring: the predecessor `config_id` (the current
    // membership, which the successor chains off) shifted onto the front of the current ring — exactly
    // what `install_membership`'s `push_lineage` will build at `on_sb_done`. So a node recovering off this
    // SwapEpoch root restores the same lineage the live install would have, keeping a retained old-epoch
    // laggard's cross-epoch catch-up admissible after the new-epoch donors restart.
    let prior_config_ids = self.lineage_after_push(self.membership.config_id());
    let state = crate::VsrState::try_new_v4(
      self.view,
      self.log_view,
      self.commit_max,
      self.checkpoint_op,
      checkpoint_id,
      self.committed_band_headers(self.checkpoint_op),
      successor.epoch(),
      self.membership.epoch(),
      successor.clone(),
      prior_config_ids,
      // This root installs the NEW successor membership, so it carries the NEW reconfigure op `N` (NOT the
      // writer's current `config_install_op` — that named the PREDECESSOR membership). A node recovering off
      // this SwapEpoch root then restores `config_install_op = N`, so it withholds the new membership from a
      // laggard until its checkpoint reaches `N` — the gate is restart-survivable from the moment of swap,
      // even though the checkpoint here is still BELOW `N` (the commit-first window the gate exists for).
      reconfigure_op,
    )
    // The live vouched floor, carried verbatim (a swap changes only the configuration; `log_floor >=
    // checkpoint_op` holds live, so no raise is needed).
    .and_then(|s| s.with_log_floor(self.log_floor))
    .expect(
      "SwapEpoch root: log_view <= view, commit >= checkpoint_op, membership epoch consistent",
    )
    // The live WAL-geometry pair, stamped exactly as `durable_root` does — a swap changes only the
    // configuration, not the geometry, so the SwapEpoch root must stay FORMATTED. Without it, a crash
    // in the window between this root landing and the forced-checkpoint root would leave a store whose
    // root records no geometry (0,0), which recovery refuses fail-closed as unrecorded — bricking a
    // legitimately-reconfigured node behind an offline migration for no reason.
    .with_wal_geometry(self.config.checkpoint_ops(), self.wal_capacity);
    let id = self.mint_op_id();
    sb.submit_write(id, state);
    self.pending_sb = Some((
      id,
      PendingSbAction::SwapEpoch(EpochSwap::new(reconfigure_op, successor)),
    ));
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
    // A RETAINED-but-not-staged install (a verified sync whose flush faulted, owed as `pending_install`) and
    // a staged one alike are mid durable completion, NOT a repair-satisfiable pre-stage sync — both are the
    // single `pending_install` check, exempted alongside the SM-reconstruct obligation: their own local
    // cadence completes them. A forced sync's target is above `commit_min` while either is owed, so this
    // never fires anyway, but the exemption keeps the install from being dropped by a repair-satisfied cancel.
    if self.pending_install.is_some() || self.sm_reconstruct_owed() {
      // A STAGED forced sync is completing via install_sync — not a repair-satisfied cancel. This also
      // covers an owed SM-reconstruct (the post-root restore retry): `sync` stays armed for the retry, so
      // this early return preserves it (the obligation is never dropped by a repair-satisfied cancel).
      // The apply-loop tails that call this already early-return while the obligation is owed, so this is a
      // defensive backstop.
      return;
    }
    // A CROSS-EPOCH crossing (`require_cross_epoch`) is explicitly exempted, matching the same carve-out
    // in `apply_sync`, `drop_transfer_below_forced_target`, and the `abdicate_if_primary` branch. A
    // crossing has `target >= N > commit_min` (the reconfigure op is above this laggard's applied
    // frontier), so this condition is structurally false for a crossing today and never fires — but the
    // exemption closes the class defensively, in case that emergent gap ever narrows.
    if self.sync.is_some_and(|s| {
      s.forced && s.target.get() <= self.commit_min.get() && !s.require_cross_epoch
    }) {
      self.sync = None;
      self.block_fetch = None;
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
    // (1) A PRE-ROOT staged install belongs to an OUTSTANDING sync: `apply_sync` stages `pending_install`
    // and `sync` together, and every clear path drops `pending_install` no later than `sync` (the
    // `on_sb_done` SyncRepersist arm `take()`s it when the durable root lands; the view-change resets drop
    // both). It also implies an in-flight checkpoint re-persist (`pending_checkpoint`) — the same
    // `apply_sync` submits the two-write checkpoint sequence that carries the install to durability. (The
    // recovery path STAGES while still `Recovering`, so a set `pending_install`/`sync`/`pending_checkpoint`
    // is not coupled to Normal status.)
    debug_assert!(
      self.pending_install.is_none() || self.sync.is_some(),
      "pending_install without an outstanding sync"
    );
    // A `pending_install` is RETAINED from the moment `apply_sync` verifies it (BEFORE its durability
    // barrier) until it COMMITS, so it spans two sub-states: (a) RETAINED-but-not-staged — a flush fault
    // left its two-write re-persist un-submitted, so NO `pending_checkpoint` is in flight and the local
    // cadence re-attempts the flush; (b) STAGED — the flush succeeded and `flush_and_stage_install` submitted
    // the SyncRepersist checkpoint. So a set `pending_install` may legitimately have NO in-flight checkpoint.
    // What MUST still hold: while it is staged, that in-flight checkpoint is the SyncRepersist carrying IT to
    // durability — NEVER an ORDINARY checkpoint. The single-superblock-writer fence at the sync-answer
    // ingress (`handle_sync_checkpoint` / the recovery peer-fetch defer while `pending_sb.is_some() ||
    // pending_checkpoint.is_some()`) makes this hold BY CONSTRUCTION: a sync stages only when the superblock
    // is free, so no ordinary `force_checkpoint` (e.g. the SwapEpoch arm's) can coexist with the install and
    // OVERWRITE its tracker. (The POST-root SM-content debt is NOT a `pending_install` — it is the separate
    // `sm_reconstruct` obligation, checked below — so once the root lands `pending_install` is consumed.)
    debug_assert!(
      self.pending_install.is_none()
        || self
          .pending_checkpoint
          .is_none_or(|pc| matches!(pc.kind, CheckpointKind::SyncRepersist)),
      "pending_install coexists with a non-SyncRepersist checkpoint"
    );
    // (1b) A block-DAG fetch belongs to an OUTSTANDING sync: it is armed only under a live nonce-matched
    // `sync` (`handle_sync_checkpoint`) OR re-armed by an SM-reconstruct retry that KEEPS `sync`, and
    // every clear path drops it no later than `sync` (an abort drops only the fetch, keeping `sync` armed
    // to re-solicit; an active-donor absent keeps BOTH, re-soliciting a fresh checkpoint).
    debug_assert!(
      self.block_fetch.is_none() || self.sync.is_some(),
      "block-DAG fetch without an outstanding sync"
    );
    // (1c) An SM-reconstruct obligation (a post-root restore faulted) runs its retry under a KEPT `sync`
    // (so `send_request_block` / `on_block_response` re-pull M's DAG), and `self.checkpoint_op` already
    // names M (the install advanced the pointer in lockstep with the durable root BEFORE the restore), so
    // the obligation's `checkpoint_op` equals the live `self.checkpoint_op`. It is mutually exclusive with a
    // PRE-root `pending_install` for the SAME point — the root completion consumes `pending_install` and
    // either clears the obligation (clean restore) or raises it (faulted restore).
    debug_assert!(
      self.sm_reconstruct.is_none() || self.sync.is_some(),
      "sm_reconstruct obligation without an outstanding sync"
    );
    debug_assert!(
      self
        .sm_reconstruct
        .as_ref()
        .is_none_or(|r| r.checkpoint_op == self.checkpoint_op),
      "sm_reconstruct obligation op disagrees with the (already-advanced) checkpoint_op"
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
    // (5c) The SM-CONTENT witness: the state machine's content position (`sm_at`, written only by the
    // content operations — apply / reconfigure-account / restore) equals the applied frontier
    // (`commit_min`, written only by the commit machinery) at every handler exit, UNLESS a flagged
    // behind-window is open: an owed SM reconstruction (the install advanced the pointers to M but the
    // verify-on-read restore faulted — the SM still holds pre-M content), or a cold-start recovery
    // still rebuilding the SM from the durable checkpoint. This is the first-class form of the
    // `state_machine()` readiness gate's prose ("once Some, the SM is consistent with all applied ops
    // up to commit_min") — two independently-written frontiers cross-checked, so a path that applies
    // over a stale SM, double-applies, or advances a pointer past un-restored content trips HERE
    // deterministically instead of surfacing as divergent SM state views later. `pending_install` is
    // deliberately NOT a disjunct: a pre-root staged install has not advanced `commit_min` yet, so the
    // equality must still hold through that window — listing it would blind the witness there.
    debug_assert!(
      self.sm_at == self.commit_min
        || self.sm_reconstruct.is_some()
        || self.status.is_recovering()
        || self.status.is_recovering_head(),
      "SM content at {} diverges from the applied frontier {} with no behind-window flagged \
       (status {:?}, sm_reconstruct owed: {})",
      self.sm_at.get(),
      self.commit_min.get(),
      self.status,
      self.sm_reconstruct.is_some(),
    );
    // (6) The peer-checkpoint fetch is a Recovering sub-state: `escalate_checkpoint_to_peer_fetch` sets
    // it only on the Recovering checkpoint-read-exhausted path, and `recover` is structurally `None`
    // (hence `awaiting_peer_checkpoint()` false) in every non-recovering status.
    debug_assert!(
      !self.awaiting_peer_checkpoint() || self.status.is_recovering(),
      "awaiting_peer_checkpoint outside Recovering"
    );
    // (7) A staged epoch swap (`pending_swap`) in a SETTLED, durable view ALWAYS has a superblock write
    // outstanding: in steady Normal (`log_view == view`) the commit-first stage either issued its
    // SwapEpoch root immediately (so `pending_sb` is the `SwapEpoch` action) or queued it behind an
    // in-flight checkpoint/durable-view write — and `on_sb_done` clears `pending_swap` no later than it
    // installs the durable root. So a settled-view staged swap is NEVER stuck with the superblock idle
    // (which would never re-trigger `maybe_swap_epoch`, stranding the swap). The exception is an UNSETTLED
    // view (a view change in progress: `!is_normal()` or `log_view != view`): a `pending_swap` SURVIVES
    // the transition (the committed change is not lost — `reset_for_view_transition`), but `maybe_swap_epoch`
    // is GATED on the durable view, so the swap WAITS — with possibly no write outstanding — until the
    // view settles, at which point the durable-view root's `on_sb_done` (or a commit tail on the
    // `catch_up_to_view` path) re-submits it. So the "write outstanding" obligation only binds in a settled
    // view. The durable-epoch-before-participate fence holds throughout: the membership installs only at a
    // durable SwapEpoch root, so while staged the epoch is still the predecessor's.
    debug_assert!(
      self.pending_swap.is_none()
        || self.pending_sb.is_some()
        || self.pending_checkpoint.is_some()
        || !self.status.is_normal()
        || self.log_view.get() != self.view.get(),
      "a staged epoch swap in a settled view with no superblock write in flight would never be submitted"
    );
  }

  /// Record a peer's reported `checkpoint_op` MONOTONICALLY: a peer's durable checkpoint never
  /// regresses, so a reordered/older report (a delayed `Commit`/`PrepareOk`, or a stale message
  /// after a partition heals) must never lower the value we hold. Keeping this monotone keeps the GC
  /// prune floor (`quorum_checkpoint_op`) and the force-sync/forfeit triggers that read it from
  /// moving backward — a regressing floor could spuriously un-fire the force-sync escalation. (T1)
  fn record_peer_checkpoint(&mut self, replica: ReplicaId, reported: OpNumber) {
    // Resolve the reporter's routing slot to its STABLE `MemberId` at ingest (exactly as
    // `on_learner_status` keys `peer_progress`), so the report follows the member — not the slot —
    // across a slot-shifting reconfiguration. The slot is always a current member here (every caller
    // range-checks it or derives it from `membership.primary`), so the lookup resolves; a slot with no
    // member (impossible past those checks) records nothing.
    let Some(member) = self.membership.member_at(replica) else {
      return;
    };
    let prev = self
      .peer_checkpoint
      .get(&member)
      .copied()
      .unwrap_or_else(OpNumber::new);
    self.peer_checkpoint.insert(member, prev.max(reported));
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
  ///
  /// `peer_checkpoint` is keyed by stable [`MemberId`], so each voter slot is resolved to the member it
  /// CURRENTLY holds before its report is read. This is what makes a slot-shifting reconfiguration safe:
  /// a report stored under a REMOVED member's id never resolves from a current voter slot (so it cannot
  /// lift the floor), and a retained voter's report follows its id into whatever slot it now occupies.
  fn compute_quorum_checkpoint_op(&self) -> OpNumber {
    let count = self.membership.replica_count();
    let mut cps: std::vec::Vec<u64> = std::vec::Vec::with_capacity(count as usize);
    // `me` is `None` when this node was REMOVED from the configuration (the removed-leader case): then
    // it seeds no own-checkpoint and the loop skips nothing, computing the statistic over exactly the
    // (new) voter set — a removed node correctly contributes nothing to the GC floor.
    let me = self.local_slot_opt();
    let my_member = self.config.local();
    if me.is_some_and(|slot| self.membership.is_voter(slot)) {
      cps.push(self.checkpoint_op.get()); // a voter counts its own durable checkpoint; a learner/removed does not
    }
    for r in 0..count {
      let rid = ReplicaId::new(u16::from(r));
      // Resolve the CURRENT occupant of this voter slot to its stable id; the `peer_checkpoint` map is
      // keyed by id, so a slot whose occupant changed reads the NEW voter's report (or 0 if unheard),
      // never the predecessor's stale entry stored under a different id.
      let Some(member) = self.membership.member_at(rid) else {
        cps.push(0);
        continue;
      };
      if member == my_member {
        continue; // self is counted by the seed above; skip its own peer entry so it is never double-counted
      }
      cps.push(self.peer_checkpoint.get(&member).map_or(0, |c| c.get()));
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
    // Only a CURRENT member's report names a servable snapshot a donor we can still reach holds. A
    // report stored under a member that a reconfiguration REMOVED must not lift the floor: no current
    // donor would serve it, so a hole cleared by it could never be filled (a permanent sync wedge).
    // `peer_checkpoint` is keyed by stable `MemberId`, so the membership lookup excludes a removed
    // member's stale entry structurally (a `slot_of` miss); a retained member's report is kept.
    for (member, cp) in &self.peer_checkpoint {
      if self.membership.slot_of(*member).is_some() {
        hi = hi.max(*cp);
      }
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

  /// Whether the ONLY outstanding sync is a NORMAL-STATUS speculative cross-epoch crossing arm — a
  /// behind-but-OPERATIONAL voter that learned of a higher epoch and armed a `require_cross_epoch` sync
  /// ([`Self::maybe_request_cross_epoch_catchup`]) while STAYING `Normal`. Such a sync is SPECULATIVE: it
  /// may never get a crossing reply (no donor holds the `M >= N` checkpoint yet), and the laggard must
  /// keep processing legitimate SAME-epoch traffic in the meantime — so it is TRANSPARENT to the
  /// same-epoch tail-apply gates ([`Self::on_prepare`]'s sync-drop, [`Self::request_tail_gap`],
  /// [`Self::report_checkpoint_to_primary`]) that exist to halt FUTILE buffering during an ordinary
  /// below-head sync. It crosses (and discards the stale same-epoch tail) only when `apply_sync` installs
  /// the verified crossing checkpoint. A `require_cross_epoch` sync in RECOVERING is the recovery
  /// peer-fetch ([`Self::enter_cross_epoch_peer_fetch`]) — NOT speculative (that laggard genuinely cannot
  /// make same-epoch progress, and is non-Normal anyway), so this is `false` there. An ordinary / forced
  /// (non-cross-epoch) sync is `false` (it DOES halt tail-apply — the cluster checkpoint is above the head,
  /// so buffering same-epoch ops is futile).
  fn cross_epoch_speculative_sync(&self) -> bool {
    self.status.is_normal() && self.sync.is_some_and(|s| s.require_cross_epoch)
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

  /// This replica's slot in the active membership, or `None` if its stable [`MemberId`] is ABSENT — a
  /// reconfiguration REMOVED it from the configuration entirely. Unlike [`Self::local_slot`] (infallible,
  /// for the consensus paths that only run on a still-member node) this is the robust form the
  /// post-swap observers use: the removed-leader abdication ([`Self::install_membership`]) and the
  /// role predicates ([`Self::is_primary`]/[`Self::is_learner`]) must tolerate a just-removed local
  /// member without panicking (a removed node is neither primary nor learner). A removed live node does
  /// not durably participate — `recover` resolves an absent member to [`Recovered::Retired`] on restart.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn local_slot_opt(&self) -> Option<ReplicaId> {
    self.membership.slot_of(self.config.local())
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

  /// Resolve a routing slot in the active [`Membership`] to the stable [`MemberId`] that occupies it,
  /// if in range — the inverse of [`Self::slot_of`]. A transport that addresses a peer by the slot this
  /// replica stamped (the slot in THIS replica's membership) reads it to recover the peer's STABLE id,
  /// so the message routes to that member even after a reconfiguration shifted slots (the slot a sender
  /// names is in the SENDER's membership; the stable id is the cross-config-invariant address).
  /// Delegates to [`Membership::member_at`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn member_at(&self, slot: ReplicaId) -> Option<MemberId> {
    self.membership.member_at(slot)
  }

  /// The cluster id this replica was configured for. The QUIC coordinator reads it to single-source
  /// the cluster used by its identity-binding cross-check (rather than carrying a duplicate field).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn cluster(&self) -> u128 {
    self.config.cluster()
  }

  /// The `config_id` of the currently active membership: the hash-chained identifier that changes
  /// with every epoch swap. A driver can compare this cheaply (scalar equality, no clone) against a
  /// stored value to detect that a membership change was installed without walking the full membership.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.membership.config_id()
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

  /// A clone of the currently active membership. Called at most once per config change in
  /// `rekey_peers`; the hot path uses `config_id()` (a scalar equality) to detect whether a clone
  /// is needed at all.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership_clone(&self) -> Membership {
    self.membership.clone()
  }

  /// True iff `other` is a `config_id` in THIS replica's configuration lineage — the in-lineage
  /// admission test for the AGNOSTIC, view-independent serves/solicitations (the committed-content
  /// repair + state-sync messages, and the repair-serve arm of `Prepare`). Such a message carries no
  /// vote/lead authority — its content is verified independently downstream — so it is admitted from
  /// any config in the chain, letting a node catch up across an epoch boundary.
  ///
  /// The chain is the CURRENT `config_id` OR one of the bounded recent-prior ids retained in the
  /// [`Self::lineage`] ring ([`LINEAGE_RING`] of them, pushed on each [`Self::install_membership`]). So
  /// a legitimate replica lagging the cluster by a small number of live single-changes is still served
  /// the catch-up traffic that lets it cross the epoch boundary, while a long-stale (older than the
  /// ring) or FORKED `config_id` — one never in this node's chain — stays rejected. `config_id` is the
  /// lineage discriminator: a divergent configuration hashes to an id absent from both the current id
  /// and the ring, so it never matches.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn in_lineage(&self, other: u128) -> bool {
    other == self.membership.config_id() || self.lineage.contains(&other)
  }

  /// True iff THIS replica is a non-voting learner (its own slot is `>= replica_count`). A learner
  /// applies the committed log but never acknowledges a prepare, never casts a view-change vote, and
  /// is never primary — it follows the cluster via the primary's broadcasts and catches up by
  /// soliciting state, exactly like a TigerBeetle standby. `false` if the local member was REMOVED
  /// (absent from the configuration): a removed node is neither a voter nor a learner.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_learner(&self) -> bool {
    self
      .local_slot_opt()
      .is_some_and(|slot| self.membership.is_learner(slot))
  }

  /// True iff THIS replica is a VOTING member of the current configuration (occupies a voting slot
  /// `< replica_count`). The correct SINGLE-SOURCE predicate for voter participation: `false` for a
  /// learner AND for a REMOVED node (absent from the configuration). Every voter-only gate (the backup
  /// idle timer, the view-change-status cadence, vote paths) reads this — NOT `!is_learner()`, which is
  /// wrongly TRUE for an absent member and would let a removed node arm consensus timers and panic on a
  /// `local_slot()` that no longer exists.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_voter(&self) -> bool {
    self
      .local_slot_opt()
      .is_some_and(|slot| self.membership.is_voter(slot))
  }

  /// Whether this replica is the primary of the current view. `false` if the local member was REMOVED
  /// (absent from the configuration) — a removed node is not the primary, so the removed-leader
  /// abdication (`install_membership`) leaves it cleanly non-primary (it no longer heartbeats).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_primary(&self) -> bool {
    self
      .local_slot_opt()
      .is_some_and(|slot| self.membership.is_primary_slot(slot, self.view))
  }

  /// The live active [`Membership`] of this replica — a read-only snapshot the driver's
  /// reconfiguration executor re-reads each step to plan from the THEN-LIVE configuration.
  /// Adds no consensus surface.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn membership(&self) -> &Membership {
    &self.membership
  }

  /// The set of current voters whose slot bit is set in some UNCOMMITTED in-flight prepare's ack
  /// bitset — a best-effort responsiveness oracle the driver's shrink phase reads as POSITIVE
  /// liveness evidence.
  ///
  /// It reads ONLY the truly-fresh, current-round, current-layout acks: an op with
  /// `commit_min < op <= self.op` (the live in-flight tail) AND `!inflight[op].committed`. Committed
  /// entries are skipped — a retained committed entry's ack bits are in the predecessor slot layout
  /// after a membership swap (only UNCOMMITTED entries are rekeyed), so reading them would be stale
  /// and mislaid. Filtering on `!committed` sidesteps both. Each set bit's slot is resolved to its
  /// stable [`MemberId`] via [`Membership::member_at`] and kept only if that slot is a current voter.
  ///
  /// When the cluster holds NO uncommitted prepare (idle, or every in-flight op already committed)
  /// the set is EMPTY — no oracle evidence, which the fail-closed shrink rule turns into a safe
  /// stall, NOT a guess. This is a pure read of existing state: no new wire message, no durable
  /// field, no safety surface. Like peer progress it is a LIVENESS hint only, never a safety input.
  ///
  /// `window` bounds the freshness band to the last `window` ops intersected with the uncommitted
  /// tail; a `window` at least the pipeline depth (or `u64::MAX`) considers the whole uncommitted
  /// tail `(commit_min .. self.op]`.
  pub fn recently_acked_voters(&self, window: u64) -> BTreeSet<MemberId> {
    let head = self.op.get();
    let floor = head.saturating_sub(window).max(self.commit_min.get());
    // When floor >= head there is no uncommitted tail to inspect.
    if floor >= head {
      return BTreeSet::new();
    }
    let mut out = BTreeSet::new();
    for (_, inf) in self.inflight.range((floor + 1)..=head) {
      if inf.committed {
        continue;
      }
      let mut bits = inf.oks;
      while bits != 0 {
        let slot = bits.trailing_zeros() as u16;
        bits &= bits - 1;
        let id = ReplicaId::new(slot);
        if self.membership.is_voter(id)
          && let Some(m) = self.membership.member_at(id)
        {
          out.insert(m);
        }
      }
    }
    out
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

  /// True iff a VIEW-CHANGING durable-view write is in flight — i.e. `self.view` may not yet be durable
  /// on this replica's own superblock and a crash would roll it back. This is the precise predicate the
  /// durable-view-before-participate fence guards on: a replica must not advertise authority/participation
  /// in a view it has not yet durably entered.
  ///
  /// It is NOT every `pending_sb` write. `pending_sb` also carries EPOCH/frontier writes through which
  /// `self.view` stays durable:
  /// - [`PendingSbAction::SwapEpoch`] is a commit-first EPOCH swap — it changes the membership/epoch, never
  ///   the view (`self.view` is carried unchanged into the SwapEpoch root). The durable-view hazard does
  ///   not apply, so a SwapEpoch must NOT suppress the primary's participation: the primary must keep
  ///   committing + heartbeating AT the predecessor epoch through the stage→durable-root window, so backups
  ///   learn the `Reconfigure` op committed, stage their OWN swap, and converge. Durable-EPOCH-before-
  ///   participate is preserved separately and structurally — [`Self::install_membership`] (the swap to the
  ///   successor) runs ONLY at `on_sb_done` once the durable root lands, so no node ever participates at the
  ///   new epoch without its durable proof.
  /// - [`PendingSbAction::Seal`] persists `commit_max` + committed-band headers; the view is durable through
  ///   it too, and the Tier C protocol has already quiesced the primary, so excluding it is inert.
  ///
  /// Only the three VIEW-CHANGING actions ([`PendingSbAction::SendDoViewChange`] /
  /// [`PendingSbAction::StartViewAsPrimary`] / [`PendingSbAction::AdoptedStartView`]) leave `self.view`
  /// not-yet-durable, so only they raise this fence.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn pending_durable_view(&self) -> bool {
    matches!(
      self.pending_sb,
      Some((
        _,
        PendingSbAction::SendDoViewChange
          | PendingSbAction::StartViewAsPrimary
          | PendingSbAction::AdoptedStartView
      ))
    )
  }

  /// True iff a state-sync RE-PERSIST root write is already STAGED (its `AwaitRoot` step) — the
  /// un-cancellable superblock write that advances the durable checkpoint to the synced point `M` and is
  /// then INSTALLED ([`Self::install_sync`]) on its completion. A view-change transition must NOT begin
  /// while this is true: the transition would either rewind the durable checkpoint (a trailing view root
  /// persisting the stale pre-sync pointer) or, copy-forwarded, leave the durable at `M` while the SM is
  /// never restored to `M` — because the install is destructive (it resets `op`/`commit_min`, restores the
  /// SM, prunes the WAL) and cannot run interleaved with the transition's adopted log. So each view-change
  /// trigger DEFERS while this holds; the deferred trigger is re-driven (its sender retransmits / the SVC
  /// quorum re-evaluates) the instant the root lands and the sync installs cleanly. (`AwaitSnapshot` has
  /// no staged root, so its checkpoint is dropped on transition — durable stays at the old pointer, and the
  /// abandoned snapshot write is harmless: with no root it can never become the read-back checkpoint by the
  /// [`Superblock::submit_read_checkpoint`] contract, which serves only the durable-root-named one.) This
  /// mirrors the in-flight-checkpoint defer the cross-epoch peer-fetch already observes and keeps state-sync
  /// and view-change mutually exclusive by status.
  fn sync_repersist_root_staged(&self) -> bool {
    matches!(
      self.pending_checkpoint,
      Some(PendingCheckpoint {
        kind: CheckpointKind::SyncRepersist,
        step: CheckpointStep::AwaitRoot(_),
        ..
      })
    )
  }

  /// True iff this replica may participate AS the primary right now: `Normal`, the primary of its view,
  /// AND its current view is already DURABLE (no pending view-CHANGING superblock write).
  ///
  /// The fence is durable-view-before-participate ([`Self::pending_durable_view`]):
  /// [`Self::start_view_as_new_primary`] sets `Normal` but DEFERS the StartView broadcast (and the rest of
  /// participation) to [`Self::start_view_participate`] on `on_sb_done`, so until that durable-VIEW write
  /// lands the new view is not yet recoverable — a crash would regress out of it. Acting AS the primary in
  /// that window (answering a delayed/duplicate `GetView` with a `StartView`, a peer's `Recovery` with our
  /// canonical head, or heartbeating/retransmitting on the commit/prepare timers) would assert this
  /// replica's authority in a view it might never have durably entered → cross-view double-participation.
  /// A commit-first SwapEpoch root in flight does NOT raise this fence (the view is durable through it — see
  /// [`Self::pending_durable_view`]), so the primary keeps participating at the predecessor epoch and backups
  /// converge on the committed `Reconfigure` op.
  ///
  /// Every such outbound PRIMARY path gates on this; the deferred `start_view_participate` already runs
  /// AFTER the view is durable, so it does not.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn participates_as_primary(&self) -> bool {
    self.status.is_normal() && self.is_primary() && !self.pending_durable_view()
  }

  /// Read access to the state machine for production callers. Returns `None` while the SM content
  /// lags behind the durable checkpoint pointer — specifically while any of:
  ///
  /// - `pending_install` is `Some`: a pre-root staged install is in flight; `install_sync` is about
  ///   to wholesale-replace the SM at the synced point, so the current SM is mid-transition.
  /// - `sm_reconstruct_owed()`: the synced checkpoint root is durable and `checkpoint_op` already
  ///   names M, but the verify-on-read `sm.restore` faulted — the SM still holds the OLD pre-M
  ///   content until the retry succeeds.
  /// - `status.is_recovering()` or `status.is_recovering_head()`: the cold-start SM reconstruction
  ///   from the durable checkpoint has not yet completed.
  ///
  /// While `None`, a caller that pairs `checkpoint_op()` (which may already name M) with this
  /// accessor to answer a read would expose un-reconstructed state. Once `Some`, the SM is
  /// consistent with `checkpoint_op` and all applied ops up to `commit_min`.
  ///
  /// Test code that needs unconditional access in fault-injection scenarios uses
  /// `state_machine_ref` instead.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn state_machine(&self) -> Option<&S> {
    if self.pending_install.is_some()
      || self.sm_reconstruct_owed()
      || self.status.is_recovering()
      || self.status.is_recovering_head()
    {
      return None;
    }
    // The readiness gate's contract, witnessed at the exposure point: an SM this accessor hands out
    // is at the applied frontier (`sm_at` is the content-side witness `assert_invariants` (5c)
    // cross-checks; asserting here too catches a stale exposure at the exact read that would leak it).
    debug_assert_eq!(
      self.sm_at,
      self.commit_min,
      "state_machine() exposing SM content at {} behind the applied frontier {}",
      self.sm_at.get(),
      self.commit_min.get(),
    );
    Some(&self.sm)
  }

  /// Raw, ungated SM access for white-box workspace simulation only — bypasses the SM-readiness
  /// gate; gated behind a non-published workspace cfg (`vsrr_internal_testkit`) so it cannot be
  /// compiled by any downstream or published build. Production reads MUST use
  /// [`Self::state_machine`] to avoid exposing un-reconstructed SM content.
  #[cfg(any(test, vsrr_internal_testkit))]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn state_machine_ref(&self) -> &S {
    &self.sm
  }

  /// The content address of this replica's current durable SM checkpoint DAG root, or `None` if no
  /// checkpoint has been written yet. This is the root the checkpoint envelope binds and the live root
  /// `gc_blocks` marks from; observers use it to walk the held checkpoint DAG (e.g. the simulation's
  /// incremental-sync oracle measures the reachable block set from it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn checkpoint_sm_root(&self) -> Option<BlockAddress> {
    self.checkpoint_sm_root
  }

  /// The content address of this replica's current durable client-session-table DAG root, or `None` if
  /// no checkpoint has been written yet. The session-table analogue of [`Self::checkpoint_sm_root`] — the
  /// second root the checkpoint envelope binds and `gc_blocks` marks from; observers walk the held
  /// session DAG from it (the simulation's incremental-sync oracle counts its reachable blocks alongside
  /// the SM DAG's).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn checkpoint_sessions_root(&self) -> Option<BlockAddress> {
    self.checkpoint_sessions_root
  }

  /// The number of DISTINCT blocks reachable from this replica's current durable checkpoint across BOTH
  /// content-addressed DAGs — the SM checkpoint DAG (`checkpoint_sm_root`, walked via the embedder's
  /// [`StateMachine::block_references`]) AND the client-session-table DAG (`checkpoint_sessions_root`,
  /// walked via the proto's session-block resolver). This is the FULL set a from-empty laggard would have
  /// to fetch to install the checkpoint, so the simulation's incrementality oracle measures `missing`
  /// (blocks actually fetched, across both DAGs) against THIS `total`. Returns `0` if no checkpoint is
  /// held yet, or if any reachable block is currently absent from `blocks` (the DAGs are not fully
  /// present, so the count is not yet meaningful). A pure read-only walk; `blocks` is the store the
  /// observer holds for this replica.
  pub fn reachable_checkpoint_block_count(&self, blocks: &dyn BlockStore) -> usize
  where
    S: StateMachine,
  {
    let (Some(sm_root), Some(sessions_root)) =
      (self.checkpoint_sm_root, self.checkpoint_sessions_root)
    else {
      return 0;
    };
    let mut seen = BTreeSet::new();
    // Walk a DAG from `root`, resolving children with `refs`; `Err(())` if a reachable block is absent.
    let walk = |root: BlockAddress,
                seen: &mut BTreeSet<BlockAddress>,
                refs: &dyn Fn(&[u8]) -> std::vec::Vec<BlockAddress>|
     -> Result<(), ()> {
      let mut stack = std::vec![root];
      while let Some(addr) = stack.pop() {
        if !seen.insert(addr) {
          continue;
        }
        let Some(block) = blocks.read_block(addr) else {
          return Err(());
        };
        for child in refs(&block) {
          stack.push(child);
        }
      }
      Ok(())
    };
    if walk(sm_root, &mut seen, &|b| S::block_references(b)).is_err()
      || walk(
        sessions_root,
        &mut seen,
        &session_blocks::session_block_references,
      )
      .is_err()
    {
      return 0;
    }
    seen.len()
  }

  /// Whether this replica has ANY storage op (WAL append or superblock write/read) still in flight —
  /// a submitted [`Wal`]/[`Superblock`] op whose completion the driver still owes.
  ///
  /// `true` iff at least one of the durability-relevant pending sets is non-empty: the outstanding WAL
  /// appends (`pending`, plus its `appending` append-before-ack gate — a subset of `pending`, ORed for
  /// explicitness), the in-flight durable-view superblock write (`pending_sb`), the in-flight
  /// checkpoint write sequence (`pending_checkpoint`, and its deferred-install staging
  /// `pending_install` — which structurally implies `pending_checkpoint`), and the in-flight
  /// checkpoint READS this replica issued to serve peers' `RequestSync`s (`sync_serving` — a
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
      // Physical writes the backend still owes a completion for — including appends the logical
      // layer ABANDONED (their `pending` entry cleared by a view transition / truncation): the
      // OpId-lifetime drain contract requires the driver to hold teardown until these quiesce, or a
      // recreated endpoint could observe their late effects under recycled correlation ids.
      || !self.wal_writes.is_empty()
      // Appends parked behind the slot-quiescence fence: not yet with the backend, but durability
      // work this endpoint still owes (each releases and submits when its blocking write quiesces).
      || !self.deferred_appends.is_empty()
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

  /// Test-only: the recorded checkpoint for the member CURRENTLY at `replica` (0 if unheard or the slot
  /// holds no member). Resolves the slot to its stable id — the map's key — so it reads the same entry
  /// `inject_peer_checkpoint_for_test`/a real `PrepareOk` at that slot recorded. Proves T1 monotonicity.
  #[cfg(test)]
  fn peer_checkpoint_for_test(&self, replica: u8) -> u64 {
    self
      .membership
      .member_at(ReplicaId::new(u16::from(replica)))
      .and_then(|m| self.peer_checkpoint.get(&m))
      .map_or(0, |c| c.get())
  }

  /// Test-only: the recorded checkpoint for a member by its stable id directly (0 if unheard), so a
  /// reconfiguration test can read a report that followed its member across a slot shift.
  #[cfg(test)]
  fn peer_checkpoint_by_member_for_test(&self, member: MemberId) -> u64 {
    self.peer_checkpoint.get(&member).map_or(0, |c| c.get())
  }

  /// Test-only: directly seed a peer's reported checkpoint (bypassing a real PrepareOk/Commit), so a
  /// test can construct a quorum-checkpoint floor without driving full message flows. Goes through the
  /// MONOTONE recorder (which resolves the slot to the member's stable id), so a lower injection cannot
  /// regress a higher recorded value.
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

  /// Test-only: is a committed reconfiguration's successor membership staged awaiting its durable
  /// `SwapEpoch` root (`pending_swap` armed)? True exactly in the commit→durable-root window of the
  /// commit-first epoch swap — after `stage_epoch_swap` latches the successor but before `on_sb_done`
  /// installs it. Lets a test assert the durable-epoch-before-participate fence directly.
  #[cfg(test)]
  fn pending_swap_for_test(&self) -> bool {
    self.pending_swap.is_some()
  }

  /// Test-only: the structural in-flight-reconfiguration predicate ([`Self::has_pending_reconfigure`]),
  /// so a regression can pin that an uncommitted `Reconfigure` op carried canonical into a new view is
  /// still recognized as in-flight even after a view-change reset cleared `reconfigure_inflight`.
  #[cfg(test)]
  fn has_pending_reconfigure_for_test(&self) -> bool {
    self.has_pending_reconfigure()
  }

  /// Test-only: does a VIEW-CHANGING durable-view write currently raise the durable-view-before-
  /// participate fence ([`Self::pending_durable_view`])? Lets a test assert that a commit-first SwapEpoch
  /// window does NOT (the view stays durable through an epoch swap), so the primary keeps participating.
  #[cfg(test)]
  fn pending_durable_view_for_test(&self) -> bool {
    self.pending_durable_view()
  }

  /// Test-only: a shared reference to the state machine, so a test can assert exactly which ops
  /// reached `S::apply` (e.g. that a consensus-layer `Body::Reconfigure` op was NEVER applied).
  #[cfg(test)]
  fn sm_for_test(&self) -> &S {
    &self.sm
  }

  /// Test-only: stage a `pending_checkpoint` (bypassing the trigger), so the `on_request` defense guard
  /// (drop a client while a checkpoint-persist is in flight — the op-reset risk) can be exercised.
  #[cfg(test)]
  fn stage_pending_checkpoint_for_test(&mut self) {
    let id = self.mint_op_id();
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: self.commit_min,
      checkpoint_id: 0,
      sm_root: crate::block_address(&[]),
      sessions_root: crate::block_address(&[]),
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
    // The forced state models a SETTLED Normal replica: its view is durably witnessed (the emit
    // fence asserts the equality on every authoritative emission the scenario then drives).
    self.durable_view = View::with(view);
    self.log_view = View::with(view);
    self.op = OpNumber::with(op);
    self.commit_min = OpNumber::with(commit_min);
    // Arbitrary-construction helper: keep the SM-content witness in lockstep with the forced applied
    // frontier (the (5c) coupling a real apply path maintains) — the forced state models an endpoint
    // whose SM has applied through `commit_min`.
    self.sm_at = OpNumber::with(commit_min);
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

  /// Test-only: how many DISTINCT voters have nacked `op` (the size of its `nack_from` tally), `0` if
  /// none. Lets a regression assert the `f+1` counting gate directly and that a fill drops the tally.
  #[cfg(test)]
  fn nack_voters_for_test(&self, op: u64) -> usize {
    self.nack_from.get(&op).map_or(0, BTreeSet::len)
  }

  /// Test-only: seed an in-memory `log` entry at `op` (a placeholder body), so the held-tail
  /// preservation of `apply_sync` can be observed (`force_state_for_test` deliberately leaves the
  /// cache empty). Does not touch the WAL.
  #[cfg(test)]
  fn seed_log_entry_for_test(&mut self, op: u64) {
    // A realistic held-tail entry: a `Present` op with a NON-EMPTY body (a Normal replica never holds a
    // `Present(EMPTY)` placeholder — that is a recovery-only Phase-1 seed — so seeding one would trip the
    // held-tail "no empty Present survives a trim" invariant).
    self.log.insert(
      op,
      LogEntry::present(
        ClientId::new(1),
        RequestNumber::with(op),
        Bytes::copy_from_slice(&[op as u8]),
      ),
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

  /// Test-only: does the outstanding sync REQUIRE a cross-epoch crossing (the unified forced-sync
  /// crossing fetch)? `false` when no sync is outstanding.
  #[cfg(test)]
  fn sync_requires_cross_epoch_for_test(&self) -> bool {
    self.sync.is_some_and(|s| s.require_cross_epoch)
  }

  /// Test-only: the outstanding sync's nonce (panics if none) — to build a matching SyncCheckpoint.
  #[cfg(test)]
  fn sync_nonce_for_test(&self) -> u64 {
    self.sync.expect("a sync is outstanding").nonce
  }

  /// Test-only: the PERSISTENT cross-epoch crossing intent target, or `None` when no crossing is owed.
  #[cfg(test)]
  fn cross_epoch_intent_for_test(&self) -> Option<u64> {
    self.cross_epoch_intent.map(|op| op.get())
  }

  /// Test-only: pin the PERSISTENT cross-epoch crossing intent directly (the value the higher-epoch
  /// trigger sets), so the clear-on-cross / re-arm lifecycle can be exercised without a full driver.
  #[cfg(test)]
  fn set_cross_epoch_intent_for_test(&mut self, target: u64) {
    self.cross_epoch_intent = Some(OpNumber::with(target));
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
      require_cross_epoch: false,
    });
  }

  /// Test-only: arm a FORCED, CROSS-EPOCH-CROSSING sync to `target` directly (the speculative
  /// Normal-status arm `maybe_request_cross_epoch_catchup` builds), so the single-superblock-writer
  /// defer (a sync-answer deferred while a SwapEpoch root is in flight) and the verification-is-authority
  /// crossing admission can be exercised without a full multi-epoch driver.
  #[cfg(test)]
  fn arm_cross_epoch_sync_for_test(&mut self, target: u64) {
    self.nonce = self.nonce.wrapping_add(1);
    self.sync = Some(SyncState {
      target: OpNumber::with(target),
      nonce: self.nonce,
      forced: true,
      require_cross_epoch: true,
    });
  }

  /// Test-only: run the block-store GC mark-and-sweep ([`Self::gc_blocks`]) directly, so a test can prove
  /// the live-root set (the durable checkpoint, an in-flight `block_fetch`, AND a RETAINED `pending_install`)
  /// shields the right blocks without needing an ordinary checkpoint to complete on the cadence.
  #[cfg(test)]
  fn gc_blocks_for_test(&mut self, blocks: &mut dyn BlockStore)
  where
    S: StateMachine,
    R: Reconfig,
  {
    self.gc_blocks(blocks);
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

  /// Test/observability: the donor a block-fetch transfer is currently pinned to, or `None` when no
  /// block pull is in progress. Lets the donor-crash sim variant target the live donor
  /// deterministically. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn block_fetch_donor(&self) -> Option<u16> {
    self.block_fetch.as_ref().map(|bf| bf.donor.get())
  }

  /// Test-only debug snapshot of the install/sync obligation state:
  /// `(pending_install checkpoint_op, pending_checkpoint target_op, pending_sb, sync target,
  /// sm_reconstruct_owed)`. Not part of the stable API.
  #[doc(hidden)]
  pub fn debug_install_state(&self) -> (Option<u64>, Option<u64>, bool, Option<u64>, bool) {
    (
      self.pending_install.as_ref().map(|p| p.checkpoint_op.get()),
      self.pending_checkpoint.as_ref().map(|p| p.target_op.get()),
      self.pending_sb.is_some(),
      self.sync.as_ref().map(|s| s.target.get()),
      self.sm_reconstruct_owed(),
    )
  }

  /// Test-only: does the live block-fetch's pinned checkpoint actually PRESENT a cross-epoch crossing
  /// (foreign config + non-empty membership)? `None` when no fetch is in flight. The crossing-answer
  /// predicates shield a stale `cross_epoch_intent` only on a `true` here, NOT on the bare fetch presence.
  #[cfg(test)]
  fn block_fetch_crossing_answered_for_test(&self) -> Option<bool> {
    self.block_fetch.as_ref().map(|bf| bf.crossing_answered)
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

  /// Test/observability counter: how many block-DAG sync reads/transfers aborted for exceeding
  /// `MAX_REACHABLE_BLOCKS` (a malformed / foreign / oversized sync-source DAG — one increment per aborted
  /// read/transfer, see the field). A non-zero, growing value is the otherwise-silent re-walk loop becoming
  /// observable. Not part of the stable API.
  #[doc(hidden)]
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn dag_walks_capped(&self) -> u64 {
    self.dag_walks_capped
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
      catchup_windows: 1,
    });
    self.pending.insert(7, Pending::Ack(OpNumber::with(1)));
    self.appending.insert(1);
    // Through the production recorder so the cached quorum statistic stays coherent.
    self.record_peer_checkpoint(ReplicaId::new(2), OpNumber::with(3));
    let sentinel_root = crate::block_address(&[]);
    self.pending_checkpoint = Some(PendingCheckpoint {
      target_op: self.commit_min,
      checkpoint_id: 0,
      sm_root: sentinel_root,
      sessions_root: sentinel_root,
      step: CheckpointStep::AwaitSnapshot(crate::OpId::new(999)),
      kind: CheckpointKind::SyncRepersist,
    });
    self.sync = Some(SyncState {
      target: self.checkpoint_op,
      nonce: 0,
      forced: false,
      require_cross_epoch: false,
    });
    self.pending_install = Some(PendingInstall {
      checkpoint_op: self.checkpoint_op,
      sessions_root: sentinel_root,
      sm_root: sentinel_root,
      held_tail: false,
      successor: None,
      successor_prev_config_id: None,
      checkpoint: crate::SyncCheckpoint::new(
        self.view,
        self.checkpoint_op,
        0,
        crate::Epoch::new(0),
        0,
        ReplicaId::new(0),
        0,
        Bytes::new(),
        Bytes::new(),
      ),
      donor: ReplicaId::new(0),
    });
    self.block_fetch = Some(BlockFetch {
      checkpoint: crate::SyncCheckpoint::new(
        self.view,
        self.checkpoint_op,
        0,
        crate::Epoch::new(0),
        0,
        ReplicaId::new(0),
        0,
        Bytes::new(),
        Bytes::new(),
      ),
      sm_root: sentinel_root,
      sessions_root: sentinel_root,
      donor: ReplicaId::new(0),
      block_sync: block_sync::BlockSync::new(sentinel_root),
      session_sync: block_sync::BlockSync::new(sentinel_root),
      // Sentinel seam (an empty-membership, same-`config_id` checkpoint): not a crossing.
      crossing_answered: false,
      resolicited_front: None,
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
      && self.block_fetch.is_none()
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

  /// Test-only: is EITHER Normal-primary cadence timer (the commit heartbeat or the prepare
  /// retransmit) armed? The removed-leader abdication ([`Self::install_membership`]) retires both, so a
  /// regression can assert the cadence is silent after a swap that drops this node from the voter set.
  #[cfg(test)]
  fn commit_or_prepare_timer_armed_for_test(&self) -> bool {
    self.timers.commit.is_some() || self.timers.prepare.is_some()
  }

  /// Test-only: is the backup `primary_idle` deadline armed? `arm_primary_idle` is `is_voter()`-gated and
  /// the removed-node abdication ([`Self::install_membership`]) calls `retire_backup_cadence`, so a
  /// regression can assert a removed (non-voter) backup holds NO idle deadline — it never proposes a
  /// view change on an idle primary.
  #[cfg(test)]
  fn primary_idle_armed_for_test(&self) -> bool {
    self.timers.primary_idle.is_some()
  }

  /// Test-only: the in-lineage admission test ([`Self::in_lineage`]) — admits `other` iff it is the
  /// current `config_id` or a retained recent-prior one, so a regression can pin the bounded lineage
  /// ring (a small laggard catches up; a forked/long-stale config_id is rejected).
  #[cfg(test)]
  fn in_lineage_for_test(&self, other: u128) -> bool {
    self.in_lineage(other)
  }

  /// Test-only: the recent-prior lineage ring (`self.lineage`), most-recent-first, so a regression can
  /// pin the EXACT post-crossing chain (e.g. a direct E0→E2 install yields `[E1, E0]`).
  #[cfg(test)]
  fn lineage_ring_for_test(&self) -> [u128; LINEAGE_RING] {
    self.lineage
  }

  /// Test-only: the adopted StartViewChange target view (`svc_target`), so a regression can observe
  /// that an admitted SVC raised the target (vs. a stale one dropped at the ingress gate).
  #[cfg(test)]
  fn svc_target_for_test(&self) -> View {
    self.svc_target
  }

  /// Mint a fresh storage correlation id. Counts up from 1, RESERVING `u64::MAX`
  /// ([`recovery::FORMAT_OP_ID`](crate::endpoint::recovery::FORMAT_OP_ID)) so it is never minted —
  /// which is what keeps a leaked `format` completion from ever aliasing a real op's `pending_sb`. A
  /// mint that would reach the reserved id fail-stops rather than wrapping (which would also break
  /// the within-incarnation uniqueness of correlation ids); it is a ~1.8e19-submission backstop
  /// (roughly 585 years at 10^9 submissions/second), never reached in practice.
  fn mint_op_id(&mut self) -> crate::OpId {
    let id = self.next_op_id;
    assert!(
      id < u64::MAX,
      "OpId space exhausted: next_op_id reached the reserved FORMAT_OP_ID"
    );
    self.next_op_id += 1;
    crate::OpId::new(id)
  }

  /// This WAL's [`effective_wal_capacity`] under this endpoint's checkpoint interval — see the free
  /// function for the geometry contract.
  fn effective_wal_capacity<W: Wal>(&self, wal: &W) -> u64 {
    effective_wal_capacity(wal.capacity(), self.config.checkpoint_ops())
  }

  /// Whether durably appending `op` would physically WRAP an un-pruned ring slot: `op` reuses slot
  /// `op mod effective`, last held by `op − effective`, which is still un-pruned iff
  /// `op − checkpoint_op > effective` ([`effective_wal_capacity`]). The head-extend paths enforce this
  /// via [`Self::maybe_sync_below_ring_window`] (drop the Prepare + jump via a forced sync); the
  /// ADOPTION (re-)append and the peer-repair fill enforce it with this predicate directly — skip the
  /// append, owing no vote/ack/fill off an append that never ran — since a deep laggard can be handed a
  /// canonical view-change log or a repair body whose band exceeds its own ring, and appending it would
  /// evict a committed, un-pruned op (the committed-op-loss class the ring-residency oracle checks).
  fn ring_append_would_wrap<W: Wal>(&self, wal: &W, op: u64) -> bool {
    op.saturating_sub(self.checkpoint_op.get()) > self.effective_wal_capacity(wal)
  }

  /// Whether `a` and `b` occupy the SAME physical WAL slot under `capacity`: the same op, or — on a
  /// bounded backend, whose placement is `op mod capacity` (the trait-level placement contract) —
  /// ring aliases. A ring-less backend (`capacity == u64::MAX`) stores every op at its own location,
  /// so only the same-op case aliases; its recycling discipline is the trait's extent-reuse clause.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn slots_alias(capacity: u64, a: u64, b: u64) -> bool {
    a == b || (capacity != u64::MAX && a % capacity == b % capacity)
  }

  /// Whether some in-flight physical write ([`Self::wal_writes`]) targets `op`'s ring slot. The
  /// fence predicate: while true, a new append to `op` must be DEFERRED — append completions may
  /// reorder, so submitting now could let the OLD bytes land LAST and leave the durable slot holding
  /// a value this replica's ack/vote never named (the truncate-reuse and ring-wrap flavors of the
  /// same hazard). The map is pipeline-bounded, so the scan is cheap.
  fn slot_write_in_flight<W: Wal>(&self, wal: &W, op: u64) -> bool {
    let capacity = wal.capacity();
    self
      .wal_writes
      .values()
      .any(|&v| Self::slots_alias(capacity, v, op))
  }

  /// The single WAL-append submission choke: every durable append routes here (the normal-path mint
  /// and backup appends, the interior canonical re-append, the view-change adoption re-appends, the
  /// peer-repair fill, and the fault re-submit), so the slot-quiescence fence cannot be bypassed by
  /// a new call site. If `op`'s ring slot has an un-quiesced older write, the FULL submission (the
  /// deferred action `kind` + the exact bytes) parks in [`Self::deferred_appends`] until that
  /// write's completion proves the slot quiesced ([`Self::release_deferred_append`]); otherwise it
  /// submits now, entering the write in [`Self::wal_writes`] and its action in `pending`. Callers
  /// keep their own `appending` bookkeeping (identical for the submitted and deferred shapes, so
  /// the append-before-ack gate and duplicate-append guards treat a deferred append as in flight).
  fn submit_or_defer_append<W: Wal>(
    &mut self,
    wal: &mut W,
    op: OpNumber,
    header: Header,
    body: Bytes,
    kind: Pending,
  ) {
    debug_assert_eq!(
      kind.op(),
      op,
      "a deferred action must name the op it appends"
    );
    if self.slot_write_in_flight(wal, op.get()) {
      // At most one in-flight write per slot exists (this fence's own guarantee), and a second
      // deferral for the same op supersedes the first — the newer submission carries the newer
      // canonical bytes/action for that op (its predecessor was abandoned by the transition that
      // re-drove it, or is the same fill retried).
      self
        .deferred_appends
        .insert(op.get(), DeferredAppend { kind, header, body });
      return;
    }
    let id = self.mint_op_id();
    wal.submit_append(id, op, header, body);
    self.wal_writes.insert(id.get(), op.get());
    self.pending.insert(id.get(), kind);
  }

  /// Submit a deferred append whose blocking write (to `quiesced`'s ring slot) has just quiesced.
  /// Usually the surviving deferred entry (transitions/GC clear abandoned ones) is the slot's only
  /// waiter — but two waiters per slot CLASS are constructible on a bounded ring (`K` and
  /// `K + capacity`, the lower one checkpoint-subsumed; see the `deferred_appends` field doc). The
  /// ASCENDING key scan below is load-bearing for that corner: it picks the LOWEST aliased waiter,
  /// whose fresh write then blocks the higher one via the re-check, so the LIVE (highest) op is the
  /// one that lands LAST in the slot. The re-check also guards the otherwise-impossible second
  /// in-flight blocker.
  fn release_deferred_append<W: Wal>(&mut self, wal: &mut W, quiesced: u64) {
    let capacity = wal.capacity();
    let Some(op) = self
      .deferred_appends
      .keys()
      .copied()
      .find(|&op| Self::slots_alias(capacity, op, quiesced))
    else {
      return;
    };
    if self.slot_write_in_flight(wal, op) {
      return;
    }
    let d = self
      .deferred_appends
      .remove(&op)
      .expect("the found key is present");
    let id = self.mint_op_id();
    wal.submit_append(id, OpNumber::with(op), d.header, d.body);
    self.wal_writes.insert(id.get(), op);
    self.pending.insert(id.get(), d.kind);
  }

  /// Retire the appends a [`Wal::truncate`]/[`Wal::prune`] reports SYNCHRONOUSLY cancelled: the
  /// backend proves these writes will now neither land nor complete, so their quiescence is
  /// immediate — clear their write entries (and any still-pending action: a synchronously-cancelled
  /// append belongs to an op the endpoint just RELEASED, so its action owes nothing) and release any
  /// deferred append their slots were blocking. Keeping this in the same call that truncated/pruned
  /// means the common backend (one that can discard its own queue synchronously) never even opens a
  /// deferral window — behavior is byte-identical to the pre-fence code there.
  fn absorb_wal_cancellations<W: Wal>(
    &mut self,
    wal: &mut W,
    cancelled: std::vec::Vec<crate::OpId>,
  ) {
    for id in cancelled {
      let Some(op) = self.wal_writes.remove(&id.get()) else {
        debug_assert!(false, "a backend cancelled an unknown append id {id:?}");
        continue;
      };
      if let Some(p) = self.pending.remove(&id.get()) {
        // The action dies with the write — but the `appending` mark may now be OWNED by a deferred
        // replacement for the same op (deferral keeps the mark), so only clear it when no waiter
        // holds the slot.
        if !self.deferred_appends.contains_key(&p.op().get()) {
          self.appending.remove(&p.op().get());
        }
      }
      self.release_deferred_append(wal, op);
    }
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
  ///     `Recovery`, and the serve `RecoveryResponse`.
  ///     A non-voting member legitimately solicits committed state and
  ///     can serve committed content to others, so these bind to the self `replica()` over the full node
  ///     range — NOT `config.primary(view)`, which would drop an honest backup-originated serve, and not
  ///     the voting set, which would drop a learner soliciting/serving committed state. They carry
  ///     committed CONTENT verified independently (checksum + committed-vouch; checkpoint-id), not quorum
  ///     authority, so a member serving them is safe. The STATE-SYNC PULL (`RequestSync`) is the same
  ///     no-authority class but additionally tolerates a SLOT-SHIFTED cross-epoch laggard
  ///     ([`Self::sender_admits_solicitation`]), and the STATE-SYNC SERVE REPLY (`SyncCheckpoint`)
  ///     tolerates a SLOT-SHIFTED DONOR mid-crossing ([`Self::sender_admits_sync_reply`]). The
  ///     content-addressed block fetch (`RequestBlock`/`BlockResponse`) is a configured-member
  ///     data-plane pair with no quorum authority (the block is self-verifying by its content hash).
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
      // serve (`RecoveryResponse`) carries a self `replica()` AND a `view()` but may
      // come from ANY Normal member (a backup or a learner, not only the primary) — bind to the self id,
      // not `config.primary(view)`. (The three state-sync serve REPLIES are below, with the cross-epoch
      // slot-shifted-donor relaxation.)
      Message::GetView(m) => self.sender_is_member(from, m.replica()),
      // `RequestPrepare`/`RequestPrepareRange` are no-authority cross-epoch-tolerant solicitations too (a
      // committed-log-body pull a cross-epoch laggard sends to a current-epoch donor) — same relaxation as
      // the sync pulls, so a slot-shifted retained laggard's repair solicitations are not dropped.
      Message::RequestPrepare(m) => {
        self.sender_admits_solicitation(from, m.replica(), m.config_id())
      }
      Message::RequestPrepareRange(m) => {
        self.sender_admits_solicitation(from, m.replica(), m.config_id())
      }
      // A `Nack` is the REPLY to a `RequestPrepare`, but unlike the solicitation it is COUNTED toward a
      // truncation quorum, so it binds STRICTLY to its self id (`sender_is_member`) — the same-config, no
      // cross-epoch relaxation — so a forged/misrouted nack cannot inflate the tally. `on_nack` further
      // keys the tally by the authenticated `from`'s stable `MemberId` and counts only voters.
      Message::Nack(m) => self.sender_is_member(from, m.replica()),
      Message::Recovery(m) => self.sender_is_member(from, m.replica()),
      // `RequestSync` is the NO-AUTHORITY cross-epoch-tolerant SOLICITATION (a checkpoint OFFER pull):
      // the strict self-id binding (`sender_is_member`) is RELAXED for a cross-epoch laggard whose
      // claimed slot has SHIFTED. See [`Self::sender_admits_solicitation`] for the binding + the
      // no-forgeable-authority proof.
      Message::RequestSync(m) => self.sender_admits_solicitation(from, m.replica(), m.config_id()),
      Message::RecoveryResponse(m) => self.sender_is_member(from, m.replica()),
      // The state-sync SERVE REPLY (`SyncCheckpoint`) carries a self `replica()` = the DONOR's CURRENT
      // slot AND a `config_id`. The strict self-id binding holds for a SAME-config reply (`config_id` ==
      // ours), but a DONOR whose slot SHIFTED across the reconfiguration stamps its CURRENT (E+1) slot +
      // DESCENDANT `config_id` while the mid-crossing OLD-epoch laggard's transport resolves `from` under
      // the laggard's OLD (E) membership slot — so strict-binding would DROP the crossing reply before
      // `apply_sync`. The path-sensitive reply binding ([`Self::sender_admits_sync_reply`]) relaxes ONLY
      // for a genuine cross-epoch reply (`config_id` != ours) with a sync OUTSTANDING; the reply carries
      // NO authority and `apply_sync` is the real authenticator (nonce + checkpoint integrity + the
      // carried successor membership). Passing `m.config_id()` keeps a same-config reply STRICT.
      Message::SyncCheckpoint(m) => self.sender_admits_sync_reply(from, m.replica(), m.config_id()),
      // `LearnerStatus` is a NON-VOTING progress report carrying a self `replica()`. It binds to the
      // FULL membership (`sender_is_member`): the EMITTER is a learner (a non-voting member), and a
      // non-member's id must never record progress in `peer_progress`. It carries no quorum authority
      // — the durable frontier it reports only gates the promote proposal, never any vote.
      Message::LearnerStatus(m) => self.sender_is_member(from, m.replica()),
      // The learner-promote-proof challenge + reply carry a self id (the soliciting primary's slot /
      // the answering learner's slot) and NO quorum authority — a no-authority solicitation and a
      // no-vote reply. Both bind to the FULL membership (`sender_is_member`): the challenge is a
      // CURRENT member (the primary) soliciting a learner, and the reply is the target learner (a
      // non-voting member). They gate ONLY a reconfiguration proposal, never any vote; the gate
      // re-validates the full `(nonce, target, epoch, config_id)` binding before acting.
      Message::RequestLearnerProof(m) => self.sender_is_member(from, m.from()),
      Message::LearnerProof(m) => self.sender_is_member(from, m.replica()),
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
      // `EpochAhead` is a pre-binding catch-up SIGNAL: `maybe_request_cross_epoch_catchup` already
      // consumed it (it carries no self-id to bind and no content to dispatch), so DROP it here — it must
      // not reach the dispatch. Returning `false` is the ingress analogue of "already handled".
      Message::EpochAhead(_) => false,
      // Block fetch messages carry no self-identifying replica slot and no quorum authority — they are
      // content-addressed data-plane messages (any configured member may solicit or serve a block).
      Message::RequestBlock(_) | Message::BlockResponse(_) => {
        matches!(from, Peer::Replica(r) if r.get() < self.membership.node_count())
      }
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

  /// The sender binding for the state-sync PULL (`RequestSync`) — the only message that binds by
  /// MEMBER IDENTITY rather than the self-claimed slot, to admit a CROSS-EPOCH laggard whose slot has
  /// SHIFTED. `claimed` is the requester's self-stamped slot; `config_id` is its advertised
  /// configuration lineage.
  ///
  /// # Why the strict slot binding strands a slot-shifted laggard
  ///
  /// A state-sync pull stamps the requester id as the sender's `local_slot()` — for an OLD-epoch laggard,
  /// its OLD slot in its OWN (stale) membership. The transport binds `from` by resolving the peer's STABLE
  /// `MemberId` in the DONOR's ACTIVE membership — the laggard's CURRENT slot. After a legal reconfiguration
  /// that closes/moves slots (`RemoveVoter`, `PromoteLearner`), the laggard's old claimed slot and `from`'s
  /// current slot DIFFER, so the strict `from == Peer::Replica(claimed)` binding ([`Self::sender_is_member`])
  /// DROPS the pull before its handler — cross-epoch catch-up strands for any slot-shifting change (the
  /// laggard is triggered by `EpochAhead` but can never PULL the crossing checkpoint: the `RequestSync`
  /// OFFER pull would be dropped before reaching the donor's handler).
  ///
  /// # Why relaxing this is safe — a state-sync pull carries NO forgeable authority
  ///
  /// Both pulls are PURE SOLICITATIONS: they carry NO view/quorum/vote authority a forged one could abuse.
  /// The handlers use the requester id ONLY (a) as a range/membership bound and (b) as the reply RECIPIENT
  /// — they drive no vote, no view adoption, no quorum bitset, no commit advance. The donor answers ONLY
  /// its OWN durable, committed-vouched checkpoint (integrity-bound to its durable `checkpoint_id`, and —
  /// cross-epoch — carrying a hash-chained successor membership the receiver re-verifies in `apply_sync`).
  /// The reply is harmless even if misaddressed: a recipient installs it ONLY against a matching
  /// outstanding sync nonce it cannot fabricate. So binding by `from` (member identity) instead of the
  /// shifting claimed slot adds NO forge surface — at worst a forged pull from an authenticated member
  /// costs the donor one bounded checkpoint read + ship (a DoS already reachable under the strict binding).
  /// This is the no-authority shape; every AUTHORITY-bearing message
  /// (`Prepare`/`Commit`/`PrepareOk`/`StartView`/`SVC`/`DVC`/…) keeps the strict slot binding, and so does
  /// the donor SERVE reply (`SyncCheckpoint`) — a donor's own slot does not shift on the receiver side,
  /// so the relaxation is scoped to the laggard's OUTBOUND pull only.
  ///
  /// # The binding
  ///
  /// - **Strict path** (the common case, byte-identical to [`Self::sender_is_member`]): `from` is the
  ///   authenticated peer for the claimed slot AND that slot is a current member. Covers same-config and
  ///   any case where slots did not shift.
  /// - **Cross-epoch relaxation** (only when the strict path fails): admit when `from` resolves to a
  ///   CURRENT member of OUR configuration AND the pull's `config_id` is a STRICT ANCESTOR of ours
  ///   ([`Self::in_lineage`] true but NOT equal to our current `config_id`) — i.e. an authenticated current
  ///   member soliciting from an older lineage config, exactly the slot-shifted cross-epoch laggard.
  ///   `from` is bound (the current slot is valid by construction); the self-claimed (stale) slot is NOT
  ///   required to equal it. A SAME-config pull that fails the strict path (a forged/misrouted self-id)
  ///   is NOT relaxed — the ancestor-config gate excludes it.
  fn sender_admits_solicitation(&self, from: Peer, claimed: ReplicaId, config_id: u128) -> bool {
    if self.sender_is_member(from, claimed) {
      return true; // strict path: same-config / no slot shift — unchanged.
    }
    // Cross-epoch relaxation: an authenticated CURRENT member soliciting from a STRICT-ANCESTOR config
    // (its slot shifted across the reconfiguration). Bind by `from`'s current slot, not the stale claim.
    let Some(slot) = from.as_replica() else {
      return false; // a client / non-replica never solicits state-sync.
    };
    self.membership.member_at(slot).is_some()
      && self.in_lineage(config_id)
      && config_id != self.membership.config_id()
  }

  /// The sender binding for the state-sync SERVE REPLY (`SyncCheckpoint`) — the ingress mirror of
  /// [`Self::sender_admits_solicitation`], relaxed for a SLOT-SHIFTED DONOR rather than a slot-shifted
  /// requester. `claimed` is the donor's self-stamped slot (`local_slot()` in the donor's CURRENT
  /// configuration); `config_id` is the reply's advertised configuration lineage — what distinguishes a
  /// genuine cross-epoch reply (a DESCENDANT of ours, eligible for relaxation) from a SAME-config reply
  /// (equal to ours, which stays strict).
  ///
  /// # Why the strict slot binding strands a mid-crossing laggard
  ///
  /// A donor stamps its reply with its CURRENT (E+1) slot. The OLD-epoch laggard, mid-crossing, resolves
  /// `from` by the donor's STABLE `MemberId` under the laggard's OWN (E) membership — the donor's OLD
  /// slot. After a LOW-INDEX `RemoveVoter`/`PromoteLearner` shifted the donor's slot, the donor's CURRENT
  /// claimed slot and `from`'s OLD slot DIFFER, so the strict `from == Peer::Replica(claimed)` binding
  /// ([`Self::sender_is_member`]) DROPS the reply at ingress — BEFORE `apply_sync` can verify the carried
  /// successor membership and install the crossing. A low-index `RemoveVoter(0)` can shift EVERY surviving
  /// donor's slot, stranding every retained old-epoch laggard and potentially wedging the successor quorum.
  ///
  /// # Why relaxing this is safe — a serve reply carries NO forgeable authority
  ///
  /// A reply carries NO view/quorum/vote authority: it is admitted past [`Self::epoch_authority_admits`]
  /// on `sync.is_some()` (NOT lineage — the reply's `config_id` is a DESCENDANT, not an ancestor, of the
  /// laggard's), and `apply_sync` authenticates it DOWNSTREAM by the in-flight sync NONCE (`m.nonce() ==
  /// s.nonce`, an increment the laggard mints and a forger cannot guess), the checkpoint INTEGRITY
  /// (`checkpoint_id(snapshot) == checkpoint_id`, the bind-checked `bound_op == checkpoint_op`), and — for
  /// a crossing — the carried successor membership's hash-chain (`to_membership_verified` re-derives
  /// `config_id` and rejects a forged/corrupt body). So a reply admitted from an authenticated member
  /// cannot be driven by a forged or unsolicited answer: without an outstanding sync nonce it matches, it
  /// is dropped at the handler regardless of this binding. Binding by `from` (member identity) rather than
  /// the donor's shifting claimed slot therefore adds NO forge surface — at worst a misaddressed reply
  /// from an authenticated member is ignored for a nonce mismatch.
  ///
  /// # The binding
  ///
  /// - **Strict path** (the common case, byte-identical to [`Self::sender_is_member`]): `from` is the
  ///   authenticated peer for the claimed slot AND that slot is a current member. Covers same-config and
  ///   any case where slots did not shift — UNCHANGED.
  /// - **Cross-epoch reply relaxation** (only when the strict path fails): admit when the reply is a
  ///   GENUINE cross-epoch reply (`config_id` != our current `config_id` — a descendant the in-flight
  ///   crossing targets) AND a sync is OUTSTANDING (`self.sync.is_some()` — the laggard is mid-crossing)
  ///   AND `from` resolves to a CURRENT member of OUR configuration — i.e. an authenticated member
  ///   answering OUR solicitation under a slot that shifted. `from` is bound (the current slot is valid
  ///   by construction); the donor's self-claimed (shifted) slot is NOT required to equal it.
  /// - A SAME-config reply (`config_id` == ours) that fails the strict path is NEVER relaxed: a donor's
  ///   slot does not shift relative to a same-config receiver, so a self-id mismatch is a forge/misroute,
  ///   and the strict `sender_is_member` binding is the identity backstop for the ordinary same-epoch
  ///   sync path. A reply that fails the strict path with NO sync outstanding (a forged/unsolicited
  ///   answer) is likewise NOT relaxed — the `sync.is_some()` gate excludes it, and the nonce check would
  ///   reject it downstream regardless.
  fn sender_admits_sync_reply(&self, from: Peer, claimed: ReplicaId, config_id: u128) -> bool {
    if self.sender_is_member(from, claimed) {
      return true; // strict path: same-config / no slot shift — unchanged.
    }
    // The relaxation is for a CROSS-EPOCH reply only. A SAME-config reply (`config_id` == our current
    // `config_id`) must stay STRICT: the donor's slot does not shift relative to a same-config receiver,
    // so a self-id mismatch is a forge/misroute, and admitting it would weaken the buggy-driver identity
    // backstop on the ordinary same-epoch sync path. Only a reply whose `config_id` is a DESCENDANT the
    // in-flight cross-epoch sync is crossing TOWARD (not our current config) can legitimately carry a
    // donor slot that shifted out from under the mid-crossing laggard.
    if config_id == self.membership.config_id() {
      return false;
    }
    // Cross-epoch reply relaxation: an authenticated CURRENT member answering OUR outstanding sync under a
    // slot that shifted across the reconfiguration. Bind by `from`'s current slot, not the donor's stale
    // claim. Scoped to `sync.is_some()` (the same gate `epoch_authority_admits` uses for these replies):
    // no outstanding sync ⇒ no crossing in flight, so a strict-mismatched reply is a forge/misroute, NOT a
    // slot-shifted answer, and stays dropped.
    if self.sync.is_none() {
      return false;
    }
    from
      .as_replica()
      .is_some_and(|slot| self.membership.member_at(slot).is_some())
  }

  /// The (epoch, config_id) AUTHORITY gate, layered ON TOP of [`Self::sender_matches`]: it admits a
  /// message to the dispatch only when its configuration claim entitles it to the AUTHORITY it would
  /// exercise. `sender_matches` answers "is `from` the slot that may send this kind?"; this answers
  /// "is the SENDER's configuration mine?". One place, every ingress path — the configuration analogue
  /// of the sender-binding chokepoint.
  ///
  /// The matrix (the message's vote/lead/serve authority):
  /// - **STRICT** — `Prepare`(normal head-advancing arm), `PrepareOk`, `Commit`, `StartViewChange`,
  ///   `DoViewChange`, `StartView`, `GetView`, `Recovery`, `RecoveryResponse`, `PrepareBatch`,
  ///   `LearnerStatus`: the message drives an APPEND / VOTE / VIEW-ADOPTION (or, for `LearnerStatus`,
  ///   GATES a reconfiguration proposal) in MY configuration, so it is admitted only on an exact
  ///   `(epoch, config_id)` match. A foreign-epoch / foreign-config message contributes NOTHING
  ///   (dropped for authority) — a peer in a different configuration neither votes in mine, makes me
  ///   adopt its view, nor reports a frontier I act on.
  /// - **AGNOSTIC** — `RequestPrepare`, `RequestPrepareRange`, `RepairBatch`, `RequestSync`,
  ///   `SyncCheckpoint`: committed, view-independent content carrying NO vote/lead authority (verified
  ///   independently downstream — checksum + committed-vouch / checkpoint-id), so it is admitted from
  ///   any config IN MY LINEAGE ([`Self::in_lineage`]), letting a node catch up across an epoch boundary.
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
      // STRICT: a learner's progress report is CONFIG-SCOPED — it gates a reconfiguration proposal in MY
      // configuration, so it is admitted only on an exact `(epoch, config_id)` match. A foreign-config
      // learner's frontier is not this primary's to act on.
      Message::LearnerStatus(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      // STRICT: the learner-promote-proof challenge + reply are CONFIG-SCOPED — they prove/gate a
      // reconfiguration in MY configuration, so each is admitted only on an exact `(epoch, config_id)`
      // match. A cross-epoch challenge/reply contributes NOTHING (a learner answers only for its live
      // config; a proof minted under the old config never validates a later mint) — the `(epoch,
      // config_id)` binding is the freshness backstop the gate relies on.
      Message::RequestLearnerProof(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      Message::LearnerProof(m) => {
        m.epoch() == self.membership.epoch() && self.in_lineage(m.config_id())
      }
      // PATH-SENSITIVE `Prepare`: gate the config_id (common to both arms); the normal arm's epoch
      // check is branched inside `on_prepare`. A foreign-lineage Prepare is dead on BOTH arms.
      Message::Prepare(m) => self.in_lineage(m.config_id()),
      // AGNOSTIC: in-lineage only — committed, view-independent content with no vote/lead authority.
      Message::RequestPrepare(m) => self.in_lineage(m.config_id()),
      Message::RequestPrepareRange(m) => self.in_lineage(m.config_id()),
      // AGNOSTIC (in-lineage, like its paired `RequestPrepare`): "I durably lack op N" is a
      // config-lineage fact. `on_nack` enforces the precision (only a CURRENT-config voter's lack counts
      // toward the tally, keyed by stable `MemberId`).
      Message::Nack(m) => self.in_lineage(m.config_id()),
      Message::RepairBatch(m) => self.in_lineage(m.config_id()),
      Message::RequestSync(m) => self.in_lineage(m.config_id()),
      // A SyncCheckpoint answering an OUTSTANDING sync is admitted even from a higher (descendant)
      // config not yet in our lineage: it is the cross-epoch catch-up answer to OUR own solicitation,
      // and the serving peer stamps it with its CURRENT (post-swap) config, which a lagging solicitor
      // could not otherwise admit. The handler authenticates it by the in-flight sync nonce and verifies
      // the checkpoint's integrity before installing, so admitting it on `sync.is_some()` cannot be
      // driven by an unsolicited or forged answer.
      Message::SyncCheckpoint(m) => self.in_lineage(m.config_id()) || self.sync.is_some(),
      // NEITHER: client-facing, no (epoch, config_id) to check.
      Message::Request(_) | Message::Reply(_) => true,
      // `EpochAhead` carries NO (epoch, config_id) authority pair to admit — it is a pre-binding hint
      // already consumed before this gate (and dropped at `sender_matches`). It exercises no authority,
      // so it is never admitted to the dispatch.
      Message::EpochAhead(_) => false,
      // Block fetch messages carry no (epoch, config_id) pair — they are content-addressed and
      // config-agnostic (a block's identity is its hash, independent of any epoch or config).
      Message::RequestBlock(_) | Message::BlockResponse(_) => true,
    }
  }

  /// Whether the SM-content reconstruction for a synced checkpoint `M` is still owed — `self.checkpoint_op`
  /// already names M (its durable root landed) but `self.sm` does not yet hold M's content (a verify-on-read
  /// `sm.restore` faulted and the retry has not yet succeeded). While owed, the node MUST NOT serve a
  /// `SyncCheckpoint` for M (it cannot — the SM is not M yet) nor apply an op against the un-restored SM;
  /// this is the single gate the serve/apply sites consult, the warm-path analogue of cold-start
  /// `recover()`'s "SM not yet reconstructed" window.
  pub(crate) fn sm_reconstruct_owed(&self) -> bool {
    self.sm_reconstruct.is_some()
  }

  /// Whether a verified state-sync install is RETAINED-but-not-yet-staged — `apply_sync` drained + verified
  /// the complete DAG but the first [`BlockStore::flush`] faulted, so its two-write re-persist was NOT
  /// submitted: the install lives on as `pending_install` with NO in-flight `pending_checkpoint`. While in
  /// this state the sync solicit / recover cadence re-flushes + stages LOCALLY ([`Self::retry_install_flush`]
  /// → [`Self::flush_and_stage_install`], no fresh donor reply needed), so a transient disk fault does not
  /// permanently strand a sync whose donor later crashed.
  #[cfg(test)]
  pub(crate) fn install_flush_retry_owed(&self) -> bool {
    self.pending_install.is_some() && self.pending_checkpoint.is_none()
  }

  /// Whether a [`SyncCheckpoint`] PRESENTS a cross-epoch crossing against our current configuration: its
  /// `config_id` is strictly foreign AND it carries a NON-EMPTY successor membership. This is the exact
  /// crossing-presentation test [`Self::apply_sync`] keys on before VERIFYING the membership hash-chain
  /// (`m.config_id() != self.membership.config_id() && !m.membership().is_empty()`), evaluated up front so a
  /// [`BlockFetch`] records whether the reply it is draining is genuinely a crossing — a same-config or
  /// empty-membership reply (a donor in the force-checkpoint window serving its `M < N` checkpoint) is NOT.
  /// Presentation, not verification: `apply_sync` still re-verifies the carried bytes hash-chain before
  /// installing, so a presented-but-unverified crossing is dropped there — but for the crossing-answer
  /// shield, a presented crossing must already count as "a donor is answering a crossing," while a reply
  /// that does not even present one must not.
  fn checkpoint_presents_crossing(&self, m: &crate::SyncCheckpoint) -> bool {
    m.config_id() != self.membership.config_id() && !m.membership().is_empty()
  }

  /// Whether a live `block_fetch` is draining a reply that genuinely PRESENTS a cross-epoch crossing (its
  /// recorded [`BlockFetch::crossing_answered`] bit). A `BlockFetch` is armed BEFORE `apply_sync` verifies
  /// the carried membership, and the cross-epoch solicit admits below-target replies onto the fetch path,
  /// so a bare `block_fetch.is_some()` is NOT proof a crossing answer is in flight — a same-config /
  /// empty-membership reply arms a live fetch that is not a crossing. The crossing-answer predicates read
  /// THIS so a non-crossing reply (or its kept-live re-pin window) cannot shield a stale `cross_epoch_intent`
  /// against same-epoch authority.
  fn crossing_answer_in_flight(&self) -> bool {
    self
      .block_fetch
      .as_ref()
      .is_some_and(|bf| bf.crossing_answered)
  }

  /// Whether the node is OPERATING at its current epoch with no GENUINE answered crossing in flight, so a
  /// stale `cross_epoch_intent` armed by a higher-epoch hint may be CLEARED on same-epoch evidence (the
  /// ingress [`Self::cancel_stale_cross_epoch_sync`] OR the trigger-level
  /// [`Self::downgrade_stale_cross_epoch_sync`]). A crossing a donor has begun answering is GENUINE and the
  /// intent backs it — it must complete on its own path, so the intent is NOT cleared while one is live: a
  /// NON-Normal recovery peer-fetch (`awaiting_peer_checkpoint`); a crossing whose live `block_fetch` is
  /// draining a reply that PRESENTS a successor membership (`crossing_answer_in_flight` — including an
  /// active-donor absent for a GC-pruned block, which KEEPS that fetch live and re-solicits a fresh
  /// checkpoint, so the answer signal survives the re-pin window); or an SM-reconstruct obligation owed (the
  /// crossing's root is durable and its successor already installed — its SM is just being reconstructed). A
  /// live fetch draining a SAME-CONFIG / EMPTY-membership reply is NOT a crossing answer and does NOT shield
  /// the intent — otherwise a stale/misrouted higher-epoch hint would stay shielded by non-crossing replies
  /// forever, wedging a primary whose `sync.is_some()` blocks new-op admission.
  ///
  /// A staged SAME-CONFIG install (`pending_install` with `successor: None`) does NOT block this clear: the
  /// intent is about a FUTURE crossing, and a same-config install would, on completion, `on_sb_done`-re-arm a
  /// bogus crossing from a surviving stale intent (the poison the intent lifecycle exists to prevent). It is
  /// not a crossing — clearing its (irrelevant) intent is safe; the install is COMMITTED, so its SYNC must
  /// not be torn down, which is the narrower [`Self::crossing_is_pre_answer_speculative`] below (this
  /// condition AND no staged install at all).
  ///
  /// A staged CROSSING install (`pending_install` with `successor.is_some()`) DOES block this clear: it is a
  /// VERIFIED, committed crossing — `apply_sync` reconstructed and verified the successor membership, staged
  /// the install, and drained `block_fetch` — so the persistent intent legitimately backs it. Same-epoch
  /// traffic is NOT evidence such a crossing is stale. If the intent were cleared here, a later
  /// `reset_for_view_transition` that cancels the pre-root install (dropping `pending_install`/`sync`) would
  /// leave the laggard with NO record it intends to cross — stranded at the OLD epoch until some unrelated
  /// higher-epoch hint happens to re-arm it. So a verified staged crossing keeps its intent.
  fn stale_crossing_intent_clearable(&self) -> bool {
    self.status.is_normal()
      // Clearable only when there is NO staged install OR the staged install is SAME-CONFIG
      // (`successor.is_none()`). A staged CROSSING install (`successor.is_some()`) is a verified, committed
      // crossing the intent backs — do NOT clear the intent on same-epoch evidence; a same-config install is
      // not a crossing, so its (irrelevant) intent stays clearable.
      && self.pending_install.as_ref().is_none_or(|pi| pi.successor.is_none())
      && !self.awaiting_peer_checkpoint()
      // A donor has begun answering a CROSSING iff a live `block_fetch` is draining a reply that PRESENTS a
      // successor membership (`crossing_answer_in_flight`). An active-donor absent for a GC-pruned block does
      // NOT clear it — the fetch is kept live and a fresh `SyncCheckpoint` re-solicited — so a crossing whose
      // donor answered (even with an absent) still reads as answered across the re-pin window. But a live
      // fetch draining a SAME-CONFIG / EMPTY-membership reply is NOT a crossing answer (it arms a fetch the
      // cross-epoch solicit admitted below target, before `apply_sync` verifies the membership) — it must not
      // shield the intent, or a misrouted higher-epoch hint stays shielded by non-crossing replies forever.
      && !self.crossing_answer_in_flight()
      // An SM-reconstruct obligation means a synced checkpoint's root is already durable and (for a crossing)
      // its successor already installed — only the SM content is being reconstructed. Never tear that down
      // on same-epoch evidence. (It usually keeps a `block_fetch` armed, already excluded above; this
      // covers the corner where the retry's DAG read clean and left `block_fetch` None.)
      && !self.sm_reconstruct_owed()
  }

  /// Whether an outstanding `require_cross_epoch` sync (the caller confirms one exists) is a BARE PRE-ANSWER
  /// speculative crossing — a hint that has accumulated NO answer-derived state, so a same-epoch
  /// stale-evidence path may safely DROP THE SYNC (not only clear the intent). This is the
  /// [`Self::stale_crossing_intent_clearable`] condition PLUS NO STAGED INSTALL AT ALL: a sync that has
  /// STAGED its `pending_install` is COMMITTED to installing, so its `sync`/`pending_install`/
  /// `pending_checkpoint` triple must stay intact until the staged root completes — tearing the sync down
  /// would ORPHAN the staged install (a state-sync root completion whose handshake was torn down) and break
  /// the `pending_install => sync` coupling. A staged install must not be torn down whether or not it carries
  /// a successor membership: an ordinary same-config install (`successor: None`) is equally committed.
  ///
  /// The two predicates therefore read CONSISTENTLY on a staged install: a VERIFIED CROSSING (`successor`
  /// set) is neither speculative (the `pending_install.is_none()` term here is false) NOR intent-clearable
  /// (the shared predicate's successor-shield is false), so its sync, transfer, and persistent intent all
  /// survive; a SAME-CONFIG install (`successor: None`) is not speculative (same `is_none()` term) but its
  /// (irrelevant) intent stays clearable, and its committed sync still survives.
  ///
  /// A live `block_fetch` is no longer an unconditional bar to speculative: a fetch draining a CROSSING
  /// reply (`crossing_answer_in_flight`) is excluded by the shared predicate (it is a genuine answered
  /// crossing), but a fetch draining a SAME-CONFIG / EMPTY-membership reply — which the cross-epoch solicit
  /// admitted onto the fetch path before `apply_sync` verifies it — IS speculative: it would install with
  /// `successor = None` and exit STILL at the old epoch, so on same-epoch evidence dropping its bare sync +
  /// fetch is the intended stale-crossing cleanup, not a torn-down genuine crossing.
  fn crossing_is_pre_answer_speculative(&self) -> bool {
    // A RETAINED `pending_install` (whether staged or owed-but-not-staged after a flush fault) is a VERIFIED,
    // drained install COMMITTED to installing — NOT a pre-answer speculation; the single `pending_install`
    // check bars speculative teardown for both, since tearing the sync down here would orphan the install.
    self.stale_crossing_intent_clearable() && self.pending_install.is_none()
  }

  /// Cancels a speculative `require_cross_epoch` sync when `msg` is strict-epoch authority traffic admitted
  /// at OUR CURRENT epoch — proof we are operating at it, so the crossing was armed by a stale/misrouted
  /// unverified hint, not a real successor (see the call site in `handle_message_inner`). A node genuinely
  /// behind a higher epoch gets no such traffic, so it never reaches here and stays armed to cross. The
  /// agnostic solicitations/answers (incl. a cross-epoch sync ANSWER, which must not cancel its own
  /// crossing), a foreign-epoch `Prepare`, client traffic, and `EpochAhead` are NOT same-epoch evidence.
  fn cancel_stale_cross_epoch_sync(&mut self, msg: &Message) {
    // A crossing requirement is outstanding as a `require_cross_epoch` SYNC and/or a persistent INTENT. The
    // intent is DECOUPLED from the sync, so it can be ORPHANED — a path like `reset_for_view_transition`
    // clears `sync` without clearing it — and then NO later same-epoch traffic could clear it if we keyed
    // only off the sync, so `on_sb_done` could re-poison a crossing from the orphan. Check BOTH, and clear
    // the orphaned intent on same-epoch evidence even when no sync remains. An ordinary / forced same-epoch
    // sync is never cancelled here.
    let crossing_sync = self.sync.is_some_and(|s| s.require_cross_epoch);
    if self.cross_epoch_intent.is_none() && !crossing_sync {
      return; // no crossing requirement outstanding (neither a crossing sync nor an intent).
    }
    // Scope to a crossing the node may safely abandon on same-epoch evidence: it is operating at its current
    // epoch with no GENUINE answered crossing in flight (the shared [`Self::stale_crossing_intent_clearable`]
    // condition). A crossing a donor has begun answering — a live transfer, a non-Normal recovery peer-fetch,
    // or an SM-reconstruct obligation — is genuine and must complete on its own path, never be disturbed
    // here. A VERIFIED CROSSING staged install (`pending_install.successor` set) is ALSO out of scope: it is
    // a committed crossing the intent backs, so neither the sync nor the intent is touched. A SAME-CONFIG
    // staged install IS in scope (its intent for a future crossing is still stale and must be clearable) but
    // is COMMITTED, so the sync teardown below is gated more narrowly than the intent clear.
    if !self.stale_crossing_intent_clearable() {
      return;
    }
    let epoch = self.membership.epoch();
    let same_epoch = match msg {
      Message::Prepare(m) => m.epoch() == epoch,
      Message::Commit(m) => m.epoch() == epoch,
      Message::PrepareOk(m) => m.epoch() == epoch,
      Message::StartViewChange(m) => m.epoch() == epoch,
      Message::DoViewChange(m) => m.epoch() == epoch,
      Message::StartView(m) => m.epoch() == epoch,
      Message::GetView(m) => m.epoch() == epoch,
      Message::Recovery(m) => m.epoch() == epoch,
      Message::RecoveryResponse(m) => m.epoch() == epoch,
      Message::PrepareBatch(m) => m.epoch() == epoch,
      Message::LearnerStatus(m) => m.epoch() == epoch,
      _ => false,
    };
    if same_epoch {
      // Drop the bare crossing SYNC only when it is PRE-ANSWER speculative — no staged install. A crossing
      // whose sync has already STAGED its `pending_install` is COMMITTED to installing: tearing the sync
      // (and its fetch) down here would ORPHAN the staged install (leaving `pending_install` +
      // `pending_checkpoint` live with no `sync`), breaking the `pending_install => sync` coupling and
      // running a state-sync root completion whose handshake was torn down. So a staged install keeps the
      // sync intact — the stale-crossing handling for a SAME-CONFIG staged install is at MOST the intent
      // clear below (a verified crossing staged install was already excluded by the scope guard, so it does
      // not reach here at all). (The sync may also already have been cleared by another path, leaving only an
      // orphaned intent.)
      if crossing_sync && self.crossing_is_pre_answer_speculative() {
        self.sync = None;
        self.block_fetch = None;
      }
      // A same-epoch operating witness proves the higher-epoch HINT was stale, so drop the PERSISTENT
      // crossing intent too — not just the in-flight sync. Otherwise `on_sb_done`'s re-arm would re-pin a
      // crossing for the bogus hint forever (re-introducing the poison this cancel exists to clear). This
      // fires even when a STAGED same-config install kept the sync above: that install completes at the old
      // epoch and would re-arm a bogus crossing from a surviving stale intent, so the intent MUST clear here
      // while the committed install runs on undisturbed. The scope guard already excluded a genuine
      // in-progress crossing (non-Normal / a live transfer / SM-reconstruct) AND a verified staged crossing
      // (`pending_install.successor` set), both of which the intent legitimately backs. A real higher epoch
      // still re-establishes the intent on the next higher-epoch trigger (pre-binding, every message).
      self.cross_epoch_intent = None;
    }
  }
}

/// The state-machine-driving operations: the `handle_*` ingress/timeout/storage entry points and the
/// poll/timer machinery they reach. These transitively invoke `S::apply`/`snapshot`/`restore` (via the
/// submodule consensus methods), so — per the method-local-bounds rule — they carry `S: StateMachine`
/// and `R: Reconfig` here, while the pure accessors/observers above are unconstrained (callable on
/// any `Endpoint<S, R>`).
impl<S, R> Endpoint<S, R>
where
  S: StateMachine,
  R: Reconfig,
{
  /// Feeds an incoming protocol message. Runs `assert_invariants` at exit (TigerBeetle's `assert_main`)
  /// so the `(status × sub-state-flag)` coupling is re-checked after EVERY ingress, across all of
  /// `handle_message_inner`'s early-return paths.
  pub fn handle_message<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    msg: Message,
  ) {
    self.handle_message_inner(now, wal, sb, blocks, from, msg);
    #[cfg(debug_assertions)]
    self.assert_invariants();
  }

  /// The epoch-mismatch RESPONSE: the egress half of the symmetric pre-`sender_matches` pair. When a
  /// strictly-LOWER-epoch vote/lead message (`Prepare`/`Commit`/`StartViewChange`/`DoViewChange` — a
  /// stranded laggard's old-epoch traffic) arrives from an ACTIVE replica member, emit a minimal
  /// `EpochAhead{epoch, checkpoint_op}` hint back to it, so a slot-shifted laggard that cannot bind the
  /// new primary still gets the catch-up trigger from a BINDABLE retained voter (us). We act on NONE of
  /// the stale message's content — it is still dropped at `sender_matches` / `epoch_authority_admits`
  /// exactly as before; this is a pure egress side-effect.
  ///
  /// The hint carries no authority (no view, no vote/quorum, no op/commit content) a forged one could
  /// abuse: the laggard treats it ONLY as a rate-limited sync trigger, and the forced cross-epoch
  /// peer-fetch it drives is crossing-required + self-verifying. No storm: ONLY a SETTLED member answers
  /// (`is_normal()` + a valid local slot — a Retired/Recovering node must not), and the response is
  /// bounded by the laggard's own timer-bounded stale traffic (one hint per inbound stale message). A
  /// lower-epoch message that is NOT from an active member elicits nothing.
  fn maybe_answer_lower_epoch(&mut self, from: Peer, msg: &Message) {
    // Only a SETTLED cluster member answers: Normal, and present in its own active membership (a Retired
    // node — removed by a reconfiguration — has no local slot and must stay silent; a Recovering /
    // ViewChange node is not in a position to vouch the cluster's current epoch).
    if !self.status.is_normal() || self.local_slot_opt().is_none() {
      return;
    }
    // The trigger set is the lower-epoch shape of a stranded laggard's vote/lead traffic. Read only the
    // sender's claimed epoch (NOT any view/op/commit content). `LearnerStatus` is excluded: a non-voting
    // learner is not a stranded VOTER laggard and crosses by its own catch-up, not this pull.
    let msg_epoch = match msg {
      Message::Prepare(m) => m.epoch(),
      Message::Commit(m) => m.epoch(),
      Message::StartViewChange(m) => m.epoch(),
      Message::DoViewChange(m) => m.epoch(),
      _ => return,
    };
    if msg_epoch >= self.membership.epoch() {
      return;
    }
    // Authenticate `from` as an ACTIVE replica member of OUR configuration (its slot resolves to a
    // current member): a non-replica / out-of-config peer elicits no hint. We do not need the message's
    // self-id to match — the hint carries no authority, so binding `from` to the configured-member set is
    // the full check.
    let Some(slot) = from.as_replica() else {
      return;
    };
    if self.membership.member_at(slot).is_none() {
      return;
    }
    self.emit(Outgoing::new(
      Recipient::To(from),
      Message::EpochAhead(crate::EpochAhead::new(
        self.membership.epoch(),
        self.checkpoint_op,
      )),
    ));
  }

  /// The body of [`Self::handle_message`]; see it for the exit-time invariant check that wraps this.
  fn handle_message_inner<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
    from: Peer,
    msg: Message,
  ) {
    // A Retired replica was removed from the configuration by a reconfiguration — it is no longer a
    // cluster member, so it processes NO incoming message: casts no vote, serves no request, adopts no
    // view, triggers no catch-up. This is the STRUCTURAL close for the removed-member class — a removed
    // node reaches no voter path (nor any panicking `local_slot()`) by construction, regardless of how
    // many entry paths exist. The embedder shuts it down on the `MembershipChanged` that removed it.
    if self.status.is_retired() {
      return;
    }
    // Cross-epoch catch-up TRIGGER — run BEFORE the sender binding below. `sender_matches` validates a
    // `Commit`/normal `Prepare` against OUR predecessor-primary for the view; but a live removal can
    // change the primary slot, so the honest E+1 primary is a DIFFERENT retained voter — its higher-epoch
    // heartbeat would be dropped at the sender binding before it could signal us to catch up. Recognize a
    // strictly-higher-epoch `Prepare`/`Commit` from a configured member (`from`) here, re-arm the
    // committed-vouched catch-up, and act on NONE of the content. (A non-trigger message no-ops.)
    self.maybe_request_cross_epoch_catchup(now, from, &msg);
    // Epoch-mismatch RESPONSE — the SYMMETRIC pre-binding hook, also BEFORE the sender binding. A
    // reconfiguration that removes the old primary / shifts slots can make the honest E+1 primary a
    // DIFFERENT retained voter a stranded laggard cannot bind (its `MemberId` is absent from the
    // laggard's old membership) — so the laggard never hears the higher-epoch trigger above. But the
    // laggard CAN still bind the RETAINED voters; its futile old-epoch traffic reaches us here (and is
    // dropped at `sender_matches` / `epoch_authority_admits` below, exactly as before). So when a
    // strictly-LOWER-epoch message arrives from an active member, we answer it with a minimal
    // higher-epoch `EpochAhead` hint, pulling the laggard's catch-up trigger back from a bindable peer.
    // It acts on NONE of the stale message's content; it is rate-limited by construction (one hint per
    // inbound stale message; the laggard's stale traffic is timer-bounded) and self-terminating (the
    // laggard crosses and stops emitting stale traffic).
    self.maybe_answer_lower_epoch(from, &msg);
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
      // Inadmissible. The cross-epoch catch-up trigger ran ABOVE (before the sender binding), so a
      // higher-epoch heartbeat from a successor primary has already re-armed our catch-up; here we just
      // drop the (unactable) content.
      return;
    }
    // Admitted strict-epoch authority traffic at OUR current epoch ⟹ we are operating at it, not crossing
    // — so cancel any speculative cross-epoch sync a (possibly stale/misrouted) unverified higher-epoch
    // hint armed. ONE ingress chokepoint, so no same-epoch path can leave a stale `require_cross_epoch`
    // set (which would otherwise block primary op-mint + backup checkpoint reports and reject every
    // same-config sync reply indefinitely). A node genuinely behind a higher epoch receives NO same-epoch
    // admissible authority traffic (its old primary swapped), so it stays armed and crosses; the
    // cross-epoch trigger re-arms `require_cross_epoch` on the next higher-epoch heartbeat / `EpochAhead`.
    self.cancel_stale_cross_epoch_sync(&msg);
    // A Recovering replica does NOT process ANY consensus message: it is still draining its own
    // durable storage (the async `handle_storage` loop) and does not even know its true head yet, so
    // it casts no PrepareOk/vote/DVC and adopts no peer's view until it reaches Normal. This also
    // blocks the higher-view `catch_up_to_view` pre-checks inside the per-message handlers (which
    // would otherwise yank a recovering replica into ViewChange mid-recovery).
    //
    // The ONE exception: a replica whose OWN durable checkpoint read exhausted its budget cannot
    // restore its SM from disk and is FETCHING the checkpoint from a peer (`awaiting_peer_checkpoint`).
    // It must accept the answering `SyncCheckpoint` — mirroring how a `RecoveringHead` replica accepts
    // a `StartView` to learn its head — and the `BlockResponse`s that carry the SM checkpoint DAG it
    // then walks. Every other message is still dropped (it casts no ack/vote).
    if self.status.is_recovering() {
      if self.awaiting_peer_checkpoint() {
        match msg {
          Message::SyncCheckpoint(m) => {
            self.on_recover_sync_checkpoint(now, wal, sb, blocks, from, m)
          }
          // While the recovery peer-fetch is pulling the SM checkpoint DAG, accept block responses
          // that feed the frontier (the over-frame chunked path is gone — the SM state IS the DAG).
          Message::BlockResponse(m) => self.on_block_response(now, wal, sb, blocks, from, m),
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
        Message::StartView(m) => self.on_start_view(now, wal, sb, blocks, m),
        Message::RecoveryResponse(m) => self.on_recovery_response(now, wal, sb, blocks, m),
        Message::Recovery(m) => {
          // Tally a co-recovering OTHER VOTER (only another voter counts toward the voting-quorum
          // evidence G2), with ZERO emission. `sender_matches` already bound `from` to `m.replica()`
          // and admitted the full membership range, so re-check the VOTER subset here AND exclude self
          // — a looped-back local `Recovery` must not count toward the OTHER-voters quorum (else a node
          // could satisfy G2 alone). The bit is keyed by the sender slot (the `svc_from` shape);
          // `recover_head_timeouts` reads then clears this set per window.
          //
          // Keyed by slot ONLY, with no per-incarnation sequence: a replayed/duplicate `Recovery` just
          // re-sets the same bit. That is intentional — the tally stays ZERO-EMISSION (byte-identity
          // safe) and the `Recovery` nonce is the sender's own token, identical across a duplicate, so it
          // cannot distinguish a replay. A duplicate-replay that spuriously satisfies G2 only triggers an
          // always-SAFE convergent view change (see `may_escalate_reformation`): committed-op safety
          // never depends on this tally's freshness.
          if self.membership.is_voter(m.replica())
            && m.replica() != self.local_slot()
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
      Message::Prepare(p) => self.on_prepare(now, wal, sb, blocks, p),
      Message::PrepareBatch(m) => self.on_prepare_batch(now, wal, sb, blocks, m),
      Message::PrepareOk(ok) => self.on_prepare_ok(now, sb, blocks, ok),
      Message::Commit(c) => self.on_commit(now, sb, blocks, c),
      Message::StartViewChange(m) => self.on_start_view_change(now, sb, m),
      Message::DoViewChange(m) => self.on_do_view_change(now, wal, sb, blocks, m),
      Message::StartView(m) => self.on_start_view(now, wal, sb, blocks, m),
      Message::GetView(m) => self.on_get_view(now, m),
      Message::RequestPrepare(m) => self.on_request_prepare(now, from, m),
      Message::RequestPrepareRange(m) => self.on_request_prepare_range(now, from, m),
      Message::Recovery(m) => self.on_recovery(now, m),
      Message::RecoveryResponse(m) => self.on_recovery_response(now, wal, sb, blocks, m),
      // State-sync: a peer's sync solicitation is answered from our durable checkpoint
      // (`on_request_sync`); a sync response is verified, its SM checkpoint DAG fetched, then applied
      // (`on_sync_checkpoint`).
      Message::RequestSync(m) => self.on_request_sync(now, sb, from, m),
      Message::SyncCheckpoint(m) => self.on_sync_checkpoint(now, wal, sb, blocks, from, m),
      Message::RepairBatch(m) => self.on_repair_batch(now, wal, sb, m),
      // A learner's NON-VOTING progress report: record the durable frontier in `peer_progress` (touches
      // no quorum/vote state). It is a liveness HINT for a later `propose_membership(PromoteLearner)`.
      Message::LearnerStatus(m) => self.on_learner_status(m),
      // The learner-promote-proof challenge: reply with this node's CONTIGUOUS APPLIED FRONTIER
      // (`commit()`) recomputed from durable state NOW (touches no quorum/vote state).
      Message::RequestLearnerProof(m) => self.on_request_learner_proof(m),
      // The target learner's fresh-proof reply: validate against the outstanding challenge and record
      // the proven frontier (the catch-up-then-promote gate's fresh safety input; no accumulation).
      Message::LearnerProof(m) => self.on_learner_proof(from, m),
      Message::Reply(_) => {}
      // `EpochAhead` is a pure pre-binding catch-up SIGNAL — fully consumed above by
      // `maybe_request_cross_epoch_catchup` (it never reaches here: `sender_matches` drops it). Acting on
      // no content, it is a dispatch no-op.
      Message::EpochAhead(_) => {}
      // Block-DAG state-sync: serve a requested block from our store (stateless, content-addressed),
      // or feed a fetched block into the in-progress block-fetch frontier.
      Message::RequestBlock(addr) => self.on_request_block(from, addr, blocks),
      Message::BlockResponse(m) => self.on_block_response(now, wal, sb, blocks, from, m),
      // The negative repair answer: count the sender's durable LACK of a repair-or-truncate candidate op
      // toward the nack quorum that truncates the uncommitted tail (a new-primary-only tally).
      Message::Nack(m) => self.on_nack(wal, from, m),
    }
  }

  /// Records a learner's NON-VOTING durable-frontier report into `peer_progress`, keyed by the sender's
  /// STABLE [`MemberId`] (resolved from its slot, stable across reconfiguration). This touches ONLY
  /// `peer_progress` — never `inflight`, the DVC/SVC vote maps, or any quorum bitset — so a
  /// `LearnerStatus` can never contribute to a commit / view-change / recovery quorum; it is purely the
  /// input to the catch-up-then-promote gate in
  /// [`Endpoint::propose_membership`](crate::Endpoint::propose_membership).
  ///
  /// The update is MONOTONE: `(*entry).max(reported)`, so a reordered or duplicated lower report under
  /// network reordering NEVER lowers a recorded value. An honest emitter sends its CONTIGUOUS APPLIED
  /// FRONTIER as `durable_commit_min` (the highest hole-free op it durably holds — see
  /// `learner_status_timeouts`), which already cannot exceed its durable WAL head; the recorded value
  /// keeps `min(durable_commit_min, durable_op)` purely as a cheap BACKSTOP that fail-closes a
  /// buggy/forged emitter (one that over-reports `durable_commit_min` past its durable WAL head, e.g. by
  /// sending its `commit_max`) — it never raises the metric for an honest emitter, so it cannot loosen
  /// the gate, only tighten it. The catch-up-then-promote gate must admit the learner only once it
  /// durably HOLDS the prefix it will be allowed to vote on, not merely knows a commit point.
  ///
  /// `sender_matches` + `epoch_authority_admits` already bound the sender to a current member of MY
  /// configuration at the claimed slot, so `member_at` resolves; a slot with no member (impossible past
  /// those gates) is ignored.
  fn on_learner_status(&mut self, m: crate::LearnerStatus) {
    let Some(member) = self.membership.member_at(m.replica()) else {
      return;
    };
    // `durable_commit_min` is the emitter's contiguous applied frontier (hole-free, `<= op_head` by
    // construction). The `min(durable_op)` is a fail-closed BACKSTOP against a buggy/forged emitter that
    // over-reports past its durable WAL head: it can only LOWER a dishonest value, never raise an honest
    // one, so it tightens the gate but cannot loosen it.
    let reported = m.durable_commit_min().min(m.durable_op());
    let entry = self.peer_progress.entry(member).or_default();
    *entry = (*entry).max(reported);
  }

  /// Answers a primary's [`RequestLearnerProof`](crate::RequestLearnerProof) challenge with a FRESH
  /// [`LearnerProof`](crate::LearnerProof): this node's CONTIGUOUS APPLIED FRONTIER (`self.commit()` ==
  /// `commit_min`, the hole-free durably-recoverable prefix) recomputed from durable state NOW.
  ///
  /// `sender_matches` already bound the challenge to a CURRENT member (the primary) at the claimed
  /// slot. Here we additionally require the challenge's `(epoch, config_id)` to match THIS node's live
  /// configuration — a cross-epoch challenge is DROPPED (the node answers only for its live config), so
  /// a stale-config proof can never satisfy a later mint. The reply echoes the challenge `nonce` (the
  /// freshness binding) and self-identifies by `local_slot()`. Computing the frontier fresh is the
  /// load-bearing property: a just-crashed node answers with its regressed (lower) frontier, and a node
  /// mid-crash never answers — so no remembered high-water survives the fault.
  fn on_request_learner_proof(&mut self, m: crate::RequestLearnerProof) {
    // Cross-epoch challenge: answer only for the live configuration (the `epoch_authority_admits` STRICT
    // gate already enforces this on ingress; re-checked here so the reply is correct-by-construction
    // against the live config it stamps).
    if m.epoch() != self.membership.epoch() || m.config_id() != self.membership.config_id() {
      return;
    }
    let frontier = self.commit();
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(m.from())),
      Message::LearnerProof(crate::LearnerProof::new(
        self.local_slot(),
        m.nonce(),
        frontier,
        self.membership.epoch(),
        self.membership.config_id(),
      )),
    ));
  }

  /// Records the target learner's fresh [`LearnerProof`](crate::LearnerProof) frontier against the
  /// outstanding promote challenge ([`Self::learner_proof`]) — the catch-up-then-promote gate's FRESH
  /// safety input. Validated against the outstanding challenge: it must be `Some`, the `nonce` must
  /// match, the authenticated `from` must resolve to the challenge `target`, and the reply's
  /// `(epoch, config_id)` must match this primary's current configuration. On a match, `proof` is set
  /// to the reported frontier; a stale-nonce / wrong-target / foreign-config reply is DROPPED (no
  /// accumulation — this is a single-shot token consumed at mint).
  fn on_learner_proof(&mut self, from: Peer, m: crate::LearnerProof) {
    let Some(challenge) = self.learner_proof.as_mut() else {
      return; // no outstanding challenge — an unsolicited / late reply.
    };
    if m.nonce() != challenge.nonce {
      return; // a stale-nonce reply (a replayed / superseded challenge's answer).
    }
    // The authenticated sender must be the challenge target. `sender_matches` bound `from` to
    // `m.replica()` already; resolve that slot to the stable MemberId and require it to be `target`, so
    // a different member's reply (even one carrying the right nonce) never satisfies the challenge.
    let resolved = from
      .as_replica()
      .and_then(|slot| self.membership.member_at(slot));
    if resolved != Some(challenge.target) {
      return; // wrong-target reply.
    }
    if m.epoch() != self.membership.epoch() || m.config_id() != self.membership.config_id() {
      return; // foreign-config reply (the freshness backstop) — never validates a mint here.
    }
    challenge.proof = Some(m.frontier());
  }

  /// Emits this learner's [`LearnerStatus`](crate::LearnerStatus) progress report when its cadence is
  /// due, then re-arms. Only a non-voting learner reports (gated by `serviceable_now` + the
  /// `handle_timeout` call site), so a voter never reaches here.
  ///
  /// `durable_commit_min` carries the CONTIGUOUS APPLIED FRONTIER (`self.commit()` == `commit_min`),
  /// NOT the durable known-committed frontier `sb.state().commit()` (the durable `commit_max`). The
  /// distinction is load-bearing for the catch-up-then-promote gate: `commit_max` is the highest op the
  /// learner KNOWS is committed, which can EXCEED its contiguous applied frontier while a missing /
  /// `Repairing` committed op BELOW it (a repair hole) still blocks apply. Reporting `commit_max` would
  /// let a SPARSE-band recovered learner — one holding the primary head yet with a hole below it — pass
  /// the gate, then enter the successor voter set unable to install the promote op until peer repair
  /// fills the hole (a non-participating voter → an avoidable view-change wedge). The applied frontier is
  /// the HONEST metric: apply is sequential and commit-first (`advance_commit` HOLDS at any hole, never
  /// skips), so EVERY op `1..=commit_min` is applied — hence durably held with a body — hence hole-free
  /// by construction; and an applied op was durably appended before it could apply (append-before-ack /
  /// the `Pending::RepairFill` durability barrier) and never pruned (`prune` frees only below
  /// `checkpoint_op <= commit_min`), so a crash recovers the learner to AT LEAST this frontier. It also
  /// cannot exceed `op_head` (an op above the head is not yet held, so cannot be applied), so it SUBSUMES
  /// the `durable_op` tail-gap cap the `on_learner_status` backstop also applies. `durable_op` stays
  /// `wal.op_head()` (the durable WAL head) for that backstop.
  fn learner_status_timeouts<W: Wal>(&mut self, now: Instant, wal: &mut W) {
    // Only a non-voting learner reports; a voter participates directly. (The call site already gates on
    // Normal; this gates on learner — together they match `serviceable_now(LearnerStatus)`.)
    if !self.is_learner() {
      self.timers.learner_status = None;
      return;
    }
    // Self-bootstrap the cadence: an idle learner has no other arm site (it never mints / proposes), so
    // arm on the first tick it is seen as a Normal learner, then emit on each subsequent due tick. This
    // is the idle-timer pattern — the learner ticks this cadence the way a backup ticks `primary_idle`.
    let Some(deadline) = self.timers.learner_status else {
      self.timers.learner_status = Some(now + LEARNER_STATUS_CADENCE);
      return;
    };
    if deadline > now {
      return;
    }
    // The contiguous applied frontier (hole-free, durably recoverable) — the honest catch-up metric the
    // promote gate needs; see the rationale on this fn. NOT the durable `commit_max`.
    let durable_commit_min = self.commit();
    let durable_op = wal.op_head();
    self.emit(Outgoing::new(
      Recipient::To(Peer::Replica(self.membership.primary(self.view))),
      Message::LearnerStatus(crate::LearnerStatus::new(
        self.local_slot(),
        durable_commit_min,
        durable_op,
        self.membership.epoch(),
        self.membership.config_id(),
      )),
    ));
    self.timers.learner_status = Some(now + LEARNER_STATUS_CADENCE);
  }

  /// Fires any timers due at `now`, dispatching by status/role.
  pub fn handle_timeout<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    match self.status {
      Status::Normal if self.is_primary() => {
        self.primary_timeouts(now, sb);
        // Pay down a SwapEpoch checkpoint debt on the heartbeat tick. A new-epoch primary that forced its
        // post-swap checkpoint and hit a TRANSIENT block-store flush fault left `config_install_op >
        // checkpoint_op` owed; while QUIESCENT (no client traffic) no commit-advance tail re-forces it, and
        // its `RequestSync` serving withholds the successor membership — so old-epoch laggards cannot cross.
        // Arming the sticky debt-pay here makes a quiescent primary SELF-HEAL: once the flush recovers it
        // re-forces the owed checkpoint and the successor-serve gate opens, with no client commit or restart
        // needed. Self-gating (no debt owed / mid-transition / a write in flight) makes this a no-op
        // otherwise, so the steady-state heartbeat is unchanged.
        self.maybe_pay_checkpoint_debt(now, sb, blocks);
        // Re-attempt a due ORDINARY checkpoint a prior commit-tail tried but whose block-store flush
        // faulted: a backup re-fires the cadence off the primary's Commit heartbeats, but a QUIESCENT
        // primary has no commit-advance tail to re-drive `maybe_checkpoint`, so without this a transient
        // flush fault would defer the checkpoint (and its WAL prune) until fresh client traffic. The cadence
        // self-gates on the boundary (`commit_min >= checkpoint_op + checkpoint_ops`) + a free superblock, so
        // it is a no-op unless a checkpoint is genuinely due, leaving the steady-state heartbeat unchanged.
        self.maybe_checkpoint(sb, blocks);
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
      Status::Recovering => self.recover_timeouts(now, wal, sb, blocks),
      Status::RecoveringHead => self.recover_head_timeouts(now, sb),
      // A Retired (removed) replica fires NO timer — it is no longer a cluster member.
      Status::Retired => {}
    }
    // Peer fault-repair retransmit runs only in Normal (the only status that can solicit/serve a hole
    // and adopt the reply). It re-solicits every unrepaired committed-op hole until each is filled.
    if self.status.is_normal() {
      self.repair_timeouts(now);
      // State-sync re-solicitation likewise runs only in Normal: re-broadcast RequestSync while a
      // sync is outstanding (awaiting a SyncCheckpoint or persisting the adopted one), re-drive the one
      // outstanding block pull of an in-progress block-fetch transfer, AND self-heal an owed local
      // flush-retry install (re-flush + re-stage locally, no donor reply needed).
      self.sync_timeouts(now, sb, blocks);
      // Learner progress report likewise runs only in Normal, and only for a non-voting learner — it
      // re-broadcasts its durable frontier so the primary's promote gate sees it catch up.
      self.learner_status_timeouts(now, wal);
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
  pub fn handle_storage<W: Wal, B: Superblock>(
    &mut self,
    now: Instant,
    wal: &mut W,
    sb: &mut B,
    blocks: &mut dyn BlockStore,
  ) {
    while let Some(done) = wal.poll() {
      self.on_wal_done(now, wal, sb, blocks, done);
    }
    while let Some(done) = sb.poll() {
      self.on_sb_done(now, wal, sb, blocks, done);
    }
    // Re-check the (status × sub-state-flag) coupling at every storage-drain exit (see
    // `assert_invariants`) — the async superblock/WAL completions are where the flag transitions land.
    #[cfg(debug_assertions)]
    self.assert_invariants();
    // The no-rewind invariant as a single typed assertion rather than N per-writer floors: when the
    // checkpoint frontier is SETTLED (no in-flight checkpoint root, no owed SM-content reconstruction), the
    // in-memory `self.checkpoint_op` EQUALS the durable `sb.state().checkpoint_op()`. The state-sync install
    // advances the pointer in lockstep with its durable root, so the durable pointer never leads the
    // in-memory one — which is why no durable-root writer can rewind the durable checkpoint (each reads
    // `self.checkpoint_op == durable`). Excluded windows: a checkpoint root in flight (both sit at the OLD
    // value until it lands); an owed reconstruction (`self.checkpoint_op` is already M while the SM catches
    // up, still consistent with the durable root that names M).
    #[cfg(debug_assertions)]
    if self.pending_checkpoint.is_none() && self.sm_reconstruct.is_none() {
      debug_assert_eq!(
        self.checkpoint_op,
        sb.state().checkpoint_op(),
        "settled in-memory checkpoint_op {} != durable {}",
        self.checkpoint_op.get(),
        sb.state().checkpoint_op().get(),
      );
    }
  }

  /// Arms the `primary_idle` deadline — but never for a non-voting learner, which has no view-change
  /// vote to cast and so never proposes a view change on an idle primary. Centralizing the arm here
  /// keeps every site that defers the idle timeout (`note_primary_contact`, the `handle_timeout`
  /// bootstrap/re-arm, the `arm_timers` Normal-backup role arm) voter-aware through one predicate — a
  /// learner AND a removed (absent) member both leave the backup idle timer disarmed.
  fn arm_primary_idle(&mut self, now: Instant) {
    if self.is_voter() {
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
    // PRESERVE an already-armed EARLIER recover-retransmit deadline across the role-timer reset, for the
    // SAME reason as `commit`/`prepare` above: `recover_retry`/`recover_head` are retransmit-cadence
    // timers whose RECOVERY makes progress ONLY when they fire (the tail/head read budget exhausts on
    // `recover_timeouts`; the re-formation escalation fires on `recover_head_timeouts`). Every inbound
    // message while Recovering/RecoveringHead ends in `arm_timers`, so re-arming to `now + interval`
    // unconditionally lets a steady sub-interval message cadence (peers soliciting each other through the
    // re-formation) slide the deadline forward forever — the read budget then never exhausts and the
    // escalation never fires, wedging recovery (a cluster-wide all-`RecoveringHead` stall never re-forms).
    // The deadline may only move EARLIER here; the forward re-arm after servicing belongs to
    // `recover_timeouts`/`send_recovery`. No stale deadline leaks across recovery generations: exiting to
    // any non-recovering status clears both (this reset, with neither arm below re-setting them).
    let prior_recover_retry = self.timers.recover_retry;
    let prior_recover_head = self.timers.recover_head;
    // PRESERVE the learner progress cadence across the role-timer reset (like `forfeit_armed`): a
    // following learner ends in `arm_timers` on every `note_primary_contact`, so re-zeroing the cadence
    // would slide it forward forever and the learner would never report. Its lifecycle is owned solely by
    // `learner_status_timeouts` (self-bootstrap / emit-and-re-arm / clear when no longer a learner), never
    // by this role re-arm.
    let learner_status = self.timers.learner_status;
    self.timers = Timers::default();
    self.timers.forfeit_armed = forfeit_armed;
    self.timers.learner_status = learner_status;
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
        if self.is_voter() {
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
        let recover_retry = now + RECOVER_READ_RETRANSMIT;
        self.timers.recover_retry =
          Some(prior_recover_retry.map_or(recover_retry, |d| d.min(recover_retry)));
      }
      // RecoveringHead: re-broadcast the `Recovery` solicitation on a cadence. A permanently-faulty
      // head cannot be repaired from local disk, so the replica solicits the canonical head from a
      // peer until a `RecoveryResponse`/`StartView` re-establishes it (then adoption arms the Normal
      // timers).
      Status::RecoveringHead => {
        let recover_head = now + RECOVER_HEAD_SOLICIT;
        self.timers.recover_head =
          Some(prior_recover_head.map_or(recover_head, |d| d.min(recover_head)));
      }
      // A Retired (removed) replica arms NO role timer — it is no longer a cluster member.
      Status::Retired => {}
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
    // The learner progress cadence (`learner_status`) is PRESERVED across this role-timer reset (it was
    // saved before `Timers::default()` and restored below), not re-armed here: its lifecycle is owned
    // solely by `learner_status_timeouts` (self-bootstrap on the first Normal-learner tick, re-arm on
    // each emit, clear when no longer a learner). Re-zeroing it here would let a learner that receives a
    // steady Prepare/Commit stream (each ending in `arm_timers` via `note_primary_contact`) perpetually
    // slide the cadence forward and never report — the same slide hazard `commit`/`prepare` avoid.
  }

  /// The single outbound-emission chokepoint. EVERY replica-originated message goes through here so the
  /// durable-view-before-participate invariant is enforced in ONE place: a view-advertising
  /// AUTHORITY / participation message (the gated set — [`Message::advertises_authoritative_view`]) must
  /// never be emitted while `self.view` lacks its durable witness (`self.view != self.durable_view`),
  /// because a crash then rolls the view back and the emission becomes a claim the recovered replica
  /// never made. The witness EQUALITY subsumes the older in-flight test ([`Self::pending_durable_view`]
  /// — a view-changing write in flight means the witness still trails the view) and additionally
  /// covers a view adopted in memory only, where no write was ever submitted and the in-flight test
  /// passes vacuously. This is the proto-side analogue of the VOPR durable-view checker, and the
  /// STRUCTURAL close of the class: a NEW emission site cannot bypass the per-site gates because it
  /// routes here. The `debug_assert!` is detection (it fails fast in every test/sim at the emission
  /// site, with zero release cost) — the per-site gates (`participates_as_primary`, the dvc gate, the
  /// `on_request_prepare` / `on_recovery` / `serve_sync_checkpoint` `pending_sb` drops) remain the
  /// PREVENTION; this assert proves they are COMPLETE. A SwapEpoch/Seal root in flight does NOT raise
  /// the fence (those roots persist the SAME view, so the witness equality holds through them): the
  /// primary keeps advertising its authoritative view AT the predecessor epoch through the swap window.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn emit(&mut self, out: Outgoing) {
    debug_assert!(
      !out.msg_ref().advertises_authoritative_view() || self.durable_view == self.view,
      "durable-view-before-participate: emitted {} for view {} whose durable witness is view {}",
      out.msg_ref().kind_str(),
      self.view,
      self.durable_view,
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
      TimerKind::LearnerStatus => self.timers.learner_status,
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
  ///   down (`!pending_forfeit`) and the view IS durable (`!pending_durable_view()`); both early-return
  ///   branches RETIRE these timers, so they are serviceable exactly on `participates_as_primary() &&
  ///   !pending_forfeit`. A commit-first SwapEpoch root does NOT retire them (the view is durable through
  ///   an epoch swap), so the primary keeps heartbeating at the predecessor epoch through the swap window.
  /// - `primary_idle`: the Normal-BACKUP branch.
  /// - `svc_message`: re-broadcast by the Normal-primary forfeit re-propose (`pending_forfeit`), by the
  ///   Normal-BACKUP idle-SVC retransmit, and by `view_change_timeouts` while not catching up.
  /// - `dvc_message`: `view_change_timeouts`, not catching up, AND the view is durable
  ///   (`!pending_durable_view()`) — the DVC is a vote, so it must not be (re)cast before the view is
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
      TimerKind::Commit | TimerKind::Prepare | TimerKind::ForfeitArmed => {
        self.participates_as_primary() && !self.pending_forfeit
      }
      // A NON-VOTER — a learner OR a REMOVED member (absent from the configuration) — never proposes or
      // escalates a view change, so the whole vote/idle timer plane (`primary_idle`, `svc_message`,
      // `dvc_message`, `view_change_status`) is non-serviceable for it; it never arms them, and this keeps
      // the no-orphan-due assert satisfied if a stale deadline ever lingered. Gated on `is_voter()`, NOT
      // `!is_learner()` (which is wrongly true for a removed member, letting it arm a consensus timer and
      // panic on a `local_slot()` that no longer exists). A learner's only view-change timer is
      // `get_view_message` (the catch-up re-solicit).
      TimerKind::PrimaryIdle => self.status.is_normal() && !self.is_primary() && self.is_voter(),
      // Three disjoint servicers (see the doc): forfeit re-propose, backup retransmit, or the
      // active view-change driver.
      TimerKind::SvcMessage => {
        self.is_voter()
          && ((self.status.is_normal() && self.is_primary() && self.pending_forfeit)
            || (self.status.is_normal() && !self.is_primary())
            || (self.status.is_view_change() && !self.catching_up()))
      }
      // The DVC retransmit is a VOTE the new primary counts toward forming the view, so it is
      // serviceable only while `self.view == self.durable_view` — the current view provably survives
      // a crash (durable-view-before-participate in the retransmit path). `enter_view_change` arms
      // `dvc_message` AND submits the SendDoViewChange durable-view write, and the INITIAL DVC is
      // sent by `on_sb_done` when that write lands (which advances the witness first); gating the
      // retransmit on the witness EQUALITY keeps a slow async superblock write from letting the
      // retransmit cast the vote early (the witness still trails the view), and — unlike the
      // in-flight test `pending_durable_view()`, which is vacuously clear on a path that never
      // submitted the write — it also refuses a vote from any posture whose view was adopted in
      // memory only. Kept in lockstep with the `view_change_timeouts` handler so the no-orphan-due
      // assert holds (an armed-and-due `dvc_message` while the view is not durable is
      // non-serviceable, so the assert ignores it and `poll_timeout` filters it out — no spin, no
      // premature vote). The other ViewChange retransmit timers stay ungated:
      // `svc_message`/`view_change_status` re-broadcast a *request-to-change* (an SVC), not a vote,
      // and `get_view_message` is a catch-up READ that (by the `catching_up` discriminant) never
      // coexists with the SendDoViewChange durable-view window.
      TimerKind::DvcMessage => {
        self.is_voter()
          && self.status.is_view_change()
          && !self.catching_up()
          && self.durable_view == self.view
      }
      TimerKind::ViewChangeStatus => self.status.is_view_change() && self.is_voter(),
      TimerKind::GetViewMessage => self.status.is_view_change() && self.catching_up(),
      TimerKind::RecoverRetry => self.status.is_recovering(),
      TimerKind::RecoverHead => self.status.is_recovering_head(),
      // `handle_timeout` runs `repair_timeouts`/`sync_timeouts` only while Normal.
      TimerKind::RepairRetry | TimerKind::SyncSolicit => self.status.is_normal(),
      // Only a non-voting learner emits a progress report, and only while Normal — `handle_timeout`
      // runs `learner_status_timeouts` under exactly this gate.
      TimerKind::LearnerStatus => self.status.is_normal() && self.is_learner(),
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

  /// Encodes the checkpoint metadata into one FRAME-BOUNDED envelope: just the bound op and the two
  /// content-addressed DAG roots.
  ///
  /// Layout: `checkpoint_op: u64 BE | sm_root: 16 BE | sessions_root: 16 BE` — a fixed 40 bytes. Neither
  /// the SM state NOR the client-session table is inline: both live in the `BlockStore` as
  /// content-addressed block DAGs, named here only by their 16-byte roots. `sm_root` is
  /// [`StateMachine::checkpoint`]'s DAG root; `sessions_root` is the proto's session-table DAG root
  /// ([`session_blocks::encode_sessions`]). A laggard fetches the blocks it is missing from BOTH DAGs
  /// over the verified `RequestBlock` path, so the envelope is ALWAYS within `MAX_FRAME_LEN` regardless
  /// of how large the table or any one cached reply grows. (Pre-0.1 there is no cross-version
  /// compatibility requirement: peers run the same build, so the layout is a plain format, not a migration.)
  ///
  /// **The leading `checkpoint_op` BINDS the op into the content hash (safety).** `checkpoint_id` is
  /// `hash(envelope)` = `fnv1a_128(checkpoint_op ++ sm_root ++ sessions_root)`. Because the two roots are
  /// themselves content hashes of the SM and session DAGs, the id binds op + SM state + session table
  /// together. A faulty/forged superblock cannot ship a STALE root (whose real frontier is op A) under an
  /// OVERSTATED advertised `checkpoint_op = B > A`: the restore paths decode this leading op and reject
  /// the checkpoint unless it equals the advertised op, closing the silent drop of committed ops in `(A, B]`.
  fn encode_checkpoint(op: OpNumber, sm_root: BlockAddress, sessions_root: BlockAddress) -> Bytes {
    let mut out = std::vec::Vec::with_capacity(8 + 16 + 16);
    out.extend_from_slice(&op.get().to_be_bytes());
    out.extend_from_slice(sm_root.as_bytes());
    out.extend_from_slice(sessions_root.as_bytes());
    Bytes::from(out)
  }

  /// Decodes a checkpoint envelope produced by [`Self::encode_checkpoint`] into
  /// `(checkpoint_op, sm_root, sessions_root)`, or `None` if the bytes are malformed/truncated.
  ///
  /// **Fallible.** A checkpoint read may return a corrupted / stale / torn snapshot (recover or
  /// state-sync over a faulty superblock), so every field access is bounds-checked and returns `None`
  /// rather than panicking. Callers treat `None` as a FAULT (recover re-reads within its budget;
  /// state-sync rejects the snapshot and re-solicits) — never a restore. The integrity of the snapshot
  /// *content* (that it is the RIGHT checkpoint) is established separately by the `checkpoint_id` hash
  /// check at each call site; this method only guarantees safe *parsing*. The session table and SM state
  /// are reconstructed SEPARATELY from `sessions_root` / `sm_root` through the verified block store.
  ///
  /// The decoded `checkpoint_op` (the leading u64) is the op BOUND into the hash: every restore path
  /// verifies it equals the advertised `cr.op()` / `m.checkpoint_op()` BEFORE restoring, so an overstated
  /// advertised op over stale-but-consistent bytes is rejected rather than silently dropping the
  /// committed ops above the snapshot's real frontier.
  fn decode_checkpoint(env: &[u8]) -> Option<(OpNumber, BlockAddress, BlockAddress)> {
    let checkpoint_op = OpNumber::with(u64::from_be_bytes(env.get(0..8)?.try_into().ok()?));
    let sm_root = BlockAddress::from_bytes(env.get(8..24)?.try_into().ok()?);
    let sessions_root = BlockAddress::from_bytes(env.get(24..40)?.try_into().ok()?);
    Some((checkpoint_op, sm_root, sessions_root))
  }

  /// Test-only: the checkpoint envelope this endpoint would encode for its CURRENT session table at `op`
  /// — its session DAG is written into `store` and named by `sessions_root`, the SM root a fixed sentinel.
  /// The byte-level determinism witness (identical tables ⇒ identical `sessions_root` ⇒ identical envelope
  /// bytes ⇒ identical checkpoint ids).
  #[cfg(test)]
  fn encode_sessions_envelope_for_test(&self, op: u64, store: &mut dyn BlockStore) -> Bytes {
    let sessions_root = session_blocks::encode_sessions(&self.clients, store);
    Self::encode_checkpoint(OpNumber::with(op), crate::block_address(&[]), sessions_root)
  }
}

#[cfg(test)]
mod tests;

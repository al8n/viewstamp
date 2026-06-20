use core::time::Duration;

use bytes::Bytes;
use smol_str::SmolStr;

use viewstamp_proto::{
  Committed, Config, DEFAULT_CHECKPOINT_OPS, Endpoint, Event, Instant, MemberId, Membership,
  MembershipChanged, Message, OpNumber, Outgoing, Peer, Prng, ProposeMembershipError, Recipient,
  Recovered, ReplicaId, SingleChange, SingleVoterDelta, Wal, prepare_restart,
};

use crate::{
  batching::{BatchingClient, BatchingConfig},
  client::ClientModel,
  clock::Clock,
  network::{Faults, InFlight, Network, SlowProfile, Target},
  sm::{BatchSm, LogSm, SimSm},
  storage::{InMemorySuperblock, InMemoryWal, StorageFaults},
};

/// Mixed into the per-replica storage-fault seed so a replica's WAL/SB fault PRNG is independent of
/// its protocol PRNG (which uses a different mixer in `with_checkpoint_ops`).
const STORAGE_SEED_MAGIC: u64 = 0x5151_DEAD_BEEF_0F0F;

/// The virtual delay applied to a message the network elects to HOLD ([`Faults::hold_per_mille`]).
/// Far past the proto's repair-or-truncate grace (5 s) so a held `PrepareOk` can outlive its op's
/// truncation + re-mint and arrive at the new primary as a STALE-body vote — the op-reuse class the
/// content-addressed vote gate defends. The event-driven clock jumps to it: a held message keeps the
/// network non-empty, so it is always eventually delivered within the tick budget.
const HOLD_DELAY: Duration = Duration::from_millis(15_000);

/// One entry of a replica's recorded apply stream ([`Cluster::replica_applied_events`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedEvent {
  /// The replica applied a committed op (the proto's [`Committed`] payload: op, client, request,
  /// reply) — one per state-machine apply, in apply order.
  Committed(Committed),
  /// The replica completed a state-sync: its state machine was REPLACED by the checkpoint snapshot
  /// bound at this op, so the apply stream REBASES — the ops folded into the snapshot are never
  /// individually re-emitted, and commits resume contiguously above the synced point. A checker must
  /// treat this as the justification for the op jump, and forward-only: the recovery peer-fetch path
  /// installs the snapshot eagerly but reports the sync only once its root is durable, so the marker
  /// can trail the first post-install commits.
  SyncPoint(OpNumber),
}

/// The outcome of a coordinated offline reconfiguration that drove the all-`RecoveringHead`
/// re-formation wedge — see [`Cluster::reconfigure_offline`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineReconfig {
  /// The common preserved view `V` every voter recovered into (and at which the wedge formed). The
  /// re-formation escalation targets `V + 1` uniformly.
  view: u64,
  /// A representative (the LOWEST) of the per-voter uncommitted head ops whose read-fault drove the
  /// voters into `RecoveringHead`. Each voter's own head is faulted (not a single fixed op), and every
  /// such head is ABOVE the committed history, so no committed op was put at risk.
  faulted_op: u64,
}

impl OfflineReconfig {
  /// The common preserved view `V` every voter recovered into and at which the wedge formed.
  pub const fn view(&self) -> u64 {
    self.view
  }

  /// A representative (the lowest) faulted voter head — the uncommitted tail op whose read-fault drove
  /// the voters into `RecoveringHead`. Above the committed history on every voter.
  pub const fn faulted_op(&self) -> u64 {
    self.faulted_op
  }
}

/// A deterministic single-thread cluster of `Endpoint<SimSm, SingleChange>` replicas + clients.
///
/// The replicas carry the [`SingleChange`] reconfiguration capability marker unconditionally. The
/// marker is a zero-sized `PhantomData<fn() -> R>` witness with NO runtime representation — every
/// runtime method (`tick`/`handle_message`/`handle_storage`/`handle_timeout`/`recover`) lives on
/// `impl<S, R: Reconfig>` and behaves identically regardless of `R`, so building every replica as
/// `SingleChange` rather than the default `RestartOnly` is byte-identical at runtime (it adds no
/// field, no branch, no allocation). It simply makes [`Endpoint::propose_membership`] reachable so the
/// cluster can drive a LIVE single-member reconfiguration; a cluster that never proposes one runs
/// exactly as a `RestartOnly` cluster would.
pub struct Cluster {
  replicas: Vec<Endpoint<SimSm, SingleChange>>,
  /// Per-replica write-ahead logs (persist across crashes; see `crash`).
  wals: Vec<InMemoryWal>,
  /// Per-replica superblocks (persist across crashes; see `crash`).
  sbs: Vec<InMemorySuperblock>,
  clients: Vec<ClientModel>,
  net: Network,
  clock: Clock,
  prng: Prng,
  /// The base seed, retained to re-derive a replica's per-replica seed on `restart`.
  seed: u64,
  faults: Faults,
  /// Seeded storage-fault plan applied to every replica's WAL + superblock (per-replica seed). The
  /// WAL/SB structs persist across crash/restart, so permanent verdicts (torn / bit-rot) and the
  /// fault PRNG survive a restart unchanged — recovery faces the same durable medium it crashed on.
  storage_faults: StorageFaults,
  /// The VOTING-replica count: the size of the set that drives every quorum and against which the
  /// fault budget is charged. Voting replicas occupy ids `0..replica_count`.
  replica_count: u8,
  /// The non-voting LEARNER count: learners follow the voting set, occupying ids
  /// `[replica_count, node_count)`. Retained so `restart`/`wipe_and_restart` rebuild a replica with
  /// the identical cluster configuration (the learner count is part of every replica's `Config`).
  learner_count: u16,
  /// The checkpoint interval, retained so `restart` rebuilds a replica with the same config.
  checkpoint_ops: u64,
  /// `None` (default) ⇒ the proto's default client-session cap. `Some(n)` ⇒ every replica's
  /// `Config::with_max_client_sessions(n)` — the small cap the churn lane uses so the deterministic
  /// apply-time eviction genuinely engages within a run's tick budget. Retained so `restart` /
  /// `wipe_and_restart` rebuild a replica with the same config (the cap is part of the cluster
  /// configuration and must be identical on every replica).
  max_client_sessions: Option<u32>,
  /// `false` (default) ⇒ every replica runs the plain [`LogSm`] (as [`SimSm::Plain`]) — no
  /// batching draw is consumed, so default per-seed schedules (and every pinned regression seed)
  /// stay byte-identical. `true` ⇒ every replica runs the batch-aware
  /// [`SimSm::Batch`], whose `apply` parses every committed body with the real batch codec. Set
  /// via [`set_batch_mode`](Self::set_batch_mode) BEFORE running; retained so
  /// `restart`/`wipe_and_restart` rebuild a replica with the same state-machine variant (the mode
  /// is cluster configuration, identical on every replica).
  batch_mode: bool,
  crashed: Vec<bool>,
  /// Per-replica RETIRED flag: `true` once this node has resolved [`Recovered::Retired`] on recover
  /// (absent from its durable membership) and is parked. A retired node stays in the vectors (so
  /// indices stay stable) but is permanently `crashed` — never ticked, polled, delivered to, or
  /// restarted (the calm-window / final-quiesce / chaos restart loops skip it). Distinct from
  /// `crashed`, which is transient; a retired node is gone for the rest of the run. No in-tree path
  /// retires a node (a removal needs an offline reconfiguration), so this stays `false` for every node;
  /// the flag + its restart-loop guards are the foundation seam a future reconfiguration would set.
  retired: Vec<bool>,
  /// Partition group id per replica. Replica↔replica messages between different groups are
  /// dropped. All replicas start in group 0 (no partition).
  groups: Vec<u8>,
  /// DIRECTED replica↔replica block matrix: `one_way[from][to]` ⇒ `from`'s messages to `to` are
  /// dropped while `to → from` still flows — the ASYMMETRIC partition shape the symmetric `groups`
  /// cannot express (e.g. a primary whose heartbeats flow OUT while the acks never arrive). All
  /// `false` by default; cleared by [`heal`](Self::heal) / [`heal_one_way`](Self::heal_one_way).
  /// The diagonal is never set (a replica always reaches itself).
  one_way: Vec<Vec<bool>>,
  /// Per-replica GRAY-FAILURE delivery profile: `Some(p)` ⇒ this replica's inter-replica messages
  /// (inbound and/or outbound per `p`) each pick up an extra seeded delay from `p`'s band — late,
  /// NOT dropped. `None` (default) ⇒ no degradation and, crucially, NO extra PRNG draw per message,
  /// so default schedules stay byte-identical (the hold-axis discipline).
  slow: Vec<Option<SlowProfile>>,
  /// Set by [`tick`](Self::tick) when a replica emitted a `PrepareOk(op)` for an op that is NOT
  /// durable in its OWN WAL+snapshot at emission time — the append-before-ack invariant, checked
  /// structurally "via the sim's storage view". Stays `None` in the absence of a violation; a checker
  /// (the VOPR driver) drains it each tick via [`take_append_before_ack_violation`].
  append_before_ack_violation: Option<SmolStr>,
  /// Set by [`tick`](Self::tick) when a replica emitted ANY view-advertising / primary-authority
  /// participation message — a `StartView`/`RecoveryResponse`, a `DoViewChange` vote, a `Prepare`, a
  /// `PrepareOk` vote, or a `Commit` — for a view that is NOT yet DURABLE on its own superblock. This
  /// is the ORACLE for the WHOLE durable-view-before-participate CLASS (the primary
  /// `StartView`/`RecoveryResponse` paths, the `DoViewChange` retransmit, the
  /// `on_request_prepare` repair `Prepare`, plus the `PrepareOk`/`Commit` participation messages),
  /// checked structurally at emission time against the sim's MONOTONE superblock view. A
  /// `StartView`/`RecoveryResponse`/`Commit`/`Prepare` asserts authority in view V; a
  /// `DoViewChange`/`PrepareOk` is a VOTE the prospective/current primary counts toward FORMING view V
  /// / committing an op in it. Emitting any of them for a `V` above the durable view means the replica
  /// participated in a view a crash could regress it out of. Stays `None` absent a violation; the VOPR
  /// driver drains it each tick via [`take_durable_view_violation`]. See
  /// [`record_durable_view_violation`](Self::record_durable_view_violation).
  durable_view_violation: Option<SmolStr>,
  /// Set by [`schedule`](Self::schedule) when a NON-VOTING learner (a `from` id `>= replica_count`)
  /// was the source of a COUNTED message — a `PrepareOk`, `StartViewChange`, or `DoViewChange`. A
  /// learner follows the committed log but must NEVER emit any of these (it is never a voter, never a
  /// prospective primary, never an active view-change participant), so this stays `None` for a correct
  /// proto; a recorded value is a REAL finding (a learner participating in consensus). Drained each
  /// tick by the VOPR driver via [`take_learner_emission_violation`]. Recorded structurally at
  /// schedule time, which sees every emitted inter-replica message with its `from` regardless of
  /// whether a fault later drops it — recording changes no scheduling and takes no PRNG draw.
  learner_emission_violation: Option<SmolStr>,
  /// `None` (default) ⇒ every replica's WAL appends SYNCHRONOUSLY (the deterministic gates' mode).
  /// `Some(d)` ⇒ async-append mode with per-append delay `d` polls — the in-flight window the
  /// append-before-ack invariant must survive. Set via [`set_async_wal_delay`] before running;
  /// persists across `crash`/`restart` because the WAL struct does.
  async_wal_delay: Option<u32>,
  /// `None` (default) ⇒ every replica's superblock writes complete SYNCHRONOUSLY (the deterministic
  /// gates' mode). `Some(d)` ⇒ async-write mode with per-write delay `d` polls — the pending
  /// durable-view window the durable-view-before-participate gate must survive. Set via
  /// [`set_async_superblock_delay`] before running; persists across `crash`/`restart` because the
  /// superblock struct does. A `crash` additionally DISCARDS any in-flight superblock write (a real
  /// crash loses an `fsync` mid-flight), so a not-yet-durable view write is genuinely lost.
  async_sb_delay: Option<u32>,
  /// `None` (default) ⇒ every replica's WAL is UNBOUNDED (`capacity() == u64::MAX`, the proto's
  /// stall-before-wrap never engages). `Some(n)` ⇒ a fixed RING of `n` slots
  /// per replica: the proto stalls op-assignment before wrapping an un-pruned slot. Set via
  /// [`set_wal_capacity`] before running; persists across `crash`/`restart` because the WAL struct does.
  /// MUST be `> checkpoint_ops + pipeline headroom` or the stall never releases (see the `Wal` capacity
  /// liveness contract).
  wal_capacity: Option<u64>,
  /// How many INTER-REPLICA messages this cluster dropped because their `encoded_len()` exceeded the
  /// transport frame cap [`MAX_FRAME_LEN`] — modelling the real transport's send-path frame guard,
  /// which refuses a peer message larger than one frame. Only `replica → replica` traffic is measured
  /// (the transport caps the peer wire; client↔replica delivery is a different path and is not
  /// dropped here, mirroring what the real transport drops). A correct header-only carrier +
  /// byte-bounded `RepairBatch` keeps EVERY legitimate peer message at/below the cap, so this stays `0`
  /// for legitimate traffic; the VOPR harness asserts exactly that while large bodies are exercised, so
  /// a regression that let a carrier overflow the frame would trip.
  oversized_dropped: u64,
  /// How many messages the network elected to HOLD ([`Faults::hold_per_mille`] fired) — delivery
  /// pushed [`HOLD_DELAY`] into the virtual future instead of `latency + jitter`. Monotone over the
  /// cluster's lifetime (the cluster struct persists across replica crash/restart, and nothing resets
  /// it), so a high-water read is exact. `0` unless a fault plan with a non-zero hold rate is
  /// installed. The VOPR hold sweep reads this as its non-vacuity witness: a held message is what lets
  /// a `PrepareOk` outlive its op's truncation + re-mint and arrive as a stale-body vote, so the sweep
  /// asserts holds genuinely fired rather than silently running the default schedule.
  holds_fired: u64,
  /// How many inter-replica messages a DIRECTED one-way block dropped (`one_way[from][to]` fired).
  /// Monotone over the cluster's lifetime, like [`Self::holds_fired`]. `0` unless one-way blocks are
  /// installed. The VOPR asym sweep reads this as its deep non-vacuity witness: episodes were not
  /// merely installed — traffic genuinely flowed one way and was cut the other.
  one_way_dropped: u64,
  /// How many inter-replica messages picked up a SLOW-replica extra delay (a [`SlowProfile`] leg
  /// fired). Monotone, like [`Self::holds_fired`]. `0` unless a slow profile is installed. The VOPR
  /// slow sweep reads this as its deep non-vacuity witness: messages were genuinely delivered LATE,
  /// not merely flagged slow.
  slow_delays_applied: u64,
  /// How many times the STALE-READ lane partitioned the CURRENT primary out (every directed leg
  /// to/from it cut, so it is both deaf and mute — the survivors stop hearing it and fail over while
  /// it sits deposed in its old view). Monotone over the cluster's lifetime, like [`Self::holds_fired`]
  /// (nothing resets it). `0` unless the stale-read lane installs an episode. The lane reads this as
  /// its non-vacuity witness: a primary was genuinely deposed, the failover the staleness floor must
  /// stay monotone through.
  stale_read_probes_fired: u64,
  /// Per-replica recorded APPLY STREAM: every `Committed` + `StateSyncCompleted` event drained from
  /// the endpoint, tagged with the replica's incarnation at emission. Filled by the per-tick event
  /// drain (and by [`crash`](Self::crash), which captures the not-yet-drained tail before the
  /// endpoint goes dark — `restart` replaces the endpoint, dropping its queue). Observation-only
  /// bookkeeping for the applied-once checker: capturing events the endpoint already produced takes
  /// no PRNG draw, sends no message, and writes no storage.
  applied_streams: Vec<Vec<(u64, AppliedEvent)>>,
  /// Per-replica recorded MEMBERSHIP-SWAP stream: every [`Event::MembershipChanged`] drained from the
  /// endpoint (one per committed `Reconfigure` op whose durable `SwapEpoch` root landed on this
  /// replica), tagged with the replica's incarnation at the swap. Filled by the per-tick event drain
  /// in [`record_applied_events`](Self::record_applied_events). Observation-only bookkeeping for the
  /// live-reconfiguration checkers (the applied-once swap oracle + the config-lineage chain): capturing
  /// an event the endpoint already produced takes no PRNG draw, sends no message, and writes no storage,
  /// so it leaves every schedule byte-identical. Empty on every run that never proposes a live
  /// reconfiguration (the default sweep + the offline-reconfig axis never emit `MembershipChanged`).
  membership_swaps: Vec<Vec<(u64, MembershipChanged)>>,
  /// Per-replica INCARNATION counter: 0 from construction, +1 per [`restart`](Self::restart) /
  /// [`wipe_and_restart`](Self::wipe_and_restart) (and per pre-run endpoint rebuild —
  /// [`set_max_client_sessions`](Self::set_max_client_sessions) /
  /// [`set_batch_mode`](Self::set_batch_mode)). An incarnation boundary is where a
  /// replica's apply stream legitimately re-emits from its durable checkpoint (recovery re-applies
  /// `(checkpoint_op .. commit_max]`; a wipe re-applies from genesis).
  incarnations: Vec<u64>,
  /// Per-replica edge-detector for the re-formation escalation: `true` if replica `i` was in
  /// `Status::RecoveringHead` at the end of the PREVIOUS [`tick`](Self::tick). Sampled each tick to
  /// count [`reform_escalations_fired`](Self::reform_escalations_fired): a node that was
  /// `RecoveringHead` and is now `ViewChange` escalated, the UNIQUE `RecoveringHead → ViewChange`
  /// transition the proto's `retire_recover_and_escalate` produces (a `RecoveringHead` node otherwise
  /// only ever leaves to `Normal` via `StartView`/`RecoveryResponse` adoption). Paired with
  /// [`was_recovering_head_inc`](Self::was_recovering_head_inc) so only a SAME-INCARNATION edge counts.
  was_recovering_head: Vec<bool>,
  /// The incarnation [`was_recovering_head`](Self::was_recovering_head) was last sampled at, per replica.
  /// A crash + restart between samples bumps the incarnation (`recover` rebuilds the endpoint), so a
  /// `RecoveringHead` observed before the crash must NOT pair with a `ViewChange` the restarted node
  /// reaches through ordinary recovery completion — that crossed a crash/restart boundary, not the
  /// proto's re-formation transition. The edge counts only when this equals the current incarnation.
  was_recovering_head_inc: Vec<u64>,
  /// High-water of the recover read-window's HELD TAIL above the durable checkpoint
  /// (`op - checkpoint_op`), sampled ONCE per recovery at recover construction in
  /// [`recover_in_place`](Self::recover_in_place). `op` is the held head the recover read loop scans and
  /// repairs (`head.min(commit_max + RECOVER_TAIL_WINDOW).max(checkpoint_op)`), fixed at construction and
  /// never raised by the loop — so this construction-time sample has no completion-edge instant to miss
  /// (the four review-round fragility this replaced). It equals the committed band
  /// (`commit_max - checkpoint_op`) when the WAL holds it — the intended large-`checkpoint_ops` case — and
  /// otherwise the committed band above the checkpoint is re-learned from PEERS only AFTER recovery, so
  /// the band is NOT what the read-window reconstructs; the held tail IS. The VOPR driver folds this as
  /// the non-vacuity witness that the large-`checkpoint_ops` axis drove the read-window over a
  /// non-trivial tail.
  recovered_band_high_water: u64,
  /// How many times a voting replica ESCALATED out of `Status::RecoveringHead` into a view change —
  /// the observable of the proto's re-formation escalation (`retire_recover_and_escalate`),
  /// counted by the `RecoveringHead → ViewChange` edge in [`tick`](Self::tick). Monotone over the
  /// cluster's lifetime. `0` unless a coordinated all-`RecoveringHead` wedge formed and re-formed (the
  /// `reconfigure_offline` axis), so the off-axis sweeps assert it stays `0` (byte-identity to a
  /// no-escalation run) while the wedge repro asserts it goes `> 0` (the escalation genuinely fired).
  reform_escalations_fired: u64,
}

impl Cluster {
  /// Creates a cluster of `replicas` replicas and `clients` clients, each client
  /// issuing `requests_per_client` requests. No faults by default.
  pub fn new(replicas: u8, clients: u32, requests_per_client: u64, seed: u64) -> Self {
    Self::with_checkpoint_ops(
      replicas,
      clients,
      requests_per_client,
      seed,
      DEFAULT_CHECKPOINT_OPS,
    )
  }

  /// Like [`Cluster::new`] but with an explicit checkpoint interval, so short runs can exercise
  /// checkpoints + checkpoint-based recovery. Builds a cluster of `replicas` VOTING replicas and no
  /// learners.
  pub fn with_checkpoint_ops(
    replicas: u8,
    clients: u32,
    requests_per_client: u64,
    seed: u64,
    checkpoint_ops: u64,
  ) -> Self {
    Self::with_members(
      replicas,
      0,
      clients,
      requests_per_client,
      seed,
      checkpoint_ops,
    )
  }

  /// Builds a cluster of `replica_count` VOTING replicas plus `learner_count` non-voting learners
  /// (the total membership, `node_count = replica_count + learner_count`), with an explicit
  /// checkpoint interval. The voting count drives every quorum and the fault budget; the node count
  /// sizes every per-replica vector, the routing target space, and the storage seeding. Each node's
  /// static [`Config`] carries its stable [`MemberId`]; the cluster SHAPE (the voting set + learners)
  /// is the shared genesis [`Membership`] every node is built with.
  pub fn with_members(
    replica_count: u8,
    learner_count: u16,
    clients: u32,
    requests_per_client: u64,
    seed: u64,
    checkpoint_ops: u64,
  ) -> Self {
    let node_count = replica_count as u16 + learner_count;
    let membership = Self::genesis_membership(replica_count, learner_count);
    let replica_set: Vec<Endpoint<SimSm, SingleChange>> = (0..node_count)
      .map(|i| {
        // `MemberId::new(i)` occupies slot `i` in the genesis membership, so every node's local slot
        // equals its old replica index — quorum/primary/voter logic is byte-identical at epoch 0.
        let cfg = Config::with_checkpoint_ops(1, MemberId::new(i as u128), checkpoint_ops)
          .expect("valid cluster config");
        // `with_reconfig` opts into the `SingleChange` capability; it constructs IDENTICAL state to the
        // `RestartOnly` `Endpoint::new` (the latter delegates here with `R = RestartOnly`), so the
        // capability marker changes no runtime byte — it only makes `propose_membership` reachable.
        Endpoint::<SimSm, SingleChange>::with_reconfig(
          cfg,
          membership.clone(),
          seed ^ (i as u64).wrapping_mul(0x1234_5678),
          SimSm::Plain(LogSm::default()),
        )
      })
      .collect();
    let client_set: Vec<ClientModel> = (0..clients)
      .map(|i| ClientModel::new((i as u128) + 1, requests_per_client, seed))
      .collect();
    let n = node_count as usize;
    let storage_faults = StorageFaults::none();
    let (wals, sbs) = Self::seed_storage(node_count, seed, storage_faults, None, None, None);
    Self {
      replicas: replica_set,
      wals,
      sbs,
      clients: client_set,
      net: Network::new(),
      clock: Clock::new(),
      prng: Prng::new(seed),
      seed,
      faults: Faults::none(),
      storage_faults,
      replica_count,
      learner_count,
      checkpoint_ops,
      max_client_sessions: None,
      batch_mode: false,
      crashed: vec![false; n],
      retired: vec![false; n],
      groups: vec![0; n],
      one_way: vec![vec![false; n]; n],
      slow: vec![None; n],
      append_before_ack_violation: None,
      durable_view_violation: None,
      learner_emission_violation: None,
      async_wal_delay: None,
      async_sb_delay: None,
      wal_capacity: None,
      oversized_dropped: 0,
      holds_fired: 0,
      one_way_dropped: 0,
      slow_delays_applied: 0,
      stale_read_probes_fired: 0,
      applied_streams: vec![Vec::new(); n],
      membership_swaps: vec![Vec::new(); n],
      incarnations: vec![0; n],
      was_recovering_head: vec![false; n],
      was_recovering_head_inc: vec![0; n],
      recovered_band_high_water: 0,
      reform_escalations_fired: 0,
    }
  }

  /// Builds the per-replica seeded WAL + superblock vectors. Each replica's storage gets a distinct
  /// seed derived from the base `seed`, its index, and [`STORAGE_SEED_MAGIC`], so fault decisions are
  /// reproducible per (seed, replica) yet independent across replicas. When `async_wal_delay` is
  /// `Some`, every WAL is built in async-append mode (the in-flight window); when `async_sb_delay` is
  /// `Some`, every superblock is built in async-write mode (the pending durable-view window) — both
  /// composed with the fault plan. When `wal_capacity` is `Some(n)`, every WAL is a fixed ring of `n`
  /// slots, composed with the fault/async modes.
  fn seed_storage(
    nodes: u16,
    seed: u64,
    faults: StorageFaults,
    async_wal_delay: Option<u32>,
    async_sb_delay: Option<u32>,
    wal_capacity: Option<u64>,
  ) -> (Vec<InMemoryWal>, Vec<InMemorySuperblock>) {
    let wals = (0..nodes)
      .map(|i| {
        let s = Self::storage_seed(seed, i);
        let mut w = match async_wal_delay {
          Some(d) => InMemoryWal::with_async_appends_and_faults(faults, s, d),
          None => InMemoryWal::with_faults(faults, s),
        };
        // Bounded ring: make this (empty) WAL a fixed ring of `n` slots, composed with the
        // fault/async mode chosen above. `None` leaves it unbounded (existing-gate behaviour).
        w.set_capacity(wal_capacity);
        w
      })
      .collect();
    let sbs = (0..nodes)
      .map(|i| {
        let s = Self::storage_seed(seed, i);
        match async_sb_delay {
          Some(d) => InMemorySuperblock::with_async_writes_and_faults(faults, s, d),
          None => InMemorySuperblock::with_faults(faults, s),
        }
      })
      .collect();
    (wals, sbs)
  }

  /// The per-replica storage-fault seed.
  fn storage_seed(seed: u64, replica: u16) -> u64 {
    seed ^ (replica as u64).wrapping_mul(STORAGE_SEED_MAGIC) ^ STORAGE_SEED_MAGIC
  }

  /// Replaces the network fault model (call before running).
  pub fn set_faults(&mut self, faults: Faults) {
    self.faults = faults;
  }

  /// Replaces the storage fault model (call before running). Re-seeds every replica's (empty) WAL +
  /// superblock with the new plan, mirroring [`Cluster::set_faults`] for the network. Permanent
  /// verdicts (torn / bit-rot) and the fault PRNG then live in the durable structs and survive a
  /// `crash` + `restart` unchanged — a restarted replica recovers from the same faulty medium.
  pub fn set_storage_faults(&mut self, faults: StorageFaults) {
    self.storage_faults = faults;
    let (wals, sbs) = Self::seed_storage(
      self.replicas.len() as u16,
      self.seed,
      faults,
      self.async_wal_delay,
      self.async_sb_delay,
      self.wal_capacity,
    );
    self.wals = wals;
    self.sbs = sbs;
  }

  /// Enables (or, with `None`, disables) **async-append mode** on every replica's WAL, with per-append
  /// delay `delay` polls. In this mode an append stays not-yet-durable (`SlotStatus::Dirty`, reads
  /// `Absent`) for `delay` polls — the in-flight window the append-before-ack invariant must survive
  /// (Phase A). Composes with the current storage-fault plan. Call before running; the mode persists
  /// across `crash`/`restart` because the WAL struct does. Rebuilds the (empty) WALs, like
  /// [`set_storage_faults`](Self::set_storage_faults).
  pub fn set_async_wal_delay(&mut self, delay: Option<u32>) {
    self.async_wal_delay = delay;
    let (wals, sbs) = Self::seed_storage(
      self.replicas.len() as u16,
      self.seed,
      self.storage_faults,
      delay,
      self.async_sb_delay,
      self.wal_capacity,
    );
    self.wals = wals;
    self.sbs = sbs;
  }

  /// Enables (or, with `None`, disables) **async-write mode** on every replica's superblock, with
  /// per-write delay `delay` polls. In this mode a durable-root or checkpoint write stays
  /// not-yet-durable (`state()` still names the prior root) for `delay` polls — the pending
  /// durable-view window the durable-view-before-participate gate must survive: a
  /// replica that just became primary has `pending_sb` armed while its view-change root write is in
  /// flight, so a delayed `GetView`/`Recovery` or a primary timer in that window must not make it act
  /// in the not-yet-durable view. Composes with the current storage-fault plan. Call before running;
  /// the mode persists across `crash`/`restart` because the superblock struct does (and a `crash`
  /// discards any in-flight write, genuinely losing a not-yet-durable view). Rebuilds the (empty)
  /// superblocks, like [`set_async_wal_delay`](Self::set_async_wal_delay).
  pub fn set_async_superblock_delay(&mut self, delay: Option<u32>) {
    self.async_sb_delay = delay;
    let (wals, sbs) = Self::seed_storage(
      self.replicas.len() as u16,
      self.seed,
      self.storage_faults,
      self.async_wal_delay,
      delay,
      self.wal_capacity,
    );
    self.wals = wals;
    self.sbs = sbs;
  }

  /// Enables (or, with `None`, disables) **bounded ring mode** on every replica's WAL: each WAL becomes
  /// a fixed RING of `n` slots, so the proto STALLS op-assignment before it would physically
  /// wrap an un-pruned slot (one not yet checkpoint-subsumed on a quorum). Composes with the current
  /// fault/async modes. Call before running; the mode persists across `crash`/`restart` because the WAL
  /// struct does. Rebuilds the (empty) WALs, like [`set_async_wal_delay`](Self::set_async_wal_delay).
  ///
  /// `n` MUST exceed `checkpoint_ops` plus pipeline headroom or the stall never releases and the
  /// primary wedges (the `Wal` capacity liveness contract). `None` restores the unbounded default.
  pub fn set_wal_capacity(&mut self, n: Option<u64>) {
    self.wal_capacity = n;
    let (wals, sbs) = Self::seed_storage(
      self.replicas.len() as u16,
      self.seed,
      self.storage_faults,
      self.async_wal_delay,
      self.async_sb_delay,
      n,
    );
    self.wals = wals;
    self.sbs = sbs;
  }

  /// The current virtual instant.
  pub fn now(&self) -> Instant {
    self.clock.now()
  }

  /// Read access to replica `i`'s state machine (for invariant checking).
  pub fn replica_sm(&self, i: usize) -> &SimSm {
    self.replicas[i].state_machine_ref()
  }

  /// Replica `i`'s recorded per-UNIT history `(op, unit_index, unit_bytes)` (for the per-unit
  /// batching oracle). Empty unless the cluster runs in batch mode.
  pub fn replica_unit_history(&self, i: usize) -> &[(u64, u32, Bytes)] {
    self.replicas[i].state_machine_ref().units()
  }

  /// Replica `i`'s recorded APPLY STREAM (for the applied-once checker): every [`Committed`] it
  /// emitted — one per state-machine apply, in apply order — plus every state-sync rebase point,
  /// each tagged with the incarnation (see [`Self::replica_incarnation`]) it was emitted in. The
  /// stream is append-only across the cluster's lifetime.
  pub fn replica_applied_events(&self, i: usize) -> &[(u64, AppliedEvent)] {
    &self.applied_streams[i]
  }

  /// Replica `i`'s recorded MEMBERSHIP-SWAP stream (for the live-reconfiguration checkers): every
  /// [`Event::MembershipChanged`] it emitted — one per committed `Reconfigure` op whose durable
  /// `SwapEpoch` root landed on this replica, in swap order — each tagged with the incarnation (see
  /// [`Self::replica_incarnation`]) it swapped in. The stream is append-only across the cluster's
  /// lifetime. Empty unless a live single-change reconfiguration was driven (the default sweep + the
  /// offline-reconfig axis never emit `MembershipChanged`).
  pub fn replica_membership_swaps(&self, i: usize) -> &[(u64, MembershipChanged)] {
    &self.membership_swaps[i]
  }

  /// The total number of live membership swaps observed across all replicas so far — the
  /// non-vacuity witness that a live single-change reconfiguration genuinely committed and installed
  /// its durable epoch swap on the cluster. `0` on every run that never proposes one.
  pub fn membership_swaps_observed(&self) -> usize {
    self.membership_swaps.iter().map(Vec::len).sum()
  }

  /// The set of committed `Reconfigure` op NUMBERS observed across all replicas' swap streams (each
  /// `MembershipChanged` names the committed op whose durable swap installed). A `Reconfigure` op is a
  /// CONSENSUS-LAYER op — committed and assigned an op number, but NOT applied to the state machine
  /// (it carries no client request) — so its op number is ABSENT from every replica's `applied()`
  /// stream, creating a legitimate gap in the applied op-number sequence. The safety contiguity check
  /// reads this to EXPECT exactly those gaps. Empty on every run that never reconfigures.
  pub fn committed_reconfigure_ops(&self) -> std::collections::BTreeSet<u64> {
    // Swap-INSTALLED reconfigure ops (from `MembershipChanged`, permanent even after the op prunes
    // below a checkpoint) UNIONED with reconfigure ops that are COMMITTED but not yet swap-installed
    // (still carried in a replica's log above its checkpoint). The second source closes the
    // commit->install window: a `Reconfigure` op advances `commit_min` (so the contiguity oracle sees
    // the applied-stream gap) the moment it commits, but its `MembershipChanged` only fires later when
    // the durable `SwapEpoch` root lands — so reading only the swap stream false-positives in between.
    let mut ops: std::collections::BTreeSet<u64> = self
      .membership_swaps
      .iter()
      .flat_map(|stream| stream.iter().map(|(_, mc)| mc.op().get()))
      .collect();
    for r in &self.replicas {
      ops.extend(r.committed_reconfigure_op_numbers());
    }
    ops
  }

  /// Whether replica `i` is currently a VOTER in its DURABLE membership (occupies a voting slot). A
  /// promoted learner reads `true` once its swap root is durable; a removed node reads `false`. Read
  /// off the superblock so it reflects the committed-and-durable configuration the node acts under.
  pub fn replica_is_voter(&self, i: usize) -> bool {
    use viewstamp_proto::Superblock;
    let state = self.sbs[i].state();
    state.membership_opt().is_some_and(|m| {
      m.slot_of(MemberId::new(i as u128))
        .is_some_and(|slot| m.is_voter(slot))
    })
  }

  /// Whether replica `i` is currently a non-voting LEARNER in its DURABLE membership. A genesis
  /// learner reads `true` until it is promoted; a voter reads `false`.
  pub fn replica_is_learner(&self, i: usize) -> bool {
    use viewstamp_proto::Superblock;
    let state = self.sbs[i].state();
    state.membership_opt().is_some_and(|m| {
      m.slot_of(MemberId::new(i as u128))
        .is_some_and(|slot| m.is_learner(slot))
    })
  }

  /// Whether replica `i` is currently a MEMBER of its DURABLE membership at all (voter or learner). A
  /// node a reconfiguration removed reads `false` (its stable id resolves to no slot). A node on a
  /// legacy (pre-membership) root reads `false` too — but a v4 cluster always carries a membership.
  pub fn replica_is_member(&self, i: usize) -> bool {
    use viewstamp_proto::Superblock;
    let state = self.sbs[i].state();
    state
      .membership_opt()
      .is_some_and(|m| m.slot_of(MemberId::new(i as u128)).is_some())
  }

  /// The number of VOTERS in replica `i`'s DURABLE membership (`replica_count`), or `None` on a
  /// legacy root. The live voting-set size the reconfiguration grows/shrinks.
  pub fn replica_voter_count(&self, i: usize) -> Option<u8> {
    use viewstamp_proto::Superblock;
    self.sbs[i]
      .state()
      .membership_opt()
      .map(|m| m.replica_count())
  }

  /// Replica `i`'s current INCARNATION (for the applied-once checker): 0 from construction, +1 on
  /// every [`restart`](Self::restart) / [`wipe_and_restart`](Self::wipe_and_restart) and every
  /// pre-run endpoint rebuild. A new
  /// incarnation's apply stream legitimately re-emits from the replica's durable checkpoint.
  pub fn replica_incarnation(&self, i: usize) -> u64 {
    self.incarnations[i]
  }

  /// Replica `i`'s current view (for invariant checking).
  pub fn replica_view(&self, i: usize) -> viewstamp_proto::View {
    self.replicas[i].view()
  }

  /// Replica `i`'s current checkpoint op (for invariant checking / boundedness gates).
  pub fn replica_checkpoint_op(&self, i: usize) -> viewstamp_proto::OpNumber {
    self.replicas[i].checkpoint_op()
  }

  /// Replica `i`'s current head op (for the M3 gate's laggard/strand-window construction).
  pub fn replica_op(&self, i: usize) -> viewstamp_proto::OpNumber {
    self.replicas[i].op()
  }

  /// Replica `i`'s current commit (`commit_min`) — the applied frontier (for the M3 gate).
  pub fn replica_commit(&self, i: usize) -> viewstamp_proto::OpNumber {
    self.replicas[i].commit()
  }

  /// Replica `i`'s `commit_max` (highest op it knows is committed cluster-wide). Used by the VOPR
  /// driver's structural ordering invariant `op >= commit_max >= commit_min >= checkpoint_op`.
  pub fn replica_commit_max(&self, i: usize) -> viewstamp_proto::OpNumber {
    self.replicas[i].commit_max()
  }

  /// True iff replica `i`'s WAL append for op `op` has COMPLETED (the slot was durably written) — or
  /// `op <= checkpoint_op` (folded into the durable snapshot). Concretely the slot is `Clean` (a
  /// durable, checksum-valid entry) OR `Faulty` (durably written, then later torn / bit-rotted: the
  /// append still COMPLETED — `WalDone::Appended` fired — and the slot stays occupied; only the
  /// *bytes* are corrupt, a separate, peer-repaired concern). A `Dirty` (still in flight) or `Empty`
  /// (never submitted) slot above the checkpoint has NOT completed its append.
  ///
  /// This is the right primitive for the append-before-ack check (the proto emits `PrepareOk` only
  /// after `Appended`, which a `Faulty` slot did fire) AND for the "a committed op stays in a quorum's
  /// durable WAL+snapshot" check (a committed slot stays occupied — `prune`/`truncate` never drop a
  /// committed slot above the checkpoint — even if its bytes later rot).
  pub fn replica_appended_op(&self, i: usize, op: OpNumber) -> bool {
    op.get() <= self.replicas[i].checkpoint_op().get()
      || matches!(
        self.wals[i].status(op),
        viewstamp_proto::SlotStatus::Clean | viewstamp_proto::SlotStatus::Faulty
      )
  }

  /// Drains the most recent append-before-ack violation observed during [`tick`](Self::tick) (a
  /// replica emitted a `PrepareOk` for an op whose WAL append had not completed — `Dirty`/`Empty`), if
  /// any. Returns `None` when no violation has occurred since the last drain. The violation is recorded
  /// structurally each tick by checking every emitted `PrepareOk` against the sender's own WAL view.
  pub fn take_append_before_ack_violation(&mut self) -> Option<SmolStr> {
    self.append_before_ack_violation.take()
  }

  /// Drains the most recent durable-view-before-participate violation observed during
  /// [`tick`](Self::tick) or [`probe_pending_view_window`](Self::probe_pending_view_window) (a replica
  /// emitted ANY view-advertising / primary-authority participation message — `StartView`,
  /// head-bearing `RecoveryResponse`, `DoViewChange`, `Prepare`, `PrepareOk`, or `Commit` — for a view
  /// above its own durable superblock view; the whole class covering all view-advertising message
  /// kinds), if any. `None` when none has occurred since the last drain.
  pub fn take_durable_view_violation(&mut self) -> Option<SmolStr> {
    self.durable_view_violation.take()
  }

  /// Drains the most recent learner-emission violation observed during [`tick`](Self::tick) (a
  /// non-voting learner emitted a `PrepareOk`/`StartViewChange`/`DoViewChange` — a counted message it
  /// must never send), if any. `None` when none has occurred since the last drain. Recorded
  /// structurally at schedule time against the emitter's id.
  pub fn take_learner_emission_violation(&mut self) -> Option<SmolStr> {
    self.learner_emission_violation.take()
  }

  /// Record a durable-view-before-participate violation if `out` (emitted by replica `ri`) advertises
  /// a view STRICTLY ABOVE replica `ri`'s own DURABLE (superblock) view — i.e. it acts authoritatively
  /// for, or votes in, a view that is not yet recoverable and which a crash could regress it out of.
  /// This is the ORACLE for the WHOLE durable-view-before-participate CLASS, flagging every
  /// VIEW-ADVERTISING / primary-authority PARTICIPATION message a
  /// replica could emit while its view write is still pending. Its flagged set EXACTLY equals the
  /// proto's gated set ([`Message::advertises_authoritative_view`]):
  ///
  /// - `StartView` — the primary's authoritative "I am the canonical primary of view V" head broadcast.
  /// - head-bearing `RecoveryResponse` (non-empty log OR `op > 0`, the PRIMARY's recovery-handshake
  ///   answer, not a backup's view-only echo) — the recovery equivalent of a `StartView`.
  /// - `DoViewChange` — a VOTE the prospective primary counts toward FORMING view V: voting
  ///   in a view not yet persisted means a crash regresses it out of a view it helped a quorum form.
  /// - `Prepare` — advertises `self.view` as authoritative. A primary's `on_request`/retransmit
  ///   `Prepare`, or a repair `Prepare` served from `on_request_prepare`, in the
  ///   not-yet-durable view advertises a view a crash could roll back.
  /// - `PrepareOk` — a backup's VOTE the primary counts toward a COMMIT quorum (carries `self.view`):
  ///   acking in a not-yet-durable view helps commit an op under a view this replica might regress out of.
  /// - `Commit` — the primary's heartbeat/commit advance (carries `self.view`): a primary-authority
  ///   broadcast in the not-yet-durable view.
  /// - `SyncCheckpoint` — the state-sync serve answering a `RequestSync`: it advertises
  ///   `self.view` as the server's authoritative view; shipping it from a not-yet-durable view
  ///   advertises a view a crash could roll back.
  ///
  /// The durable view is read off the same superblock the proto recovers from; it is MONOTONE (it only
  /// advances when a view-change/adoption write lands), so a message legitimately built while its view
  /// WAS durable never trips here (`durable_view >= msg_view` permanently), and no volatile-view stale
  /// exemption is needed — this is the durable-view analogue of the timer no-orphan-due assert, making
  /// EVERY instance of the class deterministically visible. First violation only (subsequent inert).
  fn record_durable_view_violation(&mut self, ri: usize, out: &Outgoing) {
    use viewstamp_proto::Superblock;
    if self.durable_view_violation.is_some() {
      return;
    }
    let durable_view = self.sbs[ri].state().view().get();
    let (kind, msg_view) = match out.msg_ref() {
      Message::StartView(sv) => ("StartView", sv.view().get()),
      // A primary's RecoveryResponse carries the canonical head (non-empty log or op > 0); a Normal
      // backup answers with op == 0 + empty log (view-only echo), which reports its view but not a
      // head — still a participation signal, but the head-bearing primary answer is the load-bearing
      // case the gate suppresses. Flag the head-bearing one (op > 0).
      Message::RecoveryResponse(rr) if rr.op().get() > 0 => ("RecoveryResponse", rr.view().get()),
      // A DoViewChange is a VOTE the prospective primary counts toward FORMING the new view — the
      // participation message in the retransmit path. After the durable-view gate, a replica sends
      // its DVC only once its view is persisted (the initial one from `on_sb_done`, the retransmit
      // gated on `pending_sb.is_none()`), so a DVC whose advertised view is STRICTLY ABOVE the
      // sender's durable view means it voted in a view it has not yet persisted — a crash would
      // regress it out of a view it helped a quorum form.
      Message::DoViewChange(dvc) => ("DoViewChange", dvc.view().get()),
      // A Prepare advertises `self.view` as the authoritative view of the op (a new-op broadcast /
      // retransmit from the primary, OR a committed-op repair served from `on_request_prepare`).
      // Emitting it for a view above the sender's durable view advertises a view a crash could
      // roll back — the same hazard as a StartView, on the prepare path.
      Message::Prepare(p) => ("Prepare", p.view().get()),
      Message::PrepareBatch(pb) => ("PrepareBatch", pb.view().get()),
      // A PrepareOk is a backup's VOTE the primary counts toward a COMMIT quorum (it carries
      // `self.view`). Acking in a not-yet-durable view helps commit an op under a view this replica
      // could regress out of — a vote in a view it has not persisted, the backup-side analogue of the
      // DoViewChange vote.
      Message::PrepareOk(ok) => ("PrepareOk", ok.view().get()),
      // A Commit is the primary's heartbeat / commit-advance (carries `self.view`) — a primary-
      // authority broadcast. In the not-yet-durable view it asserts this replica's primacy in a view a
      // crash could regress out of, the same hazard as a StartView/Prepare on the heartbeat path.
      Message::Commit(commit) => ("Commit", commit.view().get()),
      // A SyncCheckpoint is the state-sync serve answering a peer's RequestSync: it advertises
      // `self.view` as the serving replica's authoritative view. Shipping it from a not-yet-durable
      // view advertises a view a crash could roll back — the same participation class as the
      // StartView/RecoveryResponse/DoViewChange/Prepare/PrepareOk/Commit arms above. The checkpoint
      // content is view-independent, so the requester re-solicits and a Normal+durable peer answers.
      Message::SyncCheckpoint(sc) => ("SyncCheckpoint", sc.view().get()),
      _ => return,
    };
    if msg_view > durable_view {
      self.durable_view_violation = Some(
        format!(
          "replica {ri} emitted {kind}(view={msg_view}) while its DURABLE view is {durable_view} \
         (volatile view={}, status={}) — durable-view-before-participate violated: it \
         advertised/participated in a view not yet persisted",
          self.replicas[ri].view().get(),
          self.replicas[ri].status().as_str(),
        )
        .into(),
      );
    }
  }

  /// True iff replica `i` is the primary of its current view (for the M3 gate's failover schedule).
  pub fn replica_is_primary(&self, i: usize) -> bool {
    self.replicas[i].is_primary()
  }

  /// True iff any non-crashed replica has advanced to a view strictly greater than `v` — i.e. a real
  /// view change occurred (used by the liveness assertions, including forfeit-driven VCs).
  pub fn any_replica_view_advanced_beyond(&self, v: u64) -> bool {
    (0..self.replicas.len()).any(|i| !self.crashed[i] && self.replicas[i].view().get() > v)
  }

  /// Replica `i`'s in-memory `log` cache size (for the boundedness checker). After GC this is
  /// bounded by the un-checkpointed tail + pipeline headroom.
  pub fn replica_log_len(&self, i: usize) -> usize {
    self.replicas[i].log_len()
  }

  /// Replica `i`'s primary-pipeline (`inflight`) size (for the boundedness checker).
  pub fn replica_inflight_len(&self, i: usize) -> usize {
    self.replicas[i].inflight_len()
  }

  /// Replica `i`'s client-session table size (for the boundedness checker). Bounded by the
  /// active client set, independent of op count.
  pub fn replica_clients_len(&self, i: usize) -> usize {
    self.replicas[i].clients_len()
  }

  /// Replica `i`'s durable WAL entry count (for the boundedness checker). After GC this is
  /// bounded by the un-pruned tail.
  pub fn wal_len(&self, i: usize) -> usize {
    self.wals[i].len()
  }

  /// True iff replica `i`'s WAL PHYSICALLY holds op `op` right now — its slot is `Clean` or `Faulty`
  /// (durably written, possibly later corrupt). UNLIKE [`Self::replica_appended_op`] this does NOT fold
  /// in the `op <= checkpoint_op` snapshot-subsumption clause, so it distinguishes "still in the WAL
  /// ring" from "subsumed by the checkpoint but physically wrapped away". The bounded-WAL gate
  /// uses it to assert a committed op is PRESENT before its ring slot wraps and ABSENT after the quorum
  /// checkpoints past it and the slot is reused — at which point a laggard would state-sync.
  pub fn replica_wal_holds_op(&self, i: usize, op: OpNumber) -> bool {
    matches!(
      self.wals[i].status(op),
      viewstamp_proto::SlotStatus::Clean | viewstamp_proto::SlotStatus::Faulty
    )
  }

  /// True iff op `op`'s WAL slot has NOT been WRAPPED AWAY on replica `i` — i.e. its status is anything
  /// but `Empty` (`Clean`/`Faulty` = durably resident, `Dirty` = its OWN append still in flight). The
  /// async-robust form of [`Self::replica_wal_holds_op`] for the ring-residency checker: under
  /// async-WAL the freshest tail ops are transiently `Dirty` (in flight, not yet durable)
  /// — NOT wrapped away — so the wrap invariant must TOLERATE `Dirty` while still catching a true wrap.
  /// The bounded ring keys its entry/staged maps by OP NUMBER, so a slot whose ring index `op mod N` was
  /// REUSED by a later op `op + N` reports `Empty` for `op` (its entry evicted, and any staged entry
  /// there carries the NEW op number, not `op`), whereas a legitimate in-flight append OF `op` itself
  /// reports `Dirty` — so "status != Empty" precisely distinguishes "still this op's slot" from "the
  /// physical slot was reused by a later op" (a wrap). The proto's stall + `append_prepare` debug-assert
  /// guarantee a `Dirty` slot is never a wrap-in-progress over an un-pruned op, so tolerating `Dirty`
  /// cannot mask a real wrap.
  pub fn replica_wal_slot_not_wrapped_away(&self, i: usize, op: OpNumber) -> bool {
    !matches!(self.wals[i].status(op), viewstamp_proto::SlotStatus::Empty)
  }

  /// True iff replica `i` is participating in consensus (`Normal` or `ViewChange`) — i.e. it is NOT
  /// still recovering (`Recovering`/`RecoveringHead`). Used by the disk-fault gate to confirm a
  /// restarted replica drove its `Recovering` loop to a participating state.
  pub fn replica_status_is_operational(&self, i: usize) -> bool {
    let s = self.replicas[i].status();
    s.is_normal() || s.is_view_change()
  }

  /// Test-only: replica `i`'s status as a short string (for debugging a wedge).
  #[doc(hidden)]
  pub fn replica_status_str(&self, i: usize) -> &'static str {
    self.replicas[i].status().as_str()
  }

  /// Whether replica `i` is in `Status::RecoveringHead` — it recovered a head it cannot trust and is
  /// soliciting the canonical head from a peer, casting no vote. Used by the re-formation gate
  /// to assert a voting quorum genuinely reached the wedge (a `RecoveringHead` quorum at a common view
  /// with no `Normal` answerer) before the escalation re-forms the cluster.
  pub fn replica_status_is_recovering_head(&self, i: usize) -> bool {
    self.replicas[i].status().is_recovering_head()
  }

  /// Replica `i`'s DURABLE (superblock) view — the view persisted in its on-disk VSR root, which is
  /// what a crash + `restart` recovers it to. Unlike the volatile in-memory [`Self::replica_view`]
  /// (which a self-driven view change advances BEFORE the matching `submit_durable_view` completes,
  /// and which therefore legitimately regresses to this durable view on a restart that interrupted an
  /// not-yet-durable view change), the durable view is MONOTONE: it only advances when a view-change /
  /// adoption superblock write lands, and every binding participation (PrepareOk / DoViewChange /
  /// StartView / Prepare / Commit) is deferred until that write completes (durable-view-before-
  /// participate). So it is the correct quantity for the view-monotonicity invariant — the highest
  /// view the replica could ever have ACTED in. (Read off the same superblock the proto recovers from.)
  pub fn replica_durable_view(&self, i: usize) -> viewstamp_proto::View {
    use viewstamp_proto::Superblock;
    self.sbs[i].state().view()
  }

  /// Replica `i`'s DURABLE (superblock) configuration epoch — the high-order coordinate of the
  /// `(epoch, view)` pair, bumped per configuration epoch. A legacy (pre-membership) root reads `0`.
  /// Read off the same superblock the proto recovers from, so it is monotone across an epoch transition
  /// (a successor root is pre-written before any node recovers into it).
  pub fn replica_durable_epoch(&self, i: usize) -> viewstamp_proto::Epoch {
    use viewstamp_proto::Superblock;
    self.sbs[i].state().epoch()
  }

  /// Replica `i`'s DURABLE configuration `config_id` — the lineage hash of the active membership. A
  /// legacy (pre-membership) root reads `0`. Used by the membership-monotonicity checker to prove the
  /// configuration history is a single non-forking chain.
  pub fn replica_durable_config_id(&self, i: usize) -> u128 {
    use viewstamp_proto::Superblock;
    self.sbs[i]
      .state()
      .membership_opt()
      .map_or(0, viewstamp_proto::Membership::config_id)
  }

  /// Replica `i`'s DURABLE `prev_epoch` — the backward link of the `config_id` lineage chain (the
  /// epoch the current configuration succeeded). Equals the current epoch at genesis. Read off the
  /// superblock the proto recovers from.
  pub fn replica_durable_prev_epoch(&self, i: usize) -> viewstamp_proto::Epoch {
    use viewstamp_proto::Superblock;
    self.sbs[i].state().prev_epoch()
  }

  /// Whether replica `i`'s DURABLE root carries a membership (a v4 root). `false` for a node still on
  /// its genesis (`VsrState::new`) root that has not yet written a durable root (no checkpoint / view
  /// change since construction) — such a root is LEGACY and has no `config_id` lineage. The proto's
  /// durable-root writes produce a v4 root on the first checkpoint / view change.
  pub fn replica_has_durable_membership(&self, i: usize) -> bool {
    use viewstamp_proto::Superblock;
    self.sbs[i].state().membership_opt().is_some()
  }

  /// Read access to client `i` (for invariant checking).
  pub fn client(&self, i: usize) -> &ClientModel {
    &self.clients[i]
  }

  /// Client `i`'s acked replies STAMPED with their ack instant (for the staleness oracle):
  /// `(request, reply_body, ack_instant)` per recorded reply, in reply order. Mirrors how
  /// [`ClientModel::replies`] is surfaced via [`Self::client`], but carries the virtual instant each
  /// reply was delivered — observation-only bookkeeping, like the apply-stream capture.
  pub fn client_replies_at(&self, i: usize) -> &[(u64, Bytes, Instant)] {
    self.clients[i].replies_at()
  }

  /// Mutable access to client `i`'s batching model (`None` for a plain client) — the scripted
  /// gates' enqueue path (`enqueue_unit` / `enqueue_group`).
  pub fn client_batching_mut(&mut self, i: usize) -> Option<&mut BatchingClient> {
    self.clients[i].batching_mut()
  }

  /// Total number of replicas: voters plus learners (`replica_count + learner_count`). Every
  /// per-replica vector and the routing target space is sized by this; a per-replica iteration
  /// (draining apply streams, sizing a per-replica checker) spans it. Equals [`Self::voting_count`]
  /// when there are no learners.
  pub fn node_count(&self) -> usize {
    self.replicas.len()
  }

  /// Number of replicas, for invariant checking — the TOTAL membership (voters plus learners),
  /// because a checker sizes its per-replica state and drains every replica's apply stream. A
  /// synonym of [`Self::node_count`]; the quorum-bearing VOTING count is [`Self::voting_count`].
  pub fn replica_count(&self) -> usize {
    self.replicas.len()
  }

  /// Number of VOTING replicas: the quorum-bearing set that drives every quorum and against which
  /// the fault budget is charged. Voters occupy ids `0..voting_count`; the remaining ids
  /// (`[voting_count, node_count)`) are non-voting learners.
  pub fn voting_count(&self) -> usize {
    self.replica_count as usize
  }

  /// Number of clients.
  pub fn client_count(&self) -> usize {
    self.clients.len()
  }

  /// How many INTER-REPLICA messages were dropped because their encoded length exceeded the transport
  /// frame cap `MAX_FRAME_LEN` (the modelled send-path frame guard). `0` for legitimate traffic: the
  /// header-only view-change carriers + the byte-bounded `RepairBatch` keep every peer message
  /// at/below the cap regardless of body size. The VOPR harness reads this to assert the cap is REAL
  /// (a focused test drops a deliberately oversized message) yet NEVER fires for the protocol's own
  /// traffic even while large client bodies are exercised — the non-vacuity oracle for the header-only
  /// carriers + windowed repair.
  pub fn oversized_dropped(&self) -> u64 {
    self.oversized_dropped
  }

  /// How many messages the network has HELD so far ([`Faults::hold_per_mille`] fired: delivery pushed
  /// `HOLD_DELAY` into the virtual future). Monotone; `0` unless a fault plan with a non-zero hold
  /// rate is installed. The VOPR hold sweep asserts this fired across its seeds, so the hold lane can
  /// never silently become a no-op.
  pub fn holds_fired(&self) -> u64 {
    self.holds_fired
  }

  /// How many times a voting replica ESCALATED out of `Status::RecoveringHead` into a view change so
  /// far — the observable of the proto's re-formation escalation (`retire_recover_and_escalate`),
  /// counted by the `RecoveringHead → ViewChange` edge in [`tick`](Self::tick). Monotone. `0` on every
  /// schedule that never drove a coordinated all-`RecoveringHead` wedge (so an off-axis sweep asserts
  /// it stays `0` — byte-identity to a no-escalation run), and `> 0` once the wedge formed and
  /// re-formed (the [`reconfigure_offline`](Self::reconfigure_offline) axis), the non-vacuity witness
  /// that the escalation genuinely fired.
  pub fn reform_escalations_fired(&self) -> u64 {
    self.reform_escalations_fired
  }

  /// High-water of the recover read-window's HELD TAIL above the durable checkpoint
  /// (`op - checkpoint_op`), sampled once per recovery at recover construction — the span the read loop
  /// scans/repairs. The VOPR sweep folds it as the witness that the large-`checkpoint_ops` axis drove the
  /// read-window over a non-trivial tail (asserted well above the small-interval ceiling), not always the
  /// tiny tail the small-interval seeds yield. See the field doc for why this is sampled at construction,
  /// not at a post-operational instant.
  pub fn recovered_band_high_water(&self) -> u64 {
    self.recovered_band_high_water
  }

  /// True once all clients are done and nothing is in flight.
  pub fn is_quiescent(&self) -> bool {
    self.net.is_empty() && self.clients.iter().all(ClientModel::is_done)
  }

  /// Crash-stop replica `i`: it stops being ticked and its messages are dropped. Its durable
  /// `wals[i]`/`sbs[i]` are left intact so a later `restart` can recover from them — EXCEPT anything
  /// still in flight (async mode), which a real crash loses mid-`fsync`. We `discard_inflight` BOTH:
  ///
  /// - the superblock, so the durable root/checkpoint stay at their last-COMPLETED values. This is
  ///   what makes the pending-durable-view window a genuine crash hazard — a not-yet-durable
  ///   view write is actually lost, so the replica recovers to the OLD view (and the proto must never
  ///   have acted in the new one);
  /// - the WAL, so any STAGED (not-yet-durable) append is genuinely LOST — the faithful
  ///   fsync-loss-on-crash model. A staged append left in place would be RELEASED into the durable
  ///   log by a later `poll` AFTER recovery (a stale `Appended` carrying a superseded `OpId`),
  ///   inverting real crash semantics, where an un-`fsync`'d WAL write is lost.
  ///   Dropping it means a crash exercises the "in-flight WAL write lost" case directly: the recovered
  ///   replica's WAL head sits at most at its last DURABLE op, exactly the stale-WAL-slot class the
  ///   proto's recovery (and `truncate_wal_above_adopted_head`) must defend.
  ///
  /// In synchronous mode both are no-ops (nothing is ever staged).
  pub fn crash(&mut self, i: usize) {
    // Capture any application events still queued on the endpoint: the ops they record WERE applied
    // before the power went out, and `restart` replaces the endpoint (dropping its queue), so an
    // uncaptured tail would make an acked op applied only in that window vanish from every recorded
    // stream and falsely read as lost. Observation-only — the events are observability the protocol
    // never depends on, and the crashed endpoint is never polled again.
    self.record_applied_events(i);
    self.crashed[i] = true;
    self.sbs[i].discard_inflight();
    self.wals[i].discard_inflight();
  }

  /// Restart a previously-crashed replica: rebuild it from its durable WAL + superblock via
  /// `Endpoint::recover`. Re-derives the same per-replica config + seed used in `new`, so the
  /// recovered replica keeps its identity. Its in-memory state (log cache, SM) is reconstructed
  /// from storage; everything not yet durable is lost (as a real crash would lose it).
  ///
  /// `recover` is a metadata-only constructor that returns in `Status::Recovering` and drives its
  /// WAL-tail (+ checkpoint) reads via `handle_storage`. This does the SYNCHRONOUS recover-read drain
  /// only (`recover_in_place`), leaving a faulted replica Recovering for the CALLER to drive to a
  /// terminal status under its OWN per-tick observers — the VOPR driver's pending-view probe + phase
  /// handling + invariant suite, or a test's own checkers. The recover read retry is timer-driven, so
  /// driving the recovery INSIDE this helper would run cluster ticks that BYPASS those observers (e.g. a
  /// restart-triggered view change could open and close the short pending-durable-view window entirely
  /// unprobed); the recovery must advance in the observed main loop instead. [`Self::reconfigure_offline`]
  /// drives the post-restart wedge with its own setup tick loop.
  ///
  /// The replica restarts into its OWN durable membership and resolves itself present (at epoch 0 the
  /// genesis-fallback membership places it, and no in-tree path removes a node from a durable root), so
  /// `recover` returns `Active`. A `Retired` here — the node absent from its own durable membership — is a
  /// harness bug (a parked node must never be routed a plain restart).
  pub fn restart(&mut self, i: usize) {
    if let Some(r) = self.recover_in_place(i) {
      panic!("replica {i} recovered Retired (absent from its own durable membership): {r:?}");
    }
    self.crashed[i] = false;
  }

  /// Rebuild replica `i` from its durable WAL + superblock via `Endpoint::recover`, drive its
  /// Recovering read loop to completion, and return `None` on [`Recovered::Active`] (the rebuilt
  /// endpoint is installed) or `Some(retired)` on [`Recovered::Retired`] (a node absent from its durable
  /// membership — the old endpoint is left in place as an inert placeholder, never ticked once parked).
  /// Does NOT touch the `crashed` flag — the caller decides (a plain restart clears it on `Active`). The
  /// passed membership is only `recover`'s legacy fallback — a v4 durable root's OWN membership wins, so
  /// this resolves the node against the EFFECTIVE (durable) membership by its stable `MemberId`. A
  /// restart begins a new INCARNATION of the apply stream (recovery re-emits from the durable
  /// checkpoint), so the per-incarnation stream invariants start afresh.
  fn recover_in_place(&mut self, i: usize) -> Option<viewstamp_proto::Retired> {
    self.incarnations[i] += 1;
    let cfg = self.replica_config(i as u16);
    // The genesis-fallback membership for a legacy root (a v4 root ignores it). Sized by the CURRENT
    // voting/learner split so a same-epoch legacy bridge still resolves every node.
    let membership = Self::genesis_membership(self.replica_count, self.learner_count);
    let seed = self.seed ^ (i as u64).wrapping_mul(0x1234_5678);
    // `recover_with_reconfig` reconstructs the endpoint under the `SingleChange` marker; it runs the
    // IDENTICAL recovery path as the `RestartOnly` `Endpoint::recover` (which delegates here with
    // `R = RestartOnly`), so the marker changes no recovered byte.
    match Endpoint::<SimSm, SingleChange>::recover_with_reconfig(
      cfg,
      membership,
      seed,
      self.make_sm(),
      &mut self.wals[i],
      &mut self.sbs[i],
    ) {
      Recovered::Active(endpoint) => {
        self.replicas[i] = endpoint;
        // Drain the IMMEDIATE recover reads (synchronous in the sim). A faulted read leaves the op pending
        // and the replica Recovering; the recover-retry timer is then driven to a terminal status by the
        // CALLER — `restart` advances the shared clock for a single node, while `reconfigure_offline` ticks
        // the whole cluster so every voter recovers IN PARALLEL (aligned recover-head windows, which the
        // re-formation escalation's two-window gate needs). Driving here, per node, would stagger them.
        self.replicas[i].handle_storage(self.clock.now(), &mut self.wals[i], &mut self.sbs[i]);
        // Witness the recover read-window's HELD TAIL above the durable checkpoint, captured ONCE here at
        // construction: `op` is the held head the read loop scans/repairs, fixed at recover and never
        // raised by it (see `recovered_band_high_water`), so there is no later completion-edge instant to
        // miss. `commit_max` above the checkpoint is re-learned from peers only AFTER recovery, so the
        // held tail — not the committed band — is the faithful, edge-free witness of the read-window.
        let tail = self.replicas[i]
          .op()
          .get()
          .saturating_sub(self.replicas[i].checkpoint_op().get());
        self.recovered_band_high_water = self.recovered_band_high_water.max(tail);
        None
      }
      Recovered::Retired(r) => Some(r),
    }
  }

  /// Restart a previously-crashed replica with WIPED durable storage: its WAL + superblock are
  /// REPLACED by fresh, empty ones (same fault plan / async modes / ring capacity — a swapped disk on
  /// the same deployment), and the replica then boots the SAME path as [`restart`](Self::restart):
  /// `Endpoint::recover` over what the disk holds — here nothing, so recovery degenerates to the
  /// genesis state (view 0, no checkpoint, empty log) and completes inline to `Normal`. A real wiped
  /// node does exactly this: it cannot know it was wiped, it just recovers an empty disk.
  ///
  /// This is the classic VSR AMNESIA hazard: every promise the replica's durable state ever made
  /// (its view participation, its durable quorum copies of committed ops) is forfeited. Losing one
  /// replica's durable state is within the crash-fault model's `<= f` budget; the cluster-level
  /// invariant (committed ops survive, no divergence) must still hold, which the VOPR wipe lane's
  /// checkers judge. The caller is responsible for telling the stateful checkers about the wipe
  /// (their per-replica monotonicity baselines — durable view, checkpoint high-water — are forfeit
  /// with the disk).
  pub fn wipe_and_restart(&mut self, i: usize) {
    let s = Self::storage_seed(self.seed, i as u16);
    let mut w = match self.async_wal_delay {
      Some(d) => InMemoryWal::with_async_appends_and_faults(self.storage_faults, s, d),
      None => InMemoryWal::with_faults(self.storage_faults, s),
    };
    w.set_capacity(self.wal_capacity);
    self.wals[i] = w;
    self.sbs[i] = match self.async_sb_delay {
      Some(d) => InMemorySuperblock::with_async_writes_and_faults(self.storage_faults, s, d),
      None => InMemorySuperblock::with_faults(self.storage_faults, s),
    };
    self.restart(i);
  }

  /// Propose a LIVE single-member reconfiguration on the cluster's current serving primary: validate
  /// `delta` against the primary's configuration, mint the `Body::Reconfigure` op, and latch the
  /// single-writer in-flight change. The op then replicates + commits + swaps the epoch under the
  /// cluster's ORDINARY [`tick`](Self::tick) loop (the adversarial schedule), exactly as a client op
  /// does — this just injects the proposal; it drives nothing inline. Returns the proposed op number
  /// on success, or the proto's [`ProposeMembershipError`] (e.g. `NotPrimary` if no serving primary
  /// exists this instant, `AlreadyInFlight` if a prior change has not yet committed, or `ProofPending`
  /// for a `PromoteLearner` whose promote-time challenge is still outstanding — the proto emitted a
  /// `RequestLearnerProof` to the target and is awaiting the matching fresh `LearnerProof`; the caller
  /// re-proposes and the promote mints once the proof's frontier covers the head).
  ///
  /// Unlike [`reconfigure_offline`](Self::reconfigure_offline) (which stops the whole cluster), this
  /// keeps every node UP: it is the Tier B live-change path. The proto's commit-first epoch swap
  /// installs the successor membership only once each committing replica's durable `SwapEpoch` root
  /// lands, firing [`Event::MembershipChanged`] — which the cluster captures into
  /// [`replica_membership_swaps`](Self::replica_membership_swaps) for the live-reconfiguration
  /// checkers. `None` of the cluster's per-replica vectors are resized: a live change moves members
  /// WITHIN the genesis node set (a genesis learner promoted to voter, a voter removed), so every
  /// member that ever participates already has a running endpoint.
  pub fn propose_reconfigure_single_change(
    &mut self,
    delta: SingleVoterDelta,
  ) -> Result<OpNumber, ProposeMembershipError> {
    let now = self.clock.now();
    let Some(primary) = self.serving_primary() else {
      return Err(ProposeMembershipError::NotPrimary);
    };
    self.replicas[primary].propose_membership(now, &mut self.wals[primary], delta)
  }

  /// The serving primary's current head op (`self.op`) — the frontier a `PromoteLearner`'s target
  /// must durably cover for the proto's promote-time challenge to mint (the target's fresh
  /// `LearnerProof` frontier must reach this head). `None` if there is no serving primary this instant.
  /// The axis/test compares it against the learner's durable commit ([`Self::replica_durable_commit`])
  /// to know when a promote is worth attempting (the proto re-grounds the gate authoritatively at the
  /// proposal via the `RequestLearnerProof`/`LearnerProof` round-trip).
  pub fn primary_head(&self) -> Option<u64> {
    let primary = self.serving_primary()?;
    Some(self.replicas[primary].op().get())
  }

  /// Replica `i`'s DURABLE-root committed frontier (`sb.state().commit()`) — exactly the
  /// `durable_commit_min` a learner advertises in its [`viewstamp_proto::LearnerStatus`], so the catch-up-then-promote
  /// gate on the primary is satisfied once a learner's value here covers the primary's head AND a
  /// report has propagated. Read off the superblock the proto recovers from.
  pub fn replica_durable_commit(&self, i: usize) -> u64 {
    use viewstamp_proto::Superblock;
    self.sbs[i].state().commit().get()
  }

  /// A coordinated offline reconfiguration that DELIBERATELY drives the
  /// all-`RecoveringHead` re-formation wedge (route A: an operator-coordinated stop on a QUIESCED,
  /// all-`Normal`, partition-free cluster — the precondition the escalation's single-view convergence
  /// relies on). On success it leaves a VOTING QUORUM (in fact every voter) restarted into
  /// `Status::RecoveringHead` at a common preserved view, so only the proto's
  /// `retire_recover_and_escalate` escalation can re-form the cluster — the empirical oracle for that
  /// escalation. The steps mirror the proto's `recovering_head_post_reconfig` fixture at cluster scale:
  ///
  /// 1. **Quiesce (route A precondition):** heal every partition, drop all network faults, restart any
  ///    crashed node, and `drive_to_quiesced_normal` so every
  ///    non-crashed node is `Normal` at a COMMON view `V` with the network idle. (An offline stop is on
  ///    healthy disks, so committed data is sound throughout.) `None` if the cluster cannot quiesce
  ///    within the budget (no swap is attempted).
  /// 2. **Seal the committed frontier:** call [`seal_committed_frontier`](Endpoint::seal_committed_frontier)
  ///    on every node and AWAIT its superblock write, so each durable root carries `commit_max`. Between
  ///    checkpoints the durable commit lags the in-memory frontier; an offline-restart successor copies the durable
  ///    commit, so without this seal a coordinated restart could strand a committed op above every node's
  ///    stale durable commit. The seal makes the successor roots correct-by-construction.
  /// 3. **Uncommitted tail:** the durable frontier under load always carries an uncommitted tail
  ///    (`op > commit`); a quiesced cluster has committed everything, so re-open the window by minting
  ///    exactly one UNCOMMITTED op above the committed frontier — drive the primary to append the next
  ///    op + broadcast its `Prepare` while every backup→primary `PrepareOk` leg is cut, so each voter
  ///    durably appends the op but the commit never advances. That head op is ABOVE the cluster's
  ///    committed history, so faulting it loses no committed data (route A keeps committed data sound).
  /// 4. **Pre-write successors:** for every node build the successor durable root via
  ///    [`prepare_restart`] off its OWN durable root, KEEPING the same voting set (a no-op-membership
  ///    reconfig — it still bumps the epoch, the realistic "restart into a new epoch" case), and
  ///    [`install_root_for_test`](InMemorySuperblock::install_root_for_test) it while the node is
  ///    stopped. `prepare_restart` preserves view/log_view/commit, so every voter recovers the same
  ///    durable view `V` and targets the same `V + 1` on escalation.
  /// 5. **Head-fault wave + restart:** crash every node, inject a PERMANENT head read-fault on each
  ///    VOTER's OWN current head ([`InMemoryWal::fault_read_at`]) — sampled per voter (the in-tree
  ///    clients can append past the minted tail, so a fixed op could miss a voter's real head and leave
  ///    it `Normal`), each above the cut committed frontier — and restart all. Each voter's recovery
  ///    cannot trust its head → `RecoveringHead` at view `V`; no `Normal` node answers a `Recovery`, the
  ///    wedge. (Learners restart normally — they never escalate and never count toward the voting quorum
  ///    the gate needs.) The function then REQUIRES a voting quorum to have reached `RecoveringHead`,
  ///    returning `None` otherwise (the wedge did not form, so this must not count as a re-formation
  ///    scenario).
  ///
  /// Returns the common view `V` and a representative faulted head op, so a caller can assert the
  /// wedge formed at `V` and that re-formation converges to `V + 1`. The escalation itself is observed
  /// via [`reform_escalations_fired`](Self::reform_escalations_fired) once the cluster is ticked.
  pub fn reconfigure_offline(&mut self) -> Option<OfflineReconfig> {
    use viewstamp_proto::Superblock;
    // An all-`RecoveringHead` re-formation needs a VOTING QUORUM that can wedge with no `Normal`
    // answerer. A single-voter cluster has no such quorum, and with no backup `PrepareOk` legs to cut
    // the freeze below cannot stop the lone primary (its own append is a quorum) from committing past
    // the captured frontier — so the head-fault could hit a freshly-committed op. Fence it out.
    if self.replica_count < 2 {
      return None;
    }
    // (1) Quiesce to all-`Normal` at a common view — the route A precondition.
    self.heal();
    self.set_faults(Faults::none());
    for i in 0..self.replicas.len() {
      if self.crashed[i] && !self.retired[i] {
        self.restart(i);
      }
    }
    let view = self.drive_to_quiesced_normal(40_000)?;

    let primary = self.serving_primary()?;
    let voters: Vec<usize> = (0..self.replica_count as usize).collect();

    // Freeze the commit BEFORE sealing: cut every backup→primary PrepareOk so no op can commit while we
    // seal and mint. Clients keep APPENDING during the ticks below, but those ops stay UNCOMMITTED.
    // Without the freeze, the seal-drain ticks would commit more client ops PAST the just-sealed frontier
    // — re-creating the durable-commit lag the seal exists to remove — and the restart would lose them
    // (an op-number reuse the applied-once oracle catches).
    for x in 0..self.replicas.len() {
      if x != primary {
        self.one_way[x][primary] = true; // drop every PrepareOk back to the primary
      }
    }
    // Settle for the seal: tick until every voter shares a COMMON commit_max AND no node has any durable
    // write outstanding. The PrepareOk cut freezes the commit, so this only (a) propagates the primary's
    // commit to laggard backups (they lazily lag it, via the periodic Commit / next Prepare) and (b)
    // drains any pre-freeze checkpoint or append. Both are load-bearing: sealing a NON-uniform commit
    // would persist a committed op on only the leading node's root (the laggard-quorum truncation
    // hazard), and sealing behind in-flight durable work could revert a checkpoint or race the drain.
    let mut settled = false;
    for _ in 0..40_000 {
      self.tick();
      let commits: Vec<u64> = voters
        .iter()
        .map(|&v| self.replicas[v].commit_max().get())
        .collect();
      let uniform = commits.iter().all(|&c| c == commits[0]);
      let drained = (0..self.replicas.len())
        .all(|i| self.retired[i] || !self.replicas[i].has_inflight_storage());
      if uniform && drained {
        settled = true;
        break;
      }
    }
    if !settled {
      self.heal();
      return None;
    }
    let committed_before = voters
      .iter()
      .map(|&v| self.replicas[v].commit_max().get())
      .max()
      .unwrap_or(0);

    // (1b) Seal the committed frontier on every node BEFORE deriving the successor roots. Between
    // checkpoints `commit_max` advances only in memory — the durable root's commit lags it — and an offline-restart
    // successor copies that durable commit, so a coordinated restart can strand a committed op above
    // every node's stale durable commit. The settle above guarantees no durable work is in flight, so
    // `seal_committed_frontier` fires (returns `true`) on every node; a `false` return means something is
    // still outstanding and the seal would be unsafe, so bail.
    for i in 0..self.replicas.len() {
      if self.retired[i] {
        continue;
      }
      if !self.replicas[i].seal_committed_frontier(&mut self.sbs[i]) {
        self.heal();
        return None;
      }
    }
    // Drain the seal writes. With the PrepareOk legs cut these ticks only complete the seal roots (and
    // append uncommitted client ops) — they cannot advance the committed frontier.
    let mut sealed = false;
    for _ in 0..40_000 {
      self.tick();
      if (0..self.replicas.len())
        .all(|i| self.retired[i] || !self.replicas[i].has_inflight_storage())
      {
        sealed = true;
        break;
      }
    }
    if !sealed {
      self.heal();
      return None;
    }
    // VERIFY the seal landed: every voter's durable root commit now equals the sealed frontier. This is
    // the robust backstop — if a seal somehow raced an unrelated write, the successor would carry a
    // stale commit, so refuse rather than risk stranding a committed op across `prepare_restart`.
    for &v in &voters {
      if self.sbs[v].state().commit().get() != committed_before {
        self.heal();
        return None;
      }
    }

    // (2) Ensure every voter holds an UNCOMMITTED tail op above the frozen frontier — the head-fault
    // target. The seal drain (PrepareOks cut) may already have let clients append some; inject one more
    // to GUARANTEE a head above `committed_before` even if the clients were idle.
    let target_head = committed_before + 1;
    // A fresh client (an id past every minted one) issues a single request only the primary sees, so
    // the op is genuinely new and the in-tree client models are untouched.
    let tail_client = viewstamp_proto::ClientId::new(
      self.clients.iter().map(|c| c.id().get()).max().unwrap_or(0) + 1,
    );
    let now = self.clock.now();
    let req = Message::Request(viewstamp_proto::Request::new(
      tail_client,
      viewstamp_proto::RequestNumber::with(1),
      Bytes::from_static(b"offline-tail"),
    ));
    self.replicas[primary].handle_message(
      now,
      &mut self.wals[primary],
      &mut self.sbs[primary],
      Peer::Client(tail_client),
      req,
    );
    // Tick (PrepareOks cut) until every voter durably holds the new head op — robust to async-WAL
    // delay. The primary's commit stays at the prior frontier because no PrepareOk reaches it.
    let mut minted = false;
    for _ in 0..4_000 {
      self.tick();
      if voters
        .iter()
        .all(|&v| self.wal_head_for_test(v) >= target_head)
      {
        minted = true;
        break;
      }
    }
    self.heal(); // restore the cut legs before the stop
    if !minted {
      return None;
    }
    // Hard pre-fault check: the commit must NOT have advanced past the sealed frontier while we minted
    // (the freeze held it). If it did — a freeze that did not fully freeze for this membership — the
    // head-fault could hit a freshly-committed op the successor root never sealed; refuse rather than
    // risk a committed-op loss. (No ticks run between here and the head-fault, so this holds through it.)
    if voters
      .iter()
      .any(|&v| self.replicas[v].commit_max().get() != committed_before)
    {
      return None;
    }

    // (3) Pre-write each node's successor durable root (same voting set, bumped epoch).
    for i in 0..self.replicas.len() {
      if self.retired[i] {
        continue;
      }
      let cur = self.sbs[i].state();
      let Some(membership) = cur.membership_opt() else {
        return None; // a legacy (pre-membership) root cannot chain a successor — never on a v4 cluster
      };
      let members: Vec<MemberId> = membership.members_slice().to_vec();
      let succ = prepare_restart(
        &cur,
        membership.replica_count(),
        membership.learner_count(),
        members,
      )
      .ok()?;
      self.sbs[i].install_root_for_test(succ);
    }

    // (4) Crash every node, fault each VOTER's ACTUAL CURRENT HEAD, restart all. The voters cannot
    // trust their head on recovery → `RecoveringHead` at the common view `V`. The in-tree clients can
    // append PAST `target_head` during the mint loop, so a voter's real head can sit above it; faulting
    // a FIXED op could land on an interior (already-readable) slot and leave that voter `Normal`. Fault
    // each voter's OWN durable head instead (sampled AFTER the crash drops any in-flight WAL write, so
    // it is the head recovery will actually read) — every such head is above the cut committed frontier
    // (the commit never advanced past `committed_before` while the PrepareOk legs were cut), so no
    // committed op is ever put at risk.
    for i in 0..self.replicas.len() {
      if !self.retired[i] {
        self.crash(i);
      }
    }
    let mut faulted_heads: Vec<u64> = Vec::new();
    for &v in &voters {
      let head = self.wal_head_for_test(v);
      // The faulted head MUST be uncommitted (above the committed frontier captured after the seal
      // drain) — the mint cut every PrepareOk so the commit stayed frozen while the head climbed, so
      // `head > committed_before` always holds. Faulting a COMMITTED slot would lose a committed op.
      debug_assert!(
        head > committed_before,
        "head-fault target {head} must be above the committed frontier {committed_before}"
      );
      self.wals[v].fault_read_at(OpNumber::with(head));
      faulted_heads.push(head);
    }
    // Restart every voter (the sync recover-read drain only — `restart` no longer drives): the
    // head-faulted voters are left Recovering, then the wedge-formation loop below ticks the WHOLE cluster
    // so they reach `RecoveringHead` IN PARALLEL — aligned recover-head windows, which the re-formation
    // escalation's two-window gate needs. Driving each node to a terminal status one at a time would
    // stagger the windows and the escalation could fail to re-fire across a re-wedge.
    for i in 0..self.replicas.len() {
      if self.crashed[i] && !self.retired[i] {
        self.restart(i);
      }
    }

    // The wedge must GENUINELY form: a VOTING QUORUM has to reach `RecoveringHead`, or this is not a
    // re-formation scenario and must not count toward the axis. A head-fault that landed on an interior
    // slot (a voter whose real head climbed past the faulted op) leaves that voter `Normal`.
    //
    // A faulted-head read resolves on the recover-retry TIMER (its read budget exhausts across the
    // recover-retry cadence), NOT synchronously inside `restart`, so the voters reach `RecoveringHead`
    // only after that timer fires across the budget. Tick the SHARED clock (every replica stays on one
    // monotonic clock — no skew) until a voting quorum has wedged, stopping the INSTANT it forms: the
    // re-formation escalation needs further recover-head windows, so an immediate break leaves it
    // un-fired for the MAIN loop to drive and the oracle to observe.
    let voting_quorum = self.replica_count as usize / 2 + 1;
    let mut wedged = 0;
    for _ in 0..4_096 {
      wedged = voters
        .iter()
        .filter(|&&v| self.replica_status_is_recovering_head(v))
        .count();
      if wedged >= voting_quorum {
        break;
      }
      self.tick();
    }
    if wedged < voting_quorum {
      return None;
    }

    Some(OfflineReconfig {
      view: view.get(),
      // The representative (lowest) faulted head — every voter's faulted op is at least this, and all
      // are above the committed frontier. Reported for observability/tracing only.
      faulted_op: faulted_heads.iter().copied().min().unwrap_or(target_head),
    })
  }

  /// Drive the cluster until every non-crashed node is `Status::Normal` at a COMMON view with the
  /// network idle, returning that common view — the quiesced-stop precondition
  /// [`reconfigure_offline`](Self::reconfigure_offline) requires (route A). Assumes partitions are
  /// already healed and faults cleared (the caller does so). `None` if the cluster does not settle
  /// within `budget` ticks (a wedge or perpetual churn the caller must surface, not paper over).
  fn drive_to_quiesced_normal(&mut self, budget: u64) -> Option<viewstamp_proto::View> {
    for _ in 0..budget {
      self.tick();
      let common_view = self.common_normal_view();
      if common_view.is_some() && self.net.is_empty() {
        return common_view;
      }
    }
    None
  }

  /// The single view at which EVERY non-crashed node is `Normal`, or `None` if any non-crashed node is
  /// not `Normal` or the `Normal` nodes disagree on the view. A serving primary plus all-`Normal`
  /// backups at one view is the quiesced shape a coordinated stop preserves.
  fn common_normal_view(&self) -> Option<viewstamp_proto::View> {
    let mut view = None;
    for i in 0..self.replicas.len() {
      if self.crashed[i] {
        continue;
      }
      if !self.replicas[i].status().is_normal() {
        return None;
      }
      let v = self.replicas[i].view();
      match view {
        None => view = Some(v),
        Some(prev) if prev != v => return None,
        _ => {}
      }
    }
    view
  }

  /// Whether slot `i` is RETIRED (it resolved [`Recovered::Retired`] on recover — absent from its
  /// durable membership — and was parked). A retired node is permanently `crashed` and never restarted.
  /// No in-tree path retires a node, so this is currently always `false` (see the `retired` field).
  pub fn is_retired(&self, i: usize) -> bool {
    self.retired[i]
  }

  /// Whether replica `i` is crashed.
  pub fn is_crashed(&self, i: usize) -> bool {
    self.crashed[i]
  }

  /// The per-replica `Config` (cluster id 1, stable [`MemberId`], this cluster's checkpoint interval
  /// and — when set — its client-session cap), shared by construction-time builds and
  /// `restart`/`wipe_and_restart` so a recovered replica keeps the identical static parameters. The
  /// node at index `i` is `MemberId::new(i)`, which occupies slot `i` in [`Self::genesis_membership`]
  /// — so its local slot equals its old replica index (byte-identical at epoch 0). The cluster SHAPE
  /// (voting set + learners) is the separate genesis [`Membership`].
  fn replica_config(&self, i: u16) -> Config {
    let cfg = Config::with_checkpoint_ops(1, MemberId::new(i as u128), self.checkpoint_ops)
      .expect("valid cluster config");
    match self.max_client_sessions {
      Some(cap) => cfg
        .with_max_client_sessions(cap)
        .expect("a non-zero session cap"),
      None => cfg,
    }
  }

  /// The genesis [`Membership`] for `replica_count` voting replicas + `learner_count` learners: slot
  /// `i` is `MemberId::new(i)`, voters in `0..replica_count` and learners after. Built fresh at
  /// construction and every `restart`/`rebuild` so a recovered replica resolves to the identical
  /// slot, keeping quorum/primary/voter logic byte-identical at epoch 0.
  ///
  /// Built with a fixed `config_id = 0` (via `from_durable_parts`) so the hand-built test messages the
  /// cluster injects (which carry `config_id = 0`) pass the strict `(epoch, config_id)` ingress gate;
  /// production uses the hash-chained id.
  fn genesis_membership(replica_count: u8, learner_count: u16) -> Membership {
    let node_count = replica_count as u128 + learner_count as u128;
    Membership::from_durable_parts(
      viewstamp_proto::Epoch::new(0),
      replica_count,
      learner_count,
      (0..node_count).map(MemberId::new).collect(),
      0,
    )
    .expect("valid genesis membership")
  }

  /// Cap every replica's client-session table at `n` applied sessions (the proto's deterministic
  /// apply-time eviction then engages past it; `None` restores the proto default). Call BEFORE
  /// running: like [`Cluster::set_storage_faults`], this REBUILDS each replica's endpoint fresh with
  /// the new config (warm in-memory state would be discarded), and the retained value makes every
  /// later `restart`/`wipe_and_restart` rebuild with the same cap — the cap is cluster configuration,
  /// identical on every replica, which is what keeps the eviction replica-deterministic.
  pub fn set_max_client_sessions(&mut self, n: Option<u32>) {
    self.max_client_sessions = n;
    self.rebuild_endpoints();
  }

  /// The state machine a (re)built replica runs: the variant matching the cluster's mode.
  fn make_sm(&self) -> SimSm {
    if self.batch_mode {
      SimSm::Batch(BatchSm::default())
    } else {
      SimSm::Plain(LogSm::default())
    }
  }

  /// Rebuilds every replica's endpoint fresh with the current cluster configuration (warm
  /// in-memory state is discarded; durable storage is untouched). Each rebuilt endpoint restarts
  /// its apply stream — a new incarnation, like `restart`.
  fn rebuild_endpoints(&mut self) {
    let membership = Self::genesis_membership(self.replica_count, self.learner_count);
    for i in 0..self.replicas.len() as u16 {
      let cfg = self.replica_config(i);
      let seed = self.seed ^ (i as u64).wrapping_mul(0x1234_5678);
      self.replicas[i as usize] = Endpoint::<SimSm, SingleChange>::with_reconfig(
        cfg,
        membership.clone(),
        seed,
        self.make_sm(),
      );
      self.incarnations[i as usize] += 1;
    }
  }

  /// Switch every replica to the batch-aware state machine (`true`) or back to the plain default
  /// (`false`). Call BEFORE running, like [`Cluster::set_max_client_sessions`]: this REBUILDS each
  /// replica's endpoint fresh with the chosen variant, and the retained flag makes every later
  /// `restart`/`wipe_and_restart` rebuild with the same one — the SM variant is cluster
  /// configuration, identical on every replica. In batch mode EVERY committed body must be
  /// codec-built (the batching client model, or the plain clients' single-unit wrap): `BatchSm`
  /// panics loudly on a non-batch body, because a malformed body in the sim is a bug.
  pub fn set_batch_mode(&mut self, on: bool) {
    self.batch_mode = on;
    self.rebuild_endpoints();
  }

  /// Turn client `i` into a BATCHING client driving the aggregator model (call before running;
  /// see [`ClientModel::enable_batching`]). The cluster must be in batch mode, or its replicas
  /// will panic on the first packed body.
  pub fn enable_client_batching(&mut self, i: usize, cfg: BatchingConfig) {
    self.clients[i].enable_batching(cfg);
  }

  /// Wrap client `i`'s plain bodies as single-unit batches (call before running; see
  /// [`ClientModel::wrap_bodies_as_single_unit_batches`]) so a batch-mode cluster can carry a
  /// plain client's traffic.
  pub fn wrap_client_bodies(&mut self, i: usize) {
    self.clients[i].wrap_bodies_as_single_unit_batches();
  }

  /// RETIRE client `i`: it permanently stops issuing/retransmitting and counts as done for the
  /// liveness checks (see [`ClientModel::retire`]). Its session rows on the replicas go idle and age
  /// toward the deterministic cap eviction.
  pub fn retire_client(&mut self, i: usize) {
    self.clients[i].retire();
  }

  /// Spawn a FRESH client (a never-before-seen `ClientId` — one past the highest id ever minted)
  /// issuing `requests` requests, returning its index. The churn lane pairs this with
  /// [`Cluster::retire_client`] so the ACTIVE client count stays level while distinct client ids
  /// accumulate over the run — the population pressure that drives the session-cap eviction.
  pub fn spawn_client(&mut self, requests: u64) -> usize {
    let next_id = self.clients.iter().map(|c| c.id().get()).max().unwrap_or(0) + 1;
    let mut client = ClientModel::new(next_id, requests, self.seed);
    // A batch-mode cluster parses every committed body with the batch codec, so a freshly-spawned
    // plain client must ride the single-unit wrap (the churn axis composing with batch mode).
    if self.batch_mode {
      client.wrap_bodies_as_single_unit_batches();
    }
    self.clients.push(client);
    self.clients.len() - 1
  }

  #[doc(hidden)]
  pub fn wal_head_for_test(&self, i: usize) -> u64 {
    self.wals[i].op_head().get()
  }

  /// Test-only: the number of staged (not-yet-durable) superblock writes on replica `i` — `> 0` iff
  /// the async-write superblock has an in-flight write open RIGHT NOW (the pending durable-view /
  /// checkpoint window). The async-superblock harness uses this to confirm the window is genuinely
  /// exercised (a primary sits with `pending_sb` armed while a view-change root write is in flight).
  #[doc(hidden)]
  pub fn sb_staged_len_for_test(&self, i: usize) -> usize {
    self.sbs[i].staged_len()
  }

  /// Test-only: whether replica `i` is a `Normal` primary whose current view is NOT yet durable —
  /// i.e. its volatile in-memory view is strictly ahead of its durable (superblock) view while it is
  /// the primary of that volatile view. This is EXACTLY the pending-durable-view window from the
  /// proto's side (`pending_sb` armed for a `StartViewAsPrimary` write). Lets the async-superblock
  /// harness confirm a seed actually opens the window (rather than merely staging unrelated writes).
  #[doc(hidden)]
  pub fn in_pending_primary_view_window_for_test(&self, i: usize) -> bool {
    use viewstamp_proto::Superblock;
    let r = &self.replicas[i];
    let durable_view = self.sbs[i].state().view().get();
    r.status().is_normal() && r.is_primary() && r.view().get() > durable_view
  }

  /// Adversarially PROBE the pending-durable-view window: for every non-crashed
  /// replica that is a `Normal` primary whose view is NOT yet durable (a `StartViewAsPrimary` root
  /// write still in flight), deliver — RIGHT NOW, in this window — a `GetView` AND a `Recovery` from a
  /// peer, plus fire its timers. A correct primary must answer NEITHER (no `StartView` for the
  /// not-yet-durable view, no `RecoveryResponse` with its canonical head, no `Commit`/`Prepare`
  /// heartbeat) until the view is durable; the durability/view-monotonic checkers then catch any
  /// resulting cross-view double-participation. Returns the number of replicas probed in their window,
  /// so the sweep can assert the window is genuinely EXERCISED (not merely opened). The window is
  /// short, so relying on incidental message/timer coincidence misses it — this makes the probe
  /// deterministic. Faithful: a delayed/duplicate `GetView`/`Recovery` and a primary timer firing in
  /// that window are exactly the real events the gate must survive.
  pub fn probe_pending_view_window(&mut self) -> u64 {
    let now = self.clock.now();
    let mut probed = 0u64;
    for i in 0..self.replicas.len() {
      if self.crashed[i] || !self.in_pending_primary_view_window_for_test(i) {
        continue;
      }
      probed += 1;
      // A peer (the next replica id) solicits — both a head (GetView) and a recovery handshake.
      let peer = viewstamp_proto::ReplicaId::new(((i + 1) % self.replicas.len()) as u16);
      let from = Peer::Replica(peer);
      let view = self.replicas[i].view();
      let gv = Message::GetView(viewstamp_proto::GetView::new(
        view,
        peer,
        0xF1_u64,
        viewstamp_proto::Epoch::new(0),
        0,
      ));
      self.replicas[i].handle_message(now, &mut self.wals[i], &mut self.sbs[i], from, gv);
      let rec = Message::Recovery(viewstamp_proto::Recovery::new(
        peer,
        0xF2_u64,
        viewstamp_proto::Epoch::new(0),
        0,
      ));
      self.replicas[i].handle_message(now, &mut self.wals[i], &mut self.sbs[i], from, rec);
      // Fire the primary timers too (the `primary_timeouts` heartbeat/retransmit gate).
      self.replicas[i].handle_timeout(now, &mut self.wals[i], &mut self.sbs[i]);
      // Inspect EVERYTHING the probe made the replica emit: a correct (gated) primary emits no
      // StartView/RecoveryResponse for its not-yet-durable view; an ungated one does → durable-view
      // violation. Drain the queue (re-enqueuing for normal routing) and check each message.
      let mut drained = std::vec::Vec::new();
      while let Some(out) = self.replicas[i].poll_message() {
        self.record_durable_view_violation(i, &out);
        drained.push(out);
      }
      for out in drained {
        self.route(now, ReplicaId::new(i as u16), out);
      }
    }
    probed
  }

  /// Test-only: how many state-syncs have fully applied + become durable on replica `i` since
  /// it was last constructed (`new`/`restart`). The state-sync gate asserts the restarted laggard's
  /// count goes from 0 to `>= 1` — proving it genuinely STATE-SYNCED (fetched + restored a checkpoint
  /// past its head) rather than merely catching up op-by-op via retransmit. Mirrors the proto's
  /// `Endpoint::state_syncs_applied` observability counter.
  #[doc(hidden)]
  pub fn replica_state_sync_count(&self, i: usize) -> u64 {
    self.replicas[i].state_syncs_applied()
  }

  /// Test-only: how many of replica `i`'s applied syncs were FORCED (the escalation that
  /// recovers a pruned committed hole below the quorum checkpoint), as opposed to ordinary `> self.op`
  /// state-syncs. The focused force-sync gate asserts this goes `> 0` to prove the FORCED path fired
  /// specifically. Mirrors the proto's `Endpoint::forced_syncs_applied`.
  #[doc(hidden)]
  pub fn replica_forced_sync_count(&self, i: usize) -> u64 {
    self.replicas[i].forced_syncs_applied()
  }

  /// Test-only: how many client requests replica `i` DROPPED at op-assignment because the next
  /// op would overflow its bounded WAL ring (the physical stall-before-wrap). `0` for an unbounded WAL.
  /// The bounded-WAL gate asserts this goes `> 0` to prove the stall genuinely engaged (non-vacuity).
  /// Mirrors the proto's `Endpoint::wal_stalls`.
  #[doc(hidden)]
  pub fn replica_wal_stalls(&self, i: usize) -> u64 {
    self.replicas[i].wal_stalls()
  }

  /// Test-only: how many times replica `i` (a backup) fell BELOW its bounded-WAL ring
  /// window on a head-extending `Prepare` and STATE-SYNCED to the cluster checkpoint instead of
  /// overwriting an un-pruned slot. `0` for an unbounded WAL or an in-quorum backup. The bounded-WAL
  /// gate asserts the SUM across replicas goes `> 0` to prove the connected backup-overflow path
  /// genuinely fired (distinct from the ordinary `> self.op` state-sync trigger). Mirrors the proto's
  /// `Endpoint::below_ring_window_syncs`.
  #[doc(hidden)]
  pub fn replica_below_ring_window_syncs(&self, i: usize) -> u64 {
    self.replicas[i].below_ring_window_syncs()
  }

  /// Test-only: how many CHUNKED checkpoint transfers replica `i` completed (an announced
  /// over-frame checkpoint pulled chunk-by-chunk, assembled, and verified against the pinned content
  /// id). The large-snapshot gate asserts this goes `>= 1` to prove the CHUNKED path genuinely
  /// carried the sync (vs the single-frame fast path); the VOPR sweep folds it reset-robustly.
  /// Mirrors the proto's `Endpoint::sync_chunk_transfers_completed`.
  #[doc(hidden)]
  pub fn replica_sync_chunk_transfers_completed(&self, i: usize) -> u64 {
    self.replicas[i].sync_chunk_transfers_completed()
  }

  /// Test-only: the donor replica `i`'s chunked transfer is currently pinned to, or `None` when no
  /// chunked pull is in progress. The donor-crash gate variant uses this to crash the LIVE donor
  /// deterministically mid-transfer (forcing the failover re-pin). Mirrors the proto's
  /// `Endpoint::sync_transfer_donor`.
  #[doc(hidden)]
  pub fn replica_sync_transfer_donor(&self, i: usize) -> Option<u16> {
    self.replicas[i].sync_transfer_donor()
  }

  /// Test-only: the byte length of replica `i`'s LIVE ROOTED checkpoint envelope (exactly the bytes
  /// a state-sync serve would carry), or `None` when no checkpoint has been rooted. The
  /// large-snapshot gate compares this against `max_unchunked_snapshot_len()` to assert the
  /// would-have-wedged precondition (an envelope only the chunked path can deliver).
  #[doc(hidden)]
  pub fn replica_durable_envelope_len(&self, i: usize) -> Option<usize> {
    self.sbs[i].live_checkpoint_len()
  }

  /// Make EVERY client request carry exactly `len` body bytes (replacing the seeded small/large
  /// mix). Call before running. The large-snapshot state-sync gate uses this to push the cluster's
  /// checkpoint envelope past the one-frame threshold within a short run.
  pub fn set_fixed_client_body_len(&mut self, len: usize) {
    for c in &mut self.clients {
      c.set_fixed_body_len(len);
    }
  }

  /// Test-only: how many canonical-log selections on replica `i` actually FLOORED the union
  /// (`select_canonical_log` dropped at least one canonical-donor entry at/below the vouched
  /// checkpoint floor). The VOPR sweep folds this (reset-robustly, the counter zeroes on `recover`)
  /// to prove the floored-union path genuinely fired. Mirrors the proto's `Endpoint::unions_floored`.
  #[doc(hidden)]
  pub fn replica_unions_floored(&self, i: usize) -> u64 {
    self.replicas[i].unions_floored()
  }

  /// Test-only: how many client sessions replica `i` EVICTED at apply time (the deterministic
  /// session-cap eviction). The churn lane folds this (reset-robustly, the counter zeroes on
  /// `recover`) as its non-vacuity witness — the cap genuinely engaged under client churn. Mirrors
  /// the proto's `Endpoint::sessions_evicted`.
  #[doc(hidden)]
  pub fn replica_sessions_evicted(&self, i: usize) -> u64 {
    self.replicas[i].sessions_evicted()
  }

  /// Test-only: how many NON-EMPTY `RepairBatch`es replica `i` served answering peers'
  /// `RequestPrepareRange`s — the windowed bulk-repair channel genuinely shipping bodies. The VOPR
  /// sweep folds this (reset-robustly) to prove the byte-bounded repair-serve path fired. Mirrors the
  /// proto's `Endpoint::repair_batches_served`.
  #[doc(hidden)]
  pub fn replica_repair_batches_served(&self, i: usize) -> u64 {
    self.replicas[i].repair_batches_served()
  }

  /// Test/observability accessor: this replica's emitted prepare-batch count, mirroring the
  /// proto's `Endpoint::prepare_batches_sent`.
  #[doc(hidden)]
  pub fn replica_prepare_batches_sent(&self, i: usize) -> u64 {
    self.replicas[i].prepare_batches_sent()
  }

  /// Test-only: how many header-only carrier slices replica `i` built (`log_entries` — the single
  /// chokepoint every `DoViewChange`/`StartView`/`RecoveryResponse` log payload flows through). The
  /// VOPR sweep folds this (reset-robustly) to prove the header-only carrier path fired. Mirrors the
  /// proto's `Endpoint::header_only_carriers_emitted`.
  #[doc(hidden)]
  pub fn replica_header_only_carriers_emitted(&self, i: usize) -> u64 {
    self.replicas[i].header_only_carriers_emitted()
  }

  /// Test-only: how many of replica `i`'s WAL slots in `1..=op` are PERMANENTLY corrupt (bit-rot or
  /// torn) — i.e. would read back faulty. The permanent-fault gate uses this to assert recovery is
  /// non-vacuous (the crashed replica genuinely must peer-repair some rotted committed slot).
  #[doc(hidden)]
  pub fn wal_corrupt_slots_at_or_below_for_test(&self, i: usize, op: u64) -> usize {
    self.wals[i].corrupt_slots_at_or_below_for_test(op)
  }

  /// Test-only: how many reads replica `i`'s WAL has MISDIRECTED (returned a wrong-op valid sibling)
  /// since it was last constructed. The VOPR sweep sums this across replicas to assert the
  /// misdirected-read axis genuinely fired (so the proto's recovery placement check was exercised).
  #[doc(hidden)]
  pub fn wal_misdirects_fired(&self, i: usize) -> u64 {
    self.wals[i].misdirects_fired()
  }

  /// Test-only: how many of replica `i`'s completed WAL appends LOST their header (the torn-header
  /// contract-violation verdict). The torn-header probe lane sums this across replicas as its
  /// non-vacuity witness.
  #[doc(hidden)]
  pub fn wal_torn_headers_fired(&self, i: usize) -> u64 {
    self.wals[i].torn_headers_fired()
  }

  /// Partition the replicas into groups: `groups[i]` is replica `i`'s group id. Replica↔replica
  /// messages between different groups are dropped until `heal`. (Client↔replica traffic is unaffected.)
  pub fn partition(&mut self, groups: Vec<u8>) {
    assert_eq!(
      groups.len(),
      self.replicas.len(),
      "one group id per replica"
    );
    self.groups = groups;
  }

  /// Heal all partitions: a single symmetric group AND no one-way blocks. Full bidirectional
  /// connectivity — what a calm window / final quiesce requires.
  pub fn heal(&mut self) {
    self.groups = vec![0; self.replicas.len()];
    self.heal_one_way();
  }

  /// Heal only the DIRECTED one-way blocks, leaving any symmetric group partition in place (the
  /// asym action's own heal branch; [`heal`](Self::heal) clears both).
  pub fn heal_one_way(&mut self) {
    for row in &mut self.one_way {
      row.fill(false);
    }
  }

  /// Install a DIRECTED block: `from`'s messages to `to` are dropped until healed, while `to → from`
  /// still flows. The asymmetric analogue of [`partition`](Self::partition). Ids are member ids
  /// (`0..node_count`), so they are `u16` — a high id cannot truncate into a low one's row/column.
  pub fn block_one_way(&mut self, from: u16, to: u16) {
    assert_ne!(from, to, "a replica always reaches itself");
    self.one_way[usize::from(from)][usize::from(to)] = true;
  }

  /// Whether `from`'s messages to `to` are currently blocked by a DIRECTED one-way block (the
  /// asymmetric check; independent of the symmetric [`partitioned`](Self::partitioned)).
  pub fn one_way_blocked(&self, from: u16, to: u16) -> bool {
    self.one_way[usize::from(from)][usize::from(to)]
  }

  /// How many inter-replica messages a directed one-way block has dropped so far. Monotone; `0`
  /// unless one-way blocks are installed. The asym sweep's deep non-vacuity witness.
  pub fn one_way_dropped(&self) -> u64 {
    self.one_way_dropped
  }

  /// Install (or with `None`, clear) replica `i`'s GRAY-FAILURE delivery profile: its inter-replica
  /// messages (the legs `profile` selects) each pick up an extra seeded delay from the profile's
  /// band — late, never dropped. With no profile installed no per-message PRNG draw is taken, so
  /// default schedules stay byte-identical.
  pub fn set_slow_replica(&mut self, i: usize, profile: Option<SlowProfile>) {
    self.slow[i] = profile;
  }

  /// Clear every replica's slow profile (full prompt delivery — calm-window connectivity).
  pub fn clear_slow_replicas(&mut self) {
    self.slow.fill(None);
  }

  /// How many inter-replica messages have picked up a slow-replica extra delay so far. Monotone;
  /// `0` unless a slow profile is installed. The slow sweep's deep non-vacuity witness.
  pub fn slow_delays_applied(&self) -> u64 {
    self.slow_delays_applied
  }

  /// The cluster's SERVING primary: the non-crashed replica that is `Normal` AND `is_primary` with
  /// the HIGHEST view. A deposed old-view primary stays `Normal` + `is_primary` in its stale view
  /// until it learns a higher one, so a status predicate alone would count it as primary; the
  /// serving primary is the highest-view such replica — the one whose writes would actually commit.
  /// `None` during an election window (no normal primary yet).
  pub fn serving_primary(&self) -> Option<usize> {
    (0..self.replicas.len())
      .filter(|&i| {
        !self.crashed[i] && self.replicas[i].status().is_normal() && self.replicas[i].is_primary()
      })
      .max_by_key(|&i| self.replicas[i].view().get())
  }

  /// Cut every directed inter-replica leg to AND from `target` — deaf (its peers' acks/votes never
  /// arrive) and mute (its heartbeats/prepares never reach the survivors, whose idle view-change
  /// timers then fire and elect a new primary while the deposed one sits in its old view). A no-op
  /// returning `false` unless `target` is currently [`serving_primary`](Self::serving_primary)
  /// (never reselects, never counts a deposed old-view primary); on a genuine cut it advances
  /// [`stale_read_probes_fired`](Self::stale_read_probes_fired) and returns `true`. The directed
  /// blocks heal like any one-way episode ([`heal`](Self::heal) / [`heal_one_way`](Self::heal_one_way)),
  /// so the stale-read lane composes with the standard heal/calm machinery.
  pub fn partition_primary_out(&mut self, target: usize) -> bool {
    // Cut EXACTLY the caller's chosen replica, and ONLY if it is the cluster's SERVING primary —
    // never reselect, never count a deposed old-view primary that still believes itself primary.
    // A reselection or a status-agnostic predicate could cut (and bump the witness for) a replica
    // that is not the active primary, leaving the intended one unpartitioned and the failover
    // unforced — a false non-vacuity signal. A non-serving-primary target is a no-op (the witness
    // counts only genuine deposals of the serving primary, each of which forces a real failover).
    if self.serving_primary() != Some(target) {
      return false;
    }
    for x in 0..self.replicas.len() {
      if x != target {
        // Deaf: peer -> primary cut. Mute: primary -> peer cut.
        self.one_way[x][target] = true;
        self.one_way[target][x] = true;
      }
    }
    self.stale_read_probes_fired += 1;
    true
  }

  /// How many times the stale-read lane partitioned the current primary out so far. Monotone; `0`
  /// unless the lane installs an episode. The lane's non-vacuity witness (a primary was genuinely
  /// deposed and the cluster forced to fail over).
  pub fn stale_read_probes_fired(&self) -> u64 {
    self.stale_read_probes_fired
  }

  /// Whether replica↔replica traffic between replicas `a` and `b` is currently partitioned. Ids are
  /// member ids (`0..node_count`), so they are `u16` — a high id indexes its own group slot.
  pub fn partitioned(&self, a: u16, b: u16) -> bool {
    self.groups[usize::from(a)] != self.groups[usize::from(b)]
  }

  /// One simulation step.
  pub fn tick(&mut self) {
    let now = self.clock.now();

    for ci in 0..self.clients.len() {
      if let Some(req) = self.clients[ci].pending(now) {
        let from = Peer::Client(self.clients[ci].id());
        for ri in 0..self.replicas.len() {
          if !self.crashed[ri] {
            self.schedule(
              now,
              from,
              Target::Replica(ri as u16),
              Message::Request(req.clone()),
            );
          }
        }
      }
    }

    // Collect outgoing messages from each replica first, then route — avoids a
    // simultaneous &mut self.replicas[ri] + &mut self borrow conflict in route().
    let mut outgoing: Vec<(ReplicaId, Outgoing)> = Vec::new();
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      while let Some(out) = self.replicas[ri].poll_message() {
        // Append-before-ack, checked structurally at the moment of emission: a replica must never
        // emit a `PrepareOk(op)` whose WAL append has not COMPLETED on its own disk (the slot is
        // `Dirty`/in-flight or `Empty`/never-submitted, AND the op is above the durable checkpoint).
        // The proto defers the ack to the `WalDone::Appended` completion; a `Faulty` slot (durably
        // written, then later rotted) still fired `Appended`, so acking it is legitimate — this only
        // flags an ack of a genuinely-incomplete append. Record-only — a checker drains it; existing
        // gates ignore it.
        //
        // STALE-VIEW EXEMPTION: the invariant binds AT THE ACK'S VIEW. A
        // `PrepareOk(op, view = V)` is built + queued by the proto in view V, where `op` IS durably
        // appended; the sim drains `outgoing` only on the NEXT tick, and a view-change-to-`V+1` that
        // ran in between (truncating the uncommitted tail above the new canonical head) can empty that
        // slot before we observe the message. Re-checking such a stale ack against the replica's NOW
        // (post-truncation) WAL is stricter than VSR truly requires: the message carries `view = V`,
        // and the proto's `on_prepare_ok` DROPS any ack whose `view != self.view` (and routes a
        // higher-view ack to catch-up, never a vote), so a `PrepareOk(view < current)` can never be
        // counted toward a commit quorum — it is inert. Skip it when `msg_view < cur_view` (a
        // legitimately-superseded prior-view ack), exactly the recurring checker lesson: a per-tick proxy
        // can over-fire on a message the proto itself neutralizes — fix the checker, never the proto. A
        // `msg_view >= cur_view` non-durable ack (current view, or the impossible-but-flagged future)
        // is still a real append-before-ack violation and trips.
        if let Message::PrepareOk(ok) = out.msg_ref() {
          let op = ok.op();
          let msg_view = ok.view().get();
          let cur_view = self.replicas[ri].view().get();
          if op.get() > 0
            && msg_view >= cur_view
            && !self.replica_appended_op(ri, op)
            && self.append_before_ack_violation.is_none()
          {
            let r = &self.replicas[ri];
            self.append_before_ack_violation = Some(format!(
              "replica {ri} emitted PrepareOk(op={}, msg_view={}) but its WAL append has not completed \
               (wal_status={}, view={}, status={}, op={}, commit_min={}, commit_max={}, \
               checkpoint_op={}) — append-before-ack violated",
              op.get(),
              msg_view,
              self.wals[ri].status(op).as_str(),
              r.view().get(),
              r.status().as_str(),
              r.op().get(),
              r.commit().get(),
              r.commit_max().get(),
              r.checkpoint_op().get(),
            ).into());
          }
        }
        // Durable-view-before-participate, checked at emission: a StartView /
        // head-bearing RecoveryResponse (the primary paths) OR a DoViewChange vote (the ViewChange
        // retransmit path) for a view above the emitter's durable view is a participation in a
        // not-yet-recoverable view.
        self.record_durable_view_violation(ri, &out);
        outgoing.push((ReplicaId::new(ri as u16), out));
      }
    }
    for (from, out) in outgoing {
      self.route(now, from, out);
    }

    // Deliver due network messages. handle_message indexes self.replicas/wals/sbs
    // directly — those are disjoint from self.net, self.clients, self.crashed.
    for m in self.net.take_due(now) {
      match m.target {
        Target::Replica(idx) => {
          let ri = usize::from(idx);
          if !self.crashed[ri] {
            // SLOT-SHIFT TRANSLATION (ingress): the proto's `sender_matches` binds `from` as the
            // sender's SLOT in the RECEIVER's membership, but the network addresses peers by their stable
            // `MemberId` (== cluster index), so `m.from` carries the sender's MemberId. Re-express it as
            // that member's slot in the RECEIVER's LIVE membership. Pre-reconfiguration (and for every
            // node whose slot did not shift) slot == MemberId, so this is the IDENTITY map — the default
            // schedule is byte-identical; only after a slot-shifting reconfiguration does a retained
            // sender resolve to a different slot in the receiver's config (the case the cross-epoch
            // binding handles). A `from` MemberId absent from the receiver's membership (a removed sender,
            // or a not-yet-installed successor) keeps its raw value — the proto then drops it at the
            // sender binding exactly as the real transport's unresolved-peer path would.
            let from = self.translate_from_for_receiver(ri, m.from);
            self.replicas[ri].handle_message(
              now,
              &mut self.wals[ri],
              &mut self.sbs[ri],
              from,
              m.msg,
            );
          }
        }
        Target::Client(id) => {
          if let Some(c) = self.clients.iter_mut().find(|c| c.id().get() == id) {
            c.handle(now, m.msg);
          }
        }
      }
    }

    // Pump storage completions: drives append-before-ack (on_wal_done) + durable-view (on_sb_done).
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      self.replicas[ri].handle_storage(now, &mut self.wals[ri], &mut self.sbs[ri]);
    }

    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      self.record_applied_events(ri);
    }

    let next = [
      self.net.next_deadline(),
      self
        .replicas
        .iter()
        .enumerate()
        .filter(|(ri, _)| !self.crashed[*ri])
        .filter_map(|(_, ep)| ep.poll_timeout())
        .min(),
    ]
    .into_iter()
    .flatten()
    .min();
    let target = match next {
      Some(t) if t > now => t,
      _ => now + Duration::from_millis(1),
    };
    self.clock.advance_to(target);

    let now = self.clock.now();
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      self.replicas[ri].handle_timeout(now, &mut self.wals[ri], &mut self.sbs[ri]);
      // Pump storage after timeout: drives append-before-ack (on_wal_done) + durable-view (on_sb_done).
      self.replicas[ri].handle_storage(now, &mut self.wals[ri], &mut self.sbs[ri]);
    }

    // Drain the apply/swap events this second pump produced BEFORE the per-tick invariant check reads the
    // state. The state machine applies synchronously inside `handle_*` (so `replica_sm().applied()` shows
    // the gap a committed `Reconfigure` op leaves the instant it commits), but the matching
    // `Event::MembershipChanged` — which `committed_reconfigure_ops()` reads to EXPECT that gap — sits in
    // the proto out-queue until drained. A swap whose durable `SwapEpoch` root lands in THIS pump (the
    // new primary that preserved + recommitted a carried reconfigure body installs here) would otherwise
    // be visible as the applied gap one full tick before its op number entered the reconfigure-op set,
    // tripping the contiguity oracle on a benign drain-lag. Draining here keeps the two observations in
    // step. Observation-only (drains the out-queue; no PRNG draw / message / storage write), so off-axis
    // schedules stay byte-identical.
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      self.record_applied_events(ri);
    }

    // Per-tick re-formation observer — pure observation (no PRNG draw, message, or storage write), so
    // off-axis schedules stay byte-identical. A crashed node is skipped (its state and incarnation are
    // frozen until it restarts); this runs at the one point every tick passes through, so an escalation
    // inside `reconfigure_offline`'s internal drive is observed too.
    //
    // Re-formation escalation: the `RecoveringHead → ViewChange` edge — the UNIQUE transition
    // `retire_recover_and_escalate` produces (a `RecoveringHead` node otherwise only returns to `Normal`
    // via `StartView`/`RecoveryResponse`, never to `ViewChange`). Keyed by incarnation so a crash +
    // restart boundary is not mistaken for it, while still re-arming across a genuine re-wedge (each
    // escalation pairs within its own incarnation).
    //
    // (The recovered read-window tail witness is NOT observed here: it is sampled once at recover
    // construction in `recover_in_place`, since the held head is fixed there and the committed band above
    // the checkpoint is peer-learned only after recovery — there is no completion-edge band to observe.)
    //
    // Only VOTERS run the re-formation escalation (a voting-quorum path); a learner is never an active
    // view-change participant, so iterate the voter prefix `0..replica_count` — a non-voter must never
    // pollute this voter-only non-vacuity witness.
    for ri in 0..self.replica_count as usize {
      if self.crashed[ri] {
        continue;
      }
      let inc = self.incarnations[ri];
      let is_recovering_head = self.replicas[ri].status().is_recovering_head();
      if self.was_recovering_head[ri]
        && self.was_recovering_head_inc[ri] == inc
        && self.replicas[ri].status().is_view_change()
      {
        self.reform_escalations_fired += 1;
      }
      self.was_recovering_head[ri] = is_recovering_head;
      self.was_recovering_head_inc[ri] = inc;
    }
  }

  /// Drains replica `ri`'s pending application events into its recorded apply stream, tagged with
  /// its current incarnation: every [`Event::Committed`] (one per state-machine apply, in apply
  /// order) and every [`Event::StateSyncCompleted`] (the snapshot-rebase point that justifies the op
  /// jump a bulk restore produces). Other event kinds are embedder observability with no bearing on
  /// the apply stream. Recording is observation-only: no PRNG draw, no message, no storage write.
  fn record_applied_events(&mut self, ri: usize) {
    while let Some(ev) = self.replicas[ri].poll_event() {
      match ev {
        Event::Committed(c) => {
          self.applied_streams[ri].push((self.incarnations[ri], AppliedEvent::Committed(c)));
        }
        Event::StateSyncCompleted(op) => {
          self.applied_streams[ri].push((self.incarnations[ri], AppliedEvent::SyncPoint(op)));
        }
        // A committed `Reconfigure` op's durable `SwapEpoch` root landed: the live-reconfiguration
        // checkers fold this per-replica stream (the applied-once swap oracle + the config-lineage
        // chain). Tagged with the incarnation so a crash-restart that re-installs a swap is keyed
        // distinctly from the first install.
        Event::MembershipChanged(mc) => {
          self.membership_swaps[ri].push((self.incarnations[ri], mc));
        }
        _ => {}
      }
    }
  }

  /// Resolve a directed-send TARGET slot (named in SENDER `from`'s live membership) to the cluster
  /// index (== stable `MemberId`) the network routes to. The cluster index of every replica IS its
  /// `MemberId` (genesis `MemberId::new(i)` at slot `i`), so the sender's `member_at(slot)` yields the
  /// routing index directly. Returns the raw slot unchanged when it does not resolve (the sender is
  /// crashed/absent, or the slot is out of its membership range) — pre-reconfiguration this is the
  /// identity map, so the default schedule is byte-identical.
  fn translate_target_from_sender(&self, from: ReplicaId, slot: ReplicaId) -> u16 {
    let sender = usize::from(from.get());
    if self.crashed[sender] {
      return slot.get();
    }
    self.replicas[sender]
      .member_at(slot)
      .map_or(slot.get(), |mid| mid.get() as u16)
  }

  /// Re-express an inbound `from` (carrying the SENDER's stable `MemberId` == cluster index) as that
  /// member's SLOT in RECEIVER `ri`'s live membership — the identity the proto's `sender_matches`
  /// binds. Pre-reconfiguration (and whenever the sender's slot did not shift) `slot_of(MemberId) ==
  /// MemberId`, so this is the identity map; only a slot-shifting reconfiguration makes a retained
  /// sender resolve to a different slot in the receiver's config. A sender absent from the receiver's
  /// membership keeps its raw id (the proto drops it at the sender binding, as the real transport's
  /// unresolved-peer path would).
  fn translate_from_for_receiver(&self, ri: usize, from: Peer) -> Peer {
    let Peer::Replica(member_id) = from else {
      return from; // a client `from` carries no slot to translate.
    };
    match self.replicas[ri].slot_of(MemberId::new(member_id.get() as u128)) {
      Some(slot) => Peer::Replica(slot),
      None => from,
    }
  }

  /// Expands a `Recipient` into concrete `Target`s and schedules each.
  fn route(&mut self, now: Instant, from: ReplicaId, out: Outgoing) {
    // Belt-and-suspenders: a crashed replica should never be polled, but
    // drop any outgoing it might emit just in case.
    if self.crashed[usize::from(from.get())] {
      return;
    }
    let (to, msg) = (out.to(), out.into_msg());
    match to {
      Recipient::To(Peer::Replica(r)) => {
        // SLOT-SHIFT TRANSLATION (egress, directed): the proto names the TARGET as a SLOT in the
        // SENDER's membership; the network addresses by stable `MemberId` (== cluster index). Resolve
        // the slot through the SENDER's LIVE membership to the target MemberId. Pre-reconfiguration slot
        // == MemberId (the identity map — byte-identical default schedule); a slot-shifting
        // reconfiguration is the only case it diverges (a retained peer whose slot moved). A slot that
        // does not resolve (out of the sender's membership range) keeps its raw value, harmlessly
        // dropped downstream — the broadcast fan-outs below address cluster indices (MemberIds) directly,
        // so they need no translation.
        let target = self.translate_target_from_sender(from, r);
        self.schedule(now, Peer::Replica(from), Target::Replica(target), msg);
      }
      Recipient::To(Peer::Client(c)) => {
        self.schedule(now, Peer::Replica(from), Target::Client(c.get()), msg);
      }
      Recipient::Backups => {
        // A fan-out spans the full membership (every voting and non-voting member but this one).
        for idx in 0..self.replicas.len() as u16 {
          if idx != from.get() {
            self.schedule(now, Peer::Replica(from), Target::Replica(idx), msg.clone());
          }
        }
      }
      Recipient::AllReplicas => {
        for idx in 0..self.replicas.len() as u16 {
          self.schedule(now, Peer::Replica(from), Target::Replica(idx), msg.clone());
        }
      }
    }
  }

  /// Applies the fault model and (unless dropped) enqueues a message. With `duplicate_per_mille` a
  /// non-dropped message is enqueued a SECOND time at an independently-jittered delivery instant,
  /// exercising the protocol's idempotency / re-ack paths.
  fn schedule(&mut self, now: Instant, from: Peer, target: Target, msg: Message) {
    if let (Peer::Replica(from_r), Target::Replica(to_r)) = (from, target) {
      // A NON-VOTING learner must never emit a COUNTED message: a `PrepareOk` (a commit-quorum vote), a
      // `StartViewChange` or a `DoViewChange` (active view-change participation). It applies the committed
      // log and may solicit catch-up, but it is never a voter and never a prospective primary, so any such
      // emission is a REAL finding (a learner taking part in consensus). Classified by the emitter's LIVE
      // voter status (`is_voter`), NOT the static genesis `replica_count`: a `PromoteLearner` makes a
      // genesis-learner-slot node a VOTER, whose vote is then LEGITIMATE — keying off the static count
      // would mis-flag it. Recorded BEFORE the partition/one-way/frame drops below, so a learner's counted
      // message trips this even when a fault would later drop it; the recording changes no scheduling and
      // takes no PRNG draw. Drained by the VOPR driver each tick.
      if !self.replicas[usize::from(from_r.get())].is_voter()
        && matches!(
          msg,
          Message::PrepareOk(_) | Message::StartViewChange(_) | Message::DoViewChange(_)
        )
        && self.learner_emission_violation.is_none()
      {
        self.learner_emission_violation = Some(
          format!(
            "learner {} emitted a counted message {} — a non-voting learner must never send a \
             PrepareOk/StartViewChange/DoViewChange (it is never a voter, prospective primary, or \
             active view-change participant)",
            from_r.get(),
            msg.kind_str(),
          )
          .into(),
        );
      }
      if self.partitioned(from_r.get(), to_r) {
        return;
      }
      // The DIRECTED one-way block: this leg is cut while the reverse leg still flows (the
      // asymmetric-partition axis). Checked after the symmetric groups (either suffices to drop)
      // and counted, so the asym sweep can assert traffic was genuinely cut one-way.
      if self.one_way_blocked(from_r.get(), to_r) {
        self.one_way_dropped += 1;
        return;
      }
      // The transport's send-path frame guard: a peer message larger than one frame
      // ([`MAX_FRAME_LEN`]) cannot be sent and is dropped at the source. Model it here so the
      // inter-replica wire enforces the SAME cap the real transport does (the message-VOPR runs
      // without the transport). Header-only view-change carriers + the byte-bounded `RepairBatch` keep
      // every legitimate peer message at/below the cap, so a drop here is a REAL bug — a carrier
      // overflowed the frame. Only `replica → replica`
      // traffic is capped (client↔replica is a different path, not dropped — what the transport drops).
      if msg.encoded_len() > viewstamp_proto::MAX_FRAME_LEN as usize {
        self.oversized_dropped += 1;
        return;
      }
    }
    if self.faults.drop_per_mille > 0 && self.prng.chance(self.faults.drop_per_mille, 1000) {
      return;
    }
    // Roll the duplicate decision BEFORE enqueuing so the PRNG-draw order is fixed regardless of the
    // (independent) jitter draws below — keeping the run a pure function of the seed.
    let duplicate = self.faults.duplicate_per_mille > 0
      && self.prng.chance(self.faults.duplicate_per_mille, 1000);
    // Roll the UNBOUNDED-HOLD decision in the same fixed slot (after the duplicate roll, before the
    // jitter draw) so the draw order stays a pure function of the seed. The jitter draw below always
    // happens, so a held message's deliver_at is overridden without perturbing the stream. When
    // `hold_per_mille` is 0 the `&&` short-circuits — no draw — so default schedules are byte-identical.
    let hold = self.faults.hold_per_mille > 0 && self.prng.chance(self.faults.hold_per_mille, 1000);
    if hold {
      self.holds_fired += 1;
    }
    // Each copy's slow-replica extra delay is drawn right after its jitter (its own independent
    // draw, like the jitter itself). With no slow profile installed the call returns without
    // touching the PRNG, so default schedules stay byte-identical; a held message's deliver_at is
    // overridden below without perturbing the stream (the jitter discipline).
    let base_at = now
      + self.faults.latency
      + Duration::from_nanos(self.jitter_ns())
      + self.slow_extra(from, target);
    let deliver_at = if hold { now + HOLD_DELAY } else { base_at };
    self.net.enqueue(InFlight {
      deliver_at,
      from,
      target,
      msg: msg.clone(),
      seq: 0,
    });
    if duplicate {
      // The second copy gets its OWN jitter (and slow extra), so it can arrive before or after the
      // first.
      let dup_at = now
        + self.faults.latency
        + Duration::from_nanos(self.jitter_ns())
        + self.slow_extra(from, target);
      self.net.enqueue(InFlight {
        deliver_at: dup_at,
        from,
        target,
        msg,
        seq: 0,
      });
    }
  }

  /// The slow-replica extra delay for one delivery of a `from → target` message: a seeded draw from
  /// the sender's outbound band (when the sender is slow) plus the receiver's inbound band (when the
  /// receiver is slow). Only replica↔replica traffic is shaped (mirroring the partitions + the frame
  /// cap), and self-delivery is exempt (the slow link models the replica's NIC, not its local loop).
  /// Returns `Duration::ZERO` WITHOUT a PRNG draw when no installed profile applies, so schedules
  /// without a slow replica are byte-identical.
  fn slow_extra(&mut self, from: Peer, target: Target) -> Duration {
    let (Peer::Replica(from_r), Target::Replica(to_r)) = (from, target) else {
      return Duration::ZERO;
    };
    let (f, t) = (usize::from(from_r.get()), usize::from(to_r));
    if f == t {
      return Duration::ZERO;
    }
    let mut extra = Duration::ZERO;
    if let Some(p) = self.slow[f]
      && p.outbound
    {
      extra += self.slow_draw(p);
    }
    if let Some(p) = self.slow[t]
      && p.inbound
    {
      extra += self.slow_draw(p);
    }
    if !extra.is_zero() {
      self.slow_delays_applied += 1;
    }
    extra
  }

  /// One uniform draw from a slow profile's `[min_extra, max_extra]` band (inclusive).
  fn slow_draw(&mut self, p: SlowProfile) -> Duration {
    let lo = p.min_extra.as_nanos() as u64;
    let span = p.max_extra.saturating_sub(p.min_extra).as_nanos() as u64;
    Duration::from_nanos(lo + self.prng.below(span + 1))
  }

  /// One independent jitter draw in nanoseconds (`0` when jitter is disabled).
  fn jitter_ns(&mut self) -> u64 {
    if self.faults.jitter.is_zero() {
      0
    } else {
      self.prng.below(self.faults.jitter.as_nanos() as u64)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::storage::StorageFaults;

  #[test]
  fn one_node_cluster_ticks() {
    let mut cluster = Cluster::new(1, 1, 1, /*seed*/ 7);
    let t0 = cluster.now();
    for _ in 0..50 {
      cluster.tick();
    }
    assert!(cluster.now() > t0, "virtual clock must advance");
  }

  #[test]
  fn duplicate_delivery_preserves_safety_and_liveness() {
    // Every message duplicated (idempotency stress): a re-delivered Prepare must not double-apply and
    // a re-delivered PrepareOk must not double-count the quorum, so the cluster still commits cleanly.
    let mut c = Cluster::new(3, 2, 3, 4);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(2),
      drop_per_mille: 0,
      duplicate_per_mille: 1000,
      hold_per_mille: 0,
    });
    let mut done = false;
    for _ in 0..20_000 {
      c.tick();
      // contiguity/agreement holds under duplication.
      assert!(
        crate::check_safety(&c).is_ok(),
        "safety under duplicate delivery"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "duplicated messages still let clients finish (idempotency)"
    );
  }

  #[test]
  fn duplicate_delivery_is_deterministic() {
    // Same seed + same duplicate fault plan ⇒ identical applied logs (the dup roll uses the seeded PRNG).
    let run = || {
      let mut c = Cluster::new(3, 2, 3, 9);
      c.set_faults(Faults {
        latency: Duration::from_millis(1),
        jitter: Duration::from_millis(2),
        drop_per_mille: 0,
        duplicate_per_mille: 1000,
        hold_per_mille: 0,
      });
      for _ in 0..20_000 {
        c.tick();
        if (0..c.client_count()).all(|i| c.client(i).is_done()) {
          break;
        }
      }
      (0..c.replica_count())
        .map(|i| c.replica_sm(i).applied().to_vec())
        .collect::<Vec<_>>()
    };
    assert_eq!(
      run(),
      run(),
      "duplicate delivery is a pure function of the seed"
    );
  }

  #[test]
  fn restart_recovers_through_the_recovering_loop_under_faults() {
    let mut c = Cluster::new(3, 1, 3, 5);
    // TRANSIENT read faults on every replica's WAL (no permanent corruption); the recover loop must
    // retry through them and reach Normal.
    c.set_storage_faults(StorageFaults {
      read_fault_per_mille: 100,
      ..StorageFaults::none()
    });
    let mut warm = false;
    for _ in 0..40_000 {
      c.tick();
      if !c.replica_sm(1).applied().is_empty() {
        warm = true;
        break;
      }
    }
    assert!(warm, "replica 1 commits >= 1 op before the crash");
    c.crash(1);
    for _ in 0..500 {
      c.tick();
    }
    c.restart(1); // metadata-only recover + bounded handle_storage pump (retries the faulted reads)
    // After restart the replica is operational (Normal or ViewChange) — never stranded in Recovering,
    // because the faults are transient and clear within the proto's retry budget.
    assert!(
      c.replica_status_is_operational(1),
      "restart drives the Recovering loop to Normal under transient faults"
    );
  }

  #[test]
  fn crashed_replica_stops_and_is_skipped() {
    let mut c = Cluster::new(3, 1, 1, 7);
    c.crash(0);
    assert!(c.is_crashed(0));
    // ticking must not panic and must not deliver to/from the crashed replica.
    for _ in 0..20 {
      c.tick();
    }
    // a crashed primary means no commits; the (single) client cannot finish without view change,
    // but the loop must run cleanly.
    assert!(c.now().as_nanos() > 0);
  }

  #[test]
  fn gate_accessors_expose_op_commit_and_primary() {
    let mut c = Cluster::new(3, 1, 2, 11);
    for _ in 0..2000 {
      c.tick();
      if c.is_quiescent() {
        break;
      }
    }
    // replica 0 is the view-0 primary; its op/commit advanced as the client's requests committed.
    assert!(c.replica_is_primary(0), "replica 0 is the view-0 primary");
    assert!(c.replica_op(0).get() >= 1, "primary head advanced");
    assert!(c.replica_commit(0).get() >= 1, "primary commit advanced");
    assert!(
      !c.any_replica_view_advanced_beyond(0),
      "no view change in a clean run"
    );
    // A clean run never force-syncs (no pruned-hole strand).
    assert_eq!(
      c.replica_forced_sync_count(0),
      0,
      "no forced sync in a clean run"
    );
  }

  #[test]
  fn apply_stream_records_committed_ops_per_incarnation() {
    let mut c = Cluster::new(3, 1, 3, 11);
    for _ in 0..5_000 {
      c.tick();
      if c.is_quiescent() {
        break;
      }
    }
    assert_eq!(c.replica_incarnation(0), 0, "no restart yet");
    // The view-0 primary's stream carries one Committed per apply, in apply order, all tagged with
    // incarnation 0 — exactly its state machine's applied ops.
    let ops: Vec<u64> = c
      .replica_applied_events(0)
      .iter()
      .filter_map(|(inc, e)| {
        assert_eq!(
          *inc, 0,
          "every entry of an unrestarted replica is incarnation 0"
        );
        match e {
          AppliedEvent::Committed(commit) => Some(commit.op().get()),
          AppliedEvent::SyncPoint(_) => None,
        }
      })
      .collect();
    let expect: Vec<u64> = (1..=c.replica_sm(0).applied().len() as u64).collect();
    assert!(!expect.is_empty(), "the run committed ops");
    assert_eq!(ops, expect, "one Committed per apply, in apply order");
    // A crash captures the queued event tail; a restart begins a new incarnation.
    let before = c.replica_applied_events(1).len();
    c.crash(1);
    assert!(
      c.replica_applied_events(1).len() >= before,
      "crash never drops recorded events"
    );
    c.restart(1);
    assert_eq!(c.replica_incarnation(1), 1, "restart bumps the incarnation");
  }

  #[test]
  fn partition_groups_block_cross_group_traffic() {
    let mut c = Cluster::new(5, 1, 1, 3);
    assert!(!c.partitioned(0, 3), "no partition by default");
    c.partition(vec![0, 0, 0, 1, 1]); // {0,1,2} | {3,4}
    assert!(c.partitioned(0, 3), "cross-group is blocked");
    assert!(!c.partitioned(0, 1), "same-group is not blocked");
    assert!(!c.partitioned(3, 4), "same-group is not blocked");
    c.heal();
    assert!(!c.partitioned(0, 3), "heal removes all partitions");
  }

  #[test]
  fn one_way_blocks_are_directed_counted_and_healed() {
    // The DIRECTED block: 0 → 1 is cut while 1 → 0 still flows — the asymmetric shape the
    // symmetric groups cannot express. The blocked leg is dropped + counted; the reverse leg and
    // client-bound traffic are untouched; `heal` restores full bidirectional connectivity.
    let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
    let now = c.now();
    c.block_one_way(0, 1);
    assert!(c.one_way_blocked(0, 1), "the installed leg is blocked");
    assert!(!c.one_way_blocked(1, 0), "the REVERSE leg still flows");
    let small = Message::Commit(viewstamp_proto::Commit::new(
      viewstamp_proto::View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      viewstamp_proto::Epoch::new(0),
      0,
    ));
    // Blocked leg: dropped + counted, never enqueued.
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(0)),
      Target::Replica(1),
      small.clone(),
    );
    assert_eq!(c.one_way_dropped(), 1, "the blocked leg drop is counted");
    assert!(
      c.net.is_empty(),
      "the blocked message never reached the wire"
    );
    // Reverse leg: delivered.
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(1)),
      Target::Replica(0),
      small.clone(),
    );
    assert_eq!(c.one_way_dropped(), 1, "the reverse leg is NOT blocked");
    assert!(!c.net.is_empty(), "the reverse-leg message was enqueued");
    // Heal: the leg flows again.
    c.heal();
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(0)),
      Target::Replica(1),
      small,
    );
    assert_eq!(c.one_way_dropped(), 1, "heal cleared the one-way block");
  }

  #[test]
  fn partition_primary_out_deposes_the_primary_and_heals() {
    // The stale-read lane's partition mechanism: cut every leg to AND from the current primary
    // (deaf + mute), so the survivors stop hearing it. The witness advances, the deposed primary's
    // legs are blocked both ways, and `heal` restores connectivity.
    let mut c = Cluster::new(3, 1, 2, /*seed*/ 7);
    for _ in 0..2000 {
      c.tick();
      if c.is_quiescent() {
        break;
      }
    }
    assert!(c.replica_is_primary(0), "replica 0 is the view-0 primary");
    assert_eq!(c.stale_read_probes_fired(), 0, "no probe yet");
    assert!(
      c.partition_primary_out(0),
      "replica 0 is a live primary the lane deposes"
    );
    assert_eq!(c.stale_read_probes_fired(), 1, "the probe witness advanced");
    // Targeting a non-primary is a no-op: no cut, no witness bump (a false witness would mask the
    // intended primary going unpartitioned).
    assert!(!c.partition_primary_out(1), "replica 1 is not a primary");
    assert_eq!(
      c.stale_read_probes_fired(),
      1,
      "the witness counts only genuine deposals"
    );
    // Both directions are cut for every peer.
    assert!(
      c.one_way_blocked(1, 0) && c.one_way_blocked(0, 1),
      "deaf + mute vs peer 1"
    );
    assert!(
      c.one_way_blocked(2, 0) && c.one_way_blocked(0, 2),
      "deaf + mute vs peer 2"
    );
    // The survivors stop hearing the old primary and fail over to a higher view.
    let mut failed_over = false;
    for _ in 0..200_000 {
      c.tick();
      if c.any_replica_view_advanced_beyond(0) {
        failed_over = true;
        break;
      }
    }
    assert!(
      failed_over,
      "deposing the primary (deaf + mute) forces the survivors to elect a new primary"
    );
    // A new primary now serves in a higher view; replica 0, still cut, is at best a STALE old-view
    // primary (or has forfeited) — NOT the cluster's serving primary. Re-targeting it must be a
    // no-op with the witness unchanged: a status-agnostic predicate would wrongly count the stale
    // primary and leave the real one unpartitioned.
    let mut serving = None;
    for _ in 0..200_000 {
      c.tick();
      if let Some(p) = c.serving_primary()
        && c.replica_view(p).get() > 0
      {
        serving = Some(p);
        break;
      }
    }
    let serving = serving.expect("a new serving primary stabilized in a higher view");
    assert_ne!(
      serving, 0,
      "the deposed primary 0 is not the new serving primary"
    );
    let witness = c.stale_read_probes_fired();
    assert!(
      !c.partition_primary_out(0),
      "the deposed old-view primary 0 is not the serving primary {serving}"
    );
    assert_eq!(
      c.stale_read_probes_fired(),
      witness,
      "no false witness for a stale old-view primary"
    );
    // Heal restores full connectivity; the witness is monotone (a heal never lowers it).
    c.heal();
    assert!(
      !c.one_way_blocked(1, 0) && !c.one_way_blocked(0, 1),
      "heal cleared the cut"
    );
    assert_eq!(
      c.stale_read_probes_fired(),
      1,
      "the witness is monotone across heal"
    );
  }

  #[test]
  fn slow_profile_delays_but_delivers_and_clears() {
    // The GRAY-FAILURE profile: a slow replica's messages ARRIVE (never dropped), each at least
    // `min_extra` later than an unshaped message — late, not lost — and clearing the profile
    // restores prompt delivery (and stops consuming PRNG draws).
    let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
    let now = c.now();
    let small = Message::Commit(viewstamp_proto::Commit::new(
      viewstamp_proto::View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      viewstamp_proto::Epoch::new(0),
      0,
    ));
    let min_extra = Duration::from_millis(5);
    c.set_slow_replica(
      1,
      Some(SlowProfile {
        inbound: true,
        outbound: true,
        min_extra,
        max_extra: Duration::from_millis(20),
      }),
    );
    // Outbound leg (slow sender) and inbound leg (slow receiver): both delayed by >= min_extra over
    // the base latency; an unrelated 0 → 2 message is unshaped. No jitter in the default fault
    // plan, so the base delivery is exactly `now + latency`.
    let base = now + Faults::none().latency;
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(1)),
      Target::Replica(2),
      small.clone(),
    );
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(0)),
      Target::Replica(1),
      small.clone(),
    );
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(0)),
      Target::Replica(2),
      small.clone(),
    );
    let due = c.net.take_due(now + Duration::from_secs(3600));
    assert_eq!(due.len(), 3, "slow messages are DELIVERED, not dropped");
    let at = |from: u16, to: u16| {
      due
        .iter()
        .find(|m| m.from == Peer::Replica(ReplicaId::new(from)) && m.target == Target::Replica(to))
        .expect("the scheduled message is in flight")
        .deliver_at
    };
    assert!(
      at(1, 2) >= base + min_extra,
      "the slow sender's outbound message is late by at least the band floor"
    );
    assert!(
      at(0, 1) >= base + min_extra,
      "the slow receiver's inbound message is late by at least the band floor"
    );
    assert_eq!(
      at(0, 2),
      base,
      "a message not touching the slow replica is unshaped"
    );
    assert_eq!(c.slow_delays_applied(), 2, "both shaped legs are counted");
    // Clearing restores prompt delivery.
    c.clear_slow_replicas();
    c.schedule(
      now,
      Peer::Replica(ReplicaId::new(0)),
      Target::Replica(1),
      small,
    );
    let due = c.net.take_due(now + Duration::from_secs(3600));
    assert_eq!(
      due[0].deliver_at, base,
      "clearing the profile restores prompt delivery"
    );
    assert_eq!(
      c.slow_delays_applied(),
      2,
      "no further delays after the clear"
    );
  }

  #[test]
  fn durable_view_checker_flags_a_sync_checkpoint_above_the_durable_view() {
    // CHECKER NON-VACUITY: the durable-view oracle must flag a `SyncCheckpoint` advertising a view
    // ABOVE the emitter's durable view — the state-sync serve participates like
    // StartView/RecoveryResponse/DoViewChange/Prepare/PrepareOk/Commit. A fresh cluster's durable
    // view is 0; a SyncCheckpoint(view=1) is therefore a participation in a not-yet-durable view and
    // MUST trip.
    let mut c = Cluster::new(3, 1, 1, 1);
    assert_eq!(
      c.replica_durable_view(0).get(),
      0,
      "fresh durable view is 0"
    );
    let serve = Outgoing::new(
      Recipient::To(Peer::Replica(ReplicaId::new(2))),
      Message::SyncCheckpoint(viewstamp_proto::SyncCheckpoint::new(
        viewstamp_proto::View::with(1), // above the durable view 0
        OpNumber::with(4),
        0,
        viewstamp_proto::Epoch::new(0),
        0,
        ReplicaId::new(0),
        0xD18F,
        bytes::Bytes::from_static(b"snapshot"),
        Bytes::new(),
      )),
    );
    c.record_durable_view_violation(0, &serve);
    let why = c
      .take_durable_view_violation()
      .expect("a SyncCheckpoint above the durable view must be flagged");
    assert!(
      why.contains("SyncCheckpoint"),
      "the violation names the offending message kind: {why}"
    );
    // Control: a SyncCheckpoint AT the durable view (view 0) is a legitimate serve — not flagged.
    let ok_serve = Outgoing::new(
      Recipient::To(Peer::Replica(ReplicaId::new(2))),
      Message::SyncCheckpoint(viewstamp_proto::SyncCheckpoint::new(
        viewstamp_proto::View::with(0), // == durable view 0
        OpNumber::with(4),
        0,
        viewstamp_proto::Epoch::new(0),
        0,
        ReplicaId::new(0),
        0xD18F,
        bytes::Bytes::from_static(b"snapshot"),
        Bytes::new(),
      )),
    );
    c.record_durable_view_violation(0, &ok_serve);
    assert!(
      c.take_durable_view_violation().is_none(),
      "a SyncCheckpoint at the durable view is a legitimate serve and must NOT be flagged"
    );
  }

  #[test]
  fn network_drops_an_oversized_inter_replica_message_but_not_small_or_client_ones() {
    // The CONVERSE that proves the frame cap is REAL: a full-`Present` 8-entry `DoViewChange` of
    // large bodies — the carrier shape header-only carriers exist to avoid — EXCEEDS `MAX_FRAME_LEN`,
    // and the sim network drops it on the
    // inter-replica path (counting it), while a header-only carrier of the SAME band, a small message,
    // and an (oversized) client-bound message all pass. This is the modelled transport send-path frame
    // guard; it is what makes the VOPR's `oversized_dropped == 0` for legitimate traffic a real oracle.
    use viewstamp_proto::{
      ClientId, DoViewChange, MAX_FRAME_LEN, OpNumber, PreparedEntry, ReplicaId, RequestNumber,
      View, max_request_body_len,
    };

    let big = max_request_body_len() / 4; // each ~4 MiB; 8 of them full-bodied dwarf the 16 MiB frame
    let body = bytes::Bytes::from(std::vec![0x5Au8; big]);
    let full_body: Vec<PreparedEntry> = (1..=8u64)
      .map(|op| {
        PreparedEntry::new(
          OpNumber::with(op),
          ClientId::new(7),
          RequestNumber::with(op),
          body.clone(),
        )
      })
      .collect();
    let header_only: Vec<PreparedEntry> = (1..=8u64)
      .map(|op| {
        PreparedEntry::repairing(
          OpNumber::with(op),
          ClientId::new(7),
          RequestNumber::with(op),
          0,
        )
      })
      .collect();
    let dvc_full = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(1),
      OpNumber::with(8),
      OpNumber::with(8),
      viewstamp_proto::Epoch::new(0),
      0,
      ReplicaId::new(0),
      full_body,
    ));
    let dvc_header = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(1),
      OpNumber::with(8),
      OpNumber::with(8),
      viewstamp_proto::Epoch::new(0),
      0,
      ReplicaId::new(0),
      header_only,
    ));
    // The full-body band is over the frame; the header-only band of the SAME ops is far under it.
    assert!(
      dvc_full.encoded_len() > MAX_FRAME_LEN as usize,
      "a full-body 8-entry DoViewChange of large bodies must exceed the frame cap (the old bug)"
    );
    assert!(
      dvc_header.encoded_len() < MAX_FRAME_LEN as usize,
      "a header-only DoViewChange of the same band must fit the frame cap"
    );

    let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
    let now = c.now();
    let from = Peer::Replica(ReplicaId::new(0));
    // Peer → peer, oversized: DROPPED + counted.
    c.schedule(now, from, Target::Replica(1), dvc_full.clone());
    assert_eq!(
      c.oversized_dropped(),
      1,
      "an oversized inter-replica message is dropped by the send-path frame guard and counted"
    );
    assert!(
      c.net.is_empty(),
      "the oversized peer message was dropped, not enqueued"
    );
    // Peer → peer, header-only (same band): delivered, no new drop.
    c.schedule(now, from, Target::Replica(1), dvc_header.clone());
    assert_eq!(
      c.oversized_dropped(),
      1,
      "a header-only carrier of the same band fits the frame and is NOT dropped"
    );
    assert!(!c.net.is_empty(), "the header-only carrier was enqueued");
    // A small peer message: delivered, no new drop.
    let small = Message::Commit(viewstamp_proto::Commit::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      viewstamp_proto::Epoch::new(0),
      0,
    ));
    c.schedule(now, from, Target::Replica(2), small);
    assert_eq!(
      c.oversized_dropped(),
      1,
      "a small peer message is never dropped"
    );
    // An oversized CLIENT-bound message is NOT capped here (only peer traffic is — mirroring what the
    // real transport drops). Build a Reply that itself exceeds the frame and confirm it is not dropped.
    let huge_reply = Message::Reply(viewstamp_proto::Reply::new(
      View::with(1),
      ClientId::new(1),
      RequestNumber::with(1),
      bytes::Bytes::from(std::vec![0u8; MAX_FRAME_LEN as usize + 1024]),
    ));
    assert!(huge_reply.encoded_len() > MAX_FRAME_LEN as usize);
    c.schedule(now, from, Target::Client(1), huge_reply);
    assert_eq!(
      c.oversized_dropped(),
      1,
      "a client-bound message is not subject to the inter-replica frame cap (different path)"
    );
  }

  #[test]
  fn an_over_threshold_sync_checkpoint_would_drop_but_its_chunks_all_fit() {
    // The chunked state-sync CONVERSE: a whole `SyncCheckpoint` of an envelope just past the
    // unchunked threshold is EXACTLY what the single-frame path would have sent — the modelled
    // transport frame guard DROPS it (counted), which on a laggard whose only recovery is that
    // envelope was a permanent liveness wedge. Every `SyncChunk` of the SAME envelope fits the cap
    // by construction, a max-fill chunk landing EXACTLY on it — so the chunked path keeps
    // `oversized_dropped == 0` a real oracle over SyncCheckpoint traffic of any size.
    use viewstamp_proto::{
      MAX_FRAME_LEN, OpNumber, ReplicaId, SYNC_CHUNK_LEN, SyncCheckpoint, SyncChunk, View,
      max_unchunked_snapshot_len,
    };

    let env_len = max_unchunked_snapshot_len() + 1; // one byte past the whole-message threshold
    let env = bytes::Bytes::from(std::vec![0x5Au8; env_len]);
    let whole = Message::SyncCheckpoint(SyncCheckpoint::new(
      View::with(1),
      OpNumber::with(8),
      0xFEED,
      viewstamp_proto::Epoch::new(0),
      0,
      ReplicaId::new(0),
      7,
      env.clone(),
      Bytes::new(),
    ));
    assert!(
      whole.encoded_len() > MAX_FRAME_LEN as usize,
      "one byte past the threshold makes the whole SyncCheckpoint oversized"
    );

    let mut c = Cluster::new(3, 1, 1, /*seed*/ 7);
    let now = c.now();
    let from = Peer::Replica(ReplicaId::new(0));
    c.schedule(now, from, Target::Replica(1), whole);
    assert_eq!(
      c.oversized_dropped(),
      1,
      "the whole over-threshold envelope is dropped + counted by the frame guard"
    );
    assert!(
      c.net.is_empty(),
      "the oversized serve never reached the wire"
    );

    // EVERY chunk of the same envelope is deliverable; the max-fill first chunk lands exactly on
    // the cap and the partial tail is far under it.
    let mut offset = 0usize;
    let mut chunks = 0usize;
    while offset < env_len {
      let end = (offset + SYNC_CHUNK_LEN).min(env_len);
      let chunk = Message::SyncChunk(SyncChunk::new(
        View::with(1),
        OpNumber::with(8),
        0xFEED,
        0,
        env_len as u64,
        offset as u64,
        ReplicaId::new(0),
        7,
        env.slice(offset..end),
      ));
      assert!(
        chunk.encoded_len() <= MAX_FRAME_LEN as usize,
        "every chunk of the over-threshold envelope fits the frame cap"
      );
      if end - offset == SYNC_CHUNK_LEN {
        assert_eq!(
          chunk.encoded_len(),
          MAX_FRAME_LEN as usize,
          "a max-fill chunk lands exactly on the cap (the chunk size wastes nothing)"
        );
      }
      c.schedule(now, from, Target::Replica(1), chunk);
      offset = end;
      chunks += 1;
    }
    assert_eq!(
      chunks, 2,
      "one byte past the threshold splits into exactly two chunks"
    );
    assert_eq!(
      c.oversized_dropped(),
      1,
      "no chunk was dropped — the chunked path never produces an oversized frame"
    );
  }
}

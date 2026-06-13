use core::time::Duration;

use bytes::Bytes;
use smol_str::SmolStr;

use viewstamp_proto::{
  Committed, Config, DEFAULT_CHECKPOINT_OPS, Endpoint, Event, Instant, Message, OpNumber, Outgoing,
  Peer, Prng, Recipient, ReplicaId, Wal,
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

/// A deterministic single-thread cluster of `Endpoint<SimSm>` replicas + clients.
pub struct Cluster {
  replicas: Vec<Endpoint<SimSm>>,
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
  replica_count: u8,
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
  /// Per-replica INCARNATION counter: 0 from construction, +1 per [`restart`](Self::restart) /
  /// [`wipe_and_restart`](Self::wipe_and_restart) (and per pre-run endpoint rebuild —
  /// [`set_max_client_sessions`](Self::set_max_client_sessions) /
  /// [`set_batch_mode`](Self::set_batch_mode)). An incarnation boundary is where a
  /// replica's apply stream legitimately re-emits from its durable checkpoint (recovery re-applies
  /// `(checkpoint_op .. commit_max]`; a wipe re-applies from genesis).
  incarnations: Vec<u64>,
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
  /// checkpoints + checkpoint-based recovery.
  pub fn with_checkpoint_ops(
    replicas: u8,
    clients: u32,
    requests_per_client: u64,
    seed: u64,
    checkpoint_ops: u64,
  ) -> Self {
    let replica_set: Vec<Endpoint<SimSm>> = (0..replicas)
      .map(|i| {
        let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(i), replicas, checkpoint_ops)
          .expect("valid cluster config");
        Endpoint::new(
          cfg,
          seed ^ (i as u64).wrapping_mul(0x1234_5678),
          SimSm::Plain(LogSm::default()),
        )
      })
      .collect();
    let client_set: Vec<ClientModel> = (0..clients)
      .map(|i| ClientModel::new((i as u128) + 1, requests_per_client, seed))
      .collect();
    let n = replicas as usize;
    let storage_faults = StorageFaults::none();
    let (wals, sbs) = Self::seed_storage(replicas, seed, storage_faults, None, None, None);
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
      replica_count: replicas,
      checkpoint_ops,
      max_client_sessions: None,
      batch_mode: false,
      crashed: vec![false; n],
      groups: vec![0; n],
      one_way: vec![vec![false; n]; n],
      slow: vec![None; n],
      append_before_ack_violation: None,
      durable_view_violation: None,
      async_wal_delay: None,
      async_sb_delay: None,
      wal_capacity: None,
      oversized_dropped: 0,
      holds_fired: 0,
      one_way_dropped: 0,
      slow_delays_applied: 0,
      stale_read_probes_fired: 0,
      applied_streams: vec![Vec::new(); n],
      incarnations: vec![0; n],
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
    replicas: u8,
    seed: u64,
    faults: StorageFaults,
    async_wal_delay: Option<u32>,
    async_sb_delay: Option<u32>,
    wal_capacity: Option<u64>,
  ) -> (Vec<InMemoryWal>, Vec<InMemorySuperblock>) {
    let wals = (0..replicas)
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
    let sbs = (0..replicas)
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
  fn storage_seed(seed: u64, replica: u8) -> u64 {
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
      self.replica_count,
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
      self.replica_count,
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
      self.replica_count,
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
      self.replica_count,
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

  /// Number of replicas (for invariant checking).
  pub fn replica_count(&self) -> usize {
    self.replicas.len()
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
  /// `recover` is a metadata-only constructor that returns in `Status::Recovering` and drives
  /// its WAL-tail (+ checkpoint) reads via `handle_storage` (retrying any fault). We pump
  /// `handle_storage` here in a bounded loop so the replica reaches `Normal`/`RecoveringHead` before
  /// the next `tick` — letting gates assert state right after a restart. (The
  /// main `tick` loop also pumps `handle_storage` every tick, so an un-pumped restart would still
  /// recover; this pump is purely for test-assertion timing.)
  pub fn restart(&mut self, i: usize) {
    // A restart begins a new INCARNATION of this replica's apply stream: the rebuilt endpoint
    // re-emits from its durable checkpoint (recovery re-applies `(checkpoint_op .. commit_max]`; a
    // wiped disk re-applies from genesis), so per-incarnation stream invariants start afresh.
    self.incarnations[i] += 1;
    let cfg = self.replica_config(i as u8);
    let seed = self.seed ^ (i as u64).wrapping_mul(0x1234_5678);
    let now = self.clock.now();
    self.replicas[i] = Endpoint::recover(
      cfg,
      seed,
      self.make_sm(),
      &mut self.wals[i],
      &mut self.sbs[i],
    );
    // Drain the Recovering read loop to completion. Bounded by the WAL-tail length × the per-slot
    // retry budget plus a margin; a fault that never clears within this leaves the replica
    // Recovering/RecoveringHead and the per-tick `handle_storage` keeps trying.
    for _ in 0..4_096 {
      if !self.replicas[i].status().is_recovering() {
        break;
      }
      self.replicas[i].handle_timeout(now, &mut self.wals[i], &mut self.sbs[i]);
      self.replicas[i].handle_storage(now, &mut self.wals[i], &mut self.sbs[i]);
    }
    self.crashed[i] = false;
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
    let s = Self::storage_seed(self.seed, i as u8);
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

  /// Whether replica `i` is crashed.
  pub fn is_crashed(&self, i: usize) -> bool {
    self.crashed[i]
  }

  /// The per-replica `Config` (cluster id 1, this cluster's checkpoint interval and — when set — its
  /// client-session cap), shared by construction-time builds and `restart`/`wipe_and_restart` so a
  /// recovered replica keeps the identical cluster configuration.
  fn replica_config(&self, i: u8) -> Config {
    let cfg = Config::with_checkpoint_ops(
      1,
      ReplicaId::new(i),
      self.replica_count,
      self.checkpoint_ops,
    )
    .expect("valid cluster config");
    match self.max_client_sessions {
      Some(cap) => cfg
        .with_max_client_sessions(cap)
        .expect("a non-zero session cap"),
      None => cfg,
    }
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
    for i in 0..self.replica_count {
      let cfg = self.replica_config(i);
      let seed = self.seed ^ (i as u64).wrapping_mul(0x1234_5678);
      self.replicas[i as usize] = Endpoint::new(cfg, seed, self.make_sm());
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
      let peer = viewstamp_proto::ReplicaId::new(((i + 1) % self.replicas.len()) as u8);
      let from = Peer::Replica(peer);
      let view = self.replicas[i].view();
      let gv = Message::GetView(viewstamp_proto::GetView::new(view, peer, 0xF1_u64));
      self.replicas[i].handle_message(now, &mut self.wals[i], &mut self.sbs[i], from, gv);
      let rec = Message::Recovery(viewstamp_proto::Recovery::new(peer, 0xF2_u64));
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
        self.route(now, ReplicaId::new(i as u8), out);
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
  pub fn replica_sync_transfer_donor(&self, i: usize) -> Option<u8> {
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

  /// Replica `i`'s RECOVERED COMMITTED BAND width: `commit_max - checkpoint_op`, the count of
  /// known-committed ops the replica holds ABOVE its durable checkpoint. This is exactly the span the
  /// recover read-window logic materializes (`recover` reads + re-applies `(checkpoint_op ..
  /// commit_max]` from the WAL, bounded by `RECOVER_TAIL_WINDOW`). Read right after a `restart`, it is
  /// the band that recovery actually reconstructed; the simulator tracks its high-water across the run
  /// so the large-`checkpoint_ops` axis can be asserted NON-vacuous (a replica really recovered a
  /// non-trivial band, not always the tiny ≈4..=12 the small-interval seeds produce). Saturating, since
  /// a re-learnable `commit_max` hint can momentarily exceed a freshly-recovered `checkpoint_op` only
  /// upward (the subtraction floors at 0 when `checkpoint_op > commit_max`, which recovery never sets).
  pub fn replica_recovered_band(&self, i: usize) -> u64 {
    self.replicas[i]
      .commit_max()
      .get()
      .saturating_sub(self.replicas[i].checkpoint_op().get())
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
  /// still flows. The asymmetric analogue of [`partition`](Self::partition).
  pub fn block_one_way(&mut self, from: u8, to: u8) {
    assert_ne!(from, to, "a replica always reaches itself");
    self.one_way[from as usize][to as usize] = true;
  }

  /// Whether `from`'s messages to `to` are currently blocked by a DIRECTED one-way block (the
  /// asymmetric check; independent of the symmetric [`partitioned`](Self::partitioned)).
  pub fn one_way_blocked(&self, from: u8, to: u8) -> bool {
    self.one_way[from as usize][to as usize]
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

  /// Whether replica↔replica traffic between replicas `a` and `b` is currently partitioned.
  pub fn partitioned(&self, a: u8, b: u8) -> bool {
    self.groups[a as usize] != self.groups[b as usize]
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
              Target::Replica(ri as u8),
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
        outgoing.push((ReplicaId::new(ri as u8), out));
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
          let ri = idx as usize;
          if !self.crashed[ri] {
            self.replicas[ri].handle_message(
              now,
              &mut self.wals[ri],
              &mut self.sbs[ri],
              m.from,
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
        _ => {}
      }
    }
  }

  /// Expands a `Recipient` into concrete `Target`s and schedules each.
  fn route(&mut self, now: Instant, from: ReplicaId, out: Outgoing) {
    // Belt-and-suspenders: a crashed replica should never be polled, but
    // drop any outgoing it might emit just in case.
    if self.crashed[from.get() as usize] {
      return;
    }
    let (to, msg) = (out.to(), out.into_msg());
    match to {
      Recipient::To(Peer::Replica(r)) => {
        self.schedule(now, Peer::Replica(from), Target::Replica(r.get()), msg);
      }
      Recipient::To(Peer::Client(c)) => {
        self.schedule(now, Peer::Replica(from), Target::Client(c.get()), msg);
      }
      Recipient::Backups => {
        for idx in 0..self.replica_count {
          if idx != from.get() {
            self.schedule(now, Peer::Replica(from), Target::Replica(idx), msg.clone());
          }
        }
      }
      Recipient::AllReplicas => {
        for idx in 0..self.replica_count {
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
    let (f, t) = (from_r.get() as usize, to_r as usize);
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
    let at = |from: u8, to: u8| {
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
        ReplicaId::new(0),
        0xD18F,
        bytes::Bytes::from_static(b"snapshot"),
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
        ReplicaId::new(0),
        0xD18F,
        bytes::Bytes::from_static(b"snapshot"),
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
      ReplicaId::new(0),
      full_body,
    ));
    let dvc_header = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(1),
      OpNumber::with(8),
      OpNumber::with(8),
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
      ReplicaId::new(0),
      7,
      env.clone(),
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

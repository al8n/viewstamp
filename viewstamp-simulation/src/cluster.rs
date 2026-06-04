use core::time::Duration;

use smol_str::SmolStr;

use viewstamp_proto::{
  Config, DEFAULT_CHECKPOINT_OPS, Endpoint, Instant, Message, OpNumber, Outgoing, Peer, Prng,
  Recipient, ReplicaId, Wal,
};

use crate::client::ClientModel;
use crate::clock::Clock;
use crate::network::{Faults, InFlight, Network, Target};
use crate::sm::LogSm;
use crate::storage::{InMemorySuperblock, InMemoryWal, StorageFaults};

/// Mixed into the per-replica storage-fault seed so a replica's WAL/SB fault PRNG is independent of
/// its protocol PRNG (which uses a different mixer in `with_checkpoint_ops`).
const STORAGE_SEED_MAGIC: u64 = 0x5151_DEAD_BEEF_0F0F;

/// A deterministic single-thread cluster of `Endpoint<LogSm>` replicas + clients.
pub struct Cluster {
  replicas: Vec<Endpoint<LogSm>>,
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
  crashed: Vec<bool>,
  /// Partition group id per replica. Replica↔replica messages between different groups are
  /// dropped. All replicas start in group 0 (no partition).
  groups: Vec<u8>,
  /// Set by [`tick`](Self::tick) when a replica emitted a `PrepareOk(op)` for an op that is NOT
  /// durable in its OWN WAL+snapshot at emission time — the append-before-ack invariant, checked
  /// structurally "via the sim's storage view". Stays `None` in the absence of a violation; a checker
  /// (the VOPR driver) drains it each tick via [`take_append_before_ack_violation`]. Existing gates
  /// never read it, so it is inert for them.
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
  /// driver drains it each tick via [`take_durable_view_violation`]. Inert for existing gates (they
  /// never read it). See [`record_durable_view_violation`](Self::record_durable_view_violation).
  durable_view_violation: Option<SmolStr>,
  /// `None` (default) ⇒ every replica's WAL appends SYNCHRONOUSLY (existing-gate behaviour). `Some(d)`
  /// ⇒ async-append mode with per-append delay `d` polls — the Phase-A in-flight window the
  /// append-before-ack invariant must survive. Set via [`set_async_wal_delay`] before running;
  /// persists across `crash`/`restart` because the WAL struct does.
  async_wal_delay: Option<u32>,
  /// `None` (default) ⇒ every replica's superblock writes complete SYNCHRONOUSLY (existing-gate
  /// behaviour). `Some(d)` ⇒ async-write mode with per-write delay `d` polls — the pending
  /// durable-view window the durable-view-before-participate gate must survive. Set via
  /// [`set_async_superblock_delay`] before running; persists across `crash`/`restart` because the
  /// superblock struct does. A `crash` additionally DISCARDS any in-flight superblock write (a real
  /// crash loses an `fsync` mid-flight), so a not-yet-durable view write is genuinely lost.
  async_sb_delay: Option<u32>,
  /// `None` (default) ⇒ every replica's WAL is UNBOUNDED (`capacity() == u64::MAX`, the proto's
  /// stall-before-wrap never engages — existing-gate behaviour). `Some(n)` ⇒ a fixed RING of `n` slots
  /// per replica: the proto stalls op-assignment before wrapping an un-pruned slot. Set via
  /// [`set_wal_capacity`] before running; persists across `crash`/`restart` because the WAL struct does.
  /// MUST be `> checkpoint_ops + pipeline headroom` or the stall never releases (see the `Wal` capacity
  /// liveness contract).
  wal_capacity: Option<u64>,
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
    let replica_set: Vec<Endpoint<LogSm>> = (0..replicas)
      .map(|i| {
        let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(i), replicas, checkpoint_ops)
          .expect("valid cluster config");
        Endpoint::new(
          cfg,
          seed ^ (i as u64).wrapping_mul(0x1234_5678),
          LogSm::default(),
        )
      })
      .collect();
    let client_set: Vec<ClientModel> = (0..clients)
      .map(|i| ClientModel::new((i as u128) + 1, requests_per_client))
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
      crashed: vec![false; n],
      groups: vec![0; n],
      append_before_ack_violation: None,
      durable_view_violation: None,
      async_wal_delay: None,
      async_sb_delay: None,
      wal_capacity: None,
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
  pub fn replica_sm(&self, i: usize) -> &LogSm {
    self.replicas[i].state_machine_ref()
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
  ///   advertises a view a crash could roll back (previously an unchecked blind spot).
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
      // view advertises a view a crash could roll back — previously an unchecked blind spot (the
      // checker covered StartView/RecoveryResponse/DoViewChange/Prepare/PrepareOk/Commit but not
      // this serve). The checkpoint content is view-independent, so the requester re-solicits and a
      // Normal+durable peer answers; serving it during `pending_sb` is the same class as the others.
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

  /// Number of replicas (for invariant checking).
  pub fn replica_count(&self) -> usize {
    self.replicas.len()
  }

  /// Number of clients.
  pub fn client_count(&self) -> usize {
    self.clients.len()
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
  ///   fsync-loss-on-crash model. Previously a staged append was left in place, so the async-WAL
  ///   `poll` later RELEASED it into the durable log AFTER recovery (a stale `Appended` carrying a
  ///   superseded `OpId`) — inverting real crash semantics, where an un-`fsync`'d WAL write is lost.
  ///   Dropping it means a crash exercises the "in-flight WAL write lost" case directly: the recovered
  ///   replica's WAL head sits at most at its last DURABLE op, exactly the stale-WAL-slot class the
  ///   proto's recovery (and `truncate_wal_above_adopted_head`) must defend.
  ///
  /// In synchronous mode both are no-ops (nothing is ever staged).
  pub fn crash(&mut self, i: usize) {
    self.crashed[i] = true;
    self.sbs[i].discard_inflight();
    self.wals[i].discard_inflight();
  }

  /// Restart a previously-crashed replica: rebuild it from its durable WAL + superblock via
  /// `Endpoint::recover`. Re-derives the same per-replica config + seed used in `new`, so the
  /// recovered replica keeps its identity. Its in-memory state (log cache, SM) is reconstructed
  /// from storage; everything not yet durable is lost (as a real crash would lose it).
  ///
  /// `recover` is now a metadata-only constructor that returns in `Status::Recovering` and drives
  /// its WAL-tail (+ checkpoint) reads via `handle_storage` (retrying any fault). We pump
  /// `handle_storage` here in a bounded loop so the replica reaches `Normal`/`RecoveringHead` before
  /// the next `tick` — keeping the existing "assert state right after restart" gates stable. (The
  /// main `tick` loop also pumps `handle_storage` every tick, so an un-pumped restart would still
  /// recover; this pump is purely for test-assertion timing.)
  pub fn restart(&mut self, i: usize) {
    let cfg = Config::with_checkpoint_ops(
      1,
      ReplicaId::new(i as u8),
      self.replica_count,
      self.checkpoint_ops,
    )
    .expect("valid cluster config");
    let seed = self.seed ^ (i as u64).wrapping_mul(0x1234_5678);
    let now = self.clock.now();
    self.replicas[i] = Endpoint::recover(
      cfg,
      seed,
      LogSm::default(),
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

  /// Whether replica `i` is crashed.
  pub fn is_crashed(&self, i: usize) -> bool {
    self.crashed[i]
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
  /// Phase-B gate asserts the SUM across replicas goes `> 0` to prove the connected backup-overflow path
  /// genuinely fired (distinct from the ordinary `> self.op` state-sync trigger). Mirrors the proto's
  /// `Endpoint::below_ring_window_syncs`.
  #[doc(hidden)]
  pub fn replica_below_ring_window_syncs(&self, i: usize) -> u64 {
    self.replicas[i].below_ring_window_syncs()
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

  /// Heal all partitions (a single group).
  pub fn heal(&mut self) {
    self.groups = vec![0; self.replicas.len()];
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
        // legitimately-superseded prior-view ack), exactly the seed-151-class lesson: a per-tick proxy
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
            c.handle(m.msg);
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
      while self.replicas[ri].poll_event().is_some() {}
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
    }
    if self.faults.drop_per_mille > 0 && self.prng.chance(self.faults.drop_per_mille, 1000) {
      return;
    }
    // Roll the duplicate decision BEFORE enqueuing so the PRNG-draw order is fixed regardless of the
    // (independent) jitter draws below — keeping the run a pure function of the seed.
    let duplicate = self.faults.duplicate_per_mille > 0
      && self.prng.chance(self.faults.duplicate_per_mille, 1000);
    let deliver_at = now + self.faults.latency + Duration::from_nanos(self.jitter_ns());
    self.net.enqueue(InFlight {
      deliver_at,
      from,
      target,
      msg: msg.clone(),
      seq: 0,
    });
    if duplicate {
      // The second copy gets its OWN jitter, so it can arrive before or after the first.
      let dup_at = now + self.faults.latency + Duration::from_nanos(self.jitter_ns());
      self.net.enqueue(InFlight {
        deliver_at: dup_at,
        from,
        target,
        msg,
        seq: 0,
      });
    }
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
  fn durable_view_checker_flags_a_sync_checkpoint_above_the_durable_view() {
    // CHECKER NON-VACUITY: the durable-view oracle must flag a `SyncCheckpoint` advertising a view
    // ABOVE the emitter's durable view — the state-sync serve was previously an unchecked blind spot
    // (the checker covered StartView/RecoveryResponse/DoViewChange/Prepare/PrepareOk/Commit but NOT
    // this serve). A fresh cluster's durable view is 0; a SyncCheckpoint(view=1) is therefore a
    // participation in a not-yet-durable view and MUST trip.
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
}

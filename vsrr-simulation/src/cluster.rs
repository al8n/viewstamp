use core::time::Duration;

use vsrr_proto::{
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
  append_before_ack_violation: Option<String>,
  /// Set by [`tick`](Self::tick) when a replica emitted a primary-authority `StartView`/
  /// `RecoveryResponse` for a view that is NOT yet DURABLE on its own superblock — the
  /// durable-view-before-participate invariant (codex R8-F1), checked structurally at emission time
  /// against the sim's superblock view. These two messages assert "I am the canonical primary of view
  /// V" (a `StartView` is the primary's authoritative head broadcast; a primary's `RecoveryResponse`
  /// is the recovery-handshake equivalent), so emitting one for a `V` above the durable view means the
  /// replica participated AS the primary in a view a crash could regress out of. Stays `None` absent a
  /// violation; the VOPR driver drains it each tick via [`take_durable_view_violation`]. Inert for
  /// existing gates (they never read it).
  durable_view_violation: Option<String>,
  /// `None` (default) ⇒ every replica's WAL appends SYNCHRONOUSLY (existing-gate behaviour). `Some(d)`
  /// ⇒ async-append mode with per-append delay `d` polls — the Phase-A in-flight window the
  /// append-before-ack invariant must survive. Set via [`set_async_wal_delay`] before running;
  /// persists across `crash`/`restart` because the WAL struct does.
  async_wal_delay: Option<u32>,
  /// `None` (default) ⇒ every replica's superblock writes complete SYNCHRONOUSLY (existing-gate
  /// behaviour). `Some(d)` ⇒ async-write mode with per-write delay `d` polls — the pending
  /// durable-view window the durable-view-before-participate gate must survive (codex R8-F1). Set via
  /// [`set_async_superblock_delay`] before running; persists across `crash`/`restart` because the
  /// superblock struct does. A `crash` additionally DISCARDS any in-flight superblock write (a real
  /// crash loses an `fsync` mid-flight), so a not-yet-durable view write is genuinely lost.
  async_sb_delay: Option<u32>,
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
    let (wals, sbs) = Self::seed_storage(replicas, seed, storage_faults, None, None);
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
    }
  }

  /// Builds the per-replica seeded WAL + superblock vectors. Each replica's storage gets a distinct
  /// seed derived from the base `seed`, its index, and [`STORAGE_SEED_MAGIC`], so fault decisions are
  /// reproducible per (seed, replica) yet independent across replicas. When `async_wal_delay` is
  /// `Some`, every WAL is built in async-append mode (the in-flight window); when `async_sb_delay` is
  /// `Some`, every superblock is built in async-write mode (the pending durable-view window) — both
  /// composed with the fault plan.
  fn seed_storage(
    replicas: u8,
    seed: u64,
    faults: StorageFaults,
    async_wal_delay: Option<u32>,
    async_sb_delay: Option<u32>,
  ) -> (Vec<InMemoryWal>, Vec<InMemorySuperblock>) {
    let wals = (0..replicas)
      .map(|i| {
        let s = Self::storage_seed(seed, i);
        match async_wal_delay {
          Some(d) => InMemoryWal::with_async_appends_and_faults(faults, s, d),
          None => InMemoryWal::with_faults(faults, s),
        }
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
    );
    self.wals = wals;
    self.sbs = sbs;
  }

  /// Enables (or, with `None`, disables) **async-write mode** on every replica's superblock, with
  /// per-write delay `delay` polls. In this mode a durable-root or checkpoint write stays
  /// not-yet-durable (`state()` still names the prior root) for `delay` polls — the pending
  /// durable-view window the durable-view-before-participate gate must survive (codex R8-F1): a
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
    self.replicas[i].state_machine()
  }

  /// Replica `i`'s current view (for invariant checking).
  pub fn replica_view(&self, i: usize) -> vsrr_proto::View {
    self.replicas[i].view()
  }

  /// Replica `i`'s current checkpoint op (for invariant checking / boundedness gates).
  pub fn replica_checkpoint_op(&self, i: usize) -> vsrr_proto::OpNumber {
    self.replicas[i].checkpoint_op()
  }

  /// Replica `i`'s current head op (for the M3 gate's laggard/strand-window construction).
  pub fn replica_op(&self, i: usize) -> vsrr_proto::OpNumber {
    self.replicas[i].op()
  }

  /// Replica `i`'s current commit (`commit_min`) — the applied frontier (for the M3 gate).
  pub fn replica_commit(&self, i: usize) -> vsrr_proto::OpNumber {
    self.replicas[i].commit()
  }

  /// Replica `i`'s `commit_max` (highest op it knows is committed cluster-wide). Used by the VOPR
  /// driver's structural ordering invariant `op >= commit_max >= commit_min >= checkpoint_op`.
  pub fn replica_commit_max(&self, i: usize) -> vsrr_proto::OpNumber {
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
        vsrr_proto::SlotStatus::Clean | vsrr_proto::SlotStatus::Faulty
      )
  }

  /// Drains the most recent append-before-ack violation observed during [`tick`](Self::tick) (a
  /// replica emitted a `PrepareOk` for an op whose WAL append had not completed — `Dirty`/`Empty`), if
  /// any. Returns `None` when no violation has occurred since the last drain. The violation is recorded
  /// structurally each tick by checking every emitted `PrepareOk` against the sender's own WAL view.
  pub fn take_append_before_ack_violation(&mut self) -> Option<String> {
    self.append_before_ack_violation.take()
  }

  /// Drains the most recent durable-view-before-participate violation observed during
  /// [`tick`](Self::tick) or [`probe_pending_view_window`](Self::probe_pending_view_window) (a replica
  /// emitted a primary-authority `StartView`/`RecoveryResponse` for a view above its own durable
  /// superblock view — codex R8-F1), if any. `None` when none has occurred since the last drain.
  pub fn take_durable_view_violation(&mut self) -> Option<String> {
    self.durable_view_violation.take()
  }

  /// Record a durable-view-before-participate violation (codex R8-F1) if `out` (emitted by replica
  /// `ri`) is a primary-authority message — a `StartView`, or a `RecoveryResponse` carrying a head
  /// (non-empty log OR a non-zero op, i.e. the PRIMARY's answer, not a backup's view-only echo) — for
  /// a view STRICTLY ABOVE replica `ri`'s own DURABLE (superblock) view. Such a message asserts "I am
  /// the canonical primary of view V" in a view that is not yet recoverable, which a crash could
  /// regress out of. First violation only (subsequent ones are inert).
  fn record_durable_view_violation(&mut self, ri: usize, out: &Outgoing) {
    use vsrr_proto::Superblock;
    if self.durable_view_violation.is_some() {
      return;
    }
    let durable_view = self.sbs[ri].state().view().get();
    let (kind, msg_view) = match out.msg_ref() {
      Message::StartView(sv) => ("StartView", sv.view().get()),
      // A primary's RecoveryResponse carries the canonical head (non-empty log or op > 0); a Normal
      // backup answers with op == 0 + empty log (view-only echo), which reports its view but not a
      // head — still a participation signal, but the head-bearing primary answer is the load-bearing
      // R8-F1 case the gate suppresses. Flag the head-bearing one (op > 0).
      Message::RecoveryResponse(rr) if rr.op().get() > 0 => ("RecoveryResponse", rr.view().get()),
      _ => return,
    };
    if msg_view > durable_view {
      self.durable_view_violation = Some(format!(
        "replica {ri} emitted {kind}(view={msg_view}) while its DURABLE view is {durable_view} \
         (volatile view={}, status={}) — durable-view-before-participate (R8-F1) violated: it \
         asserted primary authority in a view not yet persisted",
        self.replicas[ri].view().get(),
        self.replicas[ri].status().as_str(),
      ));
    }
  }

  /// True iff replica `i` is the primary of its current view (for the M3 gate's failover schedule).
  pub fn replica_is_primary(&self, i: usize) -> bool {
    self.replicas[i].is_primary()
  }

  /// True iff any non-crashed replica has advanced to a view strictly greater than `v` — i.e. a real
  /// view change occurred (used by the M3 gate's liveness assertions, including forfeit-driven VCs).
  pub fn any_replica_view_advanced_beyond(&self, v: u64) -> bool {
    (0..self.replicas.len()).any(|i| !self.crashed[i] && self.replicas[i].view().get() > v)
  }

  /// Replica `i`'s in-memory `log` cache size (for the M3.4b boundedness checker). After GC this is
  /// bounded by the un-checkpointed tail + pipeline headroom.
  pub fn replica_log_len(&self, i: usize) -> usize {
    self.replicas[i].log_len()
  }

  /// Replica `i`'s primary-pipeline (`inflight`) size (for the M3.4b boundedness checker).
  pub fn replica_inflight_len(&self, i: usize) -> usize {
    self.replicas[i].inflight_len()
  }

  /// Replica `i`'s client-session table size (for the M3.4b boundedness checker). Bounded by the
  /// active client set, independent of op count.
  pub fn replica_clients_len(&self, i: usize) -> usize {
    self.replicas[i].clients_len()
  }

  /// Replica `i`'s durable WAL entry count (for the M3.4b boundedness checker). After GC this is
  /// bounded by the un-pruned tail.
  pub fn wal_len(&self, i: usize) -> usize {
    self.wals[i].len()
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
  pub fn replica_durable_view(&self, i: usize) -> vsrr_proto::View {
    use vsrr_proto::Superblock;
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
  /// `wals[i]`/`sbs[i]` are left intact so a later `restart` can recover from them — EXCEPT any
  /// superblock write still in flight (async-write mode), which a real crash loses mid-`fsync`: we
  /// `discard_inflight` it so the durable root/checkpoint stay at their last-COMPLETED values. This
  /// is what makes the pending-durable-view window (R8-F1) a genuine crash hazard — a not-yet-durable
  /// view write is actually lost, so the replica recovers to the OLD view (and the proto must never
  /// have acted in the new one). In synchronous mode this is a no-op. (Staged WAL appends are left as
  /// the existing async-WAL sweep does: a stale `Appended` completing post-restart carries a
  /// superseded `OpId` the recovered replica ignores.)
  pub fn crash(&mut self, i: usize) {
    self.crashed[i] = true;
    self.sbs[i].discard_inflight();
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
  /// checkpoint window). The async-superblock VOPR uses this to confirm the R8-F1 window is genuinely
  /// exercised (a primary sits with `pending_sb` armed while a view-change root write is in flight).
  #[doc(hidden)]
  pub fn sb_staged_len_for_test(&self, i: usize) -> usize {
    self.sbs[i].staged_len()
  }

  /// Test-only: whether replica `i` is a `Normal` primary whose current view is NOT yet durable —
  /// i.e. its volatile in-memory view is strictly ahead of its durable (superblock) view while it is
  /// the primary of that volatile view. This is EXACTLY the R8-F1 pending-durable-view window from the
  /// proto's side (`pending_sb` armed for a `StartViewAsPrimary` write). Lets the async-superblock
  /// VOPR confirm a seed actually opens the window (rather than merely staging unrelated writes).
  #[doc(hidden)]
  pub fn in_pending_primary_view_window_for_test(&self, i: usize) -> bool {
    use vsrr_proto::Superblock;
    let r = &self.replicas[i];
    let durable_view = self.sbs[i].state().view().get();
    r.status().is_normal() && r.is_primary() && r.view().get() > durable_view
  }

  /// Adversarially PROBE the R8-F1 pending-durable-view window (codex R8-F1): for every non-crashed
  /// replica that is a `Normal` primary whose view is NOT yet durable (a `StartViewAsPrimary` root
  /// write still in flight), deliver — RIGHT NOW, in this window — a `GetView` AND a `Recovery` from a
  /// peer, plus fire its timers. A correct primary must answer NEITHER (no `StartView` for the
  /// not-yet-durable view, no `RecoveryResponse` with its canonical head, no `Commit`/`Prepare`
  /// heartbeat) until the view is durable; the durability/view-monotonic checkers then catch any
  /// resulting cross-view double-participation. Returns the number of replicas probed in their window,
  /// so the sweep can assert the window is genuinely EXERCISED (not merely opened). This is the
  /// driver-side "deliver GetView/Recovery during the pending-superblock window" the R8-F1 closure
  /// needs: the window is short, so relying on incidental message/timer coincidence misses it — this
  /// makes the probe deterministic. Faithful: a delayed/duplicate `GetView`/`Recovery` and a primary
  /// timer firing in that window are exactly the real events the gate must survive.
  pub fn probe_pending_view_window(&mut self) -> u64 {
    let now = self.clock.now();
    let mut probed = 0u64;
    for i in 0..self.replicas.len() {
      if self.crashed[i] || !self.in_pending_primary_view_window_for_test(i) {
        continue;
      }
      probed += 1;
      // A peer (the next replica id) solicits — both a head (GetView) and a recovery handshake.
      let peer = vsrr_proto::ReplicaId::new(((i + 1) % self.replicas.len()) as u8);
      let from = Peer::Replica(peer);
      let view = self.replicas[i].view();
      let gv = Message::GetView(vsrr_proto::GetView::new(view, peer, 0xF1_u64));
      self.replicas[i].handle_message(now, &mut self.wals[i], &mut self.sbs[i], from, gv);
      let rec = Message::Recovery(vsrr_proto::Recovery::new(peer, 0xF2_u64));
      self.replicas[i].handle_message(now, &mut self.wals[i], &mut self.sbs[i], from, rec);
      // Fire the primary timers too (the `primary_timeouts` heartbeat/retransmit gate).
      self.replicas[i].handle_timeout(now, &mut self.wals[i], &mut self.sbs[i]);
      // Inspect EVERYTHING the probe made the replica emit: a correct (gated) primary emits no
      // StartView/RecoveryResponse for its not-yet-durable view; an ungated one does → R8-F1
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

  /// Test-only (M3.4a): how many state-syncs have fully applied + become durable on replica `i` since
  /// it was last constructed (`new`/`restart`). The state-sync gate asserts the restarted laggard's
  /// count goes from 0 to `>= 1` — proving it genuinely STATE-SYNCED (fetched + restored a checkpoint
  /// past its head) rather than merely catching up op-by-op via retransmit. Mirrors the proto's
  /// `Endpoint::state_syncs_applied` observability counter.
  #[doc(hidden)]
  pub fn replica_state_sync_count(&self, i: usize) -> u64 {
    self.replicas[i].state_syncs_applied()
  }

  /// Test-only (M3.5 T6): how many of replica `i`'s applied syncs were FORCED (the escalation that
  /// recovers a pruned committed hole below the quorum checkpoint), as opposed to ordinary `> self.op`
  /// state-syncs. The focused force-sync gate asserts this goes `> 0` to prove the FORCED path fired
  /// specifically. Mirrors the proto's `Endpoint::forced_syncs_applied`.
  #[doc(hidden)]
  pub fn replica_forced_sync_count(&self, i: usize) -> u64 {
    self.replicas[i].forced_syncs_applied()
  }

  /// Test-only: how many of replica `i`'s WAL slots in `1..=op` are PERMANENTLY corrupt (bit-rot or
  /// torn) — i.e. would read back faulty. The M3.3b permanent-fault gate uses this to assert recovery
  /// is non-vacuous (the crashed replica genuinely must peer-repair some rotted committed slot).
  #[doc(hidden)]
  pub fn wal_corrupt_slots_at_or_below_for_test(&self, i: usize, op: u64) -> usize {
    self.wals[i].corrupt_slots_at_or_below_for_test(op)
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
        if let Message::PrepareOk(ok) = out.msg_ref() {
          let op = ok.op();
          if op.get() > 0
            && !self.replica_appended_op(ri, op)
            && self.append_before_ack_violation.is_none()
          {
            let r = &self.replicas[ri];
            self.append_before_ack_violation = Some(format!(
              "replica {ri} emitted PrepareOk(op={}) but its WAL append has not completed \
               (wal_status={}, view={}, status={}, op={}, commit_min={}, commit_max={}, \
               checkpoint_op={}) — append-before-ack violated",
              op.get(),
              self.wals[ri].status(op).as_str(),
              r.view().get(),
              r.status().as_str(),
              r.op().get(),
              r.commit().get(),
              r.commit_max().get(),
              r.checkpoint_op().get(),
            ));
          }
        }
        // Durable-view-before-participate (R8-F1), checked at emission: a StartView / head-bearing
        // RecoveryResponse for a view above the emitter's durable view is a participation in a
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
}

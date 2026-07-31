use std::{net::SocketAddr, time::Duration};

use agnostic::{
  Runtime,
  net::{Net, UdpSocket},
};
use viewstamp_proto::{
  BlockStore, ClientId, Config, Event, IdentityConfig, Instant, MemberId, Membership, Peer,
  ProvidedIdentity, QuicCoordinator, QuicOptions, ReplicaId, Request, RequestNumber, StateMachine,
  Superblock, Wal,
};

use viewstamp_driver::{
  Clock, Command, DriverConfig, DriverError, Handle, InflightBudget, Pending, PendingMap,
  Retirement, ShutdownReport, StorageQuiescence, build_endpoint, deliver_event, drain_pending,
  drain_storage, finish_reconfigure_on_retire, gate_command_on_retirement, jittered,
  pending_scan_interval, reap_and_collect_retransmits, retire,
};

const RECV_BUF_LEN: usize = 65_507; // IP-layer max UDP payload

/// Backoff before re-arming `recv_from` after a receive error. While it is pending the recv arm
/// is DISABLED (a never-ready future substitutes for the read) and this deadline folds into the
/// run loop's timer arm like every other wake deadline, so commands and timers keep running and a
/// persistent synchronously-resolving receive error cannot hot-spin the loop re-arming a failing
/// read.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// Redial state for one configured peer. The driver retains every configured `(id, addr)` so a
/// connection that idles out or is lost can be re-established by THIS side — without it, a dead mesh
/// edge stays dead until the peer happens to dial back, and a view change that needs that edge
/// retransmits to no bound conn forever.
struct PeerLink {
  id: ReplicaId,
  /// The stable member identity currently occupying this slot; used by `rekey_peers` to detect
  /// when a slot's occupant has changed across a config swap and the old connection must be closed.
  member_id: MemberId,
  addr: SocketAddr,
  /// Delay before the next redial once the link is observed unbound; doubles per attempt up to the
  /// configured redial cap, reset to the configured base whenever the link binds. The base also
  /// serves as the ARM delay before the first redial fires, which gives an in-flight dial/handshake
  /// (construction dials, or a previous redial) time to bind before another dial is layered on top.
  backoff: Duration,
  /// When the next redial may fire; `None` while the link is bound (or until an unbound observation
  /// arms it).
  next_dial: Option<Instant>,
}

/// The reactor (readiness) QUIC driver, generic over the [`agnostic`] runtime. Owns the
/// coordinator + storage + socket on one task; the run loop's recv arm reads the socket directly —
/// a readiness `recv_from` borrows the driver's one receive buffer and consumes nothing when a
/// losing select arm drops it — so no helper task or socket clone exists.
pub struct ReactorQuicDriver<R: Runtime, S, W, B, L, I> {
  coord: QuicCoordinator<S, I>,
  wal: W,
  sb: B,
  /// Embedder-provided content-addressed block store, the peer of `wal`/`sb` in the node's durable
  /// store: large bodies (state-sync chunks, snapshots) are addressed by content hash here while the
  /// WAL/superblock hold the consensus log and durable root.
  ///
  /// A PRODUCTION block store MUST be PERSISTENT, and its blocks MUST be durable before the checkpoint
  /// that references them: the proto writes a checkpoint's blocks, then calls
  /// [`BlockStore::flush`](viewstamp_proto::BlockStore::flush) and only advances the durable checkpoint
  /// pointer once the flush returns `Ok` — so a real `flush` must `fsync`/barrier its pending writes and
  /// report a failure as `Err`. The in-memory store the driver tests use is durable-enough for a process
  /// that never crashes, but loses its blocks on restart and is NOT suitable for production.
  blocks: L,
  socket: <R::Net as Net>::UdpSocket,
  /// The recv arm's driver-lifetime receive buffer ([`RECV_BUF_LEN`]). There is no user-space
  /// inbound queue: the run loop receives at most one datagram per iteration, and further
  /// arrivals queue in — then overflow — the kernel socket buffer. That is exactly UDP socket
  /// backpressure, whose drops QUIC's own loss recovery already absorbs.
  recv_buf: Box<[u8]>,
  /// While `Some`, the most recent `recv_from` failed and the recv arm is disabled until this
  /// deadline passes (see [`RECV_ERROR_BACKOFF`]). Folded into [`Self::next_deadline`] so the
  /// re-enabling wake is a REAL wake deadline, never a hope that other traffic wakes the loop.
  recv_backoff_until: Option<std::time::Instant>,
  clock: Clock,
  /// The operational tuning this driver was constructed with ([`DriverConfig::new`] via
  /// [`Self::new`], or the embedder's override via [`Self::with_config`]).
  cfg: DriverConfig,
  client: ClientId,
  next_request: u64,
  pending: PendingMap,
  /// When the next in-flight `pending` scan (cancellation reclaim + retransmit collection) may
  /// run — the deadline gate on [`Self::retransmit_stale`]'s O(in-flight) walk. Starts at zero so
  /// a fresh driver's first scan is never deferred; each scan re-arms it one
  /// `pending_scan_interval` ahead, and [`Self::next_deadline`] folds it in (while anything is
  /// pending) so a parked driver wakes ON the scan schedule.
  next_pending_scan: Instant,
  /// The configured peer mesh with per-peer redial backoff state (see [`PeerLink`]); reconciled
  /// against the coordinator's bound-connection table every loop iteration.
  peers: Vec<PeerLink>,
  /// Peer address book: maps each peer's stable [`MemberId`] to its network address, populated via
  /// [`Command::AddPeer`] and seeded from the initial peer list at construction.
  peer_book: std::collections::HashMap<MemberId, SocketAddr>,
  /// Membership config gate: detects when the live config_id changes so `rekey_peers` runs exactly
  /// once per install, even when `pump_outputs` loops or `handle_timeout` triggers an install.
  reconciler: viewstamp_driver::MembershipReconciler,
  /// A clone of the shared in-flight submit budget, retained for test observability only. Production
  /// release is by construction: the `Handle` reserves a [`ReservationGuard`] per submit, the guard
  /// rides the `Command::Submit` then the `Pending` entry, and dropping that entry (commit,
  /// cancellation reclaim, shutdown drain) — or the queued command on teardown — releases the slot, so
  /// the driver itself never releases against this handle.
  #[cfg(test)]
  budget: InflightBudget,
  /// Shared write-once terminal retirement signal, latched by the run loop's event pump when this
  /// endpoint removes itself from the configuration. Its `Handle` clone reads it to fail submits
  /// terminally (see [`retire`] and [`Handle::submit`]).
  retired: Retirement,
  /// Bounded `futures_channel::mpsc::channel(cfg.cmd_cap())`: a refused send surfaces as `Busy`
  /// rather than growing, and `Receiver::close` is the teardown primitive — it refuses new sends
  /// (bouncing the command back to its sender) while this receiver still drains what was already
  /// buffered, so the shutdown ack can promise no queued command survives it.
  commands: futures_channel::mpsc::Receiver<Command>,
  /// Bounded `flume::bounded(cfg.events_cap())`: best-effort, dropped-on-full (see `deliver_event`).
  events: flume::Sender<Event>,
  /// Embedder-owned notifier. Carries a unit signal only and is drained to empty every loop iteration
  /// (`while self.storage_ready.try_recv().is_ok() {}`), so the driver retains at most the in-flight
  /// signals queued within one iteration — no per-submit growth.
  storage_ready: flume::Receiver<()>,
  /// Latched once every notifier sender has dropped. The notifier is a wake-latency optimization,
  /// not a liveness dependency — `pump_outputs` runs `handle_storage` every iteration regardless —
  /// so an embedder dropping every clone merely downgrades storage completions to timer cadence.
  /// The latch is what makes that degradation SAFE: a disconnected flume receiver resolves
  /// `recv_async` immediately (and forever), so without it the dead channel would turn the storage
  /// arm into an always-ready select winner and the loop into a hot spin that never parks.
  storage_notifier_closed: bool,
  /// In-flight reconfiguration job, or `None`. At most one job at a time; a second
  /// `Command::Reconfigure` while `Some` is rejected immediately.
  reconfigure: Option<viewstamp_driver::ReconfigureJob>,
  /// When the next voter-liveness-probe round is due while a reconfiguration job is in flight, or
  /// `None` when no job is active. Paced at `DriverConfig::health_probe_interval`; probe traffic
  /// exists ONLY while a shrink job runs.
  next_probe_at: Option<Instant>,
}

impl<R, S, W, B, L> ReactorQuicDriver<R, S, W, B, L, ProvidedIdentity>
where
  R: Runtime,
  S: StateMachine,
  W: Wal,
  B: Superblock,
  L: BlockStore,
{
  /// Construct the driver over the sealed identity (`with_identity`) path and return a `Handle`.
  ///
  /// `opts` is the embedder-built [`QuicOptions`] (its `ClusterTls` carries the cluster roots +
  /// this replica's cert/key); `storage_ready` is the receiver half of a notifier the embedder's
  /// `W`/`B` signal whenever a completion becomes pollable. `peers` maps every OTHER replica id to
  /// its UDP address.
  ///
  /// `wal` + `sb` are the node's durable store, owned by the driver from here on. The constructor
  /// INSPECTS them to choose the boot path — recover-or-new is structural, not a flag: a genesis
  /// store (the fresh-cluster root AND an empty WAL) boots a fresh endpoint (`Normal`, view 0),
  /// while ANY durable state reconstructs the endpoint via `Endpoint::recover`, resuming the
  /// durable view in `Recovering` status and re-verifying the WAL tail through the normal run-loop
  /// pumps (recovery needs no special-casing there). A restart therefore can never silently
  /// discard the durable view/log — the VSR amnesia hazard. The supplied handles MUST carry no
  /// in-flight storage ops from a prior endpoint incarnation (the [`viewstamp_proto::OpId`]
  /// lifetime contract: the id sequence restarts per endpoint, so a stale completion could alias a
  /// fresh op's id): a real crash satisfies this by construction — in-flight ops die with the
  /// process — and an embedder that re-opens storage in-process must drain or cancel first. The
  /// endpoint's recovery nonce is derived fresh per construction (wall-clock-mixed, NOT from
  /// `rng_seed`), as recovery freshness requires; `rng_seed` feeds only the QUIC coordinator.
  ///
  /// `client` + `first_request` are the durable client session, supplied by the embedder (like
  /// storage). The cluster's per-client session-dedup table is durable consensus state, so a request
  /// number is only safe to mint if it is strictly greater than any the cluster has already served
  /// for this `client`. A request number it has served is treated as a duplicate and answered with a
  /// cached `Reply` — never a fresh committed event — so a `submit` waiting on that event would hang.
  /// To avoid this the embedder MUST either use a fresh [`ClientId`] for every process, or persist
  /// `first_request` (the last request number it used) and restore it on restart. The first request
  /// this driver mints is numbered `first_request + 1`; on a fresh start pass `first_request = 0`.
  ///
  /// # Errors
  /// [`DriverError::Bind`] if the socket cannot bind; [`DriverError::Connect`] if a dial fails.
  #[allow(clippy::too_many_arguments)]
  pub async fn new(
    config: Config,
    membership: Membership,
    state_machine: S,
    wal: W,
    sb: B,
    blocks: L,
    client: ClientId,
    first_request: u64,
    opts: QuicOptions,
    identity: IdentityConfig,
    rng_seed: Option<[u8; 32]>,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    storage_ready: flume::Receiver<()>,
  ) -> Result<(Self, Handle), DriverError> {
    Self::with_config(
      config,
      membership,
      state_machine,
      wal,
      sb,
      blocks,
      client,
      first_request,
      opts,
      identity,
      rng_seed,
      bind_addr,
      peers,
      storage_ready,
      DriverConfig::new(),
    )
    .await
  }

  /// As [`Self::new`] but with an embedder-supplied [`DriverConfig`] (timeouts, backoff, submit
  /// caps) instead of the defaults. `cfg` carries operational tuning only; the consensus/transport
  /// security configuration stays in `opts` + `identity`.
  ///
  /// # Errors
  /// [`DriverError::ProbeIntervalNotBelowMaxAge`] if `cfg.health_probe_interval()` is not strictly
  /// below `cfg.health_proof_max_age()`; [`DriverError::Bind`] if the socket cannot bind;
  /// [`DriverError::Connect`] if a dial fails.
  #[allow(clippy::too_many_arguments)]
  pub async fn with_config(
    config: Config,
    membership: Membership,
    state_machine: S,
    mut wal: W,
    mut sb: B,
    mut blocks: L,
    client: ClientId,
    first_request: u64,
    opts: QuicOptions,
    identity: IdentityConfig,
    rng_seed: Option<[u8; 32]>,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    storage_ready: flume::Receiver<()>,
    cfg: DriverConfig,
  ) -> Result<(Self, Handle), DriverError> {
    // Refuse a probe cadence that cannot fit inside the round it retransmits. The executor re-solicits
    // every `health_probe_interval` WITHIN a round that lives `health_proof_max_age`; unless the cadence
    // is strictly shorter than the round, the round would expire before it could be retransmitted and a
    // live voter's reply could never land in the window, stalling every shrink fail-closed.
    // Misconfiguration is a constructor error, not a load condition.
    if cfg.health_probe_interval() >= cfg.health_proof_max_age() {
      return Err(DriverError::ProbeIntervalNotBelowMaxAge {
        interval: cfg.health_probe_interval(),
        max_age: cfg.health_proof_max_age(),
      });
    }
    let clock = Clock::new();
    let socket = <R::Net as Net>::UdpSocket::bind(bind_addr)
      .await
      .map_err(DriverError::Bind)?;

    let endpoint = build_endpoint(
      config,
      membership,
      state_machine,
      &mut wal,
      &mut sb,
      &mut blocks,
    )?;
    let mut coord = QuicCoordinator::with_identity(endpoint, opts, rng_seed, identity);

    let now = clock.now();
    let mut peer_links = Vec::with_capacity(peers.len());
    let mut peer_book = std::collections::HashMap::new();
    for (id, addr) in peers {
      coord
        .connect(now, addr, Peer::Replica(id))
        .map_err(|_| DriverError::Connect {
          peer: Peer::Replica(id),
        })?;
      // Resolve the initial slot to its MemberId so `rekey_peers` can detect slot shifts.
      let member_id = coord
        .endpoint()
        .member_at(id)
        .unwrap_or(MemberId::new(u128::MAX));
      if member_id.get() != u128::MAX {
        peer_book.insert(member_id, addr);
      }
      // Retain the configured target: the run loop's reconcile redials it if this connection (or
      // any later one) is lost.
      peer_links.push(PeerLink {
        id,
        member_id,
        addr,
        backoff: cfg.redial_backoff_base(),
        next_dial: None,
      });
    }
    let reconciler = viewstamp_driver::MembershipReconciler::new(coord.endpoint().config_id());

    // Bounded command channel: a partitioned/slow driver (not draining commands) can't grow it
    // without bound; a refused send surfaces as `DriverError::Busy` (see `Handle::submit`). Sized
    // `cmd_cap` (= max_inflight + 1) so the in-flight budget, not this queue, is the binding submit
    // limit. futures-mpsc rather than flume for its `Receiver::close`: the teardown must refuse
    // new commands while still draining the buffered ones — flume frees buffered items only when
    // every sender (every live `Handle` clone) drops, which would pin a queued submit's reply and
    // budget past the shutdown ack.
    let (commands_tx, commands_rx) = futures_channel::mpsc::channel(cfg.cmd_cap());
    // Bounded best-effort: a slow/absent `Handle::events()` consumer drops events rather than
    // growing the channel without bound (see `deliver_event`). Submit replies are unaffected.
    let (events_tx, events_rx) = flume::bounded(cfg.events_cap());
    let budget = InflightBudget::new(cfg.max_inflight(), cfg.max_pending_bytes());
    let retired = Retirement::new();
    let driver = Self {
      coord,
      wal,
      sb,
      blocks,
      socket,
      recv_buf: vec![0u8; RECV_BUF_LEN].into_boxed_slice(),
      recv_backoff_until: None,
      clock,
      cfg,
      client,
      next_request: first_request,
      pending: PendingMap::new(),
      next_pending_scan: Instant::ZERO,
      peers: peer_links,
      peer_book,
      reconciler,
      #[cfg(test)]
      budget: budget.clone(),
      retired: retired.clone(),
      commands: commands_rx,
      events: events_tx,
      storage_ready,
      storage_notifier_closed: false,
      reconfigure: None,
      next_probe_at: None,
    };
    let handle = Handle::new(commands_tx, events_rx, budget, retired);
    Ok((driver, handle))
  }
}

impl<R, S, W, B, L, I> ReactorQuicDriver<R, S, W, B, L, I>
where
  R: Runtime,
  S: StateMachine,
  W: Wal,
  B: Superblock,
  L: BlockStore,
  I: viewstamp_proto::IdentitySource,
{
  /// The number of connection closes attributed to `cause` so far — forwards the coordinator's
  /// per-cause close counter (the QUIC analogue of the stream driver's `conn_close_count`).
  /// Test/diagnostic observability, not a stable embedder API (hence `#[doc(hidden)]`).
  #[doc(hidden)]
  pub fn conn_close_count(&self, cause: viewstamp_proto::CloseCause) -> u64 {
    self.coord.conn_close_count(cause)
  }

  /// Run the driver to completion. Returns on a `Shutdown` command or when all `Handle` clones drop.
  ///
  /// Both orderly exits — and therefore the ack a [`Handle::shutdown`] awaits — are STORAGE-QUIESCE
  /// and fd-release barriers. The teardown first drains the endpoint's in-flight WAL/superblock ops
  /// (bounded; see [`Self::quiesce_storage`]) so an orderly stop is distinguishable from a crash,
  /// and reports the outcome in the ack's [`ShutdownReport`]. It then drops the socket — the driver
  /// is its SOLE owner (the recv arm borrows it in-loop; no helper task holds a clone), so that drop
  /// closes the fd synchronously — and an embedder may bind a new driver to the same address the
  /// moment `shutdown().await` (or an awaited `run()` task) returns. Cancelling the `run()` future
  /// itself releases the fd just as promptly — dropping the future drops the whole driver, socket
  /// included — but it skips the storage drain (drop glue cannot await) and reaching that
  /// cancellation is runtime-specific: aborting the spawned task cancels everywhere, while dropping
  /// a raw spawn handle does NOT (tokio detaches, leaving the task running and the socket owned;
  /// smol cancels). The portable stop paths are [`Handle::shutdown`], dropping every `Handle`, or an
  /// explicit task abort.
  pub async fn run(mut self) {
    use futures_util::{FutureExt, select_biased};

    /// Per-iteration command drain budget: bound the iter-top fairness step so a steady command
    /// stream can't itself starve the I/O select, while still letting `Shutdown`/`Submit` make
    /// progress under a recv flood.
    const CMD_BUDGET: usize = 64;

    let now = self.clock.now();
    self.pump_outputs(now).await;

    let mut shutdown_ack: Option<futures_channel::oneshot::Sender<ShutdownReport>> = None;
    loop {
      let now = self.clock.now();

      // (1) Fairness: drain up to CMD_BUDGET commands before the biased I/O select, so a continuous
      // recv backlog (e.g. a UDP flood that always wins the `recv_fut` arm) can't starve
      // `Shutdown`/`Submit`.
      let mut exit = false;
      for _ in 0..CMD_BUDGET {
        match self.commands.try_recv() {
          Ok(cmd) => {
            if self.handle_command(now, cmd, &mut shutdown_ack) {
              exit = true;
              break;
            }
          }
          // No command buffered right now: stop draining and fall through to the I/O select.
          Err(futures_channel::mpsc::TryRecvError::Empty) => break,
          // All `Handle` clones dropped AND the buffer is drained: the command channel has ended
          // for good, so exit the run loop (a continuously-readable socket would otherwise keep
          // the biased recv arm hot and the task + socket alive forever). Termination is the
          // stream END, not a sender-count probe: commands queued by since-dropped handles flow
          // through the arm above first, bounded by the channel buffer.
          Err(futures_channel::mpsc::TryRecvError::Closed) => {
            exit = true;
            break;
          }
        }
      }
      if exit {
        break;
      }

      // (2) Fairness: fire an already-due consensus/QUIC timer before the select, so a recv flood
      // can't suppress heartbeats/view-changes (which would wedge liveness). The due-check spans the
      // EARLIEST of the QUIC/auth deadline and the consensus deadline (`QuicCoordinator::poll_timeout`
      // is the QUIC deadline ONLY; the consensus timer is folded in via `earliest_deadline`), so a due
      // consensus heartbeat/view-change fires here even while a backlog keeps the biased recv arm hot.
      // `handle_timeout` on a not-yet-due timer is a no-op, so this is idempotent-safe.
      if self
        .earliest_deadline()
        .is_some_and(|d| d <= std::time::Instant::now())
      {
        self
          .coord
          .handle_timeout(now, &mut self.wal, &mut self.sb, &mut self.blocks);
        self.rekey_if_needed(now);
      }
      self.retransmit_stale(now);
      // Redial any configured peer with no bound connection (iter-top), BEFORE the pump so a
      // fresh dial's handshake Initial transmits this iteration rather than after the next select
      // wake.
      self.reconcile_peer_links(now);
      self.pump_outputs(now).await;
      self.advance_reconfigure(now);

      // Re-enable the recv arm once its error backoff has elapsed; the backoff deadline is folded
      // into `next_deadline` below, so this observation is a real wake, not a poll.
      if self
        .recv_backoff_until
        .is_some_and(|until| until <= std::time::Instant::now())
      {
        self.recv_backoff_until = None;
      }

      // Recompute AFTER the iter-top timer fire so it reflects the next deadline (avoids a redundant
      // immediate select-timer fire for the timer we just serviced).
      let deadline = self.next_deadline();

      // The four futures BORROW disjoint driver fields (`recv_fut` holds `&self.socket` +
      // `&mut self.recv_buf`, `cmd_fut` `&mut self.commands`, `storage_fut`
      // `&self.storage_ready`). Confine their construction + `select_biased!` to this inner
      // scope: when it ends the pinned futures drop, releasing those borrows so the `&mut self`
      // pumping below is legal. Each arm only writes a captured local; no whole-`self` work
      // happens in an arm. Losing the select is free for every arm: the timer/channel waits are
      // plain restartable waits, and the readiness `recv_from` consumes nothing unless it
      // completed — a datagram it did not return stays in the kernel buffer for the next
      // iteration's arm.
      let (inbound, recv_err, fire_timeout, command, exit, storage_closed) = {
        let recv_fut = match self.recv_backoff_until {
          // The recv arm IS the socket read: a by-ref readiness receive into the driver-lifetime
          // buffer, cancel-safe to lose.
          None => self.socket.recv_from(&mut self.recv_buf).left_future(),
          // Error backoff pending: park the arm on a never-ready future; the timer arm (which
          // folds the backoff deadline) re-runs the loop to re-enable it.
          Some(_) => {
            futures_util::future::pending::<std::io::Result<(usize, SocketAddr)>>().right_future()
          }
        }
        .fuse();
        let timer_fut =
          R::sleep(deadline.saturating_duration_since(std::time::Instant::now())).fuse();
        let cmd_fut = self.commands.recv().fuse();
        // A disconnected notifier resolves `recv_async` immediately and forever; once latched the
        // arm parks on a never-ready future so the dead channel cannot keep the select hot (see
        // the `storage_notifier_closed` field).
        let storage_fut = if self.storage_notifier_closed {
          futures_util::future::pending::<Result<(), flume::RecvError>>().right_future()
        } else {
          self.storage_ready.recv_async().left_future()
        }
        .fuse();
        futures_util::pin_mut!(recv_fut, timer_fut, cmd_fut, storage_fut);

        let mut inbound: Option<(usize, SocketAddr)> = None;
        let mut recv_err = false;
        let mut fire_timeout = false;
        let mut command: Option<Command> = None;
        let mut exit = false;
        let mut storage_closed = false;

        select_biased! {
            got = recv_fut => {
                match got {
                    Ok((len, from)) => inbound = Some((len, from)),
                    Err(_) => recv_err = true,
                }
            }
            _ = timer_fut => { fire_timeout = true; }
            cmd = cmd_fut => {
                match cmd { Ok(c) => command = Some(c), Err(_) => exit = true }
            }
            s = storage_fut => { storage_closed = s.is_err(); }
        }
        (
          inbound,
          recv_err,
          fire_timeout,
          command,
          exit,
          storage_closed,
        )
      };
      while self.storage_ready.try_recv().is_ok() {}
      if storage_closed {
        self.storage_notifier_closed = true;
      }
      if exit {
        break;
      }

      let now = self.clock.now();
      if let Some((len, from)) = inbound {
        self.handle_inbound_datagram(now, len, from);
      }
      if recv_err {
        // A receive error is transient for an unconnected UDP socket (anything lost under it is
        // QUIC's loss recovery to repair), so the socket stays in service — but the arm parks on
        // this backoff first, bounding the retry rate so a persistent error cannot hot-spin the
        // loop.
        self.recv_backoff_until = Some(std::time::Instant::now() + RECV_ERROR_BACKOFF);
      }
      if fire_timeout {
        self
          .coord
          .handle_timeout(now, &mut self.wal, &mut self.sb, &mut self.blocks);
        self.rekey_if_needed(now);
      }
      if let Some(cmd) = command
        && self.handle_command(now, cmd, &mut shutdown_ack)
      {
        break;
      }
      self.retransmit_stale(now);
      self.pump_outputs(now).await;
    }

    // Drop every still-pending submit (its commit never arrived) and clear the map: each entry's
    // `ReservationGuard` releases its budget slot on drop, so the budget never leaks across the
    // driver's life. A `Submit` still queued in the command channel releases in the
    // close-then-drain below, its guard with it.
    drain_pending(&mut self.pending);
    // The durability barrier, before anything is released: the run loop has exited, so nothing
    // further enters consensus, and the endpoint's outstanding WAL/superblock ops are drained to
    // quiescence (or to the bounded deadline) while its storage handles are still owned here. It
    // runs AFTER `drain_pending` so a caller awaiting a submit is released immediately rather than
    // being held for the drain window — the entries dropped there are driver-side bookkeeping and
    // touch neither the endpoint nor the store.
    let storage = self.quiesce_storage().await;
    // The command channel is the one queue whose senders OUTLIVE the driver (every `Handle`
    // clone), so its release must not depend on them dropping: close-then-drain makes the queued
    // commands airtight at the ack. `close()` turns the channel non-admitting — a `Handle` racing
    // this teardown has its `try_send` refused WITH the command, so its own rollback path runs
    // (DriverGone, reservation released) — while this receiver can still drain everything already
    // buffered. The AWAITED drain then releases every pre-close command: each dropped `Submit`
    // frees its budget reservation and its reply oneshot resolves as dropped (`ReplyDropped` at
    // the caller). Awaiting (rather than a non-blocking try loop) matters because a send racing
    // the close can have reserved its place with the push itself still in flight; the channel
    // ends only at closed-AND-empty, so the drain observes that command too. No command —
    // queued or in flight — survives the ack.
    self.commands.close();
    while let Ok(cmd) = self.commands.recv().await {
      drop(cmd);
    }
    // The fd-release point: the driver is the socket's SOLE owner — the recv arm's borrow died
    // with the loop, and no helper task holds a clone — so this drop closes the fd synchronously.
    // Once it returns the bound address is free, which is what makes the ack below (and `run()`'s
    // return) an immediate-rebind contract.
    drop(self.socket);
    if let Some(ack) = shutdown_ack {
      let _ = ack.send(ShutdownReport::new(storage));
    }
  }

  /// Drain the endpoint's in-flight storage at teardown, bounded by
  /// [`SHUTDOWN_DRAIN_DEADLINE`](viewstamp_driver::SHUTDOWN_DRAIN_DEADLINE).
  ///
  /// Each pass feeds the backend's ready completions through the endpoint — the same
  /// `handle_storage` the run loop pumps — and stops as soon as the endpoint owes none. Only the
  /// storage half is pumped: outputs a completion produces (datagrams, events) belong to a driver
  /// that is still running, and this one is releasing its socket next.
  async fn quiesce_storage(&mut self) -> StorageQuiescence {
    drain_storage(
      || {
        let now = self.clock.now();
        self
          .coord
          .handle_storage(now, &mut self.wal, &mut self.sb, &mut self.blocks);
        !self.coord.endpoint().has_inflight_storage()
      },
      R::sleep,
    )
    .await
  }

  /// Handle one [`Command`]; returns `true` when the loop should exit (a `Shutdown`).
  ///
  /// Shared by the iter-top fairness drain and the select's command arm so the `Submit`/`Shutdown`
  /// handling lives in one place.
  fn handle_command(
    &mut self,
    now: Instant,
    cmd: Command,
    shutdown_ack: &mut Option<futures_channel::oneshot::Sender<ShutdownReport>>,
  ) -> bool {
    // Gate on the retirement latch at CONSUMPTION time: a Submit/Reconfigure buffered (or racing the
    // Handle's preflight) before the run loop latched retirement is resolved terminally here rather
    // than handed to an endpoint that can never commit it. Shutdown/AddPeer pass through unchanged.
    let Some(cmd) = gate_command_on_retirement(&self.retired, cmd) else {
      return false;
    };
    match cmd {
      Command::Submit {
        body,
        reply,
        reservation,
      } => {
        // A submit whose caller is already gone (the reply future dropped) must not enter
        // consensus: nobody can observe its commit, and the cancellation reap would only evict it
        // AFTER it minted a request. Dropping it here releases its reservation immediately. This
        // is also what keeps the teardown drain equivalent to discarding: queued submits from
        // dropped handles are dead by definition.
        if reply.is_canceled() {
          drop(reservation);
          return false;
        }
        self.next_request += 1;
        let request_number = RequestNumber::with(self.next_request);
        let request = Request::new(self.client, request_number, body);
        // MOVE the reservation guard into the `Pending` entry: from here the entry owns the budget
        // slot, and dropping it (on commit, cancellation reclaim, or shutdown drain) releases.
        self.pending.insert(
          (self.client, request_number),
          Pending {
            reply,
            request: request.clone(),
            last_sent: now,
            reservation,
          },
        );
        self.coord.submit_client_request(
          now,
          &mut self.wal,
          &mut self.sb,
          &mut self.blocks,
          request,
        );
        false
      }
      Command::Shutdown { ack } => {
        *shutdown_ack = Some(ack);
        true
      }
      Command::Reconfigure {
        target,
        health,
        ack,
        reply,
      } => {
        if self.reconfigure.is_some() {
          let _ = reply.send(Err(viewstamp_driver::ReconfigureError::Propose(
            viewstamp_proto::ProposeMembershipError::AlreadyInFlight,
          )));
        } else {
          // Solicit the first voter-liveness-probe round now (and re-solicit every
          // health_probe_interval while the job runs); snapshot the proven-live voters for the executor.
          self
            .coord
            .solicit_health_proofs(now, self.cfg.health_proof_max_age());
          self.next_probe_at = Some(now + self.cfg.health_probe_interval());
          let live = self.coord.live_membership();
          let fresh = self.coord.proven_live_voters(now);
          self.reconfigure = Some(viewstamp_driver::ReconfigureJob::start(
            target,
            health,
            self.cfg.reconfigure_timeout(),
            reply,
            live,
            fresh,
            self.coord.endpoint().local(),
            ack,
          ));
        }
        false
      }
      Command::AddPeer { member_id, addr } => {
        self.peer_book.insert(member_id, addr);
        // If the added member is ALREADY in the live membership, the config install was observed
        // before its address arrived, so `rekey_peers` skipped it (no address) and advanced
        // `last_known_config_id`. Without forcing a rebuild here it would stay undialed until some
        // later, unrelated membership change. Rebuild the dial list against the current config now —
        // now that its address is known — so the now-present member is dialed immediately. Skipped for
        // a member not yet in the membership (its dial is armed when the install lands) and for self.
        if member_id != self.coord.endpoint().local()
          && self.coord.endpoint().slot_of(member_id).is_some()
        {
          self.rekey_peers(now);
        }
        false
      }
    }
  }

  /// Advance the in-flight reconfiguration job by one iteration, if any. Re-solicits the liveness
  /// probe on cadence, then reads the live membership and proven-live voter set from the coordinator
  /// (disjoint borrow: coordinator is read first, then the job takes `&mut self`), and calls
  /// `job.advance` with a closure that proposes a delta.
  fn advance_reconfigure(&mut self, now: Instant) {
    let Some(mut job) = self.reconfigure.take() else {
      return;
    };
    // Re-solicit the voter-liveness-probe round on the probe cadence while the job runs: each call
    // RETRANSMITS the outstanding round's nonce until it expires, then opens a fresh round. A voter
    // that crashed since the round opened drops out of the proven-live set at the round's rollover,
    // within one `health_proof_max_age`.
    if self.next_probe_at.is_none_or(|at| now >= at) {
      self
        .coord
        .solicit_health_proofs(now, self.cfg.health_proof_max_age());
      self.next_probe_at = Some(now + self.cfg.health_probe_interval());
    }
    let live = self.coord.live_membership();
    let fresh = self.coord.proven_live_voters(now);
    let outcome = job.advance(now, live, fresh, &mut |delta, ack| {
      self
        .coord
        .propose_membership(now, &mut self.wal, delta, ack)
    });
    if !matches!(outcome, viewstamp_driver::AdvanceOutcome::Done) {
      self.reconfigure = Some(job);
    } else {
      self.next_probe_at = None;
    }
  }

  /// The earliest REAL wake deadline — the nearest of the QUIC/auth deadline and the consensus
  /// deadline — excluding the idle fallback, or `None` when neither is armed.
  ///
  /// `QuicCoordinator::poll_timeout` reports only the QUIC/auth deadline (in `std::time::Instant`);
  /// the consensus timer — a viewstamp `Instant` from the endpoint — is the driver's to fold in, so a
  /// view-change/heartbeat deadline is seen even while QUIC itself is idle. Single source of truth for
  /// both the iter-top fairness due-check and `next_deadline`, so they can never diverge on which
  /// deadlines count.
  fn earliest_deadline(&mut self) -> Option<std::time::Instant> {
    let quic = self.coord.poll_timeout();
    let consensus = self
      .coord
      .endpoint()
      .poll_timeout()
      .map(|t| self.clock.to_std(t));
    [quic, consensus].into_iter().flatten().min()
  }

  /// Nearest of the earliest real deadline ([`Self::earliest_deadline`]), the earliest armed peer
  /// redial, the next pending scan, the recv-error backoff, and a 50ms idle fallback (so a quiet
  /// node still re-pumps storage). The redial, scan, and backoff deadlines are folded in as REAL
  /// wake deadlines so redialing, the gated `pending` scan, and the recv arm's re-enable never
  /// depend on the idle fallback happening to wake the loop. The scan deadline counts only while
  /// something IS pending: with the map empty the scan has nothing to reap or retransmit, so
  /// folding its (typically already-elapsed) deadline would only turn an idle driver's 50ms
  /// fallback into a busier wake cadence for no work.
  fn next_deadline(&mut self) -> std::time::Instant {
    let fallback = std::time::Instant::now() + std::time::Duration::from_millis(50);
    let redial = self
      .peers
      .iter()
      .filter_map(|link| link.next_dial)
      .min()
      .map(|d| self.clock.to_std(d));
    let scan = (!self.pending.is_empty()).then(|| self.clock.to_std(self.next_pending_scan));
    // When a reconfiguration job is in flight, fold a 50ms-from-now wake so the job advances on
    // the natural driver cadence even if all other deadlines are quiescent.
    let reconfig = self
      .reconfigure
      .as_ref()
      .map(|_| std::time::Instant::now() + std::time::Duration::from_millis(50));
    [
      self.earliest_deadline(),
      redial,
      scan,
      self.recv_backoff_until,
      reconfig,
    ]
    .into_iter()
    .flatten()
    .fold(fallback, std::time::Instant::min)
  }

  /// Feed one inbound datagram (the leading `len` bytes of `recv_buf`) to the coordinator, then
  /// refresh the dial-map.
  ///
  /// The datagram can install a new membership; rekeying IMMEDIATELY after the feed (before the next
  /// iteration's `reconcile_peer_links` dial pass and the pump's close drains) keeps the dial
  /// projection current, so a removed or slot-shifted member is never reopened by a dial that read a
  /// stale map. `rekey_if_needed` is config_id-gated, so a datagram that does not change the
  /// membership costs only a scalar compare.
  fn handle_inbound_datagram(&mut self, now: Instant, len: usize, from: SocketAddr) {
    self.coord.handle_udp(
      now,
      from,
      None,
      &self.recv_buf[..len],
      &mut self.wal,
      &mut self.sb,
      &mut self.blocks,
    );
    self.rekey_if_needed(now);
  }

  /// Redial every configured peer that has NO bound (identity-validated) connection in the
  /// coordinator. Steady-state consensus traffic is primary→backups only, so a backup↔backup
  /// connection that dies (a peer restart, a genuine idle-out) is never re-established by traffic —
  /// the next view change would route `StartViewChange`/`DoViewChange` to no bound conn and
  /// retransmit forever. The transport's keep-alives prevent the quiet-mesh idle-out; this reconcile
  /// recovers from real loss.
  ///
  /// An unbound link first ARMS a deadline one backoff ahead — `has_bound_conn` is `false` while a
  /// dial/handshake is still in flight, so an immediate dial per observation would stack dials —
  /// and redials only when it expires, doubling the (jittered) backoff up to the configured redial
  /// cap so a dead peer is probed at a bounded rate. Binding resets the backoff. A refused dial
  /// (e.g. the connection cap) retries on the same schedule. `QuicCoordinator::connect` is
  /// synchronous — it queues the handshake Initial for the next transmit pump — so there is no
  /// dial task to own, cancel, or leak.
  fn reconcile_peer_links(&mut self, now: Instant) {
    for link in &mut self.peers {
      if self.coord.has_bound_conn(Peer::Replica(link.id)) {
        link.backoff = self.cfg.redial_backoff_base();
        link.next_dial = None;
        continue;
      }
      match link.next_dial {
        None => link.next_dial = Some(now + jittered(link.backoff)),
        Some(due) if now >= due => {
          let _ = self.coord.connect(now, link.addr, Peer::Replica(link.id));
          link.backoff = (link.backoff * 2).min(self.cfg.redial_backoff_cap());
          link.next_dial = Some(now + jittered(link.backoff));
        }
        Some(_) => {}
      }
    }
  }

  /// Reap cancelled submits (releasing their budget), then re-broadcast pending requests not committed
  /// within the request timeout (the proto session table dedups). The cancellation reclaim is the
  /// caller-cancellation release site: a submit whose reply future was dropped is removed + its budget
  /// freed within one scan interval, so a cancelled submit's memory can't be pinned until its commit
  /// arrives. Retransmission lets a request submitted before the mesh is up reach the primary once
  /// links come up.
  ///
  /// DEADLINE-GATED: the underlying walk is O(in-flight), so it runs only when `next_pending_scan`
  /// is due, then re-arms one [`pending_scan_interval`] ahead — call sites stay per-iteration (a
  /// not-yet-due call returns immediately), and `next_deadline` folds the scan deadline in so a
  /// parked driver wakes ON this schedule. The staleness the gate introduces is what both jobs
  /// tolerate (see `PENDING_SCAN_MAX_INTERVAL`).
  fn retransmit_stale(&mut self, now: Instant) {
    if now < self.next_pending_scan {
      return;
    }
    self.next_pending_scan = now + pending_scan_interval(self.cfg.request_timeout());
    let stale = reap_and_collect_retransmits(&mut self.pending, now, self.cfg.request_timeout());
    for request in stale {
      self
        .coord
        .submit_client_request(now, &mut self.wal, &mut self.sb, &mut self.blocks, request);
    }
  }

  /// Drain storage completions + outputs until the coordinator stops producing.
  async fn pump_outputs(&mut self, now: Instant) {
    // Refresh the dial-map before the first output pass, then after each storage poll: a
    // `handle_storage` completion can itself install a new membership, so the projection must be
    // current before any subsequent dial/route/close decision.
    self.rekey_if_needed(now);
    loop {
      self
        .coord
        .handle_storage(now, &mut self.wal, &mut self.sb, &mut self.blocks);
      self.rekey_if_needed(now);
      let mut produced = false;
      // Drain the pass's datagrams, then send them SEQUENTIALLY: a readiness `send_to` on an
      // unconnected UDP socket completes as soon as the datagram is copied into the kernel buffer
      // (or refused), so serial awaits lose nothing — there is no in-kernel overlap for a batch
      // submission to win. QUIC datagrams are independent (quinn imposes no inter-datagram
      // ordering; loss and reorder are its job).
      let batch: Vec<(SocketAddr, Vec<u8>)> =
        std::iter::from_fn(|| self.coord.poll_transmit()).collect();
      if !batch.is_empty() {
        produced = true;
        for (dst, bytes) in batch {
          // Transient UDP send error is non-fatal; QUIC retransmits.
          let _ = self.socket.send_to(&bytes, dst).await;
        }
      }
      while let Some(event) = self.coord.poll_event() {
        // A live self-removal makes the endpoint structurally Retired: it emits no further commits,
        // so fail every in-flight submit terminally and latch the shared signal (so `Handle::submit`
        // rejects further submits) rather than blackholing them. The endpoint exposes no scalar epoch
        // getter, so the retirement epoch is read off a one-time membership clone — retirement fires
        // at most once per driver, off the hot path. The `StatusChanged` still forwards below.
        if matches!(&event, Event::StatusChanged(status) if status.is_retired()) {
          let (local, live) = {
            let endpoint = self.coord.endpoint();
            (endpoint.local(), endpoint.membership_clone())
          };
          let epoch = live.epoch();
          retire(&mut self.pending, &self.retired, local, epoch);
          // A retired endpoint installs nothing further, so an in-flight reconfiguration job would
          // otherwise sit parked until `reconfigure_timeout` — `advance` resolves an outstanding step
          // only once the live config reaches the awaited successor, which a competing removal makes
          // unreachable — surfacing a misleading resumable Timeout. Finish it terminally instead (Ok if
          // this job's goal was in fact reached, else the terminal Retired), off the same clone.
          finish_reconfigure_on_retire(&mut self.reconfigure, live, local, epoch);
        }
        deliver_event(&mut self.pending, &self.events, event);
        produced = true;
      }
      if !produced {
        break;
      }
    }
  }

  /// Run `rekey_peers` iff the live config_id has changed since the last call. O(1) on the
  /// no-change path; called after every endpoint-advancing call so dial/route/close decisions
  /// always see the current membership projection.
  fn rekey_if_needed(&mut self, now: Instant) {
    if self.reconciler.check(self.coord.membership_config_id()) {
      self.rekey_peers(now);
    }
  }

  /// Rebuild the DIAL list against the current membership after a config change — the DIAL-of-added
  /// half of the re-key. CLOSING a stale slot is the COORDINATOR's job now (`reconcile_routing` runs
  /// inside the endpoint-advancing handlers, right after the install, before any output is routed), so
  /// this only rebuilds `self.peers` from the new membership plus the address book: a member dropped
  /// from the membership loses its `PeerLink` (so it is never redialed), and a freshly-ADDED member
  /// gains one (armed to dial this iteration). Dialing an added member is not timing-critical — it
  /// connects, then the coordinator's routing picks it up on the validating handshake. The full
  /// membership clone happens only here — once per config change — never on the hot loop path.
  fn rekey_peers(&mut self, now: Instant) {
    let m = self.coord.live_membership();
    let local = self.coord.endpoint().local();
    let base_backoff = self.cfg.redial_backoff_base();
    let mut new_peers: Vec<PeerLink> = Vec::new();
    for slot_u16 in 0..m.node_count() {
      let slot = ReplicaId::new(slot_u16);
      let Some(member_id) = m.member_at(slot) else {
        continue;
      };
      if member_id == local {
        continue; // skip self
      }
      let Some(&addr) = self.peer_book.get(&member_id) else {
        continue; // no address known yet; AddPeer will supply it later
      };
      // Preserve the backoff + dial schedule of an UNCHANGED slot+member link (so a retained member is
      // not redialed on a re-key it was unaffected by); a freshly-added member has no prior link, so it
      // is armed to dial this iteration (`next_dial = Some(now)`), letting `reconcile_peer_links` issue
      // its first dial without waiting for the redial backoff to arm.
      let prior = self
        .peers
        .iter()
        .find(|l| l.id == slot && l.member_id == member_id);
      let (backoff, next_dial) = match prior {
        Some(l) => (l.backoff, l.next_dial),
        None => (base_backoff, Some(now)),
      };
      new_peers.push(PeerLink {
        id: slot,
        member_id,
        addr,
        backoff,
        next_dial,
      });
    }
    self.peers = new_peers;
  }
}

#[cfg(test)]
mod tests;

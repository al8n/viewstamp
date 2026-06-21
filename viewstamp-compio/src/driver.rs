use std::{net::SocketAddr, time::Duration};

use compio::net::UdpSocket;
use viewstamp_proto::{
  ClientId, Config, Event, IdentityConfig, Instant, Membership, Peer, ProvidedIdentity,
  QuicCoordinator, QuicOptions, ReplicaId, Request, RequestNumber, StateMachine, Superblock, Wal,
};

use viewstamp_driver::{
  Clock, Command, DriverConfig, DriverError, Handle, InflightBudget, Pending, PendingMap,
  build_endpoint, deliver_event, drain_pending, jittered, pending_scan_interval,
  reap_and_collect_retransmits,
};

const RECV_BUF_LEN: usize = 65_507; // IP-layer max UDP payload

/// Capacity of the bounded datagram channel (recv task -> run loop). Bounds the parked inbound
/// bytes at `RECV_CAP` exact-sized datagram copies (each at most [`RECV_BUF_LEN`]); once full the
/// recv task's `send_async` parks, no `recv_from` is in flight, and further arrivals queue in —
/// then overflow — the kernel socket buffer. That is exactly UDP socket backpressure, whose drops
/// QUIC's own loss recovery already absorbs. The run loop receives one datagram per iteration
/// (the select's highest-priority arm), so the channel only fills under genuine overload.
///
/// A bounded retained-state row beside the shared inventory (the memory-model table in
/// `viewstamp-driver`'s session module): the QUIC recv channel holds at most `RECV_CAP`
/// datagrams, the recv task's `send_async` providing the backpressure.
const RECV_CAP: usize = 256;
/// Backoff before retrying a failed `recv_from`, bounding the retry rate under a persistent
/// synchronously-resolving error so the shared thread always makes progress.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// The persistent datagram-receive task: owns a clone of the driver's socket (compio sockets share
/// one fd across clones) plus ONE receive buffer for its whole life, looping `recv_from` and
/// forwarding each datagram — copied exact-sized, the same hand-back idiom as the stream bridges —
/// into the bounded channel the run loop selects on.
///
/// Keeping the read in its own task is what makes the run loop's recv arm a plain channel wait: on
/// a proactor, DROPPING a not-yet-finished op future (what a losing select arm does) submits an
/// asynchronous CANCEL and forfeits the op's buffer, so a loop that re-arms `recv_from` per
/// iteration pays a cancel syscall plus a zeroed 64 KiB allocation on every submit/timer/storage
/// wake. Here the op is never dropped while the driver runs; each completed read hands the buffer
/// back in its `BufResult` and it is re-lent forever.
///
/// A receive error is transient for an unconnected UDP socket (anything lost under it is QUIC's
/// loss recovery to repair), so the loop keeps receiving. The task exits when the driver drops the
/// channel receiver; the driver also OWNS the task's `JoinHandle`, whose drop cancels the task on
/// every run-loop exit path. That cancel is asynchronous — dropping the handle marks the task
/// cancelled and schedules it, the executor's next pass drops this future (with its socket clone),
/// and dropping the in-flight `recv_from` submits a proactor-level cancel that holds a further fd
/// reference until processed — so the orderly teardown in `run()` does not treat the drop as the
/// fd release; the socket `close().await` there is what waits out both references.
async fn recv_datagrams(socket: UdpSocket, inbound: flume::Sender<(Vec<u8>, SocketAddr)>) {
  let mut buf = vec![0u8; RECV_BUF_LEN];
  loop {
    let compio::buf::BufResult(res, returned) = socket.recv_from(buf).await;
    buf = returned;
    let Ok((n, from)) = res else {
      // Park on the timer before retrying: on the polling backend a receive error can resolve
      // synchronously, and a persistent one (rather than per-datagram noise on an unconnected UDP
      // socket) would otherwise hot-spin this task on the one shared thread.
      compio::time::sleep(RECV_ERROR_BACKOFF).await;
      continue;
    };
    if inbound.send_async((buf[..n].to_vec(), from)).await.is_err() {
      return; // the driver dropped its receiver: it is tearing down
    }
  }
}

/// Redial state for one configured peer. The driver retains every configured `(id, addr)` so a
/// connection that idles out or is lost can be re-established by THIS side — without it, a dead mesh
/// edge stays dead until the peer happens to dial back, and a view change that needs that edge
/// retransmits to no bound conn forever.
struct PeerLink {
  id: ReplicaId,
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

/// The compio (proactor) QUIC driver. Owns the coordinator + storage + socket on one task; a
/// persistent same-thread recv task (holding a clone of the socket, owned via its `JoinHandle` by
/// `run()`) feeds it inbound datagrams.
pub struct CompioQuicDriver<S, W, B, I> {
  coord: QuicCoordinator<S, I>,
  wal: W,
  sb: B,
  socket: UdpSocket,
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
  /// A clone of the shared in-flight submit budget, retained for test observability only. Production
  /// release is by construction: the `Handle` reserves a [`ReservationGuard`] per submit, the guard
  /// rides the `Command::Submit` then the `Pending` entry, and dropping that entry (commit,
  /// cancellation reclaim, shutdown drain) — or the queued command on teardown — releases the slot, so
  /// the driver itself never releases against this handle.
  #[cfg(test)]
  budget: InflightBudget,
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
}

impl<S, W, B> CompioQuicDriver<S, W, B, ProvidedIdentity>
where
  S: StateMachine,
  W: Wal,
  B: Superblock,
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
  /// [`DriverError::Bind`] if the socket cannot bind; [`DriverError::Connect`] if a dial fails.
  #[allow(clippy::too_many_arguments)]
  pub async fn with_config(
    config: Config,
    membership: Membership,
    state_machine: S,
    mut wal: W,
    mut sb: B,
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
    let clock = Clock::new();
    let socket = UdpSocket::bind(bind_addr)
      .await
      .map_err(DriverError::Bind)?;

    let endpoint = build_endpoint(config, membership, state_machine, &mut wal, &mut sb)?;
    let mut coord = QuicCoordinator::with_identity(endpoint, opts, rng_seed, identity);

    let now = clock.now();
    let mut peer_links = Vec::with_capacity(peers.len());
    for (id, addr) in peers {
      coord
        .connect(now, addr, Peer::Replica(id))
        .map_err(|_| DriverError::Connect {
          peer: Peer::Replica(id),
        })?;
      // Retain the configured target: the run loop's reconcile redials it if this connection (or
      // any later one) is lost.
      peer_links.push(PeerLink {
        id,
        addr,
        backoff: cfg.redial_backoff_base(),
        next_dial: None,
      });
    }

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
    let driver = Self {
      coord,
      wal,
      sb,
      socket,
      clock,
      cfg,
      client,
      next_request: first_request,
      pending: PendingMap::new(),
      next_pending_scan: Instant::ZERO,
      peers: peer_links,
      #[cfg(test)]
      budget: budget.clone(),
      commands: commands_rx,
      events: events_tx,
      storage_ready,
      storage_notifier_closed: false,
      reconfigure: None,
    };
    let handle = Handle::new(commands_tx, events_rx, budget);
    Ok((driver, handle))
  }
}

impl<S, W, B, I> CompioQuicDriver<S, W, B, I>
where
  S: StateMachine,
  W: Wal,
  B: Superblock,
  I: viewstamp_proto::IdentitySource,
{
  /// Run the driver to completion. Returns on a `Shutdown` command or when all `Handle` clones drop.
  ///
  /// Both orderly exits — and therefore the ack a [`Handle::shutdown`] awaits — are fd-release
  /// barriers: before acking/returning, the teardown waits for the recv task's socket clone and
  /// its in-flight op's fd reference to drop and then CLOSES the socket fd, so an embedder may
  /// bind a new driver to the same address the moment `shutdown().await` (or an awaited `run()`
  /// task) returns. Cancelling the `run()` future itself (dropping its spawn handle) cannot
  /// barrier — drop glue cannot await — but still releases the fd promptly: the owned recv-task
  /// `JoinHandle` drops with it, and the fd closes once the runtime processes the scheduled
  /// cancellations (within its next passes, not synchronously with the drop).
  pub async fn run(mut self) {
    use futures_util::{FutureExt, select_biased};

    /// Per-iteration command drain budget: bound the iter-top fairness step so a steady command
    /// stream can't itself starve the I/O select, while still letting `Shutdown`/`Submit` make
    /// progress under a recv flood.
    const CMD_BUDGET: usize = 64;

    // The persistent recv task (see [`recv_datagrams`]): its socket clone shares the driver's fd,
    // and the bounded channel is the run loop's inbound face. The `JoinHandle` is OWNED by this
    // scope — never detached — so EVERY exit path (Shutdown, handle-drop, or this whole future
    // being cancelled) drops it, cancelling the task with its in-flight `recv_from` and its
    // socket clone. The cancel is mark-and-schedule, not synchronous teardown: the orderly exits
    // below follow it with the socket `close().await` as the true fd-release barrier, and a
    // cancellation of this whole future releases the fd on the runtime's next passes instead
    // (see [`Self::run`]'s contract).
    let (recv_tx, recv_rx) = flume::bounded(RECV_CAP);
    let recv_task = compio::runtime::spawn(recv_datagrams(self.socket.clone(), recv_tx));

    let now = self.clock.now();
    self.pump_outputs(now).await;

    let mut shutdown_ack: Option<futures_channel::oneshot::Sender<()>> = None;
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
        self.coord.handle_timeout(now, &mut self.wal, &mut self.sb);
      }
      self.retransmit_stale(now);
      // Redial any configured peer with no bound connection (iter-top, like the stream driver's
      // reconcile passes), BEFORE the pump so a fresh dial's handshake Initial transmits this
      // iteration rather than after the next select wake.
      self.reconcile_peer_links(now);
      self.pump_outputs(now).await;
      self.advance_reconfigure(now);

      // Recompute AFTER the iter-top timer fire so it reflects the next deadline (avoids a redundant
      // immediate select-timer fire for the timer we just serviced).
      let deadline = self.next_deadline();

      // The four futures BORROW the recv channel + driver fields (`recv_fut` holds `&recv_rx`,
      // `cmd_fut` `&mut self.commands`, `storage_fut` `&self.storage_ready` — disjoint fields).
      // Confine their construction + `select_biased!` to this inner scope: when it ends the pinned
      // futures drop, releasing those borrows so the `&mut self` pumping below is legal. Each arm
      // only writes a captured local; no whole-`self` work happens in an arm. All four arms are
      // plain channel/timer waits — the socket I/O itself lives in the recv task and
      // `pump_outputs` — so a losing arm never cancels an in-flight socket op.
      let (inbound, fire_timeout, command, exit, storage_closed) = {
        let recv_fut = recv_rx.recv_async().fuse();
        let timer_fut = compio::time::sleep_until(deadline).fuse();
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

        let mut inbound: Option<(Vec<u8>, SocketAddr)> = None;
        let mut fire_timeout = false;
        let mut command: Option<Command> = None;
        let mut exit = false;
        let mut storage_closed = false;

        select_biased! {
            // `Err` (a closed channel) is unreachable while this scope holds `recv_task`: the
            // task only exits when the receiver it sends to drops.
            got = recv_fut => {
                if let Ok(datagram) = got { inbound = Some(datagram); }
            }
            _ = timer_fut => { fire_timeout = true; }
            cmd = cmd_fut => {
                match cmd { Ok(c) => command = Some(c), Err(_) => exit = true }
            }
            s = storage_fut => { storage_closed = s.is_err(); }
        }
        (inbound, fire_timeout, command, exit, storage_closed)
      };
      while self.storage_ready.try_recv().is_ok() {}
      if storage_closed {
        self.storage_notifier_closed = true;
      }
      if exit {
        break;
      }

      let now = self.clock.now();
      if let Some((datagram, from)) = inbound {
        self
          .coord
          .handle_udp(now, from, None, &datagram, &mut self.wal, &mut self.sb);
      }
      if fire_timeout {
        self.coord.handle_timeout(now, &mut self.wal, &mut self.sb);
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
    // Dropping the `JoinHandle` only MARKS the recv task cancelled and SCHEDULES it: the task —
    // its socket clone and its in-flight `recv_from` — is dropped on the executor's next pass,
    // and dropping that in-flight op merely submits an asynchronous proactor cancel which itself
    // holds an fd reference until the cancellation is processed. Nothing is released yet when
    // this drop returns.
    drop(recv_task);
    // Dropping the datagram receiver releases this side; the buffered datagrams themselves free
    // with the recv task's sender clone, which the socket `close().await` below waits out. That
    // is the general teardown shape for DRIVER-INTERNAL queues: their senders all live in tasks
    // this teardown just cancelled, so they release with those tasks — promptly, but
    // asynchronously.
    drop(recv_rx);
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
    // The fd-release barrier: `close` parks until every other reference to the socket's fd — the
    // recv task's clone and its cancelled-but-unprocessed op — has dropped, then closes the fd
    // with a real close op. Once this await returns the bound address is free, which is what
    // makes the ack below (and `run()`'s return) an immediate-rebind contract rather than a hope
    // that the runtime already processed the scheduled cancellations. A close error is ignored:
    // there is no recovery at teardown, and the fd is released regardless.
    let _ = self.socket.close().await;
    if let Some(ack) = shutdown_ack {
      let _ = ack.send(());
    }
  }

  /// Handle one [`Command`]; returns `true` when the loop should exit (a `Shutdown`).
  ///
  /// Shared by the iter-top fairness drain and the select's command arm so the `Submit`/`Shutdown`
  /// handling lives in one place.
  fn handle_command(
    &mut self,
    now: Instant,
    cmd: Command,
    shutdown_ack: &mut Option<futures_channel::oneshot::Sender<()>>,
  ) -> bool {
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
        self
          .coord
          .submit_client_request(now, &mut self.wal, &mut self.sb, request);
        false
      }
      Command::Shutdown { ack } => {
        *shutdown_ack = Some(ack);
        true
      }
      Command::Reconfigure {
        target,
        health,
        reply,
      } => {
        if self.reconfigure.is_some() {
          let _ = reply.send(Err(viewstamp_driver::ReconfigureError::Propose(
            viewstamp_proto::ProposeMembershipError::AlreadyInFlight,
          )));
        } else {
          let live = self.coord.live_membership();
          let acked = self.coord.recently_acked_voters(self.cfg.ack_window());
          self.reconfigure = Some(viewstamp_driver::ReconfigureJob::start(
            target,
            health,
            self.cfg.ack_window(),
            self.cfg.reconfigure_timeout(),
            reply,
            live,
            acked,
          ));
        }
        false
      }
    }
  }

  /// Advance the in-flight reconfiguration job by one iteration, if any. Reads the live membership
  /// and acked set from the coordinator (disjoint borrow: coordinator is read first, then the job
  /// takes `&mut self`), then calls `job.advance` with a closure that proposes a delta.
  fn advance_reconfigure(&mut self, now: Instant) {
    let Some(mut job) = self.reconfigure.take() else {
      return;
    };
    let live = self.coord.live_membership();
    let acked = self.coord.recently_acked_voters(self.cfg.ack_window());
    let outcome = job.advance(now, live, acked, &mut |delta| {
      self.coord.propose_membership(now, &mut self.wal, delta)
    });
    if !matches!(outcome, viewstamp_driver::AdvanceOutcome::Done) {
      self.reconfigure = Some(job);
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
  /// redial, the next pending scan, and a 50ms idle fallback (so a quiet node still re-pumps
  /// storage). The redial and scan deadlines are folded in as REAL wake deadlines so redialing and
  /// the gated `pending` scan never depend on the idle fallback happening to wake the loop. The
  /// scan deadline counts only while something IS pending: with the map empty the scan has nothing
  /// to reap or retransmit, so folding its (typically already-elapsed) deadline would only turn an
  /// idle driver's 50ms fallback into a busier wake cadence for no work.
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
    [self.earliest_deadline(), redial, scan, reconfig]
      .into_iter()
      .flatten()
      .fold(fallback, std::time::Instant::min)
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
  /// synchronous — it queues the handshake Initial for the next transmit pump — so unlike the
  /// stream driver's `dial_peer` there is no dial task to own, cancel, or leak.
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
        .submit_client_request(now, &mut self.wal, &mut self.sb, request);
    }
  }

  /// Drain storage completions + outputs until the coordinator stops producing.
  async fn pump_outputs(&mut self, now: Instant) {
    loop {
      self.coord.handle_storage(now, &mut self.wal, &mut self.sb);
      let mut produced = false;
      // Drain the pass's datagrams, then submit them as ONE batch of concurrent `send_to`s: compio
      // is a proactor, so N in-flight submissions overlap in the kernel instead of serializing N
      // awaited round-trips (a state-transfer burst is thousands of datagrams). QUIC datagrams are
      // independent (quinn imposes no inter-datagram ordering; loss and reorder are its job), so
      // completion order is free to vary. Each future owns its buffer; `join_all` keeps them all
      // alive to completion.
      let batch: Vec<(SocketAddr, Vec<u8>)> =
        std::iter::from_fn(|| self.coord.poll_transmit()).collect();
      if !batch.is_empty() {
        produced = true;
        let sends = batch
          .into_iter()
          .map(|(dst, bytes)| self.socket.send_to(bytes, dst));
        for compio::buf::BufResult(res, _) in futures_util::future::join_all(sends).await {
          let _ = res; // transient UDP send error is non-fatal; QUIC retransmits
        }
      }
      while let Some(event) = self.coord.poll_event() {
        deliver_event(&mut self.pending, &self.events, event);
        produced = true;
      }
      if !produced {
        break;
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
  };
  use viewstamp_proto::{ClusterTls, Config, IdentityConfig, MemberId, Membership, QuicOptions};
  use viewstamp_simulation::{InMemorySuperblock, InMemoryWal, sm::LogSm};

  use super::CompioQuicDriver;

  /// The genesis membership for an `n`-voter cluster: `MemberId::new(i)` occupies slot `i`.
  ///
  /// Built with a fixed `config_id = 0` (via `from_durable_parts`) so any hand-built test message
  /// (which carries 0) passes the strict `(epoch, config_id)` ingress gate; production uses the
  /// hash-chained id.
  fn genesis(n: u8) -> Membership {
    Membership::from_durable_parts(
      viewstamp_proto::Epoch::new(0),
      n,
      0,
      (0..n as u128).map(MemberId::new).collect(),
      0,
    )
    .expect("valid genesis membership")
  }
  use viewstamp_driver::{DriverError, MAX_INFLIGHT, MAX_PENDING_BYTES, REQUEST_TIMEOUT};

  const CLUSTER: u128 = 0x5151;

  type TestQuicDriver =
    CompioQuicDriver<LogSm, InMemoryWal, InMemorySuperblock, viewstamp_proto::ProvidedIdentity>;

  /// A type-erased in-flight `submit` future, lifetime-bound to the borrowed `Handle` it ran from.
  type SubmitFut<'a> = dyn std::future::Future<Output = Result<crate::Reply, DriverError>> + 'a;

  #[test]
  fn driver_type_resolves() {
    fn _assert_handle_clone(h: &crate::Handle) {
      let _ = h.clone();
    }
  }

  /// A self-signed cluster CA + one leaf cert, the minimal trust material the mandatory cluster mTLS
  /// needs to BUILD a driver (these budget tests never form a cluster, so a single leaf suffices).
  /// Mirrors the proto's `test_ca`/`issue_replica` and the loopback integration CA.
  fn cluster_ca() -> (
    RootCertStore,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
  ) {
    let mut ca_params = rcgen::CertificateParams::new(vec![]).expect("empty SAN for CA is valid");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
      .key_usages
      .push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params
      .key_usages
      .push(rcgen::KeyUsagePurpose::DigitalSignature);
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let mut roots = RootCertStore::empty();
    roots
      .add(CertificateDer::from(ca_cert.der().to_vec()))
      .expect("CA is a trust anchor");

    let san = format!("replica-0.{CLUSTER:032x}.viewstamp");
    let mut leaf = rcgen::CertificateParams::new(vec![san]).expect("valid DNS SAN");
    leaf
      .key_usages
      .push(rcgen::KeyUsagePurpose::DigitalSignature);
    leaf
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    leaf
      .extended_key_usages
      .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let cert = leaf
      .signed_by(&leaf_key, &issuer)
      .expect("leaf signed by CA");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::try_from(leaf_key.serialize_der()).expect("leaf key DER");
    (roots, chain, key)
  }

  /// Build a single-node QUIC driver (no peers, so it NEVER commits) + its `Handle`, sharing the
  /// in-flight budget. This is the partitioned/slow case the submit budget must bound: with no quorum
  /// nothing the driver does releases a `pending` entry, so the budget only ever fills then refuses.
  async fn test_quic_driver_with_handle() -> (TestQuicDriver, crate::Handle) {
    test_quic_driver_with_storage(InMemoryWal::new(), InMemorySuperblock::new()).await
  }

  /// Like [`test_quic_driver_with_handle`] but over caller-supplied storage, so the recover-or-new
  /// constructor-choice tests can hand it a dirty store.
  async fn test_quic_driver_with_storage(
    wal: InMemoryWal,
    sb: InMemorySuperblock,
  ) -> (TestQuicDriver, crate::Handle) {
    test_quic_driver_with_config(wal, sb, crate::DriverConfig::new()).await
  }

  /// Like [`test_quic_driver_with_storage`] but through the `with_config` constructor, so the
  /// config-effect tests drive a non-default [`crate::DriverConfig`] through the production path.
  async fn test_quic_driver_with_config(
    wal: InMemoryWal,
    sb: InMemorySuperblock,
    cfg: crate::DriverConfig,
  ) -> (TestQuicDriver, crate::Handle) {
    let (roots, chain, key) = cluster_ca();
    let opts: QuicOptions = ClusterTls::new(roots, chain, key).build();
    let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let (_ready_tx, ready_rx) = flume::unbounded();
    CompioQuicDriver::with_config(
      config,
      genesis(3),
      LogSm::default(),
      wal,
      sb,
      viewstamp_proto::ClientId::new(1),
      0,
      opts,
      IdentityConfig::Hello { cluster: CLUSTER },
      Some([0u8; 32]),
      "127.0.0.1:0".parse().unwrap(),
      Vec::new(), // no peers: never a quorum, so nothing ever commits on its own
      ready_rx,
      cfg,
    )
    .await
    .expect("driver builds")
  }

  /// AMNESIA GUARD (QUIC driver): a store carrying ANY durable state NEVER boots a fresh view-0
  /// endpoint — the constructor inspects the store and reconstructs via `Endpoint::recover`. A
  /// durable root at view 5 must resume view 5 (a fresh boot would be view 0); a durable WAL op
  /// must restore the head and enter `Recovering` (the tail re-verifies through the normal storage
  /// pump). Reverting the constructor to an unconditional `Endpoint::new` fails both halves.
  #[compio::test]
  async fn a_dirty_store_never_boots_a_fresh_view_zero_endpoint_quic() {
    // Durable ROOT, empty WAL: recovery has nothing to read, so it settles inline (replica 0 is not
    // view 5's primary, hence a Normal backup) — the guard property is the RESUMED durable view.
    let mut sb = InMemorySuperblock::new();
    viewstamp_proto::Superblock::submit_write(
      &mut sb,
      viewstamp_proto::OpId::new(1),
      viewstamp_proto::VsrState::try_new(
        viewstamp_proto::View::with(5),
        viewstamp_proto::View::with(5),
        viewstamp_proto::OpNumber::new(),
        viewstamp_proto::OpNumber::new(),
        0,
        Vec::new(),
      )
      .expect("a valid durable root"),
    );
    // The storage contract: no in-flight completions cross an endpoint incarnation.
    while viewstamp_proto::Superblock::poll(&mut sb).is_some() {}
    let (driver, _handle) = test_quic_driver_with_storage(InMemoryWal::new(), sb).await;
    assert_eq!(
      driver.coord.endpoint().view().get(),
      5,
      "the durable view is resumed, never reset to a fresh view 0"
    );

    // Durable WAL op, genesis root: the endpoint enters Recovering with its durable head restored
    // (the read completions resolve through the run loop's ordinary handle_storage pump).
    let mut wal = InMemoryWal::new();
    let header = viewstamp_proto::Header::new(
      viewstamp_proto::OpNumber::with(1),
      viewstamp_proto::View::new(),
      viewstamp_proto::ClientId::new(7),
      viewstamp_proto::RequestNumber::with(1),
      b"op",
    );
    viewstamp_proto::Wal::submit_append(
      &mut wal,
      viewstamp_proto::OpId::new(1),
      viewstamp_proto::OpNumber::with(1),
      header,
      Bytes::from_static(b"op"),
    );
    while viewstamp_proto::Wal::poll(&mut wal).is_some() {}
    let (driver, _handle) = test_quic_driver_with_storage(wal, InMemorySuperblock::new()).await;
    assert!(
      driver.coord.endpoint().status().is_recovering(),
      "a durable WAL boots into Recovering, not a fresh Normal"
    );
    assert_eq!(
      driver.coord.endpoint().op().get(),
      1,
      "the durable WAL head is restored"
    );
  }

  /// First-boot path (QUIC driver): a genesis store — fresh-cluster root AND empty WAL — still boots
  /// a fresh endpoint (`Normal`, view 0, empty log); `Endpoint::new` stays reachable, guarded by the
  /// state inspection itself.
  #[compio::test]
  async fn a_genesis_store_boots_a_fresh_normal_endpoint_quic() {
    let (driver, _handle) =
      test_quic_driver_with_storage(InMemoryWal::new(), InMemorySuperblock::new()).await;
    assert!(driver.coord.endpoint().status().is_normal());
    assert_eq!(driver.coord.endpoint().view().get(), 0);
    assert_eq!(driver.coord.endpoint().op().get(), 0);
  }

  /// Drain one `Submit` from the driver's command channel through the REAL `handle_command` (mints the
  /// request number + inserts the `pending` entry). The reservation was already made by
  /// `Handle::submit`; this completes the Handle->driver crossing the run loop would do. A `Submit` is
  /// never a shutdown, so `handle_command` returns `false` here.
  fn drain_one_command(driver: &mut TestQuicDriver) {
    let cmd = driver.commands.try_recv().expect("a command was enqueued");
    let mut ack = None;
    let is_shutdown = driver.handle_command(viewstamp_proto::Instant::ZERO, cmd, &mut ack);
    assert!(!is_shutdown, "a drained Submit is not a Shutdown");
  }

  /// Poll a `submit` future once: it either enqueues + parks on the reply (`Pending`), or resolves
  /// (`Ready`, e.g. `Busy`). Returns the resolved result, if any.
  fn poll_submit(
    fut: std::pin::Pin<&mut SubmitFut<'_>>,
  ) -> Option<Result<crate::Reply, DriverError>> {
    let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
    match std::future::Future::poll(fut, &mut cx) {
      std::task::Poll::Ready(r) => Some(r),
      std::task::Poll::Pending => None,
    }
  }

  /// SUBMIT-BUDGET BOUND (QUIC driver): with NO commits ever arriving (single node, never a quorum),
  /// `pending` + the shared budget never exceed `MAX_INFLIGHT` / `MAX_PENDING_BYTES`, and a submit past
  /// the cap returns `Busy` WITHOUT minting a request. Then delivering the matching commits releases
  /// the budget so a subsequent submit is accepted again. Drives the REAL `Handle::submit`,
  /// `handle_command`, and `deliver_event`. The count cap is reached against a 1-byte body so the byte
  /// cap is nowhere near binding (the byte cap itself is covered in `handle.rs`).
  #[compio::test]
  async fn submit_budget_bounds_pending_and_releases_on_commit_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;

    for i in 0..MAX_INFLIGHT {
      let fut = handle.submit(Bytes::from_static(b"x"));
      futures_util::pin_mut!(fut);
      assert!(
        poll_submit(fut.as_mut()).is_none(),
        "submit #{i} within the cap is accepted (parks on its reply)"
      );
      drain_one_command(&mut driver);
      assert!(
        driver.pending.len() <= MAX_INFLIGHT,
        "pending never exceeds MAX_INFLIGHT"
      );
      assert!(
        driver.budget.bytes() <= MAX_PENDING_BYTES,
        "reserved bytes never exceed MAX_PENDING_BYTES"
      );
    }
    assert_eq!(
      driver.pending.len(),
      MAX_INFLIGHT,
      "exactly at the count cap"
    );

    let over = handle.submit(Bytes::from_static(b"y"));
    futures_util::pin_mut!(over);
    assert!(
      matches!(poll_submit(over.as_mut()), Some(Err(DriverError::Busy))),
      "a submit past the in-flight cap returns Busy"
    );
    assert!(
      driver.commands.try_recv().is_err(),
      "a Busy submit enqueues no command"
    );
    assert_eq!(
      driver.budget.count(),
      MAX_INFLIGHT,
      "a Busy submit does not grow the budget (rolled back)"
    );

    // Deliver the matching commits: each releases one slot via `deliver_event`.
    let keys: Vec<_> = driver.pending.keys().copied().collect();
    let (events_tx, _events_rx) = flume::bounded(viewstamp_driver::EVENTS_CAP);
    for (client, request) in keys {
      let event = viewstamp_proto::Event::Committed(viewstamp_proto::Committed::new(
        viewstamp_proto::OpNumber::with(request.get()),
        client,
        request,
        Bytes::from_static(b"R"),
      ));
      viewstamp_driver::deliver_event(&mut driver.pending, &events_tx, event);
    }
    assert_eq!(driver.budget.count(), 0, "every commit released its slot");
    assert!(driver.pending.is_empty(), "pending drained by the commits");

    let again = handle.submit(Bytes::from_static(b"z"));
    futures_util::pin_mut!(again);
    assert!(
      poll_submit(again.as_mut()).is_none(),
      "with the budget released a fresh submit is accepted again"
    );
    assert_eq!(
      driver.budget.count(),
      1,
      "the accepted submit holds one slot"
    );
  }

  /// CONFIG EFFECT (QUIC driver): a non-default `DriverConfig::max_inflight` is the LIVE submit
  /// bound, not a recorded value — built with a cap of 2 through the production `with_config`
  /// path, the THIRD concurrent submit is `Busy` (under the default the budget admits 4096), and
  /// releasing one slot re-admits. Pins that the config value reaches the shared `InflightBudget`
  /// the `Handle` reserves against.
  #[compio::test]
  async fn a_tiny_configured_max_inflight_yields_busy_earlier() {
    let cfg = crate::DriverConfig::new().with_max_inflight(2);
    let (mut driver, handle) =
      test_quic_driver_with_config(InMemoryWal::new(), InMemorySuperblock::new(), cfg).await;

    let first = handle.submit(Bytes::from_static(b"a"));
    let mut first = Box::pin(first);
    assert!(poll_submit(first.as_mut()).is_none(), "submit 1 of 2 parks");
    drain_one_command(&mut driver);
    let second = handle.submit(Bytes::from_static(b"b"));
    let mut second = Box::pin(second);
    assert!(
      poll_submit(second.as_mut()).is_none(),
      "submit 2 of 2 parks"
    );
    drain_one_command(&mut driver);
    assert_eq!(
      driver.pending.len(),
      2,
      "the configured cap's worth is in flight"
    );

    let third = handle.submit(Bytes::from_static(b"c"));
    futures_util::pin_mut!(third);
    assert!(
      matches!(poll_submit(third.as_mut()), Some(Err(DriverError::Busy))),
      "the third submit is Busy at the CONFIGURED cap of 2 — far below the 4096 default"
    );
    assert!(
      driver.commands.try_recv().is_err(),
      "the refused submit enqueued no command"
    );

    // Cancel one in-flight submit; the reap frees its slot and a fresh submit is admitted again —
    // the configured budget releases exactly like the default one.
    drop(first);
    let now =
      viewstamp_proto::Instant::ZERO + REQUEST_TIMEOUT + std::time::Duration::from_millis(1);
    driver.retransmit_stale(now);
    let again = handle.submit(Bytes::from_static(b"d"));
    futures_util::pin_mut!(again);
    assert!(
      poll_submit(again.as_mut()).is_none(),
      "after one release the configured budget admits a submit again"
    );
    drop(second);
  }

  /// OVER-FRAME REJECTION (QUIC driver): a submit whose body exceeds `max_request_body_len()` is
  /// rejected up front with `RequestTooLarge` and has NO side effects — it reserves no budget (count and
  /// bytes stay 0) and enqueues no command. Without the up-front rejection an over-frame body would
  /// enter `pending`, pin the budget, and wait forever for a commit the transport can never produce
  /// (its relayed `Request`/`Prepare` would exceed `MAX_FRAME_LEN` and be dropped).
  #[compio::test]
  async fn over_frame_submit_is_rejected_without_side_effects_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;

    let oversized = Bytes::from(vec![0u8; viewstamp_proto::max_request_body_len() + 1]);
    let fut = handle.submit(oversized);
    futures_util::pin_mut!(fut);
    assert!(
      matches!(
        poll_submit(fut.as_mut()),
        Some(Err(DriverError::RequestTooLarge))
      ),
      "an over-frame body is rejected with RequestTooLarge before reserving or enqueueing"
    );
    assert_eq!(
      driver.budget.count(),
      0,
      "a rejected over-frame submit reserves no budget slot"
    );
    assert_eq!(
      driver.budget.bytes(),
      0,
      "a rejected over-frame submit reserves no budget bytes"
    );
    assert!(
      driver.commands.try_recv().is_err(),
      "a rejected over-frame submit enqueues no command"
    );
  }

  /// BOUNDARY (QUIC driver): a body of EXACTLY `max_request_body_len()` is accepted (it parks on its
  /// reply, reserves one slot of that many bytes, and enqueues one command) — the maximum deliverable
  /// size is usable, not rejected off-by-one.
  #[compio::test]
  async fn max_size_submit_is_accepted_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;

    let max = viewstamp_proto::max_request_body_len();
    let at_max = Bytes::from(vec![0u8; max]);
    let fut = handle.submit(at_max);
    futures_util::pin_mut!(fut);
    assert!(
      poll_submit(fut.as_mut()).is_none(),
      "a max-size body is accepted (parks on its reply), not rejected"
    );
    assert_eq!(
      driver.budget.count(),
      1,
      "the max-size submit holds one slot"
    );
    assert_eq!(
      driver.budget.bytes(),
      max,
      "the max-size submit reserves exactly its body bytes"
    );
    drain_one_command(&mut driver);
    assert_eq!(
      driver.pending.len(),
      1,
      "the max-size submit becomes one pending entry"
    );
  }

  /// CANCELLATION RECLAIM (QUIC driver): a submit whose reply future is dropped is reclaimed within a
  /// `retransmit_stale` tick — entry removed, budget released — so a later otherwise-`Busy` submit
  /// succeeds.
  #[compio::test]
  async fn cancelled_submit_is_reclaimed_within_a_retransmit_tick_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;

    let first = handle.submit(Bytes::from_static(b"cancel-me"));
    let mut first = Box::pin(first);
    assert!(
      poll_submit(first.as_mut()).is_none(),
      "first submit accepted"
    );
    drain_one_command(&mut driver);

    // Fill the REST of the cap. Each future's reply RECEIVER must stay alive (else dropping it would
    // cancel that entry too), so RETAIN every future — only `first` is cancelled below.
    let mut live: Vec<std::pin::Pin<Box<SubmitFut<'_>>>> = Vec::new();
    for _ in 1..MAX_INFLIGHT {
      let mut fut: std::pin::Pin<Box<SubmitFut<'_>>> =
        Box::pin(handle.submit(Bytes::from_static(b"x")));
      assert!(poll_submit(fut.as_mut()).is_none());
      drain_one_command(&mut driver);
      live.push(fut);
    }
    assert_eq!(driver.pending.len(), MAX_INFLIGHT, "session is full");

    let blocked = handle.submit(Bytes::from_static(b"blocked"));
    futures_util::pin_mut!(blocked);
    assert!(
      matches!(poll_submit(blocked.as_mut()), Some(Err(DriverError::Busy))),
      "at the cap a submit is Busy"
    );

    drop(first); // cancel: drops the reply receiver

    let now =
      viewstamp_proto::Instant::ZERO + REQUEST_TIMEOUT + std::time::Duration::from_millis(1);
    driver.retransmit_stale(now);
    assert_eq!(
      driver.pending.len(),
      MAX_INFLIGHT - 1,
      "the cancelled entry was reclaimed"
    );
    assert_eq!(
      driver.budget.count(),
      MAX_INFLIGHT - 1,
      "and its budget slot was released"
    );

    let now_ok = handle.submit(Bytes::from_static(b"now-ok"));
    futures_util::pin_mut!(now_ok);
    assert!(
      poll_submit(now_ok.as_mut()).is_none(),
      "after the cancelled submit is reclaimed a fresh submit is accepted again"
    );
    drop(live); // keep the other in-flight reply receivers alive until here (so they stay uncancelled)
  }

  /// SCAN GATE (QUIC driver): `retransmit_stale` walks `pending` only when its scan deadline is
  /// due, then re-arms `pending_scan_interval` ahead — so per-datagram wakes never pay an
  /// O(in-flight) walk each. The gate starts disarmed (a fresh driver's first call scans), a call
  /// strictly before the re-armed deadline must NOT reap a newly-cancelled entry, and a call AT
  /// the deadline must. The skipped call is exactly the bounded staleness the cancellation-reclaim
  /// property tolerates (one scan interval, not "every call").
  #[compio::test]
  async fn the_pending_scan_is_deadline_gated_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;
    let interval = viewstamp_driver::pending_scan_interval(driver.cfg.request_timeout());

    let mut first: std::pin::Pin<Box<SubmitFut<'_>>> =
      Box::pin(handle.submit(Bytes::from_static(b"a")));
    assert!(poll_submit(first.as_mut()).is_none(), "first submit parks");
    drain_one_command(&mut driver);
    drop(first); // cancel: drops the reply receiver

    let t0 = viewstamp_proto::Instant::ZERO + REQUEST_TIMEOUT;
    driver.retransmit_stale(t0);
    assert!(
      driver.pending.is_empty(),
      "the gate starts disarmed: a fresh driver's first call scans and reaps the cancelled submit"
    );

    let mut second: std::pin::Pin<Box<SubmitFut<'_>>> =
      Box::pin(handle.submit(Bytes::from_static(b"b")));
    assert!(
      poll_submit(second.as_mut()).is_none(),
      "second submit parks"
    );
    drain_one_command(&mut driver);
    drop(second); // cancel

    driver.retransmit_stale(t0 + (interval - std::time::Duration::from_millis(1)));
    assert_eq!(
      driver.pending.len(),
      1,
      "strictly before the re-armed deadline the walk is skipped: the cancelled entry survives"
    );

    driver.retransmit_stale(t0 + interval);
    assert!(
      driver.pending.is_empty(),
      "AT the re-armed deadline the scan runs and reaps the cancelled entry"
    );
  }

  /// The pending-scan deadline is folded into `next_deadline` as a REAL wake deadline whenever a
  /// submit is in flight, so a parked driver wakes ON the scan schedule (reclaiming cancellations
  /// and retransmitting on cadence) instead of relying on the 50ms idle fallback. With NOTHING
  /// pending the scan is NOT folded: the gate value is a past instant once a scan has run, and an
  /// empty map gives the scan nothing to do — so an idle driver's baseline stays the fallback
  /// (which the first assert pins: an unconditional fold would return the past scan instant and
  /// fail it).
  #[compio::test]
  async fn next_deadline_folds_the_pending_scan_deadline_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;

    // Baseline: nothing pending, no peers, a never-driven endpoint — the ~50ms idle fallback
    // governs, proving the (elapsed) scan deadline is not folded for an empty pending map.
    let baseline = driver.next_deadline();
    assert!(
      baseline >= std::time::Instant::now() + std::time::Duration::from_millis(40),
      "with nothing pending the idle fallback governs (the scan deadline is not folded)"
    );

    // One in-flight submit + a scan deadline ~5ms out: next_deadline must move to it, well under
    // the fallback.
    let mut fut: std::pin::Pin<Box<SubmitFut<'_>>> =
      Box::pin(handle.submit(Bytes::from_static(b"x")));
    assert!(poll_submit(fut.as_mut()).is_none(), "submit parks");
    drain_one_command(&mut driver);
    let due = driver.clock.now() + std::time::Duration::from_millis(5);
    driver.next_pending_scan = due;
    assert!(
      driver.next_deadline() <= driver.clock.to_std(due),
      "with a submit in flight the scan deadline is folded into next_deadline as a real wake"
    );
    drop(fut);
  }

  /// A submit whose CALLER IS GONE before the driver processes it (the reply future dropped — its
  /// oneshot receiver canceled) must never enter consensus: `handle_command` drops it without
  /// minting a request, releasing its reservation. Without the guard, the teardown drain of a
  /// dead handle's queued submits would EXECUTE them into the endpoint during exit — irreversible
  /// operations nobody can observe.
  #[compio::test]
  async fn a_canceled_queued_submit_never_enters_consensus_quic() {
    let (mut driver, handle) = test_quic_driver_with_handle().await;
    let observer = driver.budget.clone();

    let mut fut: std::pin::Pin<Box<SubmitFut<'_>>> =
      Box::pin(handle.submit(Bytes::from_static(b"dead")));
    assert!(poll_submit(fut.as_mut()).is_none(), "accepted + queued");
    drop(fut); // the caller is gone: the reply receiver cancels
    assert_eq!(
      observer.count(),
      1,
      "the queued command still holds its reservation"
    );

    let cmd = driver.commands.try_recv().expect("the command is buffered");
    let before = driver.next_request;
    let mut ack = None;
    let exit = driver.handle_command(viewstamp_proto::Instant::ZERO, cmd, &mut ack);
    assert!(!exit, "a dropped submit is not an exit signal");
    assert_eq!(driver.next_request, before, "no request number was minted");
    assert!(driver.pending.is_empty(), "nothing entered the pending map");
    assert_eq!(observer.count(), 0, "the reservation released on the spot");
    assert_eq!(observer.bytes(), 0, "and its bytes with it");
    drop(handle);
  }

  /// SHUTDOWN RACE — NO BUDGET LEAK (QUIC driver): submits that reserved the budget and were enqueued
  /// but NOT yet drained into `pending` when the driver tears down must not leak their reservation.
  /// Each `Handle::submit` carries its `ReservationGuard` inside the queued `Command::Submit`; tearing
  /// the driver (and its command channel) down drops those still-queued commands, and each guard's
  /// `Drop` releases its slot. An independent budget clone (the survivor a cloned `Handle` would share)
  /// returns to zero — count AND bytes — so a surviving `Handle` never sees spurious `Busy` from a
  /// reservation stranded across teardown.
  #[compio::test]
  async fn queued_submits_release_budget_when_the_driver_tears_down_quic() {
    let (driver, handle) = test_quic_driver_with_handle().await;
    // The budget clone a surviving cloned `Handle` would observe (the shared submit budget outlives
    // this driver). Reading it after teardown proves no reservation was stranded.
    let observer = driver.budget.clone();

    // Enqueue several submits but DO NOT drain them into `pending`: each reserves the budget and sits
    // in the bounded command channel as a `Command::Submit` carrying its guard.
    let mut futs: Vec<std::pin::Pin<Box<SubmitFut<'_>>>> = Vec::new();
    let mut total_bytes = 0usize;
    for i in 0..8u8 {
      let body = Bytes::from(vec![i; (i as usize + 1) * 16]);
      total_bytes += body.len();
      let mut fut: std::pin::Pin<Box<SubmitFut<'_>>> = Box::pin(handle.submit(body));
      assert!(
        poll_submit(fut.as_mut()).is_none(),
        "each submit is accepted (reserves + enqueues), parking on its reply"
      );
      futs.push(fut);
    }
    assert_eq!(
      observer.count(),
      8,
      "eight reservations are held by the queued commands"
    );
    assert_eq!(
      observer.bytes(),
      total_bytes,
      "their reserved bytes are held"
    );
    assert!(driver.pending.is_empty(), "none was drained into pending");

    // Tear the driver down WITHOUT draining the commands: dropping the driver drops the
    // command-channel receiver, whose drop closes the channel and drains the buffered
    // `Command::Submit`s — each drops its guard, releasing — while `handle` (a live sender) and
    // the parked submit futures still exist. This is the queued-submit-vs-shutdown race: the
    // guards are the single release owner, so no reservation is stranded behind a surviving
    // sender.
    drop(driver);
    assert_eq!(
      observer.count(),
      0,
      "dropping the receiver alone releases every queued submit's guard — no waiting on the Handle"
    );
    drop(futs);
    drop(handle);

    assert_eq!(
      observer.count(),
      0,
      "every queued submit's guard released on teardown: the budget count returns to zero (no leak)"
    );
    assert_eq!(
      observer.bytes(),
      0,
      "and the reserved bytes return to zero, so a surviving Handle sees no spurious Busy"
    );
  }

  /// SHUTDOWN-RACE AIRTIGHTNESS (QUIC driver): a `Submit` queued BEHIND the `Shutdown` command —
  /// enqueued after `shutdown()` but before the run loop drains it — must RESOLVE and release its
  /// budget by the time the shutdown ack arrives, even though `Handle` clones (command-channel
  /// senders) stay alive past the ack. The run loop exits on the `Shutdown` with the submits still
  /// buffered; the teardown's close-then-drain of the command channel drops each queued `Submit`,
  /// so its reply oneshot resolves as dropped (`ReplyDropped`) and its `ReservationGuard` releases.
  /// A teardown that releases buffered commands only when every sender drops would instead pin the
  /// racing submits' replies and budget for as long as any `Handle` clone lives: the awaiting
  /// callers — themselves keeping a `Handle` borrowed — would hang indefinitely.
  #[compio::test]
  async fn submits_queued_behind_a_shutdown_resolve_and_release_budget_quic() {
    let (driver, handle) = test_quic_driver_with_handle().await;
    let observer = driver.budget.clone();
    // The clone that SURVIVES the ack: it keeps the command channel's sender side alive, which is
    // exactly what must NOT keep the queued commands (and their budget) alive.
    let survivor = handle.clone();

    // Enqueue the Shutdown FIRST: one poll sends the command and parks on the ack.
    let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
    let mut shutdown_fut = Box::pin(handle.shutdown());
    assert!(
      std::future::Future::poll(shutdown_fut.as_mut(), &mut cx).is_pending(),
      "the shutdown enqueues its command and parks on the ack"
    );

    // Then several submits BEHIND it: each reserves budget and enqueues, parking on its reply.
    let mut racing: Vec<std::pin::Pin<Box<SubmitFut<'_>>>> = Vec::new();
    let mut total_bytes = 0usize;
    for i in 0..4u8 {
      let body = Bytes::from(vec![i; 32]);
      total_bytes += body.len();
      let mut fut: std::pin::Pin<Box<SubmitFut<'_>>> = Box::pin(handle.submit(body));
      assert!(
        poll_submit(fut.as_mut()).is_none(),
        "a submit racing the queued shutdown is accepted (reserves + enqueues)"
      );
      racing.push(fut);
    }
    assert_eq!(observer.count(), 4, "the racing submits hold budget");
    assert_eq!(observer.bytes(), total_bytes, "and their reserved bytes");

    // Run the driver: it drains the Shutdown first and tears down with the submits still queued.
    compio::runtime::spawn(driver.run()).detach();
    compio::time::timeout(std::time::Duration::from_secs(5), shutdown_fut)
      .await
      .expect("the shutdown ack arrives")
      .expect("shutdown acks teardown");

    // Every racing submit RESOLVES after the ack (bounded await, no hang)...
    for (i, fut) in racing.into_iter().enumerate() {
      let res = compio::time::timeout(std::time::Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("racing submit #{i} must resolve at teardown, not hang"));
      assert!(
        matches!(
          res,
          Err(DriverError::ReplyDropped | DriverError::DriverGone)
        ),
        "racing submit #{i} resolves as dropped/gone, got {res:?}"
      );
    }
    // ...and the shared budget is FULLY released — count AND bytes — while the clones still live.
    assert_eq!(
      observer.count(),
      0,
      "the budget count returns to zero at the ack even with Handle clones alive"
    );
    assert_eq!(
      observer.bytes(),
      0,
      "and the reserved bytes return to zero (no reservation pinned by a queued command)"
    );
    drop(survivor);
    drop(handle);
  }
}

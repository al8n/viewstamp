use std::{
  collections::HashMap,
  io,
  net::SocketAddr,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use agnostic::{
  Runtime,
  net::{Net, TcpListener, TcpStream},
};
use futures_channel::oneshot;
use viewstamp_proto::Instant;
// The proto's transport `Conn<T>` is aliased `TransportConn` here so the bare name `Conn` belongs to
// the driver's owned per-connection unit (`crate::bridge::Conn`).
use viewstamp_proto::{
  ClientId, CloseCause, Config, Conn as TransportConn, ConnId, Membership, Peer, ReplicaId,
  Request, RequestNumber, StateMachine, StreamCoordinator, StreamTransport, Superblock, Wal,
};

use viewstamp_driver::{
  Clock, Command, DriverConfig, DriverError, Handle, InflightBudget, Pending, PendingMap,
  build_endpoint, deliver_event, drain_pending, jittered, pending_scan_interval,
  reap_and_collect_retransmits,
};

use crate::{
  bridge::{
    BridgeInbound, BridgeOut, Conn, ConnTask, DialReady, Redial, StreamOf, bridge_read,
    bridge_write,
  },
  task::AbortOnDrop,
};

/// Shared inbound-channel capacity (bridge tasks -> driver). Bounds the bytes in flight to
/// `INBOUND_CAP * RECV_BUF_LEN`: once full the bridge's `send_async` awaits, the bridge stops
/// reading, and kernel TCP backpressure slows the peer. The driver drains the inbound every loop
/// iteration (iter-top fairness + the select arm), so this only fills under genuine overload.
const INBOUND_CAP: usize = 256;

/// Backoff before re-arming `accept()` after an accept error. While it is pending the accept arm
/// is DISABLED (a never-ready future substitutes for it) and this deadline folds into the run
/// loop's timer arm like every other wake deadline, so commands, peer frames, and consensus timers
/// keep running and a persistent synchronously-resolving accept error (e.g. fd exhaustion) cannot
/// hot-spin the loop re-arming a failing accept. While the arm is parked — and whenever the arm
/// simply loses the select — further peers queue in the kernel's listen backlog: exactly listener
/// backpressure, with no user-space staging to bound.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// Tune a freshly-connected/accepted peer TCP socket. Best-effort: every option here is latency /
/// failure-detection tuning, not a correctness requirement, so a socket that rejects one still
/// carries consensus traffic.
fn tune_peer_socket<C: TcpStream>(stream: &C) {
  // TCP_NODELAY: consensus pipelines small writes (the next Prepare goes out while the prior one is
  // un-acked), and Nagle + delayed-ACK would hold each back up to ~40ms exactly there.
  let _ = stream.set_nodelay(true);
  // The remaining options are not on the agnostic trait; `SockRef` reaches them through the
  // stream's fd (every agnostic-net socket exposes the std fd traits).
  let sock = socket2::SockRef::from(stream);
  // SO_KEEPALIVE: kernel probes eventually surface a silently-dead peer (no FIN/RST arrived) as a
  // socket error, instead of leaving an idle conn to the ~15min TCP retransmission timeout.
  let _ = sock.set_keepalive(true);
  // TCP_USER_TIMEOUT (Linux-only): bound how long written-but-unacked bytes may sit before the
  // kernel fails the conn, so a peer that vanishes mid-stream errors out (and redials) in seconds.
  #[cfg(target_os = "linux")]
  let _ = sock.set_tcp_user_timeout(Some(Duration::from_secs(10)));
}

/// Builds a transport `Conn<T>` for dialing the given peer (captures the embedder's TLS client
/// config + cluster id). `Send + Sync` so the driver holding it stays `Send` (its `run()` future
/// must be spawnable on a multi-threaded runtime).
pub(crate) type DialerFactory<T> = Arc<dyn Fn(Peer) -> TransportConn<T> + Send + Sync>;
/// Builds a transport `Conn<T>` for an accepted inbound connection (captures the embedder's TLS
/// server config). `Send + Sync` for the same reason as [`DialerFactory`].
pub(crate) type AcceptorFactory<T> = Arc<dyn Fn() -> TransportConn<T> + Send + Sync>;

/// The reactor (readiness) TCP/TLS driver, generic over the [`agnostic`] runtime. Owns the
/// listener + the stream coordinator + storage on one task; the run loop's accept arm awaits
/// `listener.accept()` directly — a readiness accept consumes nothing when a losing select arm
/// drops it (an un-returned connection stays in the kernel listen backlog) — so no helper task or
/// listener clone exists. Each peer connection is one owned `Conn` unit whose live task(s) (the
/// dial task, then the two independent bridge halves) the driver holds as abort-on-drop handles,
/// so dropping the `Conn` is the connection's single complete teardown on every runtime.
pub struct ReactorStreamDriver<R: Runtime, S, T, W, B> {
  coord: StreamCoordinator<S, T>,
  wal: W,
  sb: B,
  listener: <R::Net as Net>::TcpListener,
  /// While `Some`, the most recent `accept()` failed and the accept arm is disabled until this
  /// deadline passes (see [`ACCEPT_ERROR_BACKOFF`]). Folded into [`Self::next_deadline`] so the
  /// re-enabling wake is a REAL wake deadline, never a hope that other traffic wakes the loop.
  accept_backoff_until: Option<std::time::Instant>,
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
  /// A clone of the shared in-flight submit budget, retained for test observability only. Production
  /// release is by construction: the `Handle` reserves a [`ReservationGuard`] per submit, the guard
  /// rides the `Command::Submit` then the `Pending` entry, and dropping that entry (commit,
  /// cancellation reclaim, shutdown drain) — or the queued command on teardown — releases the slot, so
  /// the driver itself never releases against this handle.
  ///
  /// [`ReservationGuard`]: viewstamp_driver::ReservationGuard
  #[cfg(test)]
  budget: InflightBudget,
  /// One owned unit per connection; its redial target (if any) lives in [`Conn::redial`], so there
  /// is no separate dialed-peer map to keep in sync. Bounded by max_conns + the peer count: accept
  /// admission stops at max_conns live conns, while mesh dials are never refused (consensus
  /// liveness) — so a redial while accepted conns hold the cap can exceed it transiently, by at
  /// most the missing-mesh count. The constructor refuses a max_conns below TWICE the peer count (the
  /// mutual-dial mesh needs a dialed and an accepted conn per peer), so the full mesh — both
  /// directions — fits the cap with the startup dials in place, and at the cap a fresh accept
  /// EVICTS the oldest unvalidated accepted conn (validated and dialed conns never evict), so
  /// unvalidated sockets cannot durably deny a mesh socket admission. Outside the guarantee: a
  /// sustained accept flood arriving faster than handshakes complete can thrash the in-flight
  /// handshakes themselves — on the cluster-private network this transport requires, that is the
  /// operator's flood to stop, not an admission-policy problem.
  conns: HashMap<ConnId, Conn<R>>,
  /// Closes counted by [`CloseCause`] (indexed by [`CloseCause::index`]): the coordinator's
  /// internal closes as drained by [`Self::reconcile_closed_conns`], plus the driver's own
  /// for-cause closes (auth-deadline reap, out-queue overflow, dead-bridge send failure,
  /// at-capacity accept drop). Each close
  /// is counted exactly once, at the site that decided it; the coordinator-reap echo of a close the
  /// driver already counted is filtered by the conn no longer being in `conns`.
  close_counts: [u64; CloseCause::COUNT],
  peer_addrs: HashMap<ReplicaId, SocketAddr>,
  dialer: DialerFactory<T>,
  acceptor: AcceptorFactory<T>,
  /// Bounded `futures_channel::mpsc::channel(cfg.cmd_cap())`: a refused send surfaces as `Busy`
  /// rather than growing, and `Receiver::close` is the teardown primitive — it refuses new sends
  /// (bouncing the command back to its sender) while this receiver still drains what was already
  /// buffered, so the shutdown ack can promise no queued command survives it.
  commands: futures_channel::mpsc::Receiver<Command>,
  /// Bounded `flume::bounded(cfg.events_cap())`: best-effort, dropped-on-full (see `deliver_event`).
  events: flume::Sender<viewstamp_proto::Event>,
  /// Bounded `flume::bounded(INBOUND_CAP)`: a full channel backpressures the bridge's `send_async`,
  /// which stops reading and slows the peer via kernel TCP backpressure.
  bridge_inbound_tx: flume::Sender<BridgeInbound>,
  bridge_inbound_rx: flume::Receiver<BridgeInbound>,
  /// Unbounded by construction but BOUNDED by the live dial count: exactly one dial task exists per
  /// dialed `Conn`, at most one dial is in flight per configured peer, and each sends at most one
  /// `DialReady` — at most one live entry per configured peer, plus at most one already-sent
  /// stale entry awaiting the next iteration's drain. Drained (bounded budget) every loop
  /// iteration.
  dial_ready_tx: flume::Sender<DialReady<R>>,
  dial_ready_rx: flume::Receiver<DialReady<R>>,
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

impl<R, S, T, W, B> ReactorStreamDriver<R, S, T, W, B>
where
  R: Runtime,
  S: StateMachine,
  T: StreamTransport,
  W: Wal,
  B: Superblock,
{
  /// Build the driver: bind the listener, build the coordinator, set up the connection table +
  /// channels, and return a `Handle`. Configured peer dials are issued at `run()` start.
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
  /// endpoint's recovery nonce is derived fresh per construction (wall-clock-mixed), as recovery
  /// freshness requires.
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
  /// [`DriverError::Bind`] if the listener cannot bind.
  #[allow(clippy::too_many_arguments)]
  pub async fn new(
    config: Config,
    membership: Membership,
    state_machine: S,
    wal: W,
    sb: B,
    client: ClientId,
    first_request: u64,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    dialer: DialerFactory<T>,
    acceptor: AcceptorFactory<T>,
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
      bind_addr,
      peers,
      dialer,
      acceptor,
      storage_ready,
      DriverConfig::new(),
    )
    .await
  }

  /// As [`Self::new`] but with an embedder-supplied [`DriverConfig`] (timeouts, backoff, submit and
  /// connection caps) instead of the defaults. `cfg` carries operational tuning only; the transport
  /// security configuration stays in the `dialer`/`acceptor` factories.
  ///
  /// # Errors
  /// [`DriverError::CapBelowPeerMesh`] if `cfg.max_conns()` is below twice the configured peer
  /// count (the mutual-dial mesh needs one dialed and one accepted connection per peer, and both
  /// are consensus-required); [`DriverError::Bind`] if the listener cannot bind.
  #[allow(clippy::too_many_arguments)]
  pub async fn with_config(
    config: Config,
    membership: Membership,
    state_machine: S,
    mut wal: W,
    mut sb: B,
    client: ClientId,
    first_request: u64,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    dialer: DialerFactory<T>,
    acceptor: AcceptorFactory<T>,
    storage_ready: flume::Receiver<()>,
    cfg: DriverConfig,
  ) -> Result<(Self, Handle), DriverError> {
    // Refuse a cap that cannot admit the replica mesh. The mesh is MUTUAL-dial: `run()` dials
    // every configured peer unconditionally (consensus liveness — mesh links are never load-shed)
    // AND every peer dials back, and an inbound socket is admission-controlled until its
    // handshake validates — so the cap must leave room for both directions. With less than twice
    // the peer count, startup dials alone can fill the cap and the accept gate then drops every
    // inbound mesh socket before it can validate: the mesh wedges even though construction
    // succeeded. Misconfiguration is a constructor error, not a load condition.
    if peers.len().saturating_mul(2) > cfg.max_conns() {
      return Err(DriverError::CapBelowPeerMesh {
        max_conns: cfg.max_conns(),
        peers: peers.len(),
      });
    }
    let clock = Clock::new();
    let listener = <R::Net as Net>::TcpListener::bind(bind_addr)
      .await
      .map_err(DriverError::Bind)?;
    let endpoint = build_endpoint(config, membership, state_machine, &mut wal, &mut sb)?;
    let coord = StreamCoordinator::new(endpoint);
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
    let (bin_tx, bin_rx) = flume::bounded(INBOUND_CAP);
    // Unbounded by construction but bounded by the live dial count: one dial task per dialed peer
    // (at most one in flight per configured peer), each sending exactly one `DialReady` — so at
    // effectively bounded by the configured peer count; see the field doc.
    let (dr_tx, dr_rx) = flume::unbounded();
    let budget = InflightBudget::new(cfg.max_inflight(), cfg.max_pending_bytes());
    let driver = Self {
      coord,
      wal,
      sb,
      listener,
      accept_backoff_until: None,
      clock,
      cfg,
      client,
      next_request: first_request,
      pending: PendingMap::new(),
      next_pending_scan: Instant::ZERO,
      #[cfg(test)]
      budget: budget.clone(),
      conns: HashMap::new(),
      close_counts: [0; CloseCause::COUNT],
      peer_addrs: peers.into_iter().collect(),
      dialer,
      acceptor,
      commands: commands_rx,
      events: events_tx,
      bridge_inbound_tx: bin_tx,
      bridge_inbound_rx: bin_rx,
      dial_ready_tx: dr_tx,
      dial_ready_rx: dr_rx,
      storage_ready,
      storage_notifier_closed: false,
      reconfigure: None,
    };
    let handle = Handle::new(commands_tx, events_rx, budget);
    Ok((driver, handle))
  }
}

impl<R, S, T, W, B> ReactorStreamDriver<R, S, T, W, B>
where
  R: Runtime,
  S: StateMachine,
  T: StreamTransport,
  W: Wal,
  B: Superblock,
{
  /// Run the driver to completion. Returns on a `Shutdown` command or when all `Handle` clones drop.
  ///
  /// Both orderly exits — and therefore the ack a [`Handle::shutdown`] awaits — are
  /// listener-release barriers: the driver is the SOLE owner of its listener (the accept arm
  /// borrows it in-loop; no helper task holds a clone), so the teardown's `drop` of the listener
  /// closes the fd synchronously, and an embedder may bind a new driver to the same address the
  /// moment `shutdown().await` (or an awaited `run()` task) returns. Peer-connection sockets are
  /// aborted in the same teardown but release asynchronously (each aborted bridge task drops its
  /// owned half once the runtime processes the abort); they are separate fds and the listener binds
  /// with `SO_REUSEADDR`, so they never gate rebinding the listen address. Cancelling the `run()`
  /// future itself releases the fd just as promptly — dropping the future drops the whole driver,
  /// listener included — but reaching that cancellation is runtime-specific: aborting the spawned
  /// task cancels everywhere, while dropping a raw spawn handle does NOT (tokio detaches, leaving
  /// the task running and the listener owned; smol cancels). The portable stop paths are
  /// [`Handle::shutdown`], dropping every `Handle`, or an explicit task abort.
  pub async fn run(mut self) {
    use futures_util::{FutureExt, select_biased};

    /// Per-iteration command drain budget: bound the iter-top fairness step so a steady command
    /// stream can't itself starve the I/O select, while still letting `Shutdown`/`Submit` make
    /// progress under an accept flood.
    const CMD_BUDGET: usize = 64;

    /// Per-iteration inbound/dial-ready drain budget: bound each iter-top channel drain so a flood
    /// on one channel can't monopolize the loop — the next iteration continues draining the rest.
    const IO_BUDGET: usize = 256;

    // Initial dials: connect to every configured peer (each at the base redial backoff).
    for (id, addr) in self.peer_addrs.clone() {
      self.dial_peer(id, addr, Duration::ZERO, self.cfg.redial_backoff_base());
    }
    let now = self.clock.now();
    self.pump_outputs(now).await;

    let mut shutdown_ack: Option<oneshot::Sender<()>> = None;
    loop {
      // Iter-top fairness: drain + PROCESS every input channel (bounded budgets) BEFORE the biased
      // select, so no channel can be starved by another. The accept arm is the select's first
      // (highest priority) arm, so without this a continuous accept backlog would win every
      // iteration and starve inbound consensus frames + dial completions indefinitely — the node
      // would accept sockets and fire timers but never advance consensus. Draining here, then using
      // the select only to WAIT, makes accept one-per-iteration while everything else drains fully
      // each pass.
      let now = self.clock.now();

      // Commands: bounded so a steady command stream can't itself monopolize the loop, while
      // `Shutdown`/`Submit` still make progress under an accept flood.
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
          // for good, so exit the run loop (an accept backlog would otherwise keep winning the
          // biased accept arm and hold the listener + conns alive, spinning on the ended command
          // channel). Termination is the stream END, not a sender-count probe: commands queued by
          // since-dropped handles flow through the arm above first, bounded by the channel buffer.
          Err(futures_channel::mpsc::TryRecvError::Closed) => {
            exit = true;
            break;
          }
        }
      }
      if exit {
        break;
      }

      // Inbound peer frames + EOF/Error closes, then dial completions: bounded so a flood on one
      // channel can't monopolize the loop (the next iteration continues draining).
      for _ in 0..IO_BUDGET {
        match self.bridge_inbound_rx.try_recv() {
          Ok(inb) => self.handle_inbound(now, inb),
          Err(_) => break,
        }
      }
      for _ in 0..IO_BUDGET {
        match self.dial_ready_rx.try_recv() {
          Ok(dr) => self.handle_dial_ready(now, dr),
          Err(_) => break,
        }
      }
      while self.storage_ready.try_recv().is_ok() {}

      // Fire an already-due consensus timer, so an accept flood can't suppress heartbeats/view-
      // changes (which would wedge liveness). `StreamCoordinator`'s `poll_timeout` reports a proto
      // `Instant`, so map it onto the clock epoch before comparing. `handle_timeout` on a not-yet-due
      // timer is a no-op, so this is idempotent-safe.
      if self
        .coord
        .poll_timeout()
        .is_some_and(|d| self.clock.to_std(d) <= std::time::Instant::now())
      {
        self.coord.handle_timeout(now, &mut self.wal, &mut self.sb);
      }
      self.retransmit_stale(now);
      self.pump_outputs(now).await;
      self.advance_reconfigure(now);
      // Reconcile conns the coordinator closed internally (bad frame / failed identity / cap
      // overflow): tear down the still-open socket + redial a dialed peer, else it's a silent
      // partition. Idempotent with the driver's own EOF/Error/out-full closes (see helper).
      self.reconcile_closed_conns(now);
      // Reap conns that registered but never validated within the configured auth deadline (a
      // stalled handshake):
      // bounds accepted-but-unauthenticated sockets so they can't exhaust fds/tasks/memory.
      self.reconcile_auth_deadlines(now);

      // Re-enable the accept arm once its error backoff has elapsed; the backoff deadline is folded
      // into `next_deadline` below, so this observation is a real wake, not a poll.
      if self
        .accept_backoff_until
        .is_some_and(|until| until <= std::time::Instant::now())
      {
        self.accept_backoff_until = None;
      }

      // Recompute AFTER the iter-top timer fire so it reflects the next deadline (avoids a redundant
      // immediate select-timer fire for the timer we just serviced).
      let deadline = self.next_deadline();

      // The six futures BORROW disjoint driver fields (`accept_fut` holds `&self.listener`,
      // `cmd_fut` `&mut self.commands`, the rest their channels). Confine construction +
      // `select_biased!` to this inner scope: when it ends the pinned futures drop, releasing the
      // borrows so the post-select `&mut self` work is legal. Losing the select is free for every
      // arm: the timer/channel waits are plain restartable waits, and the readiness `accept()`
      // consumes nothing unless it completed — a connection it did not return stays in the kernel
      // listen backlog for the next iteration's arm.
      //
      // The select only WAITS for the next event so the loop can re-drain at iter-top. The accept
      // arm is processed one-per-iteration; its `Err` (a failed accept) parks the arm on the error
      // backoff. `timer_fut`/`storage_fut` are genuinely wake-only: they yield `()` / `Ok(())`, so
      // dropping the resolved value loses nothing (the iter-top due-timer check + the unconditional
      // `pump_outputs` storage re-poll cover them next pass). `cmd_fut`/`inbound_fut`/`dial_fut`/
      // `accept_fut`, by contrast, CONSUME an item when they resolve (flume's `recv_async` removes
      // it from the channel; a completed `accept()` removes the connection from the backlog), so
      // their item is CAPTURED into a local and handled after this scope — dropping it would
      // silently lose a command (e.g. a `Shutdown`), a peer frame, a dial completion, or an
      // accepted socket. The bulk still drains at iter-top; this just doesn't waste the one item
      // the select happened to consume to wake us.
      let mut accepted = None;
      let mut accept_err = false;
      let mut command = None;
      let mut inbound = None;
      let mut dial_ready = None;
      let mut storage_closed = false;
      {
        let accept_fut = match self.accept_backoff_until {
          // The accept arm IS the listener accept: readiness-based, cancel-safe to lose.
          None => self.listener.accept().left_future(),
          // Error backoff pending: park the arm on a never-ready future; the timer arm (which
          // folds the backoff deadline) re-runs the loop to re-enable it.
          Some(_) => {
            futures_util::future::pending::<io::Result<(StreamOf<R>, SocketAddr)>>().right_future()
          }
        }
        .fuse();
        let timer_fut =
          R::sleep(deadline.saturating_duration_since(std::time::Instant::now())).fuse();
        let cmd_fut = self.commands.recv().fuse();
        let inbound_fut = self.bridge_inbound_rx.recv_async().fuse();
        let dial_fut = self.dial_ready_rx.recv_async().fuse();
        // A disconnected notifier resolves `recv_async` immediately and forever; once latched the
        // arm parks on a never-ready future so the dead channel cannot keep the select hot (see
        // the `storage_notifier_closed` field). The inbound/dial arms are immune by construction:
        // the driver retains a sender clone of each for the conns it has yet to mint.
        let storage_fut = if self.storage_notifier_closed {
          futures_util::future::pending::<Result<(), flume::RecvError>>().right_future()
        } else {
          self.storage_ready.recv_async().left_future()
        }
        .fuse();
        futures_util::pin_mut!(
          accept_fut,
          timer_fut,
          cmd_fut,
          inbound_fut,
          dial_fut,
          storage_fut
        );

        select_biased! {
          a = accept_fut => {
            match a {
              Ok((stream, addr)) => accepted = Some((stream, addr)),
              Err(_) => accept_err = true,
            }
          }
          _ = timer_fut => {}
          // Capture the whole `Result`: `Err(RecvError)` (all `Handle` clones dropped and the
          // buffer drained — the channel has ended) must exit the loop, not be silently ignored —
          // otherwise the accept arm keeps winning the biased select while the dead command
          // channel is dropped on the floor, spinning forever.
          c = cmd_fut => { command = Some(c); }
          i = inbound_fut => { if let Ok(i) = i { inbound = Some(i); } }
          d = dial_fut => { if let Ok(d) = d { dial_ready = Some(d); } }
          s = storage_fut => { storage_closed = s.is_err(); }
        }
      }
      let now = self.clock.now();

      // Handle the single item the select consumed to wake us (the rest drained at iter-top). These
      // run the same shared helpers as the iter-top drain, so there is no behavior divergence.
      if let Some(inb) = inbound {
        self.handle_inbound(now, inb);
      }
      if let Some(dr) = dial_ready {
        self.handle_dial_ready(now, dr);
      }
      if accept_err {
        // An accept error is transient for a listener (the conn that failed mid-accept is the
        // peer's to retry), so the listener stays in service — but the arm parks on this backoff
        // first, bounding the retry rate so a persistent error (e.g. fd exhaustion) cannot
        // hot-spin the loop.
        self.accept_backoff_until = Some(std::time::Instant::now() + ACCEPT_ERROR_BACKOFF);
      }
      if storage_closed {
        self.storage_notifier_closed = true;
      }
      if let Some(cmd_result) = command {
        match cmd_result {
          Ok(cmd) => {
            if self.handle_command(now, cmd, &mut shutdown_ack) {
              break;
            }
          }
          // The command channel ended (last `Handle` dropped, buffer drained): terminate the loop.
          Err(_) => break,
        }
      }

      if let Some((stream, _addr)) = accepted {
        // Admission control: at the live-connection cap, EVICT the oldest unvalidated ACCEPTED
        // conn in favor of the fresh socket. An inbound mesh socket arrives unvalidated by
        // construction (the Labeled handshake is what authenticates a cluster peer), so dropping
        // fresh accepts while earlier junk squats the table would make mesh formation depend on
        // the auth-deadline reap's timing; eviction is that same reap, demand-driven. Validated
        // (cluster-authenticated) and dialed conns are never evicted — junk displaces only other
        // junk or a not-yet-validated handshake (the oldest in flight) — and the constructor's twice-the-peers floor
        // sizes the cap so the mesh's own conns always fit. Only when every slot holds a
        // validated-or-dialed conn is the fresh accept dropped instead (let `stream` fall out of
        // scope → the socket closes), so an accept flood still cannot grow `conns` + the
        // coordinator router without bound.
        if self.conns.len() >= self.cfg.max_conns() {
          // The at-capacity policy executes either way; the count is charged to the conn that
          // loses the slot (the evictee, or the fresh socket when nothing is evictable).
          self.close_counts[CloseCause::AcceptCapacity.index()] += 1;
          // Disjoint-fields borrow (as in `reconcile_auth_deadlines`): `is_conn_validated`
          // borrows `&self.coord` while iterating `&self.conns`; the pick is closed after.
          let evict = self
            .conns
            .iter()
            .filter(|(id, c)| {
              c.auth_deadline.is_some() && c.redial.is_none() && !self.coord.is_conn_validated(**id)
            })
            .min_by_key(|(_, c)| c.auth_deadline)
            .map(|(&id, _)| id);
          if let Some(id) = evict {
            self.close_conn(id, now);
          }
        }
        if self.conns.len() < self.cfg.max_conns() {
          let conn = (self.acceptor)();
          let id = self
            .coord
            .register_accepted(Peer::Replica(ReplicaId::new(0)), conn);
          self.spawn_bridge_accepted(now, id, stream);
        } else {
          drop(stream);
        }
      }
      // Any outbound bytes the just-handled command/inbound/dial/accept queued (a submitted request,
      // a peer reply, a new conn's handshake) flush at the TOP of the next iteration: the loop
      // re-enters iter-top immediately (no `await` between here and the next `pump_outputs`), so
      // this is not a wait-for-wake.
    }

    // Drop every still-pending submit (its commit never arrived) and clear the map: each entry's
    // `ReservationGuard` releases its budget slot on drop, so the budget never leaks across the
    // driver's life. A `Submit` still queued in the command channel releases in the
    // close-then-drain below, its guard with it.
    drain_pending(&mut self.pending);
    // One teardown for every connection: dropping each `Conn` drops its `AbortOnDrop` handle(s),
    // aborting the live task(s) (the dial task OR both bridge halves) on every runtime, and drops
    // its `out_tx`. Aborting a write task parked mid-chunk on a non-draining peer destroys the
    // parked future, which drops the socket write-half the task owns — the abort IS the fd-release
    // path for peer sockets (a graceful `out_tx` drop alone could not preempt that park). On
    // shutdown the consensus state is durable, so a hard abort here (vs. a best-effort byte flush)
    // loses nothing a restart can't resume.
    self.conns.clear();
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
    // Dropping these receivers releases the receivers' side and unwedges any still-aborting
    // bridge/dial task parked on a full channel (its `send_async` errors out instead of waiting
    // for its abort to be processed). The queued items — dial completions carrying sockets,
    // buffered inbound bytes — free with their sender tasks' prompt-but-asynchronous abort above
    // (the per-connection sockets are separate fds and never gate the listen-address rebind).
    drop(self.dial_ready_rx);
    drop(self.bridge_inbound_rx);
    // The fd-release point: the driver is the listener's SOLE owner — the accept arm's borrow died
    // with the loop, and no helper task holds a clone — so this drop closes the fd synchronously.
    // Once it returns the listen address is free, which is what makes the ack below (and `run()`'s
    // return) an immediate-rebind contract.
    drop(self.listener);
    if let Some(ack) = shutdown_ack {
      let _ = ack.send(());
    }
  }

  /// Handle one [`BridgeInbound`]: feed received bytes to the coordinator, or reap the conn on the
  /// bridge's EOF/Error.
  ///
  /// Shared by the iter-top fairness drain so a continuous accept backlog can't starve peer
  /// consensus frames or connection-close signals.
  fn handle_inbound(&mut self, now: Instant, inb: BridgeInbound) {
    match inb {
      BridgeInbound::Bytes { id, bytes } => {
        self
          .coord
          .handle_conn_data(id, &bytes, false, now, &mut self.wal, &mut self.sb);
      }
      BridgeInbound::Eof { id } | BridgeInbound::Error { id } => {
        self.close_conn(id, now);
      }
    }
  }

  /// Handle one [`DialReady`]: on success replace the finished dial task with the two bridge halves
  /// (read + write tasks); on failure tear the conn down (which redials via [`Conn::redial`]).
  ///
  /// A `DialReady` is STALE iff its `ConnId` is no longer in `conns`: `dial_peer` inserts the [`Conn`]
  /// before the async connect completes, so if the conn was closed + replaced (e.g. `close_conn`
  /// reaped it and redialed a NEW id) before this dial finished, the old id is gone. A stale success
  /// is dropped entirely — the carried stream/`out_rx` simply drop here; a stale failure does
  /// nothing (the replacement conn owns its own dial).
  ///
  /// The dialed conn's `auth_deadline` is stamped HERE, at the bridge handoff — not at dial
  /// registration. A pending dial is bounded by the configured dial timeout, so a slow-but-healthy
  /// connect keeps the full auth window for the post-connect `Labeled`/TLS handshake instead of
  /// having it consumed while it was still connecting (which `reconcile_auth_deadlines` could
  /// otherwise reap as a stalled conn). This mirrors the accept path, where `spawn_bridge_accepted`
  /// stamps the deadline when the bridge starts (at accept, the post-connect point for an accepted
  /// socket).
  ///
  /// Shared by the iter-top fairness drain so a continuous accept backlog can't starve live dial
  /// completions (which would wedge reconnect).
  fn handle_dial_ready(&mut self, now: Instant, dr: DialReady<R>) {
    let Some(conn) = self.conns.get_mut(&dr.id) else {
      return; // stale: this conn was already closed/replaced before its dial completed
    };
    match dr.result {
      Ok(stream) => {
        tune_peer_socket(&stream);
        let inbound_tx = self.bridge_inbound_tx.clone();
        // Replace the now-finished dial task with the two bridge halves; dropping the old handle
        // aborts a task that already completed — a no-op. Split into OWNED halves so the read and
        // write tasks each own one half and make progress concurrently (a large write never starves
        // reads). The writer drains the `out_rx` the dial task shipped back and decrements
        // `dr.queued_bytes` — the same counter `conn.queued_bytes` clones — incrementally as it writes.
        let (read_half, write_half) = stream.into_split();
        conn.tasks = ConnTask::Bridged {
          read: AbortOnDrop::new(R::spawn(bridge_read(read_half, dr.id, inbound_tx.clone()))),
          write: AbortOnDrop::new(R::spawn(bridge_write(
            write_half,
            dr.id,
            dr.out_rx,
            dr.queued_bytes,
            inbound_tx,
          ))),
        };
        // Start the auth window now the bridge (hence the handshake) begins: the connect is done, so
        // the full configured auth deadline covers the `Labeled`/TLS handshake.
        // `reconcile_auth_deadlines` reaps the conn if it never validates within this window.
        conn.auth_deadline = Some(now + self.cfg.auth_deadline());
      }
      // Dial failed: tear the conn down. `close_conn` reaps it in the coordinator and redials the
      // peer/addr held in `Conn.redial` after a backoff.
      Err(_) => self.close_conn(dr.id, now),
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
    shutdown_ack: &mut Option<oneshot::Sender<()>>,
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
        let rn = RequestNumber::with(self.next_request);
        let request = Request::new(self.client, rn, body);
        // MOVE the reservation guard into the `Pending` entry: from here the entry owns the budget
        // slot, and dropping it (on commit, cancellation reclaim, or shutdown drain) releases.
        self.pending.insert(
          (self.client, rn),
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

  /// Reconcile conns the COORDINATOR closed internally (a bad frame, a failed identity, or an
  /// outbound-cap overflow): the socket is still open and its bridge still running, so without this
  /// the proto-closed conn is a silent partition until the socket happens to fail. Drain the
  /// coordinator's closed-conn signal and tear down + redial each via [`Self::close_conn`].
  ///
  /// Idempotent with the driver's own close paths: when the driver already tore the conn down (its
  /// EOF/Error/out-full path also reaps in the coordinator, which records the id here), the second
  /// `close_conn(id)` finds `conns` already empty for `id` (so no double-abort and no double-redial)
  /// and its `handle_conn_data(id, &[], true, ..)` is a no-op on the already-reaped conn. A
  /// genuinely-reaped id that the driver has NOT yet torn down is closed + redialed here.
  fn reconcile_closed_conns(&mut self, now: Instant) {
    while let Some((id, cause)) = self.coord.poll_conn_closed() {
      // Count only a close the COORDINATOR decided (the conn is still held here): the reap echo of
      // a close the driver already tore down — and counted at its own site — finds `conns` empty
      // for `id` and must not double-count.
      if self.conns.contains_key(&id) {
        self.close_counts[cause.index()] += 1;
      }
      self.close_conn(id, now);
    }
  }

  /// Enforce the per-conn auth deadline: a conn the coordinator now reports validated clears its
  /// deadline (no longer subject to it); a conn still unvalidated at its deadline is torn down via
  /// [`Self::close_conn`] (a DIALED conn redials from its `Conn::redial`; an ACCEPTED conn just
  /// closes). This is the accept-side admission control that stops a peer which completes the socket
  /// connect but stalls before the `Labeled`/TLS handshake validates from pinning a `conns` entry (and
  /// a coordinator router entry) forever.
  ///
  /// Validation is ALSO the redial-backoff reset point (the stream mirror of the QUIC driver's
  /// reset-on-bind): the link is genuinely up, so the conn's carried [`Redial::backoff`] returns to
  /// the base — a LATER loss redials at 200ms, not at whatever cadence a preceding dead period had
  /// built up. A conn that connects but never validates keeps its backed-off cadence: the deadline
  /// reap below feeds `close_conn`, whose redial doubles the carried backoff.
  ///
  /// Borrow note: `self.coord.is_conn_validated(id)` borrows `&self.coord` while `self.conns` is
  /// borrowed mutably — DISJOINT fields, so the loop compiles; the to-close ids are collected and
  /// closed after, because `close_conn` takes `&mut self`.
  fn reconcile_auth_deadlines(&mut self, now: Instant) {
    let mut expired = Vec::new();
    for (&id, conn) in self.conns.iter_mut() {
      if conn.auth_deadline.is_some() {
        if self.coord.is_conn_validated(id) {
          conn.auth_deadline = None;
          if let Some(redial) = conn.redial.as_mut() {
            redial.backoff = self.cfg.redial_backoff_base(); // validated: the next loss starts the schedule over
          }
        } else if let Some(d) = conn.auth_deadline
          && now >= d
        {
          expired.push(id);
        }
      }
    }
    for id in expired {
      self.close_counts[CloseCause::AuthDeadline.index()] += 1;
      self.close_conn(id, now);
    }
  }

  /// The number of connection closes attributed to `cause` so far — the coordinator's internal
  /// closes plus the driver's own (auth-deadline, out-queue overflow, dead-bridge send failure,
  /// accept-cap). Test/diagnostic
  /// observability, not a stable embedder API (hence `#[doc(hidden)]`).
  #[doc(hidden)]
  pub fn conn_close_count(&self, cause: CloseCause) -> u64 {
    self.close_counts[cause.index()]
  }

  /// Tear down a connection the proto/socket/queue has lost: one `remove` drops the [`Conn`], whose
  /// [`AbortOnDrop`] handle(s) abort its live task(s) (the dial task OR both bridge halves) and
  /// whose `out_tx` drops; then reap it in the coordinator (eof) and, if it was a DIALED conn,
  /// redial the peer/addr held in [`Conn::redial`].
  ///
  /// Shared by the bridge-EOF/Error path (the signalling half has already exited; the drop aborts the
  /// other half and discards the finished task's handle), the dial-failure path (drops the finished
  /// dial task), and the out-queue-over-budget path in [`Self::pump_outputs`] (the drop actively
  /// ABORTS a stuck writer: the `AbortOnDrop` aborts the task on every runtime, destroying the
  /// write future mid-`await` and dropping the socket half it owns — preempting a write parked on a
  /// non-reading peer, which dropping `out_tx` alone cannot — and aborts the read half with it).
  /// Redial only fires for conns WE dialed (an accepted `Conn` has `redial: None`; that peer redials
  /// us). Idempotent: a second call for an already-removed id finds `conns` empty (no
  /// double-abort/redial) and `handle_conn_data(.., true, ..)` is a no-op.
  fn close_conn(&mut self, id: ConnId, now: Instant) {
    let removed = self.conns.remove(&id); // drop aborts the task(s) (dial or both halves) + out_tx
    self
      .coord
      .handle_conn_data(id, &[], true, now, &mut self.wal, &mut self.sb); // reap in coordinator
    if let Some(Conn {
      redial: Some(redial),
      ..
    }) = removed
    {
      // Exponential per-peer redial backoff: this redial waits the lost conn's carried (jittered)
      // backoff, and the replacement conn carries the doubled value (capped) for the NEXT loss — so
      // an unreachable/RST-fast peer is probed at a decaying cadence (200ms → … → 5s) instead of a
      // fixed-rate hammer, and the jitter decorrelates dialers after a common-mode loss. Validation
      // resets the base (see `reconcile_auth_deadlines`); retries never stop, because a configured
      // consensus peer may always return.
      self.dial_peer(
        redial.peer,
        redial.addr,
        jittered(redial.backoff),
        (redial.backoff * 2).min(self.cfg.redial_backoff_cap()),
      );
    }
  }

  /// Issue a dial to `peer` at `addr` after `delay`; `backoff` is the (un-jittered) redial delay the
  /// new conn CARRIES for when it is itself lost — the per-peer exponential schedule's next step
  /// (callers pass the configured redial base on a first dial and the doubled-capped value on a
  /// redial). Registers the conn (so the coordinator can queue
  /// handshake bytes immediately) and inserts its [`Conn`], whose owned dial task MOVES the
  /// outbound receiver + byte counter into itself and ships them back in the [`DialReady`] on success.
  ///
  /// The dial task's handle is an [`AbortOnDrop`] held by the `Conn`: closing the conn before the
  /// dial completes drops the `Conn` → aborts the in-flight connect on every runtime (the moved
  /// `out_rx`/`queued_bytes` drop with it), and no `DialReady` is ever sent. This is the dial-task
  /// ownership that makes handle-drop terminate even with an unreachable configured peer.
  ///
  /// A pending dial carries NO `auth_deadline` (`None`): the connect itself is bounded by the in-task
  /// dial timeout, so a slow-but-healthy connect must not burn the handshake window. The auth
  /// deadline is stamped only at the bridge handoff (see [`Self::handle_dial_ready`]), so the full
  /// auth window covers the post-connect `Labeled`/TLS handshake rather than the connect itself.
  fn dial_peer(&mut self, peer: ReplicaId, addr: SocketAddr, delay: Duration, backoff: Duration) {
    let conn = (self.dialer)(Peer::Replica(peer));
    let id = self.coord.register_dialed(Peer::Replica(peer), conn);
    // Unbounded by item count, but bounded by the BYTE budget `pump_outputs` enforces on enqueue.
    let (out_tx, out_rx) = flume::unbounded();
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let dial_ready_tx = self.dial_ready_tx.clone();
    let qb_for_task = queued_bytes.clone();
    let dial_timeout = self.cfg.dial_timeout();
    let task = AbortOnDrop::new(R::spawn(async move {
      if !delay.is_zero() {
        R::sleep(delay).await;
      }
      // `connect_timeout` bounds the attempt (a black-holed address otherwise parks the task for
      // the kernel's SYN-retry horizon); a timeout surfaces as an `Err` dial result.
      let result = StreamOf::<R>::connect_timeout(&addr, dial_timeout).await;
      let _ = dial_ready_tx
        .send_async(DialReady {
          id,
          result,
          out_rx,
          queued_bytes: qb_for_task,
        })
        .await;
    }));
    self.conns.insert(
      id,
      Conn {
        tasks: ConnTask::Connecting(task),
        out_tx,
        queued_bytes,
        redial: Some(Redial {
          peer,
          addr,
          backoff,
        }),
        // No auth deadline while the dial is pending: the dial timeout bounds the connect, and the
        // deadline is stamped at the bridge handoff so the full window covers the handshake.
        auth_deadline: None,
      },
    );
  }

  /// Spawn the per-conn bridge halves for an ACCEPTED conn (create the channel + byte budget + insert
  /// the [`Conn`] here). `redial` is `None` — the dialing peer reconnects us, we don't redial it. Both
  /// bridge handles live in the `Conn` as [`AbortOnDrop`]s, so `close_conn` hard-aborts by dropping
  /// it (aborting both halves). The conn is stamped with an `auth_deadline` so an accepted socket
  /// that never validates is reaped (just closed, no redial).
  fn spawn_bridge_accepted(&mut self, now: Instant, id: ConnId, stream: StreamOf<R>) {
    tune_peer_socket(&stream);
    let (out_tx, out_rx) = flume::unbounded();
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let inbound_tx = self.bridge_inbound_tx.clone();
    // Split into OWNED halves so the read and write tasks proceed concurrently (a large write never
    // starves reads). Either half's EOF/error leads the driver to `close_conn`, which drops the
    // `Conn` and so aborts the other half.
    let (read_half, write_half) = stream.into_split();
    let tasks = ConnTask::Bridged {
      read: AbortOnDrop::new(R::spawn(bridge_read(read_half, id, inbound_tx.clone()))),
      write: AbortOnDrop::new(R::spawn(bridge_write(
        write_half,
        id,
        out_rx,
        queued_bytes.clone(),
        inbound_tx,
      ))),
    };
    self.conns.insert(
      id,
      Conn {
        tasks,
        out_tx,
        queued_bytes,
        redial: None,
        auth_deadline: Some(now + self.cfg.auth_deadline()),
      },
    );
  }

  /// Nearest of the consensus deadline, the earliest per-conn auth deadline, the next pending
  /// scan, the accept-error backoff, and a 50ms idle fallback (so a quiet node still re-pumps
  /// storage).
  ///
  /// The auth deadline is folded in as a REAL wake deadline — mirroring the QUIC bridge, which
  /// `min`s its `earliest_auth_deadline` into `poll_timeout` — so reaping a stalled handshake never
  /// depends on the idle fallback happening to wake the loop: a sleeping driver wakes AT the
  /// deadline and the iter-top [`Self::reconcile_auth_deadlines`] reaps on that pass. The pending
  /// scan deadline is folded the same way, so the gated `pending` walk also runs on schedule in a
  /// parked driver — but only while something IS pending: with the map empty the scan has nothing
  /// to reap or retransmit, so folding its (typically already-elapsed) deadline would only turn an
  /// idle driver's 50ms fallback into a busier wake cadence for no work. The accept backoff is
  /// folded so the parked accept arm re-enables ON schedule.
  fn next_deadline(&self) -> std::time::Instant {
    let fallback = std::time::Instant::now() + Duration::from_millis(50);
    let consensus = self.coord.poll_timeout().map(|t| self.clock.to_std(t));
    let auth = self
      .conns
      .values()
      .filter_map(|c| c.auth_deadline)
      .min()
      .map(|d| self.clock.to_std(d));
    let scan = (!self.pending.is_empty()).then(|| self.clock.to_std(self.next_pending_scan));
    // When a reconfiguration job is in flight, fold a 50ms-from-now wake so the job advances on
    // the natural driver cadence even if all other deadlines are quiescent.
    let reconfig = self
      .reconfigure
      .as_ref()
      .map(|_| std::time::Instant::now() + std::time::Duration::from_millis(50));
    [consensus, auth, scan, self.accept_backoff_until, reconfig]
      .into_iter()
      .flatten()
      .fold(fallback, std::time::Instant::min)
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
  ///
  /// Each conn's outbound channel is item-unbounded but BYTE-bounded: `queued_bytes` counts the WIRE
  /// bytes queued toward its socket (driver adds here, the bridge subtracts as it writes) — wire bytes
  /// because `poll_conn_transmit` returns post-record output (ciphertext for `Labeled<TlsRecords>`).
  /// The bound is the proto-exposed per-conn backlog [`StreamCoordinator::max_outbound_backlog`].
  ///
  /// The rule is ALWAYS-ADMIT-ONE: a single chunk is admitted whenever the queue is at/under the
  /// backlog cap, regardless of that chunk's own size. A chunk is a legitimately produced wire unit
  /// whose ciphertext size is deliberately NOT predicted — predicting it from the plaintext cap is
  /// unsound, because rustls record expansion depends on the TLS config (a small `max_fragment_size`
  /// makes per-record AEAD/framing overhead a large fraction of each tiny record, so a full plaintext
  /// chunk can encrypt to well over its plaintext), and an over-tight prediction would false-close a
  /// healthy conn. The rule admits at most ONE chunk past `backlog_cap`: a conn whose queue is ALREADY
  /// over the cap (a prior chunk pushed it over and it has not drained = a stalled/slow socket) is
  /// closed via [`Self::close_conn`] (redial + whole-message retransmit is the safe recovery) rather
  /// than growing memory without bound, so a single chunk is never false-closed while accumulation
  /// beyond one chunk past the cap closes a stalled/too-slow conn. The real per-conn out-queue PEAK is
  /// therefore `backlog_cap + max_single_wire_chunk`, NOT `backlog_cap`, where the max single wire
  /// chunk is bounded by the RECORD LAYER's send buffer (NOT by a tuned router cap): for `TlsRecords`
  /// it is a FIXED `2 * SEND_LIMIT` (`set_buffer_limit`, independent of `outbound_cap`); for
  /// passthrough it is the staging cap. Only at the DEFAULT cap (where `SEND_LIMIT` equals the staging
  /// cap, so `backlog_cap = 2 * SEND_LIMIT`) does the TLS peak reduce to ≤4x the cap; a custom cap
  /// below `SEND_LIMIT` does not shrink that fixed TLS chunk, so the record-layer term then dominates.
  /// A `try_send` failure (the bridge's `out_rx` is gone) closes the conn too. The to-close ids
  /// are collected during the borrow of `self.conns` and closed after, because `close_conn` takes
  /// `&mut self`; `close_conn` is idempotent so a duplicated id is harmless.
  async fn pump_outputs(&mut self, now: Instant) {
    // The per-conn wire-byte ACCUMULATION threshold the driver tolerates before declaring a stalled
    // socket, OWNED by the proto (2x the router's per-conn staging cap). It is NOT a per-chunk size and
    // NOT the out-queue peak — a single chunk is always admitted at/under it, so the peak is
    // `backlog_cap + one max wire chunk` (see the method doc). Read once here (a copied `usize`) before
    // the loop, so it does not conflict with the `&mut self`/`&self.conns` borrows below.
    let backlog_cap = self.coord.max_outbound_backlog();

    loop {
      self.coord.handle_storage(now, &mut self.wal, &mut self.sb);
      let mut produced = false;
      let mut to_close: Vec<(ConnId, CloseCause)> = Vec::new();
      while let Some((id, bytes)) = self.coord.poll_conn_transmit() {
        if let Some(conn) = self.conns.get(&id) {
          let len = bytes.len();
          let queued = conn.queued_bytes.load(Ordering::Relaxed);
          // Always-admit-one (see the method doc): refuse a chunk ONLY when the queue is ALREADY
          // over the backlog cap (a stalled/slow socket), then close + redial; consensus retransmits
          // the whole message. The condition does NOT reference `len`, so a chunk is never refused
          // for its own size.
          if queued > backlog_cap {
            to_close.push((id, CloseCause::OutboundOverflow));
          } else {
            conn.queued_bytes.fetch_add(len, Ordering::Relaxed);
            if conn.out_tx.try_send(BridgeOut(bytes)).is_err() {
              // The bridge's receiver is gone (its write task exited on a dead socket); undo the
              // add we just made and close the conn.
              conn.queued_bytes.fetch_sub(len, Ordering::Relaxed);
              to_close.push((id, CloseCause::PeerClosed));
            }
          }
        }
        produced = true;
      }
      while let Some(event) = self.coord.poll_event() {
        deliver_event(&mut self.pending, &self.events, event);
        produced = true;
      }
      for (id, cause) in to_close {
        // A duplicated id is closed idempotently but counted once (the second pass finds it gone).
        if self.conns.contains_key(&id) {
          self.close_counts[cause.index()] += 1;
        }
        self.close_conn(id, now);
      }
      if !produced {
        break;
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use std::{
    sync::{
      Arc,
      atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
  };

  use agnostic::{
    Runtime, RuntimeLite,
    net::{Net, TcpListener, TcpStream},
  };
  use bytes::Bytes;

  use super::ReactorStreamDriver;
  use viewstamp_driver::{DriverError, REQUEST_TIMEOUT};

  use crate::{
    bridge::{BridgeOut, Conn as BridgeConn, ConnTask},
    task::AbortOnDrop,
  };
  use viewstamp_proto::{
    ClientId, Config, Conn, Endpoint, Instant, LabelOptions, Labeled, MemberId, Membership,
    OpNumber, Passthrough, Peer, ReplicaId, SingleChange, StreamCoordinator, View,
  };
  use viewstamp_simulation::sm::LogSm;

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

  /// A type-erased in-flight `submit` future, lifetime-bound to the borrowed `Handle` it ran from.
  type SubmitFut<'a> = dyn std::future::Future<Output = Result<crate::Reply, DriverError>> + 'a;
  use viewstamp_simulation::{InMemorySuperblock, InMemoryWal};

  type TestRt = agnostic::tokio::TokioRuntime;
  type TestListener = <<TestRt as Runtime>::Net as Net>::TcpListener;
  type TestStream = <<TestRt as Runtime>::Net as Net>::TcpStream;
  type TestStreamDriver =
    ReactorStreamDriver<TestRt, LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock>;

  #[test]
  fn stream_driver_type_resolves() {
    fn _assert_handle_clone(h: &crate::Handle) {
      let _ = h.clone();
    }
  }

  /// Build a driver bound on an ephemeral loopback port with no configured peers, so no dials fire
  /// until the test drives `dial_peer` itself. `T = Labeled<Passthrough>` (the loopback transport).
  async fn test_driver() -> TestStreamDriver {
    test_driver_with_storage(InMemoryWal::new(), InMemorySuperblock::new()).await
  }

  /// Like [`test_driver`] but over caller-supplied storage, so the recover-or-new constructor-choice
  /// tests can hand it a dirty store.
  async fn test_driver_with_storage(wal: InMemoryWal, sb: InMemorySuperblock) -> TestStreamDriver {
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Arc::new(|peer| {
      let opts = LabelOptions::new(CLUSTER, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Arc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    let (driver, _handle) = ReactorStreamDriver::new(
      config,
      genesis(3),
      LogSm::default(),
      wal,
      sb,
      ClientId::new(1),
      0,
      "127.0.0.1:0".parse().unwrap(),
      Vec::new(), // no configured peers: nothing dials until the test calls `dial_peer`
      dialer,
      acceptor,
      ready_rx,
    )
    .await
    .expect("driver builds");
    driver
  }

  /// Like [`test_driver`] but through the `with_config` constructor, so the config-effect tests
  /// drive a non-default [`crate::DriverConfig`] through the production path.
  async fn test_driver_with_config(cfg: crate::DriverConfig) -> TestStreamDriver {
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Arc::new(|peer| {
      let opts = LabelOptions::new(CLUSTER, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Arc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    let (driver, _handle) = ReactorStreamDriver::with_config(
      config,
      genesis(3),
      LogSm::default(),
      InMemoryWal::new(),
      InMemorySuperblock::new(),
      ClientId::new(1),
      0,
      "127.0.0.1:0".parse().unwrap(),
      Vec::new(),
      dialer,
      acceptor,
      ready_rx,
      cfg,
    )
    .await
    .expect("driver builds");
    driver
  }

  /// The mesh is mutual-dial: `run()` dials every configured peer unconditionally (consensus
  /// liveness) AND each peer dials back, with the inbound socket admission-controlled until its
  /// handshake validates — so a cap below twice the peer count lets startup dials squeeze the
  /// accept side and wedge mesh formation. The constructor must refuse the misconfiguration.
  #[tokio::test]
  async fn a_peer_mesh_larger_than_the_conn_cap_is_refused_at_construction() {
    const CLUSTER: u128 = 0x7777;
    let mk_dialer = || -> super::DialerFactory<Labeled<Passthrough>> {
      Arc::new(|peer| {
        let opts = LabelOptions::new(CLUSTER, peer);
        Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
      })
    };
    let mk_acceptor = || -> super::AcceptorFactory<Labeled<Passthrough>> {
      Arc::new(|| {
        let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
        Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
      })
    };
    let mk_peers = || -> Vec<(ReplicaId, std::net::SocketAddr)> {
      vec![
        (ReplicaId::new(1), "127.0.0.1:1".parse().unwrap()),
        (ReplicaId::new(2), "127.0.0.1:2".parse().unwrap()),
      ]
    };
    let build = |cap: usize| async move {
      let (_ready_tx, ready_rx) = flume::unbounded();
      TestStreamDriver::with_config(
        Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap(),
        genesis(3),
        LogSm::default(),
        InMemoryWal::new(),
        InMemorySuperblock::new(),
        ClientId::new(1),
        0,
        "127.0.0.1:0".parse().unwrap(),
        mk_peers(),
        mk_dialer(),
        mk_acceptor(),
        ready_rx,
        crate::DriverConfig::new().with_max_conns(cap),
      )
      .await
    };

    // Below the floor: 2 peers need 2 dialed + room for 2 accepted mesh sockets; a cap of 3 would
    // let startup dials squeeze the accept side and wedge mesh formation.
    let Err(err) = build(3).await else {
      panic!("a 2-peer mutual mesh must not fit a cap of 3");
    };
    assert!(
      matches!(
        err,
        crate::DriverError::CapBelowPeerMesh {
          max_conns: 3,
          peers: 2
        }
      ),
      "the refusal names the cap and the mesh size: {err:?}"
    );
    // At the floor: twice the peer count leaves room for every dialed AND accepted mesh conn.
    assert!(
      build(4).await.is_ok(),
      "a cap of twice the peer count admits the whole mutual mesh"
    );
  }

  /// Like [`test_driver`] but also returns the `Handle`, so a budget test can drive the REAL
  /// `Handle::submit` (which reserves the shared budget + `try_send`s the command) against the
  /// driver's REAL `handle_command`/`deliver_event`/`retransmit_stale`. No peers are configured, so
  /// nothing ever commits on its own — exactly the partitioned/slow case the submit budget must bound.
  async fn test_driver_with_handle() -> (TestStreamDriver, crate::Handle) {
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Arc::new(|peer| {
      let opts = LabelOptions::new(CLUSTER, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Arc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    ReactorStreamDriver::new(
      config,
      genesis(3),
      LogSm::default(),
      InMemoryWal::new(),
      InMemorySuperblock::new(),
      ClientId::new(1),
      0,
      "127.0.0.1:0".parse().unwrap(),
      Vec::new(),
      dialer,
      acceptor,
      ready_rx,
    )
    .await
    .expect("driver builds")
  }

  /// Build a `Labeled<Passthrough>` driver whose coordinator uses a TINY per-conn outbound backlog
  /// cap, so a small wire chunk already exceeds it (no large allocation needed). A dialed
  /// `Labeled<Passthrough>` conn queues its identity hello into the inner outbound at construction —
  /// that queued hello is a real wire chunk produced WITHOUT the router's send-side cap check (it is
  /// written straight into the inner layer, not via `route`), so `poll_conn_transmit` returns it even
  /// when it is larger than the cap. That is exactly the over-cap-chunk-from-a-just-produced-unit the
  /// driver's always-admit-one rule must tolerate. The coordinator is rebuilt with
  /// [`StreamCoordinator::with_outbound_cap`] (the public `new` always uses the default cap).
  async fn test_driver_small_cap(cap: usize) -> TestStreamDriver {
    let mut driver = test_driver().await;
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let endpoint =
      Endpoint::<_, SingleChange>::with_reconfig(config, genesis(3), 1, LogSm::default());
    driver.coord = StreamCoordinator::with_outbound_cap(endpoint, cap);
    driver
  }

  /// Register a dialed `Labeled<Passthrough>` conn (its identity hello queued into the inner outbound)
  /// in the driver's coordinator AND insert the matching driver-owned [`BridgeConn`] under the same
  /// `ConnId`, returning `(id, out_rx, queued_bytes)`. `poll_conn_transmit` will return that conn's
  /// queued hello as a single wire chunk. The conn's tasks are trivial completed futures (the test
  /// asserts the queued bytes / channel directly, never driving a real bridge), so dropping them on a
  /// close aborts nothing live. The held `out_rx` observes what `pump_outputs` admitted.
  fn register_handshaking_conn(
    driver: &mut TestStreamDriver,
    peer: ReplicaId,
  ) -> (
    viewstamp_proto::ConnId,
    flume::Receiver<BridgeOut>,
    Arc<AtomicUsize>,
  ) {
    const CLUSTER: u128 = 0x7777;
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(peer));
    let conn = Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts));
    let id = driver.coord.register_dialed(Peer::Replica(peer), conn);
    let (out_tx, out_rx) = flume::unbounded();
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let tasks = ConnTask::Bridged {
      read: AbortOnDrop::new(TestRt::spawn(async {})),
      write: AbortOnDrop::new(TestRt::spawn(async {})),
    };
    driver.conns.insert(
      id,
      BridgeConn {
        tasks,
        out_tx,
        queued_bytes: queued_bytes.clone(),
        redial: None,
        auth_deadline: None,
      },
    );
    (id, out_rx, queued_bytes)
  }

  /// `dial_peer` is the single source of a dialed [`BridgeConn`]: it mints a `ConnId`, inserts ONE
  /// owned unit into `conns`, and records the redial target in `Conn.redial` (so there is no separate
  /// `dialed` map to drift). A `DialReady` is STALE exactly when its id is no longer in `conns` —
  /// what `handle_dial_ready` checks via `conns.get_mut` before replacing the dial task with the
  /// bridge — so a closed-and-replaced id is dropped rather than spawned or redialed.
  #[tokio::test]
  async fn dialed_conn_is_one_unit_with_a_redial_target() {
    let mut driver = test_driver().await;
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

    driver.dial_peer(
      ReplicaId::new(1),
      addr,
      Duration::ZERO,
      viewstamp_driver::REDIAL_BACKOFF_BASE,
    );
    let id = *driver
      .conns
      .keys()
      .next()
      .expect("dial_peer registered a conn");

    // The dialed conn carries its redial target inline (no parallel `dialed` map).
    assert_eq!(
      driver
        .conns
        .get(&id)
        .and_then(|c| c.redial)
        .map(|r| (r.peer, r.addr, r.backoff)),
      Some((
        ReplicaId::new(1),
        addr,
        viewstamp_driver::REDIAL_BACKOFF_BASE
      )),
      "a dialed Conn records (peer, addr) for redial-on-loss, carrying the base backoff"
    );
    assert!(
      driver.conns.contains_key(&id),
      "a freshly-dialed, not-yet-completed conn id is live"
    );

    // Removing the unit (the close-and-replace `close_conn` performs) makes the id stale: a late
    // `DialReady` for it would find `conns` empty and be dropped.
    driver.conns.remove(&id);
    assert!(
      !driver.conns.contains_key(&id),
      "a closed-and-replaced id is stale once its Conn is removed"
    );
  }

  /// REDIAL SPACING: consecutive losses of the same peer's conn space out EXPONENTIALLY. Each redial
  /// is issued at `jittered(backoff)` of the conn just lost, and the replacement conn carries the
  /// doubled (capped) value — so a failure chain schedules 200ms, 400ms, …, 5s, 5s, … and every
  /// delay is strictly above the previous one (`jittered(b) <= 1.25b < 2b`; the jitter bound is
  /// pinned in `viewstamp-driver`'s clock module). The test drives the REAL loss path (`close_conn`) repeatedly and asserts
  /// the carried backoff doubles to [`viewstamp_driver::REDIAL_BACKOFF_CAP`] then holds — deterministic: no
  /// clock is consulted, the carried backoff IS the next schedule step.
  ///
  /// NEUTER CHECK: reverting `close_conn` to a fixed-delay redial leaves every carried backoff at
  /// the base, failing the first doubling assert; dropping the `.min(cap)` overshoots the final one.
  #[tokio::test]
  async fn consecutive_redials_back_off_exponentially_to_the_cap() {
    let mut driver = test_driver().await;
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    driver.dial_peer(
      ReplicaId::new(1),
      addr,
      Duration::ZERO,
      viewstamp_driver::REDIAL_BACKOFF_BASE,
    );

    let mut expected = viewstamp_driver::REDIAL_BACKOFF_BASE;
    // 200ms → 400ms → 800ms → 1.6s → 3.2s → 5s (capped) → 5s: the cap is reached and then held.
    for _ in 0..7 {
      let id = *driver
        .conns
        .keys()
        .next()
        .expect("exactly one live dialed conn");
      let redial = driver.conns[&id]
        .redial
        .expect("a dialed conn carries its redial target");
      assert_eq!(
        (redial.peer, redial.addr),
        (ReplicaId::new(1), addr),
        "the redial target survives every replacement"
      );
      assert_eq!(
        redial.backoff, expected,
        "the carried backoff is the next redial's (un-jittered) delay"
      );
      // Lose the conn: `close_conn` redials at jittered(backoff) and the replacement carries the
      // doubled (capped) value.
      driver.close_conn(id, Instant::ZERO);
      expected = (expected * 2).min(viewstamp_driver::REDIAL_BACKOFF_CAP);
    }
    assert_eq!(
      expected,
      viewstamp_driver::REDIAL_BACKOFF_CAP,
      "the chain reached the cap"
    );
  }

  /// Validation RESETS the redial backoff to the base: a real `Labeled` handshake is driven into the
  /// driver's dialed conn (a stand-alone coordinator plays the remote replica), the conn's carried
  /// backoff is inflated to the cap (as a long dead period would leave it), and the
  /// `reconcile_auth_deadlines` pass that observes validation must clear the auth deadline AND reset
  /// the backoff — so the NEXT loss redials at the base cadence, not at the dead period's.
  #[tokio::test]
  async fn validation_resets_the_redial_backoff_to_base() {
    const CLUSTER: u128 = 0x7777;
    // The dialer must announce SELF (replica 0) for the peer to validate it — the loopback wiring;
    // `test_driver`'s factory announces the dialed target instead, fine only where nothing validates.
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Arc::new(|_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Arc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    let (mut driver, _handle) = ReactorStreamDriver::<TestRt, _, _, _, _>::new(
      Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap(),
      genesis(3),
      LogSm::default(),
      InMemoryWal::new(),
      InMemorySuperblock::new(),
      ClientId::new(1),
      0,
      "127.0.0.1:0".parse().unwrap(),
      Vec::new(),
      dialer,
      acceptor,
      ready_rx,
    )
    .await
    .expect("driver builds");

    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    driver.dial_peer(
      ReplicaId::new(1),
      addr,
      Duration::ZERO,
      viewstamp_driver::REDIAL_BACKOFF_BASE,
    );
    let id = *driver.conns.keys().next().expect("one dialed conn");

    // The remote replica (id 1): a stand-alone coordinator that accepts our conn and answers the
    // `Labeled` handshake.
    let peer_config = Config::try_new(CLUSTER, MemberId::new(1_u128)).unwrap();
    let mut peer = StreamCoordinator::new(Endpoint::<_, SingleChange>::with_reconfig(
      peer_config,
      genesis(3),
      2,
      LogSm::default(),
    ));
    let peer_conn = Conn::from_parts(Labeled::acceptor(
      Passthrough::new(),
      &LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(1))),
    ));
    let pid = peer.register_accepted(Peer::Replica(ReplicaId::new(0)), peer_conn);
    let (mut pwal, mut psb) = (InMemoryWal::new(), InMemorySuperblock::new());

    // Shuttle the handshake bytes both ways until the driver's conn validates.
    let now = Instant::ZERO;
    for _ in 0..8 {
      if driver.coord.is_conn_validated(id) {
        break;
      }
      while let Some((cid, bytes)) = driver.coord.poll_conn_transmit() {
        if cid == id {
          peer.handle_conn_data(pid, &bytes, false, now, &mut pwal, &mut psb);
        }
      }
      while let Some((cid, bytes)) = peer.poll_conn_transmit() {
        if cid == pid {
          driver
            .coord
            .handle_conn_data(id, &bytes, false, now, &mut driver.wal, &mut driver.sb);
        }
      }
    }
    assert!(
      driver.coord.is_conn_validated(id),
      "the Labeled handshake validates the dialed conn"
    );

    // As a long dead period would leave the conn: carried backoff at the cap, auth window armed
    // (the bridge handoff would have stamped it).
    {
      let conn = driver.conns.get_mut(&id).expect("the conn is live");
      conn.redial.as_mut().expect("a dialed conn").backoff = viewstamp_driver::REDIAL_BACKOFF_CAP;
      conn.auth_deadline = Some(now + viewstamp_driver::AUTH_DEADLINE);
    }

    driver.reconcile_auth_deadlines(now);

    let conn = driver
      .conns
      .get(&id)
      .expect("a validated conn is not reaped");
    assert_eq!(
      conn.auth_deadline, None,
      "validation clears the auth deadline"
    );
    assert_eq!(
      conn.redial.expect("a dialed conn").backoff,
      viewstamp_driver::REDIAL_BACKOFF_BASE,
      "validation resets the redial backoff, so the next loss starts the schedule over at the base"
    );
  }

  /// AMNESIA GUARD (stream driver): a store carrying ANY durable state NEVER boots a fresh view-0
  /// endpoint — the constructor inspects the store and reconstructs via `Endpoint::recover`. A
  /// durable root at view 5 must resume view 5 (a fresh boot would be view 0); a durable WAL op
  /// must restore the head and enter `Recovering` (the tail re-verifies through the normal storage
  /// pump). Reverting the constructor to an unconditional `Endpoint::new` fails both halves.
  #[tokio::test]
  async fn a_dirty_store_never_boots_a_fresh_view_zero_endpoint_stream() {
    // Durable ROOT, empty WAL: recovery has nothing to read, so it settles inline (replica 0 is not
    // view 5's primary, hence a Normal backup) — the guard property is the RESUMED durable view.
    let mut sb = InMemorySuperblock::new();
    viewstamp_proto::Superblock::submit_write(
      &mut sb,
      viewstamp_proto::OpId::new(1),
      viewstamp_proto::VsrState::try_new(
        View::with(5),
        View::with(5),
        OpNumber::new(),
        OpNumber::new(),
        0,
        Vec::new(),
      )
      .expect("a valid durable root"),
    );
    // The storage contract: no in-flight completions cross an endpoint incarnation.
    while viewstamp_proto::Superblock::poll(&mut sb).is_some() {}
    let driver = test_driver_with_storage(InMemoryWal::new(), sb).await;
    assert_eq!(
      driver.coord.endpoint().view().get(),
      5,
      "the durable view is resumed, never reset to a fresh view 0"
    );

    // Durable WAL op, genesis root: the endpoint enters Recovering with its durable head restored
    // (the read completions resolve through the run loop's ordinary handle_storage pump).
    let mut wal = InMemoryWal::new();
    let header = viewstamp_proto::Header::new(
      OpNumber::with(1),
      View::new(),
      ClientId::new(7),
      viewstamp_proto::RequestNumber::with(1),
      b"op",
    );
    viewstamp_proto::Wal::submit_append(
      &mut wal,
      viewstamp_proto::OpId::new(1),
      OpNumber::with(1),
      header,
      Bytes::from_static(b"op"),
    );
    while viewstamp_proto::Wal::poll(&mut wal).is_some() {}
    let driver = test_driver_with_storage(wal, InMemorySuperblock::new()).await;
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

  /// First-boot path (stream driver): a genesis store — fresh-cluster root AND empty WAL — still
  /// boots a fresh endpoint (`Normal`, view 0, empty log); `Endpoint::new` stays reachable, guarded
  /// by the state inspection itself.
  #[tokio::test]
  async fn a_genesis_store_boots_a_fresh_normal_endpoint_stream() {
    let driver = test_driver().await;
    assert!(driver.coord.endpoint().status().is_normal());
    assert_eq!(driver.coord.endpoint().view().get(), 0);
    assert_eq!(driver.coord.endpoint().op().get(), 0);
  }

  /// Handle-drop termination must hold even with an in-flight dial task: a configured but
  /// UNREACHABLE peer leaves a dialing `Conn` whose dial task is parked in the connect when the
  /// last `Handle` drops. Because the `Conn` OWNS that task's [`AbortOnDrop`] (it is not
  /// detached), the final `self.conns.clear()` aborts it, so `run()` returns promptly instead of
  /// waiting out the dial timeout. A regression to a detached dial task fails the 5s bound.
  #[tokio::test]
  async fn run_exits_with_an_in_flight_dial_to_an_unreachable_peer() {
    let config = Config::try_new(0x7777, MemberId::new(0_u128)).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Arc::new(|peer| {
      let opts = LabelOptions::new(0x7777, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Arc::new(|| {
      let opts = LabelOptions::new(0x7777, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    // 203.0.113.0/24 (TEST-NET-3) is reserved + unrouteable, so the connect never completes within
    // the test window — the dial task is genuinely in flight when the Handle drops.
    let unreachable: std::net::SocketAddr = "203.0.113.1:9".parse().unwrap();
    let (driver, handle) = ReactorStreamDriver::<TestRt, _, _, _, _>::new(
      config,
      genesis(3),
      LogSm::default(),
      InMemoryWal::new(),
      InMemorySuperblock::new(),
      ClientId::new(1),
      0,
      "127.0.0.1:0".parse().unwrap(),
      vec![(ReplicaId::new(1), unreachable)],
      dialer,
      acceptor,
      ready_rx,
    )
    .await
    .expect("driver builds");
    let task = tokio::spawn(driver.run());

    drop(handle); // last Handle gone -> command channel disconnects

    let _ = tokio::time::timeout(Duration::from_secs(5), task)
      .await
      .expect("run() returns within 5s even with an in-flight connect to an unreachable peer");
  }

  /// ALWAYS-ADMIT-ONE: a single wire chunk is admitted from an EMPTY queue regardless of its own size
  /// and does NOT close the conn — admission never references the chunk's length, only whether the
  /// queue was ALREADY over the ceiling. The staging cap is 8 bytes (via `with_outbound_cap`, so the
  /// ceiling is `8 * 2 = 16`); the dialed conn's queued identity hello (20 bytes) already exceeds the
  /// 8-byte staging cap, so no large allocation is needed to prove size is not what gates admission.
  ///
  /// NEUTER CHECK: changing `pump_outputs` to `if queued + len > backlog_cap` makes this test FAIL —
  /// the hello chunk (`0 + 20 > 16`) would close the conn from the empty queue, so `contains_key` is
  /// false and the `out_rx` is empty.
  #[tokio::test]
  async fn a_single_chunk_larger_than_the_backlog_cap_is_admitted_from_an_empty_queue() {
    let mut driver = test_driver_small_cap(8).await;
    assert_eq!(driver.coord.max_outbound_backlog(), 16); // 2x the 8-byte staging cap
    // A dialed conn whose queued identity hello is a single wire chunk larger than the 8-byte staging
    // cap (it exceeds 1x, proving chunk size does not gate admission from an empty queue).
    let (id, out_rx, queued_bytes) = register_handshaking_conn(&mut driver, ReplicaId::new(1));

    driver.pump_outputs(Instant::ZERO).await;

    // The conn is ALIVE: a lone chunk from an empty queue is admitted regardless of its size.
    assert!(
      driver.conns.contains_key(&id),
      "a single over-cap chunk from an empty queue must NOT close the conn (always-admit-one)"
    );
    // The chunk was delivered into the channel, and it genuinely exceeds the 8-byte backlog cap.
    let BridgeOut(bytes) = out_rx
      .try_recv()
      .expect("the admitted chunk is queued to the conn's bridge channel");
    assert!(
      bytes.len() > 8,
      "the admitted hello chunk ({} bytes) is larger than the 8-byte backlog cap, proving chunk size \
       is not what gates admission",
      bytes.len()
    );
    assert_eq!(
      queued_bytes.load(Ordering::Relaxed),
      bytes.len(),
      "the admitted chunk's bytes are accounted in queued_bytes (the bridge would subtract on write)"
    );
  }

  /// STUCK-SOCKET ACCUMULATION (the safety bound): a conn whose socket has not drained and whose
  /// queued backlog is ALREADY over `max_outbound_backlog` IS closed when the next chunk is produced.
  /// A stalled socket is modeled by pre-loading `queued_bytes` above the ceiling — here the staging
  /// cap is 8, so the ceiling is `8 * 2 = 16` and 100 is well past it (a prior chunk the bridge has
  /// not written), which is exactly the accumulation the bound guards. The conn's queued hello is the
  /// next chunk `poll_conn_transmit` produces; because the queue is already over the ceiling,
  /// `pump_outputs` closes + reaps the conn instead of growing memory without bound.
  #[tokio::test]
  async fn a_stuck_socket_already_over_the_backlog_cap_is_closed() {
    let mut driver = test_driver_small_cap(8).await;
    assert_eq!(driver.coord.max_outbound_backlog(), 16); // 2x the 8-byte staging cap
    let (id, _out_rx, queued_bytes) = register_handshaking_conn(&mut driver, ReplicaId::new(1));

    // The socket is stalled: a prior chunk is still queued and has not been written, leaving the
    // backlog at 100 bytes — already past the 16-byte ceiling.
    queued_bytes.store(100, Ordering::Relaxed);

    driver.pump_outputs(Instant::ZERO).await;

    assert!(
      !driver.conns.contains_key(&id),
      "a stuck socket whose backlog is already over the ceiling is closed on the next chunk \
       (accumulation bound)"
    );
  }

  /// A small chunk produced WHILE a large chunk is still draining must NOT close a healthy conn. The
  /// large chunk's in-flight bytes are modeled by pre-loading `queued_bytes` to 12: with the 8-byte
  /// staging cap the ceiling is `8 * 2 = 16`, so 12 is OVER 1x (a 1x ceiling would false-close here)
  /// yet AT/UNDER the 2x ceiling. The conn's queued identity hello is the second, small chunk
  /// `poll_conn_transmit` produces; `pump_outputs` must ADMIT it (queue 12 <= 16) and leave the conn
  /// open, with the chunk delivered to the bridge channel and its bytes added to the backlog. This is
  /// the headroom that stops a heartbeat/retransmit/request, produced during a large chunk's drain,
  /// from reaping a healthy connection.
  ///
  /// NEUTER CHECK: reverting `max_outbound_backlog` to `outbound_cap` (1x = 8) makes this FAIL — the
  /// pre-loaded 12 is then over the 8-byte ceiling, so `pump_outputs` closes the conn (`contains_key`
  /// is false and the `out_rx` is empty). The 2x headroom is exactly what keeps the conn alive.
  #[tokio::test]
  async fn a_small_chunk_while_a_large_chunk_drains_does_not_close_the_conn() {
    let mut driver = test_driver_small_cap(8).await;
    assert_eq!(driver.coord.max_outbound_backlog(), 16); // 2x the 8-byte staging cap
    let (id, out_rx, queued_bytes) = register_handshaking_conn(&mut driver, ReplicaId::new(1));

    // A large chunk is mid-drain: 12 of its bytes are still in flight (the bridge has written part of
    // it but not all). 12 > 8 (over 1x — a 1x ceiling would false-close) but 12 <= 16 (at/under 2x).
    queued_bytes.store(12, Ordering::Relaxed);

    driver.pump_outputs(Instant::ZERO).await;

    // The conn is ALIVE: a backlog at/under the 2x ceiling admits the next chunk during the drain.
    assert!(
      driver.conns.contains_key(&id),
      "a small chunk produced while a large chunk drains (backlog under the 2x ceiling) must NOT \
       close a healthy conn"
    );
    // The second chunk was delivered, and its bytes were added on top of the in-flight 12.
    let BridgeOut(bytes) = out_rx
      .try_recv()
      .expect("the second chunk is queued to the conn's bridge channel during the drain");
    assert_eq!(
      queued_bytes.load(Ordering::Relaxed),
      12 + bytes.len(),
      "the admitted chunk's bytes accumulate on top of the still-in-flight large chunk's 12 bytes"
    );
  }

  /// PEAK BOUND: the always-admit-one rule lets the out-queue reach EXACTLY `backlog_cap + one wire
  /// chunk` and no more. Two conns are pumped together under an 8-byte staging cap (ceiling `8 * 2 =
  /// 16`), each carrying its 20-byte identity hello as the single chunk `poll_conn_transmit` produces:
  ///
  ///  - Conn AT the cap (`queued_bytes = 16`): admitted, because the rule refuses only a queue STRICTLY
  ///    over the cap. Its queue is allowed to climb to `16 + 20 = 36` (`backlog_cap + one chunk`) and
  ///    the conn stays open — it is NOT closed at exactly `backlog_cap`.
  ///  - Conn one byte OVER the cap (`queued_bytes = 17`): refused and closed, because `17 > 16` — the
  ///    NEXT chunk past the cap is exactly what the accumulation bound rejects.
  ///
  /// Together these pin the peak at `backlog_cap + one chunk`: the boundary is `backlog_cap` (admit) vs
  /// `backlog_cap + 1` (close), so the queue can never grow beyond one chunk past the cap. The
  /// `queued_bytes` pre-load models a stalled/slow writer that has not drained the in-flight bytes, so
  /// no large allocation is needed.
  ///
  /// NEUTER CHECK: widening the rule to admit when `queued >= backlog_cap` (instead of `>`) keeps the
  /// over-cap conn alive and the peak claim no longer holds; tightening it to close at `queued ==
  /// backlog_cap` closes the at-cap conn and breaks the `backlog_cap + one chunk` reach. Both halves
  /// fail, so the test pins the exact `>` boundary.
  #[tokio::test]
  async fn the_out_queue_peak_is_exactly_backlog_cap_plus_one_chunk() {
    let mut driver = test_driver_small_cap(8).await;
    let backlog_cap = driver.coord.max_outbound_backlog();
    assert_eq!(backlog_cap, 16); // 2x the 8-byte staging cap

    // Conn AT the cap: its in-flight backlog is exactly `backlog_cap`, so the next chunk is still
    // admitted (the rule closes only a queue STRICTLY over the cap).
    let (at_cap, at_cap_rx, at_cap_bytes) =
      register_handshaking_conn(&mut driver, ReplicaId::new(1));
    at_cap_bytes.store(backlog_cap, Ordering::Relaxed);

    // Conn one byte OVER the cap: the next chunk is refused and the conn closed.
    let (over_cap, over_cap_rx, over_cap_bytes) =
      register_handshaking_conn(&mut driver, ReplicaId::new(2));
    over_cap_bytes.store(backlog_cap + 1, Ordering::Relaxed);

    driver.pump_outputs(Instant::ZERO).await;

    // The at-cap conn is ALIVE and its queue was allowed to reach `backlog_cap + one chunk` — proof the
    // peak is NOT clamped at `backlog_cap`.
    assert!(
      driver.conns.contains_key(&at_cap),
      "a chunk admitted with the queue AT backlog_cap must NOT close the conn (admit-one past the cap)"
    );
    let BridgeOut(at_cap_chunk) = at_cap_rx
      .try_recv()
      .expect("the at-cap conn's chunk is queued to its bridge channel");
    assert_eq!(
      at_cap_bytes.load(Ordering::Relaxed),
      backlog_cap + at_cap_chunk.len(),
      "the at-cap queue reaches exactly backlog_cap + one chunk (the real peak)"
    );
    assert!(
      !at_cap_chunk.is_empty(),
      "the admitted chunk is a real non-empty wire unit"
    );

    // The over-cap conn is CLOSED: the next chunk while the queue is already strictly over the cap is
    // refused, so the peak can never exceed backlog_cap + one chunk.
    assert!(
      !driver.conns.contains_key(&over_cap),
      "a chunk produced while the queue is already over backlog_cap closes the conn (accumulation bound)"
    );
    assert!(
      over_cap_rx.try_recv().is_err(),
      "nothing is queued to a conn refused for being already over the cap"
    );
  }

  /// The earliest per-conn auth deadline is folded into `next_deadline` as a real wake deadline
  /// (mirroring the QUIC bridge, which folds `earliest_auth_deadline` into `poll_timeout`): a driver
  /// sleeping on `next_deadline` wakes AT the deadline to reap a stalled handshake, rather than
  /// relying on the 50ms idle fallback to happen to wake it first. A fresh, never-driven endpoint
  /// arms no consensus timer, so the baseline (no auth deadlines) is exactly the fallback; arming a
  /// near auth deadline must pull the returned deadline to (at or before) it.
  #[tokio::test]
  async fn next_deadline_folds_the_earliest_auth_deadline() {
    let mut driver = test_driver().await;

    // Baseline: no conns and no consensus timer, so the ~50ms idle fallback governs.
    let baseline = driver.next_deadline();
    assert!(
      baseline >= std::time::Instant::now() + Duration::from_millis(40),
      "without an auth deadline the idle fallback (~50ms) governs"
    );

    // A conn whose auth deadline is ~5ms out: next_deadline must move to it, well under the
    // fallback. Reverting the fold (consensus-and-fallback only) returns ~+50ms and fails here.
    let (id, _out_rx, _queued_bytes) = register_handshaking_conn(&mut driver, ReplicaId::new(1));
    let due = driver.clock.now() + Duration::from_millis(5);
    driver
      .conns
      .get_mut(&id)
      .expect("registered conn")
      .auth_deadline = Some(due);
    assert!(
      driver.next_deadline() <= driver.clock.to_std(due),
      "the earliest auth deadline is folded into next_deadline as a real wake deadline"
    );
  }

  /// CONFIG EFFECT (stream driver): a non-default `DriverConfig::auth_deadline` changes WHEN the
  /// unvalidated-conn reap fires. An accepted socket registered through the production
  /// `spawn_bridge_accepted` is stamped `now + auth_deadline` from the CONFIG (here 500ms, a tenth
  /// of the 5s default); `reconcile_auth_deadlines` keeps the conn one tick before that deadline and
  /// reaps it AT it — a timeline on which the default-configured driver (deadline 5s) would still be
  /// holding the conn. Deterministic: the clock is the `Instant` values passed in, nothing sleeps.
  #[tokio::test]
  async fn a_custom_auth_deadline_changes_the_reap_timing() {
    let custom = Duration::from_millis(500);
    assert!(
      custom < viewstamp_driver::AUTH_DEADLINE,
      "the override must be far below the default for the timing contrast to mean anything"
    );
    let mut driver =
      test_driver_with_config(crate::DriverConfig::new().with_auth_deadline(custom)).await;

    // A real accepted loopback socket through the production registration + bridge spawn.
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TestListener::bind(bind).await.expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let (dialed, accepted) =
      futures_util::future::join(TestStream::connect(addr), listener.accept()).await;
    let _dialed = dialed.expect("connect");
    let (accepted, _peer) = accepted.expect("accept");

    let conn = (driver.acceptor)();
    let id = driver
      .coord
      .register_accepted(Peer::Replica(ReplicaId::new(0)), conn);
    let now0 = Instant::ZERO;
    driver.spawn_bridge_accepted(now0, id, accepted);
    assert_eq!(
      driver.conns.get(&id).and_then(|c| c.auth_deadline),
      Some(now0 + custom),
      "the production stamp uses the CONFIGURED auth deadline, not the default"
    );

    // One tick before the custom deadline: the conn survives the reconcile.
    driver.reconcile_auth_deadlines(now0 + (custom - Duration::from_millis(1)));
    assert!(
      driver.conns.contains_key(&id),
      "an unvalidated conn strictly before its configured deadline is kept"
    );
    assert_eq!(
      driver.conn_close_count(viewstamp_proto::CloseCause::AuthDeadline),
      0,
      "no auth-deadline close is counted while the conn is still within its window"
    );
    // AT the custom deadline: reaped — 4.5s before the default deadline would have fired.
    driver.reconcile_auth_deadlines(now0 + custom);
    assert!(
      !driver.conns.contains_key(&id),
      "an unvalidated conn is reaped AT the configured deadline (earlier than the default)"
    );
    assert_eq!(
      driver.conn_close_count(viewstamp_proto::CloseCause::AuthDeadline),
      1,
      "the auth-deadline reap is counted under its own cause"
    );
  }

  /// `tune_peer_socket` arms the per-conn socket options on a real connected stream: `TCP_NODELAY`
  /// (consensus pipelines small writes; Nagle + delayed-ACK would add up to ~40ms per exchange) and
  /// `SO_KEEPALIVE` (kernel-level silent-peer detection). Both are readable back off the socket, so
  /// the assertion pins the actual setsockopt effect, not just that the call did not error.
  #[tokio::test]
  async fn tune_peer_socket_sets_nodelay_and_keepalive() {
    let bind: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TestListener::bind(bind).await.expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let (dialed, accepted) =
      futures_util::future::join(TestStream::connect(addr), listener.accept()).await;
    let dialed = dialed.expect("connect");
    let (accepted, _peer) = accepted.expect("accept");

    for stream in [&dialed, &accepted] {
      super::tune_peer_socket(stream);
      assert!(
        stream.nodelay().expect("nodelay readable"),
        "TCP_NODELAY is set on the tuned socket"
      );
      assert!(
        socket2::SockRef::from(stream)
          .keepalive()
          .expect("keepalive readable"),
        "SO_KEEPALIVE is set on the tuned socket"
      );
    }
  }

  /// Drain a `Submit` from the driver's command channel and run it through the REAL `handle_command`
  /// (which mints the request number and inserts the `pending` entry). The reservation was already
  /// made by `Handle::submit`; this completes the Handle->driver crossing the run loop would do. A
  /// `Submit` is never a shutdown, so `handle_command` returns `false` here.
  fn drain_one_command(driver: &mut TestStreamDriver) {
    let cmd = driver.commands.try_recv().expect("a command was enqueued");
    let mut ack = None;
    let is_shutdown = driver.handle_command(Instant::ZERO, cmd, &mut ack);
    assert!(!is_shutdown, "a drained Submit is not a Shutdown");
  }

  /// Poll a `submit` future once: it either enqueues its command and parks on the reply (`Pending`),
  /// or resolves immediately (`Ready`, e.g. `Busy`). Returns the resolved result, if any.
  fn poll_submit(
    fut: std::pin::Pin<&mut SubmitFut<'_>>,
  ) -> Option<Result<crate::Reply, DriverError>> {
    let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
    match std::future::Future::poll(fut, &mut cx) {
      std::task::Poll::Ready(r) => Some(r),
      std::task::Poll::Pending => None,
    }
  }

  /// SUBMIT-BUDGET BOUND (stream driver): with NO commits ever arriving (no peers, never a quorum),
  /// the `pending` map + shared budget never exceed `MAX_INFLIGHT` / `MAX_PENDING_BYTES`, and a submit
  /// past the cap returns `Busy` WITHOUT minting a request. Then delivering the matching commits
  /// releases the budget, so a subsequent submit is accepted again. Drives the REAL `Handle::submit`
  /// (reserve + `try_send`), the REAL `handle_command` (insert pending), and the REAL `deliver_event`
  /// (release on commit). To keep the test fast the count cap (4096) is reached against a near-1-byte
  /// body so the byte cap is nowhere near binding; the byte cap itself is covered in `handle.rs`.
  #[tokio::test]
  async fn submit_budget_bounds_pending_and_releases_on_commit_stream() {
    use viewstamp_driver::{MAX_INFLIGHT, MAX_PENDING_BYTES};
    let (mut driver, handle) = test_driver_with_handle().await;

    // Fill exactly to the count cap: each submit reserves (Handle) then is drained into `pending`
    // (driver). Nothing commits, so nothing is released.
    for i in 0..MAX_INFLIGHT {
      let fut = handle.submit(Bytes::from_static(b"x"));
      futures_util::pin_mut!(fut);
      assert!(
        poll_submit(fut.as_mut()).is_none(),
        "submit #{i} within the cap parks on its reply (it was accepted)"
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
      "the session is exactly at the in-flight count cap"
    );
    assert_eq!(driver.budget.count(), MAX_INFLIGHT);

    // One more submit must be Busy and must NOT enqueue a command or grow pending/budget.
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
      "a Busy submit does not grow the budget (its reservation was rolled back)"
    );

    // Deliver the matching commits: each releases one budget slot via `deliver_event`. Drain the
    // pending keys so we commit exactly the requests in flight.
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

    // A subsequent submit is accepted again now the budget is free.
    let again = handle.submit(Bytes::from_static(b"z"));
    futures_util::pin_mut!(again);
    assert!(
      poll_submit(again.as_mut()).is_none(),
      "with the budget released a fresh submit is accepted again (parks on its reply)"
    );
    assert_eq!(
      driver.budget.count(),
      1,
      "the accepted submit holds exactly one reservation"
    );
  }

  /// OVER-FRAME REJECTION (stream driver): a submit whose body exceeds `max_request_body_len()` is
  /// rejected up front with `RequestTooLarge` and has NO side effects — no budget reserved (count and
  /// bytes stay 0) and no command enqueued. Without the up-front rejection an over-frame body would
  /// enter `pending`, pin the budget, and wait forever for a commit the transport can never produce
  /// (its relayed `Request`/`Prepare` would exceed `MAX_FRAME_LEN` and be dropped).
  #[tokio::test]
  async fn over_frame_submit_is_rejected_without_side_effects_stream() {
    let (mut driver, handle) = test_driver_with_handle().await;

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

  /// BOUNDARY (stream driver): a body of EXACTLY `max_request_body_len()` is accepted (it parks on its
  /// reply, reserves one slot of that many bytes, and enqueues one command) — the maximum deliverable
  /// size is usable, not rejected off-by-one.
  #[tokio::test]
  async fn max_size_submit_is_accepted_stream() {
    let (mut driver, handle) = test_driver_with_handle().await;

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

  /// CANCELLATION RECLAIM (stream driver): a submit whose reply future is dropped (cancelled) is
  /// reclaimed within a `retransmit_stale` tick — its `pending` entry removed and budget released — so
  /// a later submit that would otherwise be `Busy` succeeds. The budget is filled to the cap, one
  /// in-flight submit is cancelled, and after `retransmit_stale` the next submit is accepted.
  #[tokio::test]
  async fn cancelled_submit_is_reclaimed_within_a_retransmit_tick_stream() {
    use viewstamp_driver::MAX_INFLIGHT;
    let (mut driver, handle) = test_driver_with_handle().await;

    // The FIRST submit is the one we cancel: keep its future so dropping it cancels the reply.
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

    // At the cap a new submit is Busy.
    let blocked = handle.submit(Bytes::from_static(b"blocked"));
    futures_util::pin_mut!(blocked);
    assert!(
      matches!(poll_submit(blocked.as_mut()), Some(Err(DriverError::Busy))),
      "at the cap a submit is Busy"
    );

    // Cancel the first submit by dropping its future (drops its reply receiver).
    drop(first);

    // A retransmit tick reaps the cancelled entry + releases its budget. Use a `now` past the request
    // timeout so live entries would also retransmit (proving the cancelled one is reclaimed, not just
    // not-yet-stale); the no-peer coordinator simply has nowhere to send the retransmits.
    let now = Instant::ZERO + REQUEST_TIMEOUT + Duration::from_millis(1);
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

    // The previously-Busy submit now succeeds (budget has room again).
    let now_ok = handle.submit(Bytes::from_static(b"now-ok"));
    futures_util::pin_mut!(now_ok);
    assert!(
      poll_submit(now_ok.as_mut()).is_none(),
      "after the cancelled submit is reclaimed a fresh submit is accepted again"
    );
    drop(live); // keep the other in-flight reply receivers alive until here (so they stay uncancelled)
  }

  /// SCAN GATE (stream driver): `retransmit_stale` walks `pending` only when its scan deadline is
  /// due, then re-arms `pending_scan_interval` ahead — so per-frame wakes never pay an
  /// O(in-flight) walk each. The gate starts disarmed (a fresh driver's first call scans), a call
  /// strictly before the re-armed deadline must NOT reap a newly-cancelled entry, and a call AT
  /// the deadline must. The skipped call is exactly the bounded staleness the cancellation-reclaim
  /// property tolerates (one scan interval, not "every call").
  #[tokio::test]
  async fn the_pending_scan_is_deadline_gated_stream() {
    let (mut driver, handle) = test_driver_with_handle().await;
    let interval = viewstamp_driver::pending_scan_interval(driver.cfg.request_timeout());

    let mut first: std::pin::Pin<Box<SubmitFut<'_>>> =
      Box::pin(handle.submit(Bytes::from_static(b"a")));
    assert!(poll_submit(first.as_mut()).is_none(), "first submit parks");
    drain_one_command(&mut driver);
    drop(first); // cancel: drops the reply receiver

    let t0 = Instant::ZERO + REQUEST_TIMEOUT;
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

    driver.retransmit_stale(t0 + (interval - Duration::from_millis(1)));
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
  /// submit is in flight (mirroring the auth-deadline fold), so a parked driver wakes ON the scan
  /// schedule instead of relying on the 50ms idle fallback. With NOTHING pending the scan is NOT
  /// folded: the gate value is a past instant once a scan has run, and an empty map gives the scan
  /// nothing to do — so an idle driver's baseline stays the fallback (which the first assert pins:
  /// an unconditional fold would return the past scan instant and fail it).
  #[tokio::test]
  async fn next_deadline_folds_the_pending_scan_deadline_stream() {
    let (mut driver, handle) = test_driver_with_handle().await;

    // Baseline: nothing pending, no conns, a never-driven endpoint — the ~50ms idle fallback
    // governs, proving the (elapsed) scan deadline is not folded for an empty pending map.
    let baseline = driver.next_deadline();
    assert!(
      baseline >= std::time::Instant::now() + Duration::from_millis(40),
      "with nothing pending the idle fallback governs (the scan deadline is not folded)"
    );

    // One in-flight submit + a scan deadline ~5ms out: next_deadline must move to it, well under
    // the fallback.
    let mut fut: std::pin::Pin<Box<SubmitFut<'_>>> =
      Box::pin(handle.submit(Bytes::from_static(b"x")));
    assert!(poll_submit(fut.as_mut()).is_none(), "submit parks");
    drain_one_command(&mut driver);
    let due = driver.clock.now() + Duration::from_millis(5);
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
  #[tokio::test]
  async fn a_canceled_queued_submit_never_enters_consensus_stream() {
    let (mut driver, handle) = test_driver_with_handle().await;
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

  /// SHUTDOWN RACE — NO BUDGET LEAK (stream driver): submits that reserved the budget and were
  /// enqueued but NOT yet drained into `pending` when the driver tears down must not leak their
  /// reservation. Each `Handle::submit` carries its `ReservationGuard` inside the queued
  /// `Command::Submit`; tearing the driver (and its command channel) down drops those still-queued
  /// commands, and each guard's `Drop` releases its slot. An independent budget clone (the survivor a
  /// cloned `Handle` would share) returns to zero — count AND bytes — so a surviving `Handle` never
  /// sees spurious `Busy` from a reservation stranded across teardown.
  #[tokio::test]
  async fn queued_submits_release_budget_when_the_driver_tears_down_stream() {
    let (driver, handle) = test_driver_with_handle().await;
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

  /// SHUTDOWN-RACE AIRTIGHTNESS (stream driver): a `Submit` queued BEHIND the `Shutdown` command —
  /// enqueued after `shutdown()` but before the run loop drains it — must RESOLVE and release its
  /// budget by the time the shutdown ack arrives, even though `Handle` clones (command-channel
  /// senders) stay alive past the ack. The run loop exits on the `Shutdown` with the submits still
  /// buffered; the teardown's close-then-drain of the command channel drops each queued `Submit`,
  /// so its reply oneshot resolves as dropped (`ReplyDropped`) and its `ReservationGuard` releases.
  /// A teardown that releases buffered commands only when every sender drops would instead pin the
  /// racing submits' replies and budget for as long as any `Handle` clone lives: the awaiting
  /// callers — themselves keeping a `Handle` borrowed — would hang indefinitely.
  #[tokio::test]
  async fn submits_queued_behind_a_shutdown_resolve_and_release_budget_stream() {
    let (driver, handle) = test_driver_with_handle().await;
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
    let _run = tokio::spawn(driver.run());
    tokio::time::timeout(Duration::from_secs(5), shutdown_fut)
      .await
      .expect("the shutdown ack arrives")
      .expect("shutdown acks teardown");

    // Every racing submit RESOLVES after the ack (bounded await, no hang)...
    for (i, fut) in racing.into_iter().enumerate() {
      let res = tokio::time::timeout(Duration::from_secs(5), fut)
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

  /// The storage notifier is a wake-latency optimization the embedder may not wire at all:
  /// dropping every sender clone must DOWNGRADE storage pumping to timer cadence, not turn the
  /// dead channel into an always-ready select arm. The fixture's notifier is already
  /// disconnected, so this drives the production `run()` loop on the single-thread test flavor
  /// and hands it the worker: a spinning loop would monopolize the thread and never schedule this
  /// task again (a HANG here is the regression); parked correctly, every yield returns and the
  /// shutdown acks.
  #[tokio::test]
  async fn a_disconnected_storage_notifier_parks_its_arm_instead_of_spinning() {
    let (driver, handle) = test_driver_with_handle().await;
    let task = tokio::spawn(driver.run());
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }
    handle.shutdown().await.expect("driver acks shutdown");
    task.await.expect("run() returns after the ack");
  }
}

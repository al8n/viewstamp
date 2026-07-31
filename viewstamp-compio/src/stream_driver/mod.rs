use std::{
  collections::HashMap,
  io,
  net::SocketAddr,
  rc::Rc,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use compio::net::{TcpListener, TcpStream};
use futures_channel::oneshot;
use viewstamp_proto::Instant;
// The proto's transport `Conn<R>` is aliased `TransportConn` here so the bare name `Conn` belongs to
// the driver's owned per-connection unit (`crate::bridge::Conn`).
use viewstamp_proto::{
  ClientId, CloseCause, Config, Conn as TransportConn, ConnId, MemberId, Membership, Peer,
  ReplicaId, Request, RequestNumber, StateMachine, Storage, StreamCoordinator, StreamTransport,
  Superblock, Wal,
};

use viewstamp_driver::{
  BlockLane, Clock, Command, DriverConfig, DriverError, Handle, InflightBudget, Pending,
  PendingMap, Retirement, ShutdownReport, StorageQuiescence, build_endpoint, deliver_event,
  drain_pending, drain_storage, finish_reconfigure_on_retire, gate_command_on_retirement, jittered,
  pending_scan_interval, reap_and_collect_retransmits, retire,
};

use crate::bridge::{
  BridgeInbound, BridgeOut, Conn, ConnTask, DialReady, Redial, bridge_read, bridge_write,
};

/// Shared inbound-channel capacity (bridge tasks -> driver). Bounds the bytes in flight to
/// `INBOUND_CAP * RECV_BUF_LEN`: once full the bridge's `send_async` awaits, the bridge stops
/// reading, and kernel TCP backpressure slows the peer. The driver drains the inbound every loop
/// iteration (iter-top fairness + the select arm), so this only fills under genuine overload.
const INBOUND_CAP: usize = 256;

/// Capacity of the bounded accepted-socket channel (accept task -> run loop). Deliberately small:
/// a socket parked here is accepted but NOT yet admitted — it counts against no connection cap and
/// carries no auth deadline until the driver registers it — so this cap bounds how many such
/// limbo sockets can exist at once, while still absorbing a legitimate full-mesh reconnect burst
/// without parking the task. Once full the accept task's `send_async` parks, no `accept()` is in
/// flight, and further peers queue in the kernel's listen backlog — exactly listener
/// backpressure. The driver admits (or at-capacity drops) one accepted socket per loop iteration.
///
/// A bounded retained-state row beside the shared inventory (the memory-model table in
/// `viewstamp-driver`'s session module): the stream accept channel holds at most `ACCEPT_CAP`
/// sockets, the parked accept task — and behind it the kernel listen backlog — providing the
/// backpressure.
const ACCEPT_CAP: usize = 16;
/// Backoff before retrying a failed `accept()`: long enough to yield the shared thread and let a
/// transient condition (fd exhaustion) clear, short enough that real accepts resume promptly.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// The persistent accept task: owns a clone of the driver's listener (compio sockets share one fd
/// across clones), looping `accept()` and forwarding each accepted socket into the bounded channel
/// the run loop selects on.
///
/// Keeping the op in its own task is what makes the run loop's accept arm a plain channel wait: on
/// a proactor, DROPPING a not-yet-finished op future (what a losing select arm does) submits an
/// asynchronous CANCEL, so a loop that re-arms `accept()` per iteration pays a cancel + resubmit
/// on every wake anything else wins. The task only DELIVERS: admission — the max-conns capacity
/// drop and its close counter — stays the driver's decision at its accept arm, where the
/// connection table lives.
///
/// A transient `accept()` error (e.g. fd exhaustion) is retried after a short backoff sleep: on
/// the polling backend an accept is attempted synchronously before parking, so a PERSISTENT error
/// (EMFILE resolves immediately, not as would-block) would otherwise hot-spin this task on the one
/// shared thread and starve the run loop — the timer park is the scheduler-progress guarantee, and
/// it bounds the retry rate until file descriptors free up. The task exits when the driver
/// drops the channel receiver; the driver also OWNS the task's `JoinHandle`, whose drop cancels
/// the task on every run-loop exit path. That cancel is asynchronous — dropping the handle marks
/// the task cancelled and schedules it, the executor's next pass drops this future (with its
/// listener clone), and dropping the in-flight `accept()` submits a proactor-level cancel that
/// holds a further fd reference until processed — so the orderly teardown in `run()` does not
/// treat the drop as the fd release; the listener `close().await` there is what waits out both
/// references.
async fn accept_conns(listener: TcpListener, accepted: flume::Sender<(TcpStream, SocketAddr)>) {
  loop {
    match listener.accept().await {
      Ok((stream, addr)) => {
        if accepted.send_async((stream, addr)).await.is_err() {
          return; // the driver dropped its receiver: it is tearing down
        }
      }
      // Park on the timer before retrying so a persistent synchronous error cannot starve the
      // shared thread (see the doc above).
      Err(_) => compio::time::sleep(ACCEPT_ERROR_BACKOFF).await,
    }
  }
}

/// Tune a freshly-connected/accepted peer TCP socket. Best-effort: every option here is latency /
/// failure-detection tuning, not a correctness requirement, so a socket that rejects one still
/// carries consensus traffic.
fn tune_peer_socket(stream: &TcpStream) {
  // TCP_NODELAY: consensus pipelines small writes (the next Prepare goes out while the prior one is
  // un-acked), and Nagle + delayed-ACK would hold each back up to ~40ms exactly there.
  let _ = stream.set_nodelay(true);
  let sock = socket2::SockRef::from(stream);
  // SO_KEEPALIVE: kernel probes eventually surface a silently-dead peer (no FIN/RST arrived) as a
  // socket error, instead of leaving an idle conn to the ~15min TCP retransmission timeout.
  let _ = sock.set_keepalive(true);
  // TCP_USER_TIMEOUT (Linux-only): bound how long written-but-unacked bytes may sit before the
  // kernel fails the conn, so a peer that vanishes mid-stream errors out (and redials) in seconds.
  #[cfg(target_os = "linux")]
  let _ = sock.set_tcp_user_timeout(Some(Duration::from_secs(10)));
}

/// Builds a transport `Conn<R>` for dialing the given peer (captures the embedder's TLS client config + cluster id).
pub(crate) type DialerFactory<R> = Rc<dyn Fn(Peer) -> TransportConn<R>>;
/// Builds a transport `Conn<R>` for an accepted inbound connection (captures the embedder's TLS server config).
pub(crate) type AcceptorFactory<R> = Rc<dyn Fn() -> TransportConn<R>>;

/// The compio (proactor) TCP/TLS driver. Owns the listener + the stream coordinator + storage on one
/// task; a persistent same-thread accept task (holding a clone of the listener, owned via its
/// `JoinHandle` by `run()`) feeds it accepted sockets, and each peer connection is one owned `Conn`
/// unit whose live task(s) (the connect task, then the two independent bridge halves) the driver
/// holds, so dropping the `Conn` is the connection's single complete teardown.
pub struct CompioStreamDriver<S: StateMachine, R, W, B> {
  coord: StreamCoordinator<S, R>,
  storage: Storage<W, B>,
  /// The embedder-provided block-storage lane, the peer of `wal`/`sb` in the node's durable store:
  /// large bodies (state-sync chunks, snapshots) are addressed by content hash there while the
  /// WAL/superblock hold the consensus log and durable root. The lane owns the store; the run loop
  /// only hands it jobs and feeds back completions, so block I/O never runs on this thread.
  block_lane: BlockLane<S>,
  listener: TcpListener,
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
  #[cfg(test)]
  budget: InflightBudget,
  /// Shared write-once terminal retirement signal, latched by the run loop's event pump when this
  /// endpoint removes itself from the configuration. Its `Handle` clone reads it to fail submits
  /// terminally (see [`retire`] and [`Handle::submit`]).
  retired: Retirement,
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
  conns: HashMap<ConnId, Conn>,
  /// Closes counted by [`CloseCause`] (indexed by [`CloseCause::index`]): the coordinator's
  /// internal closes as drained by [`Self::reconcile_closed_conns`], plus the driver's own
  /// for-cause closes (auth-deadline reap, out-queue overflow, at-capacity accept drop). Each close
  /// is counted exactly once, at the site that decided it; the coordinator-reap echo of a close the
  /// driver already counted is filtered by the conn no longer being in `conns`.
  close_counts: [u64; CloseCause::COUNT],
  peer_addrs: HashMap<ReplicaId, SocketAddr>,
  /// Peer address book: maps each peer's stable [`MemberId`] to its network address, populated via
  /// [`Command::AddPeer`] and seeded from the initial peer list at construction. The slot-keyed
  /// `peer_addrs` is derived from this book plus the active membership on each config change.
  peer_book: HashMap<MemberId, SocketAddr>,
  /// Membership config gate: detects when the live config_id changes so `rekey_peers` runs exactly
  /// once per install, even when `pump_outputs` loops or `handle_timeout` triggers an install.
  reconciler: viewstamp_driver::MembershipReconciler,
  dialer: DialerFactory<R>,
  acceptor: AcceptorFactory<R>,
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
  dial_ready_tx: flume::Sender<DialReady>,
  dial_ready_rx: flume::Receiver<DialReady>,
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

impl<S, R, W, B> CompioStreamDriver<S, R, W, B>
where
  S: StateMachine,
  R: StreamTransport,
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
  /// discard the durable view/log — the VSR amnesia hazard. The constructor opens the
  /// [`Storage`](viewstamp_proto::Storage) session over the pair and keeps it for the driver's
  /// whole life, so the handles MUST be QUIESCED here — freshly formatted, or freshly opened after
  /// a process start, where in-flight ops died with the process. Handles carrying a live
  /// predecessor's un-quiesced writes can only come out of another session, which releases them
  /// only once it has proven the medium quiet. The
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
  /// `blocks` is the block-storage lane the embedder built around its block store
  /// ([`BlockLane::spawn`] for the production placement — a dedicated thread — or
  /// [`BlockLane::inline`] for a deterministic harness). A lane rather than a bare store because the
  /// lane owns the store AND the execution-order cursor that must follow it: a driver rebuilt over
  /// the same store must be handed the SAME lane, since a fresh cursor's first admission is
  /// unchecked and the cross-incarnation order guarantee would restart blank.
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
    blocks: BlockLane<S>,
    client: ClientId,
    first_request: u64,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    dialer: DialerFactory<R>,
    acceptor: AcceptorFactory<R>,
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
  /// [`DriverError::ProbeIntervalNotBelowMaxAge`] if `cfg.health_probe_interval()` is not strictly
  /// below `cfg.health_proof_max_age()`; [`DriverError::CapBelowPeerMesh`] if `cfg.max_conns()` is
  /// below twice the configured peer count (the mutual-dial mesh needs one dialed and one accepted
  /// connection per peer, and both are consensus-required); [`DriverError::Bind`] if the listener
  /// cannot bind.
  #[allow(clippy::too_many_arguments)]
  pub async fn with_config(
    config: Config,
    membership: Membership,
    state_machine: S,
    wal: W,
    sb: B,
    blocks: BlockLane<S>,
    client: ClientId,
    first_request: u64,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    dialer: DialerFactory<R>,
    acceptor: AcceptorFactory<R>,
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
    let listener = TcpListener::bind(bind_addr)
      .await
      .map_err(DriverError::Bind)?;
    // The session that owns these handles and every physical write fact over them for the rest of
    // this driver's life: built ONCE, here, over handles a `format` or a process start left
    // quiesced, and threaded by `&mut` into every call from then on. Its ledgers — the
    // slot-quiescence fence, the root timeline, the in-flight envelopes — outlive any endpoint
    // built over it.
    let mut storage = Storage::new(wal, sb);
    let endpoint = build_endpoint(
      config,
      membership,
      state_machine,
      &mut storage,
      // The lane's own accounting: what it still holds for a dead predecessor endpoint, if an
      // embedder handed this driver a surviving lane clone; empty on a fresh lane.
      blocks.occupancy(),
    )?;
    let coord = StreamCoordinator::new(endpoint);
    // Seed the peer_book from the initial (slot -> addr) peers using the coordinator's membership
    // to resolve each slot to its stable MemberId.
    let mut peer_book: HashMap<MemberId, SocketAddr> = HashMap::new();
    for &(id, addr) in &peers {
      if let Some(member_id) = coord.endpoint().member_at(id) {
        peer_book.insert(member_id, addr);
      }
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
    let (bin_tx, bin_rx) = flume::bounded(INBOUND_CAP);
    // Unbounded by construction but bounded by the live dial count: one dial task per dialed peer
    // (at most one in flight per configured peer), each sending exactly one `DialReady` — so at
    // effectively bounded by the configured peer count; see the field doc.
    let (dr_tx, dr_rx) = flume::unbounded();
    let budget = InflightBudget::new(cfg.max_inflight(), cfg.max_pending_bytes());
    let retired = Retirement::new();
    let driver = Self {
      coord,
      storage,
      block_lane: blocks,
      listener,
      clock,
      cfg,
      client,
      next_request: first_request,
      pending: PendingMap::new(),
      next_pending_scan: Instant::ZERO,
      #[cfg(test)]
      budget: budget.clone(),
      retired: retired.clone(),
      conns: HashMap::new(),
      close_counts: [0; CloseCause::COUNT],
      peer_addrs: peers.into_iter().collect(),
      peer_book,
      reconciler,
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
      next_probe_at: None,
    };
    let handle = Handle::new(commands_tx, events_rx, budget, retired);
    Ok((driver, handle))
  }
}

impl<S, R, W, B> CompioStreamDriver<S, R, W, B>
where
  S: StateMachine,
  R: StreamTransport,
  W: Wal,
  B: Superblock,
{
  /// Run the driver to completion. Returns on a `Shutdown` command or when all `Handle` clones drop.
  ///
  /// Both orderly exits — and therefore the ack a [`Handle::shutdown`] awaits — are
  /// STORAGE-QUIESCE and listener-release barriers. The teardown first drains the endpoint's
  /// in-flight storage — WAL, superblock, and the block jobs on its lane (bounded; see
  /// [`Self::quiesce_storage`]) — so an orderly stop is
  /// distinguishable from a crash, and reports the outcome in the ack's [`ShutdownReport`]. It then
  /// waits for the accept task's listener clone and its in-flight op's fd reference to drop and
  /// CLOSES the listener fd, so an embedder may bind a new driver to the same address the moment
  /// `shutdown().await` (or an awaited `run()` task) returns. Peer-connection sockets are cancelled
  /// in the same teardown but release asynchronously; they are separate fds and the listener binds
  /// with `SO_REUSEADDR`, so they never gate rebinding the listen address. Cancelling the `run()`
  /// future itself (dropping its spawn handle) cannot barrier — drop glue cannot await, so it skips
  /// the storage drain too — but still releases the fd promptly: the owned accept-task `JoinHandle`
  /// drops with it, and the fd closes once the runtime processes the scheduled cancellations
  /// (within its next passes, not synchronously with the drop).
  pub async fn run(mut self) {
    use futures_util::{FutureExt, select_biased};

    /// Per-iteration command drain budget: bound the iter-top fairness step so a steady command
    /// stream can't itself starve the I/O select, while still letting `Shutdown`/`Submit` make
    /// progress under an accept flood.
    const CMD_BUDGET: usize = 64;

    /// Per-iteration inbound/dial-ready drain budget: bound each iter-top channel drain so a flood
    /// on one channel can't monopolize the loop — the next iteration continues draining the rest.
    const IO_BUDGET: usize = 256;

    // The persistent accept task (see [`accept_conns`]): its listener clone shares the driver's
    // fd, and the bounded channel is the run loop's accept face. The `JoinHandle` is OWNED by
    // this scope — never detached — so EVERY exit path (Shutdown, handle-drop, or this whole
    // future being cancelled) drops it, cancelling the task with its in-flight `accept()` and its
    // listener clone. The cancel is mark-and-schedule, not synchronous teardown: the orderly
    // exits below follow it with the listener `close().await` as the true fd-release barrier,
    // and a cancellation of this whole future releases the fd on the runtime's next passes
    // instead (see [`Self::run`]'s contract).
    let (accept_tx, accept_rx) = flume::bounded(ACCEPT_CAP);
    let accept_task = compio::runtime::spawn(accept_conns(self.listener.clone(), accept_tx));

    // Initial dials: connect to every configured peer (each at the base redial backoff).
    for (id, addr) in self.peer_addrs.clone() {
      self.dial_peer(id, addr, Duration::ZERO, self.cfg.redial_backoff_base());
    }
    let now = self.clock.now();
    self.pump_outputs(now).await;

    let mut shutdown_ack: Option<oneshot::Sender<ShutdownReport>> = None;
    loop {
      // Iter-top fairness: drain + PROCESS every input channel (bounded budgets) BEFORE the biased
      // select, so no channel can be starved by another. `accept_fut` is the select's first (highest
      // priority) arm, so without this a continuous accept backlog would win every iteration and
      // starve inbound consensus frames + dial completions indefinitely — the node would accept
      // sockets and fire timers but never advance consensus. Draining here, then using the select
      // only to WAIT, makes accept one-per-iteration while everything else drains fully each pass.
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

      // Service the consensus timer under the none-or-due gate (see the method).
      self.service_consensus_timer(now);
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

      // Recompute AFTER the iter-top timer fire so it reflects the next deadline (avoids a redundant
      // immediate select-timer fire for the timer we just serviced).
      let deadline = self.next_deadline();

      // The six futures BORROW the accept channel + driver fields (`accept_fut` holds
      // `&accept_rx`, `cmd_fut` `&mut self.commands`, the rest their channels — disjoint fields).
      // Confine construction + `select_biased!` to this inner scope: when it ends the pinned
      // futures drop, releasing the borrows so the post-select `&mut self` work is legal. All six
      // arms are plain channel/timer waits — the socket I/O itself lives in the accept task and
      // the bridges — so a losing arm never cancels an in-flight socket op.
      //
      // The select only WAITS for the next event so the loop can re-drain at iter-top. `accept_fut`
      // is processed one-per-iteration in its arm (its `Err` — a closed channel — is unreachable
      // while this scope holds `accept_task`: the task only exits when the receiver it sends to
      // drops). `timer_fut`/`storage_fut` are genuinely wake-only:
      // they yield `()` / `Ok(())`, so dropping the resolved value loses nothing (the iter-top
      // due-timer check + the unconditional `pump_outputs` storage re-poll cover them next pass).
      // `cmd_fut`/`inbound_fut`/`dial_fut`/`accept_fut`, by contrast, CONSUME an item when they
      // resolve (flume's `recv_async` removes it from the channel), so their item is CAPTURED into
      // a local and handled after this scope — dropping it would silently lose a command (e.g. a
      // `Shutdown`), a peer frame, a dial completion, or an accepted socket. The bulk still drains
      // at iter-top; this just doesn't waste the one item the select happened to consume to wake us.
      let mut accepted = None;
      let mut command = None;
      let mut inbound = None;
      let mut dial_ready = None;
      let mut storage_closed = false;
      let mut block_done = None;
      {
        let accept_fut = accept_rx.recv_async().fuse();
        let timer_fut = compio::time::sleep_until(deadline).fuse();
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
        // The storage lane's own wake: a job the lane finished while this loop waited on I/O. Like
        // the command/inbound/dial arms it CONSUMES its item, so the completion is captured and fed
        // below — dropping it would lose a materialize's durability verdict.
        let blocks_fut = self.block_lane.recv().fuse();
        futures_util::pin_mut!(
          accept_fut,
          timer_fut,
          cmd_fut,
          inbound_fut,
          dial_fut,
          blocks_fut,
          storage_fut
        );

        select_biased! {
          a = accept_fut => { if let Ok((stream, addr)) = a { accepted = Some((stream, addr)); } }
          _ = timer_fut => {}
          // Capture the whole `Result`: `Err(RecvError)` (all `Handle` clones dropped and the
          // buffer drained — the channel has ended) must exit the loop, not be silently ignored —
          // otherwise the accept arm keeps winning the biased select while the dead command
          // channel is dropped on the floor, spinning forever.
          c = cmd_fut => { command = Some(c); }
          i = inbound_fut => { if let Ok(i) = i { inbound = Some(i); } }
          d = dial_fut => { if let Ok(d) = d { dial_ready = Some(d); } }
          b = blocks_fut => { block_done = Some(b); }
          s = storage_fut => { storage_closed = s.is_err(); }
        }
      }
      if storage_closed {
        self.storage_notifier_closed = true;
      }
      let now = self.clock.now();

      // Handle the single item the select consumed to wake us (the rest drained at iter-top). These
      // run the same shared helpers as the iter-top drain, so there is no behavior divergence.
      if let Some(done) = block_done {
        self.feed_block_completion(now, done);
      }
      if let Some(inb) = inbound {
        self.handle_inbound(now, inb);
      }
      if let Some(dr) = dial_ready {
        self.handle_dial_ready(now, dr);
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

    // One teardown for every connection: dropping each `Conn` drops its task `JoinHandle`(s) (compio
    // cancels the live connect task OR both bridge halves, closing the socket) and its `out_tx`. On
    // shutdown the
    // consensus state is durable, so a hard cancel here (vs. a best-effort byte flush) loses nothing
    // a restart can't resume.
    self.conns.clear();
    // Drop every still-pending submit (its commit never arrived) and clear the map: each entry's
    // `ReservationGuard` releases its budget slot on drop, so the budget never leaks across the
    // driver's life. A `Submit` still queued in the command channel releases in the
    // close-then-drain below, its guard with it.
    drain_pending(&mut self.pending);
    // The durability barrier, before anything is released: the run loop has exited, so nothing
    // further enters consensus, and the endpoint's outstanding storage — WAL, superblock, and the
    // block jobs on its lane — is drained to
    // quiescence (or to the bounded deadline) while its storage handles are still owned here. It
    // runs AFTER `drain_pending` so a caller awaiting a submit is released immediately rather than
    // being held for the drain window — the entries dropped there are driver-side bookkeeping and
    // touch neither the endpoint nor the store.
    let storage = self.quiesce_storage().await;
    // Dropping the `JoinHandle` only MARKS the accept task cancelled and SCHEDULES it: the task —
    // its listener clone and its in-flight `accept()` — is dropped on the executor's next pass,
    // and dropping that in-flight op merely submits an asynchronous proactor cancel which itself
    // holds an fd reference until the cancellation is processed. Nothing is released yet when
    // this drop returns.
    drop(accept_task);
    // Dropping the accepted-socket receiver releases this side; the buffered sockets themselves
    // free with the accept task's sender clone, which the listener `close().await` below waits
    // out — so accepted-but-unadmitted fds are gone by the ack. That is the general teardown
    // shape for DRIVER-INTERNAL queues: their senders all live in tasks this teardown just
    // cancelled, so they release with those tasks — promptly, but asynchronously.
    drop(accept_rx);
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
    // Dropping these receivers releases only the receivers' side, and unwedges any
    // still-cancelling bridge/dial task parked on a full channel (its `send_async` errors out
    // instead of waiting for its cancel to be processed). The queued items — dial completions
    // carrying sockets, buffered inbound bytes — free with their sender tasks' prompt-async
    // teardown above (the per-connection sockets are separate fds and never gate the
    // listen-address rebind).
    drop(self.dial_ready_rx);
    drop(self.bridge_inbound_rx);
    // The fd-release barrier: `close` parks until every other reference to the listener's fd —
    // the accept task's clone and its cancelled-but-unprocessed op — has dropped, then closes the
    // fd with a real close op. Once this await returns the listen address is free, which is what
    // makes the ack below (and `run()`'s return) an immediate-rebind contract rather than a hope
    // that the runtime already processed the scheduled cancellations. (The conns cleared above
    // release their own fds asynchronously; those are separate sockets and the listener binds
    // with `SO_REUSEADDR`, so they never gate the rebind.) A close error is ignored: there is no
    // recovery at teardown, and the fd is released regardless.
    let _ = self.listener.close().await;
    if let Some(ack) = shutdown_ack {
      let _ = ack.send(ShutdownReport::new(storage));
    }
  }

  /// Drain the endpoint's in-flight storage at teardown, bounded by
  /// [`SHUTDOWN_DRAIN_DEADLINE`](viewstamp_driver::SHUTDOWN_DRAIN_DEADLINE).
  ///
  /// Each pass feeds the backend's ready completions through the endpoint and drives the block
  /// lane — the same two steps the run loop pumps — and stops as soon as the endpoint owes none.
  /// The lane is part of the drain because a block job in flight IS durability work the endpoint
  /// owes (`has_inflight_storage` counts it): a materialize is the write half of the durable
  /// checkpoint transaction. Only the storage half is pumped: outputs a completion produces (peer
  /// frames, events) belong to a driver that is still running, and this one is cancelling its
  /// connections next.
  async fn quiesce_storage(&mut self) -> StorageQuiescence {
    drain_storage(
      || {
        let now = self.clock.now();
        self.coord.handle_storage_deferred(now, &mut self.storage);
        self.drive_block_lane(now);
        !self.coord.endpoint().has_inflight_storage(&self.storage)
      },
      compio::time::sleep,
    )
    .await
  }

  /// Hand every queued block job to the storage lane, then feed back every completion the lane has
  /// ready, until neither moves. Returns whether anything moved.
  ///
  /// The pair is one step because they feed each other: a completion can queue the next job (a
  /// materialize's durable root releasing the sweep), and an inline lane resolves each job within
  /// this call, so the loop is what settles a deterministic harness in one pass. On a spawned lane
  /// the submit half returns immediately and the completions arrive on later passes — which is
  /// exactly the point: the jobs execute on the lane's thread while this one keeps pumping
  /// consensus.
  ///
  /// Order is preserved end to end: jobs are submitted in the order the endpoint issued them, the
  /// lane executes and answers them in that same order, and they are fed back in the order the lane
  /// returns them.
  fn drive_block_lane(&mut self, now: Instant) -> bool {
    let mut any = false;
    loop {
      let mut moved = false;
      while let Some(job) = self.coord.poll_block_job() {
        self.block_lane.submit(job);
        moved = true;
      }
      while let Some(done) = self.block_lane.try_recv() {
        self.feed_block_completion(now, done);
        moved = true;
      }
      if !moved {
        return any;
      }
      any = true;
    }
  }

  /// Feed one block-job completion back into the endpoint and refresh the dial-map: a completion
  /// advances the endpoint (a checkpoint publishing its durable root), which can install a new
  /// membership.
  fn feed_block_completion(&mut self, now: Instant, done: viewstamp_proto::BlockJobDone<S>) {
    self.coord.on_block_done(now, &mut self.storage, done);
    self.rekey_if_needed(now);
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
          .handle_conn_data(id, &bytes, false, now, &mut self.storage);
        // An inbound frame can install a new membership; refresh the dial-map immediately so a
        // close/redial that follows this feed (this iteration's `reconcile_closed_conns` /
        // `reconcile_auth_deadlines`, or a `close_conn`) reads the current projection, never a
        // stale one that could reopen a removed or slot-shifted member.
        self.rekey_if_needed(now);
      }
      BridgeInbound::Eof { id } | BridgeInbound::Error { id } => {
        self.close_conn(id, now);
      }
    }
  }

  /// Handle one [`DialReady`]: on success replace the finished connect task with the two bridge halves
  /// (read + write tasks); on failure tear the conn down (which redials via [`Conn::redial`]).
  ///
  /// A `DialReady` is STALE iff its `ConnId` is no longer in `conns`: `dial_peer` inserts the [`Conn`]
  /// before the async connect completes, so if the conn was closed + replaced (e.g. `close_conn`
  /// reaped it and redialed a NEW id) before this dial finished, the old id is gone. A stale success
  /// is dropped entirely — the carried `TcpStream`/`out_rx` simply drop here; a stale failure does
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
  fn handle_dial_ready(&mut self, now: Instant, dr: DialReady) {
    let Some(conn) = self.conns.get_mut(&dr.id) else {
      return; // stale: this conn was already closed/replaced before its dial completed
    };
    match dr.result {
      Ok(stream) => {
        tune_peer_socket(&stream);
        let inbound_tx = self.bridge_inbound_tx.clone();
        // Replace the now-finished connect task with the two bridge halves; dropping the old
        // (resolved) `JoinHandle` is a no-op. Split into OWNED halves so the read and write tasks each
        // own one half and make progress concurrently via the proactor (a large write never starves
        // reads). The writer drains the `out_rx` the connect task shipped back and decrements
        // `dr.queued_bytes` — the same counter `conn.queued_bytes` clones — incrementally as it writes.
        let (read_half, write_half) = stream.into_split();
        conn.tasks = ConnTask::Bridged {
          read: compio::runtime::spawn(bridge_read(read_half, dr.id, inbound_tx.clone())),
          write: compio::runtime::spawn(bridge_write(
            write_half,
            dr.id,
            dr.out_rx,
            dr.queued_bytes,
            inbound_tx,
          )),
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
    shutdown_ack: &mut Option<oneshot::Sender<ShutdownReport>>,
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
          .submit_client_request(now, &mut self.storage, request);
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
        // later, unrelated membership change. Rebuild the dial table against the current config now —
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
        .propose_membership(now, &mut self.storage, delta, ack)
    });
    if !matches!(outcome, viewstamp_driver::AdvanceOutcome::Done) {
      self.reconfigure = Some(job);
    } else {
      self.next_probe_at = None;
    }
  }

  /// Reconcile conns the COORDINATOR closed internally (a bad frame, a failed identity, or an
  /// outbound-cap overflow): the socket is still open and its bridge still running, so without this
  /// the proto-closed conn is a silent partition until the socket happens to fail. Drain the
  /// coordinator's closed-conn signal and tear down + redial each via [`Self::close_conn`].
  ///
  /// Idempotent with the driver's own close paths: when the driver already tore the conn down (its
  /// EOF/Error/out-full path also reaps in the coordinator, which records the id here), the second
  /// `close_conn(id)` finds `conns` already empty for `id` (so no double-cancel and no double-redial)
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
          conn.auth_deadline = None; // validated: no longer subject to the deadline
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
      self.close_conn(id, now); // unvalidated past the deadline: close (+ redial if dialed)
    }
  }

  /// Tear down a connection the proto/socket/queue has lost: one `remove` drops the [`Conn`], which
  /// cancels its live task(s) (the connect task OR both bridge halves) and drops its `out_tx`; then
  /// reap it in the coordinator (eof) and, if it was a DIALED conn, redial the peer/addr held in
  /// [`Conn::redial`] — but ONLY when `peer_addrs` still maps the slot to the same address, meaning
  /// the member is still present at that slot in the live membership.
  ///
  /// The `peer_addrs` gate is the membership-change safety property: `rekey_peers` rebuilds
  /// `peer_addrs` from the live membership on every config install, so after a removal the slot is
  /// absent and after an address shift the old address no longer matches. A redial suppressed here
  /// is not lost — `rekey_peers` already issued the new-slot dial for a shifted member, and a
  /// removed member must not be redialed at all.
  ///
  /// Shared by the bridge-EOF/Error path (the signalling half has already exited; the drop cancels the
  /// other half and reaps the finished `JoinHandle`), the dial-failure path (drops the finished
  /// connect task), and the out-queue-over-budget path in [`Self::pump_outputs`] (the drop actively
  /// CANCELS a stuck writer: compio aborts a non-detached task on `JoinHandle` drop, dropping the
  /// write future mid-`await` and closing the socket — preempting a write parked on a non-reading peer,
  /// which dropping `out_tx` alone cannot — and cancels the read half with it). Redial only fires for
  /// conns WE dialed (an accepted `Conn` has `redial: None`; that peer redials us). Idempotent: a
  /// second call for an already-removed id finds `conns` empty (no double-cancel/redial) and
  /// `handle_conn_data(.., true, ..)` is a no-op.
  fn close_conn(&mut self, id: ConnId, now: Instant) {
    let removed = self.conns.remove(&id); // drop cancels the task(s) (connect or both halves) + out_tx
    self
      .coord
      .handle_conn_data(id, &[], true, now, &mut self.storage); // reap in coordinator
    if let Some(Conn {
      redial: Some(redial),
      ..
    }) = removed
    {
      // Gate on the live dial table: only redial when `peer_addrs` still maps this slot to the
      // same address. A removed member's slot is absent after `rekey_peers`; a shifted member's
      // slot has a new address (its new-slot dial was already issued by `rekey_peers`). Either way,
      // suppressing here stops stale redials from outliving membership changes.
      if self.peer_addrs.get(&redial.peer) == Some(&redial.addr) {
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
  }

  /// Issue a dial to `peer` at `addr` after `delay`; `backoff` is the (un-jittered) redial delay the
  /// new conn CARRIES for when it is itself lost — the per-peer exponential schedule's next step
  /// (callers pass the configured redial base on a first dial and the doubled-capped value on a
  /// redial). Registers the conn (so the coordinator can queue
  /// handshake bytes immediately) and inserts its [`Conn`], whose owned connect task MOVES the
  /// outbound receiver + byte counter into itself and ships them back in the [`DialReady`] on success.
  ///
  /// The connect task is NOT detached: the `Conn` holds its `JoinHandle`, so closing the conn before
  /// the dial completes drops the `Conn` → drops the `JoinHandle` → cancels the in-flight connect (the
  /// moved `out_rx`/`queued_bytes` drop with it), and no `DialReady` is ever sent. This is the
  /// connect-task ownership that makes handle-drop terminate even with an unreachable configured peer.
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
    let task = compio::runtime::spawn(async move {
      if !delay.is_zero() {
        compio::time::sleep(delay).await;
      }
      let result = match compio::time::timeout(dial_timeout, TcpStream::connect(addr)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "dial timeout")),
      };
      let _ = dial_ready_tx
        .send_async(DialReady {
          id,
          result,
          out_rx,
          queued_bytes: qb_for_task,
        })
        .await;
    });
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
  /// bridge `JoinHandle`s live in the `Conn`, so `close_conn` hard-aborts by dropping it (cancelling
  /// both halves). The conn is stamped with an `auth_deadline` so an accepted socket that never
  /// validates is reaped (just
  /// closed, no redial).
  fn spawn_bridge_accepted(&mut self, now: Instant, id: ConnId, stream: TcpStream) {
    tune_peer_socket(&stream);
    let (out_tx, out_rx) = flume::unbounded();
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let inbound_tx = self.bridge_inbound_tx.clone();
    // Split into OWNED halves so the read and write tasks proceed concurrently (a large write never
    // starves reads). Either half's EOF/error leads the driver to `close_conn`, which drops the
    // `Conn` and so cancels the other half.
    let (read_half, write_half) = stream.into_split();
    let tasks = ConnTask::Bridged {
      read: compio::runtime::spawn(bridge_read(read_half, id, inbound_tx.clone())),
      write: compio::runtime::spawn(bridge_write(
        write_half,
        id,
        out_rx,
        queued_bytes.clone(),
        inbound_tx,
      )),
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
  /// scan, and a 50ms idle fallback (so a quiet node still re-pumps storage).
  ///
  /// The auth deadline is folded in as a REAL wake deadline — mirroring the QUIC bridge, which
  /// `min`s its `earliest_auth_deadline` into `poll_timeout` — so reaping a stalled handshake never
  /// depends on the idle fallback happening to wake the loop: a sleeping driver wakes AT the
  /// deadline and the iter-top [`Self::reconcile_auth_deadlines`] reaps on that pass. The pending
  /// scan deadline is folded the same way, so the gated `pending` walk also runs on schedule in a
  /// parked driver — but only while something IS pending: with the map empty the scan has nothing
  /// to reap or retransmit, so folding its (typically already-elapsed) deadline would only turn an
  /// idle driver's 50ms fallback into a busier wake cadence for no work.
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
    [consensus, auth, scan, reconfig]
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
        .submit_client_request(now, &mut self.storage, request);
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
    // Refresh the dial-map before the first output pass, then after each storage poll: a
    // `handle_storage` completion can itself install a new membership, so the projection must be
    // current before any subsequent dial/route/close decision.
    self.rekey_if_needed(now);
    // The per-conn wire-byte ACCUMULATION threshold the driver tolerates before declaring a stalled
    // socket, OWNED by the proto (2x the router's per-conn staging cap). It is NOT a per-chunk size and
    // NOT the out-queue peak — a single chunk is always admitted at/under it, so the peak is
    // `backlog_cap + one max wire chunk` (see the method doc). Read once here (a copied `usize`) before
    // the loop, so it does not conflict with the `&mut self`/`&self.conns` borrows below.
    let backlog_cap = self.coord.max_outbound_backlog();

    loop {
      self.coord.handle_storage_deferred(now, &mut self.storage);
      self.rekey_if_needed(now);
      let mut produced = self.drive_block_lane(now);
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
        // A live self-removal makes the endpoint structurally Retired: it emits no further commits,
        // so fail every in-flight submit terminally and latch the shared signal (so `Handle::submit`
        // rejects further submits) rather than blackholing them. The endpoint exposes no scalar epoch
        // getter, so the retirement epoch is read off a one-time membership clone — retirement fires
        // at most once per driver, off the hot path. The `StatusChanged` still forwards below.
        if matches!(&event, viewstamp_proto::Event::StatusChanged(status) if status.is_retired()) {
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

  /// Service the consensus timer under a NONE-OR-DUE gate: call `handle_timeout` when nothing is armed
  /// (a disarmed role — a natal or freshly-demoted learner — must be serviced ONCE so its learner-status
  /// cadence self-arms; after that first call the timer is armed and the due-gating below takes over) OR
  /// when the earliest armed timer is due; SKIP when an armed timer is not yet due. The gate is required
  /// because `handle_timeout` is NOT a no-op on a not-yet-due timer: on a Normal primary it also re-drives
  /// a faulted checkpoint flush (`maybe_pay_checkpoint_debt` / `maybe_checkpoint`), so calling it on every
  /// socket/accept wake would rebuild + retry a persistently-faulting flush at the wake rate, amplifying a
  /// storage fault into unbounded work. Gating keeps that re-drive on the consensus cadence while still
  /// letting a disarmed cadence self-bootstrap (the `None` arm). The deadline is compared against the SAME
  /// loop-start `now` handed to `handle_timeout` below (not a freshly-sampled clock), so the gate and the
  /// handler always agree on due-ness: a gate reading a fresher clock than the `now` `handle_timeout` runs
  /// with could decide "due" while the handler's own internal check (against the stale `now`) leaves the
  /// timer unserviced/un-re-armed, yet the primary arm would still re-drive the checkpoint tail — costing
  /// a second rebuild/flush attempt next iteration for what should be one due firing per cadence.
  fn service_consensus_timer(&mut self, now: Instant) {
    if self
      .coord
      .poll_timeout()
      .is_none_or(|deadline| deadline <= now)
    {
      self.coord.handle_timeout(now, &mut self.storage);
      self.rekey_if_needed(now);
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

  /// Rebuild `peer_addrs` against the new membership after a config change — the DIAL-of-added half of
  /// the re-key. CLOSING a stale slot is the COORDINATOR's job now (`reconcile_routing` runs inside the
  /// endpoint-advancing handlers, right after the install, before any output is routed), so this only
  /// rebuilds the slot→addr table and DIALS each slot whose (slot → addr) assignment is new or changed:
  /// an added member, or a slot whose occupant shifted to a member at a different address. The dial
  /// re-establishes the connection under the new slot; a stale dialed conn the coordinator closed
  /// redials toward its OLD slot and is cleanly rejected at the peer's handshake (its attested slot no
  /// longer matches), so it self-corrects. Slots whose address is absent from the book are skipped
  /// until `AddPeer` supplies it.
  fn rekey_peers(&mut self, _now: Instant) {
    let m = self.coord.live_membership();
    let local = self.coord.endpoint().local();
    let base_backoff = self.cfg.redial_backoff_base();
    let mut new_peer_addrs: HashMap<ReplicaId, SocketAddr> = HashMap::new();
    for slot_u16 in 0..m.node_count() {
      let slot = ReplicaId::new(slot_u16);
      let Some(member_id) = m.member_at(slot) else {
        continue;
      };
      if member_id == local {
        continue; // skip self
      }
      let Some(&addr) = self.peer_book.get(&member_id) else {
        continue; // no address known yet
      };
      // A new or changed (slot → addr) means this slot needs a connection to the member now at it:
      // dial it under the new slot. The coordinator already closed any stale conn for the slot.
      if self.peer_addrs.get(&slot) != Some(&addr) {
        self.dial_peer(slot, addr, Duration::ZERO, base_backoff);
      }
      new_peer_addrs.insert(slot, addr);
    }
    self.peer_addrs = new_peer_addrs;
  }
}

#[cfg(test)]
mod tests;

impl<S: StateMachine, R, W, B> CompioStreamDriver<S, R, W, B> {
  /// The number of connection closes attributed to `cause` so far — the coordinator's internal
  /// closes plus the driver's own (auth-deadline, out-queue overflow, accept-cap). Test/diagnostic
  /// observability, not a stable embedder API (hence `#[doc(hidden)]`). Reads only the local
  /// counter array, so it carries none of the operational impl block's bounds.
  #[doc(hidden)]
  pub fn conn_close_count(&self, cause: CloseCause) -> u64 {
    self.close_counts[cause.index()]
  }
}

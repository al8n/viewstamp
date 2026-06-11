use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use compio::net::{TcpListener, TcpStream};
use futures_channel::oneshot;
use viewstamp_proto::Instant;
// The proto's transport `Conn<R>` is aliased `TransportConn` here so the bare name `Conn` belongs to
// the driver's owned per-connection unit (`crate::bridge::Conn`).
use viewstamp_proto::{
  ClientId, CloseCause, Config, Conn as TransportConn, ConnId, Peer, ReplicaId, Request,
  RequestNumber, StateMachine, StreamCoordinator, StreamTransport, Superblock, Wal,
};

use crate::DriverError;
use crate::bridge::{
  BridgeInbound, BridgeOut, Conn, ConnTask, DialReady, Redial, bridge_read, bridge_write,
};
use crate::clock::{Clock, jittered};
use crate::config::DriverConfig;
use crate::handle::{Command, Handle};
use crate::session::{
  InflightBudget, Pending, PendingMap, build_endpoint, deliver_event, drain_pending,
  reap_and_collect_retransmits,
};

/// Shared inbound-channel capacity (bridge tasks -> driver). Bounds the bytes in flight to
/// `INBOUND_CAP * RECV_BUF_LEN`: once full the bridge's `send_async` awaits, the bridge stops
/// reading, and kernel TCP backpressure slows the peer. The driver drains the inbound every loop
/// iteration (iter-top fairness + the select arm), so this only fills under genuine overload.
const INBOUND_CAP: usize = 256;

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
/// task; each peer connection is one owned `Conn` unit whose live task(s) (the connect task, then
/// the two independent bridge halves) the driver holds, so dropping the `Conn` is the connection's
/// single complete teardown.
pub struct CompioStreamDriver<S, R, W, B> {
  coord: StreamCoordinator<S, R>,
  wal: W,
  sb: B,
  listener: TcpListener,
  clock: Clock,
  /// The operational tuning this driver was constructed with ([`DriverConfig::new`] via
  /// [`Self::new`], or the embedder's override via [`Self::with_config`]).
  cfg: DriverConfig,
  client: ClientId,
  next_request: u64,
  pending: PendingMap,
  /// A clone of the shared in-flight submit budget, retained for test observability only. Production
  /// release is by construction: the `Handle` reserves a [`ReservationGuard`] per submit, the guard
  /// rides the `Command::Submit` then the `Pending` entry, and dropping that entry (commit,
  /// cancellation reclaim, shutdown drain) — or the queued command on teardown — releases the slot, so
  /// the driver itself never releases against this handle.
  #[cfg(test)]
  budget: InflightBudget,
  /// One owned unit per connection; its redial target (if any) lives in [`Conn::redial`], so there
  /// is no separate dialed-peer map to keep in sync. Bounded by the configured max_conns (accept
  /// admission control).
  conns: HashMap<ConnId, Conn>,
  /// Closes counted by [`CloseCause`] (indexed by [`CloseCause::index`]): the coordinator's
  /// internal closes as drained by [`Self::reconcile_closed_conns`], plus the driver's own
  /// for-cause closes (auth-deadline reap, out-queue overflow, at-capacity accept drop). Each close
  /// is counted exactly once, at the site that decided it; the coordinator-reap echo of a close the
  /// driver already counted is filtered by the conn no longer being in `conns`.
  close_counts: [u64; CloseCause::COUNT],
  peer_addrs: HashMap<ReplicaId, SocketAddr>,
  dialer: DialerFactory<R>,
  acceptor: AcceptorFactory<R>,
  /// Bounded `flume::bounded(cfg.cmd_cap())`: a full channel surfaces as `Busy` rather than growing.
  commands: flume::Receiver<Command>,
  /// Bounded `flume::bounded(cfg.events_cap())`: best-effort, dropped-on-full (see `deliver_event`).
  events: flume::Sender<viewstamp_proto::Event>,
  /// Bounded `flume::bounded(INBOUND_CAP)`: a full channel backpressures the bridge's `send_async`,
  /// which stops reading and slows the peer via kernel TCP backpressure.
  bridge_inbound_tx: flume::Sender<BridgeInbound>,
  bridge_inbound_rx: flume::Receiver<BridgeInbound>,
  /// Unbounded by construction but BOUNDED by the live dial count: exactly one dial task exists per
  /// dialed `Conn`, each sends at most one `DialReady`, and `conns` is capped at the configured
  /// max_conns — so at most that many `DialReady`s can ever be queued. Drained (bounded budget)
  /// every loop iteration.
  dial_ready_tx: flume::Sender<DialReady>,
  dial_ready_rx: flume::Receiver<DialReady>,
  /// Embedder-owned notifier. Carries a unit signal only and is drained to empty every loop iteration
  /// (`while self.storage_ready.try_recv().is_ok() {}`), so the driver retains at most the in-flight
  /// signals queued within one iteration — no per-submit growth.
  storage_ready: flume::Receiver<()>,
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
    state_machine: S,
    wal: W,
    sb: B,
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
  /// [`DriverError::Bind`] if the listener cannot bind.
  #[allow(clippy::too_many_arguments)]
  pub async fn with_config(
    config: Config,
    state_machine: S,
    mut wal: W,
    mut sb: B,
    client: ClientId,
    first_request: u64,
    bind_addr: SocketAddr,
    peers: Vec<(ReplicaId, SocketAddr)>,
    dialer: DialerFactory<R>,
    acceptor: AcceptorFactory<R>,
    storage_ready: flume::Receiver<()>,
    cfg: DriverConfig,
  ) -> Result<(Self, Handle), DriverError> {
    let clock = Clock::new();
    let listener = TcpListener::bind(bind_addr)
      .await
      .map_err(DriverError::Bind)?;
    let endpoint = build_endpoint(config, state_machine, &mut wal, &mut sb);
    let coord = StreamCoordinator::new(endpoint);
    // Bounded command channel: a partitioned/slow driver (not draining commands) can't grow it
    // without bound; a full channel surfaces as `DriverError::Busy` (see `Handle::submit`). Sized
    // `cmd_cap` (= max_inflight + 1) so the in-flight budget, not this queue, is the binding submit
    // limit.
    let (commands_tx, commands_rx) = flume::bounded(cfg.cmd_cap());
    // Bounded best-effort: a slow/absent `Handle::events()` consumer drops events rather than
    // growing the channel without bound (see `deliver_event`). Submit replies are unaffected.
    let (events_tx, events_rx) = flume::bounded(cfg.events_cap());
    let (bin_tx, bin_rx) = flume::bounded(INBOUND_CAP);
    // Unbounded by construction but bounded by the live dial count (one dial task per dialed `Conn`,
    // each sends one `DialReady`, `conns` capped at the configured max_conns); see the field doc.
    let (dr_tx, dr_rx) = flume::unbounded();
    let budget = InflightBudget::new(cfg.max_inflight(), cfg.max_pending_bytes());
    let driver = Self {
      coord,
      wal,
      sb,
      listener,
      clock,
      cfg,
      client,
      next_request: first_request,
      pending: PendingMap::new(),
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
    };
    let handle = Handle::new(commands_tx, events_rx, budget);
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
      // select, so no channel can be starved by another. `accept_fut` is the select's first (highest
      // priority) arm, so without this a continuous listener backlog would win every iteration and
      // starve inbound consensus frames + dial completions indefinitely — the node would accept
      // sockets and fire timers but never advance consensus. Draining here, then using the select
      // only to WAIT, makes accept one-per-iteration while everything else drains fully each pass.
      let now = self.clock.now();

      // Commands: bounded so a steady command stream can't itself monopolize the loop, while
      // `Shutdown`/`Submit` still make progress under an accept flood.
      if self.commands.sender_count() == 0 {
        break; // all Handles dropped: exit now, discard queued commands
      }
      let mut exit = false;
      for _ in 0..CMD_BUDGET {
        match self.commands.try_recv() {
          Ok(cmd) => {
            if self.handle_command(now, cmd, &mut shutdown_ack) {
              exit = true;
              break;
            }
          }
          // No command pending right now: stop draining and fall through to the I/O select.
          Err(flume::TryRecvError::Empty) => break,
          // All `Handle` clones dropped: the command channel is closed for good, so exit the run
          // loop (an accept backlog would otherwise keep winning the biased accept arm and hold the
          // listener + conns alive, spinning on the ignored disconnected command channel).
          Err(flume::TryRecvError::Disconnected) => {
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

      // The six futures BORROW driver fields (`accept_fut` holds `&self.listener`, the rest their
      // channels). Confine construction + `select_biased!` to this inner scope: when it ends the
      // pinned futures drop, releasing the borrows so the post-select `&mut self` work is legal.
      //
      // The select only WAITS for the next event so the loop can re-drain at iter-top. `accept_fut`
      // is processed one-per-iteration in its arm. `timer_fut`/`storage_fut` are genuinely wake-only:
      // they yield `()` / `Ok(())`, so dropping the resolved value loses nothing (the iter-top
      // due-timer check + the unconditional `pump_outputs` storage re-poll cover them next pass).
      // `cmd_fut`/`inbound_fut`/`dial_fut`, by contrast, CONSUME an item when they resolve (flume's
      // `recv_async` removes it from the channel), so their item is CAPTURED into a local and handled
      // after this scope — dropping it would silently lose a command (e.g. a `Shutdown`), a peer
      // frame, or a dial completion. The bulk still drains at iter-top; this just doesn't waste the
      // one item the select happened to consume to wake us.
      let mut accepted = None;
      let mut command = None;
      let mut inbound = None;
      let mut dial_ready = None;
      {
        let accept_fut = self.listener.accept().fuse();
        let timer_fut = compio::time::sleep_until(deadline).fuse();
        let cmd_fut = self.commands.recv_async().fuse();
        let inbound_fut = self.bridge_inbound_rx.recv_async().fuse();
        let dial_fut = self.dial_ready_rx.recv_async().fuse();
        let storage_fut = self.storage_ready.recv_async().fuse();
        futures_util::pin_mut!(
          accept_fut,
          timer_fut,
          cmd_fut,
          inbound_fut,
          dial_fut,
          storage_fut
        );

        select_biased! {
          a = accept_fut => { if let Ok((stream, addr)) = a { accepted = Some((stream, addr)); } }
          _ = timer_fut => {}
          // Capture the whole `Result`: `Err(RecvError::Disconnected)` (all `Handle` clones dropped)
          // must exit the loop, not be silently ignored — otherwise the accept arm keeps winning the
          // biased select while the dead command channel is dropped on the floor, spinning forever.
          c = cmd_fut => { command = Some(c); }
          i = inbound_fut => { if let Ok(i) = i { inbound = Some(i); } }
          d = dial_fut => { if let Ok(d) = d { dial_ready = Some(d); } }
          _ = storage_fut => {}
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
      if let Some(cmd_result) = command {
        match cmd_result {
          Ok(cmd) => {
            if self.handle_command(now, cmd, &mut shutdown_ack) {
              break;
            }
          }
          // The command channel closed (last `Handle` dropped): terminate the run loop.
          Err(_) => break,
        }
      }

      if let Some((stream, _addr)) = accepted {
        // Admission control: at the live-connection cap, DROP the accepted socket (let `stream` fall
        // out of scope → the socket closes) without registering, so an accept flood cannot grow
        // `conns` + the coordinator router without bound. Below the cap, register + bridge it: the
        // Labeled handshake authenticates the real peer, so the registration `peer` is only a
        // placeholder hint (the router rebinds it on validation), and the `auth_deadline` reaps it if
        // it never validates.
        if self.conns.len() >= self.cfg.max_conns() {
          self.close_counts[CloseCause::AcceptCapacity.index()] += 1;
          drop(stream);
        } else {
          let conn = (self.acceptor)();
          let id = self
            .coord
            .register_accepted(Peer::Replica(ReplicaId::new(0)), conn);
          self.spawn_bridge_accepted(now, id, stream);
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
    // driver's life. A `Submit` still queued in the command channel drops with the channel (below),
    // its guard releasing too.
    drain_pending(&mut self.pending);
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
    shutdown_ack: &mut Option<oneshot::Sender<()>>,
  ) -> bool {
    match cmd {
      Command::Submit {
        body,
        reply,
        reservation,
      } => {
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
        } else if let Some(d) = conn.auth_deadline {
          if now >= d {
            expired.push(id);
          }
        }
      }
    }
    for id in expired {
      self.close_counts[CloseCause::AuthDeadline.index()] += 1;
      self.close_conn(id, now); // unvalidated past the deadline: close (+ redial if dialed)
    }
  }

  /// The number of connection closes attributed to `cause` so far — the coordinator's internal
  /// closes plus the driver's own (auth-deadline, out-queue overflow, accept-cap). Test/diagnostic
  /// observability, not a stable embedder API (hence `#[doc(hidden)]`).
  #[doc(hidden)]
  pub fn conn_close_count(&self, cause: CloseCause) -> u64 {
    self.close_counts[cause.index()]
  }

  /// Tear down a connection the proto/socket/queue has lost: one `remove` drops the [`Conn`], which
  /// cancels its live task(s) (the connect task OR both bridge halves) and drops its `out_tx`; then
  /// reap it in the coordinator (eof) and, if it was a DIALED conn, redial the peer/addr held in
  /// [`Conn::redial`].
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

  /// Nearest of the consensus deadline, the earliest per-conn auth deadline, and a 50ms idle
  /// fallback (so a quiet node still re-pumps storage and retransmits stale requests).
  ///
  /// The auth deadline is folded in as a REAL wake deadline — mirroring the QUIC bridge, which
  /// `min`s its `earliest_auth_deadline` into `poll_timeout` — so reaping a stalled handshake never
  /// depends on the idle fallback happening to wake the loop: a sleeping driver wakes AT the
  /// deadline and the iter-top [`Self::reconcile_auth_deadlines`] reaps on that pass.
  fn next_deadline(&self) -> std::time::Instant {
    let fallback = std::time::Instant::now() + Duration::from_millis(50);
    let consensus = self.coord.poll_timeout().map(|t| self.clock.to_std(t));
    let auth = self
      .conns
      .values()
      .filter_map(|c| c.auth_deadline)
      .min()
      .map(|d| self.clock.to_std(d));
    [consensus, auth]
      .into_iter()
      .flatten()
      .fold(fallback, std::time::Instant::min)
  }

  /// Reap cancelled submits (releasing their budget), then re-broadcast pending requests not committed
  /// within the request timeout (the proto session table dedups). The cancellation reclaim is the
  /// caller-cancellation release site: a submit whose reply future was dropped is removed + its budget
  /// freed within this tick, so a cancelled submit's memory can't be pinned until its commit arrives.
  /// Retransmission lets a request submitted before the mesh is up reach the primary once links come up.
  fn retransmit_stale(&mut self, now: Instant) {
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
  use std::rc::Rc;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::Duration;

  use bytes::Bytes;

  use super::CompioStreamDriver;
  use crate::DriverError;
  use crate::bridge::{BridgeOut, Conn as BridgeConn, ConnTask};
  use crate::session::REQUEST_TIMEOUT;
  use viewstamp_proto::{
    ClientId, Config, Conn, Endpoint, Instant, LabelOptions, Labeled, OpNumber, Passthrough, Peer,
    ReplicaId, StreamCoordinator, View,
  };
  use viewstamp_simulation::sm::LogSm;

  /// A type-erased in-flight `submit` future, lifetime-bound to the borrowed `Handle` it ran from.
  type SubmitFut<'a> = dyn std::future::Future<Output = Result<crate::Reply, DriverError>> + 'a;
  use viewstamp_simulation::{InMemorySuperblock, InMemoryWal};

  #[test]
  fn stream_driver_type_resolves() {
    fn _assert_handle_clone(h: &crate::Handle) {
      let _ = h.clone();
    }
  }

  /// Build a driver bound on an ephemeral loopback port with no configured peers, so no dials fire
  /// until the test drives `dial_peer` itself. `R = Labeled<Passthrough>` (the loopback transport).
  async fn test_driver()
  -> CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock> {
    test_driver_with_storage(InMemoryWal::new(), InMemorySuperblock::new()).await
  }

  /// Like [`test_driver`] but over caller-supplied storage, so the recover-or-new constructor-choice
  /// tests can hand it a dirty store.
  async fn test_driver_with_storage(
    wal: InMemoryWal,
    sb: InMemorySuperblock,
  ) -> CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock> {
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, ReplicaId::new(0), 3).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Rc::new(|peer| {
      let opts = LabelOptions::new(CLUSTER, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Rc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    let (driver, _handle) = CompioStreamDriver::new(
      config,
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
  async fn test_driver_with_config(
    cfg: crate::DriverConfig,
  ) -> CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock> {
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, ReplicaId::new(0), 3).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Rc::new(|peer| {
      let opts = LabelOptions::new(CLUSTER, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Rc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    let (driver, _handle) = CompioStreamDriver::with_config(
      config,
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

  /// Like [`test_driver`] but also returns the `Handle`, so a budget test can drive the REAL
  /// `Handle::submit` (which reserves the shared budget + `try_send`s the command) against the
  /// driver's REAL `handle_command`/`deliver_event`/`retransmit_stale`. No peers are configured, so
  /// nothing ever commits on its own — exactly the partitioned/slow case the submit budget must bound.
  async fn test_driver_with_handle() -> (
    CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock>,
    crate::Handle,
  ) {
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, ReplicaId::new(0), 3).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Rc::new(|peer| {
      let opts = LabelOptions::new(CLUSTER, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Rc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    CompioStreamDriver::new(
      config,
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
  async fn test_driver_small_cap(
    cap: usize,
  ) -> CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock> {
    let mut driver = test_driver().await;
    const CLUSTER: u128 = 0x7777;
    let config = Config::try_new(CLUSTER, ReplicaId::new(0), 3).unwrap();
    let endpoint = Endpoint::new(
      config,
      u64::from(config.replica().get()) + 1,
      LogSm::default(),
    );
    driver.coord = StreamCoordinator::with_outbound_cap(endpoint, cap);
    driver
  }

  /// Register a dialed `Labeled<Passthrough>` conn (its identity hello queued into the inner outbound)
  /// in the driver's coordinator AND insert the matching driver-owned [`BridgeConn`] under the same
  /// `ConnId`, returning `(id, out_rx, queued_bytes)`. `poll_conn_transmit` will return that conn's
  /// queued hello as a single wire chunk. The conn's tasks are trivial completed futures (the test
  /// asserts the queued bytes / channel directly, never driving a real bridge), so dropping them on a
  /// close cancels nothing live. The held `out_rx` observes what `pump_outputs` admitted.
  fn register_handshaking_conn(
    driver: &mut CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock>,
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
      read: compio::runtime::spawn(async {}),
      write: compio::runtime::spawn(async {}),
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

  /// `dial_peer` is the single source of a dialed [`Conn`]: it mints a `ConnId`, inserts ONE owned
  /// unit into `conns`, and records the redial target in `Conn.redial` (so there is no separate
  /// `dialed` map to drift). A `DialReady` is STALE exactly when its id is no longer in `conns` —
  /// what `handle_dial_ready` checks via `conns.get_mut` before replacing the connect task with the
  /// bridge — so a closed-and-replaced id is dropped rather than spawned or redialed.
  #[compio::test]
  async fn dialed_conn_is_one_unit_with_a_redial_target() {
    let mut driver = test_driver().await;
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

    driver.dial_peer(
      ReplicaId::new(1),
      addr,
      Duration::ZERO,
      crate::config::REDIAL_BACKOFF_BASE,
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
      Some((ReplicaId::new(1), addr, crate::config::REDIAL_BACKOFF_BASE)),
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
  /// pinned in `clock.rs`). The test drives the REAL loss path (`close_conn`) repeatedly and asserts
  /// the carried backoff doubles to [`crate::config::REDIAL_BACKOFF_CAP`] then holds — deterministic: no
  /// clock is consulted, the carried backoff IS the next schedule step.
  ///
  /// NEUTER CHECK: reverting `close_conn` to a fixed-delay redial leaves every carried backoff at
  /// the base, failing the first doubling assert; dropping the `.min(cap)` overshoots the final one.
  #[compio::test]
  async fn consecutive_redials_back_off_exponentially_to_the_cap() {
    let mut driver = test_driver().await;
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    driver.dial_peer(
      ReplicaId::new(1),
      addr,
      Duration::ZERO,
      crate::config::REDIAL_BACKOFF_BASE,
    );

    let mut expected = crate::config::REDIAL_BACKOFF_BASE;
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
      expected = (expected * 2).min(crate::config::REDIAL_BACKOFF_CAP);
    }
    assert_eq!(
      expected,
      crate::config::REDIAL_BACKOFF_CAP,
      "the chain reached the cap"
    );
  }

  /// Validation RESETS the redial backoff to the base: a real `Labeled` handshake is driven into the
  /// driver's dialed conn (a stand-alone coordinator plays the remote replica), the conn's carried
  /// backoff is inflated to the cap (as a long dead period would leave it), and the
  /// `reconcile_auth_deadlines` pass that observes validation must clear the auth deadline AND reset
  /// the backoff — so the NEXT loss redials at the base cadence, not at the dead period's.
  #[compio::test]
  async fn validation_resets_the_redial_backoff_to_base() {
    const CLUSTER: u128 = 0x7777;
    // The dialer must announce SELF (replica 0) for the peer to validate it — the loopback wiring;
    // `test_driver`'s factory announces the dialed target instead, fine only where nothing validates.
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Rc::new(|_peer| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Rc::new(|| {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    let (mut driver, _handle) = CompioStreamDriver::new(
      Config::try_new(CLUSTER, ReplicaId::new(0), 3).unwrap(),
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
      crate::config::REDIAL_BACKOFF_BASE,
    );
    let id = *driver.conns.keys().next().expect("one dialed conn");

    // The remote replica (id 1): a stand-alone coordinator that accepts our conn and answers the
    // `Labeled` handshake.
    let peer_config = Config::try_new(CLUSTER, ReplicaId::new(1), 3).unwrap();
    let mut peer = StreamCoordinator::new(Endpoint::new(peer_config, 2, LogSm::default()));
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
      conn.redial.as_mut().expect("a dialed conn").backoff = crate::config::REDIAL_BACKOFF_CAP;
      conn.auth_deadline = Some(now + crate::config::AUTH_DEADLINE);
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
      crate::config::REDIAL_BACKOFF_BASE,
      "validation resets the redial backoff, so the next loss starts the schedule over at the base"
    );
  }

  /// AMNESIA GUARD (stream driver): a store carrying ANY durable state NEVER boots a fresh view-0
  /// endpoint — the constructor inspects the store and reconstructs via `Endpoint::recover`. A
  /// durable root at view 5 must resume view 5 (a fresh boot would be view 0); a durable WAL op
  /// must restore the head and enter `Recovering` (the tail re-verifies through the normal storage
  /// pump). Reverting the constructor to an unconditional `Endpoint::new` fails both halves.
  #[compio::test]
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
  #[compio::test]
  async fn a_genesis_store_boots_a_fresh_normal_endpoint_stream() {
    let driver = test_driver().await;
    assert!(driver.coord.endpoint().status().is_normal());
    assert_eq!(driver.coord.endpoint().view().get(), 0);
    assert_eq!(driver.coord.endpoint().op().get(), 0);
  }

  /// Handle-drop termination must hold even with an in-flight connect task: a configured but
  /// UNREACHABLE peer leaves a dialing `Conn` whose connect task is parked in `TcpStream::connect`
  /// when the last `Handle` drops. Because the `Conn` OWNS that task's `JoinHandle` (it is not
  /// detached), the final `self.conns.clear()` cancels it, so `run()` returns promptly instead of
  /// waiting out the dial timeout. A regression to a detached connect task fails the 5s bound.
  #[compio::test]
  async fn run_exits_with_an_in_flight_dial_to_an_unreachable_peer() {
    let config = Config::try_new(0x7777, ReplicaId::new(0), 3).unwrap();
    let dialer: super::DialerFactory<Labeled<Passthrough>> = Rc::new(|peer| {
      let opts = LabelOptions::new(0x7777, peer);
      Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
    });
    let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Rc::new(|| {
      let opts = LabelOptions::new(0x7777, Peer::Replica(ReplicaId::new(0)));
      Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
    });
    let (_ready_tx, ready_rx) = flume::unbounded();
    // 203.0.113.0/24 (TEST-NET-3) is reserved + unrouteable, so the connect never completes within
    // the test window — the connect task is genuinely in flight when the Handle drops.
    let unreachable: std::net::SocketAddr = "203.0.113.1:9".parse().unwrap();
    let (driver, handle) = CompioStreamDriver::new(
      config,
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
    let task = compio::runtime::spawn(driver.run());

    drop(handle); // last Handle gone -> command channel disconnects

    let _ = compio::time::timeout(Duration::from_secs(5), task)
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
  #[compio::test]
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
  #[compio::test]
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
  #[compio::test]
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
  #[compio::test]
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
  #[compio::test]
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
  #[compio::test]
  async fn a_custom_auth_deadline_changes_the_reap_timing() {
    let custom = Duration::from_millis(500);
    assert!(
      custom < crate::config::AUTH_DEADLINE,
      "the override must be far below the default for the timing contrast to mean anything"
    );
    let mut driver =
      test_driver_with_config(crate::DriverConfig::new().with_auth_deadline(custom)).await;

    // A real accepted loopback socket through the production registration + bridge spawn.
    let listener = compio::net::TcpListener::bind("127.0.0.1:0")
      .await
      .expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let (dialed, accepted) =
      futures_util::future::join(compio::net::TcpStream::connect(addr), listener.accept()).await;
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
  #[compio::test]
  async fn tune_peer_socket_sets_nodelay_and_keepalive() {
    let listener = compio::net::TcpListener::bind("127.0.0.1:0")
      .await
      .expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let (dialed, accepted) =
      futures_util::future::join(compio::net::TcpStream::connect(addr), listener.accept()).await;
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
  fn drain_one_command(
    driver: &mut CompioStreamDriver<LogSm, Labeled<Passthrough>, InMemoryWal, InMemorySuperblock>,
  ) {
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
  #[compio::test]
  async fn submit_budget_bounds_pending_and_releases_on_commit_stream() {
    use crate::session::{MAX_INFLIGHT, MAX_PENDING_BYTES};
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
    let (events_tx, _events_rx) = flume::bounded(crate::session::EVENTS_CAP);
    for (client, request) in keys {
      let event = viewstamp_proto::Event::Committed(viewstamp_proto::Committed::new(
        viewstamp_proto::OpNumber::with(request.get()),
        client,
        request,
        Bytes::from_static(b"R"),
      ));
      crate::session::deliver_event(&mut driver.pending, &events_tx, event);
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
  #[compio::test]
  async fn over_frame_submit_is_rejected_without_side_effects_stream() {
    let (driver, handle) = test_driver_with_handle().await;

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
  #[compio::test]
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
  #[compio::test]
  async fn cancelled_submit_is_reclaimed_within_a_retransmit_tick_stream() {
    use crate::session::MAX_INFLIGHT;
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

  /// SHUTDOWN RACE — NO BUDGET LEAK (stream driver): submits that reserved the budget and were
  /// enqueued but NOT yet drained into `pending` when the driver tears down must not leak their
  /// reservation. Each `Handle::submit` carries its `ReservationGuard` inside the queued
  /// `Command::Submit`; tearing the driver (and its command channel) down drops those still-queued
  /// commands, and each guard's `Drop` releases its slot. An independent budget clone (the survivor a
  /// cloned `Handle` would share) returns to zero — count AND bytes — so a surviving `Handle` never
  /// sees spurious `Busy` from a reservation stranded across teardown.
  #[compio::test]
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

    // Tear the driver down WITHOUT draining the commands: dropping the driver drops the command-channel
    // receiver; dropping the submit futures releases their borrow of `handle` (and their reply
    // receivers); dropping `handle` (the last sender) then frees the buffered `Command::Submit`s — each
    // drops its guard, releasing. This is the queued-submit-vs-shutdown race: the guards are the single
    // release owner, so no reservation is stranded.
    drop(driver);
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
}

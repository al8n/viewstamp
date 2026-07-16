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
  BlockAddress, BlockStore, ClientId, Config, Conn, Endpoint, Instant, LabelOptions, Labeled,
  MemberId, Membership, OpNumber, Passthrough, Peer, ReplicaId, SingleChange, StreamCoordinator,
  View,
};
use viewstamp_simulation::sm::LogSm;

/// A throwaway in-memory [`BlockStore`] for the driver tests: the proto's own `MemBlockStore` is
/// crate-private, so each driver/coordinator instance owns one of these for its state-machine
/// checkpoint blocks (one per instance, persisting for that instance's lifetime, parallel to its
/// superblock).
#[derive(Default)]
struct MemBlocks(std::collections::HashMap<BlockAddress, Bytes>);

impl BlockStore for MemBlocks {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.0.get(&addr).cloned()
  }
  fn write_block(&mut self, addr: BlockAddress, block: Bytes) {
    self.0.insert(addr, block);
  }
  fn has_block(&self, addr: BlockAddress) -> bool {
    self.0.contains_key(&addr)
  }
}

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
type TestStreamDriver = ReactorStreamDriver<
  TestRt,
  LogSm,
  Labeled<Passthrough>,
  InMemoryWal,
  InMemorySuperblock,
  MemBlocks,
>;

#[test]
fn stream_driver_type_resolves() {
  fn _assert_handle_clone(h: &crate::Handle) {
    let _ = h.clone();
  }
}

/// Build a driver bound on an ephemeral loopback port with no configured peers, so no dials fire
/// until the test drives `dial_peer` itself. `T = Labeled<Passthrough>` (the loopback transport).
async fn test_driver() -> TestStreamDriver {
  // A test driver models a genuine new cluster: FORMAT the store once (the pinned genesis root) so
  // recovery resumes the designated view-0 primary as Normal (an unformatted store would abdicate —
  // the wipe-amnesia safeguard). `test_driver_with_storage` (dirty-store) is not formatted.
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  let config = Config::try_new(0x7777, MemberId::new(0_u128)).unwrap();
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  test_driver_with_storage(wal, sb).await
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
    let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(0)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  });
  let (_ready_tx, ready_rx) = flume::unbounded();
  let blocks = MemBlocks::default();
  let (driver, _handle) = ReactorStreamDriver::new(
    config,
    genesis(3),
    LogSm::default(),
    wal,
    sb,
    blocks,
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
    let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(0)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  });
  let (_ready_tx, ready_rx) = flume::unbounded();
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  // A genesis fixture: FORMAT the store so recovery resumes rather than fail-stopping this voter.
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let (driver, _handle) = ReactorStreamDriver::with_config(
    config,
    genesis(3),
    LogSm::default(),
    wal,
    sb,
    MemBlocks::default(),
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
      let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(0)));
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
    let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
    let wal = InMemoryWal::new();
    let mut sb = InMemorySuperblock::new();
    // A genesis fixture: FORMAT the store so recovery resumes rather than fail-stopping this voter.
    viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
    TestStreamDriver::with_config(
      config,
      genesis(3),
      LogSm::default(),
      wal,
      sb,
      MemBlocks::default(),
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
    let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(0)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  });
  let (_ready_tx, ready_rx) = flume::unbounded();
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  // A genesis fixture: FORMAT the store so recovery resumes rather than fail-stopping this voter.
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  ReactorStreamDriver::new(
    config,
    genesis(3),
    LogSm::default(),
    wal,
    sb,
    MemBlocks::default(),
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
  // Genesis: commit over a throwaway store to obtain a runnable endpoint; the driver pumps it against
  // its own (already-formatted) storage, and this coordinator never recovers.
  let (gwal, mut gsb) = (InMemoryWal::new(), InMemorySuperblock::new());
  let endpoint =
    Endpoint::<_, SingleChange>::with_reconfig(config, genesis(3), 1, LogSm::default(), u64::MAX)
      .commit(&gwal, &mut gsb)
      .expect("genesis commit formats the throwaway store");
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
  let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(peer.get() as u128)));
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
  // Seed `peer_addrs` so the `close_conn` gate sees slot 1 as live (the backoff schedule must
  // not be suppressed by the membership gate — we're testing a RETAINED, active peer).
  driver.peer_addrs.insert(ReplicaId::new(1), addr);
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
    let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(0)));
    Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
  });
  let acceptor: super::AcceptorFactory<Labeled<Passthrough>> = Arc::new(|| {
    let opts = LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(0)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  });
  let (_ready_tx, ready_rx) = flume::unbounded();
  let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  // A genesis fixture: FORMAT the store so recovery resumes rather than fail-stopping this voter.
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let (mut driver, _handle) = ReactorStreamDriver::<TestRt, _, _, _, _, _>::new(
    config,
    genesis(3),
    LogSm::default(),
    wal,
    sb,
    MemBlocks::default(),
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
  let (mut pwal, mut psb) = (InMemoryWal::new(), InMemorySuperblock::new());
  let mut pblocks = MemBlocks::default();
  // Genesis: commit over the peer's own store (which it then pumps), so it is formatted exactly as a
  // real peer's store would be.
  let peer_endpoint = Endpoint::<_, SingleChange>::with_reconfig(
    peer_config,
    genesis(3),
    2,
    LogSm::default(),
    u64::MAX,
  )
  .commit(&pwal, &mut psb)
  .expect("genesis commit formats the peer store");
  let mut peer = StreamCoordinator::new(peer_endpoint);
  let peer_conn = Conn::from_parts(Labeled::acceptor(
    Passthrough::new(),
    &LabelOptions::new(CLUSTER, Peer::Member(MemberId::new(1))),
  ));
  let pid = peer.register_accepted(Peer::Replica(ReplicaId::new(0)), peer_conn);

  // Shuttle the handshake bytes both ways until the driver's conn validates.
  let now = Instant::ZERO;
  for _ in 0..8 {
    if driver.coord.is_conn_validated(id) {
      break;
    }
    while let Some((cid, bytes)) = driver.coord.poll_conn_transmit() {
      if cid == id {
        peer.handle_conn_data(pid, &bytes, false, now, &mut pwal, &mut psb, &mut pblocks);
      }
    }
    while let Some((cid, bytes)) = peer.poll_conn_transmit() {
      if cid == pid {
        driver.coord.handle_conn_data(
          id,
          &bytes,
          false,
          now,
          &mut driver.wal,
          &mut driver.sb,
          &mut driver.blocks,
        );
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
    .expect("a valid durable root")
    .with_wal_geometry(viewstamp_proto::DEFAULT_CHECKPOINT_OPS, u64::MAX),
  );
  // The storage contract: no in-flight completions cross an endpoint incarnation.
  while viewstamp_proto::Superblock::poll(&mut sb).is_some() {}
  let driver = test_driver_with_storage(InMemoryWal::new(), sb).await;
  assert_eq!(
    driver.coord.endpoint().view().get(),
    5,
    "the durable view is resumed, never reset to a fresh view 0"
  );

  // Durable WAL op, FORMATTED genesis root: the endpoint enters Recovering with its durable head
  // restored (the read completions resolve through the run loop's ordinary handle_storage pump). The
  // store is FORMATTED — a real store that ran wrote its genesis root before appending — so this is a
  // recoverable dirty store, distinct from a VIRGIN (wiped/unformatted) store carrying a durable op,
  // which is a wiped voter that fail-stops instead (covered by the proto recovery tests).
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
  let mut sb = InMemorySuperblock::new();
  viewstamp_driver::format(
    Config::try_new(0x7777, MemberId::new(0_u128)).unwrap(),
    &genesis(3),
    &wal,
    &mut sb,
  )
  .expect("format the genesis store");
  let driver = test_driver_with_storage(wal, sb).await;
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

/// First-boot path (stream driver): a genuine new cluster's store is FORMATTED once (the pinned
/// genesis root), then recovered — the format witness lets recovery resume the designated view-0
/// primary as Normal, synchronously (empty WAL, nothing to read). An unformatted store would
/// abdicate instead (the wipe-amnesia safeguard).
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
    let opts = LabelOptions::new(0x7777, Peer::Member(MemberId::new(0)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  });
  let (_ready_tx, ready_rx) = flume::unbounded();
  // 203.0.113.0/24 (TEST-NET-3) is reserved + unrouteable, so the connect never completes within
  // the test window — the dial task is genuinely in flight when the Handle drops.
  let unreachable: std::net::SocketAddr = "203.0.113.1:9".parse().unwrap();
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  // A genesis fixture: FORMAT the store so recovery resumes rather than fail-stopping this voter.
  viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  let (driver, handle) = ReactorStreamDriver::<TestRt, _, _, _, _, _>::new(
    config,
    genesis(3),
    LogSm::default(),
    wal,
    sb,
    MemBlocks::default(),
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
  let (at_cap, at_cap_rx, at_cap_bytes) = register_handshaking_conn(&mut driver, ReplicaId::new(1));
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

/// REMOVED-MEMBER REDIAL SUPPRESSION: when a member is removed from the membership and the
/// coordinator closes its stale dialed conn, `close_conn` must NOT redial it. The mechanism is
/// the `peer_addrs` gate in `close_conn`: after `rekey_peers` rebuilds the dial table without the
/// removed slot, the slot is absent from `peer_addrs`, so the gate suppresses the redial.
///
/// Regression: the unconditional redial path let a removed member's conn be re-opened after
/// the coordinator closed it, defeating `reconcile_routing`.
#[tokio::test]
async fn removed_member_is_not_redialed_after_coordinator_close() {
  let mut driver = test_driver().await;
  let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

  // Simulate the state right after a config install that removed slot 1: `peer_addrs` no
  // longer contains the slot (as `rekey_peers` would leave it), but there is a live dialed
  // conn for slot 1 with a `Redial` entry (as there would be from an earlier dial).
  driver.dial_peer(
    ReplicaId::new(1),
    addr,
    Duration::ZERO,
    viewstamp_driver::REDIAL_BACKOFF_BASE,
  );
  let id = *driver.conns.keys().next().expect("one dialed conn");

  // Remove the slot from `peer_addrs` as `rekey_peers` would after a membership change that
  // dropped slot 1.
  driver.peer_addrs.remove(&ReplicaId::new(1));

  // The coordinator closes the stale conn (the reconcile path).
  driver.close_conn(id, viewstamp_proto::Instant::ZERO);

  // The conn was torn down.
  assert!(
    !driver.conns.contains_key(&id),
    "the closed conn is removed from conns"
  );
  // No redial was issued: `peer_addrs` was empty for that slot, so `close_conn` suppressed it.
  assert!(
    driver.conns.is_empty(),
    "no new dialed conn was created — the removed member is not redialed"
  );
}

/// SHIFTED-MEMBER REDIAL SUPPRESSION: when a member's address changes (slot shift / re-key),
/// `close_conn` on the OLD-address conn must NOT redial the old address. The `peer_addrs` gate
/// sees the slot mapped to the NEW address, which does not match the stored `Redial::addr`, so
/// the redial is suppressed. The new-slot dial was already issued by `rekey_peers`.
#[tokio::test]
async fn shifted_member_old_address_is_not_redialed_after_coordinator_close() {
  let mut driver = test_driver().await;
  let old_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
  let new_addr: std::net::SocketAddr = "127.0.0.2:9".parse().unwrap();

  // A dialed conn to slot 1 at the OLD address.
  driver.dial_peer(
    ReplicaId::new(1),
    old_addr,
    Duration::ZERO,
    viewstamp_driver::REDIAL_BACKOFF_BASE,
  );
  let old_id = *driver.conns.keys().next().expect("one dialed conn");

  // `rekey_peers` ran and already issued a dial to slot 1 at the NEW address.
  driver.dial_peer(
    ReplicaId::new(1),
    new_addr,
    Duration::ZERO,
    viewstamp_driver::REDIAL_BACKOFF_BASE,
  );
  // `peer_addrs` now records the NEW address for the slot (as `rekey_peers` would leave it).
  driver.peer_addrs.insert(ReplicaId::new(1), new_addr);

  assert_eq!(driver.conns.len(), 2, "two dialed conns: old and new slot");

  // The coordinator closes the old-address conn.
  driver.close_conn(old_id, viewstamp_proto::Instant::ZERO);

  // The old conn was torn down and no THIRD conn was added (the old address was not redialed).
  assert!(
    !driver.conns.contains_key(&old_id),
    "the old-address conn is removed"
  );
  assert_eq!(
    driver.conns.len(),
    1,
    "exactly one conn remains (the new-address dial); the old address was NOT redialed"
  );
  // The surviving conn is the new-address one.
  let surviving_redial = driver
    .conns
    .values()
    .next()
    .and_then(|c| c.redial)
    .expect("the surviving conn has a redial entry");
  assert_eq!(
    surviving_redial.addr, new_addr,
    "the surviving dial targets the new address"
  );
}

/// LIVE RETIREMENT (stream driver): when this endpoint removes itself from the configuration the run
/// loop's `retire` step fails every in-flight submit with the terminal `Retired` error (never a hang
/// or `ReplyDropped`), releases their budget, and rejects a later submit immediately — the same
/// terminal state a restart over the removed membership reaches. Composes the REAL `Handle::submit`,
/// the REAL `handle_command` (insert pending), the driver's shared retirement signal, and the shared
/// `retire`, reading the retirement identity off the endpoint exactly as the run-loop pump does.
#[tokio::test]
async fn self_retirement_fails_in_flight_and_rejects_new_submits_stream() {
  let (mut driver, handle) = test_driver_with_handle().await;

  // One in-flight submit (no peers, so no quorum ever forms and it parks): reserve + enqueue, then
  // drain into `pending` exactly as the run loop would.
  let fut = handle.submit(Bytes::from_static(b"x"));
  futures_util::pin_mut!(fut);
  assert!(
    poll_submit(fut.as_mut()).is_none(),
    "the submit parks on its reply"
  );
  drain_one_command(&mut driver);
  assert_eq!(
    driver.budget.count(),
    1,
    "the in-flight submit holds its reservation"
  );

  // The run loop's live->retired handler: read the endpoint identity and fail every in-flight submit.
  let (local, epoch) = {
    let endpoint = driver.coord.endpoint();
    (endpoint.local(), endpoint.membership_clone().epoch())
  };
  viewstamp_driver::retire(&mut driver.pending, &driver.retired, local, epoch);
  assert!(
    driver.pending.is_empty(),
    "retire drained the in-flight entry"
  );
  assert_eq!(driver.budget.count(), 0, "and released its budget slot");

  // The parked submit resolves to the terminal Retired (its latched identity), not ReplyDropped/hang.
  match poll_submit(fut.as_mut()) {
    Some(Err(DriverError::Retired { local: l, epoch: e })) => {
      assert_eq!(l, local);
      assert_eq!(e, epoch);
    }
    other => panic!("expected Ready(Err(Retired)) after retirement, got {other:?}"),
  }

  // A submit issued AFTER retirement is rejected immediately, reserving no budget and enqueueing nothing.
  let after = handle.submit(Bytes::from_static(b"y"));
  futures_util::pin_mut!(after);
  match poll_submit(after.as_mut()) {
    Some(Err(DriverError::Retired { .. })) => {}
    other => panic!("expected immediate Retired for a post-retirement submit, got {other:?}"),
  }
  assert_eq!(
    driver.budget.count(),
    0,
    "a post-retirement submit reserves no budget"
  );
  assert!(
    driver.commands.try_recv().is_err(),
    "a post-retirement submit enqueues no command"
  );
}

/// QUEUED SUBMIT ACROSS RETIREMENT (stream driver): a submit left BUFFERED in the command channel when
/// the endpoint retires — enqueued before the latch, drained after — is caught at CONSUMPTION by
/// `handle_command`'s retirement gate: it never enters `pending` nor reaches the endpoint, its budget
/// releases, and its caller resolves to the terminal `Retired` rather than hanging. This is the
/// one-hop-downstream hang the up-front `Handle` rejection alone leaves open.
#[tokio::test]
async fn a_queued_submit_across_retirement_resolves_to_retired_stream() {
  let (mut driver, handle) = test_driver_with_handle().await;

  // Enqueue a submit but LEAVE it queued (do NOT drain the pump): the reservation is held while the
  // command sits in the channel.
  let fut = handle.submit(Bytes::from_static(b"x"));
  futures_util::pin_mut!(fut);
  assert!(
    poll_submit(fut.as_mut()).is_none(),
    "the submit parks on its reply"
  );
  assert_eq!(
    driver.budget.count(),
    1,
    "the queued submit holds its reservation"
  );

  // The endpoint retires while the submit is still buffered: latch the signal exactly as the run
  // loop's StatusChanged(Retired) handler does (pending is empty, so retire only latches).
  let (local, epoch) = {
    let endpoint = driver.coord.endpoint();
    (endpoint.local(), endpoint.membership_clone().epoch())
  };
  viewstamp_driver::retire(&mut driver.pending, &driver.retired, local, epoch);

  // NOW let the pump process the queued command: the consumption-time gate drops it instead of
  // handing it to the retired endpoint.
  drain_one_command(&mut driver);
  assert!(
    driver.pending.is_empty(),
    "the gated submit never enters pending"
  );
  assert_eq!(
    driver.budget.count(),
    0,
    "and its reservation is released (no leak)"
  );

  // The waiter resolves to the terminal Retired — not a hang, not a generic ReplyDropped.
  match poll_submit(fut.as_mut()) {
    Some(Err(DriverError::Retired { local: l, epoch: e })) => {
      assert_eq!(l, local);
      assert_eq!(e, epoch);
    }
    other => {
      panic!("expected Ready(Err(Retired)) for a submit gated at consumption, got {other:?}")
    }
  }
}

/// QUEUED RECONFIGURE ACROSS RETIREMENT (stream driver): a reconfigure goal left BUFFERED in the
/// command channel when the endpoint retires is answered at CONSUMPTION with the terminal
/// `ReconfigureError::Retired` — mirroring the `Handle`'s up-front rejection — instead of starting a
/// reconfiguration job on an endpoint that can never drive it.
#[tokio::test]
async fn a_queued_reconfigure_across_retirement_resolves_to_retired_stream() {
  let (mut driver, handle) = test_driver_with_handle().await;

  // Enqueue a reconfigure goal but LEAVE it queued (the Handle's up-front retired check passes: the
  // signal is not latched yet).
  let target = viewstamp_proto::MembershipTarget::new(
    std::collections::BTreeSet::from([viewstamp_proto::MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  let fut = handle.reconfigure_to(target, viewstamp_driver::HealthHint::default());
  futures_util::pin_mut!(fut);
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  assert!(
    std::future::Future::poll(fut.as_mut(), &mut cx).is_pending(),
    "the reconfigure enqueues its command and parks on the reply"
  );

  // The endpoint retires while the goal is still buffered.
  let (local, epoch) = {
    let endpoint = driver.coord.endpoint();
    (endpoint.local(), endpoint.membership_clone().epoch())
  };
  viewstamp_driver::retire(&mut driver.pending, &driver.retired, local, epoch);

  // NOW let the pump process the queued command: the gate answers it terminally rather than starting
  // a job on the retired endpoint.
  drain_one_command(&mut driver);
  assert!(
    driver.reconfigure.is_none(),
    "the gated reconfigure starts no job on the retired endpoint"
  );

  match std::future::Future::poll(fut.as_mut(), &mut cx) {
    std::task::Poll::Ready(Err(viewstamp_driver::ReconfigureError::Retired {
      local: l,
      epoch: e,
    })) => {
      assert_eq!(l, local);
      assert_eq!(e, epoch);
    }
    other => {
      panic!("expected Ready(Err(Retired)) for a reconfigure gated at consumption, got {other:?}")
    }
  }
}

/// ACTIVE RECONFIGURE ACROSS RETIREMENT (stream driver): a reconfiguration job already STARTED — with an
/// outstanding proposal, its target not yet reached — when a concurrent removal retires the endpoint is
/// FINISHED terminally with `ReconfigureError::Retired` and its slot cleared. The run loop's
/// StatusChanged(Retired) handler calls `finish_reconfigure_on_retire` right after `retire`; without it
/// the job sits parked until `reconfigure_timeout`, surfacing a misleading (resumable) Timeout.
#[tokio::test]
async fn an_active_reconfigure_across_retirement_resolves_to_retired_stream() {
  let (mut driver, handle) = test_driver_with_handle().await;

  // Start a job whose target is NOT yet reached (grow the {0,1,2} genesis to add member 3), then advance
  // it once so it posts its first proposal — the "outstanding proposal" state. The no-quorum driver
  // never installs the step, so the job stays in flight.
  let target = viewstamp_proto::MembershipTarget::new(
    std::collections::BTreeSet::from([0u128, 1, 2, 3].map(viewstamp_proto::MemberId::new)),
    std::collections::BTreeSet::new(),
  );
  let fut = handle.reconfigure_to(target, viewstamp_driver::HealthHint::default());
  futures_util::pin_mut!(fut);
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  assert!(
    std::future::Future::poll(fut.as_mut(), &mut cx).is_pending(),
    "the reconfigure enqueues its command and parks on the reply"
  );
  drain_one_command(&mut driver); // starts the job: the endpoint is not retired yet
  driver.advance_reconfigure(viewstamp_proto::Instant::ZERO); // posts the outstanding proposal
  assert!(
    driver.reconfigure.is_some(),
    "the job is in flight with an outstanding proposal"
  );

  // The endpoint retires (a concurrent removal). Run the StatusChanged(Retired) handler's steps: latch
  // the signal, then FINISH the in-flight job terminally off the same membership clone.
  let (local, live) = {
    let endpoint = driver.coord.endpoint();
    (endpoint.local(), endpoint.membership_clone())
  };
  let epoch = live.epoch();
  viewstamp_driver::retire(&mut driver.pending, &driver.retired, local, epoch);
  viewstamp_driver::finish_reconfigure_on_retire(&mut driver.reconfigure, live, local, epoch);

  assert!(
    driver.reconfigure.is_none(),
    "the retirement handler clears the in-flight job slot"
  );
  match std::future::Future::poll(fut.as_mut(), &mut cx) {
    std::task::Poll::Ready(Err(viewstamp_driver::ReconfigureError::Retired {
      local: l,
      epoch: e,
    })) => {
      assert_eq!(l, local);
      assert_eq!(e, epoch);
    }
    other => panic!(
      "expected Ready(Err(Retired)) for an in-flight reconfigure across retirement, got {other:?}"
    ),
  }
}

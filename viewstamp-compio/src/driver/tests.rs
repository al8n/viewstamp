use bytes::Bytes;
use rustls::{
  RootCertStore,
  pki_types::{CertificateDer, PrivateKeyDer},
};
use viewstamp_proto::{
  BlockAddress, BlockStore, ClusterTls, Config, IdentityConfig, MemberId, Membership, QuicOptions,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal, sm::LogSm};

use super::CompioQuicDriver;

/// A throwaway in-memory [`BlockStore`] for the driver tests: the proto's own `MemBlockStore` is
/// crate-private, so each driver instance owns one of these for its state-machine checkpoint
/// blocks (one per driver, persisting for that driver's lifetime, parallel to its superblock).
#[derive(Default)]
struct MemBlocks(std::collections::HashMap<BlockAddress, Bytes>);

impl BlockStore for MemBlocks {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.0.get(&addr).cloned()
  }
  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = viewstamp_proto::block_address(&block);
    self.0.insert(addr, block);
    addr
  }
  fn flush(&mut self) -> Result<(), viewstamp_proto::BlockStoreError> {
    Ok(())
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
use viewstamp_driver::{
  BlockLane, DriverError, MAX_INFLIGHT, MAX_PENDING_BYTES, REQUEST_TIMEOUT, SHUTDOWN_DRAIN_DEADLINE,
};

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
  // A genesis fixture: the empty store is FORMATTED on the shared `with_config` path (below), so
  // recovery resumes the designated view-0 primary as Normal rather than fail-stopping this voter.
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
  mut sb: InMemorySuperblock,
  cfg: crate::DriverConfig,
) -> (TestQuicDriver, crate::Handle) {
  let (roots, chain, key) = cluster_ca();
  let opts: QuicOptions = ClusterTls::new(roots, chain, key).build();
  let config = Config::try_new(CLUSTER, MemberId::new(0_u128)).unwrap();
  // A GENESIS fixture (empty store) is FORMATTED so recovery resumes rather than fail-stopping this
  // voter; a DIRTY-store fixture (a caller-populated store) is left as-is to exercise recovery. This
  // is the single format point on the fixture path — `with_storage`/`with_handle` route through here.
  if viewstamp_proto::Superblock::state(&sb) == viewstamp_proto::VsrState::new() {
    viewstamp_driver::format(config, &genesis(3), &wal, &mut sb).expect("format the genesis store");
  }
  let (_ready_tx, ready_rx) = flume::unbounded();
  CompioQuicDriver::with_config(
    config,
    genesis(3),
    LogSm::default(),
    wal,
    sb,
    BlockLane::inline(MemBlocks::default()),
    viewstamp_proto::ClientId::new(1),
    0,
    opts,
    IdentityConfig::Hello(CLUSTER),
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
    viewstamp_proto::WriteId::new(1, 1),
    viewstamp_proto::VsrState::try_new(
      viewstamp_proto::View::with(5),
      viewstamp_proto::View::with(5),
      viewstamp_proto::OpNumber::new(),
      viewstamp_proto::OpNumber::new(),
      0,
      Vec::new(),
    )
    .expect("a valid durable root")
    .with_wal_geometry(viewstamp_proto::DEFAULT_CHECKPOINT_OPS, u64::MAX),
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
    viewstamp_proto::WriteId::new(1, 1),
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

/// First-boot path (QUIC driver): a genesis store — fresh-cluster root AND empty WAL — boots the
/// SAME unconditional-recovery path as every other store (no emptiness fork to mis-read a rot-able
/// scalar): a zero-length recovery, gated only on the genesis root write that pins the WAL
/// geometry, settling `Normal`/view-0 on the run loop's ordinary storage pump with no peer
/// dependency.
#[compio::test]
async fn a_genesis_store_boots_a_fresh_normal_endpoint_quic() {
  // A genuine new cluster's store is prepared ONCE via `format` (writing the pinned genesis root),
  // then the driver recovers it: the format witness lets recovery resume the designated view-0
  // primary as Normal, synchronously (empty WAL, nothing to read). Without format the store would be
  // unformatted and this would-be primary would abdicate instead — the wipe-amnesia safeguard.
  let (driver, _handle) = test_quic_driver_with_handle().await;
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
  let now = viewstamp_proto::Instant::ZERO + REQUEST_TIMEOUT + std::time::Duration::from_millis(1);
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

  let now = viewstamp_proto::Instant::ZERO + REQUEST_TIMEOUT + std::time::Duration::from_millis(1);
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

  // Baseline: nothing pending, no peers, a never-driven endpoint, so the scan deadline must not be
  // folded. Checked structurally rather than against a wall-clock reading: `next_pending_scan` is
  // still its zero-initialized sentinel (nothing has ever scanned), so an unconditionally-folded
  // result would equal exactly `driver.clock.to_std` of it. Every deadline `next_deadline` can
  // LEGITIMATELY return — the idle fallback, or a real armed timer such as the primary's own
  // commit heartbeat — is a `now` reading (real or `clock`-relative) plus a positive offset, and
  // `now` is never earlier than the clock's own epoch, so it is always strictly later than the
  // sentinel. This holds regardless of how long construction or scheduling took, unlike comparing
  // against a freshly re-read `Instant::now() + N`.
  let unfolded_scan = driver.clock.to_std(driver.next_pending_scan);
  assert!(
    driver.next_deadline() > unfolded_scan,
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

/// INBOUND-ADVANCE REKEY ORDERING (QUIC): a datagram that advances the membership must refresh the
/// dial-map IMMEDIATELY — inside `handle_inbound_datagram`, before the next `reconcile_peer_links`
/// dial pass — so the dial pass reads the fresh projection. Without the rekey in the inbound
/// helper, `self.peers` would still hold the removed slot's `PeerLink` and `reconcile_peer_links`
/// would dial it, re-opening a member the install dropped.
///
/// The install is modeled by an advanced config_id (the feed makes the reconciler observe a new
/// config) plus a `peer_book` the live projection no longer supports for the slot (an empty book,
/// as a removed member leaves), so `rekey_peers` rebuilds `self.peers` WITHOUT the slot.
#[compio::test]
async fn inbound_datagram_rekeys_so_the_dial_pass_drops_a_removed_slot() {
  let (mut driver, _handle) = test_quic_driver_with_handle().await;
  let stale_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

  // A stale dial-map entry for slot 1 (a `PeerLink` as an earlier config left it). `peer_book` is
  // empty, so the live membership projection has no address for the slot — a rekey will drop it,
  // exactly as a removal would.
  driver.peers.push(super::PeerLink {
    id: viewstamp_proto::ReplicaId::new(1),
    member_id: MemberId::new(1),
    addr: stale_addr,
    backoff: viewstamp_driver::REDIAL_BACKOFF_BASE,
    next_dial: Some(viewstamp_proto::Instant::ZERO),
  });

  // Force the reconciler to see a config change on the next check, modeling the membership the
  // datagram installs (no multi-node round runs in a unit test, so the real config_id is
  // unchanged); the inbound helper's `rekey_if_needed` then rebuilds the dial-map.
  driver.reconciler = viewstamp_driver::MembershipReconciler::new(u128::MAX);

  // Feed a datagram through the production inbound helper. The bytes are not a valid QUIC packet,
  // so the coordinator drops them — what matters is that the helper rekeys after the feed.
  driver.handle_inbound_datagram(
    viewstamp_proto::Instant::ZERO,
    &[0u8, 0u8, 0u8, 0u8],
    stale_addr,
  );

  // The inbound feed refreshed the dial-map: the removed slot is gone from `self.peers`, so the
  // following `reconcile_peer_links` dial pass cannot reopen it.
  assert!(
    !driver
      .peers
      .iter()
      .any(|l| l.id == viewstamp_proto::ReplicaId::new(1)),
    "the inbound feed rekeyed: the unsupported slot was dropped from the dial list"
  );

  // The dial pass that follows the feed dials nothing for the dropped slot — it has no link.
  driver.reconcile_peer_links(viewstamp_proto::Instant::ZERO);
  assert!(
    !driver.coord.has_bound_conn(viewstamp_proto::Peer::Replica(
      viewstamp_proto::ReplicaId::new(1)
    )),
    "no conn was dialed for the removed slot after the inbound-feed rekey"
  );
}

#[test]
fn embedder_facing_default_constants_are_reachable_at_the_crate_roots() {
  // The referenceable defaults exist so an embedder can compute RELATIVE overrides (e.g. a
  // geo-tuned RTT as a multiple of the pinned LAN default). This pins their crate-root paths from
  // OUTSIDE the defining crates — a `pub` const inside a private module is unreachable no matter
  // its visibility, which is exactly the defect this test compiles away.
  assert_eq!(
    viewstamp_proto::DEFAULT_IDLE_TIMEOUT_MILLIS,
    viewstamp_proto::QuicTuning::new().idle_timeout_millis()
  );
  assert_eq!(
    viewstamp_proto::DEFAULT_INITIAL_RTT_MILLIS,
    viewstamp_proto::QuicTuning::new().initial_rtt_millis()
  );
  assert_eq!(
    viewstamp_proto::DEFAULT_CONNECTION_RECEIVE_WINDOW,
    viewstamp_proto::QuicTuning::new().connection_receive_window()
  );
  assert_eq!(
    viewstamp_proto::DEFAULT_STREAM_RECEIVE_WINDOW,
    viewstamp_proto::QuicTuning::new().stream_receive_window()
  );
  // The per-stream ceiling an embedder computes a relative override against: a larger request is
  // clamped to it, so the value has to be readable from out here.
  assert_eq!(
    viewstamp_proto::QuicTuning::new()
      .with_stream_receive_window(u64::MAX)
      .stream_receive_window(),
    viewstamp_proto::MAX_STREAM_RECEIVE_WINDOW
  );
  assert_eq!(
    viewstamp_driver::DriverConfig::new().max_conns(),
    viewstamp_driver::MAX_CONNS
  );
  assert_eq!(
    viewstamp_driver::DriverConfig::new().dial_timeout(),
    viewstamp_driver::DIAL_TIMEOUT
  );
  let batch = viewstamp_driver::BatchConfig::new(64);
  assert_eq!(
    batch.max_queued_units(),
    viewstamp_driver::DEFAULT_MAX_QUEUED_UNITS
  );
  assert_eq!(
    batch.max_queued_bytes(),
    viewstamp_driver::DEFAULT_MAX_QUEUED_BYTES
  );
}

/// LIVE RETIREMENT (QUIC driver): when this endpoint removes itself from the configuration the run
/// loop's `retire` step fails every in-flight submit with the terminal `Retired` error (never a hang
/// or `ReplyDropped`), releases their budget, and rejects a later submit immediately — the same
/// terminal state a restart over the removed membership reaches. Composes the REAL `Handle::submit`,
/// the REAL `handle_command` (insert pending), the driver's shared retirement signal, and the shared
/// `retire`, reading the retirement identity off the endpoint exactly as the run-loop pump does.
#[compio::test]
async fn self_retirement_fails_in_flight_and_rejects_new_submits_quic() {
  let (mut driver, handle) = test_quic_driver_with_handle().await;

  // One in-flight submit (no quorum ever forms, so it parks): reserve + enqueue, then drain into
  // `pending` exactly as the run loop would.
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

/// QUEUED SUBMIT ACROSS RETIREMENT (QUIC driver): a submit left BUFFERED in the command channel when
/// the endpoint retires — enqueued before the latch, drained after — is caught at CONSUMPTION by
/// `handle_command`'s retirement gate: it never enters `pending` nor reaches the endpoint, its budget
/// releases, and its caller resolves to the terminal `Retired` rather than hanging. This is the
/// one-hop-downstream hang the up-front `Handle` rejection alone leaves open.
#[compio::test]
async fn a_queued_submit_across_retirement_resolves_to_retired_quic() {
  let (mut driver, handle) = test_quic_driver_with_handle().await;

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

/// QUEUED RECONFIGURE ACROSS RETIREMENT (QUIC driver): a reconfigure goal left BUFFERED in the command
/// channel when the endpoint retires is answered at CONSUMPTION with the terminal
/// `ReconfigureError::Retired` — mirroring the `Handle`'s up-front rejection — instead of starting a
/// reconfiguration job on an endpoint that can never drive it.
#[compio::test]
async fn a_queued_reconfigure_across_retirement_resolves_to_retired_quic() {
  let (mut driver, handle) = test_quic_driver_with_handle().await;

  // Enqueue a reconfigure goal but LEAVE it queued (the Handle's up-front retired check passes: the
  // signal is not latched yet).
  let target = viewstamp_proto::MembershipTarget::new(
    std::collections::BTreeSet::from([viewstamp_proto::MemberId::new(1)]),
    std::collections::BTreeSet::new(),
  );
  let fut = handle.reconfigure_to(target, viewstamp_driver::HealthHint::default(), None);
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

/// ACTIVE RECONFIGURE ACROSS RETIREMENT (QUIC driver): a reconfiguration job already STARTED — with an
/// outstanding proposal, its target not yet reached — when a concurrent removal retires the endpoint is
/// FINISHED terminally with `ReconfigureError::Retired` and its slot cleared. The run loop's
/// StatusChanged(Retired) handler calls `finish_reconfigure_on_retire` right after `retire`; without it
/// the job sits parked until `reconfigure_timeout`, surfacing a misleading (resumable) Timeout.
#[compio::test]
async fn an_active_reconfigure_across_retirement_resolves_to_retired_quic() {
  let (mut driver, handle) = test_quic_driver_with_handle().await;

  // Start a job whose target is NOT yet reached (grow the {0,1,2} genesis to add member 3), then advance
  // it once so it posts its first proposal — the "outstanding proposal" state. The no-quorum driver
  // never installs the step, so the job stays in flight.
  let target = viewstamp_proto::MembershipTarget::new(
    std::collections::BTreeSet::from([0u128, 1, 2, 3].map(viewstamp_proto::MemberId::new)),
    std::collections::BTreeSet::new(),
  );
  let fut = handle.reconfigure_to(target, viewstamp_driver::HealthHint::default(), None);
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

/// A WAL whose staged appends need more polls to land than any teardown could deliver: the backend
/// simply never completes what the endpoint submitted to it.
const APPENDS_NEVER_LAND: u32 = u32::MAX;

/// A WAL whose staged appends land only after this many polls. Chosen far above the TWO polls
/// `run()`'s pre-loop `pump_outputs` delivers before the loop's first command drain takes the
/// already-queued `Shutdown` — so an append staged here is provably still in flight when the
/// shutdown is received, and only the teardown drain can complete it — while still finishing in
/// tens of milliseconds at the drain's poll cadence.
const APPENDS_LAND_AFTER: u32 = 64;

/// Put one client request into the endpoint through the REAL `Handle::submit` + `handle_command`
/// crossing, leaving its WAL append in flight, and assert the endpoint says so.
///
/// That assertion is the anti-vacuity precondition every drain test needs: a drain over an endpoint
/// that owes storage nothing reports quiescence for free, so without it a green result would prove
/// nothing. The returned submit future must be kept alive — dropping it cancels the reply receiver.
fn submit_one_append_in_flight<'h>(
  driver: &mut TestQuicDriver,
  handle: &'h crate::Handle,
) -> std::pin::Pin<Box<SubmitFut<'h>>> {
  let mut fut: std::pin::Pin<Box<SubmitFut<'h>>> =
    Box::pin(handle.submit(Bytes::from_static(b"durable")));
  assert!(
    poll_submit(fut.as_mut()).is_none(),
    "the submit parks on its reply"
  );
  drain_one_command(driver);
  assert!(
    driver
      .coord
      .endpoint()
      .has_inflight_storage(&driver.storage),
    "the submitted request must leave a WAL append in flight, or the drain has nothing to prove"
  );
  fut
}

/// DEADLINE EXPIRY REPORTS HONESTLY (QUIC driver): against a backend that never completes the append
/// the endpoint submitted, the teardown cannot reach quiescence — so it waits out
/// `SHUTDOWN_DRAIN_DEADLINE`, then acks with `storage_quiesced() == false` and releases storage
/// anyway. Both halves are the property: an unbounded wait would wedge every shutdown behind a stuck
/// device, and reporting a clean stop would make an abandoned mid-write indistinguishable from a
/// drained one. The elapsed floor is what proves it genuinely tried to drain rather than answering
/// `false` on the spot.
#[compio::test]
async fn deadline_expiry_acks_shutdown_unquiesced_quic() {
  let (mut driver, handle) = test_quic_driver_with_storage(
    InMemoryWal::with_async_appends(APPENDS_NEVER_LAND),
    InMemorySuperblock::new(),
  )
  .await;
  let submit = submit_one_append_in_flight(&mut driver, &handle);

  let started = std::time::Instant::now();
  compio::runtime::spawn(driver.run()).detach();
  let report = compio::time::timeout(SHUTDOWN_DRAIN_DEADLINE * 4, handle.shutdown())
    .await
    .expect("the shutdown acks rather than hanging on a backend that never completes")
    .expect("shutdown acks teardown");
  let elapsed = started.elapsed();

  assert!(
    !report.storage_quiesced(),
    "an append the backend never completed must be reported as NOT quiesced"
  );
  assert!(
    elapsed >= SHUTDOWN_DRAIN_DEADLINE,
    "the teardown waited out the drain deadline before giving up, took {elapsed:?}"
  );
  assert!(
    elapsed < SHUTDOWN_DRAIN_DEADLINE * 3,
    "the wait is BOUNDED by the deadline, not open-ended; took {elapsed:?}"
  );
  drop(submit);
}

/// THE DRAIN GENUINELY COMPLETES IN-FLIGHT WORK (QUIC driver): an append the endpoint still owed
/// when the `Shutdown` arrived is carried to completion by the teardown drain, and the ack reports
/// `storage_quiesced() == true`.
///
/// Non-vacuous by construction, not by hope. The `Shutdown` is enqueued BEFORE `run()` exists, so it
/// is the first command the loop drains; the endpoint's own in-flight-storage signal is asserted
/// true at that point; and the fixture needs `APPENDS_LAND_AFTER` polls to land against the two the
/// pre-loop pump can deliver. So the append is still in flight when the shutdown is received, and a
/// `true` report can only come from the drain having polled it through.
#[compio::test]
async fn the_teardown_drain_completes_an_in_flight_append_quic() {
  let (mut driver, handle) = test_quic_driver_with_storage(
    InMemoryWal::with_async_appends(APPENDS_LAND_AFTER),
    InMemorySuperblock::new(),
  )
  .await;
  let submit = submit_one_append_in_flight(&mut driver, &handle);

  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  let mut shutdown_fut = Box::pin(handle.shutdown());
  assert!(
    std::future::Future::poll(shutdown_fut.as_mut(), &mut cx).is_pending(),
    "the shutdown enqueues its command and parks on the ack"
  );
  assert!(
    driver
      .coord
      .endpoint()
      .has_inflight_storage(&driver.storage),
    "the append is STILL in flight now the shutdown is queued: this is the moment the drain must \
     act on"
  );

  compio::runtime::spawn(driver.run()).detach();
  let report = compio::time::timeout(SHUTDOWN_DRAIN_DEADLINE * 2, shutdown_fut)
    .await
    .expect("a completing backend drains well inside the deadline")
    .expect("shutdown acks teardown");

  assert!(
    report.storage_quiesced(),
    "the drain carried the in-flight append to completion, so the stop was orderly"
  );
  drop(submit);
}

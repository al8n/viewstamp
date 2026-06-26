use super::*;
use crate::{
  Config, Endpoint, Instant, MemberId, Peer, ReplicaId, SingleChange,
  transport::{
    quic::{crypto::test_ca, testutil::addr},
    testutil::{CountSm, genesis},
  },
};

/// A mandatory-mTLS [`QuicOptions`] for `cluster` (a fresh `ClusterTls` bundle), so `with_identity`'s
/// `requires_client_auth()` invariant holds. These coordinator tests exercise dial-cap / clock-anchor
/// behavior, not identity, but `with_identity` (correctly) refuses a no-auth options bundle, so they
/// must build a real cluster-private mTLS config rather than the accept-any test path.
fn mtls_opts(cluster: u128) -> QuicOptions {
  let ca = test_ca();
  let cert = ca.issue_replica(0, cluster);
  ClusterTls::new(ca.roots(), cert.chain(), cert.key()).build()
}

#[test]
fn connect_emits_an_initial_datagram() {
  let cluster = 0x5151;
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let mut c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
    mtls_opts(cluster),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
  c.connect(Instant::ZERO, addr(2), Peer::Replica(ReplicaId::new(1)))
    .expect("the first dial on a fresh coordinator is under the cap");
  let dgram = c.poll_transmit();
  assert!(dgram.is_some(), "dialing must produce an Initial datagram");
  assert_eq!(
    dgram.unwrap().0,
    addr(2),
    "the Initial is addressed to the dialed peer"
  );
}

#[test]
fn sni_for_matches_the_replica_cert_san_form() {
  // The cert SAN is minted per stable MemberId, so the SNI must use `Peer::Member` to match.
  // `Peer::Member(m)` formats as `replica-<MemberId>.<cluster-hex>.viewstamp`, which is the
  // same form the ClusterTls issuer writes into the SAN field that WebPkiServerVerifier checks.
  assert_eq!(
    sni_for(Peer::Member(MemberId::new(1)), 0x5151),
    "replica-1.00000000000000000000000000005151.viewstamp"
  );
  // The `Peer::Replica` arm must produce the identical string when slot == MemberId (genesis).
  assert_eq!(
    sni_for(Peer::Replica(ReplicaId::new(1)), 0x5151),
    "replica-1.00000000000000000000000000005151.viewstamp"
  );
}

/// The connection cap is surfaced at the PUBLIC coordinator boundary: once the effective cap's worth
/// of dials are live, the NEXT `connect` returns `Err(DialError::AtCapacity { cap })`, leaving the
/// bridge's table and the quinn endpoint slab unchanged. The coordinator used to swallow the bridge's
/// typed `DialError` (a `let _ =`), so an over-cap dial was indistinguishable from a scheduled one;
/// surfacing it lets a caller back off / report saturation / test the cap here.
///
/// The effective cap is the membership-sized one the coordinator derives (the explicit `1` here is
/// RAISED to the mutual-dial-mesh floor), so the test fills exactly `cap` dials and asserts the
/// `cap+1`th is refused — robust to the membership sizing rather than assuming a literal `1`.
#[test]
fn a_public_connect_over_the_cap_returns_at_capacity_and_allocates_nothing() {
  let cluster = 0x5151;
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let mut c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
    // Explicit `1` is floored up to the mutual-dial-mesh minimum; read the effective cap below.
    mtls_opts(cluster).with_max_connections(1),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
  let cap = c.max_connections_for_test();

  // Fill the cap with distinct dials (distinct expected peer + address each): all admitted, each
  // allocating one table entry and one slab slot.
  for i in 0..cap {
    c.connect(
      Instant::ZERO,
      addr(1000 + i as u16),
      Peer::Replica(ReplicaId::new(1 + i as u16)),
    )
    .expect("a dial under the cap is admitted");
  }
  assert_eq!(
    c.bridge_table_len(),
    cap,
    "the cap's worth of dials are live"
  );
  assert_eq!(
    c.bridge_endpoint_open_connections(),
    cap,
    "each admitted dial allocates one endpoint slab slot"
  );

  // The next dial is AT the cap: the PUBLIC API must surface the typed AtCapacity error (carrying the
  // effective cap) and allocate nothing — the gate runs before `endpoint.connect`, so no partial state.
  let over = c.connect(Instant::ZERO, addr(2000), Peer::Replica(ReplicaId::new(0)));
  assert_eq!(
    over,
    Err(DialError::AtCapacity { cap }),
    "an over-cap public dial returns the typed AtCapacity error carrying the effective cap"
  );
  assert_eq!(
    c.bridge_table_len(),
    cap,
    "a refused dial must NOT add a table entry past the cap"
  );
  assert_eq!(
    c.bridge_endpoint_open_connections(),
    cap,
    "a refused dial must NOT allocate an endpoint slab slot past the cap"
  );
}

/// `DialError` is nameable through the crate's PUBLIC re-export, exactly as an external caller would
/// reach it (`viewstamp_proto::DialError`). The `transport` / `quic` / `bridge` modules are all
/// private, so before the crate-root re-export an external caller received `connect`'s typed error
/// but could not name it or `match` its `AtCapacity` variant — the error was `pub` but unreachable.
///
/// This test deliberately refers to the type ONLY via `crate::DialError` (the in-crate spelling of
/// the public path), NOT via the private `super::DialError` / `bridge::DialError` module path the
/// other dial-cap tests use, so it fails to compile if the crate-root re-export regresses. It drives
/// a public `connect` over the cap and `match`es the typed variant the public API returns.
#[test]
fn dial_error_is_nameable_through_the_public_reexport() {
  // Bind the type through the PUBLIC re-export path. An external crate would write
  // `use viewstamp_proto::DialError;`; in-crate that public item is `crate::DialError`.
  use crate::DialError;

  let cluster = 0x5151;
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let mut c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
    // Explicit `1` is floored up to the mutual-dial-mesh minimum; read the effective cap below.
    mtls_opts(cluster).with_max_connections(1),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
  let effective_cap = c.max_connections_for_test();

  // Fill the effective cap with distinct dials, all under the cap.
  for i in 0..effective_cap {
    c.connect(
      Instant::ZERO,
      addr(1000 + i as u16),
      Peer::Replica(ReplicaId::new(1 + i as u16)),
    )
    .expect("a dial under the cap is admitted");
  }

  // The over-cap dial returns the typed error, named + destructured through the public re-export.
  let cap = match c.connect(Instant::ZERO, addr(2000), Peer::Replica(ReplicaId::new(0))) {
    Err(DialError::AtCapacity { cap }) => cap,
    other => panic!("expected Err(DialError::AtCapacity) from the public API, got {other:?}"),
  };
  assert_eq!(
    cap, effective_cap,
    "the typed AtCapacity carries the effective (membership-sized) cap"
  );
}

/// A coordinator FIRST driven at a non-zero viewstamp epoch maps quinn time anchored at that epoch,
/// so `poll_timeout` reports quinn's small real timer — NOT a deadline pushed the whole epoch into
/// the future.
///
/// The clock adapter is anchored LAZILY on the first `quinn_now` (here the first `connect`) to the
/// driver's actual first-seen `now`, so `quinn_now(first_now) == std_base` (the real instant captured
/// then). A real driver's monotonic clock does NOT start at zero; a freshly-dialed connection arms
/// quinn's handshake/initial timer tens-to-hundreds of ms out, and `poll_timeout` must return that —
/// a deadline within a small delta of real-now — so a sleep-until-`poll_timeout` driver wakes to
/// retransmit the handshake on time (and likewise reaps auth / drains closes on time).
///
/// This drives the FIRST `connect` at viewstamp epoch 10 s and asserts the reported `poll_timeout`
/// deadline is well under 1 s past real-now — i.e. quinn's handshake timer, not an epoch-shifted one.
///
/// NEUTER CHECK: anchor `vsr_base = Instant::ZERO` (the old `build`) instead of lazily to the first
/// `now`, and `quinn_now(10s) == std_base + 10s`, so the connection's timers — and the reported
/// deadline — sit ~10 s in the future: the assertion below (deadline < real-now + 1 s) fails, exactly
/// the over-long sleep this fixes.
#[test]
fn poll_timeout_is_anchored_to_a_non_zero_driver_epoch() {
  use core::time::Duration;

  let cluster = 0x5151;
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let mut c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
    mtls_opts(cluster),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );

  // A driver whose monotonic clock starts well past zero: the FIRST drive is at viewstamp epoch 10 s.
  // The lazy anchor pins (vsr_base, std_base) = (10 s, real-now) on this call.
  let epoch = Instant::from_nanos(10_000_000_000);
  let real_before = std::time::Instant::now();
  c.connect(epoch, addr(2), Peer::Replica(ReplicaId::new(1)))
    .expect("the first dial on a fresh coordinator is under the cap");
  let real_after = std::time::Instant::now();

  // The dialed connection arms quinn's handshake/initial timer (tens-to-hundreds of ms out). The
  // reported deadline must be that timer measured from REAL now — NOT offset by the 10 s epoch.
  let deadline = c
    .poll_timeout()
    .expect("a freshly-dialed connection arms a quinn timer");
  let ahead = deadline.saturating_duration_since(real_before);
  assert!(
    ahead < Duration::from_secs(1),
    "poll_timeout must report quinn's handshake timer anchored at the driver's real epoch (< 1 s \
     ahead of real-now), not a deadline shifted by the 10 s viewstamp epoch; got {ahead:?} ahead"
  );
  // And it is a genuine FUTURE timer, not already elapsed — i.e. the dial really armed one. (Allow
  // for the tiny real-time the dial itself consumed between `real_before` and `real_after`.)
  assert!(
    deadline >= real_after || deadline.saturating_duration_since(real_before) > Duration::ZERO,
    "the reported deadline is quinn's armed handshake timer, in the (near) future"
  );
}

/// The SAFE provided-identity constructor enforces the load-bearing invariant: it REJECTS a
/// `QuicOptions` that lacks mandatory client-certificate auth. The provided `Hello` source binds an
/// accepted connection from a SELF-CLAIMED control preface; that self-claim is trustworthy only
/// because mandatory mTLS over cluster-private roots has already proven the peer holds a cluster
/// cert. A no-auth options bundle (the `accept_any_for_test` path, `requires_client_auth() == false`)
/// would turn sender identity into unauthenticated labeling, so `with_identity` panics on it — arbitrary
/// / no-auth options belong only behind the named `dangerous_custom_identity` hazard.
///
/// NEUTER CHECK: drop the `opts.requires_client_auth()` assert in `with_identity`, and this no-auth
/// bundle is accepted — exactly the unauthenticated-`Hello`-binding hole the assert closes.
#[test]
#[should_panic(expected = "mandatory mTLS")]
fn with_identity_rejects_options_without_mandatory_client_auth() {
  let cluster = 0x5151;
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  // `accept_any_for_test` builds a server WITHOUT client auth (`requires_client_auth() == false`):
  // the provided-identity invariant forbids it on the safe path.
  let _ = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
    QuicOptions::accept_any_for_test(),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
}

/// The companion to the rejection above: a `ClusterTls::build` bundle (mandatory mTLS over
/// cluster-private roots, `requires_client_auth() == true`) is ACCEPTED by `with_identity`, so the
/// invariant gates the unsafe options without blocking the intended cluster-private path.
#[test]
fn with_identity_accepts_cluster_tls_mandatory_mtls_options() {
  let cluster = 0x5151;
  let opts = mtls_opts(cluster);
  assert!(
    opts.requires_client_auth(),
    "a ClusterTls::build bundle carries mandatory client auth"
  );
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  // Must not panic: the safe provided-identity path accepts a mandatory-mTLS options bundle.
  let c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(2), 1, CountSm::default()),
    opts,
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
  assert_eq!(
    c.endpoint().cluster(),
    cluster,
    "the coordinator wraps the endpoint for the configured cluster"
  );
}

/// Build a coordinator for a `replica_count`-replica cluster (this node `Replica(0)`), optionally
/// overriding the connection cap, and return the EFFECTIVE cap the bridge ended up with.
fn effective_cap(replica_count: u8, override_cap: Option<usize>) -> usize {
  let cluster = 0x5151;
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let mut opts = mtls_opts(cluster);
  if let Some(cap) = override_cap {
    opts = opts.with_max_connections(cap);
  }
  let c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(replica_count), 1, CountSm::default()),
    opts,
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
  c.max_connections_for_test()
}

/// The effective connection cap is sized to the configured membership so it covers the full
/// mutual-dial mesh (`2*(replica_count - 1)` connections) for any supported cluster — the 64 default
/// alone would refuse mesh dials past ~33 replicas (a liveness failure at scale). The coordinator
/// RAISES the cap to `mesh_connection_floor(replica_count)` (`3*(N-1)`, floored) at construction.
///
/// NEUTER CHECK: drop the `with_max_connections(...max(mesh_floor))` raise in `build` and the N=64
/// effective cap stays at the 64 default — below the `2*63 = 126` mesh need — so the `>= 126`
/// assertion fails, exactly the at-scale mesh starvation this fixes.
#[test]
fn the_connection_cap_covers_the_mutual_dial_mesh_for_the_configured_membership() {
  // A small cluster: the derived cap must cover the steady-state mesh (`2*(5-1) = 8`).
  let n5 = effective_cap(5, None);
  assert!(
    n5 >= 2 * (5 - 1),
    "a 5-replica node's cap ({n5}) must cover its {}-connection mutual-dial mesh",
    2 * (5 - 1)
  );

  // The supported maximum (64 replicas): the bare mesh is `2*63 = 126`; the derived cap must be at
  // least that, so the whole mesh forms before the cap refuses anything.
  let n64 = effective_cap(64, None);
  assert!(
    n64 >= 126,
    "a 64-replica node's effective cap ({n64}) must be >= 126 (the 2*(64-1) steady-state mesh); the \
     64 default would starve the mesh past ~33 replicas"
  );

  // An EXPLICIT override BELOW the mesh need is raised to the floor (the cap must never refuse a
  // legitimate steady-state mesh connection), while an override ABOVE the floor is honoured as-is.
  let raised = effective_cap(5, Some(2));
  assert!(
    raised >= 2 * (5 - 1),
    "an explicit cap below the mesh need ({raised}) must be raised to cover the 5-replica mesh"
  );
  let generous = effective_cap(5, Some(1000));
  assert_eq!(
    generous, 1000,
    "an explicit cap above the mesh floor is honoured as-is (a larger flood budget)"
  );
}

/// A 1-replica cluster (no peers, so a zero-connection mesh) still keeps the small constant floor, so
/// a degenerate single-node config is not capped to zero admissible connections.
#[test]
fn the_connection_cap_keeps_a_floor_for_a_tiny_cluster() {
  let n1 = effective_cap(1, Some(1));
  assert!(
    n1 >= 4,
    "even a 1-replica node keeps a small connection floor ({n1}) for accept/reconnect headroom"
  );
}

/// A relayed (replica-sent) `Request` whose body is ONE byte over the deliverable maximum is dropped
/// at the QUIC transport ingress BEFORE the endpoint: it appends no op and is never fed to
/// `handle_message` (the consensus-frame counter does not advance). The hazard: a buggy /
/// version-skewed member relays a `Request` that fits its own frame but whose resulting `Prepare`
/// would exceed `MAX_FRAME_LEN`, so the primary would log an op it can never replicate. The
/// at-maximum body, by contrast, is served
/// and reaches the endpoint — the boundary is usable. The gate keeps the consensus `Endpoint`
/// transport-agnostic.
#[test]
fn a_relayed_over_max_request_is_dropped_at_quic_ingress_with_no_side_effects() {
  use crate::{
    ClientId, Message, Request, RequestNumber,
    transport::{
      frame::{MAX_FRAME_LEN, max_request_body_len},
      testutil::{TestSb, TestWal},
    },
  };
  use bytes::Bytes;

  let cluster = 0x5151;
  // Replica 0 is the primary of view 0, so an admitted relayed Request would be served.
  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let mut wal = TestWal::default();
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, genesis(3), 1, CountSm::default()),
    mtls_opts(cluster),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );
  assert_eq!(c.endpoint().op().get(), 0, "no op before any request");
  assert_eq!(
    c.consensus_frames_delivered(),
    0,
    "no consensus frame delivered yet"
  );

  // A relayed Request (from a configured REPLICA — the replica-relayed ingress this gate guards)
  // whose body is one byte past the deliverable maximum: its resulting Prepare would exceed
  // MAX_FRAME_LEN.
  let over = Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from(vec![0u8; max_request_body_len() + 1]),
  ));
  c.inject_message_for_test(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    over,
  );
  assert_eq!(
    c.endpoint().op().get(),
    0,
    "an over-max relayed request appends no op (dropped before the endpoint)"
  );
  assert_eq!(
    c.consensus_frames_delivered(),
    0,
    "an over-max relayed request is never fed to handle_message (dropped at ingress)"
  );

  // The BOUNDARY: a body of EXACTLY max_request_body_len() reaches the endpoint and is served.
  assert!(
    max_request_body_len() < MAX_FRAME_LEN as usize,
    "the deliverable max is under the frame cap by the request overhead"
  );
  let at_max = Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from(vec![0u8; max_request_body_len()]),
  ));
  c.inject_message_for_test(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    at_max,
  );
  assert_eq!(
    c.consensus_frames_delivered(),
    1,
    "an at-maximum relayed request IS delivered to the endpoint (the boundary is usable)"
  );
  assert_eq!(
    c.endpoint().op().get(),
    1,
    "and it IS served: one op appended (the gate admits exactly the max)"
  );
}

/// `connect` derives the QUIC SNI from the dialed slot's STABLE `MemberId`, not the slot number
/// itself. The cert SAN is `replica-<MemberId>.<cluster-hex>.viewstamp`; if the SNI were
/// slot-keyed (`replica-<slot>.<cluster-hex>.viewstamp`) then any reconfiguration that shifts a
/// retained member to a new slot would produce a mismatch between the dial's SNI and the server's
/// SAN, causing TLS verification to fail.
///
/// This test constructs a membership where `MemberId(2)` occupies slot 1 (member 1 was removed
/// and member 2 filled the vacated slot), then reads the SNI `connect` would present for slot 1
/// through `dial_sni_for_slot_for_test`.
///
/// PRE-FIX FAILURE CONFIRMATION: the old slot-keyed path would call
/// `sni_for(Peer::Replica(slot), cluster)`, producing `replica-1.<cluster-hex>.viewstamp`.
/// The test asserts this string is NOT what the fixed code returns, demonstrating it would have
/// mismatch the `replica-2.<cluster-hex>.viewstamp` SAN on the server cert and been rejected by
/// TLS. The fixed code's output, `replica-2.<cluster-hex>.viewstamp`, matches the cert SAN.
#[test]
fn dial_sni_is_keyed_to_the_stable_member_id_not_the_routing_slot() {
  use crate::{Epoch, Membership};

  let cluster = 0x1234_5678_u128;

  // A 2-voter membership after a slot shift: MemberId(0) at slot 0, MemberId(2) at slot 1.
  // Member 1 was removed; member 2 filled the vacated slot 1. config_id = 0 (test convention).
  let shifted_membership = Membership::from_durable_parts(
    Epoch::new(1),
    2,
    0,
    vec![MemberId::new(0), MemberId::new(2)],
    0,
  )
  .expect("valid 2-voter membership");

  let cfg = Config::try_new(cluster, MemberId::new(0)).unwrap();
  let c = QuicCoordinator::with_identity(
    Endpoint::<_, SingleChange>::with_reconfig(cfg, shifted_membership, 1, CountSm::default()),
    mtls_opts(cluster),
    Some([0u8; 32]),
    IdentityConfig::Hello { cluster },
  );

  // The SNI the fixed `connect` presents for slot 1: stable MemberId(2) form.
  let fixed_sni = c.dial_sni_for_slot_for_test(ReplicaId::new(1));
  let expected_sni = format!("replica-2.{cluster:032x}.viewstamp");
  assert_eq!(
    fixed_sni, expected_sni,
    "the dial SNI for slot 1 must use the stable MemberId(2), not the slot number 1"
  );

  // PRE-FIX: the slot-keyed SNI the old code would have sent. The cert SAN is
  // `replica-2.<cluster>.viewstamp`; this slot-keyed form does not match it, so TLS would reject
  // the connection. The two strings being different is the proof that the fix matters.
  let pre_fix_sni = sni_for(Peer::Replica(ReplicaId::new(1)), cluster);
  assert_ne!(
    fixed_sni, pre_fix_sni,
    "the fixed (MemberId-keyed) SNI must differ from the pre-fix (slot-keyed) SNI after a slot \
     shift: the pre-fix SNI would mismatch the cert SAN and be rejected by TLS"
  );
}

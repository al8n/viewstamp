//! End-to-end loopback: two `StreamCoordinator`s wired byte-to-byte (no sockets) reach consensus
//! over the transport — plain (`tcp`) and TLS (`tls`), including a payload larger than rustls's
//! 16 KiB inbound plaintext limit (the `Intake::Pending` reassembly path). Proves the composition
//! Sans-I/O before any real driver exists.

use core::time::Duration;

use crate::{
  ClientId, Config, Conn, ConnId, Endpoint, Instant, LabelOptions, Labeled, MemberId, Message,
  Passthrough, Peer, ReplicaId, RequestNumber, StreamCoordinator, StreamTransport,
  message::Request,
  transport::testutil::{CountSm, TestSb, TestWal, genesis},
};

const CLUSTER: u128 = 0x5151;

fn replica<R: StreamTransport>(id: u16) -> (StreamCoordinator<CountSm, R>, TestWal, TestSb) {
  let cfg = Config::try_new(CLUSTER, MemberId::new(id as u128)).unwrap();
  let coord = StreamCoordinator::new(Endpoint::new(
    cfg,
    genesis(2),
    u64::from(id) + 1,
    CountSm::default(),
  ));
  (coord, TestWal::default(), TestSb::default())
}

fn sized_request(body: &[u8]) -> Message {
  Message::Request(Request::new(
    ClientId::new(1),
    RequestNumber::with(1),
    bytes::Bytes::copy_from_slice(body),
  ))
}

#[allow(clippy::too_many_arguments)]
fn run_until_converged<R: StreamTransport>(
  r0: &mut StreamCoordinator<CountSm, R>,
  wal0: &mut TestWal,
  sb0: &mut TestSb,
  c0: ConnId,
  r1: &mut StreamCoordinator<CountSm, R>,
  wal1: &mut TestWal,
  sb1: &mut TestSb,
  c1: ConnId,
) -> bool {
  let mut now = Instant::ZERO;
  for _ in 0..8000 {
    now = now + Duration::from_millis(10);
    r0.handle_storage(now, wal0, sb0);
    r1.handle_storage(now, wal1, sb1);
    r0.handle_timeout(now, wal0, sb0);
    r1.handle_timeout(now, wal1, sb1);
    for _ in 0..2 {
      while let Some((_id, bytes)) = r0.poll_conn_transmit() {
        r1.handle_conn_data(c1, &bytes, false, now, wal1, sb1);
      }
      while let Some((_id, bytes)) = r1.poll_conn_transmit() {
        r0.handle_conn_data(c0, &bytes, false, now, wal0, sb0);
      }
    }
    if r0.endpoint().state_machine_ref().applied().len() == 1
      && r1.endpoint().state_machine_ref().applied().len() == 1
    {
      return true;
    }
  }
  false
}

fn assert_converged<R: StreamTransport>(
  r0: &StreamCoordinator<CountSm, R>,
  r1: &StreamCoordinator<CountSm, R>,
  converged: bool,
  body: &[u8],
) {
  assert!(
    converged,
    "the cluster did not converge within the step budget"
  );
  let want: &[(u64, std::vec::Vec<u8>)] = &[(1, body.to_vec())];
  assert_eq!(
    r0.endpoint().state_machine_ref().applied(),
    want,
    "primary applied op 1"
  );
  assert_eq!(
    r1.endpoint().state_machine_ref().applied(),
    want,
    "backup converged over the transport"
  );
}

#[test]
fn two_replicas_commit_over_plain_tcp() {
  fn dialer(me: u16) -> Conn<Labeled<Passthrough>> {
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me)));
    Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
  }
  fn acceptor(me: u16) -> Conn<Labeled<Passthrough>> {
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  }
  let (mut r0, mut wal0, mut sb0) = replica::<Labeled<Passthrough>>(0);
  let (mut r1, mut wal1, mut sb1) = replica::<Labeled<Passthrough>>(1);
  let c0 = r0.register_dialed(Peer::Replica(ReplicaId::new(1)), dialer(0));
  let c1 = r1.register_accepted(Peer::Replica(ReplicaId::new(0)), acceptor(1));
  r0.inject_message_for_test(
    Instant::ZERO,
    &mut wal0,
    &mut sb0,
    Peer::Client(ClientId::new(1)),
    sized_request(b"x"),
  );
  let converged = run_until_converged(
    &mut r0, &mut wal0, &mut sb0, c0, &mut r1, &mut wal1, &mut sb1, c1,
  );
  assert_converged(&r0, &r1, converged, b"x");
}

// The PUBLIC node-local submit path: `StreamCoordinator::submit_client_request` injects a client
// request at this replica AND broadcasts it to the backups, so the view-0 primary (replica 0) serves
// it — the driver's real submit surface (the `inject_message_for_test` seam is `#[cfg(test)]`). Two
// replicas converge over plain TCP with the request fed through the public api, not the inject seam.
#[test]
fn public_submit_client_request_over_tcp_converges() {
  fn dialer(me: u16) -> Conn<Labeled<Passthrough>> {
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me)));
    Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts))
  }
  fn acceptor(me: u16) -> Conn<Labeled<Passthrough>> {
    let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me)));
    Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts))
  }
  let (mut r0, mut wal0, mut sb0) = replica::<Labeled<Passthrough>>(0);
  let (mut r1, mut wal1, mut sb1) = replica::<Labeled<Passthrough>>(1);
  let c0 = r0.register_dialed(Peer::Replica(ReplicaId::new(1)), dialer(0));
  let c1 = r1.register_accepted(Peer::Replica(ReplicaId::new(0)), acceptor(1));
  r0.submit_client_request(
    Instant::ZERO,
    &mut wal0,
    &mut sb0,
    Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"x"),
    ),
  );
  let converged = run_until_converged(
    &mut r0, &mut wal0, &mut sb0, c0, &mut r1, &mut wal1, &mut sb1, c1,
  );
  assert_converged(&r0, &r1, converged, b"x");
}

// A raw Passthrough (no handshake) converges without any test-only validation nudge: registration
// validates each conn immediately, so a primary that emits before any inbound read is not
// black-holed.
#[test]
fn two_replicas_commit_over_raw_passthrough() {
  fn raw() -> Conn<Passthrough> {
    Conn::from_parts(Passthrough::new())
  }
  let (mut r0, mut wal0, mut sb0) = replica::<Passthrough>(0);
  let (mut r1, mut wal1, mut sb1) = replica::<Passthrough>(1);
  let c0 = r0.register_dialed(Peer::Replica(ReplicaId::new(1)), raw());
  let c1 = r1.register_accepted(Peer::Replica(ReplicaId::new(0)), raw());
  r0.inject_message_for_test(
    Instant::ZERO,
    &mut wal0,
    &mut sb0,
    Peer::Client(ClientId::new(1)),
    sized_request(b"x"),
  );
  let converged = run_until_converged(
    &mut r0, &mut wal0, &mut sb0, c0, &mut r1, &mut wal1, &mut sb1, c1,
  );
  assert_converged(&r0, &r1, converged, b"x");
}

#[cfg(feature = "tls")]
mod tls {
  use super::*;
  use crate::{TlsOptions, TlsRecords};
  use std::sync::Arc;

  fn tls_options() -> TlsOptions {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
      rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    let server = rustls::ServerConfig::builder()
      .with_no_client_auth()
      .with_single_cert(vec![cert_der], key_der)
      .unwrap();
    let client = rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(crate::transport::tls::test_verifier::AcceptAny))
      .with_no_client_auth();
    TlsOptions::new(server, client)
  }
  fn dialer(me: u16, opts: &TlsOptions) -> Conn<Labeled<TlsRecords>> {
    let lopts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me)));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let inner = TlsRecords::client(opts.client_arc(), name).unwrap();
    Conn::from_parts(Labeled::dialer(inner, &lopts))
  }
  fn acceptor(me: u16, opts: &TlsOptions) -> Conn<Labeled<TlsRecords>> {
    let lopts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(me)));
    let inner = TlsRecords::server(opts.server_arc()).unwrap();
    Conn::from_parts(Labeled::acceptor(inner, &lopts))
  }

  fn run_tls(body: &[u8]) {
    let opts = tls_options();
    let (mut r0, mut wal0, mut sb0) = replica::<Labeled<TlsRecords>>(0);
    let (mut r1, mut wal1, mut sb1) = replica::<Labeled<TlsRecords>>(1);
    let c0 = r0.register_dialed(Peer::Replica(ReplicaId::new(1)), dialer(0, &opts));
    let c1 = r1.register_accepted(Peer::Replica(ReplicaId::new(0)), acceptor(1, &opts));
    r0.inject_message_for_test(
      Instant::ZERO,
      &mut wal0,
      &mut sb0,
      Peer::Client(ClientId::new(1)),
      sized_request(body),
    );
    let converged = run_until_converged(
      &mut r0, &mut wal0, &mut sb0, c0, &mut r1, &mut wal1, &mut sb1, c1,
    );
    assert_converged(&r0, &r1, converged, body);
  }

  #[test]
  fn two_replicas_commit_over_tls() {
    run_tls(b"x");
  }

  // A >16 KiB body forces the rustls received-plaintext-limit Intake::Pending reassembly through
  // the full Conn<Labeled<TlsRecords>> stack — the path no small-message test exercises.
  #[test]
  fn two_replicas_commit_a_large_request_over_tls() {
    let body = std::vec![0x5au8; 64 * 1024];
    run_tls(&body);
  }
}

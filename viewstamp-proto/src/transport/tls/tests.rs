use super::*;
use crate::{Instant, transport::stream::RecordIo};
use std::sync::Arc;

fn test_configs() -> (
  Arc<rustls::ServerConfig>,
  Arc<rustls::ClientConfig>,
  rustls::pki_types::ServerName<'static>,
) {
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
    .with_custom_certificate_verifier(Arc::new(test_verifier::AcceptAny))
    .with_no_client_auth();
  (
    Arc::new(server),
    Arc::new(client),
    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
  )
}

fn pump<A: RecordIo, B: RecordIo>(from: &mut A, to: &mut B) -> bool {
  let mut wire = Vec::new();
  from.poll_transport_transmit(&mut wire);
  if wire.is_empty() {
    return false;
  }
  to.handle_transport_data(&wire, Instant::ZERO);
  true
}

// The TLS analogue of the StreamTransport compile-pass construction doc-test (which can only cover
// Passthrough, since a TLS conn needs rustls configs the doc-test cannot build cheaply): a driver
// builds the inner TlsRecords concretely, wraps it in the labeled handshake, and constructs the
// Conn — all from the crate-root public API, proving downstream TLS construction works.
#[test]
fn a_driver_can_construct_a_tls_backed_conn() {
  use crate::{Conn, LabelOptions, Labeled, Peer, ReplicaId};
  let (server, client, name) = test_configs();
  let opts = LabelOptions::new(0xABCD, Peer::Replica(ReplicaId::new(0)));
  let dialer_inner = TlsRecords::client(client, name).unwrap();
  let _dialer: Conn<Labeled<TlsRecords>> = Conn::from_parts(Labeled::dialer(dialer_inner, &opts));
  let acceptor_inner = TlsRecords::server(server).unwrap();
  let acceptor: Conn<Labeled<TlsRecords>> =
    Conn::from_parts(Labeled::acceptor(acceptor_inner, &opts));
  // A freshly-built TLS conn is encrypted and still handshaking until the record layer settles.
  assert!(acceptor.is_secure(), "a TLS-backed conn reports as secure");
}

#[test]
fn handshake_completes_and_plaintext_flows() {
  let (server, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  let mut s = TlsRecords::server(server).unwrap();
  for _ in 0..16 {
    let a = pump(&mut c, &mut s);
    let b = pump(&mut s, &mut c);
    if !a && !b {
      break;
    }
  }
  assert!(!c.is_handshaking() && !s.is_handshaking());
  assert!(TlsRecords::is_secure());
  c.write_plaintext(b"ping");
  while pump(&mut c, &mut s) {}
  let mut got = Vec::new();
  s.read_plaintext(&mut got);
  assert_eq!(&got, b"ping");
}

#[test]
fn large_plaintext_drives_intake_pending_and_reassembles() {
  let (server, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  let mut s = TlsRecords::server(server).unwrap();
  for _ in 0..16 {
    let a = pump(&mut c, &mut s);
    let b = pump(&mut s, &mut c);
    if !a && !b {
      break;
    }
  }
  assert!(!c.is_handshaking() && !s.is_handshaking());
  let payload = std::vec![0x5au8; 64 * 1024];
  c.write_plaintext(&payload);
  let mut wire = Vec::new();
  c.poll_transport_transmit(&mut wire);
  assert!(
    wire.len() > 16 * 1024,
    "ciphertext spans multiple TLS records"
  );
  let intake = s.handle_transport_data(&wire, Instant::ZERO);
  assert!(
    intake.is_pending(),
    "the 16 KiB received-plaintext limit must force backpressure"
  );
  let mut got = Vec::new();
  s.read_plaintext(&mut got);
  let mut consumed = match intake {
    Intake::Pending(n) => n,
    other => panic!("expected Pending, got {other:?}"),
  };
  while consumed < wire.len() {
    match s.handle_transport_data(&wire[consumed..], Instant::ZERO) {
      Intake::Pending(n) => consumed += n,
      Intake::Done => consumed = wire.len(),
      Intake::Failed => panic!("unexpected Failed"),
    }
    s.read_plaintext(&mut got);
  }
  assert_eq!(got, payload, "the full >16 KiB payload reassembles");
}

#[test]
fn write_plaintext_stages_in_plaintext_units_and_is_bounded() {
  let (_, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  // Many small frames totaling a few MiB, staged WITHOUT draining (no poll_transport_transmit):
  // every call must accept its full length. A legitimate small frame well under the plaintext cap
  // is never falsely short-written — the bound is the plaintext stage, not encrypted bytes, so TLS
  // record overhead can never make a healthy under-cap conn trip.
  let frame = std::vec![0xa5u8; 1024];
  let mut staged = 0usize;
  while staged < 4 * 1024 * 1024 {
    let n = c.write_plaintext(&frame);
    assert_eq!(
      n,
      frame.len(),
      "a small frame under the plaintext cap is never short-written"
    );
    staged += n;
  }

  // A fresh conn whose stage is filled exactly to SEND_LIMIT accepts no more: the next write
  // returns 0 (the cap is the single binding constraint, enforced in plaintext units).
  let (_, client2, name2) = test_configs();
  let mut full = TlsRecords::client(client2, name2).unwrap();
  let cap = std::vec![0u8; SEND_LIMIT];
  assert_eq!(
    full.write_plaintext(&cap),
    SEND_LIMIT,
    "the stage accepts exactly SEND_LIMIT plaintext bytes"
  );
  assert_eq!(
    full.write_plaintext(b"x"),
    0,
    "once the stage is at SEND_LIMIT a further write is rejected"
  );
}

#[test]
fn staged_plaintext_is_retained_in_buffered_outbound_while_handshaking() {
  let (_, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  // No peer has been pumped, so the client is still mid-handshake.
  assert!(c.is_handshaking());
  let payload = b"some staged plaintext";
  assert_eq!(c.write_plaintext(payload), payload.len());
  // While handshaking, transmit must not move staged plaintext into rustls (where buffered_outbound
  // could not see it); the staged bytes stay accounted in `pending`.
  let mut out = Vec::new();
  c.poll_transport_transmit(&mut out);
  assert_eq!(
    c.buffered_outbound(),
    payload.len(),
    "staged plaintext stays counted while the handshake is in flight"
  );
  // Idempotent: a second transmit while still handshaking does not feed/clear the stage either.
  let mut out2 = Vec::new();
  c.poll_transport_transmit(&mut out2);
  assert!(c.is_handshaking());
  assert_eq!(
    c.buffered_outbound(),
    payload.len(),
    "repeated transmit while handshaking leaves the stage untouched"
  );
}

#[test]
fn a_short_rustls_write_does_not_drop_staged_plaintext() {
  let (_, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  // Stage several KB across multiple write_plaintext calls while the handshake is still in flight.
  let chunk = std::vec![0x33u8; 1024];
  let mut staged = 0usize;
  for _ in 0..8 {
    staged += c.write_plaintext(&chunk);
  }
  assert_eq!(staged, 8 * 1024);
  assert_eq!(c.buffered_outbound(), staged);
  // A transmit while handshaking never feeds rustls, so nothing can be cleared without acceptance:
  // every staged byte remains queued and counted (no silent drop of plaintext).
  let mut out = Vec::new();
  c.poll_transport_transmit(&mut out);
  assert!(c.is_handshaking());
  assert_eq!(
    c.buffered_outbound(),
    staged,
    "no staged plaintext is dropped: pending is never cleared without rustls accepting it"
  );
}

#[test]
fn tls_is_terminal_after_a_fatal_record() {
  // A fatal rustls record must leave the layer terminal atomically: failure and the terminal flag
  // are set together, so a direct caller that ignores the Failed cannot afterwards surface any
  // plaintext decrypted before the fatal record, accept an app write, or re-process input. A fresh
  // server fed a clearly malformed TLS record drives the fatal path cheaply (no handshake needed).
  let (server, _client, _name) = test_configs();
  let mut s = TlsRecords::server(server).unwrap();
  let garbage = std::vec![0xffu8; 1024];
  assert_eq!(
    s.handle_transport_data(&garbage, Instant::ZERO),
    Intake::Failed,
    "a malformed TLS record is a terminal reject"
  );
  let mut out = Vec::new();
  assert_eq!(
    s.read_plaintext(&mut out),
    0,
    "a failed layer surfaces no plaintext"
  );
  assert!(out.is_empty());
  assert_eq!(
    s.write_plaintext(b"app"),
    0,
    "a failed layer accepts no application plaintext"
  );
  let mut wire = Vec::new();
  assert_eq!(
    s.poll_transport_transmit(&mut wire),
    0,
    "a failed layer emits nothing"
  );
  assert_eq!(
    s.handle_transport_data(b"more", Instant::ZERO),
    Intake::Failed,
    "a further feed stays terminal"
  );
}

#[test]
fn malformed_post_handshake_input_is_fatal_not_backpressure() {
  let (server, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  let mut s = TlsRecords::server(server).unwrap();
  for _ in 0..16 {
    let a = pump(&mut c, &mut s);
    let b = pump(&mut s, &mut c);
    if !a && !b {
      break;
    }
  }
  assert!(!s.is_handshaking());
  let garbage = std::vec![0xffu8; 32 * 1024];
  assert_eq!(
    s.handle_transport_data(&garbage, Instant::ZERO),
    Intake::Failed,
    "malformed TLS input must be fatal, not Pending backpressure"
  );
}

#[test]
fn tls_options_debug_is_non_exhaustive() {
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
    .with_custom_certificate_verifier(Arc::new(test_verifier::AcceptAny))
    .with_no_client_auth();
  let opts = TlsOptions::new(server, client);
  let debug = format!("{opts:?}");
  assert!(
    debug.contains("TlsOptions"),
    "the Debug impl names the type: {debug}"
  );
}

#[test]
fn tls_records_debug_reports_a_field_snapshot() {
  let (_, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  c.write_plaintext(b"hello");
  let debug = format!("{c:?}");
  assert!(debug.contains("TlsRecords"), "{debug}");
  assert!(
    debug.contains("pending: 5"),
    "the staged plaintext length is surfaced: {debug}"
  );
  assert!(debug.contains("peer_closed: false"), "{debug}");
  assert!(debug.contains("aborted: false"), "{debug}");
}

#[test]
fn peer_identity_is_always_none() {
  let (_, client, name) = test_configs();
  let c = TlsRecords::client(client, name).unwrap();
  assert_eq!(
    c.peer_identity(),
    None,
    "TlsRecords carries no peer identity of its own — the Labeled decorator supplies one"
  );
}

#[test]
fn clear_outbound_discards_staged_plaintext_and_is_terminal() {
  let (_, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  c.write_plaintext(b"staged");
  assert_eq!(c.buffered_outbound(), 6);
  c.clear_outbound();
  assert_eq!(
    c.buffered_outbound(),
    0,
    "clear_outbound discards the staged plaintext"
  );
  assert!(
    c.is_handshaking(),
    "a cleared (aborted) layer never reports settled again"
  );
  assert!(
    c.peer_has_closed(),
    "a cleared (aborted) layer always reports the peer as closed"
  );
}

#[test]
fn send_close_notify_queues_an_alert_for_both_roles_until_aborted() {
  let (server, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  let mut s = TlsRecords::server(server).unwrap();
  for _ in 0..16 {
    let a = pump(&mut c, &mut s);
    let b = pump(&mut s, &mut c);
    if !a && !b {
      break;
    }
  }
  assert!(!c.is_handshaking() && !s.is_handshaking());
  // Both roles forward to the inner rustls connection.
  c.send_close_notify();
  let mut wire = Vec::new();
  c.poll_transport_transmit(&mut wire);
  assert!(
    !wire.is_empty(),
    "the client role queues a close_notify alert"
  );
  s.send_close_notify();
  let mut wire2 = Vec::new();
  s.poll_transport_transmit(&mut wire2);
  assert!(
    !wire2.is_empty(),
    "the server role queues a close_notify alert"
  );
  // Once aborted, send_close_notify is a no-op: no panic and nothing further is queued.
  c.clear_outbound();
  c.send_close_notify();
  let mut wire3 = Vec::new();
  assert_eq!(
    c.poll_transport_transmit(&mut wire3),
    0,
    "an aborted layer emits nothing, even after send_close_notify"
  );
}

#[test]
fn a_processed_close_notify_short_circuits_read_tls_on_the_next_feed() {
  // rustls's read_tls short-circuits to Ok(0) once has_received_close_notify is set (without
  // touching the reader), which surfaces as an immediate n==0 break in the intake loop; the
  // re-entrant process() call afterwards still reports the (already-true) closed state.
  let (server, client, name) = test_configs();
  let mut c = TlsRecords::client(client, name).unwrap();
  let mut s = TlsRecords::server(server).unwrap();
  for _ in 0..16 {
    let a = pump(&mut c, &mut s);
    let b = pump(&mut s, &mut c);
    if !a && !b {
      break;
    }
  }
  assert!(!c.is_handshaking() && !s.is_handshaking());
  c.send_close_notify();
  let mut wire = Vec::new();
  c.poll_transport_transmit(&mut wire);
  assert!(!wire.is_empty());
  // First feed: the alert is actually processed, so peer_has_closed flips true.
  assert_eq!(s.handle_transport_data(&wire, Instant::ZERO), Intake::Done);
  assert!(s.peer_has_closed(), "the close_notify was processed");
  // Second feed, with fresh (unrelated) bytes: read_tls now short-circuits to Ok(0) rather than
  // consuming them, and the layer stays a harmless Done, not a failure.
  assert_eq!(
    s.handle_transport_data(b"ignored-after-close", Instant::ZERO),
    Intake::Done,
    "a feed after an already-processed close_notify is a harmless no-op, not a failure"
  );
  assert!(s.peer_has_closed());
}

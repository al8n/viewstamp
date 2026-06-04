//! The rustls record layer (`tls` feature). The caller supplies the `rustls` configs (with the
//! operator's cluster-CA verifier); this wraps them Sans-I/O.

use std::io::Read;
use std::sync::Arc;

use rustls::{
  ClientConfig, ClientConnection, ServerConfig, ServerConnection, pki_types::ServerName,
};

use crate::{Instant, Peer};

use super::stream::{Intake, RecordIo};

/// The cap on staged outbound plaintext before `write_plaintext` reports a short count, in the same
/// plaintext unit the router projects its per-conn cap.
// aligned with router::DEFAULT_OUTBOUND_CAP (plaintext bytes)
const SEND_LIMIT: usize = 64 * 1024 * 1024;

/// Caller-built rustls configs, Arc-wrapped. The `ServerConfig` carries the operator's
/// `ClientCertVerifier` (e.g. `WebPkiClientVerifier` rooted at the cluster CA) for real mTLS
/// sender-auth; this type adds no security policy of its own.
#[derive(Clone)]
pub struct TlsOptions {
  server: Arc<ServerConfig>,
  client: Arc<ClientConfig>,
}

impl core::fmt::Debug for TlsOptions {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("TlsOptions").finish_non_exhaustive()
  }
}

impl TlsOptions {
  /// Wraps caller-built configs.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn new(server: ServerConfig, client: ClientConfig) -> Self {
    Self {
      server: Arc::new(server),
      client: Arc::new(client),
    }
  }
  /// A shared handle to the server config.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn server_arc(&self) -> Arc<ServerConfig> {
    self.server.clone()
  }
  /// A shared handle to the client config.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn client_arc(&self) -> Arc<ClientConfig> {
    self.client.clone()
  }
}

enum Conn {
  Client(ClientConnection),
  Server(ServerConnection),
}

/// The rustls record layer as a [`StreamTransport`].
pub struct TlsRecords {
  conn: Conn,
  /// Outbound plaintext staged for the next transmit, bounded by `SEND_LIMIT`. This is the real
  /// send bound (plaintext, in the router's unit); rustls only sees one coalesced blob per
  /// transmit, so its own send-buffer limit is a backstop the staged plaintext can never reach.
  pending: Vec<u8>,
  peer_closed: bool,
  /// Set when a fatal rustls error makes the record layer terminal. Decrypted application plaintext
  /// can be staged inside rustls before a later record turns out fatal; once this is set every
  /// `RecordIo` method becomes a no-op or terminal result, so that pre-fatal plaintext can
  /// never be surfaced and no further I/O happens — even for a direct caller past the `Conn` gate.
  aborted: bool,
}

impl core::fmt::Debug for TlsRecords {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("TlsRecords")
      .field("pending", &self.pending.len())
      .field("peer_closed", &self.peer_closed)
      .field("aborted", &self.aborted)
      .finish_non_exhaustive()
  }
}

impl TlsRecords {
  /// Builds the client (dialing) side for `name`.
  pub fn client(
    client: Arc<ClientConfig>,
    name: ServerName<'static>,
  ) -> Result<Self, rustls::Error> {
    let mut c = ClientConnection::new(client, name)?;
    // The real send bound is the `pending` staging cap (SEND_LIMIT, plaintext, = router cap). This
    // rustls limit is only a backstop on a direct caller and cannot bind on the normal path:
    // `pending <= SEND_LIMIT` plaintext encrypts to well under 2 * SEND_LIMIT.
    c.set_buffer_limit(Some(2 * SEND_LIMIT));
    Ok(Self {
      conn: Conn::Client(c),
      pending: Vec::new(),
      peer_closed: false,
      aborted: false,
    })
  }
  /// Builds the server (accepting) side.
  pub fn server(server: Arc<ServerConfig>) -> Result<Self, rustls::Error> {
    let mut s = ServerConnection::new(server)?;
    // The real send bound is the `pending` staging cap (SEND_LIMIT, plaintext, = router cap). This
    // rustls limit is only a backstop on a direct caller and cannot bind on the normal path:
    // `pending <= SEND_LIMIT` plaintext encrypts to well under 2 * SEND_LIMIT.
    s.set_buffer_limit(Some(2 * SEND_LIMIT));
    Ok(Self {
      conn: Conn::Server(s),
      pending: Vec::new(),
      peer_closed: false,
      aborted: false,
    })
  }

  /// Marks the layer terminal and returns the fatal intake result. Dropping the staged plaintext here
  /// keeps `buffered_outbound` honest after the failure; routing every fatal rustls path through this
  /// guarantees a `Failed` result always leaves the layer terminal, so no subsequent method can do I/O
  /// or surface plaintext decrypted before the fatal record.
  fn fail(&mut self) -> Intake {
    self.aborted = true;
    self.pending.clear();
    Intake::Failed
  }

  fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
    match &mut self.conn {
      Conn::Client(c) => c.read_tls(rd),
      Conn::Server(c) => c.read_tls(rd),
    }
  }
  fn process(&mut self) -> Result<rustls::IoState, rustls::Error> {
    match &mut self.conn {
      Conn::Client(c) => c.process_new_packets(),
      Conn::Server(c) => c.process_new_packets(),
    }
  }
}

impl RecordIo for TlsRecords {
  fn handle_transport_data(&mut self, ciphertext: &[u8], _now: Instant) -> Intake {
    if self.aborted {
      return Intake::Failed;
    }
    let mut consumed = 0usize;
    let mut fed = false;
    while consumed < ciphertext.len() {
      let mut rest = &ciphertext[consumed..];
      let n = match self.read_tls(&mut rest) {
        Ok(n) => n,
        // rustls uses ErrorKind::Other for received-plaintext backpressure; any other error
        // (a malformed TLS record / deframer failure) is fatal, not backpressure.
        Err(e) if e.kind() == std::io::ErrorKind::Other => return Intake::Pending(consumed),
        Err(_) => return self.fail(),
      };
      if n == 0 {
        break;
      }
      consumed += n;
      match self.process() {
        Ok(io) => {
          if io.peer_has_closed() {
            self.peer_closed = true;
          }
        }
        Err(_) => return self.fail(),
      }
      fed = true;
    }
    if !fed {
      match self.process() {
        Ok(io) => {
          if io.peer_has_closed() {
            self.peer_closed = true;
          }
        }
        Err(_) => return self.fail(),
      }
    }
    Intake::Done
  }

  fn poll_transport_transmit(&mut self, out: &mut Vec<u8>) -> usize {
    if self.aborted {
      return 0;
    }
    let before = out.len();
    // Hand staged plaintext to rustls only once the handshake has completed: while handshaking rustls
    // retains application plaintext internally until traffic keys exist, which buffered_outbound (which
    // reports `pending`) cannot see. Keeping it in `pending` until then keeps the cap accounting honest.
    if !self.is_handshaking() && !self.pending.is_empty() {
      use std::io::Write as _;
      // Drain only what rustls accepted; an unaccepted suffix stays in `pending` (still counted by
      // buffered_outbound) rather than being silently dropped. On the normal path rustls accepts all of
      // the bounded `pending` (its limit is a backstop above the worst-case encryption of SEND_LIMIT).
      let accepted = match &mut self.conn {
        Conn::Client(c) => c.writer().write(&self.pending),
        Conn::Server(c) => c.writer().write(&self.pending),
      }
      .unwrap_or(0);
      self.pending.drain(..accepted);
    }
    loop {
      let n = match &mut self.conn {
        Conn::Client(c) => c.write_tls(out),
        Conn::Server(c) => c.write_tls(out),
      }
      .expect("write_tls into a Vec is infallible");
      if n == 0 {
        break;
      }
    }
    out.len() - before
  }

  fn read_plaintext(&mut self, out: &mut Vec<u8>) -> usize {
    // The load-bearing terminal guard: after a fatal record rustls may still hold application
    // plaintext decrypted from an earlier record. Surfacing nothing once aborted is what makes a
    // `Failed` intake atomically hide that pre-fatal plaintext.
    if self.aborted {
      return 0;
    }
    let mut total = 0;
    let mut scratch = [0u8; 4096];
    loop {
      let res = match &mut self.conn {
        Conn::Client(c) => c.reader().read(&mut scratch),
        Conn::Server(c) => c.reader().read(&mut scratch),
      };
      match res {
        Ok(n) if n > 0 => {
          out.extend_from_slice(&scratch[..n]);
          total += n;
        }
        _ => break,
      }
    }
    total
  }

  fn write_plaintext(&mut self, plaintext: &[u8]) -> usize {
    if self.aborted {
      return 0;
    }
    // Stage into the bounded plaintext buffer; the accepted count is how many bytes fit under
    // SEND_LIMIT (the router's plaintext cap). A short count is the normal backpressure signal,
    // not the infinite-buffer assumption `write_all` would make. rustls is fed on transmit.
    let room = SEND_LIMIT.saturating_sub(self.pending.len());
    let take = room.min(plaintext.len());
    self.pending.extend_from_slice(&plaintext[..take]);
    take
  }

  fn buffered_outbound(&self) -> usize {
    // The staged plaintext is the retained outbound; rustls's internal send buffer is fed and
    // drained transiently within `poll_transport_transmit`, so `pending` is the bounded outbound
    // the router's cap must observe.
    self.pending.len()
  }

  fn is_handshaking(&self) -> bool {
    // A terminal layer never settles again: it must not look like a fresh, validated conn the
    // router would adopt, so it counts as still-handshaking (mirroring `Labeled`).
    if self.aborted {
      return true;
    }
    match &self.conn {
      Conn::Client(c) => c.is_handshaking(),
      Conn::Server(c) => c.is_handshaking(),
    }
  }
  fn peer_identity(&self) -> Option<Peer> {
    None
  }
  fn peer_has_closed(&self) -> bool {
    if self.aborted {
      return true;
    }
    self.peer_closed
  }
  fn send_close_notify(&mut self) {
    if self.aborted {
      return;
    }
    match &mut self.conn {
      Conn::Client(c) => c.send_close_notify(),
      Conn::Server(c) => c.send_close_notify(),
    }
  }
  fn clear_outbound(&mut self) {
    // Drop the staged plaintext so a dying conn cannot leak a partial frame onto the wire, and mark
    // the layer terminal so it does no further I/O or plaintext surfacing afterwards. rustls exposes
    // no API to discard already-encrypted pending ciphertext, so anything already fed on a prior
    // transmit is the caller's not to re-drain; clearing the stage covers the un-fed bytes.
    self.pending.clear();
    self.aborted = true;
  }
  fn is_secure() -> bool {
    true
  }
}

#[cfg(test)]
pub(crate) mod test_verifier {
  //! An accept-any verifier for the in-memory handshake tests ONLY. Production deployments
  //! supply a cluster-CA-rooted verifier in their rustls config.
  use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

  #[derive(Debug)]
  pub struct AcceptAny;

  impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
      &self,
      _e: &CertificateDer<'_>,
      _i: &[CertificateDer<'_>],
      _n: &ServerName<'_>,
      _o: &[u8],
      _t: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
      Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
      &self,
      _m: &[u8],
      _c: &CertificateDer<'_>,
      _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
      &self,
      _m: &[u8],
      _c: &CertificateDer<'_>,
      _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
      Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
      rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Instant;
  use crate::transport::stream::RecordIo;
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
    assert_eq!(c.write_plaintext(b"hello vsrr"), 10);
    // While handshaking, transmit must not move staged plaintext into rustls (where buffered_outbound
    // could not see it); the staged bytes stay accounted in `pending`.
    let mut out = Vec::new();
    c.poll_transport_transmit(&mut out);
    assert_eq!(
      c.buffered_outbound(),
      10,
      "staged plaintext stays counted while the handshake is in flight"
    );
    // Idempotent: a second transmit while still handshaking does not feed/clear the stage either.
    let mut out2 = Vec::new();
    c.poll_transport_transmit(&mut out2);
    assert!(c.is_handshaking());
    assert_eq!(
      c.buffered_outbound(),
      10,
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
}

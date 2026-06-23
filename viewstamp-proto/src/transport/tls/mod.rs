//! The rustls record layer (`tls` feature). The caller supplies the `rustls` configs (with the
//! operator's cluster-CA verifier); this wraps them Sans-I/O.

use std::{io::Read, sync::Arc};

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

/// The rustls record layer as a [`StreamTransport`](super::StreamTransport).
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
    // `write_tls` drains ALL of rustls's queued output — handshake records included, not just the
    // encrypted application plaintext above. So handshake bytes flow through this same transmit path
    // and are counted in the driver's per-conn `queued_bytes` (bounded by its always-admit-one rule),
    // not bypassed. The handshake is small and bounded, so no extra accounting is needed.
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
pub(crate) mod test_verifier;

#[cfg(test)]
mod tests;

//! The byte-record seam: a pluggable record layer under the per-socket [`Conn`](super::Conn).

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use crate::{Instant, Peer};

/// The outcome of feeding one transport read to a `RecordIo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
pub enum Intake {
  /// The input was fully consumed; the record layer made progress.
  Done,
  /// `n` input bytes were consumed but the record layer is back-pressured (e.g. rustls's
  /// 16 KiB received-plaintext limit). The caller drains plaintext, then re-feeds the tail.
  Pending(usize),
  /// A terminal record-layer reject (TLS handshake failure / decrypt error).
  Failed,
}

/// The crate-internal record-layer I/O contract: raw passthrough, the cluster+identity handshake
/// decorator, or the TLS record layer. Sans-I/O — it transforms bytes and never touches a socket.
///
/// Mirrors `memberlist-proto`'s record-layer seam. Outbound app plaintext goes in via
/// [`write_plaintext`](Self::write_plaintext); the wire bytes come out via
/// [`poll_transport_transmit`](Self::poll_transport_transmit). Inbound wire bytes go in via
/// [`handle_transport_data`](Self::handle_transport_data); decrypted plaintext comes out via
/// [`read_plaintext`](Self::read_plaintext).
///
/// This trait carries only the per-read I/O contract; the record layers are *constructed* through
/// their own public inherent constructors ([`Passthrough::new`](super::Passthrough::new),
/// [`TlsRecords::client`](super::TlsRecords)/`server`, [`Labeled::dialer`](super::Labeled)/`acceptor`),
/// so a downstream driver can build a [`Conn`](super::Conn) without naming this trait.
///
/// The trait is `pub(crate)`: only this crate's record layers can name and implement it, so the
/// byte-level I/O is reachable only through the [`Conn`](super::Conn) state machine. An out-of-crate
/// type can neither call these methods nor implement the trait, leaving the [`Conn`] the sole
/// possible driver of a record layer. The public [`StreamTransport`] marker is auto-implemented for
/// every `RecordIo`, so a driver names `Conn<R: StreamTransport>` without ever naming this contract.
pub(crate) trait RecordIo: Sized {
  /// Feeds one inbound transport read at `now`. Returns how much was consumed / a terminal reject.
  fn handle_transport_data(&mut self, input: &[u8], now: Instant) -> Intake;
  /// Drains queued outbound wire bytes into `out`; returns the byte count appended.
  fn poll_transport_transmit(&mut self, out: &mut Vec<u8>) -> usize;
  /// Drains decrypted inbound plaintext into `out`; returns the byte count appended.
  fn read_plaintext(&mut self, out: &mut Vec<u8>) -> usize;
  /// Queues application plaintext for sending (the record layer encrypts/frames it). Returns how
  /// many leading bytes were accepted into the bounded outbound buffer, like `io::Write::write`. A
  /// return less than `plaintext.len()` means the outbound buffer is full; the caller must treat
  /// that as terminal — the record layer does not partially frame the wire from a short write.
  fn write_plaintext(&mut self, plaintext: &[u8]) -> usize;

  /// The number of plaintext bytes currently queued for transmit in this record layer's outbound
  /// buffer (including any handshake prefix it queued itself). The single source of truth for the
  /// router's outbound cap, so nothing queued in the record layer escapes the cap accounting.
  fn buffered_outbound(&self) -> usize;

  /// True until the record layer + handshake have settled. While true, [`Conn`](super::Conn)
  /// yields no `Message` (the acceptor gate).
  fn is_handshaking(&self) -> bool;
  /// The peer identity proven by the handshake, once settled. `None` for raw layers
  /// ([`Passthrough`](super::Passthrough)/[`TlsRecords`](super::TlsRecords)); the
  /// [`Labeled`](super::Labeled) decorator surfaces the validated claimed [`Peer`].
  fn peer_identity(&self) -> Option<Peer> {
    None
  }
  /// True once the peer's clean close was observed in-band (TLS `close_notify`); always
  /// false for layers whose close is out-of-band (plain TCP — the driver's `read == 0`).
  fn peer_has_closed(&self) -> bool;
  /// Queues a graceful close (TLS `close_notify`); a no-op where close is out-of-band. A finalized
  /// [`Conn`](super::Conn) is immediately `Closed` (it transmits nothing more) and the router reaps a
  /// closed conn before the next transmit, so a queued close-notify has no drain path without a
  /// deferred-reap/farewell-flush mechanism; the driver closes the socket out-of-band instead. Wired
  /// once that flush path exists.
  #[allow(dead_code)]
  fn send_close_notify(&mut self);
  /// Discards queued outbound on a failure/abort so a dying conn can't leak a partial frame
  /// or the local handshake prefix onto the wire.
  fn clear_outbound(&mut self);

  /// Compile-time constant: true when the layer already provides confidentiality (TLS). Surfaced to a
  /// driver through [`Conn::is_secure`](super::Conn::is_secure) ("is this connection encrypted") and
  /// lets a future application-encryption decorator skip double-encryption.
  fn is_secure() -> bool;
}

/// A pluggable per-socket record layer: raw passthrough, the cluster+identity handshake decorator,
/// or the TLS record layer. A driver names `Conn<R: StreamTransport>` and constructs record layers
/// through their public inherent constructors, but the byte-level I/O contract lives on the
/// crate-internal `RecordIo` supertrait.
///
/// The trait is **sealed**: its supertrait `RecordIo` is `pub(crate)` and cannot be named outside
/// this crate, so no out-of-crate type can implement `StreamTransport` (and none can call the
/// crate-internal I/O methods), leaving the [`Conn`](super::Conn) the sole possible driver of a
/// record layer. Even a complete out-of-crate impl is rejected:
///
/// ```compile_fail
/// use viewstamp_proto::StreamTransport;
/// struct Evil;
/// // Fails: `StreamTransport` has a supertrait (`RecordIo`) that is `pub(crate)` and cannot be
/// // named or implemented outside the crate, so no downstream type can implement it.
/// impl StreamTransport for Evil {}
/// ```
///
/// Construction stays open, though: a downstream driver builds the concrete record layers and a
/// [`Conn`](super::Conn) over them from the public inherent constructors — only the I/O is sealed.
///
/// ```
/// use viewstamp_proto::{Conn, Labeled, LabelOptions, Passthrough, Peer, ReplicaId};
/// let opts = LabelOptions::new(0xABCD, Peer::Replica(ReplicaId::new(0)));
/// // The driver builds the inner record layer concretely, then wraps it in the labeled handshake.
/// let _dialer = Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts));
/// let _acceptor = Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts));
/// ```
#[allow(private_bounds)]
pub trait StreamTransport: RecordIo {}
impl<T: RecordIo> StreamTransport for T {}

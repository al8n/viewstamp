//! The persistent per-socket pipe: a record layer + framing, with an explicit lifecycle that gates
//! all application I/O. A conn decodes and sends application frames only while `Validated`, and
//! performs no I/O once `Closed`; the router drives the `Handshaking -> Validated` transition after
//! it has confirmed the conn's authenticated identity.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use crate::{Instant, Message, Peer};

use super::TransportError;
use super::frame::{FrameDecoder, MAX_FRAME_LEN};
use super::stream::{Intake, StreamTransport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  /// The record/identity handshake has not settled, or the router has not yet validated the peer
  /// identity. Only handshake bytes flow; no application frames are decoded or sent.
  Handshaking,
  /// Identity validated and bound; application frames flow.
  Validated,
  /// Terminal: no I/O of any kind, awaiting reap.
  Closed,
}

/// A long-lived per-peer connection: drives the record layer, frames `Message`s, and gates all
/// application I/O behind its validated identity.
#[derive(Debug)]
pub struct Conn<R> {
  r: R,
  decoder: FrameDecoder,
  from: Option<Peer>,
  scratch: Vec<u8>,
  state: State,
  peer_finished: bool,
}

impl<R: StreamTransport> Conn<R> {
  /// Wraps a freshly-constructed record layer (starts `Handshaking`).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn from_parts(r: R) -> Self {
    Self {
      r,
      decoder: FrameDecoder::new(MAX_FRAME_LEN),
      from: None,
      scratch: Vec::new(),
      state: State::Handshaking,
      peer_finished: false,
    }
  }

  /// True once this conn is terminal.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) const fn is_closed(&self) -> bool {
    matches!(self.state, State::Closed)
  }

  /// True once the conn's identity has been validated and bound (application frames flow).
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) const fn is_validated(&self) -> bool {
    matches!(self.state, State::Validated)
  }

  /// True while the record/identity handshake is still settling. The router waits for this to fall
  /// before validating the conn.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn is_handshaking(&self) -> bool {
    self.r.is_handshaking()
  }

  /// The identity the record layer authenticated once the handshake settles (`None` for a
  /// no-identity transport, whose trusted identity is supplied by the router's registration).
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn handshake_identity(&self) -> Option<Peer> {
    self.r.peer_identity()
  }

  /// Transitions the conn to `Validated` with the bound identity. Driven by the router after it
  /// confirms the handshake identity against the registration. No-op unless currently `Handshaking`.
  pub(crate) fn mark_validated(&mut self, identity: Peer) {
    if matches!(self.state, State::Handshaking) {
      self.from = Some(identity);
      self.state = State::Validated;
    }
  }

  /// Aborts the conn: discards queued outbound and makes it terminal.
  pub(crate) fn abort(&mut self) {
    self.r.clear_outbound();
    self.state = State::Closed;
  }

  /// Forces the closed state, for tests of the router's canonical-conn discipline.
  #[cfg(test)]
  pub(crate) fn mark_closed_for_test(&mut self) {
    self.state = State::Closed;
  }

  /// Feeds one inbound transport read: advances the record layer and buffers decrypted plaintext.
  /// Does NOT decode application frames (that is `poll_decoded`, gated on `Validated`). A closed
  /// conn consumes nothing. `eof` is the driver's `read == 0`. Returns `Ok(peer_finished)`; an `Err`
  /// makes the conn terminal. The caller (`StreamCoordinator`) feeds input in bounded chunks and
  /// decodes between them, so the transport's intake staging stays bounded.
  pub(crate) fn handle_data(
    &mut self,
    bytes: &[u8],
    eof: bool,
    now: Instant,
  ) -> Result<bool, TransportError> {
    if matches!(self.state, State::Closed) {
      return Ok(true);
    }
    let mut off = 0;
    loop {
      match self.r.handle_transport_data(&bytes[off..], now) {
        Intake::Failed => {
          self.state = State::Closed;
          return Err(TransportError::RecordRejected);
        }
        Intake::Done => {
          if let Err(e) = self.buffer_plaintext() {
            self.state = State::Closed;
            return Err(e);
          }
          break;
        }
        Intake::Pending(n) => {
          off += n;
          let drained = match self.buffer_plaintext() {
            Ok(d) => d,
            Err(e) => {
              self.state = State::Closed;
              return Err(e);
            }
          };
          if n == 0 && !drained {
            if self.r.is_handshaking() {
              self.state = State::Closed;
              return Err(TransportError::RecordRejected);
            }
            break;
          }
        }
      }
    }
    let fin = eof || self.r.peer_has_closed();
    if fin {
      self.peer_finished = true;
    }
    Ok(fin)
  }

  /// Drains decrypted plaintext into the frame decoder. Returns whether any was drained; an
  /// over-cap declared frame length propagates out as an error.
  fn buffer_plaintext(&mut self) -> Result<bool, TransportError> {
    self.scratch.clear();
    self.r.read_plaintext(&mut self.scratch);
    let drained = !self.scratch.is_empty();
    if drained {
      let chunk = core::mem::take(&mut self.scratch);
      let res = self.decoder.extend(&chunk);
      self.scratch = chunk;
      self.scratch.clear();
      res?;
    }
    Ok(drained)
  }

  /// Finalizes a peer-finished conn AFTER its complete buffered frames have been drained: closes it,
  /// reporting truncation only if a partial frame remains.
  pub(crate) fn finalize(&mut self) -> Result<(), TransportError> {
    if matches!(self.state, State::Closed) {
      return Ok(());
    }
    let remaining = self.decoder.partial_len();
    self.state = State::Closed;
    if remaining > 0 {
      Err(TransportError::TruncatedFrame { remaining })
    } else {
      Ok(())
    }
  }

  /// Decodes buffered application frames into `(from, Message)` pairs — only while `Validated`, so a
  /// conn never delivers application frames before its identity is validated or after it closes. An
  /// undecodable or oversized frame makes the conn terminal.
  pub(crate) fn poll_decoded(
    &mut self,
    out: &mut Vec<(Peer, Message)>,
  ) -> Result<(), TransportError> {
    if !matches!(self.state, State::Validated) {
      return Ok(());
    }
    let from = match self.from {
      Some(p) => p,
      None => return Ok(()),
    };
    while let Some(frame) = self.decoder.next_frame() {
      match Message::decode(&frame) {
        Ok(msg) => out.push((from, msg)),
        Err(e) => {
          self.state = State::Closed;
          return Err(TransportError::from(e));
        }
      }
    }
    Ok(())
  }

  /// Queues an already-framed application payload — only while `Validated` (a closed or unvalidated
  /// conn is never an application-send target). The router only calls this when its projective
  /// outbound cap guarantees the frame fits, so on the normal path the record layer accepts the
  /// whole frame. A short write means the bounded outbound is full (a direct/out-of-contract caller
  /// or a mis-sized cap), which is terminal: the conn closes so no partial frame is ever
  /// transmitted (`poll_transmit` yields nothing once `Closed` and the buffer is dropped on reap),
  /// and per-conn outbound memory cannot grow without bound through any record layer.
  ///
  /// Returns `true` if this call closed the conn (a short write), so the router can fold a
  /// route-time short-write close into the same reap pass as an outbound-cap overflow.
  pub(crate) fn write_framed(&mut self, framed: &[u8]) -> bool {
    if !matches!(self.state, State::Validated) {
      return false;
    }
    let accepted = self.r.write_plaintext(framed);
    if accepted < framed.len() {
      self.state = State::Closed;
      return true;
    }
    false
  }

  /// Whether the record layer provides confidentiality on the wire (TLS yes, raw/passthrough no).
  /// A driver-facing "is this connection encrypted" query, surfacing the record layer's compile-time
  /// security property.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn is_secure(&self) -> bool {
    R::is_secure()
  }

  /// The record layer's actual buffered outbound size — the single source of truth for the router's
  /// outbound cap. Querying the record layer (rather than a parallel Conn-side counter) counts
  /// everything queued there, including a handshake prefix the layer queued itself, so the cap check
  /// can never drift from the real buffer.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn queued_outbound(&self) -> usize {
    self.r.buffered_outbound()
  }

  /// Drains queued outbound wire bytes (handshake bytes flow while `Handshaking`; nothing once
  /// `Closed`). The record layer drains everything to the driver.
  pub(crate) fn poll_transmit(&mut self, out: &mut Vec<u8>) -> usize {
    if matches!(self.state, State::Closed) {
      return 0;
    }
    self.r.poll_transport_transmit(out)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::message::Request;
  use crate::transport::frame::encode_frame;
  use crate::transport::stream::RecordIo;
  use crate::{ClientId, Instant, Message, Peer, ReplicaId, RequestNumber};

  fn req_msg() -> Message {
    Message::Request(Request::new(
      ClientId::new(1),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"x"),
    ))
  }

  /// A record layer that buffers input as plaintext and surfaces at most `chunk` bytes per
  /// `read_plaintext`, returning `Pending` while more than `chunk` remains buffered (to drive
  /// the Conn Intake loop), else `Done`. `chunk = usize::MAX` => always `Done`, drains fully.
  struct FakeRecords {
    buf: Vec<u8>,
    outbound: usize,
    chunk: usize,
    handshaking: bool,
    from: Peer,
  }
  impl FakeRecords {
    fn new(chunk: usize, from: Peer) -> Self {
      Self {
        buf: Vec::new(),
        outbound: 0,
        chunk,
        handshaking: false,
        from,
      }
    }
  }
  impl RecordIo for FakeRecords {
    fn handle_transport_data(&mut self, input: &[u8], _: Instant) -> Intake {
      self.buf.extend_from_slice(input);
      if self.buf.len() > self.chunk {
        Intake::Pending(input.len())
      } else {
        Intake::Done
      }
    }
    fn poll_transport_transmit(&mut self, _: &mut Vec<u8>) -> usize {
      let n = self.outbound;
      self.outbound = 0;
      n
    }
    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> usize {
      let n = self.buf.len().min(self.chunk);
      out.extend_from_slice(&self.buf[..n]);
      self.buf.drain(..n);
      n
    }
    fn write_plaintext(&mut self, plaintext: &[u8]) -> usize {
      self.outbound += plaintext.len();
      plaintext.len()
    }
    fn buffered_outbound(&self) -> usize {
      self.outbound
    }
    fn is_handshaking(&self) -> bool {
      self.handshaking
    }
    fn peer_identity(&self) -> Option<Peer> {
      Some(self.from)
    }
    fn peer_has_closed(&self) -> bool {
      false
    }
    fn send_close_notify(&mut self) {}
    fn clear_outbound(&mut self) {}
    fn is_secure() -> bool {
      false
    }
  }

  #[test]
  fn decodes_two_messages_from_one_read() {
    let from = Peer::Replica(ReplicaId::new(2));
    let mut frames = Vec::new();
    encode_frame(&req_msg().encode(), &mut frames);
    encode_frame(&req_msg().encode(), &mut frames);
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    let closed = conn.handle_data(&frames, false, Instant::ZERO).unwrap();
    assert!(!closed);
    let mut out = Vec::new();
    conn.poll_decoded(&mut out).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].0, from);
  }

  #[test]
  fn intake_pending_loop_reassembles_a_large_frame() {
    let from = Peer::Replica(ReplicaId::new(0));
    let mut frame = Vec::new();
    encode_frame(&req_msg().encode(), &mut frame);
    // chunk smaller than the frame forces multiple Pending iterations.
    let mut conn = Conn::from_parts(FakeRecords::new(4, from));
    conn.mark_validated(from);
    let closed = conn.handle_data(&frame, false, Instant::ZERO).unwrap();
    assert!(!closed);
    let mut out = Vec::new();
    conn.poll_decoded(&mut out).unwrap();
    assert_eq!(
      out.len(),
      1,
      "the frame reassembles across Pending iterations"
    );
  }

  #[test]
  fn mid_frame_eof_is_truncation() {
    let from = Peer::Replica(ReplicaId::new(0));
    let mut frame = Vec::new();
    encode_frame(&req_msg().encode(), &mut frame);
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    // EOF mid-frame: the peer finished but the conn is not yet closed; finalize reports truncation.
    let fin = conn.handle_data(&frame[..3], true, Instant::ZERO).unwrap();
    assert!(fin);
    assert!(!conn.is_closed());
    let err = conn.finalize().unwrap_err();
    assert!(matches!(err, TransportError::TruncatedFrame { .. }));
    assert!(conn.is_closed());
  }

  #[test]
  fn a_complete_final_frame_is_delivered_then_closed() {
    let from = Peer::Replica(ReplicaId::new(0));
    let mut frame = Vec::new();
    encode_frame(&req_msg().encode(), &mut frame);
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    // A complete frame arrives in the SAME read that signals EOF.
    let fin = conn.handle_data(&frame, true, Instant::ZERO).unwrap();
    assert!(fin);
    assert!(
      !conn.is_closed(),
      "close is deferred until frames are drained"
    );
    let mut out = Vec::new();
    conn.poll_decoded(&mut out).unwrap();
    assert_eq!(out.len(), 1, "the final frame is delivered, not dropped");
    assert_eq!(out[0].0, from);
    conn.finalize().unwrap();
    assert!(conn.is_closed());
  }

  #[test]
  fn an_oversized_frame_closes_the_conn() {
    let from = Peer::Replica(ReplicaId::new(0));
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    let mut bad = Vec::new();
    bad.extend_from_slice(&u32::MAX.to_be_bytes()); // a frame header claiming a huge length
    // The over-cap declared length is rejected at intake, before any body can accumulate.
    let err = conn.handle_data(&bad, false, Instant::ZERO).unwrap_err();
    assert!(matches!(err, TransportError::FrameTooLong { .. }));
    assert!(
      conn.is_closed(),
      "an oversized frame must close the conn so it gets reaped"
    );
  }

  #[test]
  fn an_oversized_frame_in_a_large_read_is_rejected() {
    let from = Peer::Replica(ReplicaId::new(0));
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    let mut huge = Vec::new();
    huge.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes()); // over-cap declared length
    huge.extend_from_slice(&std::vec![0u8; 200 * 1024]); // a large trailing body
    let err = conn.handle_data(&huge, false, Instant::ZERO).unwrap_err();
    assert!(matches!(err, TransportError::FrameTooLong { .. }));
    assert!(
      conn.is_closed(),
      "the oversized frame is rejected and the conn closed"
    );
  }

  #[test]
  fn a_zero_length_frame_closes_the_conn_on_decode() {
    let from = Peer::Replica(ReplicaId::new(0));
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    let mut zeros = Vec::new();
    zeros.extend_from_slice(&0u32.to_be_bytes()); // a single zero-length frame
    conn.handle_data(&zeros, false, Instant::ZERO).unwrap();
    let mut out = Vec::new();
    assert!(
      conn.poll_decoded(&mut out).is_err(),
      "an empty frame fails to decode"
    );
    assert!(conn.is_closed());
  }

  #[test]
  fn many_frames_in_one_read_all_decode() {
    let from = Peer::Replica(ReplicaId::new(1));
    // A single read carrying many small frames buffers them all; poll_decoded yields every one.
    let mut frames = Vec::new();
    let count = 2000;
    for _ in 0..count {
      encode_frame(&req_msg().encode(), &mut frames);
    }
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.mark_validated(from);
    conn.handle_data(&frames, false, Instant::ZERO).unwrap();
    let mut out = Vec::new();
    conn.poll_decoded(&mut out).unwrap();
    assert_eq!(out.len(), count, "every frame in the read is decoded");
  }

  #[test]
  fn handshake_gate_blocks_decode() {
    // A conn that was never validated buffers plaintext but decodes nothing.
    let from = Peer::Replica(ReplicaId::new(0));
    let mut frames = Vec::new();
    encode_frame(&req_msg().encode(), &mut frames);
    let mut conn = Conn::from_parts(FakeRecords::new(usize::MAX, from));
    conn.handle_data(&frames, false, Instant::ZERO).unwrap();
    let mut out = Vec::new();
    conn.poll_decoded(&mut out).unwrap();
    assert!(out.is_empty(), "no Message decoded while still Handshaking");
  }

  #[test]
  fn a_short_write_closes_the_conn() {
    use crate::transport::testutil::MockRecords;
    let from = Peer::Replica(ReplicaId::new(0));
    let mut frame = Vec::new();
    encode_frame(&req_msg().encode(), &mut frame);
    // Cap the record layer below the frame so write_framed short-writes (the out-of-contract path
    // the router's projective cap normally prevents).
    let records = MockRecords::new(false, Some(from)).with_write_cap(frame.len() - 1);
    let mut conn = Conn::from_parts(records);
    conn.mark_validated(from);
    conn.write_framed(&frame);
    assert!(
      conn.is_closed(),
      "a short write is terminal: the conn closes so no partial frame is transmitted"
    );
    let mut out = Vec::new();
    assert_eq!(
      conn.poll_transmit(&mut out),
      0,
      "a closed conn transmits nothing — the partial bytes never reach the wire"
    );
  }

  #[test]
  fn queued_outbound_counts_a_labeled_handshake_hello() {
    use crate::{LabelOptions, Labeled, Passthrough};
    const CLUSTER: u128 = 0xABCD;
    let a_id = Peer::Replica(ReplicaId::new(0));
    let d_id = Peer::Replica(ReplicaId::new(7));

    // A standalone dialer with the acceptor's identity tells us how many bytes the acceptor's own
    // hello occupies once queued into its inner layer (the eager dialer flush is the same encoding).
    let acceptor_hello_len = {
      let probe: Labeled<Passthrough> =
        Labeled::dialer(Passthrough::new(), &LabelOptions::new(CLUSTER, a_id));
      probe.buffered_outbound()
    };
    assert!(acceptor_hello_len > 0, "a hello is non-empty");

    // The remote dialer's hello bytes, to drive the acceptor through validation.
    let dialer_wire = {
      let mut dialer: Labeled<Passthrough> =
        Labeled::dialer(Passthrough::new(), &LabelOptions::new(CLUSTER, d_id));
      let mut wire = Vec::new();
      dialer.poll_transport_transmit(&mut wire);
      wire
    };

    let acceptor: Labeled<Passthrough> =
      Labeled::acceptor(Passthrough::new(), &LabelOptions::new(CLUSTER, a_id));
    let mut conn = Conn::from_parts(acceptor);
    assert_eq!(
      conn.queued_outbound(),
      0,
      "an acceptor has not queued its hello before it validates the remote"
    );
    // Feeding the dialer hello makes the acceptor validate the peer and queue its own hello into the
    // inner layer — which queued_outbound() now observes via the record layer's real buffer.
    conn
      .handle_data(&dialer_wire, false, Instant::ZERO)
      .unwrap();
    assert!(
      conn.queued_outbound() >= acceptor_hello_len,
      "queued_outbound reflects the acceptor's queued handshake hello, not a separate counter"
    );
  }

  #[test]
  fn a_bound_raw_conn_decodes_inbound_with_the_bound_peer() {
    let mut conn = Conn::from_parts(crate::Passthrough::new());
    let who = Peer::Replica(ReplicaId::new(3));
    conn.mark_validated(who); // the router validates + binds the trusted identity
    let mut frames = Vec::new();
    encode_frame(&req_msg().encode(), &mut frames);
    conn.handle_data(&frames, false, Instant::ZERO).unwrap();
    let mut out = Vec::new();
    conn.poll_decoded(&mut out).unwrap();
    assert_eq!(out.len(), 1, "a bound raw conn decodes inbound frames");
    assert_eq!(out[0].0, who, "inbound is tagged with the bound peer");
  }
}

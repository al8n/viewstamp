//! The persistent per-socket pipe: a record layer + framing, with an explicit lifecycle that gates
//! all application I/O. A conn decodes and sends application frames only while `Validated`, and
//! performs no I/O once `Closed`; the router drives the `Handshaking -> Validated` transition after
//! it has confirmed the conn's authenticated identity.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use bytes::Bytes;

use crate::{Instant, Message, Peer, decode_message};

use super::{
  CloseCause, TransportError,
  frame::{FrameDecoder, MAX_FRAME_LEN},
  stream::{Intake, StreamTransport},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  /// The record/identity handshake has not settled, or the router has not yet validated the peer
  /// identity. Only handshake bytes flow; no application frames are decoded or sent.
  Handshaking,
  /// Identity validated and bound; application frames flow.
  Validated,
  /// Terminal: no I/O of any kind, awaiting reap. Carries WHY the conn closed, recorded at the
  /// transition itself so every close has a cause by construction — the router's reap reads it out
  /// for the driver without any close path having to thread an error value through.
  Closed(CloseCause),
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
    matches!(self.state, State::Closed(_))
  }

  /// Why this conn closed — `Some` iff it is terminal (the cause rides the `Closed` state).
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) const fn close_cause(&self) -> Option<CloseCause> {
    match self.state {
      State::Closed(cause) => Some(cause),
      _ => None,
    }
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

  /// Aborts the conn for `cause`: discards queued outbound and makes it terminal.
  pub(crate) fn abort(&mut self, cause: CloseCause) {
    self.r.clear_outbound();
    self.state = State::Closed(cause);
  }

  /// Forces the closed state, for tests of the router's canonical-conn discipline.
  #[cfg(test)]
  pub(crate) fn mark_closed_for_test(&mut self) {
    self.state = State::Closed(CloseCause::PeerClosed);
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
    if self.is_closed() {
      return Ok(true);
    }
    let mut off = 0;
    loop {
      match self.r.handle_transport_data(&bytes[off..], now) {
        Intake::Failed => {
          self.state = State::Closed(CloseCause::RecordRejected);
          return Err(TransportError::RecordRejected);
        }
        Intake::Done => {
          if let Err(e) = self.buffer_plaintext() {
            self.state = State::Closed(CloseCause::from(&e));
            return Err(e);
          }
          break;
        }
        Intake::Pending(n) => {
          off += n;
          let drained = match self.buffer_plaintext() {
            Ok(d) => d,
            Err(e) => {
              self.state = State::Closed(CloseCause::from(&e));
              return Err(e);
            }
          };
          if n == 0 && !drained {
            if self.r.is_handshaking() {
              self.state = State::Closed(CloseCause::RecordRejected);
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
    if self.is_closed() {
      return Ok(());
    }
    let remaining = self.decoder.partial_len();
    if remaining > 0 {
      self.state = State::Closed(CloseCause::TruncatedFrame);
      Err(TransportError::TruncatedFrame { remaining })
    } else {
      self.state = State::Closed(CloseCause::PeerClosed);
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
      match decode_message(Bytes::from(frame)) {
        Ok(msg) => out.push((from, msg)),
        Err(e) => {
          let e = TransportError::from(e);
          self.state = State::Closed(CloseCause::from(&e));
          return Err(e);
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
      self.state = State::Closed(CloseCause::OutboundOverflow);
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
    if self.is_closed() {
      return 0;
    }
    self.r.poll_transport_transmit(out)
  }
}

#[cfg(test)]
mod tests;

//! A trivial raw byte pipe — the `tcp`-tier record layer with no crypto and no handshake.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use crate::Instant;

use super::stream::{Intake, RecordIo};

/// A transparent record layer: inbound wire bytes ARE the plaintext, outbound plaintext IS
/// the wire. No confidentiality, no handshake.
///
/// Its byte buffers are bounded per direction so a caller cannot grow them without limit:
/// inbound intake applies [`Intake::Pending`] backpressure at `RECV_LIMIT`, and outbound
/// plaintext is capped at `SEND_LIMIT`. Normally the record layer is driven by
/// [`StreamCoordinator`](super::StreamCoordinator), which already bounds intake by feeding fixed
/// chunks and bounds outbound via the router cap, so neither limit trips on that path; they only
/// guard a caller that drives the public record-layer methods directly.
#[derive(Debug, Default)]
pub struct Passthrough {
  outbound: Vec<u8>,
  inbound: Vec<u8>,
}

/// The most decrypted plaintext `Passthrough` buffers inbound before applying backpressure. Larger
/// than the coordinator's intake chunk so the normal path never trips it; it only bounds a caller
/// that drives the record layer directly, bypassing the coordinator's chunked intake.
const RECV_LIMIT: usize = 256 * 1024;
/// The most plaintext `Passthrough` buffers outbound before `write_plaintext` reports a short
/// accepted count. The router's projective outbound cap aborts a conn before this on the normal
/// path; it only bounds a direct caller, which must treat the short count as terminal.
const SEND_LIMIT: usize = 64 * 1024 * 1024;

impl Passthrough {
  /// Creates an empty passthrough pipe.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn new() -> Self {
    Self {
      outbound: Vec::new(),
      inbound: Vec::new(),
    }
  }
}

impl RecordIo for Passthrough {
  fn handle_transport_data(&mut self, input: &[u8], _now: Instant) -> Intake {
    let room = RECV_LIMIT.saturating_sub(self.inbound.len());
    let take = room.min(input.len());
    self.inbound.extend_from_slice(&input[..take]);
    if take < input.len() {
      // The inbound buffer is full: signal backpressure so the caller drains `read_plaintext` and
      // re-feeds the unconsumed tail (the `Conn` Intake loop does this).
      Intake::Pending(take)
    } else {
      Intake::Done
    }
  }
  fn poll_transport_transmit(&mut self, out: &mut Vec<u8>) -> usize {
    let n = self.outbound.len();
    out.append(&mut self.outbound);
    n
  }
  fn read_plaintext(&mut self, out: &mut Vec<u8>) -> usize {
    let n = self.inbound.len();
    out.append(&mut self.inbound);
    n
  }
  fn write_plaintext(&mut self, plaintext: &[u8]) -> usize {
    let room = SEND_LIMIT.saturating_sub(self.outbound.len());
    let take = room.min(plaintext.len());
    self.outbound.extend_from_slice(&plaintext[..take]);
    // The accepted count is the backpressure signal: `take < plaintext.len()` means the cap is hit
    // and the caller must treat it as a short write rather than silently losing the remainder.
    take
  }

  fn buffered_outbound(&self) -> usize {
    self.outbound.len()
  }

  fn is_handshaking(&self) -> bool {
    false
  }
  fn peer_has_closed(&self) -> bool {
    false
  }
  fn send_close_notify(&mut self) {}
  fn clear_outbound(&mut self) {
    self.outbound.clear();
  }
  fn is_secure() -> bool {
    false
  }
}

#[cfg(test)]
mod tests;

//! `[u32 length][payload]` framing over a record layer's plaintext stream. The decoder parses
//! incrementally and never retains an over-cap frame's body: it validates the declared length as
//! soon as the 4-byte prefix completes, before copying any body bytes.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use std::collections::VecDeque;

use super::TransportError;

/// The default maximum framed-unit length (16 MiB). Bounds buffering against a hostile peer; viewstamp's
/// largest messages (StartView / DoViewChange / SyncCheckpoint) fit well under.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

const LEN_PREFIX: usize = 4;

/// Appends `[u32 len][payload]` to `out`.
#[cfg_attr(not(tarpaulin), inline)]
pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) {
  debug_assert!(
    payload.len() <= u32::MAX as usize,
    "payload length must fit a u32 prefix"
  );
  out.reserve(LEN_PREFIX + payload.len());
  out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
  out.extend_from_slice(payload);
}

/// Incremental frame parser. Holds at most one partial frame (bounded by `4 + max`) plus a queue of
/// complete frames; an over-cap declared length is rejected before any of its body is copied.
#[derive(Debug)]
pub struct FrameDecoder {
  partial: Vec<u8>,
  ready: VecDeque<Vec<u8>>,
  max: u32,
}

impl FrameDecoder {
  /// Creates a decoder bounding each frame at `max` bytes.
  #[cfg_attr(not(tarpaulin), inline)]
  pub const fn new(max: u32) -> Self {
    Self {
      partial: Vec::new(),
      ready: VecDeque::new(),
      max,
    }
  }

  /// Feeds freshly-read plaintext, parsing complete frames out of it. Rejects an over-cap declared
  /// length as soon as the prefix completes — before that frame's body is retained.
  pub fn extend(&mut self, mut bytes: &[u8]) -> Result<(), TransportError> {
    while !bytes.is_empty() {
      if self.partial.len() < LEN_PREFIX {
        let take = (LEN_PREFIX - self.partial.len()).min(bytes.len());
        self.partial.extend_from_slice(&bytes[..take]);
        bytes = &bytes[take..];
        if self.partial.len() < LEN_PREFIX {
          break;
        }
      }
      let len = u32::from_be_bytes([
        self.partial[0],
        self.partial[1],
        self.partial[2],
        self.partial[3],
      ]);
      if len > self.max {
        return Err(TransportError::FrameTooLong { len, max: self.max });
      }
      let total = LEN_PREFIX + len as usize;
      let take = (total - self.partial.len()).min(bytes.len());
      self.partial.extend_from_slice(&bytes[..take]);
      bytes = &bytes[take..];
      if self.partial.len() == total {
        let frame = self.partial[LEN_PREFIX..].to_vec();
        self.partial.clear();
        self.ready.push_back(frame);
      } else {
        break;
      }
    }
    Ok(())
  }

  /// Pops the next complete frame, if any.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn next_frame(&mut self) -> Option<Vec<u8>> {
    self.ready.pop_front()
  }

  /// Bytes of an incomplete frame currently retained (non-zero at EOF means a truncated frame).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn partial_len(&self) -> usize {
    self.partial.len()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn round_trip_single_and_multi() {
    let mut buf = Vec::new();
    encode_frame(b"abc", &mut buf);
    encode_frame(b"de", &mut buf);
    let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
    dec.extend(&buf).unwrap();
    assert_eq!(dec.next_frame(), Some(b"abc".to_vec()));
    assert_eq!(dec.next_frame(), Some(b"de".to_vec()));
    assert_eq!(dec.next_frame(), None);
    assert_eq!(dec.partial_len(), 0);
  }

  #[test]
  fn partial_frame_accumulates() {
    let mut buf = Vec::new();
    encode_frame(b"hello", &mut buf);
    let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
    dec.extend(&buf[..3]).unwrap();
    assert_eq!(dec.next_frame(), None);
    dec.extend(&buf[3..]).unwrap();
    assert_eq!(dec.next_frame(), Some(b"hello".to_vec()));
  }

  #[test]
  fn an_oversized_declared_length_is_rejected_before_buffering_the_body() {
    let mut dec = FrameDecoder::new(8);
    let mut packet = Vec::new();
    packet.extend_from_slice(&100u32.to_be_bytes()); // declares 100 > cap 8
    packet.extend_from_slice(&[0u8; 1000]); // a large body must never be retained
    assert_eq!(
      dec.extend(&packet),
      Err(TransportError::FrameTooLong { len: 100, max: 8 })
    );
    assert!(dec.partial_len() <= 4, "the over-cap body is not retained");
  }

  #[test]
  fn split_prefix_then_oversized_body_is_rejected_without_retaining_the_tail() {
    let mut dec = FrameDecoder::new(8);
    dec.extend(&[0u8, 0u8, 0u8]).unwrap(); // 3 bytes of the prefix
    let mut rest = Vec::new();
    rest.push(100u8); // the 4th prefix byte completes "declares 100"
    rest.extend_from_slice(&[0u8; 1000]); // huge tail
    assert_eq!(
      dec.extend(&rest),
      Err(TransportError::FrameTooLong { len: 100, max: 8 })
    );
    assert!(dec.partial_len() <= 4, "the over-cap tail is not retained");
  }

  #[test]
  fn header_only_reports_a_partial() {
    let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
    let mut buf = Vec::new();
    encode_frame(b"hello", &mut buf);
    dec.extend(&buf[..4]).unwrap(); // header only, no body
    assert_eq!(dec.next_frame(), None);
    assert_eq!(dec.partial_len(), 4);
  }
}

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

/// The per-pass plaintext budget a coordinator reads from one stream before draining the frames it
/// produced — the single source of truth for both stream coordinators. A read pass copies at most
/// this many bytes into its scratch buffer and feeds them to the decoder, then drains the resulting
/// complete frames, so the decoder's ready queue holds at most one budget's worth of frames at a time
/// (≤ `STAGE_CHUNK / 4` zero-body frames). This caps inbound staging independently of the total stream
/// receive window: a hostile peer that fills an 8 MiB window with tiny frames cannot make the decoder
/// queue millions of `Vec`s in one pass, because each pass reads only this much before the frames are
/// drained. Sized well above a single consensus message so normal traffic still clears in one pass.
pub const STAGE_CHUNK: usize = 64 * 1024;

/// The `[u32 length]` prefix size that precedes every frame body.
pub const LEN_PREFIX: usize = 4;

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
    // First parse complete frames out of bytes ALREADY buffered in `partial` — non-empty as a complete-
    // frame buffer only after a prior `extend_first` left a pipelined pre-auth tail. Draining here decodes
    // a buffered tail consensus frame even when `bytes` is empty (the post-validation re-read with no new
    // plaintext), the case that would otherwise strand it. On the steady path `partial` holds at most one
    // in-progress frame, so this returns immediately and changes nothing.
    self.drain_buffered()?;
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

  /// Parses every COMPLETE frame currently held in `partial` onto `ready`, stopping on the first
  /// incomplete leading frame (a bare prefix, or a prefix plus a partial body), which it leaves as the
  /// normal sub-`total` in-progress partial for [`Self::extend`]'s byte-feeding loop (or the next call)
  /// to resume. Rejects an over-cap declared length (the tail of a pipelined pre-auth batch re-checked
  /// under the now-raised cap) before yielding that frame. `partial` holds more than one in-progress
  /// frame ONLY after [`Self::extend_first`] buffered a pipelined tail; the steady path enters with at
  /// most one sub-`total` in-progress frame and returns immediately, so this is a no-op for the TCP
  /// record path (which never calls `extend_first` and so never holds a complete frame in `partial`).
  fn drain_buffered(&mut self) -> Result<(), TransportError> {
    while self.partial.len() >= LEN_PREFIX {
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
      if self.partial.len() < total {
        // A complete prefix but not the whole body yet: leave it as the in-progress partial for the
        // caller's loop (or the next call) to resume.
        break;
      }
      let frame = self.partial[LEN_PREFIX..total].to_vec();
      self.partial.drain(..total);
      self.ready.push_back(frame);
    }
    Ok(())
  }

  /// Feeds freshly-read plaintext but decodes AT MOST the first complete frame, retaining every byte
  /// past that frame UN-decoded in the partial buffer (its length prefix is NOT yet evaluated against
  /// the cap). Used ONLY for the QUIC Control class while a connection is `Authenticating`: the sole
  /// legitimate pre-auth frame is the identity hello, so exactly one frame is decoded under the small
  /// hello-sized cap, and a hostile FIRST frame declaring `> max` is still rejected here (the
  /// pin/oversized-hello attack). A peer that already validated US may pipeline a legitimate consensus
  /// Control frame (a `Prepare` / `PrepareOk` exceeding the hello cap) directly behind its hello in one
  /// read; that tail must NOT be rejected under the pre-auth cap. Leaving it buffered raw — its prefix
  /// re-evaluated on the next `extend` after [`Self::set_max`] raises the cap on validation — preserves
  /// it losslessly: the post-validation read (scheduled by `bind_validated`) decodes it under
  /// [`MAX_FRAME_LEN`]. The retained tail is bounded by the per-pass read budget, not by `max`.
  ///
  /// Returns `Err` only when the FIRST frame's declared length is over the cap (rejected before any of
  /// its body is retained, exactly like [`Self::extend`]). A FIRST frame still incomplete after `bytes`
  /// (only a prefix, or a prefix plus a partial body) is retained as a normal in-progress partial and
  /// re-driven on the next call; no frame is yielded yet.
  #[cfg(feature = "quic")]
  pub fn extend_first(&mut self, mut bytes: &[u8]) -> Result<(), TransportError> {
    // Once the first (hello) frame is complete and queued, decode no further while capped: buffer every
    // later byte raw so it decodes only after `set_max` raises the cap. A split-across-reads hello has
    // `ready` empty until its body completes, so this also covers resuming a partial hello on re-entry.
    if !self.ready.is_empty() {
      return self.buffer_capped_tail(bytes);
    }
    // Complete the 4-byte length prefix. If it is still short after `bytes`, the hello's prefix has not
    // arrived in full yet — retain the sub-prefix partial and resume on the next call.
    if self.partial.len() < LEN_PREFIX {
      let take = (LEN_PREFIX - self.partial.len()).min(bytes.len());
      self.partial.extend_from_slice(&bytes[..take]);
      bytes = &bytes[take..];
      if self.partial.len() < LEN_PREFIX {
        return Ok(());
      }
    }
    let len = u32::from_be_bytes([
      self.partial[0],
      self.partial[1],
      self.partial[2],
      self.partial[3],
    ]);
    // The oversized-hello pin attack: a FIRST frame declaring over the cap is rejected on the prefix
    // alone, before any of its body is retained — exactly as `extend` rejects it.
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
      // The hello is complete: buffer the pipelined remainder (a peer that already validated us may flush
      // queued consensus Control behind its hello), but gate each tail frame on its length prefix against
      // `MAX_FRAME_LEN` BEFORE retaining its body — the same guard `extend` applies, just under the cap
      // the tail will actually be decoded at post-validation (NOT the small pre-auth `max`, so a
      // legitimate `MAX_HELLO_LEN < len <= MAX_FRAME_LEN` consensus frame is preserved). It is otherwise
      // re-evaluated only later by `extend`'s `drain_buffered` after `set_max`; checking it here keeps an
      // over-cap tail from pinning up to a whole read budget of body bytes pre-auth.
      return self.buffer_capped_tail(bytes);
    }
    // Otherwise the hello's body is still incomplete (a sub-`total` partial within the cap): retain it
    // and resume on the next call. No frame is yielded yet, so nothing trails it to buffer.
    Ok(())
  }

  /// Buffer the post-hello pipelined tail (`bytes`) onto `partial` while rejecting any tail frame whose
  /// declared length exceeds [`MAX_FRAME_LEN`] BEFORE that frame's body is retained — the same prefix
  /// guard [`Self::extend`] applies, against the cap the tail is eventually decoded under
  /// post-validation. The pre-auth `max` (`MAX_HELLO_LEN`) bounds ONLY the hello; a peer that already
  /// validated us may legitimately pipeline a consensus Control frame larger than the hello cap (but
  /// `<= MAX_FRAME_LEN`) directly behind its hello, so that case must survive — only a frame over the
  /// real frame limit is rejected (no body retained), exactly as `extend` would once the cap is raised.
  ///
  /// Walks every frame already buffered in `partial` (it may hold validated-prefix bytes from a prior
  /// call) plus the freshly-appended `bytes`: for each frame whose full 4-byte prefix is present, an
  /// over-cap declared length returns `FrameTooLong`; an in-cap one is stepped over (its body buffered
  /// to be decoded by `extend`'s `drain_buffered` once `set_max` raises the cap). The walk stops at the
  /// first frame whose prefix is not yet complete — that prefix is re-checked on the next call once its
  /// remaining bytes arrive, so no body is ever buffered ahead of a passing prefix check.
  #[cfg(feature = "quic")]
  fn buffer_capped_tail(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
    self.partial.extend_from_slice(bytes);
    let mut off = 0usize;
    while off + LEN_PREFIX <= self.partial.len() {
      let len = u32::from_be_bytes([
        self.partial[off],
        self.partial[off + 1],
        self.partial[off + 2],
        self.partial[off + 3],
      ]);
      if len > MAX_FRAME_LEN {
        // Reject on the prefix alone. The over-cap frame's body is NOT retained: trim `partial` back to
        // the prefix so the post-validation `extend` would also reject it (and the connection is torn
        // down), and so a `partial_len` observable stays bounded by the prefix, not the declared body.
        self.partial.truncate(off + LEN_PREFIX);
        return Err(TransportError::FrameTooLong {
          len,
          max: MAX_FRAME_LEN,
        });
      }
      let next = off + LEN_PREFIX + len as usize;
      if next > self.partial.len() {
        // This frame's prefix passed but its body is not fully buffered yet: leave the rest for the next
        // call to extend and re-walk (its prefix is already validated, so no further check is owed here).
        break;
      }
      off = next;
    }
    Ok(())
  }

  /// Pops the next complete frame, if any.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn next_frame(&mut self) -> Option<Vec<u8>> {
    self.ready.pop_front()
  }

  /// Adjusts the per-frame length cap in place, leaving any buffered partial frame and the ready queue
  /// untouched. Used to RAISE the cap once a precondition is met (the QUIC Control class is held at a
  /// small pre-authentication cap, then lifted to the full frame limit on validation). Any partial
  /// already retained was admitted under the OLD cap (so it is `≤ 4 + old_max`); a larger new cap only
  /// admits more, so raising it is always consistent — a not-yet-completed prefix re-evaluates its
  /// declared length against the new cap on the next `extend`. QUIC-only: the TCP record path frames at
  /// a fixed cap.
  #[cfg(feature = "quic")]
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn set_max(&mut self, max: u32) {
    self.max = max;
  }

  /// Bytes of an incomplete frame currently retained (non-zero at EOF means a truncated frame).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn partial_len(&self) -> usize {
    self.partial.len()
  }

  /// Whether this decoder is at its FINAL (un-raisable) length cap — the full [`MAX_FRAME_LEN`], not the
  /// small pre-authentication hello cap a [`Self::set_max`] later raises. The QUIC graceful-FIN
  /// truncation decision reads this so it judges a retained `partial` against the cap the bytes will
  /// actually be decoded under: while still at the hello cap a non-zero `partial_len` behind a complete
  /// first frame is the legitimately-retained pipelined tail, not a truncation; only at the final cap is
  /// such a partial unconditionally torn. Sourcing the cap from the decoder (not a caller flag) keeps the
  /// two QUIC decode sites from disagreeing. QUIC-only: the TCP record path frames at a single fixed cap.
  #[cfg(feature = "quic")]
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn is_at_final_cap(&self) -> bool {
    self.max == MAX_FRAME_LEN
  }

  /// Whether at least one complete frame is queued for [`Self::next_frame`]. The QUIC graceful-FIN
  /// truncation check reads this to tell apart a pre-auth `[partial first frame][FIN]` (no complete
  /// frame yet — a true truncation) from `[complete hello][...buffered tail...][FIN]` (the hello is
  /// queued, so a non-zero `partial_len` is the retained pipelined tail, NOT a truncation): under
  /// [`Self::extend_first`] a non-empty ready queue means the first (hello) frame completed and the
  /// remainder is the intentionally-buffered tail re-decoded post-validation, not a torn frame.
  #[cfg(feature = "quic")]
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn has_ready(&self) -> bool {
    !self.ready.is_empty()
  }

  /// Count of complete-but-undrained frames currently queued — the observable a bounded-read
  /// regression asserts stays proportional to the per-pass read budget, not to the total frames a
  /// peer crammed into one receive window.
  #[cfg(test)]
  pub fn ready_len(&self) -> usize {
    self.ready.len()
  }

  /// Append raw bytes straight into the retained `partial`, bypassing the prefix cap guard the public
  /// feed methods enforce. Test-only, for the QUIC `bind_validated` deferred-truncation regression: that
  /// branch fires only when a buffered tail still declares over `MAX_FRAME_LEN` at the raised cap, which
  /// the `extend_first` / `buffer_capped_tail` prefix guard makes unreachable through the live decode path
  /// (it rejects an over-cap tail prefix during the pre-auth read). Seeding the over-cap prefix directly
  /// reconstructs the otherwise-defensive state so the deferred-not-synchronous teardown can be pinned.
  #[cfg(all(test, feature = "quic"))]
  pub fn seed_partial_for_test(&mut self, bytes: &[u8]) {
    self.partial.extend_from_slice(bytes);
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

  /// `extend_first` yields ONLY the first frame under the small cap and retains a pipelined frame that
  /// is OVER that cap, un-decoded; after `set_max` raises the cap, the next `extend` decodes the tail.
  /// This is the pre-auth Control path: a peer that already validated us pipelines a consensus frame
  /// (larger than the hello cap) directly behind its hello in one read, and it must not be rejected.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_first_yields_the_hello_and_retains_an_over_cap_pipelined_tail() {
    let hello = vec![0xAAu8; 6]; // fits the small cap
    let big = vec![0x5Au8; 64]; // over the cap, under the raised cap
    let mut buf = Vec::new();
    encode_frame(&hello, &mut buf);
    encode_frame(&big, &mut buf);

    let mut dec = FrameDecoder::new(8); // a hello-sized cap; `big` (64) exceeds it
    dec.extend_first(&buf).unwrap(); // ONE pass delivers hello + the over-cap tail
    // Only the hello surfaces; the tail is buffered RAW (its over-cap prefix is NOT yet checked).
    assert_eq!(dec.next_frame(), Some(hello));
    assert_eq!(
      dec.next_frame(),
      None,
      "the over-cap tail is NOT decoded while capped"
    );
    assert!(
      dec.partial_len() > 8,
      "the whole tail frame is buffered un-decoded"
    );

    // Validation raises the cap; the next `extend` drains the buffered tail with NO new bytes.
    dec.set_max(MAX_FRAME_LEN);
    dec.extend(&[]).unwrap();
    assert_eq!(
      dec.next_frame(),
      Some(big),
      "the tail decodes once the cap is raised"
    );
    assert_eq!(dec.next_frame(), None);
    assert_eq!(dec.partial_len(), 0);
  }

  /// A FIRST frame whose declared length is over the cap is STILL rejected by `extend_first` on the
  /// prefix alone — the oversized-hello pin attack the pre-auth cap exists to stop, preserved.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_first_rejects_an_oversized_first_frame_on_the_prefix() {
    let mut dec = FrameDecoder::new(8);
    let mut packet = Vec::new();
    packet.extend_from_slice(&100u32.to_be_bytes()); // a FIRST frame declaring 100 > cap 8
    packet.extend_from_slice(&[0u8; 1000]); // its body must never be retained
    assert_eq!(
      dec.extend_first(&packet),
      Err(TransportError::FrameTooLong { len: 100, max: 8 })
    );
    assert!(
      dec.partial_len() <= 4,
      "the over-cap first frame's body is not retained"
    );
    assert_eq!(dec.next_frame(), None);
  }

  /// `extend_first` resumes a hello split across reads, then retains the pipelined over-cap tail that
  /// arrived in the same final segment — no frame is yielded until the hello completes.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_first_resumes_a_split_hello_then_buffers_the_tail() {
    let hello = vec![0x11u8; 6];
    let big = vec![0x22u8; 64];
    let mut buf = Vec::new();
    encode_frame(&hello, &mut buf);
    encode_frame(&big, &mut buf);

    let mut dec = FrameDecoder::new(8);
    // First read: only part of the hello (prefix + 2 body bytes). Nothing yielded yet.
    dec.extend_first(&buf[..6]).unwrap();
    assert_eq!(dec.next_frame(), None);
    // Second read: the rest of the hello plus the whole over-cap tail, in one segment.
    dec.extend_first(&buf[6..]).unwrap();
    assert_eq!(dec.next_frame(), Some(hello));
    assert_eq!(
      dec.next_frame(),
      None,
      "the over-cap tail stays buffered while capped"
    );

    dec.set_max(MAX_FRAME_LEN);
    dec.extend(&[]).unwrap();
    assert_eq!(dec.next_frame(), Some(big));
  }

  /// After the cap is raised, a single `extend` drains MULTIPLE pipelined tail frames out of `partial`,
  /// in order — `extend_first` may buffer more than one frame behind the hello in one read pass.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_drains_multiple_buffered_tail_frames_after_the_cap_is_raised() {
    let hello = vec![0x01u8; 4];
    let a = vec![0x0Au8; 40];
    let b = vec![0x0Bu8; 50];
    let mut buf = Vec::new();
    encode_frame(&hello, &mut buf);
    encode_frame(&a, &mut buf);
    encode_frame(&b, &mut buf);

    let mut dec = FrameDecoder::new(8);
    dec.extend_first(&buf).unwrap();
    assert_eq!(dec.next_frame(), Some(hello));
    assert_eq!(dec.next_frame(), None);

    dec.set_max(MAX_FRAME_LEN);
    dec.extend(&[]).unwrap();
    assert_eq!(dec.next_frame(), Some(a));
    assert_eq!(dec.next_frame(), Some(b));
    assert_eq!(dec.next_frame(), None);
    assert_eq!(dec.partial_len(), 0);
  }

  /// A pipelined tail frame declaring OVER `MAX_FRAME_LEN` must be rejected on its 4-byte length prefix
  /// — BEFORE any of its body is buffered — even while the decoder is still at the small pre-auth cap.
  /// The hello validated this side, so the tail is buffered for post-validation decode; without a prefix
  /// guard the over-cap body would be retained up to the read budget (raising the pre-auth pin from the
  /// hello cap to a whole `STAGE_CHUNK`) and only rejected later by `extend` under the raised cap. The
  /// guard rejects it here against the FULL frame cap (the cap the tail would decode under), retaining no
  /// tail body, so the connection is torn down on the prefix.
  ///
  /// NEUTER CHECK: drop the prefix check in `buffer_capped_tail` (blindly `extend_from_slice` the whole
  /// tail) and `extend_first` returns `Ok` here while `partial_len` grows to include the over-cap body —
  /// exactly the pre-auth body retention this guard closes.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_first_rejects_an_over_cap_pipelined_tail_on_its_prefix() {
    let hello = vec![0xAAu8; 6]; // fits the small pre-auth cap
    let mut buf = Vec::new();
    encode_frame(&hello, &mut buf);
    // A tail frame whose declared length exceeds the FULL frame cap, followed by body bytes that must
    // NEVER be retained. (The prefix is hand-built so the declared length can exceed MAX_FRAME_LEN
    // without allocating a multi-megabyte body.)
    buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
    let tail_body = [0u8; 256];
    buf.extend_from_slice(&tail_body);

    let mut dec = FrameDecoder::new(8); // the hello-sized pre-auth cap
    assert_eq!(
      dec.extend_first(&buf),
      Err(TransportError::FrameTooLong {
        len: MAX_FRAME_LEN + 1,
        max: MAX_FRAME_LEN,
      }),
      "an over-`MAX_FRAME_LEN` pipelined tail is rejected even at the small pre-auth cap"
    );
    // The hello still surfaced (it was decoded before the offending tail), and NONE of the over-cap tail
    // body was retained — `partial` holds at most the hello-having-been-cleared plus the tail's 4-byte
    // prefix, never its 256-byte body.
    assert_eq!(dec.next_frame(), Some(hello));
    assert!(
      dec.partial_len() <= LEN_PREFIX,
      "no over-cap tail body is retained (partial bounded by the prefix, not the body): got {}",
      dec.partial_len()
    );
  }

  /// The over-cap pipelined tail is rejected on its prefix even when the over-cap frame arrives BEHIND a
  /// legitimate in-cap tail frame in the same buffer: the walk steps over the in-cap frame's buffered
  /// body, then rejects the next frame on its prefix — still retaining none of the over-cap body.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_first_rejects_an_over_cap_tail_behind_an_in_cap_tail() {
    let hello = vec![0x11u8; 6];
    let ok_tail = vec![0x22u8; 64]; // over the pre-auth cap, under MAX_FRAME_LEN — legitimate, buffered
    let mut buf = Vec::new();
    encode_frame(&hello, &mut buf);
    encode_frame(&ok_tail, &mut buf);
    buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes()); // then an over-cap frame's prefix
    buf.extend_from_slice(&[0u8; 128]); // its body must not be retained

    let mut dec = FrameDecoder::new(8);
    assert_eq!(
      dec.extend_first(&buf),
      Err(TransportError::FrameTooLong {
        len: MAX_FRAME_LEN + 1,
        max: MAX_FRAME_LEN,
      })
    );
    assert_eq!(dec.next_frame(), Some(hello));
    // `partial` may hold the legitimate in-cap tail (`ok_tail`, retained for post-validation decode) plus
    // the rejected frame's 4-byte prefix — but NOT the rejected frame's 128-byte body.
    assert!(
      dec.partial_len() <= LEN_PREFIX + LEN_PREFIX + ok_tail.len(),
      "only the in-cap tail (plus the rejected prefix) is retained, never the over-cap body: got {}",
      dec.partial_len()
    );
  }

  /// The legitimate pipelined-tail case is unchanged by the tail guard: a tail frame in
  /// `MAX_HELLO_LEN < len <= MAX_FRAME_LEN` (a consensus Control frame a peer that already validated us
  /// pipelines behind its hello, larger than the hello cap) is BUFFERED — not rejected — and decodes
  /// once `set_max` raises the cap. This pins the boundary the guard must straddle: it checks against
  /// `MAX_FRAME_LEN`, NOT the small pre-auth `MAX_HELLO_LEN`, so a real consensus frame survives.
  #[cfg(feature = "quic")]
  #[test]
  fn extend_first_preserves_a_legitimate_over_hello_cap_tail() {
    use crate::transport::labeled::MAX_HELLO_LEN;
    let hello = vec![0x33u8; 6];
    // A tail strictly larger than the hello cap but well within the frame limit — the consensus frame
    // the pre-auth tail buffering exists to preserve.
    let big = vec![0x44u8; MAX_HELLO_LEN + 64];
    let mut buf = Vec::new();
    encode_frame(&hello, &mut buf);
    encode_frame(&big, &mut buf);

    let mut dec = FrameDecoder::new(MAX_HELLO_LEN as u32); // the real pre-auth Control cap
    dec.extend_first(&buf).unwrap(); // NOT rejected — the tail is in (hello_cap, MAX_FRAME_LEN]
    assert_eq!(dec.next_frame(), Some(hello));
    assert_eq!(
      dec.next_frame(),
      None,
      "the over-hello-cap tail stays buffered while capped (not yet decoded, not rejected)"
    );
    dec.set_max(MAX_FRAME_LEN);
    dec.extend(&[]).unwrap();
    assert_eq!(
      dec.next_frame(),
      Some(big),
      "the legitimate consensus tail decodes once the cap is raised"
    );
    assert_eq!(dec.partial_len(), 0);
  }
}

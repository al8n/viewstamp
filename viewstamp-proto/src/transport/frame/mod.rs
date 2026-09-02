//! `[u32 length][payload]` framing over a record layer's plaintext stream. The decoder parses
//! incrementally and never retains an over-cap frame's body: it validates the declared length as
//! soon as the 4-byte prefix completes, before copying any body bytes.

#[cfg(not(feature = "std"))]
use std::vec::Vec;

use std::collections::VecDeque;

use super::TransportError;

/// The default maximum framed-unit length (16 MiB). Bounds buffering against a hostile peer; viewstamp's
/// largest messages (StartView / DoViewChange / SyncCheckpoint) fit well under. Re-exported from the
/// base crate (`crate::message::MAX_FRAME_LEN`) so it is the SAME cap the always-available byte-bounded
/// repair serve sizes its batches against (one source of truth across the feature boundary).
pub const MAX_FRAME_LEN: u32 = crate::message::MAX_FRAME_LEN;

/// The largest client-request body the transport can deliver end-to-end, in bytes: [`MAX_FRAME_LEN`]
/// minus the worst-case per-message encoding overhead a client request incurs
/// (`crate::message::MAX_REQUEST_BODY_OVERHEAD`).
///
/// A client body does not travel alone — the SAME body bytes are wrapped by a [`Request`](crate::Request)
/// encoding on the client → primary hop, by a (larger) [`Prepare`](crate::Prepare) encoding on the
/// primary → backups hop, and — once the op is logged — by a single
/// [`PreparedEntry`](crate::PreparedEntry) inside a `RepairBatch` (the windowed peer-repair answer)
/// or `PrepareBatch` (the primary's batched retransmit) log slice. The send path refuses any message
/// whose `encoded_len()` exceeds [`MAX_FRAME_LEN`], and `MAX_REQUEST_BODY_OVERHEAD` is the largest
/// of those per-carrier overheads at their protobuf WORST CASE — every scalar charged its
/// varint-widest encoding (the one-entry `PrepareBatch`, not the bare `Prepare` hop, binds it). A
/// body of at most this many bytes therefore encodes to at most [`MAX_FRAME_LEN`] on EVERY message
/// that can carry it, whatever its scalar values, so it is deliverable on every hop; past the bound
/// a carrier can encode over the frame cap and be dropped by the transport, wedging the repair or
/// retransmit of a committed op that had been accepted. A driver should reject an over-this-size
/// submit up front rather than admit a request the cluster can never commit.
///
/// `const`: [`MAX_FRAME_LEN`] (16 MiB) dwarfs the fixed overhead, so the subtraction never underflows.
#[cfg_attr(not(tarpaulin), inline)]
pub const fn max_request_body_len() -> usize {
  MAX_FRAME_LEN as usize - crate::message::MAX_REQUEST_BODY_OVERHEAD
}

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

/// Capacity [`FrameDecoder`] carries forward in its partial buffer between frames.
///
/// A completed frame at most this large is copied out of the retained buffer, so the steady path of
/// small consensus frames reuses one allocation and never reallocates.  A larger one hands the
/// buffer over as the frame instead of copying it, and the partial buffer restarts from nothing —
/// otherwise a maximum-sized frame would leave its whole capacity retained while its copy sat in the
/// ready queue, two frame-sized allocations for one frame.  Set to the per-pass read budget
/// ([`STAGE_CHUNK`]), which is already what one read may hand the decoder at a time.
const RETAINED_PARTIAL_CAP: usize = STAGE_CHUNK;

/// Ready-queue slots [`FrameDecoder`] carries forward once the queue drains.
///
/// One read pass can complete a whole budget's worth of minimal frames — `STAGE_CHUNK / LEN_PREFIX`
/// = 16384 of them — and a `VecDeque` keeps the capacity that burst grew, so without this the queue's
/// backing would stay at 16384 slots (about 384 KiB of `Vec` headers on a 64-bit target) for the
/// connection's life after one burst. Draining back to empty releases everything above this, which
/// comfortably holds the handful of frames a steady pass delivers.
const RETAINED_READY_CAP: usize = 64;

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
      self.reserve_for(total);
      self.partial.extend_from_slice(&bytes[..take]);
      bytes = &bytes[take..];
      if self.partial.len() == total {
        let frame = self.take_completed_frame(total);
        self.ready.push_back(frame);
      } else {
        break;
      }
    }
    Ok(())
  }

  /// Land the partial buffer's LAST growth exactly on `total` instead of doubling past it.
  ///
  /// `Vec`'s amortized doubling would reserve 32 MiB to hold a 16 MiB frame, and that buffer is the
  /// one handed over as the delivered frame — as much slack as payload, carried for as long as the
  /// frame is. Reserving the exact remainder on the step that would otherwise overshoot lands it on
  /// the frame's own size. Every earlier growth keeps the doubling, so appending stays amortized
  /// O(1); the exact reserve happens at most once per frame.
  ///
  /// The declared length is NOT trusted into an allocation: this only fires once the buffer has
  /// already grown to at least half the total, which the peer's DELIVERED bytes are what drive. A
  /// peer that declares a maximum frame and then sends nothing still holds nothing.
  fn reserve_for(&mut self, total: usize) {
    if self.partial.capacity() >= total || self.partial.capacity().saturating_mul(2) < total {
      return;
    }
    self.partial.reserve_exact(total - self.partial.len());
  }

  /// Move the `total`-byte frame at the front of `partial` out as its own `Vec`, leaving `partial`
  /// carrying at most [`RETAINED_PARTIAL_CAP`] of capacity.
  ///
  /// Exactly ONE frame-sized allocation is live at a time.  A frame within the retained capacity is
  /// copied out and the buffer reused, which keeps the steady path allocation-free.  A larger frame
  /// HANDS OVER the buffer — the frame IS `partial`'s storage, with the length prefix shifted off —
  /// so no second frame-sized allocation is made and none is retained.  A pipelined tail behind the
  /// frame (only after [`Self::extend_first`] buffered one) is kept, and any capacity left over
  /// above the retained bound is released.
  fn take_completed_frame(&mut self, total: usize) -> Vec<u8> {
    debug_assert!(self.partial.len() >= total);
    let frame = if self.partial.len() == total && self.partial.capacity() > RETAINED_PARTIAL_CAP {
      let mut frame = core::mem::take(&mut self.partial);
      frame.drain(..LEN_PREFIX);
      frame
    } else {
      let frame = self.partial[LEN_PREFIX..total].to_vec();
      self.partial.drain(..total);
      frame
    };
    if self.partial.capacity() > RETAINED_PARTIAL_CAP {
      // A no-op while `partial` still holds more than the bound (a buffered tail keeps its bytes).
      self.partial.shrink_to(RETAINED_PARTIAL_CAP);
    }
    frame
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
      let frame = self.take_completed_frame(total);
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
    self.reserve_for(total);
    self.partial.extend_from_slice(&bytes[..take]);
    bytes = &bytes[take..];
    if self.partial.len() == total {
      let frame = self.take_completed_frame(total);
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
    let frame = self.ready.pop_front();
    // Emptying the queue releases the slots a burst grew it to: the capacity is what would otherwise
    // be retained for the connection's life (see `RETAINED_READY_CAP`). Only on the empty transition,
    // so draining a burst frame-by-frame does not reallocate per pop.
    if self.ready.is_empty() && self.ready.capacity() > RETAINED_READY_CAP {
      self.ready.shrink_to(RETAINED_READY_CAP);
    }
    frame
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
  #[cfg(all(test, feature = "quic"))]
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
mod tests;

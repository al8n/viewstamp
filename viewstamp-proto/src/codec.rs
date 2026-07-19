//! Versioned, canonical, bounds-checked disk codec primitives for the durable
//! ([`Header`](crate::Header)/[`VsrState`](crate::VsrState)) encodings, plus the [`CodecError`]
//! surface a decoded [`Message`](crate::Message) wire envelope also reports through.
//!
//! The proto owns no I/O; a later I/O layer (TCP networking + async disk storage) serializes these
//! value types over the wire and onto disk, so the encoding is **part of the protocol
//! contract**, not a driver detail. The MESSAGE encoding itself is the protobuf wire envelope
//! (`crate::wire`; `encode_message`/`decode_message`) — a peer's wire version is fenced once, at the
//! transport handshake (`HELLO_VERSION`), not carried by every message. The DURABLE on-disk forms
//! version INDEPENDENTLY of that handshake fence and of each other (the [`Header`] via
//! [`HEADER_VERSION`](crate::HEADER_VERSION), the superblock root [`VsrState`](crate::VsrState) via
//! [`SUPERBLOCK_VERSION`](crate::SUPERBLOCK_VERSION)), so neither a message-format change nor the
//! other durable form ever invalidates a persisted root. The requirements the durable codecs meet:
//!
//! - **Versioned** — decode REJECTS an unknown leading version with [`CodecError::UnknownVersion`]
//!   so each on-disk format can evolve.
//! - **Canonical** — a fixed field order, big-endian scalars (matching the existing
//!   `Header::compute_checksum` `to_be_bytes` order), length-prefixed variable parts.
//! - **Bounds-checked, panic-free decode** — decode takes `&[u8]` and returns
//!   `Result<T, CodecError>`; it NEVER panics / indexes out of range on a truncated,
//!   corrupt, or adversarial buffer (the internal `Reader` below length-checks every read,
//!   mirroring `Endpoint::decode_checkpoint`).

/// A typed, structured error from decoding a [`Header`](crate::Header),
/// [`VsrState`](crate::VsrState), or [`Message`](crate::Message) from bytes (or from a
/// [`VsrState`](crate::VsrState) whose decoded fields violate its invariants).
///
/// Every variant is a *parse* outcome, never a panic: a short buffer, an unknown version,
/// a length prefix that overruns the remaining bytes, trailing garbage, or a malformed
/// wire field each map to a distinct variant so a caller (and the fuzz/corruption tests)
/// can tell *why* a buffer was rejected. One variant, [`UnknownMessage`](Self::UnknownMessage),
/// is not a rejection of a *corrupt* buffer at all: it names a [`Message`](crate::Message) envelope
/// that decoded cleanly and within every bound but carries a body a newer peer added — so a
/// transport can drop it and keep the connection live, distinct from every fault above.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
  /// The buffer ended before a field could be fully read: `expected` more bytes were
  /// needed at the current position but only `got` remained.
  #[error("truncated input: expected {expected} more bytes, got {got}")]
  Truncated {
    /// The number of bytes the field required.
    expected: usize,
    /// The number of bytes actually remaining.
    got: usize,
  },
  /// The leading format version did not match the decoder's expectation — for a
  /// [`Header`](crate::Header), [`HEADER_VERSION`](crate::HEADER_VERSION); for a durable
  /// [`VsrState`](crate::VsrState) root, exactly
  /// [`SUPERBLOCK_VERSION`](crate::SUPERBLOCK_VERSION) (the durable-format fence — no other version
  /// parses). Carries the version that was read.
  #[error("unknown wire/disk version: {0}")]
  UnknownVersion(u16),
  /// A length-prefixed field's prefix named more elements/bytes than the rest of the buffer
  /// could contain (a corrupt or adversarial length). Distinct from [`Self::Truncated`] so a
  /// hostile oversized prefix is not confused with an honestly-short tail.
  #[error("length prefix {len} exceeds the {remaining} remaining bytes")]
  LengthOverflow {
    /// The decoded length prefix (in bytes or elements).
    len: usize,
    /// The number of bytes actually remaining when it was read.
    remaining: usize,
  },
  /// The encoding was structurally valid but bytes remained after the value was fully
  /// decoded — a canonical encoding has exactly one byte representation, so trailing bytes
  /// signal a corrupt or maliciously-extended buffer. Carries the number of leftover bytes.
  #[error("{0} trailing bytes after a fully-decoded value")]
  TrailingBytes(usize),
  /// A [`VsrState`](crate::VsrState) was decoded but its fields violate its construction
  /// invariants (e.g. `log_view > view`, an out-of-band committed header). Carries the
  /// underlying [`VsrStateError`](crate::VsrStateError).
  #[error("decoded VsrState is invalid: {0}")]
  InvalidVsrState(#[from] crate::VsrStateError),
  /// A v4 [`VsrState`](crate::VsrState) root's `membership_present` flag was neither `0` (absent) nor
  /// `1` (a membership block follows). Carries the unexpected byte.
  #[error("invalid membership-present flag: {0}")]
  InvalidMembershipPresent(u8),
  /// A wire field decoded to a value the domain type cannot represent (a wrong-length id/checksum,
  /// an out-of-range count, an absent required oneof), or the protobuf envelope itself violated the
  /// wire grammar (an invalid wire type, an overlong varint, a missing message body) without a more
  /// specific variant to name it. Carries a static label naming the offending field or context.
  #[error("malformed wire field: {what}")]
  Malformed {
    /// A static label naming the offending field or decode context.
    what: &'static str,
  },
  /// A [`Message`](crate::Message) envelope decoded cleanly and within every bound, but its `body`
  /// oneof names no message this build recognizes — a FORWARD-COMPATIBLE unrecognized body from a
  /// newer peer (an additive `Message.body` variant introduced after this build's schema), NOT a
  /// corrupt frame. Held distinct from [`Malformed`](Self::Malformed) precisely so a transport can
  /// DROP the frame and keep the connection live — a newer peer is not a faulty one — exactly as an
  /// unknown datagram is dropped, rather than tear the connection down. A degenerate zero-field
  /// envelope carries no body either and maps here too: the decoder retains no witness of a skipped
  /// unknown field, so "body absent" cannot be narrowed to "body absent AND an unknown field was
  /// seen"; it carries nothing, no current peer sends it, and dropping it is equally correct. Only
  /// [`decode_message`](crate::decode_message) produces this, and only after a successful bounded
  /// parse — a truncation, wire-grammar violation, or unknown-field flood is always
  /// [`Malformed`](Self::Malformed)/[`Truncated`](Self::Truncated), never this.
  #[error("forward-compatible unrecognized message body")]
  UnknownMessage,
}

impl From<crate::MembershipError> for CodecError {
  /// A membership block decoded from a v4 root that violates the [`Membership`](crate::Membership)
  /// structural invariants surfaces as an [`InvalidVsrState`](Self::InvalidVsrState) (the root is the
  /// thing being decoded), routed through [`VsrStateError`](crate::VsrStateError).
  #[cfg_attr(not(tarpaulin), inline)]
  fn from(e: crate::MembershipError) -> Self {
    Self::InvalidVsrState(e.into())
  }
}

/// A forward-only, bounds-checked cursor over an input buffer.
///
/// Every `read_*` length-checks first and returns [`CodecError::Truncated`] (never panics)
/// when the buffer is too short, mirroring the bounds discipline of
/// `Endpoint::decode_checkpoint`. This is the single place reads are validated, so every
/// `decode` built on it is panic-free on adversarial input by construction.
pub(crate) struct Reader<'a> {
  buf: &'a [u8],
  pos: usize,
}

impl<'a> Reader<'a> {
  /// Wraps a buffer at offset 0.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn new(buf: &'a [u8]) -> Self {
    Self { buf, pos: 0 }
  }

  /// The number of bytes not yet consumed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn remaining(&self) -> usize {
    self.buf.len() - self.pos
  }

  /// Errors with [`CodecError::TrailingBytes`] iff any input remains — call after a value is
  /// fully decoded to enforce the canonical one-encoding-per-value property.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn finish(&self) -> Result<(), CodecError> {
    match self.remaining() {
      0 => Ok(()),
      n => Err(CodecError::TrailingBytes(n)),
    }
  }

  /// Borrows the next `n` bytes, advancing the cursor, or errors [`CodecError::Truncated`].
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
    let end = self.pos.checked_add(n).ok_or(CodecError::Truncated {
      expected: n,
      got: self.remaining(),
    })?;
    let slice = self.buf.get(self.pos..end).ok_or(CodecError::Truncated {
      expected: n,
      got: self.remaining(),
    })?;
    self.pos = end;
    Ok(slice)
  }

  /// Reads a single `u8`.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
    Ok(self.take(1)?[0])
  }

  /// Reads a big-endian `u16`.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn u16(&mut self) -> Result<u16, CodecError> {
    let b: [u8; 2] = self.take(2)?.try_into().expect("take(2) yields 2 bytes");
    Ok(u16::from_be_bytes(b))
  }

  /// Reads a big-endian `u32`.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn u32(&mut self) -> Result<u32, CodecError> {
    let b: [u8; 4] = self.take(4)?.try_into().expect("take(4) yields 4 bytes");
    Ok(u32::from_be_bytes(b))
  }

  /// Reads a big-endian `u64`.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
    let b: [u8; 8] = self.take(8)?.try_into().expect("take(8) yields 8 bytes");
    Ok(u64::from_be_bytes(b))
  }

  /// Reads a big-endian `u128`.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn u128(&mut self) -> Result<u128, CodecError> {
    let b: [u8; 16] = self.take(16)?.try_into().expect("take(16) yields 16 bytes");
    Ok(u128::from_be_bytes(b))
  }

  /// Reads a `u32` element-count for a length-prefixed sequence, rejecting a count that
  /// could not possibly fit (each element is at least `min_elem_len` bytes) as
  /// [`CodecError::LengthOverflow`] *before* any element is parsed — so a hostile huge count
  /// cannot drive an unbounded pre-allocation or loop.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn seq_len(&mut self, min_elem_len: usize) -> Result<usize, CodecError> {
    let count = self.u32()? as usize;
    // A zero-sized element can't overflow the remaining bytes; guard the multiply only when
    // each element costs at least one byte (every sequence element here does).
    if min_elem_len > 0 {
      let floor = count.saturating_mul(min_elem_len);
      if floor > self.remaining() {
        return Err(CodecError::LengthOverflow {
          len: floor,
          remaining: self.remaining(),
        });
      }
    }
    Ok(count)
  }
}

//! Versioned, canonical, bounds-checked wire/disk codec primitives shared by the
//! durable ([`Header`](crate::Header)/[`VsrState`](crate::VsrState)) and message
//! ([`Message`](crate::Message)) encodings.
//!
//! The proto owns no I/O; a later I/O layer (TCP networking + async disk storage) serializes these
//! value types over the wire and onto disk, so the encoding is **part of the protocol
//! contract**, not a driver detail. The three requirements every encoding here meets:
//!
//! - **Versioned** — every MESSAGE encoding leads with [`WIRE_VERSION`]; the DURABLE on-disk forms
//!   version INDEPENDENTLY (the [`Header`] via [`HEADER_VERSION`](crate::HEADER_VERSION), the superblock
//!   root [`VsrState`](crate::VsrState) via [`SUPERBLOCK_VERSION`](crate::SUPERBLOCK_VERSION)), so a
//!   message-format change never invalidates a persisted root. Decode REJECTS an unknown version with
//!   [`CodecError::UnknownVersion`] so each format can evolve.
//! - **Canonical** — a fixed field order, big-endian scalars (matching the existing
//!   `Header::compute_checksum` `to_be_bytes` order), length-prefixed variable parts.
//! - **Bounds-checked, panic-free decode** — decode takes `&[u8]` and returns
//!   `Result<T, CodecError>`; it NEVER panics / indexes out of range on a truncated,
//!   corrupt, or adversarial buffer (the internal `Reader` below length-checks every read,
//!   mirroring `Endpoint::decode_checkpoint`).

use bytes::BufMut;

/// The MESSAGE wire format version every [`Message`](crate::Message) encoding leads with. The DURABLE
/// on-disk forms version INDEPENDENTLY — the [`Header`](crate::Header) via
/// [`HEADER_VERSION`](crate::HEADER_VERSION), the superblock root [`VsrState`](crate::VsrState) via
/// [`SUPERBLOCK_VERSION`](crate::SUPERBLOCK_VERSION) — so a message-only bump here never invalidates a
/// persisted root or blocks a rolling upgrade. A decode that reads a different version fails with
/// [`CodecError::UnknownVersion`] rather than misinterpreting later bytes, letting each format evolve
/// without silently reinterpreting old/foreign data.
pub const WIRE_VERSION: u16 = 14;

/// A typed, structured error from decoding a [`Header`](crate::Header),
/// [`VsrState`](crate::VsrState), or [`Message`](crate::Message) from bytes (or from a
/// [`VsrState`](crate::VsrState) whose decoded fields violate its invariants).
///
/// Every variant is a *parse* outcome, never a panic: a short buffer, an unknown version
/// or message tag, a length prefix that overruns the remaining bytes, or trailing garbage
/// each map to a distinct variant so a caller (and the fuzz/corruption tests) can tell
/// *why* a buffer was rejected.
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
  /// The leading format version did not match [`WIRE_VERSION`] (or, for a [`Header`](crate::Header),
  /// [`HEADER_VERSION`](crate::HEADER_VERSION)). Carries the version that was read.
  #[error("unknown wire/disk version: {0}")]
  UnknownVersion(u16),
  /// The leading [`Message`](crate::Message) discriminant tag did not name a known variant.
  /// Carries the unknown tag byte.
  #[error("unknown message tag: {0}")]
  UnknownTag(u8),
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
  /// A boolean-encoded field was neither `0` nor `1`. The wire form is canonical (exactly one byte
  /// representation per value), so a non-`0`/`1` byte is a malformed frame, not a truthy value.
  #[error("invalid boolean byte: {0}")]
  InvalidBool(u8),
  /// A wire field decoded to a value the domain type cannot represent (a wrong-length id/checksum,
  /// an out-of-range count, an absent required oneof), or the protobuf envelope itself violated the
  /// wire grammar (an invalid wire type, an overlong varint, a missing message body) without a more
  /// specific variant to name it. Carries a static label naming the offending field or context.
  #[error("malformed wire field: {what}")]
  Malformed {
    /// A static label naming the offending field or decode context.
    what: &'static str,
  },
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

  /// Reads a `u32`-length-prefixed byte run (a `Bytes` payload), validating the prefix against
  /// the bytes that actually remain: a prefix exceeding the remainder is a corrupt or adversarial
  /// length, reported as [`CodecError::LengthOverflow`] rather than an out-of-range slice.
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn bytes_u32(&mut self) -> Result<&'a [u8], CodecError> {
    let len = self.u32()? as usize;
    if len > self.remaining() {
      return Err(CodecError::LengthOverflow {
        len,
        remaining: self.remaining(),
      });
    }
    self.take(len)
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

/// Appends a `u32`-length-prefixed copy of `bytes` to `out` (the canonical variable-length
/// payload framing read back by [`Reader::bytes_u32`]: a big-endian `u32` byte count, then the
/// bytes). Used to frame every `Bytes` payload + snapshot envelope in a message.
#[cfg_attr(not(tarpaulin), inline)]
pub(crate) fn write_bytes_u32(out: &mut impl BufMut, bytes: &[u8]) {
  // The length prefix is a `u32`; a payload at/above 4 GiB would silently truncate the count and corrupt
  // the frame. No proto payload approaches this (a message is frame-bounded well below 4 GiB), so it is a
  // `debug_assert` guarding the cast rather than a runtime branch.
  debug_assert!(
    bytes.len() <= u32::MAX as usize,
    "write_bytes_u32: payload length {} exceeds u32::MAX",
    bytes.len()
  );
  out.put_u32(bytes.len() as u32);
  out.put_slice(bytes);
}

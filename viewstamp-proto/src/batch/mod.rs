//! Edge-batching codec: many application units riding ONE consensus operation's opaque body.
//!
//! A driver-side aggregator coalesces independent user units into a single client request — it
//! builds the [`Request`](crate::Request) body with a [`BatchBuilder`]. The embedder's
//! [`StateMachine::apply`](crate::StateMachine::apply) decodes that body with a [`BatchView`],
//! applies each unit in order, and encodes one result per unit into the reply body with a
//! [`ReplyBuilder`]; the aggregator decodes the reply with a [`ReplyView`] and completes each
//! unit's caller. Consensus is untouched: the proto replicates and applies the batch as one opaque
//! op body, so batching multiplies per-op throughput without touching quorum or log logic.
//!
//! # Wire layout (request and reply bodies alike)
//!
//! A big-endian `u32` unit count (`>= 1`), then per unit a big-endian `u32` length followed by the
//! unit's bytes. Units are opaque and variable-length; a zero-length unit is legitimate. Decoding
//! is EXACT: the count must be at least one, every declared length must lie in-bounds, and the
//! final unit must end exactly at the buffer's end — trailing bytes are malformed, so each unit
//! list has one canonical encoding.
//!
//! # Budget contract
//!
//! [`BatchBuilder::new`] takes the byte budget the assembled body must fit (for a request body,
//! the transport bound `max_request_body_len()`), and [`BatchBuilder::push`] enforces
//! [`BATCH_COUNT_OVERHEAD`]` + Σ (`[`BATCH_UNIT_OVERHEAD`]` + unit_len) <= budget` INCLUDING the
//! unit being pushed — the first unit can fail too. [`BatchBuilder::finish`] refuses an empty
//! batch. These builders are the only producers of the layout, so a produced body is non-empty
//! and within budget by construction.
//!
//! # Ceiling contract (reply side)
//!
//! The aggregator sizes each batch so its WORST-CASE reply fits
//! [`max_reply_body_len`](crate::max_reply_body_len): it declares a per-unit reply ceiling and
//! admits request units only while the ceiling-priced reply still fits the reply budget.
//! [`ReplyBuilder`] holds the state machine to that declaration — [`ReplyBuilder::push`] rejects
//! a unit reply over the ceiling with [`ReplyPushError::UnitOverCeiling`], because an over-ceiling
//! unit would seal a reply body the transport can refuse, with no in-protocol recovery: the op is
//! already committed and applied by the time the reply exists.

use bytes::{BufMut, Bytes, BytesMut};

/// Bytes the batch layout spends before any unit: the big-endian `u32` unit count.
pub const BATCH_COUNT_OVERHEAD: usize = 4;

/// Fixed bytes each unit costs beyond its own length: its big-endian `u32` length prefix.
pub const BATCH_UNIT_OVERHEAD: usize = 4;

/// The largest budget a builder honors. The count and per-unit length prefixes are `u32`, and the
/// message layer length-prefixes every body with a `u32` (`codec::write_bytes_u32`), so no body
/// over `u32::MAX` bytes is encodable anyway; clamping the budget here is what lets `push` prove —
/// from `total <= budget` alone — that every emitted length fits its prefix and that the unit
/// count can never reach `u32::MAX`.
const BUDGET_CAP: usize = u32::MAX as usize;

/// A pushed unit does not fit the batch: its length prefix plus its bytes would lift the encoded
/// body past the builder's budget. The failed push leaves the builder unchanged, so the caller can
/// seal the current batch and retry the unit in the next one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
  "unit of {unit_len} bytes does not fit the batch budget: {bytes_used} of {budget} bytes used"
)]
pub struct BatchFull {
  bytes_used: usize,
  unit_len: usize,
  budget: usize,
}

impl BatchFull {
  /// The encoded bytes the batch already holds (count prefix included).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn bytes_used(&self) -> usize {
    self.bytes_used
  }

  /// The length of the refused unit.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn unit_len(&self) -> usize {
    self.unit_len
  }

  /// The budget the encoded batch is held to.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn budget(&self) -> usize {
    self.budget
  }
}

/// `finish` refused a batch with no units: the wire layout requires `count >= 1`, so an empty
/// batch has no encoding (and nothing to apply or reply to).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a batch must carry at least one unit")]
pub struct EmptyBatch;

/// A reply unit was refused by [`ReplyBuilder::push`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplyPushError {
  /// The unit exceeds the per-unit reply ceiling the aggregator declared when it sized the batch.
  /// Checked BEFORE the budget: the ceiling is the per-unit contract a single unit can violate on
  /// its own, regardless of how full the batch already is.
  #[error("reply unit of {len} bytes exceeds the declared per-unit ceiling of {max_unit_len}")]
  UnitOverCeiling {
    /// The offending unit's length.
    len: usize,
    /// The declared per-unit ceiling.
    max_unit_len: usize,
  },
  /// The unit is within the ceiling but the reply body's budget cannot take it.
  #[error("{0}")]
  Full(#[from] BatchFull),
}

/// A request or reply body failed batch validation.
///
/// Every variant is a *parse* outcome, never a panic: a short buffer, a zero count, a count or
/// unit length the remaining bytes cannot hold, or trailing garbage each map to a distinct
/// variant so a caller can tell *why* a body was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BatchMalformed {
  /// The buffer ended before a `u32` prefix (the count, or a unit length) could be fully read:
  /// `expected` more bytes were needed at the current position but only `got` remained.
  #[error("truncated batch: expected {expected} more bytes, got {got}")]
  Truncated {
    /// The number of bytes the prefix required.
    expected: usize,
    /// The number of bytes actually remaining.
    got: usize,
  },
  /// The unit count was zero — a batch carries at least one unit.
  #[error("batch count is zero (a batch carries at least one unit)")]
  ZeroCount,
  /// The unit count named more units than the remaining bytes could possibly hold (each unit
  /// costs at least its 4-byte length prefix), rejected *before* any unit is walked so a hostile
  /// huge count cannot drive an unbounded loop.
  #[error("batch count {count} cannot fit the {remaining} remaining bytes")]
  CountOverflow {
    /// The decoded unit count.
    count: u32,
    /// The number of bytes remaining after the count prefix.
    remaining: usize,
  },
  /// A unit's length prefix named more bytes than remained (a corrupt or adversarial length).
  /// Distinct from [`Self::Truncated`] so a hostile oversized prefix is not confused with an
  /// honestly-short tail.
  #[error("unit length {len} exceeds the {remaining} remaining bytes")]
  LengthOverflow {
    /// The decoded unit length.
    len: usize,
    /// The number of bytes actually remaining when it was read.
    remaining: usize,
  },
  /// The declared units decoded cleanly but bytes remained after the final unit — the layout has
  /// exactly one byte representation per unit list, so trailing bytes signal a corrupt or
  /// maliciously-extended body. Carries the number of leftover bytes.
  #[error("{0} trailing bytes after the final unit")]
  TrailingBytes(usize),
}

/// Accumulates user units into one request-body batch, holding the encoded length to a byte
/// budget by construction.
///
/// The driver-side aggregator owns one per in-flight batch: it pushes each submitted unit —
/// sealing the batch and starting the next when [`Self::push`] reports [`BatchFull`] — and ships
/// [`Self::finish`]'s bytes as the opaque body of a single [`Request`](crate::Request).
#[derive(Debug)]
pub struct BatchBuilder {
  buf: BytesMut,
  count: u32,
  budget: usize,
}

impl BatchBuilder {
  /// Creates a builder whose encoded output may not exceed `budget` bytes.
  ///
  /// For a request body the budget is the transport bound `max_request_body_len()` (or anything
  /// smaller). A budget above `u32::MAX` is clamped to it — no larger body is encodable, since
  /// the message layer length-prefixes every body with a `u32`; the clamp is also what lets
  /// [`Self::push`] prove every emitted length fits its `u32` prefix. A budget below
  /// `BATCH_COUNT_OVERHEAD + BATCH_UNIT_OVERHEAD` admits no unit at all, so [`Self::finish`] can
  /// only ever fail on it.
  pub fn new(budget: usize) -> Self {
    let mut buf = BytesMut::with_capacity(BATCH_COUNT_OVERHEAD);
    // Reserve the count prefix up front: `bytes_used` is then exactly `buf.len()`, and `finish`
    // fills the real count in place without shifting the units.
    buf.put_bytes(0, BATCH_COUNT_OVERHEAD);
    Self {
      buf,
      count: 0,
      budget: budget.min(BUDGET_CAP),
    }
  }

  /// Appends one unit, or refuses it — leaving the batch unchanged — when its length prefix plus
  /// its bytes would lift the encoded body past the budget. The check includes the unit being
  /// pushed, so a first unit too large for the whole budget fails too. A zero-length unit is a
  /// legitimate payload (it still costs its length prefix).
  pub fn push(&mut self, unit: &[u8]) -> Result<(), BatchFull> {
    // The would-be encoded length including this unit. `checked_add` because `unit.len()` is
    // caller-controlled and an overflowing total is by definition over any representable budget.
    let needed = self
      .buf
      .len()
      .checked_add(BATCH_UNIT_OVERHEAD)
      .and_then(|n| n.checked_add(unit.len()));
    match needed {
      Some(needed) if needed <= self.budget => {}
      _ => {
        return Err(BatchFull {
          bytes_used: self.buf.len(),
          unit_len: unit.len(),
          budget: self.budget,
        });
      }
    }
    // `needed <= budget <= u32::MAX` bounds both writes: the unit length fits its u32 prefix, and
    // the count — each unit costing at least its 4-byte prefix — stays well under u32::MAX.
    self.buf.put_u32(unit.len() as u32);
    self.buf.put_slice(unit);
    self.count += 1;
    Ok(())
  }

  /// The number of units pushed so far.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn len(&self) -> usize {
    self.count as usize
  }

  /// True iff no unit has been pushed yet ([`Self::finish`] would refuse the batch).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    self.count == 0
  }

  /// The encoded length so far, count prefix included: `BATCH_COUNT_OVERHEAD +
  /// Σ (BATCH_UNIT_OVERHEAD + unit_len)`. Equals the length [`Self::finish`] would emit, and
  /// never exceeds [`Self::budget`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn bytes_used(&self) -> usize {
    self.buf.len()
  }

  /// The byte budget the encoded batch is held to (the constructor argument, clamped to
  /// `u32::MAX`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn budget(&self) -> usize {
    self.budget
  }

  /// Seals the batch into the opaque body bytes, refusing an empty one (`count >= 1` is a wire
  /// invariant — the decoder rejects a zero count as [`BatchMalformed::ZeroCount`]).
  pub fn finish(self) -> Result<Bytes, EmptyBatch> {
    if self.count == 0 {
      return Err(EmptyBatch);
    }
    let mut buf = self.buf;
    // `new` wrote the 4-byte placeholder, so the slice is always in range.
    buf[..BATCH_COUNT_OVERHEAD].copy_from_slice(&self.count.to_be_bytes());
    Ok(buf.freeze())
  }
}

/// Accumulates per-unit results into one reply-body batch: the same layout and budget seal as
/// [`BatchBuilder`], plus the per-unit ceiling the aggregator declared when it sized the batch.
///
/// The embedder's state machine owns one per applied batch: it pushes exactly one result per
/// decoded request unit, in unit order, and returns [`Self::finish`]'s bytes from
/// [`StateMachine::apply`](crate::StateMachine::apply) so they ride the
/// [`Reply`](crate::Reply) back to the aggregator.
#[derive(Debug)]
pub struct ReplyBuilder {
  inner: BatchBuilder,
  max_unit_len: usize,
}

impl ReplyBuilder {
  /// Creates a builder whose encoded output may not exceed `budget` bytes and whose every unit
  /// may not exceed `max_unit_len` bytes.
  ///
  /// For a reply body the budget is [`max_reply_body_len`](crate::max_reply_body_len) (or
  /// anything smaller); `max_unit_len` is the per-unit reply ceiling the aggregator budgeted the
  /// batch against. The budget is clamped exactly as in [`BatchBuilder::new`].
  pub fn new(budget: usize, max_unit_len: usize) -> Self {
    Self {
      inner: BatchBuilder::new(budget),
      max_unit_len,
    }
  }

  /// Appends one unit's reply, or refuses it — leaving the batch unchanged — when it exceeds the
  /// declared per-unit ceiling ([`ReplyPushError::UnitOverCeiling`], checked first) or the body
  /// budget ([`ReplyPushError::Full`]). The ceiling check is the state-machine-side half of the
  /// aggregator's reply budgeting: a unit held to the ceiling always fits the batch the
  /// aggregator admitted it to.
  pub fn push(&mut self, unit: &[u8]) -> Result<(), ReplyPushError> {
    if unit.len() > self.max_unit_len {
      return Err(ReplyPushError::UnitOverCeiling {
        len: unit.len(),
        max_unit_len: self.max_unit_len,
      });
    }
    self.inner.push(unit)?;
    Ok(())
  }

  /// The number of units pushed so far.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn len(&self) -> usize {
    self.inner.len()
  }

  /// True iff no unit has been pushed yet ([`Self::finish`] would refuse the batch).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    self.inner.is_empty()
  }

  /// The encoded length so far, count prefix included (see [`BatchBuilder::bytes_used`]).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn bytes_used(&self) -> usize {
    self.inner.bytes_used()
  }

  /// The byte budget the encoded reply batch is held to (clamped to `u32::MAX`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn budget(&self) -> usize {
    self.inner.budget()
  }

  /// The declared per-unit reply ceiling every pushed unit is held to.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn max_unit_len(&self) -> usize {
    self.max_unit_len
  }

  /// Seals the reply batch into the opaque body bytes, refusing an empty one.
  pub fn finish(self) -> Result<Bytes, EmptyBatch> {
    self.inner.finish()
  }
}

/// The validated unit region of a parsed batch body: the bytes after the count prefix, plus the
/// count itself. Shared by [`BatchView`] and [`ReplyView`] — the two sides decode one layout —
/// and only constructible through [`Self::parse`]'s full validation, so every walk over it is
/// in-bounds by construction.
#[derive(Debug, Clone, Copy)]
struct RawView<'a> {
  units: &'a [u8],
  count: u32,
}

impl<'a> RawView<'a> {
  /// Validates the exact layout: a `u32` count `>= 1`, then exactly `count` length-prefixed
  /// units ending precisely at the buffer's end.
  fn parse(buf: &'a [u8]) -> Result<Self, BatchMalformed> {
    let (count_bytes, units) =
      buf
        .split_first_chunk::<BATCH_COUNT_OVERHEAD>()
        .ok_or(BatchMalformed::Truncated {
          expected: BATCH_COUNT_OVERHEAD,
          got: buf.len(),
        })?;
    let count = u32::from_be_bytes(*count_bytes);
    if count == 0 {
      return Err(BatchMalformed::ZeroCount);
    }
    // Floor check before walking: each unit costs at least its length prefix, so a count whose
    // prefixes alone exceed the remainder is rejected without touching a single unit.
    if (count as usize).saturating_mul(BATCH_UNIT_OVERHEAD) > units.len() {
      return Err(BatchMalformed::CountOverflow {
        count,
        remaining: units.len(),
      });
    }
    let mut tail = units;
    let mut left = count;
    while left > 0 {
      let (len_bytes, rest) =
        tail
          .split_first_chunk::<BATCH_UNIT_OVERHEAD>()
          .ok_or(BatchMalformed::Truncated {
            expected: BATCH_UNIT_OVERHEAD,
            got: tail.len(),
          })?;
      let len = u32::from_be_bytes(*len_bytes) as usize;
      let (_, rest) = rest
        .split_at_checked(len)
        .ok_or(BatchMalformed::LengthOverflow {
          len,
          remaining: rest.len(),
        })?;
      tail = rest;
      left -= 1;
    }
    if !tail.is_empty() {
      return Err(BatchMalformed::TrailingBytes(tail.len()));
    }
    Ok(Self { units, count })
  }

  /// The validated unit count (`>= 1`).
  const fn len(&self) -> usize {
    self.count as usize
  }

  /// Iterates the units in order, zero-copy.
  const fn units(&self) -> BatchUnits<'a> {
    BatchUnits {
      tail: self.units,
      remaining: self.count,
    }
  }

  /// The `index`th unit, or `None` past the end. Re-walks the preceding length prefixes
  /// (`O(index)` prefix reads — bodies are skipped, not touched); iteration via `units` is the
  /// sequential path.
  fn unit(&self, index: usize) -> Option<&'a [u8]> {
    self.units().nth(index)
  }
}

/// A zero-copy decoded view over a request body's batch of units — the state-machine side of the
/// codec: [`StateMachine::apply`](crate::StateMachine::apply) parses the committed op body and
/// applies each unit in order.
///
/// [`Self::parse`] is the only constructor and validates the exact layout, so every accessor and
/// iteration on a view is in-bounds and panic-free by construction.
#[derive(Debug, Clone, Copy)]
pub struct BatchView<'a>(RawView<'a>);

impl<'a> BatchView<'a> {
  /// Validates `buf` as a batch body: a big-endian `u32` count `>= 1`, then exactly `count`
  /// `u32`-length-prefixed units ending precisely at the buffer's end — a declared length past
  /// the remainder, a count the bytes cannot hold, or trailing bytes each fail with the matching
  /// [`BatchMalformed`] variant.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn parse(buf: &'a [u8]) -> Result<Self, BatchMalformed> {
    RawView::parse(buf).map(Self)
  }

  /// The number of units in the batch (`>= 1`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn len(&self) -> usize {
    self.0.len()
  }

  /// Always `false`: [`Self::parse`] rejects a zero count. Provided to pair with [`Self::len`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    self.0.count == 0
  }

  /// Iterates the units in order as zero-copy borrows into the parsed input.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn units(&self) -> BatchUnits<'a> {
    self.0.units()
  }

  /// The `index`th unit, or `None` past the end. Re-walks the preceding length prefixes
  /// (`O(index)` — prefer [`Self::units`] for sequential access).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn unit(&self, index: usize) -> Option<&'a [u8]> {
    self.0.unit(index)
  }
}

/// A zero-copy decoded view over a reply body's batch of per-unit results — the aggregator side
/// of the codec: it parses the [`Reply`](crate::Reply) body and completes each submitted unit's
/// caller with its result, pairing reply units with request units by position.
///
/// Identical layout and validation to [`BatchView`]; the two names keep each direction's role
/// explicit at its call sites.
#[derive(Debug, Clone, Copy)]
pub struct ReplyView<'a>(RawView<'a>);

impl<'a> ReplyView<'a> {
  /// Validates `buf` as a reply body — the same exact-layout validation as [`BatchView::parse`].
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn parse(buf: &'a [u8]) -> Result<Self, BatchMalformed> {
    RawView::parse(buf).map(Self)
  }

  /// The number of unit results in the reply (`>= 1`; equals the request batch's unit count when
  /// the state machine kept the one-result-per-unit contract).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn len(&self) -> usize {
    self.0.len()
  }

  /// Always `false`: [`Self::parse`] rejects a zero count. Provided to pair with [`Self::len`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    self.0.count == 0
  }

  /// Iterates the unit results in order as zero-copy borrows into the parsed input.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn units(&self) -> BatchUnits<'a> {
    self.0.units()
  }

  /// The `index`th unit result, or `None` past the end. Re-walks the preceding length prefixes
  /// (`O(index)` — prefer [`Self::units`] for sequential access).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn unit(&self, index: usize) -> Option<&'a [u8]> {
    self.0.unit(index)
  }
}

/// Iterator over a parsed batch's units, yielding each as a zero-copy `&[u8]` borrow into the
/// parsed input. Returned by [`BatchView::units`] and [`ReplyView::units`]; exact-size (the
/// validated count is known up front).
#[derive(Debug, Clone)]
pub struct BatchUnits<'a> {
  tail: &'a [u8],
  remaining: u32,
}

impl<'a> Iterator for BatchUnits<'a> {
  type Item = &'a [u8];

  #[cfg_attr(not(tarpaulin), inline)]
  fn next(&mut self) -> Option<&'a [u8]> {
    if self.remaining == 0 {
      return None;
    }
    // Parse validated every prefix and bound, so the two `?`s below are the panic-free residue of
    // that proof, not reachable branches.
    let (len_bytes, rest) = self.tail.split_first_chunk::<BATCH_UNIT_OVERHEAD>()?;
    let (unit, rest) = rest.split_at_checked(u32::from_be_bytes(*len_bytes) as usize)?;
    self.tail = rest;
    self.remaining -= 1;
    Some(unit)
  }

  #[cfg_attr(not(tarpaulin), inline)]
  fn size_hint(&self) -> (usize, Option<usize>) {
    let n = self.remaining as usize;
    (n, Some(n))
  }
}

impl ExactSizeIterator for BatchUnits<'_> {}

impl core::iter::FusedIterator for BatchUnits<'_> {}

#[cfg(test)]
mod tests;

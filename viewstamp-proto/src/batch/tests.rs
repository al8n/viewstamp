use super::*;
use crate::Prng;

/// Encodes `units` by hand in the wire layout (the test-side mirror the builders are checked
/// against).
fn encode_raw(units: &[&[u8]]) -> std::vec::Vec<u8> {
  let mut out = std::vec::Vec::new();
  out.extend_from_slice(&(units.len() as u32).to_be_bytes());
  for unit in units {
    out.extend_from_slice(&(unit.len() as u32).to_be_bytes());
    out.extend_from_slice(unit);
  }
  out
}

#[test]
fn builder_output_round_trips_through_both_views() {
  let units: [&[u8]; 4] = [b"", b"a", b"hello world", &[0xAB; 300]];
  let mut builder = BatchBuilder::new(1024);
  let mut reply = ReplyBuilder::new(1024, 300);
  for unit in units {
    builder.push(unit).expect("within budget");
    reply.push(unit).expect("within budget and ceiling");
  }
  assert_eq!(builder.len(), 4);
  assert!(!builder.is_empty());
  let expected_len = BATCH_COUNT_OVERHEAD
    + units
      .iter()
      .map(|u| BATCH_UNIT_OVERHEAD + u.len())
      .sum::<usize>();
  assert_eq!(builder.bytes_used(), expected_len);

  let body = builder.finish().expect("non-empty");
  assert_eq!(body.len(), expected_len);
  assert_eq!(
    &body[..],
    encode_raw(&units),
    "the builder emits the wire layout byte-for-byte"
  );

  let view = BatchView::parse(&body).expect("builder output parses");
  assert_eq!(view.len(), units.len());
  assert!(!view.is_empty());
  let got: std::vec::Vec<&[u8]> = view.units().collect();
  assert_eq!(got, units, "iteration yields the pushed units in order");
  for (i, unit) in units.iter().enumerate() {
    assert_eq!(
      view.unit(i),
      Some(*unit),
      "unit {i} via the indexed accessor"
    );
  }
  assert_eq!(view.unit(units.len()), None, "one past the end is None");

  // The reply side shares the layout byte-for-byte and parses identically.
  let reply_body = reply.finish().expect("non-empty");
  assert_eq!(reply_body, body, "the two builders emit one layout");
  let reply_view = ReplyView::parse(&reply_body).expect("reply output parses");
  assert_eq!(reply_view.len(), units.len());
  assert_eq!(reply_view.unit(2), Some(&b"hello world"[..]));
  let got: std::vec::Vec<&[u8]> = reply_view.units().collect();
  assert_eq!(got, units);
}

#[test]
fn random_unit_lists_round_trip_byte_identical() {
  let mut rng = Prng::new(0xBA7C);
  for _ in 0..64 {
    let count = 1 + rng.below(17) as usize;
    let units: std::vec::Vec<std::vec::Vec<u8>> = (0..count)
      .map(|_| {
        let len = rng.below(600) as usize;
        (0..len).map(|_| rng.next_u64() as u8).collect()
      })
      .collect();
    let mut builder = BatchBuilder::new(u32::MAX as usize);
    let mut reply = ReplyBuilder::new(u32::MAX as usize, 600);
    for unit in &units {
      builder.push(unit).expect("under budget");
      reply.push(unit).expect("under budget and ceiling");
    }
    let body = builder.finish().expect("non-empty");
    let view = BatchView::parse(&body).expect("builder output parses");
    assert_eq!(view.len(), units.len());
    let got: std::vec::Vec<&[u8]> = view.units().collect();
    let want: std::vec::Vec<&[u8]> = units.iter().map(|u| u.as_slice()).collect();
    assert_eq!(got, want);
    for (i, unit) in units.iter().enumerate() {
      assert_eq!(view.unit(i), Some(unit.as_slice()));
    }
    let reply_body = reply.finish().expect("non-empty");
    assert_eq!(reply_body, body, "the reply layout is the same layout");
    assert_eq!(
      ReplyView::parse(&reply_body).expect("parses").len(),
      units.len()
    );
  }
}

#[test]
fn a_unit_landing_exactly_on_the_budget_fits_and_one_more_byte_does_not() {
  // 4 (count) + 4 (length prefix) + 10 (unit) == 18.
  let mut exact = BatchBuilder::new(18);
  exact.push(&[7u8; 10]).expect("lands exactly on the budget");
  assert_eq!(exact.bytes_used(), 18);
  assert_eq!(exact.budget(), 18);
  // The batch is byte-full: even a zero-length unit (4 more prefix bytes) no longer fits.
  assert_eq!(
    exact.push(&[]),
    Err(BatchFull {
      bytes_used: 18,
      unit_len: 0,
      budget: 18,
    })
  );
  // The failed push left the batch intact: it still seals with its single unit.
  let body = exact.finish().expect("non-empty");
  assert_eq!(body.len(), 18);
  assert_eq!(BatchView::parse(&body).expect("parses").len(), 1);

  let mut over = BatchBuilder::new(18);
  assert_eq!(
    over.push(&[7u8; 11]),
    Err(BatchFull {
      bytes_used: 4,
      unit_len: 11,
      budget: 18,
    }),
    "one byte over the budget is refused"
  );
}

#[test]
fn the_first_unit_over_budget_fails_and_the_builder_is_unchanged() {
  let mut builder = BatchBuilder::new(8);
  assert_eq!(
    builder.push(b"x"),
    Err(BatchFull {
      bytes_used: 4,
      unit_len: 1,
      budget: 8,
    }),
    "the running total includes the would-be FIRST unit"
  );
  assert!(builder.is_empty());
  assert_eq!(builder.len(), 0);
  assert_eq!(builder.bytes_used(), BATCH_COUNT_OVERHEAD);
  // The refusal was a no-op: a unit that fits is still accepted afterwards.
  builder
    .push(b"")
    .expect("an empty unit fits the 8-byte budget exactly");
  assert_eq!(builder.bytes_used(), 8);
}

#[test]
fn units_summing_exactly_to_the_budget_land_on_it() {
  // 4 + (4 + 3) + (4 + 5) == 20.
  let mut builder = BatchBuilder::new(20);
  builder.push(b"abc").expect("fits");
  builder.push(b"defgh").expect("sums exactly to the budget");
  assert_eq!(builder.bytes_used(), 20);
  let body = builder.finish().expect("non-empty");
  assert_eq!(body.len(), 20);
  let view = BatchView::parse(&body).expect("parses");
  assert_eq!(view.unit(0), Some(&b"abc"[..]));
  assert_eq!(view.unit(1), Some(&b"defgh"[..]));
}

#[test]
fn finish_on_an_empty_builder_is_an_error() {
  assert_eq!(BatchBuilder::new(64).finish(), Err(EmptyBatch));
  assert_eq!(ReplyBuilder::new(64, 16).finish(), Err(EmptyBatch));
  // Still empty after a refused push: the refusal must not count as a unit.
  let mut builder = BatchBuilder::new(8);
  assert!(builder.push(b"too big").is_err());
  assert_eq!(builder.finish(), Err(EmptyBatch));
}

#[test]
fn a_reply_unit_at_the_ceiling_passes_and_one_byte_over_is_rejected() {
  let mut reply = ReplyBuilder::new(1024, 5);
  assert_eq!(reply.max_unit_len(), 5);
  reply.push(&[1u8; 5]).expect("exactly at the ceiling");
  assert_eq!(
    reply.push(&[1u8; 6]),
    Err(ReplyPushError::UnitOverCeiling {
      len: 6,
      max_unit_len: 5,
    })
  );
  assert_eq!(reply.len(), 1, "the refused unit was not appended");

  // A unit over BOTH bounds reports the ceiling: the per-unit contract is checked first.
  let mut tiny = ReplyBuilder::new(8, 5);
  assert_eq!(
    tiny.push(&[1u8; 6]),
    Err(ReplyPushError::UnitOverCeiling {
      len: 6,
      max_unit_len: 5,
    })
  );
}

#[test]
fn a_reply_unit_under_the_ceiling_but_over_budget_reports_full() {
  let mut reply = ReplyBuilder::new(10, 8);
  assert_eq!(
    reply.push(&[1u8; 8]),
    Err(ReplyPushError::Full(BatchFull {
      bytes_used: 4,
      unit_len: 8,
      budget: 10,
    }))
  );
  assert!(reply.is_empty());
  assert_eq!(reply.bytes_used(), BATCH_COUNT_OVERHEAD);
  assert_eq!(reply.budget(), 10);
}

#[test]
fn zero_length_units_are_legitimate_payloads() {
  let mut builder = BatchBuilder::new(64);
  for _ in 0..3 {
    builder.push(&[]).expect("an empty unit is valid");
  }
  assert_eq!(builder.bytes_used(), 16);
  let body = builder.finish().expect("non-empty");
  let view = BatchView::parse(&body).expect("parses");
  assert_eq!(view.len(), 3);
  assert!(view.units().all(|u| u.is_empty()));
  assert_eq!(view.unit(2), Some(&[][..]));
  assert_eq!(view.unit(3), None);
}

#[test]
fn parse_rejects_a_truncated_count_prefix() {
  assert_eq!(
    BatchView::parse(&[]).unwrap_err(),
    BatchMalformed::Truncated {
      expected: 4,
      got: 0,
    }
  );
  assert_eq!(
    BatchView::parse(&[0, 0]).unwrap_err(),
    BatchMalformed::Truncated {
      expected: 4,
      got: 2,
    }
  );
}

#[test]
fn parse_rejects_a_zero_count() {
  assert_eq!(
    BatchView::parse(&[0, 0, 0, 0]).unwrap_err(),
    BatchMalformed::ZeroCount
  );
  // The zero count is rejected before any trailing-byte accounting.
  assert_eq!(
    BatchView::parse(&[0, 0, 0, 0, 9]).unwrap_err(),
    BatchMalformed::ZeroCount
  );
}

#[test]
fn parse_rejects_a_count_the_remaining_bytes_cannot_hold() {
  // count = 2 but only one empty unit follows: the 8-byte prefix floor exceeds the 4 remaining.
  let body = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b
  };
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::CountOverflow {
      count: 2,
      remaining: 4,
    }
  );
  // A hostile huge count fails the same floor check before any unit is walked.
  let body = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&u32::MAX.to_be_bytes());
    b.extend_from_slice(&[0u8; 32]);
    b
  };
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::CountOverflow {
      count: u32::MAX,
      remaining: 32,
    }
  );
}

#[test]
fn parse_rejects_a_missing_or_torn_final_unit_as_truncated() {
  // count = 2; the first unit is complete and padded past the count floor; the second never
  // starts.
  let mut body = std::vec::Vec::new();
  body.extend_from_slice(&2u32.to_be_bytes());
  body.extend_from_slice(&5u32.to_be_bytes());
  body.extend_from_slice(b"abcde");
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::Truncated {
      expected: 4,
      got: 0,
    }
  );
  // A torn second length prefix is the same truncation, with the leftover bytes counted.
  body.extend_from_slice(&[0, 0]);
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::Truncated {
      expected: 4,
      got: 2,
    }
  );
}

#[test]
fn parse_rejects_a_unit_length_running_past_the_buffer() {
  let mut body = std::vec::Vec::new();
  body.extend_from_slice(&1u32.to_be_bytes());
  body.extend_from_slice(&5u32.to_be_bytes());
  body.extend_from_slice(b"abc");
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::LengthOverflow {
      len: 5,
      remaining: 3,
    }
  );
  // A u32::MAX length prefix exercises the same in-bounds check without cursor-arithmetic
  // overflow.
  let mut body = std::vec::Vec::new();
  body.extend_from_slice(&1u32.to_be_bytes());
  body.extend_from_slice(&u32::MAX.to_be_bytes());
  body.extend_from_slice(&[0u8; 64]);
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::LengthOverflow {
      len: u32::MAX as usize,
      remaining: 64,
    }
  );
}

#[test]
fn parse_rejects_trailing_bytes_after_the_final_unit() {
  let mut body = encode_raw(&[b"abc", b""]);
  body.push(0);
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::TrailingBytes(1)
  );
  body.extend_from_slice(&[0, 0]);
  assert_eq!(
    BatchView::parse(&body).unwrap_err(),
    BatchMalformed::TrailingBytes(3)
  );
}

#[test]
fn reply_view_applies_identical_validation() {
  let truncated_unit = {
    let mut b = std::vec::Vec::new();
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&5u32.to_be_bytes());
    b.extend_from_slice(b"abc");
    b
  };
  let trailing = {
    let mut b = encode_raw(&[b"x"]);
    b.push(7);
    b
  };
  let cases: [&[u8]; 5] = [
    &[],
    &[0, 0, 0, 0],
    &[0, 0, 0, 9],
    &truncated_unit,
    &trailing,
  ];
  for bad in cases {
    assert_eq!(
      BatchView::parse(bad).unwrap_err(),
      ReplyView::parse(bad).unwrap_err(),
      "the two views share one validator"
    );
  }
  let good = encode_raw(&[b"ok", b""]);
  assert_eq!(ReplyView::parse(&good).expect("parses").len(), 2);
}

/// The request-side pin against the REAL transport bound: with the budget set to
/// `max_request_body_len()`, a single max-fill unit's encoded batch lands exactly on the
/// budget — so a one-unit batch can use the whole deliverable body — and one byte more is
/// refused at push.
#[cfg(feature = "tcp")]
#[test]
fn a_single_max_unit_is_tight_against_max_request_body_len() {
  use crate::max_request_body_len;

  let budget = max_request_body_len();
  let max_unit = budget - BATCH_COUNT_OVERHEAD - BATCH_UNIT_OVERHEAD;
  let unit = std::vec![0u8; max_unit];
  let mut builder = BatchBuilder::new(budget);
  builder
    .push(&unit)
    .expect("a max-fill unit lands exactly on the budget");
  assert_eq!(builder.bytes_used(), budget);
  let body = builder.finish().expect("non-empty");
  assert_eq!(
    body.len(),
    budget,
    "the encoded batch body lands exactly on max_request_body_len()"
  );
  let view = BatchView::parse(&body).expect("parses");
  assert_eq!(view.len(), 1);
  assert_eq!(view.unit(0).map(<[u8]>::len), Some(max_unit));

  let mut over = BatchBuilder::new(budget);
  assert_eq!(
    over.push(&std::vec![0u8; max_unit + 1]),
    Err(BatchFull {
      bytes_used: BATCH_COUNT_OVERHEAD,
      unit_len: max_unit + 1,
      budget,
    }),
    "one byte over the max unit pushes the batch past the transport bound"
  );
}

/// The reply-side pin against the REAL reply bound: a single ceiling-sized result encodes to
/// exactly `max_reply_body_len()`, and one byte over the ceiling is refused.
#[test]
fn a_reply_batch_is_tight_against_max_reply_body_len() {
  let budget = crate::max_reply_body_len();
  let max_unit = budget - BATCH_COUNT_OVERHEAD - BATCH_UNIT_OVERHEAD;
  let mut reply = ReplyBuilder::new(budget, max_unit);
  reply
    .push(&std::vec![0u8; max_unit])
    .expect("a ceiling-sized reply lands exactly on the budget");
  assert_eq!(reply.bytes_used(), budget);
  let body = reply.finish().expect("non-empty");
  assert_eq!(body.len(), budget);
  assert_eq!(ReplyView::parse(&body).expect("parses").len(), 1);

  let mut over = ReplyBuilder::new(budget, max_unit);
  assert_eq!(
    over.push(&std::vec![0u8; max_unit + 1]),
    Err(ReplyPushError::UnitOverCeiling {
      len: max_unit + 1,
      max_unit_len: max_unit,
    })
  );
}

#[test]
fn budgets_above_the_u32_ceiling_are_clamped() {
  assert_eq!(BatchBuilder::new(usize::MAX).budget(), u32::MAX as usize);
  assert_eq!(
    ReplyBuilder::new(usize::MAX, 16).budget(),
    u32::MAX as usize
  );
  // An in-range budget is taken as-is.
  assert_eq!(BatchBuilder::new(1024).budget(), 1024);
}

#[test]
fn batch_full_accessors_expose_the_refused_push_context() {
  let err = BatchFull {
    bytes_used: 18,
    unit_len: 4,
    budget: 20,
  };
  assert_eq!(err.bytes_used(), 18);
  assert_eq!(err.unit_len(), 4);
  assert_eq!(err.budget(), 20);
}

#[test]
fn reply_view_is_empty_is_always_false_for_a_parsed_view() {
  // `parse` rejects a zero count, so a successfully parsed `ReplyView` is never empty.
  let body = encode_raw(&[b"solo"]);
  let view = ReplyView::parse(&body).expect("parses");
  assert!(!view.is_empty());
}

#[test]
fn the_unit_iterator_is_exact_size_and_fused() {
  let body = encode_raw(&[b"a", b"bc", b""]);
  let view = BatchView::parse(&body).expect("parses");
  let mut units = view.units();
  assert_eq!(units.len(), 3);
  assert_eq!(units.size_hint(), (3, Some(3)));
  assert_eq!(units.next(), Some(&b"a"[..]));
  assert_eq!(units.len(), 2);
  assert_eq!(units.next(), Some(&b"bc"[..]));
  assert_eq!(units.next(), Some(&b""[..]));
  assert_eq!(units.len(), 0);
  assert_eq!(units.size_hint(), (0, Some(0)));
  assert_eq!(units.next(), None);
  assert_eq!(units.next(), None, "exhaustion is fused");
}

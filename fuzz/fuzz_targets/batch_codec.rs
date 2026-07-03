//! Batch-codec robustness: `BatchView::parse` / `ReplyView::parse` over arbitrary bytes must
//! never panic, the two views must agree (they decode one layout), and anything accepted must
//! walk to exactly `len()` units whose prefixes and bytes span the input exactly (the
//! exact-length contract). Arbitrary unit lists must round-trip the builders unchanged.

#![no_main]

use libfuzzer_sys::fuzz_target;
use viewstamp_proto::{BatchBuilder, BatchView, ReplyBuilder, ReplyView};

fuzz_target!(|data: &[u8]| {
  // Parse arbitrary bytes: never panics; an accepted view's units re-add to the input length.
  let batch = BatchView::parse(data);
  let reply = ReplyView::parse(data);
  assert_eq!(
    batch.is_ok(),
    reply.is_ok(),
    "the two views share one validator"
  );
  assert_eq!(
    batch.as_ref().err(),
    reply.as_ref().err(),
    "rejections agree variant-for-variant"
  );
  if let Ok(view) = batch {
    assert!(view.len() >= 1, "a parsed batch carries at least one unit");
    let mut walked = 0usize;
    let mut total = 4usize; // the count prefix
    for unit in view.units() {
      walked += 1;
      total += 4 + unit.len();
    }
    assert_eq!(walked, view.len(), "iteration yields exactly len() units");
    assert_eq!(total, data.len(), "prefixes + units span the input exactly");
  }

  // Round-trip: carve `data` into a unit list (each first byte is the next unit's length, the
  // final unit truncating at the input's end), build through BOTH builders, reparse, compare.
  let mut units: Vec<&[u8]> = Vec::new();
  let mut rest = data;
  while let Some((&take, tail)) = rest.split_first() {
    let take = usize::from(take).min(tail.len());
    units.push(&tail[..take]);
    rest = &tail[take..];
  }
  if units.is_empty() {
    return;
  }
  let mut builder = BatchBuilder::new(u32::MAX as usize);
  let mut reply = ReplyBuilder::new(u32::MAX as usize, 255);
  for unit in &units {
    builder.push(unit).expect("within budget");
    reply.push(unit).expect("within budget and ceiling");
  }
  let body = builder.finish().expect("at least one unit was pushed");
  let view = BatchView::parse(&body).expect("builder output parses");
  assert_eq!(view.len(), units.len(), "the unit count round-trips");
  for (i, (got, want)) in view.units().zip(units.iter()).enumerate() {
    assert_eq!(got, *want, "unit {i} round-trips byte-identical");
  }
  let reply_body = reply.finish().expect("at least one unit was pushed");
  assert_eq!(reply_body, body, "the two builders emit one layout");
  assert_eq!(
    ReplyView::parse(&reply_body)
      .expect("reply output parses")
      .len(),
    units.len()
  );
});

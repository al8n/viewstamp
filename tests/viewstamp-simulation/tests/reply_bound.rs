//! The reply ceiling, walked one byte at a time through a whole cluster.
//!
//! The endpoint's reply bound is derived from the transport frame cap, so a reply past it cannot be
//! framed — and the op producing it is already committed by the time anyone knows. These lanes fix
//! the state machine's reply at exactly the bound minus one, the bound, and the bound plus one, and
//! run a real 3-replica cluster over each: the first two must reach the client as bodies, and the
//! third must reach it as the terminal refusal, derived identically on every replica, with nothing
//! oversized ever offered to the client link.
//!
//! Not a PRNG-drawn axis: the reply size is cluster configuration set before the run, so these are
//! three fixed schedules rather than a sweep, and every other seeded lane stays byte-identical.

use viewstamp_proto::{ReplyBody, ReplyOutcome, ReplyTooLarge};
use viewstamp_simulation::{
  AppliedEvent, AppliedOnceChecker, BoundednessChecker, Cluster, DurabilityChecker,
  ReconfigureAppliedOnceChecker, ReplySize, StalenessChecker, ViewMonotonicChecker, check_safety,
};

/// Runs a 3-replica cluster of one client issuing `requests` requests under `reply_size`, to
/// quiescence.
fn run_with(reply_size: ReplySize, requests: u64) -> Cluster {
  let mut c = Cluster::new(3, 1, requests, /*seed*/ 20);
  c.set_reply_size(reply_size);
  for _ in 0..5_000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  c
}

/// Runs a 3-replica, single-client, single-request cluster whose state machine replies with exactly
/// `reply_len` bytes, to quiescence.
fn run_with_reply_len(reply_len: usize) -> Cluster {
  run_with(ReplySize::Fixed(reply_len), 1)
}

/// Every replica's applied outcome for the single committed op.
fn applied_outcomes(c: &Cluster) -> Vec<ReplyOutcome> {
  (0..c.replica_count())
    .filter_map(|i| {
      c.replica_applied_events(i)
        .iter()
        .find_map(|(_, ev)| match ev {
          AppliedEvent::Committed(committed) => Some(committed.outcome().clone()),
          AppliedEvent::SyncPoint(_) => None,
        })
    })
    .collect()
}

/// Asserts the invariants that must hold whatever the reply size: the op committed everywhere, the
/// client is done, and no message was ever too big for either link.
fn assert_committed_and_framed(c: &Cluster) {
  assert!(
    c.client(0).is_done(),
    "the client reached a terminal outcome"
  );
  for i in 0..c.replica_count() {
    assert_eq!(
      c.replica_sm(i).applied().len(),
      1,
      "replica {i} applied the one op"
    );
  }
  assert_eq!(
    c.oversized_dropped(),
    0,
    "no inter-replica message exceeded the frame cap"
  );
  assert_eq!(
    c.client_link_oversized_dropped(),
    0,
    "no client-link message exceeded the frame cap — with the request bounded at submit and the \
     reply bounded at apply, this count is a fence, not a tolerance"
  );
}

#[test]
fn a_reply_at_or_below_the_bound_reaches_the_client_as_a_body() {
  let max = ReplyBody::max_len();
  for len in [max - 1, max] {
    let c = run_with_reply_len(len);
    assert_committed_and_framed(&c);
    let acked = c.client(0).acked();
    assert_eq!(acked.len(), 1, "the client acked its one request");
    assert_eq!(
      acked[0].1.as_ok().map(ReplyBody::len),
      Some(len),
      "the client received the whole {len}-byte body"
    );
    for i in 0..c.replica_count() {
      assert_eq!(
        c.replica_replies_too_large(i),
        0,
        "replica {i} refused nothing at {len} bytes"
      );
    }
  }
}

#[test]
fn a_reply_one_byte_over_the_bound_is_refused_identically_on_every_replica() {
  // ONE byte past the ceiling. The op still commits and applies everywhere — the mutation is not
  // undone — but its result is undeliverable, so every replica derives the SAME refusal and the
  // client reaches a terminal error instead of a payload. The old simulator certified this
  // execution as a success: it never capped the client link, so the unframeable reply was delivered
  // anyway, and the client model appended its bytes as if the state machine had produced them.
  let max = ReplyBody::max_len();
  let expected = ReplyOutcome::TooLarge(ReplyTooLarge::new(max + 1, max));
  let c = run_with_reply_len(max + 1);
  assert_committed_and_framed(&c);

  // The client's terminal outcome is an ERROR, recorded as one — never as a reply body.
  assert!(
    c.client(0).reply_bodies().is_empty(),
    "an over-bound reply is never recorded as a reply body"
  );
  let acked = c.client(0).acked();
  assert_eq!(acked.len(), 1, "the refused request is still acknowledged");
  assert_eq!(
    (acked[0].0, acked[0].1.clone()),
    (1u64, expected.clone()),
    "the client's request ends in the refusal, carrying the offending length and the bound"
  );

  // Every replica applied the op to the SAME outcome — the property the session cache, the
  // duplicate resend, failover, and the session checkpoint all rest on.
  let outcomes = applied_outcomes(&c);
  assert_eq!(
    outcomes.len(),
    c.replica_count(),
    "every replica recorded an applied outcome"
  );
  for (i, outcome) in outcomes.iter().enumerate() {
    assert_eq!(*outcome, expected, "replica {i} derived the same refusal");
  }
  for i in 0..c.replica_count() {
    assert_eq!(
      c.replica_replies_too_large(i),
      1,
      "replica {i} counted its one refused reply"
    );
  }

  // The FULL checker set — not the applied-once oracle alone. A refusal is an acknowledgement, so
  // request ordering, the staleness floor, durability, boundedness and view monotonicity must all
  // judge it exactly as they judge a body.
  assert_all_checkers_pass(&c);
}

/// Runs every oracle the deterministic suites run, over a finished cluster. The point of the whole
/// set — rather than the applied-once checker alone — is that a refusal is an ACKNOWLEDGEMENT: the
/// request-ordering check and the staleness floor both read the client's ack history, and both must
/// judge a refused committed write exactly as they judge a body-bearing one.
fn assert_all_checkers_pass(c: &Cluster) {
  assert!(check_safety(c).is_ok(), "safety (ordering + agreement)");
  let mut once = AppliedOnceChecker::new(c.replica_count());
  assert!(once.check(c).is_ok(), "applied-once");
  let mut reconfigure_once = ReconfigureAppliedOnceChecker::new(c.replica_count());
  assert!(
    reconfigure_once.check(c).is_ok(),
    "reconfigure-applied-once"
  );
  let durability = DurabilityChecker::new(c.replica_count());
  assert!(durability.check(c).is_ok(), "durability");
  let mut staleness = StalenessChecker::new(c.replica_count(), c.client_count());
  assert!(staleness.check(c).is_ok(), "staleness");
  assert!(
    BoundednessChecker::new(64, 8).observe(c).is_ok(),
    "boundedness"
  );
  let mut views = ViewMonotonicChecker::new(c.replica_count());
  assert!(views.observe(c).is_ok(), "view monotonicity");
}

#[test]
fn a_mixed_refusal_and_success_stream_keeps_its_request_ordering() {
  // Alternating reply sizes across the ceiling: the client's request stream interleaves bodies and
  // refusals. Every request is still ANSWERED, so the acknowledgement history must be the dense
  // 1..=n sequence — which is only true if a refusal is recorded as an acknowledgement. Reading
  // bodies alone would see a hole at every refused request and mis-judge the ordering.
  let max = ReplyBody::max_len();
  let requests = 6;
  let c = run_with(ReplySize::Alternating(max + 1), requests);
  assert!(c.client(0).is_done(), "every request reached an outcome");

  let acked = c.client(0).acked();
  assert_eq!(acked.len(), requests as usize, "one ack per request");
  let (bodies, refusals): (Vec<_>, Vec<_>) = acked.iter().partition(|(_, o, _)| o.is_ok());
  assert!(
    !bodies.is_empty() && !refusals.is_empty(),
    "the lane must genuinely mix outcomes: {} bodies, {} refusals",
    bodies.len(),
    refusals.len()
  );
  for (idx, (rn, _, _)) in acked.iter().enumerate() {
    assert_eq!(*rn, idx as u64 + 1, "the ack history is dense and in order");
  }
  // The ordering check reads that history, so it accepts a mixed stream — and would reject one
  // whose refusals had gone unrecorded.
  assert_all_checkers_pass(&c);
}

#[test]
fn a_read_after_a_refused_committed_write_is_stale_unless_it_reflects_it() {
  // A refused reply still ACKNOWLEDGES a committed write, so it raises the staleness floor: a
  // linearizable read issued after that ack must reflect the op. This is precisely what a
  // body-only acknowledgement history loses — the refused write would be absent from the floor and
  // a read returning an earlier index would pass.
  let max = ReplyBody::max_len();
  let c = run_with(ReplySize::Fixed(max + 1), 1);
  let acked = c.client(0).acked();
  assert_eq!(acked.len(), 1, "the one request was acknowledged");
  assert!(
    acked[0].1.is_too_large(),
    "and it was acknowledged as refused"
  );
  let ack_instant = acked[0].2;
  let applied = c.replica_sm(0).applied().len() as u64;
  assert_eq!(applied, 1, "the refused write is applied");

  // A read issued AFTER the ack that reflects the write is fine.
  let mut fresh = StalenessChecker::new(c.replica_count(), c.client_count());
  fresh.record_read(
    ack_instant + core::time::Duration::from_millis(1),
    applied,
    bytes::Bytes::new(),
  );
  assert!(
    fresh.check(&c).is_ok(),
    "a read reflecting the refused committed write is not stale"
  );

  // The same read returning the state BEFORE it is stale — the assertion that only holds because
  // the refusal is in the floor.
  let mut stale = StalenessChecker::new(c.replica_count(), c.client_count());
  stale.record_read(
    ack_instant + core::time::Duration::from_millis(1),
    applied - 1,
    bytes::Bytes::new(),
  );
  assert!(
    stale.check(&c).is_violation(),
    "a read that misses the refused committed write must be flagged stale"
  );
}

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
use viewstamp_simulation::{AppliedEvent, AppliedOnceChecker, Cluster};

/// Runs a 3-replica, single-client, single-request cluster whose state machine replies with exactly
/// `reply_len` bytes, to quiescence.
fn run_with_reply_len(reply_len: usize) -> Cluster {
  let mut c = Cluster::new(3, 1, 1, /*seed*/ 20);
  c.set_fixed_reply_len(Some(reply_len));
  for _ in 0..5_000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  c
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
    assert!(
      c.client(0).refused().is_empty(),
      "a {len}-byte reply (bound {max}) is not refused"
    );
    let replies = c.client(0).replies();
    assert_eq!(replies.len(), 1, "the client acked its one request");
    assert_eq!(
      replies[0].1.len(),
      len,
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
    c.client(0).replies().is_empty(),
    "an over-bound reply is never recorded as a reply body"
  );
  assert_eq!(
    c.client(0).refused(),
    &[(1u64, ReplyTooLarge::new(max + 1, max))],
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

  // The exactly-once oracle agrees: the acked outcome is the applied outcome.
  let mut once = AppliedOnceChecker::new(c.replica_count());
  assert!(
    once.check(&c).is_ok(),
    "the applied-once oracle must accept a refused outcome acked to the client"
  );
}

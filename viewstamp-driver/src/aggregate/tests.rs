use std::{
  cell::Cell,
  future::Future,
  pin::Pin,
  rc::Rc,
  task::{Context, Poll},
  time::Duration,
};

use bytes::Bytes;
use futures_util::{pin_mut, task::noop_waker_ref};
use viewstamp_proto::{BatchView, ReplyBuilder, ReplyOutcome};

use super::{
  BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchConfig, BatchError, BatchHandle,
  OutcomeUnknownReason, RefusedReason, ReplyLostReason, aggregator, aggregator_with_stall,
};
use crate::{
  Command, DriverError, Handle,
  session::{InflightBudget, MAX_INFLIGHT, MAX_PENDING_BYTES, Retirement},
};

/// The test's driver end: it owns the command receiver and plays the driver, decoding each
/// submitted body and answering its reply oneshot.
struct TestDriver {
  commands: futures_channel::mpsc::Receiver<Command>,
  _events: flume::Sender<viewstamp_proto::Event>,
}

impl TestDriver {
  /// The next submitted body: its raw bytes, decoded units, and the reply sender to answer.
  fn next_body(
    &mut self,
  ) -> (
    Bytes,
    Vec<Vec<u8>>,
    futures_channel::oneshot::Sender<ReplyOutcome>,
  ) {
    let cmd = self.commands.try_recv().expect("a body was submitted");
    match cmd {
      Command::Submit {
        body,
        reply,
        reservation,
      } => {
        // Play the driver resolving the entry: the reservation releases on drop.
        drop(reservation);
        let units = BatchView::parse(&body)
          .expect("the pump ships valid batch bodies")
          .units()
          .map(<[u8]>::to_vec)
          .collect();
        (body, units, reply)
      }
      other => panic!("expected Submit, got {other:?}"),
    }
  }

  fn assert_no_body(&mut self) {
    assert!(
      self.commands.try_recv().is_err(),
      "no body should have been submitted"
    );
  }
}

/// A hand-built `Handle` over raw channels, exactly as the driver crates construct one; the
/// driver byte cap shapes `submit_byte_limit` for budget-edge tests.
fn driver_handle(max_pending_bytes: usize) -> (Handle, TestDriver) {
  let (tx, commands) = futures_channel::mpsc::channel::<Command>(8);
  let (events_tx, events_rx) = flume::unbounded();
  let handle = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, max_pending_bytes),
    Retirement::new(),
  );
  (
    handle,
    TestDriver {
      commands,
      _events: events_tx,
    },
  )
}

fn poll_once<F: Future>(fut: &mut Pin<&mut F>) -> Poll<F::Output> {
  let mut cx = Context::from_waker(noop_waker_ref());
  fut.as_mut().poll(&mut cx)
}

/// A committed reply body carrying one result per `units` entry.
fn reply_for(units: &[&[u8]]) -> ReplyOutcome {
  let mut builder = ReplyBuilder::new(viewstamp_proto::max_reply_body_len(), usize::MAX);
  for unit in units {
    builder.push(unit).expect("test replies fit the budget");
  }
  ReplyOutcome::from_applied(builder.finish().expect("non-empty"))
}

#[test]
fn config_requires_the_ceiling_and_defaults_the_queue_caps() {
  let cfg = BatchConfig::new(512);
  assert_eq!(cfg.max_unit_reply_len(), 512);
  assert_eq!(cfg.max_queued_units(), 4096);
  assert_eq!(cfg.max_queued_bytes(), 128 * 1024 * 1024);

  let cfg = cfg.with_max_queued_units(8).with_max_queued_bytes(64);
  assert_eq!(cfg.max_queued_units(), 8);
  assert_eq!(cfg.max_queued_bytes(), 64);

  let clamped = BatchConfig::new(0)
    .with_max_queued_units(0)
    .with_max_queued_bytes(0);
  assert_eq!(clamped.max_queued_units(), 1);
  assert_eq!(clamped.max_queued_bytes(), 1);
}

#[test]
fn reason_strings_are_stable() {
  assert_eq!(RefusedReason::QueueFull.as_str(), "queue_full");
  assert_eq!(RefusedReason::UnitTooLarge.as_str(), "unit_too_large");
  assert_eq!(RefusedReason::GroupTooLarge.as_str(), "group_too_large");
  assert_eq!(RefusedReason::PumpGone.as_str(), "pump_gone");
  assert_eq!(RefusedReason::Stalled.as_str(), "stalled");
  assert_eq!(RefusedReason::DriverRefused.as_str(), "driver_refused");
  assert_eq!(OutcomeUnknownReason::ReplyDropped.as_str(), "reply_dropped");
  assert_eq!(OutcomeUnknownReason::Stalled.as_str(), "stalled");
  assert_eq!(OutcomeUnknownReason::PumpGone.as_str(), "pump_gone");
  assert_eq!(OutcomeUnknownReason::Driver.as_str(), "driver");
  assert_eq!(ReplyLostReason::MalformedReply.as_str(), "malformed_reply");
  assert_eq!(
    ReplyLostReason::ReplyCountMismatch.as_str(),
    "reply_count_mismatch"
  );
}

/// `BatchHandle` must stay `Send + Sync` unconditionally, and `run()`'s future must be `Send`
/// for `Send` sleep factories — both pinned at compile time. The negative direction (a `!Send`
/// factory making `run()` `!Send`) is a documented compile-fail expectation left for the
/// driver-crate gates.
#[test]
fn batch_handle_and_pump_run_compile_time_pins() {
  fn assert_send_sync<T: Send + Sync>() {}
  fn requires_send<T: Send>(_: T) {}
  assert_send_sync::<BatchHandle>();

  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  let (_batch, pump) = aggregator(handle, BatchConfig::new(64));
  requires_send(pump.run());

  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  let (_batch, pump) =
    aggregator_with_stall(handle, BatchConfig::new(64), Duration::from_secs(1), |_| {
      std::future::pending::<()>()
    });
  requires_send(pump.run());
}

/// The batching clock: the first unit ships alone immediately; units submitted while its body
/// flies coalesce FIFO into ONE next body, and demux maps each unit's reply by position.
#[test]
fn units_coalesce_fifo_into_one_body_while_one_flies() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, units, reply1) = driver.next_body();
  assert_eq!(
    units,
    vec![b"u1".to_vec()],
    "an idle pump ships a lone unit"
  );

  // Three more queue while body 1 flies; the pump must not mint a second submit.
  let s2 = batch.submit(Bytes::from_static(b"u2"));
  let s3 = batch.submit(Bytes::from_static(b"u3"));
  let s4 = batch.submit(Bytes::from_static(b"u4"));
  pin_mut!(s2, s3, s4);
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut s3).is_pending());
  assert!(poll_once(&mut s4).is_pending());
  assert!(poll_once(&mut run).is_pending());
  driver.assert_no_body();

  reply1.send(reply_for(&[b"r1"])).expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(
    poll_once(&mut s1),
    Poll::Ready(Ok(Bytes::from_static(b"r1")))
  );
  let (_, units, reply2) = driver.next_body();
  assert_eq!(
    units,
    vec![b"u2".to_vec(), b"u3".to_vec(), b"u4".to_vec()],
    "everything queued during the flight packs FIFO into one body"
  );
  reply2
    .send(reply_for(&[b"r2", b"r3", b"r4"]))
    .expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Ok(Bytes::from_static(b"r2")))
  );
  assert_eq!(
    poll_once(&mut s3),
    Poll::Ready(Ok(Bytes::from_static(b"r3")))
  );
  assert_eq!(
    poll_once(&mut s4),
    Poll::Ready(Ok(Bytes::from_static(b"r4")))
  );
}

/// REQUEST-budget edge: a unit exactly filling `submit_byte_limit` packs to a body landing
/// byte-exact on the limit and ships alone — a queued companion starts the next body.
#[test]
fn a_unit_exactly_filling_the_submit_byte_limit_ships_alone() {
  let (handle, mut driver) = driver_handle(64);
  assert_eq!(handle.submit_byte_limit(), 64, "the driver byte cap binds");
  let (batch, pump) = aggregator(handle, BatchConfig::new(0));
  let run = pump.run();
  pin_mut!(run);

  let max_fill = 64 - BATCH_COUNT_OVERHEAD - BATCH_UNIT_OVERHEAD;
  let s1 = batch.submit(Bytes::from(vec![7u8; max_fill]));
  let s2 = batch.submit(Bytes::from_static(b"x"));
  pin_mut!(s1, s2);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut run).is_pending());

  let (body, units, reply1) = driver.next_body();
  assert_eq!(body.len(), 64, "the packed body lands exactly on the limit");
  assert_eq!(
    units,
    vec![vec![7u8; max_fill]],
    "the max-fill unit ships alone"
  );
  reply1.send(reply_for(&[b""])).expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(poll_once(&mut s1), Poll::Ready(Ok(Bytes::new())));

  let (_, units, reply2) = driver.next_body();
  assert_eq!(
    units,
    vec![b"x".to_vec()],
    "the companion starts the next body"
  );
  reply2.send(reply_for(&[b""])).expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(poll_once(&mut s2), Poll::Ready(Ok(Bytes::new())));
}

/// REPLY-budget edge: with a ceiling sized so exactly two ceiling-priced replies fill
/// `max_reply_body_len()`, a third queued unit splits into the next body even though the
/// request bytes would fit.
#[test]
fn the_reply_ceiling_math_splits_a_body_at_max_reply_body_len() {
  let reply_budget = viewstamp_proto::max_reply_body_len();
  let ceiling = (reply_budget - BATCH_COUNT_OVERHEAD) / 2 - BATCH_UNIT_OVERHEAD;
  assert!(
    BATCH_COUNT_OVERHEAD + 2 * (BATCH_UNIT_OVERHEAD + ceiling) <= reply_budget,
    "two ceiling-priced replies fit"
  );
  assert!(
    BATCH_COUNT_OVERHEAD + 3 * (BATCH_UNIT_OVERHEAD + ceiling) > reply_budget,
    "three do not"
  );

  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(ceiling));
  let run = pump.run();
  pin_mut!(run);

  // Occupy the pump with a first body, then queue three tiny units behind it.
  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, reply1) = driver.next_body();

  let s2 = batch.submit(Bytes::from_static(b"u2"));
  let s3 = batch.submit(Bytes::from_static(b"u3"));
  let s4 = batch.submit(Bytes::from_static(b"u4"));
  pin_mut!(s2, s3, s4);
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut s3).is_pending());
  assert!(poll_once(&mut s4).is_pending());

  reply1.send(reply_for(&[b"r1"])).expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  let (_, units, reply2) = driver.next_body();
  assert_eq!(
    units,
    vec![b"u2".to_vec(), b"u3".to_vec()],
    "the reply budget admits exactly two units; the third defers"
  );
  reply2.send(reply_for(&[b"r2", b"r3"])).expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  let (_, units, _reply3) = driver.next_body();
  assert_eq!(
    units,
    vec![b"u4".to_vec()],
    "the split unit leads the next body"
  );
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Ok(Bytes::from_static(b"r2")))
  );
  assert_eq!(
    poll_once(&mut s3),
    Poll::Ready(Ok(Bytes::from_static(b"r3")))
  );
  assert!(poll_once(&mut s4).is_pending(), "body 3 is still in flight");
}

/// GROUP atomicity: a group that no longer fits the open body defers WHOLE — the partial body
/// ships without it and the group leads the next body, never split across bodies.
#[test]
fn a_group_packs_whole_or_defers_whole() {
  let (handle, mut driver) = driver_handle(64);
  let (batch, pump) = aggregator(handle, BatchConfig::new(0));
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, reply1) = driver.next_body();

  // 4 + (4+10) = 18 used after u2; the group needs (4+20)*2 = 48 more — 66 > 64, so it defers.
  let s2 = batch.submit(Bytes::from(vec![2u8; 10]));
  let group = batch.submit_group(vec![Bytes::from(vec![3u8; 20]), Bytes::from(vec![4u8; 20])]);
  pin_mut!(s2, group);
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut group).is_pending());

  reply1.send(reply_for(&[b"r1"])).expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  let (_, units, reply2) = driver.next_body();
  assert_eq!(
    units,
    vec![vec![2u8; 10]],
    "the body ships without the group"
  );
  reply2.send(reply_for(&[b"r2"])).expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  let (_, units, reply3) = driver.next_body();
  assert_eq!(
    units,
    vec![vec![3u8; 20], vec![4u8; 20]],
    "the deferred group leads the next body, whole"
  );
  reply3.send(reply_for(&[b"ra", b"rb"])).expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(
    poll_once(&mut group),
    Poll::Ready(Ok(vec![
      Bytes::from_static(b"ra"),
      Bytes::from_static(b"rb")
    ]))
  );
}

/// A group whose encoded size lands exactly on the submit byte limit packs (whole), and the
/// replies come back in unit order.
#[test]
fn a_group_exactly_at_the_budget_packs() {
  let (handle, mut driver) = driver_handle(64);
  let (batch, pump) = aggregator(handle, BatchConfig::new(0));
  let run = pump.run();
  pin_mut!(run);

  // 4 + (4+26) + (4+26) == 64.
  let group = batch.submit_group(vec![Bytes::from(vec![5u8; 26]), Bytes::from(vec![6u8; 26])]);
  pin_mut!(group);
  assert!(poll_once(&mut group).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (body, units, reply) = driver.next_body();
  assert_eq!(body.len(), 64, "the group lands exactly on the limit");
  assert_eq!(units, vec![vec![5u8; 26], vec![6u8; 26]]);
  reply
    .send(reply_for(&[b"first", b"second"]))
    .expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(
    poll_once(&mut group),
    Poll::Ready(Ok(vec![
      Bytes::from_static(b"first"),
      Bytes::from_static(b"second")
    ]))
  );
}

/// Never-fits refusals happen AT SUBMIT, against the construction-time limits, before any
/// budget or queue is touched: an over-request-budget unit, an over-request-budget group, an
/// over-reply-budget group, and a ceiling too large for even one reply.
#[test]
fn oversized_units_and_groups_are_refused_at_submit() {
  let (handle, _driver) = driver_handle(64);
  let (batch, _pump) = aggregator(handle, BatchConfig::new(0));

  let too_big = batch.submit(Bytes::from(vec![0u8; 57]));
  pin_mut!(too_big);
  assert_eq!(
    poll_once(&mut too_big),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::UnitTooLarge,
    })),
    "57 encoded bytes + 8 overhead exceed the 64-byte limit"
  );
  let exact = batch.submit(Bytes::from(vec![0u8; 56]));
  pin_mut!(exact);
  assert!(
    poll_once(&mut exact).is_pending(),
    "one byte less is admissible"
  );

  let group = batch.submit_group(vec![Bytes::from(vec![0u8; 30]), Bytes::from(vec![0u8; 27])]);
  pin_mut!(group);
  assert_eq!(
    poll_once(&mut group),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::GroupTooLarge,
    })),
    "the group exceeds the request budget as a whole"
  );

  assert_eq!(
    batch.queue_budget().count(),
    1,
    "only the admissible submit reserved"
  );

  // Reply side: a ceiling consuming the whole reply budget admits exactly ONE unit per body —
  // a two-unit group can never fit a body whole.
  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  let reply_budget = viewstamp_proto::max_reply_body_len();
  let one_per_body = reply_budget - BATCH_COUNT_OVERHEAD - BATCH_UNIT_OVERHEAD;
  let (batch, _pump) = aggregator(handle, BatchConfig::new(one_per_body));
  let pair = batch.submit_group(vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
  pin_mut!(pair);
  assert_eq!(
    poll_once(&mut pair),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::GroupTooLarge,
    })),
    "two ceiling-priced replies cannot fit one reply body"
  );
  let lone = batch.submit(Bytes::from_static(b"a"));
  pin_mut!(lone);
  assert!(
    poll_once(&mut lone).is_pending(),
    "one ceiling-priced reply fits"
  );

  // A ceiling past the whole reply budget admits NOTHING; no clamp hides the misconfiguration.
  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, _pump) = aggregator(handle, BatchConfig::new(reply_budget));
  let refused = batch.submit(Bytes::from_static(b"a"));
  pin_mut!(refused);
  assert_eq!(
    poll_once(&mut refused),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::UnitTooLarge,
    }))
  );
  assert_eq!(batch.queue_budget().count(), 0, "nothing was reserved");

  let empty = batch.submit_group(Vec::new());
  pin_mut!(empty);
  assert_eq!(
    poll_once(&mut empty),
    Poll::Ready(Ok(Vec::new())),
    "an empty group is a no-op, not an error"
  );
}

/// Demux taxonomy pin: a committed body whose reply fails batch validation resolves EVERY unit
/// `CommittedReplyLost::MalformedReply` — never `Refused` (the body IS durably applied).
#[test]
fn a_malformed_reply_is_committed_reply_lost_for_every_unit() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);

  let group = batch.submit_group(vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
  pin_mut!(group);
  assert!(poll_once(&mut group).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, reply) = driver.next_body();
  reply
    .send(ReplyOutcome::from_applied(Bytes::from_static(b"\x00\x00")))
    .expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(
    poll_once(&mut group),
    Poll::Ready(Err(BatchError::CommittedReplyLost {
      reason: ReplyLostReason::MalformedReply,
    }))
  );
}

/// Demux taxonomy pin: a parsed reply whose unit count differs from the request batch resolves
/// every unit `CommittedReplyLost::ReplyCountMismatch` — positional pairing is untrustworthy.
#[test]
fn a_count_mismatched_reply_is_committed_reply_lost_for_every_unit() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"a"));
  let s2 = batch.submit(Bytes::from_static(b"b"));
  pin_mut!(s1, s2);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, units, reply) = driver.next_body();
  assert_eq!(units.len(), 2);
  reply
    .send(reply_for(&[b"only"]))
    .expect("the submit awaits");
  assert!(poll_once(&mut run).is_pending());
  let expected = Err(BatchError::CommittedReplyLost {
    reason: ReplyLostReason::ReplyCountMismatch,
  });
  assert_eq!(poll_once(&mut s1), Poll::Ready(expected.clone()));
  assert_eq!(poll_once(&mut s2), Poll::Ready(expected));
}

/// Submit-error taxonomy pin: a driver whose command channel is already closed refuses the
/// body (`Handle::submit` fails its pre-enqueue `try_send` — nothing entered the driver), and
/// the pump keeps serving later submits the same honest refusal.
#[test]
fn a_closed_driver_channel_refuses_the_body() {
  let (handle, driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  drop(driver);
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"a"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(
    poll_once(&mut run).is_pending(),
    "the pump survives the refusal"
  );
  assert_eq!(
    poll_once(&mut s1),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::DriverRefused,
    }))
  );
}

/// Submit-error taxonomy pin: a driver that ACCEPTS the command and then drops the reply
/// channel makes every unit of the body `OutcomeUnknown` — it may commit.
#[test]
fn an_accepted_then_dropped_reply_is_outcome_unknown_for_the_body() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"a"));
  let s2 = batch.submit(Bytes::from_static(b"b"));
  pin_mut!(s1, s2);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, reply) = driver.next_body();
  drop(reply);
  assert!(poll_once(&mut run).is_pending());
  let expected = Err(BatchError::OutcomeUnknown {
    reason: OutcomeUnknownReason::ReplyDropped,
  });
  assert_eq!(poll_once(&mut s1), Poll::Ready(expected.clone()));
  assert_eq!(poll_once(&mut s2), Poll::Ready(expected));
}

/// Pre-pack cancellation: a unit whose caller dropped before packing never appears in any
/// submitted body, and its queue-budget reservation releases at the skip.
#[test]
fn a_pre_pack_cancelled_unit_never_enters_a_body_and_frees_its_budget() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, reply1) = driver.next_body();

  // u2 queues behind the flying body, then its caller cancels; u3 queues after it.
  let s2 = batch.submit(Bytes::from_static(b"u2"));
  {
    pin_mut!(s2);
    assert!(poll_once(&mut s2).is_pending());
  }
  let s3 = batch.submit(Bytes::from_static(b"u3"));
  pin_mut!(s3);
  assert!(poll_once(&mut s3).is_pending());
  assert_eq!(
    batch.queue_budget().count(),
    2,
    "u2 and u3 hold queue budget"
  );

  reply1.send(reply_for(&[b"r1"])).expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  let (_, units, _reply2) = driver.next_body();
  assert_eq!(
    units,
    vec![b"u3".to_vec()],
    "the cancelled unit is skipped at pack, never submitted"
  );
  assert_eq!(
    batch.queue_budget().count(),
    0,
    "the skip released u2's reservation"
  );
  assert_eq!(batch.queue_budget().bytes(), 0);
}

/// Mid-body cancellation: a caller cancelling AFTER its unit packed discards only that
/// caller's result — body-mates still resolve with their own replies.
#[test]
fn a_mid_body_cancellation_leaves_body_mates_intact() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);

  // Both queue before the pump runs, so they pack into one body. s1 is box-pinned so it can be
  // dropped mid-flight below.
  let mut s1 = Box::pin(batch.submit(Bytes::from_static(b"u1")));
  let s2 = batch.submit(Bytes::from_static(b"u2"));
  pin_mut!(s2);
  assert!(poll_once(&mut s1.as_mut()).is_pending());
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, units, reply) = driver.next_body();
  assert_eq!(units.len(), 2, "both units packed before the cancellation");

  // Cancel s1 with its BODY IN FLIGHT: only this caller's result may be discarded.
  drop(s1);
  reply.send(reply_for(&[b"r1", b"r2"])).expect("awaits");
  assert!(poll_once(&mut run).is_pending());
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Ok(Bytes::from_static(b"r2"))),
    "the surviving body-mate resolves with its own reply"
  );
}

/// The queue byte budget refuses past its cap with NO retained growth — the refused submit
/// rolls its reservation back and leaves the counters at exactly the live entries.
#[test]
fn the_queue_byte_budget_refuses_over_cap_without_growth() {
  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  // The byte axis charges ENCODED cost: an 8-byte unit costs 8 + the per-unit framing (4).
  let (batch, _pump) = aggregator(handle, BatchConfig::new(64).with_max_queued_bytes(20));

  let s1 = batch.submit(Bytes::from(vec![1u8; 8]));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert_eq!(batch.queue_budget().bytes(), 12);

  let s2 = batch.submit(Bytes::from(vec![2u8; 8]));
  pin_mut!(s2);
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::QueueFull,
    }))
  );
  assert_eq!(
    batch.queue_budget().count(),
    1,
    "the refused submit rolled back"
  );
  assert_eq!(
    batch.queue_budget().bytes(),
    12,
    "no retained growth past the cap"
  );

  // The rollback left the headroom intact: an entry within the remaining capacity is admitted
  // — a reservation leaked by the refusal would have refused this too.
  let s3 = batch.submit(Bytes::from(vec![3u8; 2]));
  pin_mut!(s3);
  assert!(
    poll_once(&mut s3).is_pending(),
    "an entry within the remaining capacity is admitted"
  );
  assert_eq!(
    batch.queue_budget().bytes(),
    18,
    "the cap binds on encoded cost"
  );
}

/// Queue admission sees EVERY unit of a group: each member charges a count slot and its
/// encoded byte cost (payload plus per-unit framing), so a flood of zero-length units inside
/// few groups cannot ride under either cap while retaining per-unit channel state behind a
/// stalled body.
#[test]
fn empty_unit_groups_cannot_bypass_the_queue_caps() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64).with_max_queued_units(8));
  let mut run = Box::pin(pump.run());

  // Stall the pump on a first body the driver never answers.
  let s1 = batch.submit(Bytes::from_static(b"flying"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run.as_mut()).is_pending());
  let (_, _, _reply) = driver.next_body();

  // Nine empty units in one group exceed the eight-slot count cap: refused at submit, with
  // nothing retained.
  let over = batch.submit_group(vec![Bytes::new(); 9]);
  pin_mut!(over);
  assert_eq!(
    poll_once(&mut over),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::QueueFull,
    })),
    "the count cap counts units, not group entries"
  );
  assert_eq!(batch.queue_budget().count(), 0, "nothing retained");

  // A group inside the cap charges one slot per unit and the encoded byte cost.
  let fits = batch.submit_group(vec![Bytes::new(); 3]);
  pin_mut!(fits);
  assert!(poll_once(&mut fits).is_pending());
  assert_eq!(batch.queue_budget().count(), 3, "one slot per unit");
  assert_eq!(
    batch.queue_budget().bytes(),
    3 * viewstamp_proto::BATCH_UNIT_OVERHEAD,
    "empty units still pay their encoded framing"
  );
}

/// An in-flight body whose EVERY caller cancelled tears the pump down: only the pump can free
/// the driver's pending entry (the driver sees the aggregator as the live caller, not the
/// units), so the abandonment arm drops the submit — releasing the driver-side reply sender —
/// refuses everything queued, and returns without minting another request (the abandoned
/// number may never have reached the primary; minting past it would wedge the session on a
/// silent gap).
#[test]
fn an_in_flight_body_with_every_caller_cancelled_tears_the_pump_down() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let mut run = Box::pin(pump.run());

  // One unit flies; the driver never answers. Box-pinned so the drop below drops the FUTURE
  // (pin_mut! shadows to a Pin reference, whose drop would release nothing).
  let mut s1 = Box::pin(batch.submit(Bytes::from_static(b"abandoned")));
  assert!(poll_once(&mut s1.as_mut()).is_pending());
  assert!(poll_once(&mut run.as_mut()).is_pending());
  let (_, _, reply) = driver.next_body();

  // A second unit queues behind it.
  let s2 = batch.submit(Bytes::from_static(b"queued"));
  pin_mut!(s2);
  assert!(poll_once(&mut s2).is_pending());

  // Every caller of the flying body cancels: the pump must observe it, drop the submit (the
  // driver-side reply sender sees its receiver gone), refuse the queued unit, and return.
  drop(s1);
  assert!(
    poll_once(&mut run.as_mut()).is_ready(),
    "the pump tore down"
  );
  assert!(reply.is_canceled(), "the driver pending entry was released");
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::PumpGone,
    })),
    "the queued unit never entered consensus"
  );
  assert_eq!(batch.queue_budget().count(), 0, "every guard released");
  assert_eq!(batch.queue_budget().bytes(), 0);
}

/// The final handle drop's wake must let even an INLINE-polled pump observe teardown: the
/// live-handle count decrements under the lock before the wake fires, so a waker that polls
/// `run()` synchronously from inside that wake sees zero and returns. (An Arc-strong-count
/// signal loses this wakeup: the dropping handle's own Arc field is released only after its
/// `Drop` returns, so the inline poll would observe a still-live count, re-park, and never be
/// woken again.)
#[test]
fn the_final_handle_drop_wakes_an_inline_polled_pump_to_completion() {
  use std::sync::atomic::{AtomicBool, Ordering};

  type BoxedRun = Pin<Box<dyn Future<Output = ()> + Send>>;
  struct InlinePoller {
    slot: std::sync::Mutex<Option<BoxedRun>>,
    done: AtomicBool,
  }
  impl std::task::Wake for InlinePoller {
    fn wake(self: std::sync::Arc<Self>) {
      self.wake_by_ref();
    }
    fn wake_by_ref(self: &std::sync::Arc<Self>) {
      // Poll the parked run future synchronously, right here inside the wake.
      let Some(mut run) = self.slot.lock().unwrap().take() else {
        return;
      };
      let waker = std::task::Waker::from(std::sync::Arc::clone(self));
      let mut cx = Context::from_waker(&waker);
      if run.as_mut().poll(&mut cx).is_ready() {
        self.done.store(true, Ordering::SeqCst);
      } else {
        *self.slot.lock().unwrap() = Some(run);
      }
    }
  }

  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let poller = std::sync::Arc::new(InlinePoller {
    slot: std::sync::Mutex::new(None),
    done: AtomicBool::new(false),
  });

  // Park the pump with the inline poller as its waker, then stash the future in the poller.
  let mut run: BoxedRun = Box::pin(pump.run());
  let waker = std::task::Waker::from(std::sync::Arc::clone(&poller));
  let mut cx = Context::from_waker(&waker);
  assert!(run.as_mut().poll(&mut cx).is_pending());
  *poller.slot.lock().unwrap() = Some(run);

  // The final handle drop: its wake inline-polls the parked pump, which must observe zero
  // handles and complete.
  drop(batch);
  assert!(
    poller.done.load(Ordering::SeqCst),
    "the inline-polled pump observed teardown and returned"
  );
}

/// EVERY wake fires outside the queue lock: the probing waker try_locks the queue inside its
/// `wake()` and panics if the lock is held — so a wake-capable call under any lock scope (the
/// send's pump wake, a handle-drop wake, a teardown resolution) fails the test at the wake
/// site. This pins the discipline that keeps an inline-polling waker from deadlocking the
/// non-reentrant mutex by re-entering a submit or the pump.
#[test]
fn every_wake_fires_outside_the_queue_lock() {
  struct LockProbe {
    queue: std::sync::Arc<std::sync::Mutex<super::QueueState>>,
  }
  impl std::task::Wake for LockProbe {
    fn wake(self: std::sync::Arc<Self>) {
      self.wake_by_ref();
    }
    fn wake_by_ref(self: &std::sync::Arc<Self>) {
      assert!(
        self.queue.try_lock().is_ok(),
        "a wake fired while the queue lock was held"
      );
    }
  }

  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let probe = std::sync::Arc::new(LockProbe {
    queue: batch.queue_state(),
  });
  let waker = std::task::Waker::from(std::sync::Arc::clone(&probe));
  let mut cx = Context::from_waker(&waker);

  let mut run = Box::pin(pump.run());
  // Park the pump: it registers the probe as its park waker.
  assert!(run.as_mut().poll(&mut cx).is_pending());

  // The send's pump wake fires the probe (outside the lock, or it panics).
  let s1 = batch.submit(Bytes::from_static(b"w"));
  pin_mut!(s1);
  assert!(s1.as_mut().poll(&mut cx).is_pending());

  // Pack + hand off; resolve the reply: the demux resolution wakes s1's probe.
  assert!(run.as_mut().poll(&mut cx).is_pending());
  let (_, units, reply) = driver.next_body();
  let mut rb = ReplyBuilder::new(viewstamp_proto::max_reply_body_len(), 64);
  for _ in 0..units.len() {
    rb.push(b"ok").expect("reply fits");
  }
  reply
    .send(ReplyOutcome::from_applied(
      rb.finish().expect("a unit was pushed"),
    ))
    .expect("the pump awaits the reply");
  assert!(run.as_mut().poll(&mut cx).is_ready() || run.as_mut().poll(&mut cx).is_pending());
  assert!(s1.as_mut().poll(&mut cx).is_ready());

  // A unit queued at teardown: the Drop resolution wakes its probe after the lock released.
  let s2 = batch.submit(Bytes::from_static(b"q"));
  pin_mut!(s2);
  assert!(s2.as_mut().poll(&mut cx).is_pending());
  drop(run);
  assert!(s2.as_mut().poll(&mut cx).is_ready());

  // A handle drop's wake path (a clone dropping runs the same Drop): no pump is parked, the
  // take is None — the lock scope's discipline is still exercised.
  drop(batch.clone());
}

/// Submits racing pump teardown from other threads can never strand: the closed flag and the
/// queue mutate under one lock, so every racer either lands before the `Drop` drain (resolved
/// `Refused` by it) or observes `closed` and refuses at send — every submit RESOLVES and the
/// budget drains to zero. (A channel with no close-then-drain would let a send slip past the
/// final drain and park its caller forever, pinning its budget.) The threads hammer the
/// window; the join is the no-strand witness.
#[test]
fn submits_racing_pump_teardown_never_strand() {
  for _ in 0..64 {
    let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
    let (batch, pump) = aggregator(handle, BatchConfig::new(64));
    let workers: Vec<_> = (0..3)
      .map(|_| {
        let batch = batch.clone();
        std::thread::spawn(move || {
          for _ in 0..16 {
            let submit = batch.submit(Bytes::from_static(b"racer"));
            pin_mut!(submit);
            // Drive the future to completion by hand (no runtime in this crate): every
            // resolution is acceptable — Refused before/at teardown, or a strand (which this
            // loop would turn into a hang, the failure signal).
            let outcome = loop {
              match poll_once(&mut submit) {
                Poll::Ready(outcome) => break outcome,
                Poll::Pending => std::thread::yield_now(),
              }
            };
            if matches!(outcome, Err(BatchError::Refused { .. })) {
              // The retry a refusal licenses: it must itself resolve (a second refusal), never
              // block on the closed queue or strand.
              let retry = batch.submit(Bytes::from_static(b"retry"));
              pin_mut!(retry);
              loop {
                match poll_once(&mut retry) {
                  Poll::Ready(_) => break,
                  Poll::Pending => std::thread::yield_now(),
                }
              }
            }
          }
        })
      })
      .collect();
    drop(pump);
    for w in workers {
      w.join().expect("no racer stranded or panicked");
    }
    assert_eq!(batch.queue_budget().count(), 0, "every guard released");
    assert_eq!(batch.queue_budget().bytes(), 0);
  }
}

/// A pump dying with a body IN FLIGHT resolves that body's callers `OutcomeUnknown` — the body
/// is already in the driver and may commit regardless, so reading the death as a retry-safe
/// refusal would license a double-apply — while a unit still QUEUED behind it resolves
/// `Refused`: it never entered consensus. The classification split is the whole contract.
#[test]
fn dropping_the_run_future_with_a_body_in_flight_is_outcome_unknown() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let mut run = Box::pin(pump.run());

  let s1 = batch.submit(Bytes::from_static(b"flying"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  // The pump packs and hands the body to the driver; the test driver holds the reply pending.
  assert!(poll_once(&mut run.as_mut()).is_pending());
  let (_, _, _reply) = driver.next_body();

  // A second unit queues behind the flying body and is never packed.
  let s2 = batch.submit(Bytes::from_static(b"queued"));
  pin_mut!(s2);
  assert!(poll_once(&mut s2).is_pending());

  drop(run);
  assert_eq!(
    poll_once(&mut s1),
    Poll::Ready(Err(BatchError::OutcomeUnknown {
      reason: OutcomeUnknownReason::PumpGone,
    })),
    "the in-flight body's unit must read as maybe-committed, never as refused"
  );
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::PumpGone,
    })),
    "the queued unit never entered consensus and is safe to resubmit"
  );
  assert_eq!(batch.queue_budget().count(), 0, "every guard released");
  assert_eq!(batch.queue_budget().bytes(), 0);
}

/// Teardown of an un-run pump: dropping the pump drops the queue, resolving waiting callers
/// `Refused`/`PumpGone`-shaped and releasing every queue-budget guard.
#[test]
fn dropping_the_pump_refuses_queued_callers_and_frees_budget() {
  let (handle, _driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));

  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert_eq!(batch.queue_budget().count(), 1);

  drop(pump);
  assert_eq!(
    poll_once(&mut s1),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::PumpGone,
    }))
  );
  assert_eq!(
    batch.queue_budget().count(),
    0,
    "the dropped queue released its guards"
  );
  assert_eq!(batch.queue_budget().bytes(), 0);

  let s2 = batch.submit(Bytes::from_static(b"u2"));
  pin_mut!(s2);
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::PumpGone,
    })),
    "submits after the pump is gone refuse immediately"
  );
}

/// Teardown: with every `BatchHandle` dropped and the queue drained, `run()` returns; a
/// cancelled leftover entry is skipped (its budget released), never submitted.
#[test]
fn run_returns_when_every_handle_is_dropped_and_the_queue_drains() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let (batch, pump) = aggregator(handle, BatchConfig::new(64));
  let run = pump.run();
  pin_mut!(run);
  assert!(poll_once(&mut run).is_pending(), "an idle pump parks");

  // A queued-then-cancelled entry is all that remains when the last handle drops.
  let budget = batch.queue_budget().clone();
  {
    let s1 = batch.submit(Bytes::from_static(b"u1"));
    pin_mut!(s1);
    assert!(poll_once(&mut s1).is_pending());
  }
  drop(batch);
  assert_eq!(
    poll_once(&mut run),
    Poll::Ready(()),
    "drained + disconnected: run returns"
  );
  driver.assert_no_body();
  assert_eq!(budget.count(), 0, "the skipped entry released its guard");
}

/// A hand-fired sleep future: ready iff the test set the shared flag.
type FlagSleep = std::future::PollFn<Box<dyn FnMut(&mut Context<'_>) -> Poll<()>>>;

/// A hand-driven sleep factory: each body's sleep resolves when the shared flag is set. `Rc`
/// makes it deliberately `!Send` — the no-`Send`-bound API accepts it.
fn flag_sleep(flag: &Rc<Cell<bool>>) -> impl Fn(Duration) -> FlagSleep {
  let flag = flag.clone();
  move |_| {
    let flag = flag.clone();
    std::future::poll_fn(Box::new(move |_| {
      if flag.get() {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    }))
  }
}

/// Terminal stall: the timer winning the race resolves the in-flight body `OutcomeUnknown`,
/// every queued entry `Refused` (never entered consensus), kills the handles, and returns from
/// `run()` — the pump never mints another request on the handle.
#[test]
fn a_terminal_stall_resolves_everything_and_stops_the_pump() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let fired = Rc::new(Cell::new(false));
  let (batch, pump) = aggregator_with_stall(
    handle,
    BatchConfig::new(64),
    Duration::from_secs(5),
    flag_sleep(&fired),
  );
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, _reply1) = driver.next_body();

  let s2 = batch.submit(Bytes::from_static(b"u2"));
  pin_mut!(s2);
  assert!(poll_once(&mut s2).is_pending());
  assert!(
    poll_once(&mut run).is_pending(),
    "armed but unfired: still racing"
  );

  fired.set(true);
  assert_eq!(
    poll_once(&mut run),
    Poll::Ready(()),
    "the stall ends the pump"
  );
  assert_eq!(
    poll_once(&mut s1),
    Poll::Ready(Err(BatchError::OutcomeUnknown {
      reason: OutcomeUnknownReason::Stalled,
    })),
    "the in-flight body may yet commit"
  );
  assert_eq!(
    poll_once(&mut s2),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::Stalled,
    })),
    "queued entries never entered consensus"
  );
  let s3 = batch.submit(Bytes::from_static(b"u3"));
  pin_mut!(s3);
  assert_eq!(
    poll_once(&mut s3),
    Poll::Ready(Err(BatchError::Refused {
      reason: RefusedReason::PumpGone,
    })),
    "the handles are dead after the stall"
  );
  driver.assert_no_body();
}

/// The race's other side: a submit resolving on the same wake as an about-to-fire timer wins —
/// normal demux proceeds, the pump keeps running, and no stall is declared.
#[test]
fn a_resolved_submit_beats_a_simultaneously_fired_timer() {
  let (handle, mut driver) = driver_handle(MAX_PENDING_BYTES);
  let fired = Rc::new(Cell::new(false));
  let (batch, pump) = aggregator_with_stall(
    handle,
    BatchConfig::new(64),
    Duration::from_secs(5),
    flag_sleep(&fired),
  );
  let run = pump.run();
  pin_mut!(run);

  let s1 = batch.submit(Bytes::from_static(b"u1"));
  pin_mut!(s1);
  assert!(poll_once(&mut s1).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, _, reply1) = driver.next_body();

  // Both sides are ready before the next poll; the submit is polled first and wins.
  reply1.send(reply_for(&[b"r1"])).expect("awaits");
  fired.set(true);
  assert!(
    poll_once(&mut run).is_pending(),
    "no stall: the pump keeps running"
  );
  assert_eq!(
    poll_once(&mut s1),
    Poll::Ready(Ok(Bytes::from_static(b"r1")))
  );

  // The pump is fully alive: a later submit ships in a fresh body.
  fired.set(false);
  let s2 = batch.submit(Bytes::from_static(b"u2"));
  pin_mut!(s2);
  assert!(poll_once(&mut s2).is_pending());
  assert!(poll_once(&mut run).is_pending());
  let (_, units, _) = driver.next_body();
  assert_eq!(units, vec![b"u2".to_vec()]);
}

/// The aggregate handle behaves consistently with a retired driver: when the pump's `Handle::submit`
/// of a packed body fails with `DriverError::Retired`, the units are classified `OutcomeUnknown`, not
/// a false `Refused`. A body already in flight when the node was removed may have replicated to the
/// surviving quorum and committed before removal, so its fate is genuinely unknowable — claiming
/// `Refused` would license a double-apply.
#[test]
fn a_retired_submit_is_classified_outcome_unknown() {
  let err = DriverError::Retired {
    local: viewstamp_proto::MemberId::new(4),
    epoch: viewstamp_proto::Epoch::new(2),
  };
  match super::submit_failure(&err) {
    BatchError::OutcomeUnknown { reason } => {
      assert_eq!(
        reason,
        OutcomeUnknownReason::Driver,
        "a retired submit is conservatively unknown"
      );
    }
    other => panic!("expected OutcomeUnknown for a retired submit, got {other:?}"),
  }
}

/// An over-bound reply is classified `CommittedReplyLost`, never `OutcomeUnknown`: the packed body
/// COMMITTED and every unit in it applied — only the reply batch is gone — so a caller that retried
/// a non-idempotent unit would apply it a second time. The class is the retry contract, and here
/// the contract is "do not retry".
#[test]
fn an_over_bound_reply_is_classified_committed_reply_lost() {
  let max = viewstamp_proto::ReplyBody::max_len();
  let err = DriverError::ReplyTooLarge { len: max + 1, max };
  match super::submit_failure(&err) {
    BatchError::CommittedReplyLost { reason } => {
      assert_eq!(reason, ReplyLostReason::ReplyTooLarge);
      assert_eq!(reason.as_str(), "reply_too_large");
    }
    other => panic!("expected CommittedReplyLost for an over-bound reply, got {other:?}"),
  }
}

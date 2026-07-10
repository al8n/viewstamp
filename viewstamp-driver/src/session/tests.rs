use std::time::Duration;

use bytes::Bytes;
use viewstamp_proto::{ClientId, Committed, Event, Instant, OpNumber, Request, RequestNumber};

use super::{InflightBudget, Pending};

/// A budget at the DEFAULT caps, as the drivers construct without a config override.
fn default_budget() -> InflightBudget {
  InflightBudget::new(super::MAX_INFLIGHT, super::MAX_PENDING_BYTES)
}

/// Build a `Pending` exactly as the driver does: reserve a `body`-sized slot on `budget` and MOVE
/// the resulting guard into the entry, so dropping the entry releases that one reservation. Returns
/// the entry and the live reply receiver (held by the caller so the entry is not auto-cancelled).
fn pending_entry(
  budget: &InflightBudget,
  request: u64,
  body: Bytes,
) -> (Pending, futures_channel::oneshot::Receiver<Bytes>) {
  let reservation = budget
    .try_acquire(body.len())
    .expect("a fresh budget has room for one reservation");
  let (reply, reply_rx) = futures_channel::oneshot::channel();
  let entry = Pending {
    reply,
    request: Request::new(ClientId::new(1), RequestNumber::with(request), body),
    last_sent: Instant::ZERO,
    reservation,
  };
  (entry, reply_rx)
}

/// The cap accessors report the construction-time bounds verbatim, independent of how much is
/// currently reserved — they are the budget's static shape, not its live counters.
#[test]
fn budget_caps_are_readable_and_immutable() {
  let budget = InflightBudget::new(7, 99);
  assert_eq!(budget.max_count(), 7);
  assert_eq!(budget.max_bytes(), 99);
  let _guard = budget.try_acquire(10).expect("room for one reservation");
  assert_eq!(
    budget.max_count(),
    7,
    "a live reservation moves the counters, not the caps"
  );
  assert_eq!(budget.max_bytes(), 99);
}

#[test]
fn deliver_completes_a_matching_pending_reply() {
  let (events_tx, _events_rx) = flume::unbounded();
  let budget = default_budget();
  let mut pending = std::collections::HashMap::new();
  let (entry, mut reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"q"));
  pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);

  let event = Event::Committed(Committed::new(
    OpNumber::with(1),
    ClientId::new(1),
    RequestNumber::with(1),
    Bytes::from_static(b"R"),
  ));
  super::deliver_event(&mut pending, &events_tx, event);

  assert_eq!(reply_rx.try_recv().unwrap(), Some(Bytes::from_static(b"R")));
  assert!(pending.is_empty());
  assert_eq!(
    budget.count(),
    0,
    "a matching commit removes the entry, whose guard releases its reservation"
  );
  assert_eq!(
    budget.bytes(),
    0,
    "the reserved body bytes are released too"
  );
}

/// A matching commit releases the budget EVEN IF the reply receiver was already dropped (a
/// cancelled submit whose commit then arrives): the entry is removed and its guard freed, the
/// dropped `send` is harmless. This is one of the release sites that keeps the budget from leaking.
#[test]
fn deliver_releases_budget_when_the_reply_receiver_is_gone() {
  let (events_tx, _events_rx) = flume::unbounded();
  let budget = default_budget();
  let mut pending = std::collections::HashMap::new();
  let (entry, reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"q"));
  pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);
  drop(reply_rx); // the caller cancelled: the reply receiver is gone before the commit arrives

  super::deliver_event(
    &mut pending,
    &events_tx,
    Event::Committed(Committed::new(
      OpNumber::with(1),
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"R"),
    )),
  );

  assert!(pending.is_empty());
  assert_eq!(
    budget.count(),
    0,
    "the commit removes the entry (its guard releases) even with the reply receiver gone (no leak)"
  );
}

/// `pending_scan_interval` derives from the configured request timeout: an eighth of it, capped
/// at `PENDING_SCAN_MAX_INTERVAL`. The default 250 ms timeout hits the cap; a small timeout
/// scales down proportionally so the scan still samples each entry ~8x per timeout window; a
/// huge timeout never slows cancellation reclaim past the cap.
#[test]
fn pending_scan_interval_derives_from_the_request_timeout() {
  assert_eq!(
    super::pending_scan_interval(super::REQUEST_TIMEOUT),
    super::PENDING_SCAN_MAX_INTERVAL,
    "the default request timeout's eighth (31.25ms) is capped at the 25ms ceiling"
  );
  assert_eq!(
    super::pending_scan_interval(Duration::from_millis(80)),
    Duration::from_millis(10),
    "a small configured timeout scales the scan interval down to an eighth of it"
  );
  assert_eq!(
    super::pending_scan_interval(Duration::from_secs(10)),
    super::PENDING_SCAN_MAX_INTERVAL,
    "a large configured timeout never slows the scan past the ceiling"
  );
  assert!(
    super::pending_scan_interval(Duration::ZERO) >= Duration::from_millis(1),
    "a zero configured timeout still yields a positive scan interval (no wake-scan-rearm spin)"
  );
}

/// `reap_and_collect_retransmits` reclaims a cancelled submit's entry + budget within a tick: an
/// entry whose reply receiver is dropped is removed (its guard releases) and it is NOT returned for
/// retransmission.
#[test]
fn reap_reclaims_a_cancelled_submit() {
  let budget = default_budget();
  let mut pending = std::collections::HashMap::new();
  let (entry, reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"cancelled"));
  pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);
  drop(reply_rx); // cancel

  // Far enough past REQUEST_TIMEOUT that a LIVE entry would be retransmitted — proving the cancelled
  // one is reclaimed, not merely not-yet-stale.
  let later = Instant::ZERO + super::REQUEST_TIMEOUT + Duration::from_millis(1);
  let stale = super::reap_and_collect_retransmits(&mut pending, later, super::REQUEST_TIMEOUT);

  assert!(
    stale.is_empty(),
    "a cancelled submit is not retransmitted, it is reclaimed"
  );
  assert!(pending.is_empty(), "the cancelled entry is removed");
  assert_eq!(budget.count(), 0, "its budget reservation is released");
  assert_eq!(budget.bytes(), 0, "its reserved bytes are released");
}

/// `reap_and_collect_retransmits` re-broadcasts a LIVE stale entry (reply receiver still held, past
/// `REQUEST_TIMEOUT`) and keeps it in `pending` with its budget intact — only cancelled or
/// committed entries leave.
#[test]
fn reap_retransmits_a_live_stale_entry_and_keeps_its_budget() {
  let budget = default_budget();
  let mut pending = std::collections::HashMap::new();
  let (entry, _reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"live"));
  pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);

  let later = Instant::ZERO + super::REQUEST_TIMEOUT + Duration::from_millis(1);
  let stale = super::reap_and_collect_retransmits(&mut pending, later, super::REQUEST_TIMEOUT);

  assert_eq!(stale.len(), 1, "a live stale entry is re-broadcast");
  assert_eq!(pending.len(), 1, "and stays in pending");
  assert_eq!(budget.count(), 1, "its budget reservation is retained");
}

/// `drain_pending` drops every remaining entry, each entry's guard releasing its reservation (the
/// shutdown release site): the budget returns to zero so a driver's lifetime never leaks.
#[test]
fn drain_pending_releases_all_budget() {
  let budget = default_budget();
  let mut pending = std::collections::HashMap::new();
  // Hold each reply receiver alive (so the entries are not cancelled) until after the drain.
  let mut rxs = Vec::new();
  for i in 1..=5u64 {
    let (entry, reply_rx) = pending_entry(&budget, i, Bytes::from_static(b"x"));
    pending.insert((ClientId::new(1), RequestNumber::with(i)), entry);
    rxs.push(reply_rx);
  }
  assert_eq!(budget.count(), 5);

  super::drain_pending(&mut pending);

  assert!(pending.is_empty(), "drain clears the map");
  assert_eq!(
    budget.count(),
    0,
    "and every entry's guard released its reservation"
  );
  assert_eq!(budget.bytes(), 0);
  drop(rxs);
}

/// The guard is the SINGLE release owner regardless of where it dies: a `ReservationGuard` that is
/// simply DROPPED (never moved into a `Pending`) releases its slot — the exact path a
/// `Command::Submit` takes when it is dropped still-queued as the driver tears down on `Shutdown`,
/// so a submit racing shutdown before it reaches `pending` cannot leak budget.
#[test]
fn dropping_an_un_drained_reservation_guard_releases_the_budget() {
  let budget = default_budget();
  let g1 = budget
    .try_acquire(10)
    .expect("room for the first reservation");
  let g2 = budget
    .try_acquire(20)
    .expect("room for the second reservation");
  assert_eq!(budget.count(), 2, "two live reservations");
  assert_eq!(budget.bytes(), 30, "their reserved bytes sum");

  // Drop the guards WITHOUT ever moving them into a `Pending` — exactly what happens to a queued
  // `Command::Submit` dropped with the command channel on shutdown.
  drop(g1);
  assert_eq!(
    budget.count(),
    1,
    "dropping one guard releases exactly its slot"
  );
  assert_eq!(budget.bytes(), 20);
  drop(g2);
  assert_eq!(
    budget.count(),
    0,
    "dropping the queued reservations returns the budget to zero (no leak across teardown)"
  );
  assert_eq!(budget.bytes(), 0);
}

fn committed(op: u64) -> Event {
  Event::Committed(Committed::new(
    OpNumber::with(op),
    ClientId::new(1),
    RequestNumber::with(op),
    Bytes::from_static(b"R"),
  ))
}

/// A NON-Committed event (an observability variant) flows to the embedder channel UNTOUCHED: it
/// answers no pending submit (the map is untouched) and is forwarded verbatim.
#[test]
fn non_committed_events_forward_to_the_embedder_untouched() {
  let (events_tx, events_rx) = flume::bounded(super::EVENTS_CAP);
  let budget = default_budget();
  let mut pending = std::collections::HashMap::new();
  let (entry, _reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"q"));
  pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);

  let ev = Event::StateSyncCompleted(OpNumber::with(9));
  super::deliver_event(&mut pending, &events_tx, ev.clone());

  assert_eq!(
    events_rx.try_recv().expect("the event is observable"),
    ev,
    "a non-Committed event reaches the embedder channel verbatim"
  );
  assert_eq!(
    pending.len(),
    1,
    "no pending submit is answered/removed by a non-Committed event"
  );
  assert_eq!(budget.count(), 1, "and no budget is released");
}

/// The committed-events channel is bounded best-effort: an application that never drains
/// `Handle::events()` must not grow the channel without bound. Pushing far more than `EVENTS_CAP`
/// committed events through `deliver_event` into the real `flume::bounded(EVENTS_CAP)` channel —
/// WITHOUT ever receiving — leaves the channel length capped at `EVENTS_CAP` (an event sent
/// once full is dropped at the failed try_send), instead of accumulating every commit forever.
#[test]
fn undrained_events_channel_stays_bounded_at_capacity() {
  let (events_tx, events_rx) = flume::bounded(super::EVENTS_CAP);
  let mut pending = std::collections::HashMap::new();

  // Many times the cap, with nothing draining `events_rx`.
  for op in 1..=(super::EVENTS_CAP as u64 * 8) {
    super::deliver_event(&mut pending, &events_tx, committed(op));
    assert!(
      events_rx.len() <= super::EVENTS_CAP,
      "the undrained events channel must never exceed EVENTS_CAP (got {})",
      events_rx.len(),
    );
  }
  assert_eq!(
    events_rx.len(),
    super::EVENTS_CAP,
    "after a flood with no consumer the channel saturates at exactly EVENTS_CAP, not unbounded"
  );
}

/// A drained consumer still observes events: each committed event pushed through `deliver_event`
/// is received in order when `events_rx` is drained between sends (the bound only drops under a
/// non-draining consumer, never one that keeps up).
#[test]
fn a_drained_events_channel_observes_every_event() {
  let (events_tx, events_rx) = flume::bounded(super::EVENTS_CAP);
  let mut pending = std::collections::HashMap::new();

  for op in 1..=(super::EVENTS_CAP as u64 * 4) {
    super::deliver_event(&mut pending, &events_tx, committed(op));
    let got = events_rx
      .try_recv()
      .expect("a drained consumer observes the event");
    let Event::Committed(got) = got else {
      panic!("only Committed events were pushed, got {got:?}");
    };
    assert_eq!(
      got.op().get(),
      op,
      "events are observed in order when drained"
    );
  }
  assert_eq!(
    events_rx.len(),
    0,
    "a kept-up consumer leaves nothing buffered"
  );
}

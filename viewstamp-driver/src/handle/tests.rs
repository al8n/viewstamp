use super::{Command, Handle};
use crate::{
  DriverError,
  session::{InflightBudget, MAX_INFLIGHT, MAX_PENDING_BYTES, Retirement},
};
use bytes::Bytes;

/// `Handle` must stay `Send + Sync`: it is the one object meant to cross threads (any thread may
/// `submit` to any group), so the command-sender wrapping may not cost it either auto trait.
#[test]
fn handle_is_send_and_sync() {
  fn assert_send_sync<T: Send + Sync>() {}
  assert_send_sync::<Handle>();
}

/// `submit_byte_limit` is the min of the transport bound and the driver's byte cap, whichever
/// binds: at the default caps the transport bound is the smaller (128 MiB >> one max frame), and
/// a small configured byte cap takes over so a packer can never mint a body the budget refuses
/// forever.
#[test]
fn submit_byte_limit_is_the_binding_min_of_transport_and_budget() {
  let (_events_tx, events_rx) = flume::unbounded();
  let (tx, _rx) = futures_channel::mpsc::channel::<Command>(8);
  let default_caps = Handle::new(
    tx,
    events_rx.clone(),
    InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES),
    Retirement::new(),
  );
  assert_eq!(
    default_caps.submit_byte_limit(),
    viewstamp_proto::max_request_body_len(),
    "at the default byte cap the transport bound binds"
  );

  let (tx, _rx) = futures_channel::mpsc::channel::<Command>(8);
  let tiny_cap = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, 64),
    Retirement::new(),
  );
  assert_eq!(
    tiny_cap.submit_byte_limit(),
    64,
    "a configured byte cap below the transport bound binds instead"
  );
}

#[test]
fn submit_sends_a_command_carrying_its_reply_channel() {
  // cmd_cap-sized (bounded) channel; the budget starts empty.
  let (tx, mut rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let handle = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES),
    Retirement::new(),
  );

  // submit() is async; poll it just far enough to enqueue the command without awaiting the reply.
  let fut = handle.submit(Bytes::from_static(b"hello"));
  futures_util::pin_mut!(fut);
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  let _ = std::future::Future::poll(fut, &mut cx); // enqueues the command, then parks on the reply

  let cmd = rx.try_recv().expect("a command was enqueued");
  match cmd {
    Command::Submit {
      body,
      reply,
      reservation,
    } => {
      assert_eq!(&body[..], b"hello");
      // The submit carries its budget reservation guard with the command (released on drop).
      drop(reservation);
      // Completing the reply channel is what `submit` awaits.
      let _ = reply.send(Bytes::from_static(b"world"));
    }
    other => panic!("expected Submit, got {other:?}"),
  }
}

/// A `submit` the command channel refuses returns `Busy` and ROLLS BACK its budget reservation —
/// it never leaks a slot for a command the driver never sees. The channel admits its buffer plus
/// one in-flight command per live sender (this `Handle` is the one sender here), so with a 1-slot
/// buffer the first TWO submits enqueue and the THIRD is the refused one; after the rollback the
/// count stays at the two live submits, so the budget is not silently exhausted by refused
/// submits. (In production the submit budget binds first — `cmd_cap` exceeds `max_inflight` — so
/// this refusal is the defensive mapping, not the steady-state bound.)
#[test]
fn submit_on_a_full_command_channel_is_busy_and_rolls_back_budget() {
  let (tx, _rx) = futures_channel::mpsc::channel::<Command>(1);
  let (_events_tx, events_rx) = flume::unbounded();
  let budget = InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES);
  let handle = Handle::new(tx, events_rx, budget.clone(), Retirement::new());
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());

  // Fill the 1-slot buffer, then the sender's guaranteed slot: both submits park on their replies.
  let fut1 = handle.submit(Bytes::from_static(b"a"));
  futures_util::pin_mut!(fut1);
  let _ = std::future::Future::poll(fut1, &mut cx);
  let fut2 = handle.submit(Bytes::from_static(b"b"));
  futures_util::pin_mut!(fut2);
  let _ = std::future::Future::poll(fut2, &mut cx);
  assert_eq!(
    budget.count(),
    2,
    "the enqueued submits hold their reservations"
  );

  // The channel now refuses this sender: the next submit must be Busy and leave the budget at 2
  // (its own reservation rolled back), not 3.
  let fut3 = handle.submit(Bytes::from_static(b"c"));
  futures_util::pin_mut!(fut3);
  match std::future::Future::poll(fut3, &mut cx) {
    std::task::Poll::Ready(Err(DriverError::Busy)) => {}
    other => panic!("expected Ready(Err(Busy)) on a refusing command channel, got {other:?}"),
  }
  assert_eq!(
    budget.count(),
    2,
    "a Busy submit rolls back its reservation: the count stays at the live submits"
  );
}

/// A body over `max_request_body_len()` is rejected up front with `RequestTooLarge` and touches
/// neither the budget nor the command channel: the size check runs BEFORE the reserve and `try_send`,
/// so a body the transport could never deliver (its relayed `Request`/`Prepare` would exceed
/// `MAX_FRAME_LEN`) never reserves a slot nor enqueues a command — it cannot hang or pin the budget.
#[test]
fn submit_over_the_max_body_is_rejected_without_touching_budget_or_channel() {
  let (tx, mut rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let budget = InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES);
  let handle = Handle::new(tx, events_rx, budget.clone(), Retirement::new());
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());

  let oversized = Bytes::from(vec![0u8; viewstamp_proto::max_request_body_len() + 1]);
  let fut = handle.submit(oversized);
  futures_util::pin_mut!(fut);
  match std::future::Future::poll(fut, &mut cx) {
    std::task::Poll::Ready(Err(DriverError::RequestTooLarge)) => {}
    other => panic!("expected Ready(Err(RequestTooLarge)) for an over-frame body, got {other:?}"),
  }
  assert_eq!(budget.count(), 0, "no budget slot is reserved");
  assert_eq!(budget.bytes(), 0, "no budget bytes are reserved");
  assert!(rx.try_recv().is_err(), "no command is enqueued");
}

/// The count cap is enforced across the shared budget: once `MAX_INFLIGHT` reservations are held,
/// the next reserve fails (the driver-side `submit` would return `Busy`). Reserving directly
/// exercises the cap without minting `MAX_INFLIGHT` futures.
#[test]
fn the_budget_count_cap_refuses_past_max_inflight() {
  let budget = InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES);
  // Hold every guard so the reservations stay live up to the cap (dropping one would free a slot).
  let mut guards = Vec::new();
  for _ in 0..MAX_INFLIGHT {
    guards.push(
      budget
        .try_acquire(1)
        .expect("reservations up to the cap succeed"),
    );
  }
  assert!(
    budget.try_acquire(1).is_none(),
    "the reservation past MAX_INFLIGHT is refused"
  );
  assert_eq!(
    budget.count(),
    MAX_INFLIGHT,
    "a refused reservation rolls back: the count never exceeds the cap"
  );
  drop(guards);
}

/// `reconfigure_to` on a CLOSED command channel returns `DriverGone`, not the retryable `Busy`.
/// A conscientious caller must not livelock against a dead driver.
#[test]
fn reconfigure_to_on_closed_channel_yields_driver_gone() {
  use crate::reconfigure::{HealthHint, ReconfigureError};
  use std::collections::BTreeSet;
  use viewstamp_proto::{MemberId, MembershipTarget};

  let (tx, rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let handle = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES),
    Retirement::new(),
  );
  // Drop the receiver so the channel is closed from the driver side.
  drop(rx);

  let target = MembershipTarget::new(BTreeSet::from([MemberId::new(1)]), BTreeSet::new());
  let fut = handle.reconfigure_to(target, HealthHint::default(), None);
  futures_util::pin_mut!(fut);
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  match std::future::Future::poll(fut, &mut cx) {
    std::task::Poll::Ready(Err(ReconfigureError::DriverGone)) => {}
    other => panic!("expected Ready(Err(DriverGone)) on a closed channel, got {other:?}"),
  }
}

/// `add_peer` on a FULL command channel reports `Busy` rather than dropping the address update
/// silently. A lost update would strand an already-live member with no address — permanently
/// undialed, with no caller signal — so the caller must learn to retry. The channel admits its
/// buffer plus one in-flight command per live sender (one `Handle` here), so a 1-slot buffer takes
/// TWO sends and the THIRD is refused.
#[test]
fn add_peer_on_a_full_command_channel_is_busy() {
  use std::net::SocketAddr;
  use viewstamp_proto::MemberId;

  let (tx, _rx) = futures_channel::mpsc::channel::<Command>(1);
  let (_events_tx, events_rx) = flume::unbounded();
  let handle = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES),
    Retirement::new(),
  );
  let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

  // Fill the 1-slot buffer, then the sender's guaranteed slot: both updates enqueue.
  handle
    .add_peer(MemberId::new(1), addr)
    .expect("the first update fills the buffer slot");
  handle
    .add_peer(MemberId::new(2), addr)
    .expect("the second update fills the sender's guaranteed slot");

  // The channel now refuses this sender: a live-member address update is BUSY, not silently lost.
  match handle.add_peer(MemberId::new(3), addr) {
    Err(DriverError::Busy) => {}
    other => panic!("expected Err(Busy) on a full command channel, got {other:?}"),
  }
}

/// `add_peer` on a CLOSED command channel reports `DriverGone`, not the retryable `Busy` — a
/// conscientious caller must not livelock registering addresses against a dead driver.
#[test]
fn add_peer_on_a_closed_command_channel_yields_driver_gone() {
  use std::net::SocketAddr;
  use viewstamp_proto::MemberId;

  let (tx, rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let handle = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES),
    Retirement::new(),
  );
  // Drop the receiver so the channel is closed from the driver side.
  drop(rx);

  let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
  match handle.add_peer(MemberId::new(1), addr) {
    Err(DriverError::DriverGone) => {}
    other => panic!("expected Err(DriverGone) on a closed channel, got {other:?}"),
  }
}

/// Latch a fresh terminal retirement signal at `(local, epoch)`, exactly as the run loop's `retire`
/// does with no in-flight submits to drain — the fixture for the `Handle`'s terminal-retirement paths.
fn retired_at(local: u128, epoch: u64) -> Retirement {
  let cell = Retirement::new();
  crate::session::retire(
    &mut crate::session::PendingMap::new(),
    &cell,
    viewstamp_proto::MemberId::new(local),
    viewstamp_proto::Epoch::new(epoch),
  );
  cell
}

/// A `submit` on a RETIRED handle returns the terminal `Retired` error immediately — before reserving
/// budget or touching the command channel — carrying the latched local id + epoch. A retired node
/// emits no further commits, so a minted request could never resolve; it must not hang or pin budget.
#[test]
fn submit_after_retirement_returns_retired_without_touching_budget_or_channel() {
  use viewstamp_proto::{Epoch, MemberId};

  let (tx, mut cmd_rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let budget = InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES);
  let handle = Handle::new(tx, events_rx, budget.clone(), retired_at(5, 2));
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());

  let fut = handle.submit(Bytes::from_static(b"q"));
  futures_util::pin_mut!(fut);
  match std::future::Future::poll(fut, &mut cx) {
    std::task::Poll::Ready(Err(DriverError::Retired { local, epoch })) => {
      assert_eq!(
        local,
        MemberId::new(5),
        "the submit carries the latched local id"
      );
      assert_eq!(epoch, Epoch::new(2), "and the latched retirement epoch");
    }
    other => panic!("expected Ready(Err(Retired)) immediately on a retired handle, got {other:?}"),
  }
  assert_eq!(budget.count(), 0, "a retired submit reserves no budget");
  assert_eq!(budget.bytes(), 0, "and no budget bytes");
  assert!(
    cmd_rx.try_recv().is_err(),
    "a retired submit enqueues no command"
  );
}

/// A submit ALREADY in flight when the node retires resolves to the terminal `Retired` error — NOT
/// the generic `ReplyDropped` a bare oneshot-cancel yields — once the run loop latches the signal and
/// drains the in-flight entry (dropping its reply sender), and its budget slot is freed by that drain.
#[test]
fn an_in_flight_submit_resolves_to_retired_when_the_signal_latches() {
  use viewstamp_proto::{Epoch, MemberId};

  let (tx, mut cmd_rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let budget = InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES);
  let cell = Retirement::new();
  let handle = Handle::new(tx, events_rx, budget.clone(), cell.clone());
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());

  // Poll once: the submit reserves budget, enqueues its command, and parks on the reply.
  let fut = handle.submit(Bytes::from_static(b"q"));
  futures_util::pin_mut!(fut);
  assert!(
    matches!(
      std::future::Future::poll(fut.as_mut(), &mut cx),
      std::task::Poll::Pending
    ),
    "an accepted submit parks on its reply"
  );
  assert_eq!(
    budget.count(),
    1,
    "the enqueued submit holds its reservation"
  );

  // The run loop moves a Submit's reply sender + reservation into `pending`; take them here so
  // dropping them reproduces `retire`'s drain of that in-flight entry.
  let (reply, reservation) = match cmd_rx.try_recv().expect("a command was enqueued") {
    Command::Submit {
      reply, reservation, ..
    } => (reply, reservation),
    other => panic!("expected Submit, got {other:?}"),
  };

  // Latch the shared signal (as the pump does on the transition), then drop the drained entry.
  crate::session::retire(
    &mut crate::session::PendingMap::new(),
    &cell,
    MemberId::new(7),
    Epoch::new(3),
  );
  drop(reply);
  drop(reservation);
  assert_eq!(
    budget.count(),
    0,
    "the drained reservation releases its budget slot"
  );

  // The parked submit now resolves to the terminal Retired (with the latched identity), not ReplyDropped.
  match std::future::Future::poll(fut.as_mut(), &mut cx) {
    std::task::Poll::Ready(Err(DriverError::Retired { local, epoch })) => {
      assert_eq!(local, MemberId::new(7));
      assert_eq!(epoch, Epoch::new(3));
    }
    other => panic!("expected Ready(Err(Retired)) after the signal latches, got {other:?}"),
  }
}

/// `reconfigure_to` on a RETIRED handle returns the terminal `ReconfigureError::Retired` immediately —
/// a removed node is no longer a cluster member and cannot drive a reconfiguration — enqueueing no
/// command, mirroring `submit`'s up-front rejection.
#[test]
fn reconfigure_to_after_retirement_returns_retired() {
  use crate::reconfigure::{HealthHint, ReconfigureError};
  use std::collections::BTreeSet;
  use viewstamp_proto::{Epoch, MemberId, MembershipTarget};

  let (tx, mut cmd_rx) = futures_channel::mpsc::channel::<Command>(8);
  let (_events_tx, events_rx) = flume::unbounded();
  let handle = Handle::new(
    tx,
    events_rx,
    InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES),
    retired_at(9, 4),
  );

  let target = MembershipTarget::new(BTreeSet::from([MemberId::new(1)]), BTreeSet::new());
  let fut = handle.reconfigure_to(target, HealthHint::default(), None);
  futures_util::pin_mut!(fut);
  let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
  match std::future::Future::poll(fut, &mut cx) {
    std::task::Poll::Ready(Err(ReconfigureError::Retired { local, epoch })) => {
      assert_eq!(local, MemberId::new(9));
      assert_eq!(epoch, Epoch::new(4));
    }
    other => panic!("expected Ready(Err(Retired)) on a retired handle, got {other:?}"),
  }
  assert!(
    cmd_rx.try_recv().is_err(),
    "a retired reconfigure enqueues no command"
  );
}

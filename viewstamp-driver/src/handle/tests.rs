use super::{Command, Handle};
use crate::{
  DriverError,
  session::{InflightBudget, MAX_INFLIGHT, MAX_PENDING_BYTES},
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
  );
  assert_eq!(
    default_caps.submit_byte_limit(),
    viewstamp_proto::max_request_body_len(),
    "at the default byte cap the transport bound binds"
  );

  let (tx, _rx) = futures_channel::mpsc::channel::<Command>(8);
  let tiny_cap = Handle::new(tx, events_rx, InflightBudget::new(MAX_INFLIGHT, 64));
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
  let handle = Handle::new(tx, events_rx, budget.clone());
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
  let handle = Handle::new(tx, events_rx, budget.clone());
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
  );
  // Drop the receiver so the channel is closed from the driver side.
  drop(rx);

  let target = MembershipTarget::new(BTreeSet::from([MemberId::new(1)]), BTreeSet::new());
  let fut = handle.reconfigure_to(target, HealthHint::default());
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
  );
  // Drop the receiver so the channel is closed from the driver side.
  drop(rx);

  let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
  match handle.add_peer(MemberId::new(1), addr) {
    Err(DriverError::DriverGone) => {}
    other => panic!("expected Err(DriverGone) on a closed channel, got {other:?}"),
  }
}

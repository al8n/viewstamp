use bytes::Bytes;
use viewstamp_proto::Event;

use crate::{
  DriverError,
  session::{InflightBudget, ReservationGuard},
};

/// A committed reply body returned by [`Handle::submit`].
pub type Reply = Bytes;

/// A control message from a [`Handle`] to the driver task.
#[derive(Debug)]
pub enum Command {
  /// Submit a client request; answer `reply` with the committed reply body.
  Submit {
    /// The request payload.
    body: Bytes,
    /// The one-shot channel the driver answers when the op commits.
    reply: futures_channel::oneshot::Sender<Reply>,
    /// The owning `InflightBudget` reservation for this submit. Carried with the queued command so
    /// the reservation is released by its `Drop` wherever the command finally dies: the driver MOVES
    /// it into the `Pending` entry on drain, or it drops with the command channel if a `Shutdown`
    /// tears the driver down before this submit is drained (so a submit racing shutdown cannot leak
    /// budget). It is the SINGLE owner of the reservation — never released manually here.
    reservation: ReservationGuard,
  },
  /// Ask the driver to stop; `ack` is signalled once teardown completes.
  Shutdown {
    /// Signalled after the driver loop exits and the socket is dropped.
    ack: futures_channel::oneshot::Sender<()>,
  },
}

/// A cheaply-cloneable handle to submit client requests and observe committed events.
///
/// Cloning is O(1) (channel-handle + two `Arc` clones). All clones share one node-local client
/// session — including its `InflightBudget`, so the count/byte submit caps apply across all clones,
/// not per clone.
#[derive(Clone)]
pub struct Handle {
  commands: flume::Sender<Command>,
  events: flume::Receiver<Event>,
  budget: InflightBudget,
}

impl Handle {
  pub(crate) fn new(
    commands: flume::Sender<Command>,
    events: flume::Receiver<Event>,
    budget: InflightBudget,
  ) -> Self {
    Self {
      commands,
      events,
      budget,
    }
  }

  /// Submit a client request and await its committed reply body.
  ///
  /// This RESERVES one slot of the shared in-flight submit budget (by count and by `body` length)
  /// BEFORE sending the command, and never blocks waiting for budget: if either cap is already full,
  /// or the bounded command channel is full, it returns [`DriverError::Busy`] immediately without
  /// minting a request. The reservation is held until the driver resolves the submit (commit,
  /// cancellation, or shutdown), which releases it; the await below only parks on the reply, not on
  /// budget.
  ///
  /// # Errors
  /// [`DriverError::RequestTooLarge`] if `body` exceeds
  /// [`viewstamp_proto::max_request_body_len()`](viewstamp_proto::max_request_body_len) — the body
  /// would frame larger than the transport can deliver (as the relayed `Request`/`Prepare`) and be
  /// dropped, so no commit could arrive; it is rejected up front WITHOUT reserving budget or enqueueing
  /// a command (the budget is untouched and nothing is minted), so an undeliverable request can neither
  /// hang nor pin the shared submit budget; [`DriverError::Busy`] if the in-flight submit budget (count
  /// or bytes) or the command channel is full — shed load and retry later; [`DriverError::DriverGone`]
  /// if the driver task has stopped; [`DriverError::ReplyDropped`] if the driver dropped the reply
  /// channel without answering (e.g. shutdown mid-flight).
  pub async fn submit(&self, body: impl Into<Bytes>) -> Result<Reply, DriverError> {
    let body = body.into();
    let body_len = body.len();
    // Reject a body the transport can never deliver BEFORE touching the budget or the channel. A body
    // over `max_request_body_len()` would, once relayed, frame to more than `MAX_FRAME_LEN` (as a
    // `Request` to the primary AND the larger `Prepare` to the backups) and be dropped on the wire — no
    // commit can come back, so a multi-replica cluster would leave the caller hanging while the body
    // pinned the shared submit budget. Surfaced as a non-blocking error here, the request never enters
    // `pending` nor reserves a slot for a commit that the transport could never produce.
    if body_len > viewstamp_proto::max_request_body_len() {
      return Err(DriverError::RequestTooLarge);
    }
    // Reserve the budget synchronously BEFORE sending, taking an owning `ReservationGuard`. On any
    // failure past this point the guard drops on the early return — its `Drop` releases the slot — so
    // the budget tracks only commands the driver will actually see (and turn into a `pending` entry
    // whose drop later releases). One owner, released exactly once, wherever the guard finally dies.
    let Some(reservation) = self.budget.try_acquire(body_len) else {
      return Err(DriverError::Busy);
    };
    let (reply, rx) = futures_channel::oneshot::channel();
    // `try_send` (never block): a full bounded command channel is backpressure, surfaced as `Busy`; a
    // disconnected channel means the driver is gone. On either, the un-sent `Command` carried in the
    // error — and so its `reservation` guard — drops, releasing the slot; no manual rollback.
    match self.commands.try_send(Command::Submit {
      body,
      reply,
      reservation,
    }) {
      Ok(()) => {}
      Err(flume::TrySendError::Full(_)) => return Err(DriverError::Busy),
      Err(flume::TrySendError::Disconnected(_)) => return Err(DriverError::DriverGone),
    }
    rx.await.map_err(|_| DriverError::ReplyDropped)
  }

  /// Request shutdown and await teardown completion.
  ///
  /// # Errors
  /// [`DriverError::DriverGone`] if the driver task has already stopped.
  pub async fn shutdown(&self) -> Result<(), DriverError> {
    let (ack, rx) = futures_channel::oneshot::channel();
    self
      .commands
      .send_async(Command::Shutdown { ack })
      .await
      .map_err(|_| DriverError::DriverGone)?;
    rx.await.map_err(|_| DriverError::ReplyDropped)
  }

  /// A receiver of consensus events — every [`Event`] the replica emits ([`Event::Committed`] plus
  /// the observability variants: view/status transitions, state-sync progress, repair solicits,
  /// durable checkpoints). (First cut: single-consumer; clones compete for events.)
  ///
  /// This is a BEST-EFFORT observation stream: the channel is bounded, so events are
  /// DROPPED if this receiver is not drained fast enough (or never drained) — observing events is
  /// optional and exerts no backpressure on the driver. For RELIABLE delivery of a request's outcome
  /// use [`Self::submit`], whose per-call reply is answered independently of this stream's pressure.
  #[must_use]
  pub fn events(&self) -> flume::Receiver<Event> {
    self.events.clone()
  }
}

#[cfg(test)]
mod tests {
  use super::{Command, Handle};
  use crate::{
    DriverError,
    session::{InflightBudget, MAX_INFLIGHT, MAX_PENDING_BYTES},
  };
  use bytes::Bytes;

  #[test]
  fn submit_sends_a_command_carrying_its_reply_channel() {
    // CMD_CAP-sized (bounded) channel; the budget starts empty.
    let (tx, rx) = flume::bounded::<Command>(8);
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

  /// A `submit` that cannot enqueue (the bounded command channel is full) returns `Busy` and ROLLS
  /// BACK its budget reservation — it never leaks a slot for a command the driver never sees. After
  /// the rollback the count is back to zero, so the budget is not silently exhausted by refused
  /// submits.
  #[test]
  fn submit_on_a_full_command_channel_is_busy_and_rolls_back_budget() {
    let (tx, _rx) = flume::bounded::<Command>(1);
    let (_events_tx, events_rx) = flume::unbounded();
    let budget = InflightBudget::new(MAX_INFLIGHT, MAX_PENDING_BYTES);
    let handle = Handle::new(tx, events_rx, budget.clone());
    let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());

    // Fill the 1-slot channel with a first submit (parks on its reply).
    let fut1 = handle.submit(Bytes::from_static(b"a"));
    futures_util::pin_mut!(fut1);
    let _ = std::future::Future::poll(fut1, &mut cx);
    assert_eq!(budget.count(), 1, "the first submit holds one reservation");

    // The channel is now full: the next submit must be Busy and leave the budget at 1 (its own
    // reservation rolled back), not 2.
    let fut2 = handle.submit(Bytes::from_static(b"b"));
    futures_util::pin_mut!(fut2);
    match std::future::Future::poll(fut2, &mut cx) {
      std::task::Poll::Ready(Err(DriverError::Busy)) => {}
      other => panic!("expected Ready(Err(Busy)) on a full command channel, got {other:?}"),
    }
    assert_eq!(
      budget.count(),
      1,
      "a Busy submit rolls back its reservation: the count stays at the one live submit"
    );
  }

  /// A body over `max_request_body_len()` is rejected up front with `RequestTooLarge` and touches
  /// neither the budget nor the command channel: the size check runs BEFORE the reserve and `try_send`,
  /// so a body the transport could never deliver (its relayed `Request`/`Prepare` would exceed
  /// `MAX_FRAME_LEN`) never reserves a slot nor enqueues a command — it cannot hang or pin the budget.
  #[test]
  fn submit_over_the_max_body_is_rejected_without_touching_budget_or_channel() {
    let (tx, rx) = flume::bounded::<Command>(8);
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
}

use std::sync::{Mutex, MutexGuard, PoisonError};

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
    /// it into the `Pending` entry on drain, or the teardown's close-then-drain of the command
    /// channel drops it still-queued if a `Shutdown` tears the driver down first (so a submit racing
    /// shutdown cannot leak budget). It is the SINGLE owner of the reservation — never released
    /// manually here.
    reservation: ReservationGuard,
  },
  /// Ask the driver to stop; `ack` is signalled once teardown completes.
  Shutdown {
    /// Signalled after the driver loop exits and its socket/listener fd is fully RELEASED
    /// (closed, with every helper-task and in-flight-op reference gone) — so the bound address is
    /// immediately rebindable when the ack arrives.
    ack: futures_channel::oneshot::Sender<()>,
  },
  /// Drive an arbitrary-target reconfiguration to convergence (a per-step plan loop in the driver task).
  Reconfigure {
    /// The set goal.
    target: viewstamp_proto::MembershipTarget,
    /// The optional operator shrink-phase health hint.
    health: crate::reconfigure::HealthHint,
    /// The completion channel.
    reply: futures_channel::oneshot::Sender<Result<(), crate::reconfigure::ReconfigureError>>,
  },
  /// Register a peer's network address in the driver's address book; dialed when this member appears
  /// in a future membership rebuild. Best-effort: dropped if the driver is shutting down.
  AddPeer {
    /// The stable identity of the peer.
    member_id: viewstamp_proto::MemberId,
    /// The network address the peer listens on.
    addr: std::net::SocketAddr,
  },
}

/// A cheaply-cloneable handle to submit client requests and observe committed events.
///
/// Cloning is O(1) (two channel handles plus the budget's two `Arc`s). All clones share one node-local client
/// session — including its `InflightBudget`, so the count/byte submit caps apply across all clones,
/// not per clone.
pub struct Handle {
  /// The command sender, `Mutex`-wrapped because `futures_channel::mpsc::Sender::try_send` takes
  /// `&mut self` (the sender tracks its own parked state) while `submit`/`shutdown` take `&self`.
  /// The lock is held only across a non-blocking `try_send`/`clone` — never across an await — so
  /// callers sharing one clone by reference serialize only the enqueue itself.
  commands: Mutex<futures_channel::mpsc::Sender<Command>>,
  events: flume::Receiver<Event>,
  budget: InflightBudget,
}

impl Clone for Handle {
  fn clone(&self) -> Self {
    // A cloned sender starts fresh (unparked) and carries its own guaranteed channel slot: the
    // command channel admits up to its buffer plus one in-flight command per live sender, so each
    // `Handle` clone widens the queue's slack by one. The submit BUDGET — shared by all clones — is
    // the binding bound on in-flight submits, not that slack (see `DriverConfig::cmd_cap`).
    Self {
      commands: Mutex::new(self.commands().clone()),
      events: self.events.clone(),
      budget: self.budget.clone(),
    }
  }
}

impl Handle {
  #[doc(hidden)]
  pub fn new(
    commands: futures_channel::mpsc::Sender<Command>,
    events: flume::Receiver<Event>,
    budget: InflightBudget,
  ) -> Self {
    Self {
      commands: Mutex::new(commands),
      events,
      budget,
    }
  }

  /// Lock the command sender. A poisoned lock only means another thread panicked while holding it;
  /// the sender is a plain channel handle whose state cannot be torn by an unwind mid-`try_send`,
  /// so the inner value is taken either way rather than cascading the panic into every clone.
  fn commands(&self) -> MutexGuard<'_, futures_channel::mpsc::Sender<Command>> {
    self.commands.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Submit a client request and await its committed reply body.
  ///
  /// This RESERVES one slot of the shared in-flight submit budget (by count and by `body` length)
  /// BEFORE sending the command, and never blocks waiting for budget: if either cap is already full,
  /// or the bounded command channel refuses the send, it returns [`DriverError::Busy`] immediately
  /// without minting a request. The reservation is held until the driver resolves the submit
  /// (commit, cancellation, or shutdown), which releases it; the await below only parks on the
  /// reply, not on budget.
  ///
  /// # Errors
  /// [`DriverError::RequestTooLarge`] if `body` exceeds
  /// [`viewstamp_proto::max_request_body_len()`](viewstamp_proto::max_request_body_len) — the body
  /// would frame larger than the transport can deliver (as the relayed `Request`/`Prepare`) and be
  /// dropped, so no commit could arrive; it is rejected up front WITHOUT reserving budget or enqueueing
  /// a command (the budget is untouched and nothing is minted), so an undeliverable request can neither
  /// hang nor pin the shared submit budget; [`DriverError::Busy`] if the in-flight submit budget (count
  /// or bytes) is full or the command channel refuses the send — shed load and retry later;
  /// [`DriverError::DriverGone`] if the driver task has stopped; [`DriverError::ReplyDropped`] if the
  /// driver dropped the reply channel without answering (e.g. shutdown mid-flight).
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
    // `try_send` (never block; the lock spans only this call): a refusing command channel is
    // backpressure, surfaced as `Busy`; a closed channel means the driver is gone. On either, the
    // un-sent `Command` carried back in the error — and so its `reservation` guard — drops,
    // releasing the slot; no manual rollback.
    let sent = self.commands().try_send(Command::Submit {
      body,
      reply,
      reservation,
    });
    if let Err(err) = sent {
      return Err(if err.is_full() {
        DriverError::Busy
      } else {
        DriverError::DriverGone
      });
    }
    rx.await.map_err(|_| DriverError::ReplyDropped)
  }

  /// The largest body a single [`Self::submit`] on this handle can ever carry to a commit: the
  /// smaller of the transport bound
  /// ([`viewstamp_proto::max_request_body_len()`](viewstamp_proto::max_request_body_len), past
  /// which `submit` returns [`DriverError::RequestTooLarge`]) and this driver's configured
  /// in-flight byte cap (the budget's `max_bytes`, past which even a LONE body can never reserve
  /// and `submit` returns [`DriverError::Busy`] forever).
  ///
  /// Anything that packs bodies for this handle — the batching aggregator — must size them against
  /// THIS limit, read from the handle it submits through: packing against the transport bound
  /// alone would mint bodies a smaller-than-default byte cap permanently refuses.
  #[must_use]
  pub fn submit_byte_limit(&self) -> usize {
    viewstamp_proto::max_request_body_len().min(self.budget.max_bytes())
  }

  /// Request shutdown and await teardown completion.
  ///
  /// The returned future resolves only after the driver has fully RELEASED its socket/listener
  /// fd — the fd is closed, not merely scheduled to close — so the address the driver was bound
  /// to is immediately rebindable: constructing a new driver on the same address right after this
  /// returns must succeed.
  ///
  /// # Errors
  /// [`DriverError::DriverGone`] if the driver task has already stopped.
  pub async fn shutdown(&self) -> Result<(), DriverError> {
    let (ack, rx) = futures_channel::oneshot::channel();
    // A fresh sender clone starts unparked with its own guaranteed channel slot, so the Shutdown
    // enqueues immediately even when the buffer is full of submits; the only send failure is a
    // closed channel — the driver is already gone.
    let mut commands = self.commands().clone();
    if commands.try_send(Command::Shutdown { ack }).is_err() {
      return Err(DriverError::DriverGone);
    }
    rx.await.map_err(|_| DriverError::ReplyDropped)
  }

  /// Drive the cluster to `target` by sequencing proven Tier B single-member changes. The driver task runs
  /// the per-step replanning loop; this method submits the goal and awaits convergence. SOLE-DRIVER: it is
  /// the only reconfiguration driver for the cluster (a driver-level plan guard serializes two calls on the
  /// same driver). See [`crate::reconfigure::ReconfigureError`] for the bounded-loop outcomes.
  ///
  /// # Errors
  /// [`crate::reconfigure::ReconfigureError::Propose`] with
  /// [`viewstamp_proto::ProposeMembershipError::Busy`] if the command channel is full (retryable);
  /// [`crate::reconfigure::ReconfigureError::DriverGone`] if the channel is closed or the reply is
  /// dropped (terminal — the driver is gone, do not retry this handle); all other outcomes propagate
  /// from the driver-task executor loop.
  pub async fn reconfigure_to(
    &self,
    target: viewstamp_proto::MembershipTarget,
    health: crate::reconfigure::HealthHint,
  ) -> Result<(), crate::reconfigure::ReconfigureError> {
    let (reply, rx) = futures_channel::oneshot::channel();
    // Mirror `submit`: `try_send` never blocks. A FULL channel is backpressure — retryable Busy.
    // A CLOSED channel means the driver is gone — terminal DriverGone (never retry a dead handle).
    let sent = self.commands().try_send(Command::Reconfigure {
      target,
      health,
      reply,
    });
    if let Err(ref err) = sent {
      return Err(if err.is_full() {
        crate::reconfigure::ReconfigureError::Propose(viewstamp_proto::ProposeMembershipError::Busy)
      } else {
        crate::reconfigure::ReconfigureError::DriverGone
      });
    }
    // A dropped reply also means the driver exited before answering — terminal.
    rx.await
      .map_err(|_| crate::reconfigure::ReconfigureError::DriverGone)?
  }

  /// A receiver of consensus events — every [`Event`] the replica emits ([`Event::Committed`] plus
  /// the observability variants: view/status transitions, state-sync progress, repair solicits,
  /// durable checkpoints). (Single-consumer: clones compete for events — each event reaches
  /// exactly one receiver, not every clone.)
  ///
  /// This is a BEST-EFFORT observation stream: the channel is bounded, so events are
  /// DROPPED if this receiver is not drained fast enough (or never drained) — observing events is
  /// optional and exerts no backpressure on the driver. For RELIABLE delivery of a request's outcome
  /// use [`Self::submit`], whose per-call reply is answered independently of this stream's pressure.
  #[must_use]
  pub fn events(&self) -> flume::Receiver<Event> {
    self.events.clone()
  }

  /// Register the network address for `member_id` in the driver's peer address book.
  ///
  /// The driver dials this address when `member_id` appears at a new slot in the active membership
  /// after a configuration change. Call this before any membership change that adds the member so the
  /// driver has the address ready when it rebuilds its peer list. Non-async: the address update is
  /// enqueued without blocking.
  ///
  /// The update must not be lost silently: a member that is already live but absent from the
  /// driver's address book stays UNDIALED until an `AddPeer` for it lands, so a dropped update would
  /// strand that member with no caller signal. The send is therefore reported, mirroring
  /// [`Self::submit`] / [`Self::reconfigure_to`] backpressure: retry on [`DriverError::Busy`], and
  /// treat [`DriverError::DriverGone`] as terminal.
  ///
  /// # Errors
  /// [`DriverError::Busy`] if the command channel is full — the update was not enqueued; retry once
  /// the driver drains; [`DriverError::DriverGone`] if the driver task has stopped (the channel is
  /// closed) — terminal, do not retry this handle.
  pub fn add_peer(
    &self,
    member_id: viewstamp_proto::MemberId,
    addr: std::net::SocketAddr,
  ) -> Result<(), DriverError> {
    // Mirror `submit`/`reconfigure_to`: `try_send` never blocks. A FULL channel is backpressure —
    // retryable Busy. A CLOSED channel means the driver is gone — terminal DriverGone.
    self
      .commands()
      .try_send(Command::AddPeer { member_id, addr })
      .map_err(|err| {
        if err.is_full() {
          DriverError::Busy
        } else {
          DriverError::DriverGone
        }
      })
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
}

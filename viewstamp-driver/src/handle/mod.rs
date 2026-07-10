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
mod tests;

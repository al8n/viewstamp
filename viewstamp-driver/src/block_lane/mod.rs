//! The driver's block-storage lane: the serial execution context a
//! [`BlockJob`](viewstamp_proto::BlockJob) runs on, off the thread that pumps consensus.
//!
//! The consensus endpoint holds no block store — it EMITS jobs and consumes their completions — so
//! where those jobs execute is the driver's choice. This module is that choice: one lane per store,
//! owning the store, the [`BlockJobCursor`] that witnesses execution order, and (for a spawned lane)
//! the thread the work runs on. The run loop hands each polled job to the lane and feeds back each
//! completion it produces; a materialize large enough to take seconds occupies the lane, never the
//! run loop, so commits and heartbeats keep flowing underneath it.
//!
//! # Serial, in issue order
//!
//! Both lane placements execute jobs SERIALLY IN THE ORDER THEY WERE SUBMITTED and hand back
//! completions in that same order — the order is a storage-safety obligation, not a preference (see
//! the [job seam contract](viewstamp_proto::BlockJob)). A spawned lane gets it from its shape: ONE
//! worker thread pulling a FIFO channel, pushing each completion into a second FIFO channel. An
//! inline lane executes on the submitting thread under one mutex, which is serial by the same
//! argument. Neither placement can reorder, and the cursor fail-stops if one ever did.
//!
//! # The cursor's lifetime
//!
//! The cursor belongs to the LANE, and the lane OWNS the store — the store cannot be handed to a
//! rebuilt endpoint without its lane, because there is no way to take it back out. That is what
//! makes the cross-incarnation half of the order guarantee real: a dead endpoint's queued job
//! carries the smaller incarnation, so when it executes after its successor's job the cursor stops
//! it. A driver that minted a fresh cursor whenever it rebuilt an endpoint over the same store
//! would forfeit that entirely (a fresh cursor's first admission has nothing to follow and is
//! unchecked), so [`BlockLane`] is CLONE and the clone shares one lane: an embedder rebuilding a
//! driver in place passes the SAME lane, and its cursor — with any job the dead endpoint still owed
//! — carries across the rebuild.

use std::sync::{Arc, Mutex};

use viewstamp_proto::{
  BlockJob, BlockJobCursor, BlockJobDone, BlockStore, StateMachine, execute_block_job,
};

/// The store, the execution-order cursor, and (for a spawned lane) the thread block jobs run on.
///
/// Construct one per block store with [`spawn`](Self::spawn) — the production placement, a
/// dedicated worker thread — or [`inline`](Self::inline) for a deterministic harness that must
/// execute jobs on its own thread.
///
/// The driver takes it by value. CLONE it first if the store outlives this driver: the cursor that
/// witnesses execution order belongs to the lane, and handing a rebuilt driver a FRESH lane over the
/// same store forfeits the cross-incarnation half of that check (a fresh cursor's first admission
/// has nothing to follow and is unchecked).
pub struct BlockLane<S: StateMachine> {
  sink: Sink<S>,
  /// The completions half. The lane retains a sender clone for its whole life, so the receiver
  /// never observes a disconnect — a run loop may park a select arm on
  /// [`recv`](Self::recv) forever without a dead channel turning that arm into an
  /// always-ready select winner.
  done_tx: flume::Sender<BlockJobDone<S>>,
  done_rx: flume::Receiver<BlockJobDone<S>>,
}

/// Where a submitted job executes.
enum Sink<S: StateMachine> {
  /// A dedicated worker thread owns the store + cursor and pulls this FIFO channel.
  Spawned(flume::Sender<BlockJob<S>>),
  /// The submitting thread executes under this mutex, which owns the store + cursor.
  Inline(Arc<Mutex<Executor>>),
}

/// The store and the execution-order cursor, welded together: everything one lane executes against.
struct Executor {
  cursor: BlockJobCursor,
  store: Box<dyn BlockStore + Send>,
}

impl Executor {
  fn run<S: StateMachine>(&mut self, job: BlockJob<S>) -> BlockJobDone<S> {
    execute_block_job(&mut self.cursor, job, &mut *self.store)
  }
}

impl<S: StateMachine> Clone for BlockLane<S> {
  /// Another handle on the SAME lane — same store, same cursor, same worker.
  ///
  /// The completions channel is shared too, so exactly one holder may consume from a lane at a
  /// time: clone to carry a lane ACROSS drivers (the rebuild case), never to run two drivers off
  /// one store at once.
  ///
  /// That single-consumer rule is a RUNTIME discipline, not one the type system enforces: nothing
  /// stops two live clones from calling [`try_recv`](Self::try_recv) or [`recv`](Self::recv)
  /// concurrently — it compiles and runs. The channel underneath is multi-consumer, so doing so
  /// would silently SPLIT completions between the two callers (each one landing wherever
  /// `recv`/`try_recv` happens to win the race) rather than duplicate them, so whichever clone does
  /// not feed a given completion into an endpoint's `on_block_done` leaves that job's completion
  /// permanently unaccounted for. Keeping to one consumer at a time is on the embedder.
  fn clone(&self) -> Self {
    Self {
      sink: match &self.sink {
        Sink::Spawned(tx) => Sink::Spawned(tx.clone()),
        Sink::Inline(exec) => Sink::Inline(Arc::clone(exec)),
      },
      done_tx: self.done_tx.clone(),
      done_rx: self.done_rx.clone(),
    }
  }
}

impl<S: StateMachine> core::fmt::Debug for BlockLane<S> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("BlockLane")
      .field(
        "placement",
        &match self.sink {
          Sink::Spawned(_) => "spawned",
          Sink::Inline(_) => "inline",
        },
      )
      .field("completions_ready", &self.done_rx.len())
      .finish_non_exhaustive()
  }
}

impl<S: StateMachine + Send + 'static> BlockLane<S> {
  /// A lane on its own worker thread — the production placement.
  ///
  /// Requires a `Send` state machine, since a job carries the captured checkpoint image (and, for a
  /// restore, a detached seed) across the thread boundary. A state machine deliberately pinned to
  /// one thread (an `Rc`-shared one, say) can only take the [`inline`](Self::inline) placement.
  ///
  /// The thread owns `store` and the lane's cursor for as long as any [`BlockLane`] handle lives,
  /// and executes one job at a time. Block I/O therefore never runs on the thread that pumps
  /// consensus: a checkpoint materialize that takes seconds of writes plus an `fsync` delays only
  /// the jobs behind it, while the run loop keeps committing ops, answering heartbeats, and
  /// servicing view-change timers.
  ///
  /// Both channels are UNBOUNDED, deliberately: submitting is what the consensus pump does, so a
  /// bounded queue would push back by BLOCKING the pump — reintroducing the stall the lane exists
  /// to remove. The depth is bounded at the source instead, by the endpoint's own caps on how many
  /// jobs it can have outstanding (one checkpoint sequence, one transfer walk, and a hard cap on
  /// concurrent peer block serves).
  ///
  /// The thread exits when the last handle drops. A job still executing at that moment runs to
  /// completion and its result is discarded — crash-equivalent, and safe for exactly the reason a
  /// crash is: the completion names a dead endpoint's incarnation, which the endpoint refuses
  /// before it consults any correlation state.
  ///
  /// That exit is DETACHED, not awaited, which matters beyond the discarded result: if a driver's
  /// teardown drops its last handle while this thread is mid-job (the bounded shutdown drain hit
  /// its deadline with a job still running — see
  /// [`SHUTDOWN_DRAIN_DEADLINE`](crate::SHUTDOWN_DRAIN_DEADLINE)), `store` is NOT dropped by the
  /// time the driver's `run()` returns or a `shutdown().await` resolves. It drops later, on this
  /// thread, once the in-flight job finishes and the thread notices its channel is gone. An
  /// embedder whose `store` holds an OS-level exclusive lock (a `flock`'d file, say) cannot assume
  /// that lock is released the instant teardown reports back — reopening the same backing media
  /// right after an unclean shutdown can race this still-live worker thread.
  pub fn spawn<L: BlockStore + Send + 'static>(store: L) -> Self {
    let (jobs_tx, jobs_rx) = flume::unbounded::<BlockJob<S>>();
    let (done_tx, done_rx) = flume::unbounded::<BlockJobDone<S>>();
    let worker_done = done_tx.clone();
    let mut exec = Executor {
      cursor: BlockJobCursor::new(),
      store: Box::new(store),
    };
    // Detached, not joined: the lane has no teardown of its own to await. `recv` ends when every
    // handle has dropped its job sender, which is the driver's own teardown, and the thread then
    // drops the store and exits. A completion the receiver no longer wants ends it the same way.
    std::thread::Builder::new()
      .name("viewstamp-block-lane".to_owned())
      .spawn(move || {
        while let Ok(job) = jobs_rx.recv() {
          if worker_done.send(exec.run(job)).is_err() {
            return;
          }
        }
      })
      .expect("spawning the block-storage lane thread");
    Self {
      sink: Sink::Spawned(jobs_tx),
      done_tx,
      done_rx,
    }
  }
}

impl<S: StateMachine> BlockLane<S> {
  /// A lane that executes on the submitting thread — for a deterministic harness.
  ///
  /// [`submit`](Self::submit) runs the job to completion before it returns, so a test that drives a
  /// driver step by step sees every block job resolve within the step that issued it, with no
  /// thread and no scheduling to wait on. It carries the same cursor and the same serial order as a
  /// spawned lane; what it does NOT carry is the whole point of the spawned one — the work runs on
  /// the caller's thread, so a slow store stalls it.
  pub fn inline<L: BlockStore + Send + 'static>(store: L) -> Self {
    let (done_tx, done_rx) = flume::unbounded::<BlockJobDone<S>>();
    Self {
      sink: Sink::Inline(Arc::new(Mutex::new(Executor {
        cursor: BlockJobCursor::new(),
        store: Box::new(store),
      }))),
      done_tx,
      done_rx,
    }
  }

  /// Hands one job to the lane, to execute after every job already submitted.
  ///
  /// Never blocks on a spawned lane (the queue is unbounded); executes the job before returning on
  /// an inline one.
  ///
  /// # Panics
  /// If a spawned lane's worker thread is gone — it unwound, which means a job panicked: the
  /// [`BlockJobCursor`]'s issue-order fail-stop, or the embedder's own store. The lane cannot
  /// execute anything after that, and a driver that kept submitting into the dead queue would stall
  /// its storage silently, so the panic is re-raised at the submit that discovers it.
  ///
  /// That re-raise depends on a NEXT submit arriving. If none does — the panicked job was the last
  /// one issued, or nothing else needs the store before teardown — the panic never surfaces here at
  /// all: the endpoint is simply left owing that job's completion forever. It stays in-flight, a
  /// bounded shutdown drain (see [`ShutdownReport`](crate::ShutdownReport)) can never see it
  /// resolve, and teardown reports unquiesced once its deadline elapses rather than hanging.
  pub fn submit(&self, job: BlockJob<S>) {
    match &self.sink {
      Sink::Spawned(jobs) => {
        assert!(
          jobs.send(job).is_ok(),
          "the block-storage lane's worker thread has stopped: a block job unwound it (the \
           issue-order fail-stop, or the block store itself), so no further job can execute",
        );
      }
      Sink::Inline(exec) => {
        let done = exec
          .lock()
          .expect(
            "the inline block-storage lane's mutex is poisoned: a block job panicked under it",
          )
          .run(job);
        // The receiver is this same lane's, retained for the lane's whole life.
        let _ = self.done_tx.send(done);
      }
    }
  }

  /// Takes one completion the lane has finished, or `None` when it has none ready.
  ///
  /// Completions come back in submission order; feed them to the endpoint in the order this
  /// returns them.
  pub fn try_recv(&self) -> Option<BlockJobDone<S>> {
    self.done_rx.try_recv().ok()
  }

  /// Resolves when the lane finishes its next job, yielding that completion — the run loop's wake
  /// on a lane that has been executing while the loop waited on I/O.
  ///
  /// Cancel-safe to lose: the completion is consumed only when this resolves, so an arm that loses
  /// a select leaves it queued for [`try_recv`](Self::try_recv) or the next wait. It never resolves
  /// to a disconnect (the lane retains a sender), so a select arm may park on it indefinitely.
  pub async fn recv(&self) -> BlockJobDone<S> {
    match self.done_rx.recv_async().await {
      Ok(done) => done,
      // Unreachable while `self` is alive, since `self.done_tx` is a live sender. Parking rather
      // than returning keeps a hypothetical disconnect from making this a permanently-ready select
      // arm that spins the run loop.
      Err(_) => core::future::pending().await,
    }
  }
}

#[cfg(test)]
mod tests;

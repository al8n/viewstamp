//! The shutdown contract shared by both drivers: what a teardown reports back, and the bounded
//! storage drain that produces it.

use std::time::Duration;

/// How long a driver teardown waits for the endpoint's in-flight WAL/superblock ops to complete
/// before it stops waiting and releases storage anyway (see [`ShutdownReport::storage_quiesced`]).
///
/// Deliberately a constant rather than a [`DriverConfig`](crate::DriverConfig) knob: this is a
/// fail-safe ceiling on a wait that should never be reached, not a value an embedder tunes for
/// throughput. 5 s is two to three orders of magnitude above a healthy completion — a device write
/// plus its durability barrier resolves in milliseconds even with a deep queue ahead of it — so a
/// working backend always drains well inside it, while a wedged or unreachable one cannot hold the
/// shutdown open indefinitely. It sits in the same "generous but bounded" band the drivers already
/// use for their other fail-safe waits ([`DIAL_TIMEOUT`](crate::DIAL_TIMEOUT), the per-conn auth
/// window).
pub const SHUTDOWN_DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// How often the teardown re-polls storage while draining. The embedder's storage-ready notifier is
/// a wake-latency optimization it may not wire at all, so the drain must not depend on it and polls
/// on this cadence instead. Short enough that a drain finishes about as promptly as the backend
/// does, long enough that even a fully wedged backend costs a few thousand cheap polls rather than
/// a spin.
const SHUTDOWN_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Whether the driver's storage reached a quiet state before teardown released it.
///
/// One fact within a [`ShutdownReport`], not the shutdown's whole outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageQuiescence {
  /// Every WAL/superblock op the endpoint had in flight completed: the backend owes this endpoint
  /// nothing, so nothing was cut off mid-write.
  Quiesced,
  /// [`SHUTDOWN_DRAIN_DEADLINE`] elapsed with at least one op still in flight, and the driver
  /// released storage anyway.
  DeadlineExpired,
}

/// What a completed shutdown reports back to [`Handle::shutdown`](crate::Handle::shutdown).
///
/// A REPORT, not a verdict: it carries the individual facts a caller may want about the teardown —
/// today, storage quiescence — and grows further ones by extension rather than by being replaced.
/// It is `Copy`, so one teardown's findings can be answered to any number of waiters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShutdownReport {
  storage: StorageQuiescence,
}

impl ShutdownReport {
  /// Build the report a driver teardown sends with its ack.
  #[doc(hidden)]
  #[must_use]
  pub const fn new(storage: StorageQuiescence) -> Self {
    Self { storage }
  }

  /// Whether storage reached a quiet state before the driver released it: `true` iff, within
  /// [`SHUTDOWN_DRAIN_DEADLINE`], every WAL append and superblock write the endpoint owed durability
  /// for completed, together with every checkpoint read it had issued to serve a peer's
  /// `RequestSync` and every block job still on its storage lane (a materialize is the write half of
  /// the durable checkpoint transaction, so a lane still executing one is storage the endpoint
  /// owes). In-flight RECOVERY reads are excluded: dropping one loses nothing durable, and a
  /// `Recovering` endpoint is itself the product of `recover()`.
  ///
  /// One block-job case always ends here rather than racing the deadline: a job that PANICS on a
  /// spawned lane kills its worker thread, so that job's completion can never arrive at all (see
  /// [`BlockLane::submit`](crate::BlockLane::submit)'s panic docs). The endpoint owes it forever, so
  /// the drain always runs out the clock in that case and this reports `false`.
  ///
  /// `false` is a legitimate outcome for a TEARDOWN — not a failure the driver papers over, and
  /// not something to retry. On expiry the driver drops storage mid-write, which is exactly what a
  /// crash does, and a crash is an event this system is built to survive: a WAL slot either holds a
  /// completed append or it does not, and the next boot re-derives the durable extent from the
  /// durable headers either way. A late completion is also inert on the correlation plane — a
  /// storage correlation id is scoped to the endpoint incarnation that minted it, so a completion
  /// landing once this endpoint is gone can never equal an id a rebuilt endpoint mints, and is
  /// refused at a single choke point before any correlation table is consulted. That is what makes
  /// a BOUNDED wait acceptable for a teardown instead of a wedge risk: an unbounded one would
  /// trade a survivable outcome for an unbounded hang. What `false` does NOT license is rebuilding
  /// an endpoint over the SAME still-live handles: the un-quiesced writes it reports are physical
  /// facts the refusal cannot cancel, and a successor built over them lacks the slot-quiescence
  /// witnesses to defer its conflicting re-appends. After an expired drain the safe successors are
  /// process exit or releasing the handles with the process — crash semantics, which the next boot
  /// recovers.
  ///
  /// What `false` does tell an embedder is that this stop was not orderly — some durability work
  /// the endpoint had submitted has an unknown outcome, so the next boot may have a tail to
  /// re-verify — and that a backend reporting it routinely is not completing its writes.
  #[must_use]
  pub const fn storage_quiesced(&self) -> bool {
    matches!(self.storage, StorageQuiescence::Quiesced)
  }
}

/// Drain the endpoint's in-flight storage under [`SHUTDOWN_DRAIN_DEADLINE`], reporting whether it
/// reached quiescence. The single definition of the drain policy, so the drivers cannot drift on
/// how long they wait or on what expiry means.
///
/// `pump` runs ONE storage pass — feed the WAL and superblock completions the backend has ready
/// through the endpoint — and returns whether the endpoint is now free of in-flight storage ops. It
/// is called before the deadline is ever consulted, so a store that is already quiet costs one pass
/// and no sleep. `sleep` is the caller's runtime timer, awaited between passes; whatever it
/// resolves to is discarded (the runtimes disagree on that type, and only the delay matters).
///
/// A pass can itself submit further durability work (a completion releasing a deferred append, a
/// checkpoint sequence advancing its next write), which is why this loops on the endpoint's own
/// in-flight signal rather than counting the ops it started with.
#[doc(hidden)]
pub async fn drain_storage<P, S, F>(mut pump: P, sleep: S) -> StorageQuiescence
where
  P: FnMut() -> bool,
  S: Fn(Duration) -> F,
  F: core::future::Future,
{
  let deadline = std::time::Instant::now() + SHUTDOWN_DRAIN_DEADLINE;
  loop {
    if pump() {
      return StorageQuiescence::Quiesced;
    }
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
      return StorageQuiescence::DeadlineExpired;
    }
    let _ = sleep(remaining.min(SHUTDOWN_DRAIN_POLL_INTERVAL)).await;
  }
}

#[cfg(test)]
mod tests;

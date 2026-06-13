//! The edge-batching aggregator: many caller units riding ONE driver submit per consensus op.
//!
//! [`aggregator`] splits a driver's [`Handle`] into a cloneable [`BatchHandle`] (callers submit
//! individual units or atomic groups) and an [`AggregatorPump`] the embedder spawns like the
//! driver itself. The pump keeps AT MOST ONE `Handle::submit` in flight — an aggregator-imposed
//! discipline, not a proto rule (the proto only requires consecutive request numbering; drivers
//! pipeline freely) — and that discipline IS the batching clock: units queue while a body flies,
//! and when it resolves everything queued packs into the next body via
//! [`BatchBuilder`](viewstamp_proto::BatchBuilder). Throughput then scales with load (an idle
//! aggregator ships a lone unit immediately; a busy one amortizes consensus across whole queues)
//! without any timer in the hot path.
//!
//! # Budgets
//!
//! A packed body is sized against BOTH directions up front:
//!
//! - REQUEST: the body fits [`Handle::submit_byte_limit`] — the real driver budget, sourced from
//!   the handle the pump consumes, so a packed body can never be refused as too large or
//!   `Busy`-wedged by a smaller-than-default driver byte cap.
//! - REPLY: the WORST-CASE reply fits `max_reply_body_len()` — the pump admits units to a body
//!   only while `BATCH_COUNT_OVERHEAD + Σ (BATCH_UNIT_OVERHEAD + max_unit_reply_len)` stays within
//!   it, pricing every unit's reply at the [`BatchConfig::new`] ceiling. The state machine's
//!   [`ReplyBuilder`](viewstamp_proto::ReplyBuilder) holds the other side of that contract.
//!
//! A unit or group that can NEVER fit (over either effective budget alone) is refused at submit
//! time; everything admitted to the queue is therefore packable, so the pump can never wedge on an
//! unpackable head-of-line entry.
//!
//! # The error taxonomy
//!
//! Every unit resolves with its reply bytes or a [`BatchError`] whose top-level class IS the retry
//! contract: [`BatchError::Refused`] never reached consensus (safe to resubmit),
//! [`BatchError::OutcomeUnknown`] may have committed (resubmit only behind embedder idempotency),
//! [`BatchError::CommittedReplyLost`] definitely committed but the reply is unusable (resubmitting
//! a non-idempotent unit is a guaranteed double-apply). The aggregator never auto-retries:
//! retrying is a correctness decision only the embedder can make.

use std::{
  cell::RefCell,
  collections::VecDeque,
  future::{Future, poll_fn},
  pin::{Pin, pin},
  sync::{Arc, Mutex, PoisonError},
  task::{Context, Poll},
  time::Duration,
};

use bytes::Bytes;
use viewstamp_proto::{BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchBuilder, ReplyView};

use crate::{
  DriverError, Handle,
  session::{InflightBudget, ReservationGuard},
};

/// Default cap on queued entries (a [`BatchHandle::submit`] is one entry; a whole
/// [`BatchHandle::submit_group`] is one entry). Mirrors the driver's in-flight submit count cap
/// (`MAX_INFLIGHT`): 4096 distinct waiting callers is far more concurrency than one aggregator
/// feeds a single client session, yet each queued entry costs only its `Bytes` handles, oneshots,
/// and budget guard. Past the cap a submit returns [`BatchError::Refused`] /
/// [`RefusedReason::QueueFull`]. Tunable via [`BatchConfig::with_max_queued_units`].
const MAX_QUEUED_UNITS: usize = 4096;

/// Default cap on total queued unit bytes (logical [`Bytes::len`] accounting). Mirrors the
/// driver's in-flight byte cap (`MAX_PENDING_BYTES`, 128 MiB): far above any realistic waiting
/// working set — about eight maximal request bodies — yet a hard bound a flooding caller cannot
/// exceed. Past the cap a submit returns [`BatchError::Refused`] / [`RefusedReason::QueueFull`].
/// Tunable via [`BatchConfig::with_max_queued_bytes`].
const MAX_QUEUED_BYTES: usize = 128 * 1024 * 1024;

/// Tunable aggregator parameters. Unlike [`crate::DriverConfig`] there is no zero-argument
/// default: the per-unit reply ceiling is the embedder's contract with its state machine — any
/// default would silently misprice reply budgets — so [`BatchConfig::new`] requires it, and only
/// the queue caps carry defaults (each default constant documents its sizing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchConfig {
  /// Count cap on queued entries (the queue budget's first axis AND the queue channel's bound).
  max_queued_units: usize,
  /// Byte cap across all queued unit bodies (the queue budget's second axis).
  max_queued_bytes: usize,
  /// The worst-case reply length of ONE unit, used to size each body's reply budget.
  max_unit_reply_len: usize,
}

impl BatchConfig {
  /// A config with the default queue caps and the REQUIRED per-unit reply ceiling.
  ///
  /// `max_unit_reply_len` is the largest reply the embedder's state machine may produce for one
  /// unit: the pump prices every admitted unit's reply at this ceiling so a full batch's reply
  /// always fits `max_reply_body_len()`, and the state machine's
  /// [`ReplyBuilder`](viewstamp_proto::ReplyBuilder) (constructed with the SAME ceiling) refuses
  /// any reply unit over it. The value is taken verbatim — a ceiling so large that even ONE
  /// ceiling-priced reply exceeds `max_reply_body_len()` is not clamped: it makes every submit
  /// refuse ([`RefusedReason::UnitTooLarge`] / [`RefusedReason::GroupTooLarge`]) rather than admit
  /// units whose committed replies the transport could refuse with no in-protocol recovery.
  #[must_use]
  pub const fn new(max_unit_reply_len: usize) -> Self {
    Self {
      max_queued_units: MAX_QUEUED_UNITS,
      max_queued_bytes: MAX_QUEUED_BYTES,
      max_unit_reply_len,
    }
  }

  /// Count cap on queued entries; a submit past it returns [`BatchError::Refused`] /
  /// [`RefusedReason::QueueFull`].
  #[inline(always)]
  pub const fn max_queued_units(&self) -> usize {
    self.max_queued_units
  }

  /// Byte cap across all queued unit bodies; a submit past it returns [`BatchError::Refused`] /
  /// [`RefusedReason::QueueFull`].
  #[inline(always)]
  pub const fn max_queued_bytes(&self) -> usize {
    self.max_queued_bytes
  }

  /// The declared worst-case reply length of one unit (the reply-budget ceiling).
  #[inline(always)]
  pub const fn max_unit_reply_len(&self) -> usize {
    self.max_unit_reply_len
  }

  /// Override the queued-entry count cap (clamped to at least 1 so an idle aggregator can always
  /// admit one entry).
  #[must_use]
  pub const fn with_max_queued_units(mut self, max: usize) -> Self {
    self.max_queued_units = if max == 0 { 1 } else { max };
    self
  }

  /// Override the queued byte cap (clamped to at least 1). The accounting is LOGICAL
  /// [`Bytes::len`]: a sliced `Bytes` counts its slice length while its backing allocation's
  /// retention stays the caller's concern, exactly as with [`Handle::submit`]. Keep the cap at or
  /// above the handle's [`Handle::submit_byte_limit`] or a lone maximal unit — too big for the
  /// queue yet legal for a body — is refused [`RefusedReason::QueueFull`] forever.
  #[must_use]
  pub const fn with_max_queued_bytes(mut self, max: usize) -> Self {
    self.max_queued_bytes = if max == 0 { 1 } else { max };
    self
  }
}

/// Why a unit or group was refused before entering consensus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RefusedReason {
  /// The aggregator queue budget (entry count or queued bytes) is full; shed load and retry once
  /// queued units pack and ship.
  #[error("the aggregator queue budget is full; retry later")]
  QueueFull,
  /// The unit can never fit ANY body: its encoded request cost exceeds the handle's submit byte
  /// limit, or one ceiling-priced reply already exceeds the reply budget.
  #[error("the unit can never fit a batch under the request/reply budgets")]
  UnitTooLarge,
  /// The group as a whole can never fit ANY body (groups are atomic — they are never split): its
  /// total encoded request cost exceeds the handle's submit byte limit, or its unit count times
  /// the ceiling-priced reply exceeds the reply budget.
  #[error("the group can never fit a batch whole under the request/reply budgets")]
  GroupTooLarge,
  /// The aggregator pump is no longer running (dropped, returned at teardown, or exited after a
  /// terminal stall), so nothing can pack or submit this unit.
  #[error("the aggregator pump is gone")]
  PumpGone,
  /// The pump declared a terminal stall while this unit was still QUEUED: it never entered any
  /// body, so it never reached consensus.
  #[error("the aggregator stalled before the unit entered a body")]
  Stalled,
  /// The driver refused the packed body without admitting it: its command channel was already
  /// closed ([`DriverError::DriverGone`] fires only from the pre-enqueue `try_send` in
  /// [`Handle::submit`], so the command never entered the driver), or — defensively, asserted
  /// unreachable — the driver returned `Busy`/`RequestTooLarge` for a body the pack had sized
  /// within [`Handle::submit_byte_limit`] under the one-in-flight discipline.
  #[error("the driver refused the packed body without admitting it")]
  DriverRefused,
}

impl RefusedReason {
  /// The stable string name of this reason (snake_case, serialization-stable).
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::QueueFull => "queue_full",
      Self::UnitTooLarge => "unit_too_large",
      Self::GroupTooLarge => "group_too_large",
      Self::PumpGone => "pump_gone",
      Self::Stalled => "stalled",
      Self::DriverRefused => "driver_refused",
    }
  }
}

/// Why a unit's outcome is unknowable: its body was handed to the driver, which may yet commit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OutcomeUnknownReason {
  /// The driver accepted the body's command but dropped its reply channel without answering
  /// ([`DriverError::ReplyDropped`], e.g. shutdown mid-flight): the request may already be
  /// replicating and MAY commit.
  #[error("the driver accepted the body but dropped its reply channel")]
  ReplyDropped,
  /// The pump declared a terminal stall while this unit's body was IN FLIGHT: the body was
  /// submitted and may commit whenever the cluster recovers.
  #[error("the aggregator stalled with the unit's body in flight")]
  Stalled,
  /// The driver surfaced an error that does not establish whether the body entered consensus;
  /// treated as unknown because claiming `Refused` falsely would license a double-apply.
  #[error("the driver failed the submit without establishing the body's fate")]
  Driver,
  /// The pump died — its `run()` future dropped — while this unit's body was IN FLIGHT: the body
  /// was already handed to the driver and may commit regardless of the pump's death.
  #[error("the pump died with the unit's body in flight")]
  PumpGone,
}

impl OutcomeUnknownReason {
  /// The stable string name of this reason (snake_case, serialization-stable).
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::ReplyDropped => "reply_dropped",
      Self::Stalled => "stalled",
      Self::Driver => "driver",
      Self::PumpGone => "pump_gone",
    }
  }
}

/// Why a COMMITTED body's reply could not be demultiplexed back to its units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplyLostReason {
  /// The committed reply body failed batch-layout validation, so no unit's result is extractable.
  #[error("the committed reply body is not a valid reply batch")]
  MalformedReply,
  /// The committed reply parsed but carries a different unit count than the request body, so no
  /// positional pairing of results to units is trustworthy.
  #[error("the committed reply's unit count does not match the request batch")]
  ReplyCountMismatch,
}

impl ReplyLostReason {
  /// The stable string name of this reason (snake_case, serialization-stable).
  #[inline(always)]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::MalformedReply => "malformed_reply",
      Self::ReplyCountMismatch => "reply_count_mismatch",
    }
  }
}

/// A batched unit's failure, classed by its RETRY CONTRACT — the class, not the reason, is what a
/// caller's retry logic may branch on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BatchError {
  /// The unit never reached consensus: it was refused before entering any submitted body (or its
  /// body never entered the driver). Resubmitting — here or on another node — is always safe.
  #[error("unit refused before reaching consensus ({reason}); safe to resubmit")]
  Refused {
    /// What refused the unit.
    reason: RefusedReason,
  },
  /// The unit's body was handed to the driver and MAY have committed; the aggregator never
  /// auto-retries it. Resubmit only behind embedder idempotency keys (exactly-once is the
  /// embedder's contract above this API).
  #[error("unit outcome unknown ({reason}); it may have committed — resubmit only idempotently")]
  OutcomeUnknown {
    /// Why the outcome is unknowable.
    reason: OutcomeUnknownReason,
  },
  /// The unit's body COMMITTED — it is durably applied — but its reply is unusable. Retrying a
  /// non-idempotent unit is a guaranteed double-apply; recover the result out of band instead.
  #[error("unit committed but its reply is unusable ({reason}); retrying double-applies")]
  CommittedReplyLost {
    /// Why the committed reply is unusable.
    reason: ReplyLostReason,
  },
}

/// The pump's half of one caller's per-unit oneshot: resolved with the unit's committed reply
/// bytes or its [`BatchError`].
type UnitReply = futures_channel::oneshot::Sender<Result<Bytes, BatchError>>;

/// One caller unit waiting to pack: its body and the oneshot resolving its caller.
struct PendingUnit {
  body: Bytes,
  reply: UnitReply,
}

/// One queued submission — a single unit or a whole atomic group — plus the queue-budget guard
/// that travels with it. The guard releases wherever the entry dies before packing (pre-pack
/// cancellation skip, stall/teardown drain, or the channel dropping it whole); on packing the pump
/// holds it until the driver's own reservation exists, then drops it (see `AggregatorPump::run`).
struct Entry {
  units: Vec<PendingUnit>,
  reservation: ReservationGuard,
}

impl Entry {
  /// True iff every caller of this entry has dropped its reply future: nothing can ever observe
  /// a result, so the entry is skipped at pack time and its work never enters consensus.
  fn fully_canceled(&self) -> bool {
    self.units.iter().all(|u| u.reply.is_canceled())
  }

  /// Consume the entry into its units' reply senders, dropping the bodies AND the queue-budget
  /// guard (this is the guard's release for an entry resolved without packing).
  fn into_replies(self) -> Vec<UnitReply> {
    self.units.into_iter().map(|u| u.reply).collect()
  }
}

/// The encoded request-body cost of packing `lens` as one batch alone: the count prefix plus each
/// unit's length prefix and bytes. `None` on overflow — over any representable budget.
fn encoded_request_len(lens: impl Iterator<Item = usize>) -> Option<usize> {
  lens.into_iter().try_fold(BATCH_COUNT_OVERHEAD, |acc, len| {
    acc.checked_add(BATCH_UNIT_OVERHEAD)?.checked_add(len)
  })
}

/// The most units one body may carry under the reply budget: admitting `n` units prices the
/// worst-case reply at `BATCH_COUNT_OVERHEAD + n * (BATCH_UNIT_OVERHEAD + max_unit_reply_len)`,
/// which must fit `max_reply_body_len()`. Zero when even one ceiling-priced reply cannot fit —
/// every submit then refuses at the handle.
fn max_units_per_body(max_unit_reply_len: usize) -> usize {
  let per_unit = max_unit_reply_len.saturating_add(BATCH_UNIT_OVERHEAD);
  viewstamp_proto::max_reply_body_len().saturating_sub(BATCH_COUNT_OVERHEAD) / per_unit
}

/// The per-body limits snapshotted at construction, shared verbatim by the [`BatchHandle`]s
/// (submit-time never-fits checks) and the pump (pack-time admission) so the two can never
/// disagree about what fits.
#[derive(Debug, Clone, Copy)]
struct BodyLimits {
  /// The request-side body budget: [`Handle::submit_byte_limit`] of the consumed handle.
  submit_limit: usize,
  /// The reply-side unit-count budget per body (see [`max_units_per_body`]).
  max_units: usize,
}

impl BodyLimits {
  /// True iff a fresh body could carry these `lens` as one atomic entry — the submit-time
  /// admission check. Everything the queue admits satisfies this, so the FIRST entry of an empty
  /// builder always fits and the pump can never wedge.
  fn admits(&self, count: usize, lens: impl Iterator<Item = usize>) -> bool {
    count <= self.max_units
      && encoded_request_len(lens).is_some_and(|needed| needed <= self.submit_limit)
  }

  /// True iff `entry` also fits the OPEN body alongside what is already packed — the pack-time
  /// admission check, atomic over the whole entry (a group packs whole or defers whole).
  fn fits_open_body(&self, builder: &BatchBuilder, packed_units: usize, entry: &Entry) -> bool {
    let extra = entry.units.iter().try_fold(0usize, |acc, u| {
      acc
        .checked_add(BATCH_UNIT_OVERHEAD)?
        .checked_add(u.body.len())
    });
    packed_units
      .checked_add(entry.units.len())
      .is_some_and(|n| n <= self.max_units)
      && extra.is_some_and(|extra| {
        builder
          .bytes_used()
          .checked_add(extra)
          .is_some_and(|needed| needed <= builder.budget())
      })
  }
}

/// A cheaply-cloneable handle submitting units to the batching aggregator. Unconditionally
/// `Send + Sync` (channel ends, the queue budget, and copied limits), independent of the pump's
/// sleep factory: any thread may submit while the pump runs wherever the embedder spawned it.
pub struct BatchHandle {
  queue: Arc<Mutex<QueueState>>,
  budget: InflightBudget,
  limits: BodyLimits,
}

/// The aggregator's ONE synchronization domain: the entry queue, the teardown flag, and the
/// pump's park waker, under a single lock. Two hazard classes shaped this:
///
/// - A channel with no close-then-drain lets a send race past a teardown drain into a dead
///   buffer — caller parked forever, guard pinned. Here the closed flag and the queue mutate
///   under ONE lock: a send either lands before the drain (which then resolves it) or observes
///   `closed` and refuses; the stranded interleaving is unrepresentable.
/// - A wake fired under a held lock deadlocks an inline-polling waker that re-enters (a retry on
///   refusal, the pump's own park). Every operation here therefore only MUTATES under the lock
///   and TAKES the waker out with it; the wake — and every oneshot resolution — fires after
///   release. No wake-capable call exists inside any lock scope, by construction.
pub(crate) struct QueueState {
  entries: VecDeque<Entry>,
  closed: bool,
  /// The pump's park waker (single consumer): registered when the pump finds the queue empty,
  /// taken — under the lock — by whichever send or teardown should wake it.
  waker: Option<core::task::Waker>,
  /// Live [`BatchHandle`] count, mutated UNDER the lock by the handles' manual `Clone`/`Drop`.
  /// This — not the queue Arc's strong count — is the pump's teardown signal: an Arc count is
  /// observed by an inline-polled pump BEFORE the dropping handle's own Arc field is released
  /// (fields drop after `Drop::drop` returns), which loses the final wakeup; this count
  /// decrements under the lock before the wake fires, so a woken pump always observes zero.
  handles: usize,
}

impl BatchHandle {
  /// Submit ONE unit and await its committed reply bytes.
  ///
  /// The unit rides some future body alongside whatever else is queued; its reply resolves when
  /// that body commits and demultiplexes. Dropping the returned future cancels the unit: before
  /// packing it never enters consensus (skipped, its queue budget released); after packing only
  /// this caller's result is discarded — body-mates are unaffected.
  ///
  /// # Errors
  /// [`BatchError::Refused`] with [`RefusedReason::UnitTooLarge`] if the unit can never fit any
  /// body (checked against limits snapshotted at construction, BEFORE touching the queue budget);
  /// [`RefusedReason::QueueFull`] if the queue budget (count or bytes) is full — shed load and
  /// retry; [`RefusedReason::PumpGone`] if the pump died before accepting the unit, or after
  /// accepting it while it was still queued or deferred (it never entered consensus). A pump
  /// dying while the unit's BODY is in flight resolves [`OutcomeUnknownReason::PumpGone`]
  /// instead — the body may commit regardless. After the body ships, the
  /// [`BatchError::OutcomeUnknown`] / [`BatchError::CommittedReplyLost`] classes per their
  /// retry contracts.
  pub async fn submit(&self, unit: Bytes) -> Result<Bytes, BatchError> {
    if !self.limits.admits(1, core::iter::once(unit.len())) {
      return Err(BatchError::Refused {
        reason: RefusedReason::UnitTooLarge,
      });
    }
    // Reserve the queue budget BEFORE enqueueing (logical Bytes::len accounting); the guard
    // travels with the entry and releases wherever the entry dies pre-pack.
    let Some(reservation) = self.budget.try_acquire(unit.len()) else {
      return Err(BatchError::Refused {
        reason: RefusedReason::QueueFull,
      });
    };
    let (reply, rx) = futures_channel::oneshot::channel();
    self.send(Entry {
      units: vec![PendingUnit { body: unit, reply }],
      reservation,
    })?;
    // Unreachable by construction: every pump death resolves observable callers explicitly
    // (queued and deferred as Refused, in-flight as OutcomeUnknown), so this oneshot always
    // carries a sent value. The conservative arm exists for the contract's sake — a false
    // refusal would license a double-apply, a false unknown only suppresses a safe retry.
    rx.await.map_err(|_| BatchError::OutcomeUnknown {
      reason: OutcomeUnknownReason::PumpGone,
    })?
  }

  /// Submit an ATOMIC group of units: all of them ride ONE body — the group is never split across
  /// consensus operations — and the replies return in unit order.
  ///
  /// An empty group is a no-op (`Ok(vec![])`): nothing to pack, nothing entered consensus.
  /// Because a body resolves as a whole, every unit of a group fails with the SAME error class
  /// when it fails at all, so the first error is the group's error. Dropping the returned future
  /// cancels the group as one entry (pre-pack: skipped whole; post-pack: only these results are
  /// discarded).
  ///
  /// # Errors
  /// [`BatchError::Refused`] with [`RefusedReason::GroupTooLarge`] if the group can never fit any
  /// body WHOLE (request bytes or ceiling-priced reply count, against the construction-time
  /// limits); otherwise exactly as [`Self::submit`].
  pub async fn submit_group(&self, units: Vec<Bytes>) -> Result<Vec<Bytes>, BatchError> {
    if units.is_empty() {
      return Ok(Vec::new());
    }
    if !self
      .limits
      .admits(units.len(), units.iter().map(Bytes::len))
    {
      return Err(BatchError::Refused {
        reason: RefusedReason::GroupTooLarge,
      });
    }
    // One queue-budget slot for the whole entry; bytes are the group's logical sum. `admits`
    // bounded the encoded sum above, so the logical sum cannot overflow.
    let logical: usize = units.iter().map(Bytes::len).sum();
    let Some(reservation) = self.budget.try_acquire(logical) else {
      return Err(BatchError::Refused {
        reason: RefusedReason::QueueFull,
      });
    };
    let mut receivers = Vec::with_capacity(units.len());
    let units = units
      .into_iter()
      .map(|body| {
        let (reply, rx) = futures_channel::oneshot::channel();
        receivers.push(rx);
        PendingUnit { body, reply }
      })
      .collect();
    self.send(Entry { units, reservation })?;
    let mut replies = Vec::with_capacity(receivers.len());
    for rx in receivers {
      // Same conservative unreachable arm as `submit`: explicit resolution everywhere makes a
      // dropped oneshot impossible; if one were ever observed, unknown is the safe reading.
      replies.push(rx.await.map_err(|_| BatchError::OutcomeUnknown {
        reason: OutcomeUnknownReason::PumpGone,
      })??);
    }
    Ok(replies)
  }

  /// Enqueue one entry, mapping the channel's refusals. A `Full` refusal is asserted unreachable:
  /// the budget reserves BEFORE the send and its count cap equals the channel bound, so every
  /// reserved entry has a channel slot. Either error drops the entry — and its guard — rolling
  /// the budget back.
  fn send(&self, entry: Entry) -> Result<(), BatchError> {
    let waker = {
      let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
      if queue.closed {
        // The pump has torn down (or is tearing down under this same lock): refuse — the entry,
        // and its guard, roll back with the early return. (The queue budget's count cap bounds
        // the queue length; no separate capacity refusal exists.)
        return Err(BatchError::Refused {
          reason: RefusedReason::PumpGone,
        });
      }
      queue.entries.push_back(entry);
      queue.waker.take()
    };
    // The wake fires OUTSIDE the lock: an inline-polling waker may immediately run the pump —
    // which takes this same lock.
    if let Some(waker) = waker {
      waker.wake();
    }
    Ok(())
  }

  /// The shared queue, for the wake-discipline assertion (a probing waker try_locks it).
  #[cfg(test)]
  pub(crate) fn queue_state(&self) -> Arc<Mutex<QueueState>> {
    Arc::clone(&self.queue)
  }

  /// The queue budget, for test assertions on reservation/release accounting.
  #[cfg(test)]
  pub(crate) fn queue_budget(&self) -> &InflightBudget {
    &self.budget
  }
}

/// The terminal-stall configuration: the per-body deadline and the factory minting each body's
/// sleep future.
struct Stall<F> {
  deadline: Duration,
  sleep: F,
}

/// The never-ready future behind [`NoStall`]. No value of it is ever constructed — a plain
/// [`aggregator`] simply has no stall armed — it exists so the placeholder factory TYPE names a
/// `Send` future and `AggregatorPump::run`'s future stays `Send` without a stall configured.
#[derive(Debug, Clone, Copy)]
pub struct NeverReady;

impl Future for NeverReady {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
    Poll::Pending
  }
}

/// The plain constructor's sleep-factory placeholder: a stateless `fn`-pointer signature (the
/// stable-Rust stand-in for a zero-sized `Fn` impl) returning the never-constructed
/// [`NeverReady`]. It satisfies `run()`'s factory bound while keeping the no-stall pump's future
/// `Send`.
pub type NoStall = fn(Duration) -> NeverReady;

/// What resolved an in-flight body: the submit itself, or the armed stall timer.
enum Verdict {
  Resolved(Result<Bytes, DriverError>),
  Stalled,
  /// Every caller of the in-flight body cancelled: no one can observe any outcome, so the pump
  /// drops the submit (the driver's cancellation reclaim releases its pending entry and budget)
  /// and tears down terminally — minting another request after abandoning this one would leave
  /// the same silent number gap a stall would.
  Abandoned,
}

/// The aggregator's run loop, holding the consumed driver [`Handle`]; the embedder spawns
/// [`Self::run`] exactly as it spawns the driver's own `run()`.
///
/// Dropping the pump — never run, or with its `run()` future cancelled — resolves every entry
/// still queued or deferred [`BatchError::Refused`] / [`RefusedReason::PumpGone`]-shaped (an
/// in-flight body's callers resolve [`OutcomeUnknownReason::PumpGone`] instead) and releases its
/// queue budget: the explicit [`Drop`] drains the queue channel (whose shared buffer otherwise
/// outlives the receiver while any [`BatchHandle`] holds a sender), and entries the dropped run
/// future held locally resolve through their dropped oneshots.
pub struct AggregatorPump<F> {
  handle: Handle,
  stall: Option<Stall<F>>,
  limits: BodyLimits,
  /// Entries popped from the channel but not yet packed (a group deferred whole when a body
  /// filled). Lives in the pump — not as a `run()` local — so a dropped run future resolves them
  /// EXPLICITLY in `Drop` as `Refused` (they never entered consensus) instead of leaving their
  /// callers to misread dropped oneshots.
  deferred: RefCell<VecDeque<Entry>>,
  /// The callers of the body currently handed to the driver, staged here for the duration of the
  /// in-flight await. Lives in the pump so a dropped run future resolves them EXPLICITLY in
  /// `Drop` as `OutcomeUnknown` — the body is already in the driver and may commit; a dropped
  /// oneshot would otherwise read as a retry-safe refusal and license a double-apply. A `Mutex`
  /// (not a `RefCell`) because the abandonment arm polls cancellation from inside the in-flight
  /// race: the closure holds a shared reference across the await, and the run future stays
  /// `Send` only over a `Sync` cell. The lock is single-task and uncontended; it never nests
  /// with the queue lock.
  in_flight: Mutex<Vec<UnitReply>>,
  /// The queue shared with every [`BatchHandle`] (see [`QueueState`]): teardown closes and
  /// drains it under its one lock; the pump parks on its waker slot.
  queue: Arc<Mutex<QueueState>>,
}

impl<F> Drop for AggregatorPump<F> {
  fn drop(&mut self) {
    // Every pump death resolves every observable caller EXPLICITLY, classified by how far its
    // work got — never by dropping oneshots (a dropped oneshot carries no classification, and
    // misreading an in-flight body as refused would license a double-apply). Runs on every pump
    // death: un-run, a cancelled `run()` future, or `run()` returning (an async fn drops its
    // locals, this pump included, as it returns) — so even an entry enqueued between a teardown
    // drain and that return resolves here instead of parking its caller.
    //
    // The in-flight body was handed to the driver and may commit regardless: unknown.
    let in_flight = core::mem::take(
      &mut *self
        .in_flight
        .lock()
        .unwrap_or_else(PoisonError::into_inner),
    );
    resolve_all(
      in_flight,
      &BatchError::OutcomeUnknown {
        reason: OutcomeUnknownReason::PumpGone,
      },
    );
    // Deferred and still-queued entries never entered consensus: refused, safe to resubmit.
    let refused = BatchError::Refused {
      reason: RefusedReason::PumpGone,
    };
    for entry in self.deferred.take() {
      resolve_all(entry.into_replies(), &refused);
    }
    // Close and collect under the queue's one lock, resolve AFTER releasing it (resolution
    // wakes receivers; no wake-capable call runs under the lock — see `QueueState`).
    let drained = {
      let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
      queue.closed = true;
      queue.waker = None;
      core::mem::take(&mut queue.entries)
    };
    for entry in drained {
      resolve_all(entry.into_replies(), &refused);
    }
  }
}

/// Split `handle` into a [`BatchHandle`] and a no-stall [`AggregatorPump`]: callers submit units
/// through the former; the embedder spawns the latter's [`AggregatorPump::run`].
///
/// CONSUMES the handle: the pump must be the handle's SOLE submitter. Its one-body-at-a-time
/// discipline is what turns queue depth into batch size, and a stranger submit interleaved on a
/// clone of the same driver's handle would compete for the driver budget the pump packs against —
/// other clones must not submit while an aggregator owns one.
///
/// Without a stall configured the pump waits on an in-flight body indefinitely (exactly as a bare
/// `Handle::submit` does); [`aggregator_with_stall`] bounds that wait.
pub fn aggregator(handle: Handle, cfg: BatchConfig) -> (BatchHandle, AggregatorPump<NoStall>) {
  split(handle, cfg, None)
}

/// [`aggregator`] plus a TERMINAL stall deadline: each submitted body races `sleep(deadline)`
/// (a fresh sleep per body, armed when the body submits). If the sleep wins, the pump declares
/// the aggregator wedged and shuts down for good — in-flight units resolve
/// [`BatchError::OutcomeUnknown`] / [`OutcomeUnknownReason::Stalled`], queued entries resolve
/// [`BatchError::Refused`] / [`RefusedReason::Stalled`] (they never entered consensus — safe to
/// resubmit elsewhere), subsequent submits refuse, and `run()` returns. The pump never mints
/// another request on that handle: abandoning body N and minting N+1 would leave a request-number
/// gap the proto deliberately ignores, silently wedging every later request.
///
/// `sleep` is any timer source (`F: Fn(Duration) -> Fut, Fut: Future<Output = ()>`); deliberately
/// NO `Send` bounds — see [`AggregatorPump::run`] for what `Send`-ness they cost.
pub fn aggregator_with_stall<F, Fut>(
  handle: Handle,
  cfg: BatchConfig,
  deadline: Duration,
  sleep: F,
) -> (BatchHandle, AggregatorPump<F>)
where
  F: Fn(Duration) -> Fut,
  Fut: Future<Output = ()>,
{
  split(handle, cfg, Some(Stall { deadline, sleep }))
}

/// The shared constructor: snapshot the per-body limits from the consumed handle + config, and
/// wire the bounded queue channel (the belt to the queue budget's braces — its bound equals the
/// budget's count cap, so a reserved entry always has a slot).
fn split<F>(
  handle: Handle,
  cfg: BatchConfig,
  stall: Option<Stall<F>>,
) -> (BatchHandle, AggregatorPump<F>) {
  let limits = BodyLimits {
    submit_limit: handle.submit_byte_limit(),
    max_units: max_units_per_body(cfg.max_unit_reply_len()),
  };
  let queue = Arc::new(Mutex::new(QueueState {
    // The queue budget's count cap (= max_queued_units, reserved before every send) is what
    // bounds this deque; no separate channel capacity exists.
    entries: VecDeque::new(),
    closed: false,
    waker: None,
    handles: 1,
  }));
  (
    BatchHandle {
      queue: Arc::clone(&queue),
      budget: InflightBudget::new(cfg.max_queued_units(), cfg.max_queued_bytes()),
      limits,
    },
    AggregatorPump {
      handle,
      stall,
      limits,
      deferred: RefCell::new(VecDeque::new()),
      in_flight: Mutex::new(Vec::new()),
      queue,
    },
  )
}

impl Clone for BatchHandle {
  fn clone(&self) -> Self {
    self
      .queue
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .handles += 1;
    Self {
      queue: Arc::clone(&self.queue),
      budget: self.budget.clone(),
      limits: self.limits,
    }
  }
}

impl Drop for BatchHandle {
  fn drop(&mut self) {
    // The decrement happens UNDER the lock, BEFORE the wake fires: a parked pump woken by the
    // final drop — even one polled inline from this very wake — observes `handles == 0` and
    // returns. Only the final drop takes the waker; earlier drops change no observation.
    let waker = {
      let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
      queue.handles -= 1;
      if queue.handles == 0 {
        queue.waker.take()
      } else {
        None
      }
    };
    if let Some(waker) = waker {
      waker.wake();
    }
  }
}

/// Resolve every unit of `units` with the same error (whole-body outcomes resolve uniformly);
/// closed receivers drop the send silently — a cancelled caller just never observes it.
fn resolve_all(units: Vec<UnitReply>, err: &BatchError) {
  for reply in units {
    let _ = reply.send(Err(err.clone()));
  }
}

/// Demultiplex a committed reply body back to its units, by position. The body committed — it is
/// durably applied — so every failure here is [`BatchError::CommittedReplyLost`], NEVER `Refused`:
/// an undecodable or miscounted reply does not un-commit the batch, and labeling it retryable
/// would license double-applies.
fn demux(units: Vec<UnitReply>, reply_body: &Bytes) {
  let view = match ReplyView::parse(reply_body) {
    Ok(view) => view,
    Err(_) => {
      resolve_all(
        units,
        &BatchError::CommittedReplyLost {
          reason: ReplyLostReason::MalformedReply,
        },
      );
      return;
    }
  };
  if view.len() != units.len() {
    resolve_all(
      units,
      &BatchError::CommittedReplyLost {
        reason: ReplyLostReason::ReplyCountMismatch,
      },
    );
    return;
  }
  for (reply, unit) in units.into_iter().zip(view.units()) {
    // Zero-copy: each unit's reply shares the committed body's backing buffer.
    let _ = reply.send(Ok(reply_body.slice_ref(unit)));
  }
}

/// Map a failed `Handle::submit` of a packed body onto the taxonomy, for every unit of that body.
fn submit_failure(err: &DriverError) -> BatchError {
  match err {
    // Fires only from the pre-enqueue `try_send` in `Handle::submit`: the command never entered
    // the driver, so nothing was minted — the body never reached consensus.
    DriverError::DriverGone => BatchError::Refused {
      reason: RefusedReason::DriverRefused,
    },
    // The driver ACCEPTED the command and then dropped the reply channel (e.g. shutdown
    // mid-flight): the request may already be replicating and may commit.
    DriverError::ReplyDropped => BatchError::OutcomeUnknown {
      reason: OutcomeUnknownReason::ReplyDropped,
    },
    // Unreachable for a packed body: the pack respected `submit_byte_limit` (so neither the size
    // check nor the byte cap can refuse) and the pump submits one body at a time against a count
    // cap of at least one. Mapped defensively as a refusal — neither error admits a command.
    DriverError::Busy | DriverError::RequestTooLarge => {
      debug_assert!(
        false,
        "a packed body respects submit_byte_limit under the one-in-flight discipline: {err}"
      );
      BatchError::Refused {
        reason: RefusedReason::DriverRefused,
      }
    }
    // A submit error this aggregator does not know cannot prove the body stayed out of
    // consensus; the conservative class is unknown, never a false `Refused`.
    _ => BatchError::OutcomeUnknown {
      reason: OutcomeUnknownReason::Driver,
    },
  }
}

impl<F, Fut> AggregatorPump<F>
where
  F: Fn(Duration) -> Fut,
  Fut: Future<Output = ()>,
{
  /// Drive the aggregator until every [`BatchHandle`] is dropped and the queue is drained (or a
  /// terminal stall fires). The embedder spawns this future exactly like the driver's own
  /// `run()`.
  ///
  /// # Send
  ///
  /// This future is `Send` iff `F: Send` AND `Fut: Send`: it owns the pump (the factory `F` rides
  /// inside) and holds each body's armed sleep `Fut` across awaits. [`BatchHandle`] is
  /// `Send + Sync` unconditionally, so a `!Send` timer source costs only where the PUMP may run,
  /// never where callers submit from.
  ///
  /// A `!Send` timer therefore cannot cross a `Send`-requiring spawner — the run future inherits
  /// the factory's locality:
  ///
  /// ```compile_fail
  /// fn requires_send<T: Send>(_: T) {}
  /// fn pin_it(
  ///   handle: viewstamp_driver::Handle,
  ///   cfg: viewstamp_driver::BatchConfig,
  ///   sleep: std::rc::Rc<()>,
  /// ) {
  ///   // The factory captures an Rc, so F is !Send — and so is run().
  ///   let (_batch, pump) = viewstamp_driver::aggregator_with_stall(
  ///     handle,
  ///     cfg,
  ///     core::time::Duration::from_secs(1),
  ///     move |_d| {
  ///       let _local = sleep.clone();
  ///       core::future::ready(())
  ///     },
  ///   );
  ///   requires_send(pump.run());
  /// }
  /// ```
  pub async fn run(self) {
    // Deferral (`self.deferred`) preserves FIFO across whole-group deferrals: packing always
    // drains it before the channel. It lives in the pump so a dropped run future resolves its
    // entries explicitly in `Drop`.
    loop {
      // THE BATCHING CLOCK, phase 1: no body is in flight. Park until at least one entry exists,
      // returning on teardown: the queue's explicit handle count reaching zero means every
      // BatchHandle has dropped — decremented under the lock before the final drop's wake fires,
      // so even an inline-polled pump observes it.
      if self.deferred.borrow().is_empty() {
        let received = poll_fn(|cx| {
          let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
          if let Some(entry) = queue.entries.pop_front() {
            return Poll::Ready(Some(entry));
          }
          if queue.closed || queue.handles == 0 {
            return Poll::Ready(None);
          }
          match &mut queue.waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            slot => *slot = Some(cx.waker().clone()),
          }
          Poll::Pending
        })
        .await;
        match received {
          Some(entry) => self.deferred.borrow_mut().push_back(entry),
          None => return,
        }
      }

      // Phase 2: pack ONE body FIFO — everything queued while the last body flew, up to the
      // first entry that does not fit (which stays queued for the next body).
      let mut builder = BatchBuilder::new(self.limits.submit_limit);
      let mut callers = Vec::new();
      let mut guards = Vec::new();
      loop {
        let popped = self.deferred.borrow_mut().pop_front().or_else(|| {
          self
            .queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .pop_front()
        });
        let entry = match popped {
          Some(entry) => entry,
          None => break,
        };
        // Pre-pack cancellation: an entry no caller can observe never enters consensus. Dropping
        // it here releases its queue-budget guard.
        if entry.fully_canceled() {
          continue;
        }
        if !self.limits.fits_open_body(&builder, callers.len(), &entry) {
          // Submit-time admission guarantees every queued entry fits an EMPTY body, so a non-fit
          // can only mean the body already has content: ship it and lead the next body with this
          // entry. The defensive arm below keeps an impossible unpackable entry from wedging the
          // pump forever.
          if builder.is_empty() {
            debug_assert!(
              false,
              "submit-time admission lets every queued entry fit an empty body"
            );
            let reason = if entry.units.len() > 1 {
              RefusedReason::GroupTooLarge
            } else {
              RefusedReason::UnitTooLarge
            };
            resolve_all(entry.into_replies(), &BatchError::Refused { reason });
            continue;
          }
          self.deferred.borrow_mut().push_front(entry);
          break;
        }
        for unit in entry.units {
          builder
            .push(&unit.body)
            .expect("fits_open_body admitted the whole entry");
          callers.push(unit.reply);
        }
        guards.push(entry.reservation);
      }
      if callers.is_empty() {
        // Everything popped was cancelled; nothing to ship.
        continue;
      }
      let body = builder
        .finish()
        .expect("a packed body holds at least one unit");

      // Phase 3: submit the body — the ONE in-flight submit — and resolve it.
      let mut submit = pin!(self.handle.submit(body));
      // Stage the body's callers in the pump for the in-flight window: from here until the
      // verdict, a dropped run future must resolve them OutcomeUnknown in `Drop` (the body is in
      // — or about to be handed to — the driver and may commit), never leave them to read their
      // dropped oneshots as a refusal.
      *self
        .in_flight
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = callers;
      // First poll: `Handle::submit` runs synchronously up to its reply await, so after this poll
      // the driver's OWN reservation (or its outright refusal) exists. Only now do the queue
      // guards drop — the handoff is reserve-then-release, never under-counted.
      let early = poll_fn(|cx| {
        Poll::Ready(match submit.as_mut().poll(cx) {
          Poll::Ready(result) => Some(result),
          Poll::Pending => None,
        })
      })
      .await;
      drop(guards);
      let verdict = match early {
        Some(result) => Verdict::Resolved(result),
        None => {
          // Arm a fresh stall timer now the body is in flight (none configured = no timer: the
          // race below can only resolve on the submit).
          let mut sleep = pin!(self.stall.as_ref().map(|s| (s.sleep)(s.deadline)));
          poll_fn(|cx| {
            // The submit polls FIRST: a submit and a timer ready on the same wake resolve as a
            // completed body — an about-to-fire timer never discards an answered request.
            if let Poll::Ready(result) = submit.as_mut().poll(cx) {
              return Poll::Ready(Verdict::Resolved(result));
            }
            if let Some(timer) = sleep.as_mut().as_pin_mut()
              && timer.poll(cx).is_ready()
            {
              return Poll::Ready(Verdict::Stalled);
            }
            // Abandonment: when EVERY staged caller has cancelled, nobody can observe any
            // outcome — and only this arm can free the driver's pending entry, since the driver
            // sees the AGGREGATOR as the live caller, not the units. `poll_canceled` registers
            // this task for each receiver's drop, so the last cancellation wakes the race.
            {
              let mut staged = self
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
              if !staged.is_empty()
                && staged
                  .iter_mut()
                  .all(|reply| matches!(reply.poll_canceled(cx), Poll::Ready(())))
              {
                return Poll::Ready(Verdict::Abandoned);
              }
            }
            Poll::Pending
          })
          .await
        }
      };

      // The in-flight window is over: reclaim the callers for explicit resolution below.
      let callers = core::mem::take(
        &mut *self
          .in_flight
          .lock()
          .unwrap_or_else(PoisonError::into_inner),
      );
      match verdict {
        Verdict::Resolved(Ok(reply_body)) => demux(callers, &reply_body),
        Verdict::Resolved(Err(err)) => resolve_all(callers, &submit_failure(&err)),
        Verdict::Stalled => {
          // TERMINAL: the in-flight body may commit whenever the cluster recovers — unknown for
          // its units — while queued entries never entered consensus and may be resubmitted
          // elsewhere. The pump then exits WITHOUT minting another request on this handle:
          // abandoning body N and minting N+1 would leave a request-number gap the proto
          // ignores, wedging every later request silently.
          resolve_all(
            callers,
            &BatchError::OutcomeUnknown {
              reason: OutcomeUnknownReason::Stalled,
            },
          );
          let stalled = BatchError::Refused {
            reason: RefusedReason::Stalled,
          };
          for entry in self.deferred.take() {
            resolve_all(entry.into_replies(), &stalled);
          }
          // Close-then-drain under the shared gate (see `Drop`): a send racing this drain either
          // landed before it (drained as Stalled below) or observes `closed` and refuses. The
          // drain only COLLECTS under the lock — resolution wakes receivers, and nothing
          // wake-capable runs under the gate (a re-entrant waker retrying a submit would
          // deadlock the non-reentrant mutex).
          let mut drained = Vec::new();
          {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.closed = true;
            queue.waker = None;
            drained.extend(queue.entries.drain(..));
          }
          for entry in drained {
            resolve_all(entry.into_replies(), &stalled);
          }
          return;
        }
        Verdict::Abandoned => {
          // TERMINAL: every caller of the in-flight body cancelled, so no outcome is observable
          // by anyone. Dropping the submit (with the loop scope) is what lets the driver's
          // cancellation reclaim release the pending entry and its budget — the driver sees the
          // PUMP as the live caller, never the units. The pump then exits without minting
          // another request on this handle: the abandoned body's number may never have reached
          // the primary, and minting past it would leave the silent gap that wedges every later
          // request. `callers` (all cancelled) drop unobserved.
          drop(callers);
          let refused = BatchError::Refused {
            reason: RefusedReason::PumpGone,
          };
          for entry in self.deferred.take() {
            resolve_all(entry.into_replies(), &refused);
          }
          // Close-then-drain under the queue's lock; resolve after release (see `Drop`).
          let mut drained = Vec::new();
          {
            let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            queue.closed = true;
            queue.waker = None;
            drained.extend(queue.entries.drain(..));
          }
          for entry in drained {
            resolve_all(entry.into_replies(), &refused);
          }
          return;
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
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
  use viewstamp_proto::{BatchView, ReplyBuilder};

  use super::{
    BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchConfig, BatchError, BatchHandle,
    OutcomeUnknownReason, RefusedReason, ReplyLostReason, aggregator, aggregator_with_stall,
  };
  use crate::{
    Command, Handle,
    session::{InflightBudget, MAX_INFLIGHT, MAX_PENDING_BYTES},
  };

  /// The test's driver end: it owns the command receiver and plays the driver, decoding each
  /// submitted body and answering its reply oneshot.
  struct TestDriver {
    commands: futures_channel::mpsc::Receiver<Command>,
    _events: flume::Sender<viewstamp_proto::Event>,
  }

  impl TestDriver {
    /// The next submitted body: its raw bytes, decoded units, and the reply sender to answer.
    fn next_body(&mut self) -> (Bytes, Vec<Vec<u8>>, futures_channel::oneshot::Sender<Bytes>) {
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
  fn reply_for(units: &[&[u8]]) -> Bytes {
    let mut builder = ReplyBuilder::new(viewstamp_proto::max_reply_body_len(), usize::MAX);
    for unit in units {
      builder.push(unit).expect("test replies fit the budget");
    }
    builder.finish().expect("non-empty")
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
      .send(Bytes::from_static(b"\x00\x00"))
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
    let (batch, _pump) = aggregator(handle, BatchConfig::new(64).with_max_queued_bytes(10));

    let s1 = batch.submit(Bytes::from(vec![1u8; 8]));
    pin_mut!(s1);
    assert!(poll_once(&mut s1).is_pending());
    assert_eq!(batch.queue_budget().bytes(), 8);

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
      8,
      "no retained growth past the cap"
    );

    // Capacity returns once the queued entry leaves (here: refused submits keep failing until
    // then, proving the cap binds on live entries, not on a leaked high-water mark).
    let s3 = batch.submit(Bytes::from(vec![3u8; 2]));
    pin_mut!(s3);
    assert!(
      poll_once(&mut s3).is_pending(),
      "an entry within the remaining capacity is admitted"
    );
    assert_eq!(batch.queue_budget().bytes(), 10, "the cap is byte-exact");
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
      .send(rb.finish().expect("a unit was pushed"))
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

  /// Submits racing pump teardown from other threads can never strand: flume has no
  /// close-then-drain, so without the shared gate a send slipping past the Drop drain's final
  /// `try_recv` would park its caller forever on an entry no one can observe and pin its queue
  /// budget. Under the gate every racer either lands before the drain (resolved `Refused` by it)
  /// or observes the closed gate (refused at send) — so every submit RESOLVES and the budget
  /// drains to zero. The threads hammer the window; the join is the no-strand witness.
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
                // block on teardown's gate or strand.
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
}

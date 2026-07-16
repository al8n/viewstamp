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

/// Default cap on queued units. Mirrors the driver's in-flight submit count cap
/// (`MAX_INFLIGHT`): 4096 waiting units is far more concurrency than one aggregator
/// feeds a single client session, yet each queued unit costs only its `Bytes` handle, oneshot,
/// and budget share. Every UNIT counts — a group charges one slot per member, since each retains
/// its own reply channel and per-unit state. Past the cap a submit returns
/// [`BatchError::Refused`] / [`RefusedReason::QueueFull`]. Tunable via
/// [`BatchConfig::with_max_queued_units`].
pub const DEFAULT_MAX_QUEUED_UNITS: usize = 4096;

/// Default cap on total queued unit bytes, charged at each unit's ENCODED cost: its logical
/// [`Bytes::len`] plus the codec's per-unit framing ([`BATCH_UNIT_OVERHEAD`]) — so even
/// zero-length units pay for the queue state they retain, and a flood of tiny units cannot ride
/// under the byte axis. (A `Bytes` sliced from a larger allocation still retains that backing
/// while queued — the caller's choice, identical to handing the same slice to `Handle::submit`.)
/// Mirrors the driver's in-flight byte cap (`MAX_PENDING_BYTES`, 128 MiB): far above any
/// realistic waiting working set — about eight maximal request bodies — yet a hard bound a
/// flooding caller cannot exceed. Past the cap a submit returns [`BatchError::Refused`] /
/// [`RefusedReason::QueueFull`]. Tunable via [`BatchConfig::with_max_queued_bytes`].
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 128 * 1024 * 1024;

/// Tunable aggregator parameters. Unlike [`crate::DriverConfig`] there is no zero-argument
/// default: the per-unit reply ceiling is the embedder's contract with its state machine — any
/// default would silently misprice reply budgets — so [`BatchConfig::new`] requires it, and only
/// the queue caps carry defaults (each default constant documents its sizing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchConfig {
  /// Count cap on queued units (the queue budget's first axis).
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
      max_queued_units: DEFAULT_MAX_QUEUED_UNITS,
      max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
      max_unit_reply_len,
    }
  }

  /// Count cap on queued units; a submit past it returns [`BatchError::Refused`] /
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

  /// Override the queued-unit count cap (clamped to at least 1 so an idle aggregator can always
  /// admit one lone unit).
  #[must_use]
  pub const fn with_max_queued_units(mut self, max: usize) -> Self {
    self.set_max_queued_units(max);
    self
  }

  /// In-place form of [`Self::with_max_queued_units`] — same clamp, chainable.
  pub const fn set_max_queued_units(&mut self, max: usize) -> &mut Self {
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
    self.set_max_queued_bytes(max);
    self
  }

  /// In-place form of [`Self::with_max_queued_bytes`] — same clamp, chainable.
  pub const fn set_max_queued_bytes(&mut self, max: usize) -> &mut Self {
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, derive_more::IsVariant)]
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
/// cancellation skip, or the stall/teardown drains); on packing the pump
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
/// `Send + Sync` (the shared queue `Arc`, the queue budget, and copied limits), independent of the pump's
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
    // Reserve the queue budget BEFORE enqueueing, charging the unit's ENCODED cost — its bytes
    // plus the codec's per-unit framing — so even a zero-length unit pays for the queue state it
    // retains. The guard travels with the entry and releases wherever the entry dies pre-pack.
    let Some(reservation) = self.budget.try_acquire(BATCH_UNIT_OVERHEAD + unit.len()) else {
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
    // One queue-budget slot PER UNIT and the group's ENCODED byte sum (payload plus per-unit
    // framing): a group retains per-unit channel state and per-unit encoded cost, so both caps
    // must see every unit — a flood of tiny or empty units inside few groups would otherwise
    // bypass the advertised bounds. `admits` bounded the encoded sum above, so it cannot
    // overflow.
    let encoded: usize = units
      .iter()
      .map(|unit| BATCH_UNIT_OVERHEAD + unit.len())
      .sum();
    let Some(reservation) = self.budget.try_acquire_many(units.len(), encoded) else {
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

  /// Enqueue one entry under the queue lock, refusing [`RefusedReason::PumpGone`] once the queue
  /// is closed; the refusal drops the entry — and its guard — rolling the budget back.
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
/// queue budget: the explicit [`Drop`] closes the shared queue under its lock and resolves
/// everything it drains (the queue outlives the pump while any [`BatchHandle`] holds the `Arc`),
/// and the deferred and in-flight entries live in the pump itself, so the same [`Drop`] resolves
/// them too.
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
/// share the queue state between handle and pump (the deque is bounded by the queue budget's
/// count cap alone — every entry reserves before it enqueues).
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
    // A live self-removal retired the node. If the body was already in flight when the node was
    // removed it may have replicated to the surviving quorum and committed BEFORE removal, so its
    // fate is genuinely unknowable — the conservative class is unknown, never a false `Refused` that
    // would license a double-apply.
    DriverError::Retired { .. } => BatchError::OutcomeUnknown {
      reason: OutcomeUnknownReason::Driver,
    },
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
    // drains it before the shared queue. It lives in the pump so a dropped run future resolves its
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
          // Close-then-drain under the queue lock (see `Drop`): a send racing this drain either
          // landed before it (drained as Stalled below) or observes `closed` and refuses. The
          // drain only COLLECTS under the lock — resolution wakes receivers, and nothing
          // wake-capable runs under the lock (a re-entrant waker retrying a submit would
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
mod tests;

//! Shared session state for both drivers, and the driver MEMORY MODEL.
//!
//! Both the QUIC and stream drivers retain a small fixed set of channels and maps. Each is
//! EXPLICITLY bounded so a partitioned/slow cluster, a flooding peer, or a caller that submits
//! faster than the cluster commits cannot grow the driver's memory without bound. The shared
//! inventory (a driver crate documents any channels of its own beside their cap constants):
//!
//! | retained state            | bound                                                              |
//! |---------------------------|--------------------------------------------------------------------|
//! | `pending` submit map      | [`MAX_INFLIGHT`] entries AND [`MAX_PENDING_BYTES`] of request body  |
//! | command channel           | `max_inflight + 1` buffered [`crate::Command`]s, + one in-flight per live sender (bounded; `try_send`) |
//! | events channel            | [`EVENTS_CAP`] (bounded best-effort; dropped-on-full)              |
//! | stream inbound channel    | `INBOUND_CAP` frames (bounded; bridge `send_async` backpressure)    |
//! | per-conn out-queue        | `max_outbound_backlog` + one wire chunk (byte-bounded on enqueue)   |
//! | `conns` connection table  | `max_conns` live connections (accept admission control)            |
//! | dial-ready channel        | live dial count, itself bounded by `max_conns`                     |
//! | storage-ready channel     | drained-to-empty every loop iteration; carries a unit signal only  |
//!
//! The submit-budget row is the one this module owns ([`InflightBudget`]); the rest are bounded at
//! their construction sites in the two drivers and cross-referenced here. The budget is the artifact
//! that closes the submit path: a `Submit` RESERVES against the budget before it is sent, so a caller
//! cannot enqueue commands or mint `pending` entries past the cap — it gets [`crate::DriverError::Busy`]
//! instead of growing memory.
//!
//! The bound VALUES here are the DEFAULTS: each is the corresponding [`crate::DriverConfig`] knob's
//! `Default`, and an embedder overrides them through the drivers' `with_config` constructors. Every
//! bound stays a bound at any setting — only its size is tunable.

use std::{
  collections::HashMap,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Duration,
};

use bytes::Bytes;
use viewstamp_proto::{
  BlockStore, ClientId, Config, Endpoint, Event, Instant, Membership, Recovered, Request,
  RequestNumber, SingleChange, StateMachine, Superblock, VsrState, Wal,
};

use crate::DriverError;

/// Construct a driver's consensus endpoint from its durable store — recover-or-new, decided by
/// INSPECTING the store rather than by an embedder flag.
///
/// # Errors
///
/// [`DriverError::Retired`] when the recover path resolves THIS node to no slot in the durable
/// root's membership — a reconfiguration removed it (the `Endpoint::recover` →
/// [`Recovered::Retired`](viewstamp_proto::Recovered) outcome). A retired node cannot run a replica
/// loop, so the driver refuses to start rather than booting a node the cluster has dropped. The
/// genesis-boot path never returns this (a fresh node is in its own genesis membership).
///
/// A genesis store — the fresh-cluster durable root ([`VsrState::new`]) AND an empty WAL — boots a
/// fresh endpoint (`Endpoint::new`: `Normal`, view 0). ANY durable state instead reconstructs the
/// endpoint via `Endpoint::recover`: it resumes the durable view in `Recovering` status and
/// re-verifies its WAL tail through the driver's ordinary pumps (`handle_storage` routes the
/// recovery read completions, `handle_timeout` drives the recover-retry timer, `handle_message`
/// the peer solicitation), so the run loops need no recovery special-casing. Inspecting the store
/// is what makes the choice structural: restarting a node over a dirty store can never silently
/// boot a fresh view-0 endpoint — the VSR amnesia hazard, where a replica that forgets its durable
/// view/log re-votes across a view change and committed state can diverge.
///
/// The seed feeds the endpoint's freshness nonces (`Recovery`/`GetView`). A recovery nonce MUST
/// differ per incarnation — a restarted replica that re-used its predecessor's nonce could adopt a
/// stale `RecoveryResponse` addressed to that prior incarnation — so the per-replica id is mixed
/// with wall-clock nanos captured here: every construction is a distinct incarnation by
/// derivation, not by an embedder-supplied value that could repeat.
///
/// Construction is also the natural `OpId` drain point (the lifetime contract on
/// [`viewstamp_proto::OpId`]): each call pairs ONE fresh endpoint with the storage handles the
/// driver takes ownership of, and the driver never rebuilds an endpoint over live handles — so no
/// completion this driver polls can predate its endpoint, PROVIDED the handles carry no in-flight
/// ops from a previous incarnation (the drivers' constructor-level storage contract; a real crash
/// satisfies it by construction because in-flight ops die with the process).
pub fn build_endpoint<S, W, B>(
  config: Config,
  membership: Membership,
  sm: S,
  wal: &mut W,
  sb: &mut B,
  blocks: &mut dyn BlockStore,
) -> Result<Endpoint<S, SingleChange>, DriverError>
where
  S: StateMachine,
  W: Wal,
  B: Superblock,
{
  // Wall-clock nanos make the seed (hence the nonces) fresh per incarnation; the node's stable
  // `MemberId` keeps replicas constructed in the same instant (a test cluster) on distinct seeds,
  // rotated into the high bits so it does not collide with the fast-moving low nano bits. The
  // truncation keeps the low 64 bits — exactly the fast-moving ones.
  let wall = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_or(0, |d| d.as_nanos() as u64);
  let seed = wall ^ ((config.local().get() as u64).wrapping_add(1)).rotate_left(48);
  if sb.state() == VsrState::new() && wal.op_head().get() == 0 {
    // `SingleChange` is a zero-sized PhantomData witness with no runtime representation; the driver
    // always carries the capability so the coordinators can call `propose_membership` without the
    // embedder opting in per-instance. The bytes are identical to a `RestartOnly` endpoint.
    Ok(Endpoint::<S, SingleChange>::with_reconfig(
      config, membership, seed, sm,
    ))
  } else {
    // The recover path resolves THIS node against the DURABLE root's membership: a v4 root that no
    // longer lists it (an offline reconfiguration removed it) yields `Recovered::Retired`, which the
    // driver surfaces as a hard error — a retired node has no replica loop to run.
    match Endpoint::<S, SingleChange>::recover_with_reconfig(
      config, membership, seed, sm, wal, sb, blocks,
    ) {
      Recovered::Active(endpoint) => Ok(endpoint),
      Recovered::Retired(retired) => Err(DriverError::Retired {
        local: retired.local(),
        epoch: retired.epoch(),
      }),
    }
  }
}

/// Default for how long a submitted-but-uncommitted request waits before the driver re-broadcasts
/// it (the proto session table dedups). Shared by both the QUIC and stream drivers; tunable via
/// `DriverConfig::with_request_timeout` (a geo-replicated cluster whose commit latency nears 250 ms
/// raises it so steady-state submits are not re-broadcast spuriously).
pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);

/// Ceiling on the interval between in-flight `pending` scans ([`reap_and_collect_retransmits`]).
/// The scan is O(in-flight) — a cancelled-check plus duration math per entry — and the drivers'
/// run loops would otherwise pay it on EVERY wake, making it the one per-message O(in-flight)
/// cost under a full session at per-datagram wake rates. Both of the scan's jobs tolerate ~25 ms
/// of staleness instead: retransmission runs on the 250 ms default [`REQUEST_TIMEOUT`] cadence
/// (a scan up to 25 ms late defers a re-broadcast by at most a tenth of that cadence), and
/// cancellation reclaim only has to free a dropped submit's entry + budget promptly — a caller
/// retrying after `Busy` cannot distinguish a slot freed now from one freed tens of milliseconds
/// later.
pub(crate) const PENDING_SCAN_MAX_INTERVAL: Duration = Duration::from_millis(25);

/// The re-arm interval of the drivers' deadline-gated `pending` scan, for a driver configured
/// with `request_timeout`: an eighth of the timeout, capped at `PENDING_SCAN_MAX_INTERVAL`.
/// The `/ 8` keeps the gate proportional when an embedder configures a far smaller timeout (each
/// entry's staleness is still sampled ~8x per timeout window, so a due retransmit fires within
/// ~12.5% of its cadence); the cap keeps a LARGER configured timeout from slowing cancellation
/// reclaim below the default cadence.
pub fn pending_scan_interval(request_timeout: Duration) -> Duration {
  // Floored at 1ms: a zero or near-zero configured timeout must not produce a zero interval,
  // which — folded into the wake deadline while work is pending — would wake-scan-rearm without
  // ever parking the shared thread.
  (request_timeout / 8)
    .min(PENDING_SCAN_MAX_INTERVAL)
    .max(Duration::from_millis(1))
}

/// Default maximum number of submitted-but-not-yet-resolved client requests the node-local session
/// holds in flight at once, shared by both drivers. Each in-flight submit retains a `pending` entry
/// (its request body + reply oneshot) until its commit arrives, so without a count cap a partitioned
/// or slow cluster (commits never arrive) or a caller that submits in a tight loop would grow
/// `pending` — and the per-tick `retransmit_stale` clone of every entry — without bound. 4096 is
/// generous: a well-behaved client keeps only a handful of requests in flight, and 4096 distinct
/// in-flight requests is far more concurrency than a single node-local session needs, yet small
/// enough that the entry overhead (a key, a `Bytes` handle, a oneshot) is negligible. Past the cap a
/// submit returns [`crate::DriverError::Busy`] rather than enqueueing unboundedly. Tunable via
/// `DriverConfig::with_max_inflight`.
pub const MAX_INFLIGHT: usize = 4096;

/// Default maximum total request-body bytes across all in-flight submits, shared by both drivers.
/// Bounds the retained request payloads independently of the count cap so a smaller number of LARGE
/// requests cannot grow memory without bound. 128 MiB MUST be (and is) >= the proto's 16 MiB maximum
/// frame length, so a single maximal request always fits the budget on an empty session — the byte
/// cap can never wedge a legitimate lone request, it only bounds aggregate accumulation. 128 MiB is
/// a sensible ceiling for retained client-request bodies on one node: well above any realistic
/// in-flight working set, yet a hard bound an adversarial or buggy caller cannot exceed. Past the
/// cap a submit returns [`crate::DriverError::Busy`]. Tunable via
/// `DriverConfig::with_max_pending_bytes` (keep the >=-one-max-frame property when lowering it).
pub const MAX_PENDING_BYTES: usize = 128 * 1024 * 1024;

/// Default best-effort capacity of the event observation channel (driver ->
/// [`crate::Handle`]), shared by both drivers. Bounds the retained events to `EVENTS_CAP`
/// so an application that submits but never drains `Handle::events()` cannot grow the channel
/// without bound — the observation stream is dropped-on-full, not buffered forever. 1024 is a
/// generous default: a consumer that keeps up never sees a drop, and the RELIABLE delivery path
/// (the per-`submit` oneshot, answered in [`deliver_event`]) is unaffected by this cap. Tunable via `DriverConfig::with_events_cap`.
pub const EVENTS_CAP: usize = 1024;

/// The shared in-flight submit budget: a cheaply-cloneable handle bounding the submitted-but-not-yet-
/// resolved requests by BOTH a count and a byte total (the configured `max_inflight` /
/// `max_pending_bytes`, default [`MAX_INFLIGHT`] / [`MAX_PENDING_BYTES`]). One
/// clone lives in the [`crate::Handle`] (which RESERVES synchronously before sending a `Submit`) and
/// one in the driver. Each reservation is owned by a [`ReservationGuard`] whose `Drop` releases it, so
/// the budget is freed exactly once wherever the reservation finally dies — carried in the queued
/// `Command::Submit`, then moved into the [`Pending`] entry. The invariant: `count` == the number of
/// live guards and `bytes` == the sum of their reserved body lengths, at all times — never leaked,
/// never double-released.
///
/// Cloning is O(1): two `Arc` bumps plus two copied cap words. Both counters use
/// [`Ordering::Relaxed`] — they are independent
/// monotonic-ish budgets, not a lock guarding other state, so only their own atomicity matters; a
/// reserve uses fetch-add-then-check-then-rollback so concurrent `Handle` clones can momentarily
/// observe an over-cap total but never COMMIT one (each rolls its own add back).
#[derive(Clone, Debug)]
pub struct InflightBudget {
  count: Arc<AtomicUsize>,
  bytes: Arc<AtomicUsize>,
  /// The count cap this budget enforces (immutable after construction, copied into every clone).
  max_count: usize,
  /// The byte cap this budget enforces (immutable after construction, copied into every clone).
  max_bytes: usize,
}

impl InflightBudget {
  /// A fresh budget with nothing reserved, enforcing the given count/byte caps (the driver passes
  /// its `DriverConfig`'s `max_inflight` / `max_pending_bytes`).
  pub fn new(max_count: usize, max_bytes: usize) -> Self {
    Self {
      count: Arc::new(AtomicUsize::new(0)),
      bytes: Arc::new(AtomicUsize::new(0)),
      max_count,
      max_bytes,
    }
  }

  /// Try to reserve ONE in-flight slot of `body_len` bytes, returning an owning [`ReservationGuard`] on
  /// success or `None` when either cap is already full. Atomically adds to both counters, then checks
  /// both caps; if EITHER now exceeds its cap, rolls BOTH adds back and returns `None` (the caller must
  /// not proceed). On success the returned guard owns exactly one release, performed on its `Drop`.
  ///
  /// Fetch-add-then-check-then-rollback (not check-then-add) is what makes this safe under concurrent
  /// `Handle` clones: two reservers cannot both read room and both commit past the cap, because each
  /// reserves first and only keeps the reservation if the post-add total is within cap.
  pub(crate) fn try_acquire(&self, body_len: usize) -> Option<ReservationGuard> {
    self.try_acquire_many(1, body_len)
  }

  /// As [`Self::try_acquire`] but reserving `count` slots at once (an aggregator group charges
  /// one slot per unit); the returned guard releases exactly what it reserved.
  pub(crate) fn try_acquire_many(&self, count: usize, body_len: usize) -> Option<ReservationGuard> {
    let new_count = self.count.fetch_add(count, Ordering::Relaxed) + count;
    let new_bytes = self.bytes.fetch_add(body_len, Ordering::Relaxed) + body_len;
    if new_count > self.max_count || new_bytes > self.max_bytes {
      self.count.fetch_sub(count, Ordering::Relaxed);
      self.bytes.fetch_sub(body_len, Ordering::Relaxed);
      return None;
    }
    Some(ReservationGuard {
      budget: self.clone(),
      count,
      bytes: body_len,
    })
  }

  /// Release `count` in-flight slots of `body_len` bytes, reversing exactly one prior reservation. Private:
  /// the ONLY caller is [`ReservationGuard::drop`], so a reservation is released exactly once, by the
  /// guard that owns it, no matter where that guard finally dies.
  fn release(&self, count: usize, body_len: usize) {
    self.count.fetch_sub(count, Ordering::Relaxed);
    self.bytes.fetch_sub(body_len, Ordering::Relaxed);
  }

  /// The current count of reserved in-flight slots (test/observability).
  pub fn count(&self) -> usize {
    self.count.load(Ordering::Relaxed)
  }

  /// The current reserved byte total (test/observability).
  pub fn bytes(&self) -> usize {
    self.bytes.load(Ordering::Relaxed)
  }

  /// The count cap this budget enforces (immutable after construction).
  pub const fn max_count(&self) -> usize {
    self.max_count
  }

  /// The byte cap this budget enforces (immutable after construction). This is the binding bound
  /// on a single submit's body: a body longer than this can never reserve, so anything packing
  /// bodies for [`crate::Handle::submit`] must size them against it (see
  /// [`crate::Handle::submit_byte_limit`]).
  pub const fn max_bytes(&self) -> usize {
    self.max_bytes
  }
}

/// An owning RAII handle to ONE [`InflightBudget`] reservation: it holds a budget clone plus the
/// reserved slot count and body length, and its [`Drop`] releases exactly that reservation
/// (count + bytes). It is the SINGLE
/// owner of its reservation, so the budget is freed exactly once wherever the guard finally dies and
/// no manual release is needed at any submit-exit site:
///
/// - A successful [`crate::Handle::submit`] reservation produces a guard and moves it into the
///   `Command::Submit` it enqueues. If the `try_send` fails (channel refuses → `Busy`, closed →
///   `DriverGone`) the un-sent `Command` — and so its guard — drops on the early return, releasing the
///   slot: an un-sent submit cannot leak.
/// - When the driver drains a `Submit` into `pending`, the guard MOVES into the [`Pending`] entry. The
///   reservation then lives with the entry: dropping the entry on commit, on cancellation reclaim, or
///   on shutdown drain drops the guard, which releases.
/// - A `Submit` still queued in the command channel when the driver tears down is dropped by the
///   teardown's close-then-drain of that channel (or by the receiver's own draining drop), its guard
///   with it, so a submit racing shutdown before it reaches `pending` cannot leak budget — and cannot
///   outlive the shutdown ack behind a surviving `Handle` clone.
///
/// There is no disarm/forget path in use, so a guard ALWAYS releases on drop — the budget tracks live
/// reservations exactly and can neither leak nor double-release.
///
/// `pub` (with no public constructor or accessor — it is minted only by the crate-private
/// `InflightBudget::try_acquire`) solely because it rides the public [`crate::Command::Submit`]: an
/// opaque token the driver moves into a [`Pending`] entry, never inspected by an embedder.
#[derive(Debug)]
pub struct ReservationGuard {
  budget: InflightBudget,
  count: usize,
  bytes: usize,
}

impl Drop for ReservationGuard {
  fn drop(&mut self) {
    self.budget.release(self.count, self.bytes);
  }
}

/// A submitted-but-not-yet-committed client request: its reply channel, the request value to
/// retransmit, when it was last (re)broadcast, and the owning [`ReservationGuard`] for its
/// [`InflightBudget`] slot. The guard lives HERE for the entry's whole life, so dropping the entry —
/// on commit, on cancellation reclaim, or on shutdown drain — releases its budget exactly once with no
/// explicit release call at any of those sites.
pub struct Pending {
  pub reply: futures_channel::oneshot::Sender<Bytes>,
  pub request: Request,
  pub last_sent: Instant,
  /// Owns this entry's budget reservation; its `Drop` releases the slot when the entry is removed.
  pub reservation: ReservationGuard,
}

/// The node-local client session map: `(client, request) -> Pending`.
pub type PendingMap = HashMap<(ClientId, RequestNumber), Pending>;

/// Drop every entry remaining in `pending`, then clear the map. The driver's shutdown/teardown site:
/// any submit still in flight at shutdown (its commit never arrived) frees its reservation as its
/// [`Pending`] is dropped here (the guard's `Drop`), so the budget returns to zero and never leaks
/// across a driver's lifetime. The dropped reply oneshots surface [`crate::DriverError::ReplyDropped`]
/// to any still-waiting `submit`.
pub fn drain_pending(pending: &mut PendingMap) {
  pending.clear();
}

/// Reap cancelled submits, then collect the requests due for retransmission. Shared by both drivers'
/// `retransmit_stale`, which deadline-gates this walk to the [`pending_scan_interval`] cadence (the
/// walk is O(in-flight); the gate's staleness budget is documented on
/// `PENDING_SCAN_MAX_INTERVAL`). Two responsibilities, in one pass over `pending`:
///
/// 1. CANCELLATION RECLAIM. A submit whose returned reply future (the `oneshot::Receiver`) has been
///    dropped is cancelled: its `p.reply` sender reports [`futures_channel::oneshot::Sender::is_canceled`].
///    Such an entry can never be observed by any caller, so it is REMOVED here, within a retransmit
///    tick; dropping the removed [`Pending`] drops its [`ReservationGuard`], freeing the
///    [`InflightBudget`] slot — so a cancelled submit's memory + budget are reclaimed promptly instead
///    of being pinned until its commit arrives (or forever if it never does).
/// 2. RETRANSMIT. Of the entries that survive, those not committed within `request_timeout` (the
///    driver's configured value; default [`REQUEST_TIMEOUT`]) are re-broadcast (the proto session
///    table dedups). Their `last_sent` is stamped to `now` and the request cloned out for the caller
///    to submit to the coordinator.
///
/// Returns the requests to re-broadcast; the caller feeds each to its coordinator's
/// `submit_client_request` (kept out of here so this stays storage/coordinator-agnostic).
pub fn reap_and_collect_retransmits(
  pending: &mut PendingMap,
  now: Instant,
  request_timeout: Duration,
) -> Vec<Request> {
  let mut stale = Vec::new();
  pending.retain(|_, p| {
    if p.reply.is_canceled() {
      return false; // cancelled by the caller: dropping the entry releases its budget guard
    }
    if now.saturating_duration_since(p.last_sent) >= request_timeout {
      p.last_sent = now;
      stale.push(p.request.clone());
    }
    true
  });
  stale
}

/// Match a committed event to a pending submit (answering its reply channel) and forward EVERY
/// event — committed or otherwise — to the event subscription. Shared by both the QUIC and stream
/// drivers.
///
/// On a matching commit the entry is REMOVED — WHETHER OR NOT the reply receiver is still alive (a
/// cancelled submit whose commit then arrives must still leave the map; the dropped `send` is
/// harmless). The removed entry's [`ReservationGuard`] is then dropped (explicitly, below), freeing the
/// [`InflightBudget`] slot. This is the commit release site; together with caller-cancellation reclaim
/// (`retransmit_stale`) and shutdown drain ([`drain_pending`]) it covers every path a `pending` entry
/// leaves in flight, so the budget never leaks.
///
/// NON-Committed events (`ViewChanged`/`StatusChanged`/state-sync/repair/checkpoint observability)
/// have no pending submit to answer: they flow to the embedder channel UNTOUCHED. The wildcard arm is
/// deliberate (the proto `Event` is `#[non_exhaustive]`): any future variant forwards as observability
/// by default rather than being silently swallowed.
///
/// Two delivery paths with different guarantees:
/// - The per-`submit` oneshot (`p.reply`) is the RELIABLE path: the matching submit always receives
///   its committed reply, independent of any pressure on the events channel.
/// - The events channel (`events`) is BEST-EFFORT observability. It is bounded
///   ([`EVENTS_CAP`]), so the `try_send` here DROPS the event when the channel is full — i.e. when an
///   application holds a `Handle::events()` receiver but does not drain it fast enough. Dropping
///   (rather than buffering forever) is what keeps the channel from growing without bound under a
///   slow/absent consumer — the non-Committed variants add only transition-cadence volume (per view
///   change / sync / checkpoint, not per op), so the cap's sizing is unchanged. Nothing internal
///   consumes this stream — only the external application does — so dropping an observation event is
///   safe; consensus progress and submit replies do not depend on the events stream being complete.
pub fn deliver_event(pending: &mut PendingMap, events: &flume::Sender<Event>, event: Event) {
  let forward = match event {
    Event::Committed(committed) => {
      if let Some(p) = pending.remove(&(committed.client(), committed.request())) {
        let _ = p.reply.send(committed.reply_bytes());
        // Release this entry's budget slot now its op committed: dropping the guard runs its `Drop`.
        drop(p.reservation);
      }
      Event::Committed(committed)
    }
    // Non-Committed observability: no submit to answer — forward to the embedder untouched.
    other => other,
  };
  // Best-effort: drops when the bounded events channel is full (a slow/absent consumer). The
  // submit reply above is the reliable path; this is observation only.
  let _ = events.try_send(forward);
}

#[cfg(test)]
mod tests;

//! Shared session state for both drivers, and the driver MEMORY MODEL.
//!
//! Both the QUIC ([`crate::CompioQuicDriver`]) and stream ([`crate::CompioStreamDriver`]) drivers
//! retain a small fixed set of channels and maps. Each is EXPLICITLY bounded so a partitioned/slow
//! cluster, a flooding peer, or a caller that submits faster than the cluster commits cannot grow
//! the driver's memory without bound. The complete inventory:
//!
//! | retained state            | bound                                                              |
//! |---------------------------|--------------------------------------------------------------------|
//! | `pending` submit map      | [`MAX_INFLIGHT`] entries AND [`MAX_PENDING_BYTES`] of request body  |
//! | command channel           | `max_inflight + 1` queued [`crate::Command`]s (bounded; `try_send`) |
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
  ClientId, Config, Endpoint, Event, Instant, Request, RequestNumber, StateMachine, Superblock,
  VsrState, Wal,
};

/// Construct a driver's consensus endpoint from its durable store — recover-or-new, decided by
/// INSPECTING the store rather than by an embedder flag.
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
pub(crate) fn build_endpoint<S, W, B>(config: Config, sm: S, wal: &mut W, sb: &mut B) -> Endpoint<S>
where
  S: StateMachine,
  W: Wal,
  B: Superblock,
{
  // Wall-clock nanos make the seed (hence the nonces) fresh per incarnation; the replica id keeps
  // replicas constructed in the same instant (a test cluster) on distinct seeds, rotated into the
  // high bits so it does not collide with the fast-moving low nano bits. The truncation keeps the
  // low 64 bits — exactly the fast-moving ones.
  let wall = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_or(0, |d| d.as_nanos() as u64);
  let seed = wall ^ (u64::from(config.replica().get()) + 1).rotate_left(48);
  if sb.state() == VsrState::new() && wal.op_head().get() == 0 {
    Endpoint::new(config, seed, sm)
  } else {
    Endpoint::recover(config, seed, sm, wal, sb)
  }
}

/// Default for how long a submitted-but-uncommitted request waits before the driver re-broadcasts
/// it (the proto session table dedups). Shared by both the QUIC and stream drivers; tunable via
/// `DriverConfig::with_request_timeout` (a geo-replicated cluster whose commit latency nears 250 ms
/// raises it so steady-state submits are not re-broadcast spuriously).
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_millis(250);

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
pub(crate) const MAX_INFLIGHT: usize = 4096;

/// Default maximum total request-body bytes across all in-flight submits, shared by both drivers.
/// Bounds the retained request payloads independently of the count cap so a smaller number of LARGE
/// requests cannot grow memory without bound. 128 MiB MUST be (and is) >= the proto's 16 MiB maximum
/// frame length, so a single maximal request always fits the budget on an empty session — the byte
/// cap can never wedge a legitimate lone request, it only bounds aggregate accumulation. 128 MiB is
/// a sensible ceiling for retained client-request bodies on one node: well above any realistic
/// in-flight working set, yet a hard bound an adversarial or buggy caller cannot exceed. Past the
/// cap a submit returns [`crate::DriverError::Busy`]. Tunable via
/// `DriverConfig::with_max_pending_bytes` (keep the >=-one-max-frame property when lowering it).
pub(crate) const MAX_PENDING_BYTES: usize = 128 * 1024 * 1024;

/// Default best-effort capacity of the event observation channel (driver ->
/// [`crate::Handle`]), shared by both drivers. Bounds the retained events to `EVENTS_CAP`
/// so an application that submits but never drains `Handle::events()` cannot grow the channel
/// without bound — the observation stream is dropped-on-full, not buffered forever. 1024 is a
/// generous default: a consumer that keeps up never sees a drop, and the RELIABLE delivery path
/// (the per-`submit` oneshot, answered in [`deliver_event`]) is unaffected by this cap. Mirrors
/// `INBOUND_CAP`. Tunable via `DriverConfig::with_events_cap`.
pub(crate) const EVENTS_CAP: usize = 1024;

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
pub(crate) struct InflightBudget {
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
  pub(crate) fn new(max_count: usize, max_bytes: usize) -> Self {
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
    let new_count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
    let new_bytes = self.bytes.fetch_add(body_len, Ordering::Relaxed) + body_len;
    if new_count > self.max_count || new_bytes > self.max_bytes {
      self.count.fetch_sub(1, Ordering::Relaxed);
      self.bytes.fetch_sub(body_len, Ordering::Relaxed);
      return None;
    }
    Some(ReservationGuard {
      budget: self.clone(),
      bytes: body_len,
    })
  }

  /// Release ONE in-flight slot of `body_len` bytes, reversing exactly one prior reservation. Private:
  /// the ONLY caller is [`ReservationGuard::drop`], so a reservation is released exactly once, by the
  /// guard that owns it, no matter where that guard finally dies.
  fn release(&self, body_len: usize) {
    self.count.fetch_sub(1, Ordering::Relaxed);
    self.bytes.fetch_sub(body_len, Ordering::Relaxed);
  }

  /// The current count of reserved in-flight slots (test/observability).
  #[cfg(test)]
  pub(crate) fn count(&self) -> usize {
    self.count.load(Ordering::Relaxed)
  }

  /// The current reserved byte total (test/observability).
  #[cfg(test)]
  pub(crate) fn bytes(&self) -> usize {
    self.bytes.load(Ordering::Relaxed)
  }
}

/// An owning RAII handle to ONE [`InflightBudget`] reservation: it holds a budget clone plus the
/// reserved body length, and its [`Drop`] releases that one slot (count + bytes). It is the SINGLE
/// owner of its reservation, so the budget is freed exactly once wherever the guard finally dies and
/// no manual release is needed at any submit-exit site:
///
/// - A successful [`crate::Handle::submit`] reservation produces a guard and moves it into the
///   `Command::Submit` it enqueues. If the `try_send` fails (channel full → `Busy`, disconnected →
///   `DriverGone`) the un-sent `Command` — and so its guard — drops on the early return, releasing the
///   slot: an un-sent submit cannot leak.
/// - When the driver drains a `Submit` into `pending`, the guard MOVES into the [`Pending`] entry. The
///   reservation then lives with the entry: dropping the entry on commit, on cancellation reclaim, or
///   on shutdown drain drops the guard, which releases.
/// - A `Submit` still queued in the command channel when the driver tears down (the channel is dropped)
///   drops its guard too, so a submit racing shutdown before it reaches `pending` cannot leak budget.
///
/// There is no disarm/forget path in use, so a guard ALWAYS releases on drop — the budget tracks live
/// reservations exactly and can neither leak nor double-release.
///
/// `pub` (with no public constructor or accessor — it is minted only by the crate-private
/// [`InflightBudget::try_acquire`]) solely because it rides the public [`crate::Command::Submit`]: an
/// opaque token the driver moves into a [`Pending`] entry, never inspected by an embedder.
#[derive(Debug)]
pub struct ReservationGuard {
  budget: InflightBudget,
  bytes: usize,
}

impl Drop for ReservationGuard {
  fn drop(&mut self) {
    self.budget.release(self.bytes);
  }
}

/// A submitted-but-not-yet-committed client request: its reply channel, the request value to
/// retransmit, when it was last (re)broadcast, and the owning [`ReservationGuard`] for its
/// [`InflightBudget`] slot. The guard lives HERE for the entry's whole life, so dropping the entry —
/// on commit, on cancellation reclaim, or on shutdown drain — releases its budget exactly once with no
/// explicit release call at any of those sites.
pub(crate) struct Pending {
  pub(crate) reply: futures_channel::oneshot::Sender<Bytes>,
  pub(crate) request: Request,
  pub(crate) last_sent: Instant,
  /// Owns this entry's budget reservation; its `Drop` releases the slot when the entry is removed.
  pub(crate) reservation: ReservationGuard,
}

/// The node-local client session map: `(client, request) -> Pending`.
pub(crate) type PendingMap = HashMap<(ClientId, RequestNumber), Pending>;

/// Drop every entry remaining in `pending`, then clear the map. The driver's shutdown/teardown site:
/// any submit still in flight at shutdown (its commit never arrived) frees its reservation as its
/// [`Pending`] is dropped here (the guard's `Drop`), so the budget returns to zero and never leaks
/// across a driver's lifetime. The dropped reply oneshots surface [`crate::DriverError::ReplyDropped`]
/// to any still-waiting `submit`.
pub(crate) fn drain_pending(pending: &mut PendingMap) {
  pending.clear();
}

/// Reap cancelled submits, then collect the requests due for retransmission. Shared by both drivers'
/// per-tick `retransmit_stale`. Two responsibilities, in one pass over `pending`:
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
pub(crate) fn reap_and_collect_retransmits(
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
pub(crate) fn deliver_event(pending: &mut PendingMap, events: &flume::Sender<Event>, event: Event) {
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
mod tests {
  use std::time::Duration;

  use bytes::Bytes;
  use viewstamp_proto::{ClientId, Committed, Event, Instant, OpNumber, Request, RequestNumber};

  use super::{InflightBudget, Pending};

  /// A budget at the DEFAULT caps, as the drivers construct without a config override.
  fn default_budget() -> InflightBudget {
    InflightBudget::new(super::MAX_INFLIGHT, super::MAX_PENDING_BYTES)
  }

  /// Build a `Pending` exactly as the driver does: reserve a `body`-sized slot on `budget` and MOVE
  /// the resulting guard into the entry, so dropping the entry releases that one reservation. Returns
  /// the entry and the live reply receiver (held by the caller so the entry is not auto-cancelled).
  fn pending_entry(
    budget: &InflightBudget,
    request: u64,
    body: Bytes,
  ) -> (Pending, futures_channel::oneshot::Receiver<Bytes>) {
    let reservation = budget
      .try_acquire(body.len())
      .expect("a fresh budget has room for one reservation");
    let (reply, reply_rx) = futures_channel::oneshot::channel();
    let entry = Pending {
      reply,
      request: Request::new(ClientId::new(1), RequestNumber::with(request), body),
      last_sent: Instant::ZERO,
      reservation,
    };
    (entry, reply_rx)
  }

  #[test]
  fn deliver_completes_a_matching_pending_reply() {
    let (events_tx, _events_rx) = flume::unbounded();
    let budget = default_budget();
    let mut pending = std::collections::HashMap::new();
    let (entry, mut reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"q"));
    pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);

    let event = Event::Committed(Committed::new(
      OpNumber::with(1),
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"R"),
    ));
    super::deliver_event(&mut pending, &events_tx, event);

    assert_eq!(reply_rx.try_recv().unwrap(), Some(Bytes::from_static(b"R")));
    assert!(pending.is_empty());
    assert_eq!(
      budget.count(),
      0,
      "a matching commit removes the entry, whose guard releases its reservation"
    );
    assert_eq!(
      budget.bytes(),
      0,
      "the reserved body bytes are released too"
    );
  }

  /// A matching commit releases the budget EVEN IF the reply receiver was already dropped (a
  /// cancelled submit whose commit then arrives): the entry is removed and its guard freed, the
  /// dropped `send` is harmless. This is one of the release sites that keeps the budget from leaking.
  #[test]
  fn deliver_releases_budget_when_the_reply_receiver_is_gone() {
    let (events_tx, _events_rx) = flume::unbounded();
    let budget = default_budget();
    let mut pending = std::collections::HashMap::new();
    let (entry, reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"q"));
    pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);
    drop(reply_rx); // the caller cancelled: the reply receiver is gone before the commit arrives

    super::deliver_event(
      &mut pending,
      &events_tx,
      Event::Committed(Committed::new(
        OpNumber::with(1),
        ClientId::new(1),
        RequestNumber::with(1),
        Bytes::from_static(b"R"),
      )),
    );

    assert!(pending.is_empty());
    assert_eq!(
      budget.count(),
      0,
      "the commit removes the entry (its guard releases) even with the reply receiver gone (no leak)"
    );
  }

  /// `reap_and_collect_retransmits` reclaims a cancelled submit's entry + budget within a tick: an
  /// entry whose reply receiver is dropped is removed (its guard releases) and it is NOT returned for
  /// retransmission.
  #[test]
  fn reap_reclaims_a_cancelled_submit() {
    let budget = default_budget();
    let mut pending = std::collections::HashMap::new();
    let (entry, reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"cancelled"));
    pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);
    drop(reply_rx); // cancel

    // Far enough past REQUEST_TIMEOUT that a LIVE entry would be retransmitted — proving the cancelled
    // one is reclaimed, not merely not-yet-stale.
    let later = Instant::ZERO + super::REQUEST_TIMEOUT + Duration::from_millis(1);
    let stale = super::reap_and_collect_retransmits(&mut pending, later, super::REQUEST_TIMEOUT);

    assert!(
      stale.is_empty(),
      "a cancelled submit is not retransmitted, it is reclaimed"
    );
    assert!(pending.is_empty(), "the cancelled entry is removed");
    assert_eq!(budget.count(), 0, "its budget reservation is released");
    assert_eq!(budget.bytes(), 0, "its reserved bytes are released");
  }

  /// `reap_and_collect_retransmits` re-broadcasts a LIVE stale entry (reply receiver still held, past
  /// `REQUEST_TIMEOUT`) and keeps it in `pending` with its budget intact — only cancelled or
  /// committed entries leave.
  #[test]
  fn reap_retransmits_a_live_stale_entry_and_keeps_its_budget() {
    let budget = default_budget();
    let mut pending = std::collections::HashMap::new();
    let (entry, _reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"live"));
    pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);

    let later = Instant::ZERO + super::REQUEST_TIMEOUT + Duration::from_millis(1);
    let stale = super::reap_and_collect_retransmits(&mut pending, later, super::REQUEST_TIMEOUT);

    assert_eq!(stale.len(), 1, "a live stale entry is re-broadcast");
    assert_eq!(pending.len(), 1, "and stays in pending");
    assert_eq!(budget.count(), 1, "its budget reservation is retained");
  }

  /// `drain_pending` drops every remaining entry, each entry's guard releasing its reservation (the
  /// shutdown release site): the budget returns to zero so a driver's lifetime never leaks.
  #[test]
  fn drain_pending_releases_all_budget() {
    let budget = default_budget();
    let mut pending = std::collections::HashMap::new();
    // Hold each reply receiver alive (so the entries are not cancelled) until after the drain.
    let mut rxs = Vec::new();
    for i in 1..=5u64 {
      let (entry, reply_rx) = pending_entry(&budget, i, Bytes::from_static(b"x"));
      pending.insert((ClientId::new(1), RequestNumber::with(i)), entry);
      rxs.push(reply_rx);
    }
    assert_eq!(budget.count(), 5);

    super::drain_pending(&mut pending);

    assert!(pending.is_empty(), "drain clears the map");
    assert_eq!(
      budget.count(),
      0,
      "and every entry's guard released its reservation"
    );
    assert_eq!(budget.bytes(), 0);
    drop(rxs);
  }

  /// The guard is the SINGLE release owner regardless of where it dies: a `ReservationGuard` that is
  /// simply DROPPED (never moved into a `Pending`) releases its slot — the exact path a
  /// `Command::Submit` takes when it is dropped still-queued as the driver tears down on `Shutdown`,
  /// so a submit racing shutdown before it reaches `pending` cannot leak budget.
  #[test]
  fn dropping_an_un_drained_reservation_guard_releases_the_budget() {
    let budget = default_budget();
    let g1 = budget
      .try_acquire(10)
      .expect("room for the first reservation");
    let g2 = budget
      .try_acquire(20)
      .expect("room for the second reservation");
    assert_eq!(budget.count(), 2, "two live reservations");
    assert_eq!(budget.bytes(), 30, "their reserved bytes sum");

    // Drop the guards WITHOUT ever moving them into a `Pending` — exactly what happens to a queued
    // `Command::Submit` dropped with the command channel on shutdown.
    drop(g1);
    assert_eq!(
      budget.count(),
      1,
      "dropping one guard releases exactly its slot"
    );
    assert_eq!(budget.bytes(), 20);
    drop(g2);
    assert_eq!(
      budget.count(),
      0,
      "dropping the queued reservations returns the budget to zero (no leak across teardown)"
    );
    assert_eq!(budget.bytes(), 0);
  }

  fn committed(op: u64) -> Event {
    Event::Committed(Committed::new(
      OpNumber::with(op),
      ClientId::new(1),
      RequestNumber::with(op),
      Bytes::from_static(b"R"),
    ))
  }

  /// A NON-Committed event (an observability variant) flows to the embedder channel UNTOUCHED: it
  /// answers no pending submit (the map is untouched) and is forwarded verbatim.
  #[test]
  fn non_committed_events_forward_to_the_embedder_untouched() {
    let (events_tx, events_rx) = flume::bounded(super::EVENTS_CAP);
    let budget = default_budget();
    let mut pending = std::collections::HashMap::new();
    let (entry, _reply_rx) = pending_entry(&budget, 1, Bytes::from_static(b"q"));
    pending.insert((ClientId::new(1), RequestNumber::with(1)), entry);

    let ev = Event::StateSyncCompleted(OpNumber::with(9));
    super::deliver_event(&mut pending, &events_tx, ev.clone());

    assert_eq!(
      events_rx.try_recv().expect("the event is observable"),
      ev,
      "a non-Committed event reaches the embedder channel verbatim"
    );
    assert_eq!(
      pending.len(),
      1,
      "no pending submit is answered/removed by a non-Committed event"
    );
    assert_eq!(budget.count(), 1, "and no budget is released");
  }

  /// The committed-events channel is bounded best-effort: an application that never drains
  /// `Handle::events()` must not grow the channel without bound. Pushing far more than `EVENTS_CAP`
  /// committed events through `deliver_event` into the real `flume::bounded(EVENTS_CAP)` channel —
  /// WITHOUT ever receiving — leaves the channel length capped at `EVENTS_CAP` (old events are
  /// dropped on full), instead of accumulating every commit forever.
  #[test]
  fn undrained_events_channel_stays_bounded_at_capacity() {
    let (events_tx, events_rx) = flume::bounded(super::EVENTS_CAP);
    let mut pending = std::collections::HashMap::new();

    // Many times the cap, with nothing draining `events_rx`.
    for op in 1..=(super::EVENTS_CAP as u64 * 8) {
      super::deliver_event(&mut pending, &events_tx, committed(op));
      assert!(
        events_rx.len() <= super::EVENTS_CAP,
        "the undrained events channel must never exceed EVENTS_CAP (got {})",
        events_rx.len(),
      );
    }
    assert_eq!(
      events_rx.len(),
      super::EVENTS_CAP,
      "after a flood with no consumer the channel saturates at exactly EVENTS_CAP, not unbounded"
    );
  }

  /// A drained consumer still observes events: each committed event pushed through `deliver_event`
  /// is received in order when `events_rx` is drained between sends (the bound only drops under a
  /// non-draining consumer, never one that keeps up).
  #[test]
  fn a_drained_events_channel_observes_every_event() {
    let (events_tx, events_rx) = flume::bounded(super::EVENTS_CAP);
    let mut pending = std::collections::HashMap::new();

    for op in 1..=(super::EVENTS_CAP as u64 * 4) {
      super::deliver_event(&mut pending, &events_tx, committed(op));
      let got = events_rx
        .try_recv()
        .expect("a drained consumer observes the event");
      let Event::Committed(got) = got else {
        panic!("only Committed events were pushed, got {got:?}");
      };
      assert_eq!(
        got.op().get(),
        op,
        "events are observed in order when drained"
      );
    }
    assert_eq!(
      events_rx.len(),
      0,
      "a kept-up consumer leaves nothing buffered"
    );
  }
}

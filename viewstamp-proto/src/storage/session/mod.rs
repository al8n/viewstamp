//! The storage session: the owner whose lifetime is the medium's.
//!
//! Every fact in this module exists because it outlives an [`Endpoint`](crate::Endpoint): a
//! submitted write is a physical fact about the medium, not about the endpoint that submitted it,
//! and it stays a fact across any number of endpoint rebuilds until its completion (or a
//! synchronous cancellation) proves it quiesced. The session owns the [`Wal`] and [`Superblock`]
//! handles together with every such fact, so the slot-quiescence fence, the root timeline, and the
//! in-flight checkpoint-envelope ledger survive an endpoint rebuild by construction instead of by a
//! caller remembering to carry them.

use std::collections::{BTreeMap, VecDeque};
use std::vec::Vec;

use bytes::Bytes;

use crate::{
  JobId, OpNumber,
  block_job::{BlockJob, BlockJobDone, BlockJobKind},
  state_machine::StateMachine,
};

use super::{Header, ReadId, Superblock, SuperblockDone, VsrState, Wal, WalDone, WriteId};

mod lane;

use lane::LaneFront;

#[cfg(test)]
mod tests;

/// The session key of an in-flight write: the full `(incarnation, sequence)` pair.
///
/// The endpoint's correlation tables key by sequence alone (past its incarnation choke every id in
/// hand is its own), but the session outlives endpoints and sequences restart at 1 in each
/// incarnation — so the medium ledger must key by the full pair or a successor's write could alias
/// a predecessor's.
type SessionKey = (u64, u64);

#[cfg_attr(not(tarpaulin), inline(always))]
fn key(id: WriteId) -> SessionKey {
  (id.incarnation(), id.seq())
}

/// The verdict of a fenced append submission: either the bytes went to the backend, or an
/// un-quiesced older write holds the physical slot and the caller must park the submission until
/// the session reports that slot freed.
///
/// The fence is this return value, not a predicate consulted beforehand: there is no way to reach
/// [`Wal::submit_append`] through the session without receiving — and having to handle — the
/// verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an unhandled SlotFenced verdict drops the append silently — park it for release"]
pub(crate) enum AppendSubmission {
  /// The append was submitted; its write is now in the session ledger until it quiesces.
  Submitted,
  /// An un-quiesced older write (this endpoint's or a dead predecessor's) occupies the physical
  /// slot; nothing was submitted, and the submission's bytes come back to the caller to park
  /// until the session reports the slot freed.
  SlotFenced {
    /// The refused submission's header, returned for parking.
    header: Header,
    /// The refused submission's body, returned for parking.
    body: Bytes,
  },
}

/// One synchronously-cancelled append reported by a [`Wal::truncate`]/[`Wal::prune`], already
/// settled in the session ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettledCancellation {
  /// The cancelled write's id — any incarnation's.
  pub(crate) id: WriteId,
  /// The op whose physical slot this cancellation freed: the slot a fence-deferred re-append may
  /// now take. Always `Some` past the settle choke — an id the ledger never saw is a backend
  /// contract violation the settle fail-stops on — but kept optional so the settle can build the
  /// record before it judges the id.
  pub(crate) freed_slot: Option<u64>,
}

/// One drained WAL completion, with the medium fact it settled.
///
/// Settlement happens inside [`Storage::poll_wal`], before the caller sees the completion at all:
/// the quiesce fact (medium-scoped, any incarnation's) and the correlation fact (endpoint-scoped,
/// judged later by the incarnation choke) travel the same channel but have different lifetimes,
/// and unbundling them here is what lets a successor endpoint learn that a dead predecessor's
/// write quiesced from a completion it must otherwise refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalPolled {
  /// The completion, to be routed through the endpoint's incarnation choke unchanged.
  pub(crate) done: WalDone,
  /// The op whose physical slot this completion quiesced ([`WalDone::Appended`] or
  /// [`WalDone::Cancelled`] of a ledgered write — any incarnation's), freeing it for a
  /// fence-deferred re-append. `None` for reads and for ids the ledger never saw.
  pub(crate) freed_slot: Option<u64>,
}

/// One drained superblock completion, with the medium fact it settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SbPolled {
  /// The completion, to be routed through the endpoint's incarnation choke unchanged.
  pub(crate) done: SuperblockDone,
  /// The root write this completion landed, with the exact state it made durable — any
  /// incarnation's. `Some` exactly when the completion retired the FRONT of the session's root
  /// queue (roots land in submission order; the single-serialized-writer contract). A successor
  /// endpoint reads an inherited landing from here — the refused foreign completion itself carries
  /// no state.
  pub(crate) landed_root: Option<(WriteId, VsrState)>,
}

/// The storage session: owns the [`Wal`] and [`Superblock`] handles together with every physical
/// write fact that outlives an endpoint — the in-flight append ledger (the slot-quiescence fence's
/// witness set), the in-flight root writes with the exact states they will make durable (the root
/// timeline), the in-flight checkpoint-envelope writes, and the block lane's front (its job queue,
/// its admission quotas, and its issue-order witness).
///
/// **One session per store, for the store's whole in-process lifetime.** Construct it once over
/// quiesced handles — freshly formatted, or freshly opened after a process start — and thread
/// `&mut Storage` through every endpoint entry point. An endpoint rebuild (`Endpoint::recover`
/// over the same session) inherits every fence and every queued block job automatically, because
/// none of them were the endpoint's to lose.
///
/// **A fresh ledger over a live store is unrepresentable.** The constructor consumes the handles;
/// while anything is in flight they cannot come back out ([`Self::into_parts`] refuses); and the
/// only route to [`Wal::submit_append`]/[`Superblock::submit_write`], or to the block lane's
/// queue, is through the recording methods here. So a second session over the same handles — the
/// construction in which a reborn ledger forgets what the store still owes — cannot be written:
/// the handles to build it with are inside the first session until the first session proves the
/// store quiet.
///
/// The block lane's front rides here for exactly that reason. Its queue and the quotas that bound
/// its depth are one object with one lifetime, so an endpoint rebuild can neither drop a queued job
/// while inheriting its weight nor start a fresh quota over a queue that never drained; and because
/// the front is reachable only through this session, "a fresh front over a live lane" is as
/// unsayable as a fresh append ledger. The lane's own half — the store, the worker, and the
/// [`BlockJobCursor`](crate::BlockJobCursor) that witnesses EXECUTION order — stays with the
/// driver's lane, which owns the store and cannot hand it back.
///
/// What no in-process type can seal: a second `W` aliasing the same OS resource (two `File`s onto
/// one path, a second process on one WAL directory). That single operational assumption — one
/// live handle pair per store — belongs to the embedder's `Wal`/`Superblock` implementation
/// (`flock` or equivalent), and it is the only one left outside the type system.
pub struct Storage<W, B, S: StateMachine> {
  wal: W,
  sb: B,
  /// EVERY in-flight physical WAL append over this medium: full id → op. Entered at submit,
  /// removed only when the write QUIESCES — its completion arrives ([`WalDone::Appended`]/
  /// [`WalDone::Cancelled`]; an append has no other ending) or a [`Wal::truncate`]/[`Wal::prune`]
  /// reports it synchronously cancelled. This is the slot-quiescence fence's witness set:
  /// [`Self::submit_append`] refuses a second in-flight write for any ring slot listed here (same
  /// op, or its ring alias `op ± k·capacity`), across every endpoint incarnation that ever wrote
  /// this medium — completion reordering can never let abandoned old bytes land OVER a replacement
  /// some endpoint already acked.
  wal_writes: BTreeMap<SessionKey, u64>,
  /// EVERY in-flight durable-root write, in queue order, each with the exact [`VsrState`] it
  /// will make durable. The single-serialized-writer contract delivers their completions in this
  /// order, so the BACK entry is the root the medium is guaranteed to converge to — the effective
  /// root ([`Self::effective_root`]) — and the FRONT is the next landing. Holding the submitted
  /// states here is what makes the effective root readable off ONE timeline: a root writer that
  /// paired an in-memory scalar with a freshly-read durable half could mint a pair no checkpoint
  /// ever had whenever an inherited root landed in between, and a rebuilt endpoint that baselined
  /// on the landed root instead of the back of this queue would come up BELOW a state the medium
  /// is already guaranteed to reach.
  ///
  /// The queue's tail may be PARKED rather than submitted ([`Self::roots_submitted`] counts the
  /// submitted prefix): a root submission is deferred behind a DIFFERENT incarnation's outstanding
  /// root — the superblock analogue of the append fence — and the session itself submits it, in
  /// queue order, once every foreign root ahead of it has landed. Parked or submitted, an entry is
  /// a committed point on the timeline: the effective root includes it, and quiescence
  /// ([`Self::has_inflight`], [`Self::into_parts`]) waits for it.
  roots: VecDeque<(WriteId, VsrState)>,
  /// How many entries at the FRONT of [`Self::roots`] have been handed to
  /// [`Superblock::submit_write`]. Always a prefix: submission order is queue order, so a parked
  /// entry can never overtake one ahead of it. Entries at/after this index are parked behind a
  /// foreign outstanding root and are submitted by [`Self::poll_sb`] as the landings ahead of them
  /// settle.
  roots_submitted: usize,
  /// EVERY in-flight checkpoint-envelope write: full id → the checkpoint op it stages. Tracked so
  /// quiescence ([`Self::has_inflight`], [`Self::into_parts`]) covers the envelope leg of a
  /// checkpoint exactly as it covers appends and roots. The envelope needs no submission fence:
  /// the durable root stores the envelope's content hash, so a lost same-slot race is DETECTED at
  /// the next recovery (checksum mismatch → peer fetch) rather than silently restored.
  checkpoints: BTreeMap<SessionKey, u64>,
  /// The block lane's front: every job issued over this store and not yet completed, the quotas
  /// they occupy, and the order they must execute in.
  lane: LaneFront<S>,
}

impl<W, B, S: StateMachine> Storage<W, B, S> {
  /// Opens the session over `wal` and `sb`, taking ownership. The ONLY constructor.
  ///
  /// The handles must be QUIESCED: freshly formatted ([`format`](crate::format) confirms its
  /// genesis root synchronously), or freshly opened after a process start (a crash took the
  /// previous process's in-flight ops with it, up to the device-latency window the storage
  /// contract states). Handles that carry un-quiesced writes from a live predecessor can only come
  /// from [`Self::into_parts`], which refuses exactly that state.
  pub fn new(wal: W, sb: B) -> Self {
    Self {
      wal,
      sb,
      wal_writes: BTreeMap::new(),
      roots: VecDeque::new(),
      roots_submitted: 0,
      checkpoints: BTreeMap::new(),
      lane: LaneFront::new(),
    }
  }

  /// Hands the raw handles back — only when nothing is in flight on the store.
  ///
  /// # Errors
  /// Returns `Err(self)` unchanged while any append, root write, checkpoint-envelope write, or
  /// block job is still outstanding: releasing the handles then would let a successor session (or
  /// bare trait calls) write over slots the store still owes completions for, and would drop a
  /// queued job while the lane's cursor still expects it — the reborn-ledger shape this type exists
  /// to make unrepresentable.
  // The `Err` variant IS the session, handed back untouched so the caller keeps draining it. Boxing
  // it to shrink the variant would allocate on the one path whose whole purpose is to return the
  // caller's own value unchanged.
  #[allow(clippy::result_large_err)]
  pub fn into_parts(self) -> Result<(W, B), Self> {
    if self.has_inflight() {
      return Err(self);
    }
    Ok((self.wal, self.sb))
  }

  /// Whether the store still owes any completion: an append, a root write, a checkpoint-envelope
  /// write, or a block job issued through this session and not yet completed — whichever endpoint
  /// incarnation issued it.
  pub fn has_inflight(&self) -> bool {
    !self.wal_writes.is_empty()
      || !self.roots.is_empty()
      || !self.checkpoints.is_empty()
      || self.lane.owes_completion()
  }

  /// Takes the next block-storage job the endpoint has issued, or `None` when none is queued.
  ///
  /// The driver executes it with [`execute_block_job`](crate::execute_block_job) on its storage
  /// lane and feeds the result back through `Endpoint::on_block_done`. Jobs MUST be executed, and
  /// their completions delivered, SERIALLY IN THE ORDER THEY ARE POLLED — see the
  /// [job seam contract](crate::BlockJob) for why that order is a storage-safety obligation and how
  /// a violation is caught.
  ///
  /// Taken from the session rather than from the endpoint because the queue is the LANE's: a job
  /// issued by an endpoint that has since been replaced is still owed by the lane, still executes,
  /// and still releases the quota it claimed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_block_job(&mut self) -> Option<BlockJob<S>> {
    self.lane.poll()
  }

  /// Queue a block job the endpoint has issued, claiming the lane quota its kind occupies. The ONLY
  /// route into the lane's queue.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn enqueue_block_job(&mut self, id: JobId, kind: BlockJobKind<S>) {
    self.lane.enqueue(id, kind);
  }

  /// Settle a block-job completion against the lane's issue-order witness and quotas, before the
  /// endpoint judges correlation. See [`LaneFront::settle`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn settle_block_job(&mut self, done: &BlockJobDone<S>) {
    self.lane.settle(done);
  }

  /// Whether the lane already owes an un-consumed image capture — the capture site's admission
  /// gate.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn materialize_owed(&self) -> bool {
    self.lane.materialize_owed()
  }

  /// How many `Serve` jobs the lane owes completions for — the serve cap's admission count.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn serves_outstanding(&self) -> usize {
    self.lane.serves_outstanding()
  }

  /// Whether the lane already owes a frontier walk — the walk's admission gate.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn walk_owed(&self) -> bool {
    self.lane.walk_owed()
  }

  /// The WAL's synchronous views (`op_head`/`header`/`status`/`capacity`). Read-only: every
  /// mutation routes through the session's recording methods.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn wal(&self) -> &W {
    &self.wal
  }

  /// The superblock's synchronous view (`state`). Read-only: every mutation routes through the
  /// session's recording methods.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn sb(&self) -> &B {
    &self.sb
  }

  /// Test-only escape hatch to the raw WAL handle, for fixture knobs (staging, landing order,
  /// fault injection). Never part of the public surface: a `&mut W` in embedder hands would let an
  /// append bypass the ledger.
  #[cfg(test)]
  pub(crate) fn wal_mut(&mut self) -> &mut W {
    &mut self.wal
  }

  /// Test-only escape hatch to the raw superblock handle. See [`Self::wal_mut`].
  #[cfg(test)]
  pub(crate) fn sb_mut(&mut self) -> &mut B {
    &mut self.sb
  }
}

impl<W: Wal, B: Superblock, S: StateMachine> Storage<W, B, S> {
  /// Whether `a` and `b` occupy the same physical WAL slot under this medium's capacity: the same
  /// op, or — on a bounded backend, whose placement is `op mod capacity` (the trait-level
  /// placement contract) — ring aliases. A ring-less backend (`capacity == u64::MAX`) stores every
  /// op at its own location, so only the same-op case aliases; its extent-recycling discipline is
  /// the trait's extent-reuse clause.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn slots_alias(&self, a: u64, b: u64) -> bool {
    let capacity = self.wal.capacity();
    a == b || (capacity != u64::MAX && a % capacity == b % capacity)
  }

  /// Whether some in-flight physical write targets `op`'s ring slot — ANY incarnation's. The fence
  /// predicate: while true, a new append to `op` must be parked, because append completions may
  /// reorder and submitting now could let the old bytes land LAST, leaving the durable slot
  /// holding a value no live ack/vote named. The map is pipeline-bounded, so the scan is cheap.
  pub(crate) fn slot_write_in_flight(&self, op: u64) -> bool {
    self.wal_writes.values().any(|&v| self.slots_alias(v, op))
  }

  /// Fenced append submission — the ONLY route to [`Wal::submit_append`]. Either records the write
  /// in the session ledger and submits it, or reports the slot fenced by an un-quiesced older
  /// write (this endpoint's or a dead predecessor's) and submits nothing.
  pub(crate) fn submit_append(
    &mut self,
    id: WriteId,
    op: OpNumber,
    header: Header,
    body: Bytes,
  ) -> AppendSubmission {
    if self.slot_write_in_flight(op.get()) {
      return AppendSubmission::SlotFenced { header, body };
    }
    self.wal.submit_append(id, op, header, body);
    self.wal_writes.insert(key(id), op.get());
    AppendSubmission::Submitted
  }

  /// Submit a WAL read. Reads carry no physical-write fact — a dead incarnation's read completes
  /// into the choke and mutates nothing — so the session only forwards them.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn submit_wal_read(&mut self, id: ReadId, op: OpNumber) {
    self.wal.submit_read(id, op);
  }

  /// Truncate the WAL above `above`, settling every synchronously-cancelled append — any
  /// incarnation's — in the session ledger before the caller sees it. Each entry reports the slot
  /// it freed so the caller can release a fence-deferred re-append.
  pub(crate) fn truncate(&mut self, above: OpNumber) -> Vec<SettledCancellation> {
    let cancelled = self.wal.truncate(above);
    self.settle_cancellations(cancelled)
  }

  /// Prune the WAL below `below`, settling every synchronously-cancelled append — any
  /// incarnation's — exactly as [`Self::truncate`] does.
  pub(crate) fn prune(&mut self, below: OpNumber) -> Vec<SettledCancellation> {
    let cancelled = self.wal.prune(below);
    self.settle_cancellations(cancelled)
  }

  fn settle_cancellations(&mut self, cancelled: Vec<WriteId>) -> Vec<SettledCancellation> {
    cancelled
      .into_iter()
      .map(|id| {
        let freed_slot = self.wal_writes.remove(&key(id));
        // Every append over this medium was recorded at submission, whichever endpoint submitted
        // it — so an id the ledger never saw is the backend cancelling an append it was never
        // handed. Enforced in every profile: a backend inventing write facts is a medium whose
        // ledger can no longer be trusted, and consensus over an untrusted ledger risks silent
        // durable-state corruption — fail-stop is the crash-fault model's safe outcome.
        assert!(
          freed_slot.is_some(),
          "a backend cancelled an append id the session never submitted: {id:?}"
        );
        SettledCancellation { id, freed_slot }
      })
      .collect()
  }

  /// Drain the next WAL completion, settling its medium fact first: a completed append — ANY
  /// incarnation's — leaves the ledger here, and the freed slot rides alongside the completion so
  /// the caller can release a fence-deferred re-append even when the completion itself is refused
  /// as foreign. There is no unsettled way to see a completion.
  pub(crate) fn poll_wal(&mut self) -> Option<WalPolled> {
    let done = self.wal.poll()?;
    let freed_slot = match &done {
      WalDone::Appended(id) | WalDone::Cancelled(id) => self.wal_writes.remove(&key(*id)),
      _ => None,
    };
    Some(WalPolled { done, freed_slot })
  }

  /// The EFFECTIVE root: the state of the last root on the timeline — the BACK of the root queue
  /// if any root is still in flight (submitted or parked), else the durable root. This is the state
  /// the medium is guaranteed to converge to once the queue drains (root completions arrive in
  /// submission order and the last-submitted root wins), so it is the sound recovery baseline for
  /// every field a rebuilt endpoint's own root writes stamp FROM LIVE MEMORY (`view`/`log_view`/
  /// `commit`): a successor that baselined those on the landed root instead would come up BELOW a
  /// state already owed to the medium, and its own root writes would then rewind the durable
  /// view/commit the moment an inherited root landed under it. The remaining root fields (the
  /// checkpoint pair and the configuration block) are instead COPIED FORWARD from here by every
  /// root writer, so a rebuilt endpoint holds them at the LANDED root — what a crash actually
  /// recovers — without its writes ever rewinding the timeline.
  /// Invariant during any window in which no new root is submitted: landings drain the queue's
  /// front without moving the back, and when the queue empties the durable root EQUALS the
  /// last-submitted one — so this value is stable across the drain, never a snapshot of a moment.
  ///
  /// What it deliberately does NOT claim: that this state is durable YET. Across a process death
  /// the in-flight tail dies with the process, so an endpoint recovering here must keep its
  /// DURABLE-view witness on the landed root and lift it only as the landings arrive.
  pub(crate) fn effective_root(&self) -> VsrState {
    match self.roots.back() {
      Some((_, state)) => state.clone(),
      None => self.sb.state(),
    }
  }

  /// The checkpoint pair `(checkpoint_op, checkpoint_id)` of the effective root
  /// ([`Self::effective_root`]), projected without cloning the full state. Both halves come off ONE
  /// root value on one timeline, which is the whole point: a root writer pairing an in-memory op
  /// with a freshly-read durable id can mint a pair no checkpoint ever had the moment an inherited
  /// root lands between the two reads. By the single-serialized-writer contract every in-flight
  /// root lands before anything submitted after it, so a new root carrying this pair can never
  /// rewind the durable checkpoint.
  pub(crate) fn effective_checkpoint_pair(&self) -> (OpNumber, u128) {
    match self.roots.back() {
      Some((_, state)) => (state.checkpoint_op(), state.checkpoint_id()),
      None => {
        let state = self.sb.state();
        (state.checkpoint_op(), state.checkpoint_id())
      }
    }
  }

  /// Submit a durable-root write, recording `(id, state)` on the root timeline. The ONLY route to
  /// [`Superblock::submit_write`] past genesis.
  ///
  /// While a DIFFERENT incarnation's root is still outstanding, the submission is PARKED — recorded
  /// on the timeline but not yet handed to the backend — and the session submits it, in queue
  /// order, once every foreign root ahead of it has landed ([`Self::poll_sb`]). This is the
  /// superblock analogue of the append fence: a successor endpoint defers its own root write
  /// behind a dead predecessor's outstanding one, so the two incarnations' writes can never be
  /// interleaved at the backend. Same-incarnation stacking is NOT parked — an endpoint may have a
  /// checkpoint root and a view-change root in flight together, relying on ordered delivery and
  /// last-submitted-wins exactly as before.
  pub(crate) fn submit_root(&mut self, id: WriteId, state: VsrState) {
    // The no-rewind invariants ENFORCED at the submission choke, in every build profile. The
    // asserts run BEFORE `Superblock::submit_write`, so a violating root is REFUSED — it never
    // reaches the medium — and the refusal is fail-stop rather than a recoverable error because
    // the caller's correlation state (`pending_sb`/`pending_checkpoint`) already assumes the
    // submission: continuing past a refusal would leave the endpoint awaiting a completion that
    // can never arrive, a silent permanent wedge — strictly worse than a crash the fault model
    // already tolerates (a panicking replica is one of the f crash faults; a LANDED rewind is a
    // cluster-wide durable-state loss no restart repairs). Every root writer baselines on the
    // effective root (recovery) and sources its checkpoint/configuration halves from it (the live
    // writers), so a rewinding root is a caller bug — unreachable by construction — and this
    // choke is the backstop that keeps it so under release schedules, where the simulator runs.
    // The view check is the durable-view-monotonicity invariant at its choke point: landings
    // arrive in queue order, so a view-monotone queue is exactly a never-regressing durable view.
    let effective = self.effective_root();
    assert!(
      state.view() >= effective.view(),
      "a durable-root write would rewind the durable view ({} below effective {})",
      state.view().get(),
      effective.view().get(),
    );
    assert!(
      state.checkpoint_op() >= effective.checkpoint_op(),
      "a durable-root write would rewind the checkpoint pointer ({} below effective {})",
      state.checkpoint_op().get(),
      effective.checkpoint_op().get(),
    );
    // The epoch/configuration half is monotone for the same reason the view is: landings arrive in
    // queue order, so a root carrying an epoch below the timeline's would republish a superseded
    // configuration underneath a swap the medium already guaranteed — the durable-membership rewind
    // a crash then recovers. Every root writer sources this half from the timeline (recovery
    // baselines the configuration on the landed root and copies an in-flight successor forward at
    // submit), so a regression here is a caller bug, not a reachable state.
    assert!(
      state.epoch() >= effective.epoch(),
      "a durable-root write would rewind the durable epoch ({} below effective {})",
      state.epoch().get(),
      effective.epoch().get(),
    );
    // At an UNCHANGED epoch the configuration is immutable: every configuration change advances
    // the epoch by construction, so a root carrying the same epoch as the timeline's but a
    // different membership would publish a divergent configuration with no epoch to order the two
    // — a lateral rewind the epoch check alone cannot see. Scoped to both roots membership-bearing
    // (a membership-less root carries no configuration to diverge from).
    assert!(
      state.epoch() != effective.epoch()
        || match (state.membership_opt(), effective.membership_opt()) {
          (Some(new), Some(cur)) => new.config_id() == cur.config_id(),
          _ => true,
        },
      "a durable-root write would replace the configuration at an unchanged epoch ({})",
      state.epoch().get(),
    );
    // Scoped to a membership-BEARING effective root: a membership-less root carries no
    // configuration history, so its `config_install_op` is a checkpoint-op alias (the decode
    // default), not an install record a later root could rewind.
    assert!(
      effective.membership_opt().is_none()
        || state.config_install_op() >= effective.config_install_op(),
      "a durable-root write would rewind the configuration install op ({} below effective {})",
      state.config_install_op().get(),
      effective.config_install_op().get(),
    );
    let parked = self.roots_submitted < self.roots.len()
      || self
        .roots
        .iter()
        .take(self.roots_submitted)
        .any(|(qid, _)| qid.incarnation() != id.incarnation());
    if !parked {
      self.sb.submit_write(id, state.clone());
      self.roots_submitted += 1;
    }
    self.roots.push_back((id, state));
  }

  /// Hand the longest releasable parked prefix to the backend: each parked root submits, in queue
  /// order, once nothing of a DIFFERENT incarnation is outstanding ahead of it. Runs after every
  /// root landing, so the fence releases exactly when its blocking write quiesces — the same
  /// release discipline as a fence-deferred append.
  fn release_parked_roots(&mut self) {
    while self.roots_submitted < self.roots.len() {
      let next_id = self.roots[self.roots_submitted].0;
      let blocked = self
        .roots
        .iter()
        .take(self.roots_submitted)
        .any(|(qid, _)| qid.incarnation() != next_id.incarnation());
      if blocked {
        return;
      }
      let (id, state) = self.roots[self.roots_submitted].clone();
      self.sb.submit_write(id, state);
      self.roots_submitted += 1;
    }
  }

  /// Submit a checkpoint-envelope write at `op`, recording it in the envelope ledger. The ONLY
  /// route to [`Superblock::submit_write_checkpoint`].
  pub(crate) fn submit_checkpoint(&mut self, id: WriteId, op: OpNumber, snapshot: Bytes) {
    self.sb.submit_write_checkpoint(id, op, snapshot);
    self.checkpoints.insert(key(id), op.get());
  }

  /// Submit a checkpoint read. Reads carry no physical-write fact; the session only forwards them.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) fn submit_checkpoint_read(&mut self, id: ReadId) {
    self.sb.submit_read_checkpoint(id);
  }

  /// Drain the next superblock completion, settling its medium fact first: a root landing — ANY
  /// incarnation's — pops the front of the root timeline and rides alongside the completion with
  /// the exact state it made durable, so a successor endpoint can adopt an inherited landing even
  /// though the completion itself is refused as foreign. An envelope landing leaves the envelope
  /// ledger the same way. Each root landing also releases any parked roots whose fence it was: a
  /// successor's deferred root write is handed to the backend the moment the last foreign root
  /// ahead of it has landed.
  pub(crate) fn poll_sb(&mut self) -> Option<SbPolled> {
    let done = self.sb.poll()?;
    let landed_root = match &done {
      SuperblockDone::Wrote(id) => {
        // Only a SUBMITTED root can land, so the front matches only within the submitted prefix
        // (a parked front has never been with the backend and no completion can name it).
        if self.roots_submitted > 0 && self.roots.front().is_some_and(|(fid, _)| fid == id) {
          self.roots_submitted -= 1;
          let landed = self.roots.pop_front();
          self.release_parked_roots();
          landed
        } else if self.checkpoints.remove(&key(*id)).is_some() {
          None
        } else if let Some(at) = self.roots.iter().position(|(fid, _)| fid == id) {
          // Root completions must arrive in submission order (the single-serialized-writer
          // contract), and a parked root has no completion to arrive at all; either shape here is
          // a backend violation. Settle it anyway so the ledger drains — including releasing any
          // parked tail whose fence this settlement retired, exactly as the in-order arm does,
          // else the parked roots would strand with nothing left to release them (`has_inflight`
          // true forever, `into_parts` refused forever) — then surface the violation, in every
          // profile: out-of-order root landings break the last-submitted-wins convergence every
          // effective-root read stands on, so continuing would be consensus over a medium whose
          // durable root is no longer the one the timeline promised. The settle precedes the
          // panic so the ledger is coherent at the panic point.
          if at < self.roots_submitted {
            self.roots_submitted -= 1;
          }
          self.roots.remove(at);
          self.release_parked_roots();
          panic!("a root write completed out of submission order: {id:?} at queue position {at}");
        } else {
          // A completion for a write the session never submitted — the same untrusted-medium
          // fail-stop as the cancellation arm above.
          panic!("a superblock write completed that the session never submitted: {id:?}");
        }
      }
      _ => None,
    };
    Some(SbPolled { done, landed_root })
  }
}

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

use crate::OpNumber;

use super::{Header, ReadId, Superblock, SuperblockDone, VsrState, Wal, WalDone, WriteId};

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
  /// The op whose physical slot this cancellation freed, when the ledger held the write: the slot
  /// a fence-deferred re-append may now take. `None` for an id the ledger never saw (a backend
  /// contract violation, already debug-asserted).
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
/// timeline), and the in-flight checkpoint-envelope writes.
///
/// **One session per medium, for the medium's whole in-process lifetime.** Construct it once over
/// quiesced handles — freshly formatted, or freshly opened after a process start — and thread
/// `&mut Storage` through every endpoint entry point. An endpoint rebuild (`Endpoint::recover`
/// over the same session) inherits every fence automatically, because the fences were never the
/// endpoint's to lose.
///
/// **A fresh ledger over a live medium is unrepresentable.** The constructor consumes the handles;
/// while anything is in flight they cannot come back out ([`Self::into_parts`] refuses); and the
/// only route to [`Wal::submit_append`]/[`Superblock::submit_write`] is through the recording
/// methods here. So a second session over the same handles — the construction in which a reborn
/// ledger forgets the medium's outstanding writes — cannot be written: the handles to build it
/// with are inside the first session until the first session proves the medium quiet.
///
/// What no in-process type can seal: a second `W` aliasing the same OS resource (two `File`s onto
/// one path, a second process on one WAL directory). That single operational assumption — one
/// live handle pair per medium — belongs to the embedder's `Wal`/`Superblock` implementation
/// (`flock` or equivalent), and it is the only one left outside the type system.
pub struct Storage<W, B> {
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
  /// EVERY in-flight durable-root write, in submission order, each with the exact [`VsrState`] it
  /// will make durable. The single-serialized-writer contract delivers their completions in this
  /// order, so the BACK entry is the root the medium is guaranteed to converge to — the effective
  /// root — and the FRONT is the next landing. Holding the submitted states here is what makes
  /// [`Self::effective_checkpoint_pair`] readable off ONE timeline: a root writer that paired an
  /// in-memory scalar with a freshly-read durable half could mint a pair no checkpoint ever had
  /// whenever an inherited root landed in between.
  roots: VecDeque<(WriteId, VsrState)>,
  /// EVERY in-flight checkpoint-envelope write: full id → the checkpoint op it stages. Tracked so
  /// quiescence ([`Self::has_inflight`], [`Self::into_parts`]) covers the envelope leg of a
  /// checkpoint exactly as it covers appends and roots. The envelope needs no submission fence:
  /// the durable root stores the envelope's content hash, so a lost same-slot race is DETECTED at
  /// the next recovery (checksum mismatch → peer fetch) rather than silently restored.
  checkpoints: BTreeMap<SessionKey, u64>,
}

impl<W, B> Storage<W, B> {
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
      checkpoints: BTreeMap::new(),
    }
  }

  /// Hands the raw handles back — only when nothing is in flight on the medium.
  ///
  /// # Errors
  /// Returns `Err(self)` unchanged while any append, root write, or checkpoint-envelope write is
  /// still un-quiesced: releasing the handles then would let a successor session (or bare trait
  /// calls) write over slots the medium still owes completions for — the reborn-ledger shape this
  /// type exists to make unrepresentable.
  pub fn into_parts(self) -> Result<(W, B), Self> {
    if self.has_inflight() {
      return Err(self);
    }
    Ok((self.wal, self.sb))
  }

  /// Whether the medium still owes any completion: an append, a root write, or a
  /// checkpoint-envelope write submitted through this session and not yet quiesced — whichever
  /// endpoint incarnation submitted it.
  pub fn has_inflight(&self) -> bool {
    !self.wal_writes.is_empty() || !self.roots.is_empty() || !self.checkpoints.is_empty()
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

impl<W: Wal, B: Superblock> Storage<W, B> {
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
        // handed, a contract violation surfaced here rather than judged per incarnation.
        debug_assert!(
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

  /// The checkpoint pair `(checkpoint_op, checkpoint_id)` of the effective root — the LAST
  /// SUBMITTED root if any is in flight, else the durable root. Both halves come off ONE root
  /// value on one timeline, which is the whole point: a root writer pairing an in-memory op with a
  /// freshly-read durable id can mint a pair no checkpoint ever had the moment an inherited root
  /// lands between the two reads. By the single-serialized-writer contract every in-flight root
  /// lands before anything submitted after it, so a new root carrying this pair can never rewind
  /// the durable checkpoint.
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
  pub(crate) fn submit_root(&mut self, id: WriteId, state: VsrState) {
    // The no-rewind invariant as a submission-time check: every root writer sources its checkpoint
    // pair from the effective root (or advances past it), so a root that would rewind the durable
    // checkpoint pointer is a caller bug caught here, not a state the medium can reach.
    debug_assert!(
      state.checkpoint_op() >= self.effective_checkpoint_pair().0,
      "a durable-root write would rewind the checkpoint pointer ({} below effective {})",
      state.checkpoint_op().get(),
      self.effective_checkpoint_pair().0.get(),
    );
    self.sb.submit_write(id, state.clone());
    self.roots.push_back((id, state));
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
  /// ledger the same way.
  pub(crate) fn poll_sb(&mut self) -> Option<SbPolled> {
    let done = self.sb.poll()?;
    let landed_root = match &done {
      SuperblockDone::Wrote(id) => {
        if self.roots.front().is_some_and(|(fid, _)| fid == id) {
          self.roots.pop_front()
        } else if self.checkpoints.remove(&key(*id)).is_some() {
          None
        } else if let Some(at) = self.roots.iter().position(|(fid, _)| fid == id) {
          // Root completions must arrive in submission order (the single-serialized-writer
          // contract); an out-of-order landing is a backend violation. Settle it anyway so the
          // ledger drains, but surface the violation.
          debug_assert!(
            false,
            "a root write completed out of submission order: {id:?} at queue position {at}"
          );
          self.roots.remove(at)
        } else {
          debug_assert!(
            false,
            "a superblock write completed that the session never submitted: {id:?}"
          );
          None
        }
      }
      _ => None,
    };
    Some(SbPolled { done, landed_root })
  }
}

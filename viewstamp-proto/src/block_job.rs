//! The typed block-storage job seam: the unit of block I/O the consensus pump EMITS instead of
//! executing.
//!
//! The endpoint never touches a [`BlockStore`]. Where it used to materialize a checkpoint, flush, or
//! GC inline, it now queues a [`BlockJob`] (drained via `Endpoint::poll_block_job`) and later
//! consumes the matching [`BlockJobDone`] (fed back via `Endpoint::on_block_done`). The embedder
//! executes each job against its store with [`execute_block_job`] — the ONE place that sequences
//! write-all-then-flush for a materialize and runs the typed per-DAG GC walks — on whatever
//! execution context it chooses (a driver storage lane, a blocking pool, or inline for a
//! deterministic harness).
//!
//! # The executor contract: serial, in issue order
//!
//! Jobs of one endpoint MUST execute SERIALLY IN ISSUE ORDER, and their completions MUST be
//! delivered back in that same order. The order is load-bearing for storage safety, not a
//! convenience: a `Gc` issued with the live roots of checkpoint generation N must run BEFORE a
//! later-issued `Materialize` writes generation N+1's blocks — executed the other way around, the
//! sweep sees N+1's fresh blocks as unreachable garbage and frees them, and the endpoint then
//! publishes a durable root naming blocks the store no longer holds. [`BlockJobCursor`] enforces the
//! execution half mechanically (every job routes through [`execute_block_job`] with the lane's
//! cursor, which fail-stops on an out-of-order job before it touches the store), and the endpoint
//! fail-stops on an out-of-order completion — so a driver that violates the contract is CAUGHT,
//! never silently tolerated.
//!
//! # Identity
//!
//! Every job carries a [`JobId`] minted by the issuing endpoint — the same incarnation + sequence
//! pairing as [`WriteId`](crate::WriteId)/[`ReadId`](crate::ReadId), drawn from the same
//! per-incarnation sequence counter. A completion naming another incarnation belongs to a dead
//! endpoint over the same storage and is refused at the endpoint's single incarnation choke before
//! any correlation state is touched, exactly like a WAL or superblock completion.

use crate::{
  JobId,
  block_store::{BlockAddress, BlockDagWalk, BlockStore, BlockStoreError},
  endpoint::{SessionImage, session_blocks},
  state_machine::StateMachine,
};

/// What kind of work a [`BlockJob`] carries — a stable, fieldless observability tag (the payloads
/// stay crate-internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant, derive_more::Display)]
#[display("{}", self.as_str())]
#[non_exhaustive]
pub enum BlockJobTag {
  /// Write a captured checkpoint image (SM + session table) into the store and flush.
  Materialize,
  /// A bare durability barrier over previously written blocks.
  Flush,
  /// The typed per-DAG mark-and-sweep over the live roots.
  Gc,
}

impl BlockJobTag {
  /// The tag's stable lower-case name, for logs and metric labels.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Materialize => "materialize",
      Self::Flush => "flush",
      Self::Gc => "gc",
    }
  }
}

/// The crate-internal payload of a [`BlockJob`].
pub(crate) enum BlockJobKind<S: StateMachine> {
  /// Materialize a checkpoint: write the SM image's DAG and the session table's DAG, then flush.
  Materialize {
    image: S::Image,
    sessions: SessionImage,
  },
  /// A bare durability barrier over blocks a previous job (or a completed transfer) already wrote.
  Flush,
  /// Mark-and-sweep from the live roots, each DAG walked by its own resolver.
  Gc {
    sm_roots: std::vec::Vec<BlockAddress>,
    session_roots: std::vec::Vec<BlockAddress>,
  },
}

/// One unit of block I/O the endpoint has issued, opaque to the driver: hand it to
/// [`execute_block_job`] with the store, and feed the returned [`BlockJobDone`] back into the
/// endpoint. See the [module docs](self) for the serial-in-issue-order contract.
pub struct BlockJob<S: StateMachine> {
  pub(crate) id: JobId,
  pub(crate) kind: BlockJobKind<S>,
}

impl<S: StateMachine> BlockJob<S> {
  /// The issuing endpoint's correlation id for this job (echoed on the completion).
  pub const fn id(&self) -> JobId {
    self.id
  }

  /// The observability tag naming what kind of work this job carries.
  pub const fn tag(&self) -> BlockJobTag {
    match &self.kind {
      BlockJobKind::Materialize { .. } => BlockJobTag::Materialize,
      BlockJobKind::Flush => BlockJobTag::Flush,
      BlockJobKind::Gc { .. } => BlockJobTag::Gc,
    }
  }
}

impl<S: StateMachine> core::fmt::Debug for BlockJob<S> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("BlockJob")
      .field("id", &self.id)
      .field("tag", &self.tag())
      .finish_non_exhaustive()
  }
}

/// The crate-internal outcome of a [`BlockJobDone`].
pub(crate) enum BlockJobOutput {
  /// The materialize wrote both DAGs; `flush` is the durability verdict the publication gate turns
  /// on (an `Err` means the roots must NOT be named by a durable checkpoint pointer).
  Materialized {
    sm_root: BlockAddress,
    sessions_root: BlockAddress,
    flush: Result<(), BlockStoreError>,
  },
  /// The barrier's verdict.
  Flushed(Result<(), BlockStoreError>),
  /// The sweep ran (it has no data to report; retention is the store's obligation).
  Gced,
}

/// The completion of one [`BlockJob`], fed back into the issuing endpoint. Opaque to the driver;
/// completions MUST be delivered in the same order their jobs were issued.
pub struct BlockJobDone<S: StateMachine> {
  pub(crate) id: JobId,
  pub(crate) output: BlockJobOutput,
  pub(crate) _sm: core::marker::PhantomData<fn() -> S>,
}

impl<S: StateMachine> BlockJobDone<S> {
  /// The correlation id of the job this completion answers.
  pub const fn id(&self) -> JobId {
    self.id
  }
}

impl<S: StateMachine> core::fmt::Debug for BlockJobDone<S> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("BlockJobDone")
      .field("id", &self.id)
      .finish_non_exhaustive()
  }
}

/// The driver-owned execution-order witness for one storage lane: [`execute_block_job`] fail-stops
/// on a job that does not follow the last executed one in `(incarnation, sequence)` order.
///
/// Endpoint incarnations are minted from one process-wide monotone counter and sequences grow within
/// an incarnation, so the pair is lexicographically strictly increasing along any correct serial
/// lane — a job executed out of issue order, or a DEAD endpoint's queued job executing after its
/// successor's, breaks the order and is caught HERE, before it can touch the store. (The canonical
/// hazard: a stale `Gc` carrying an old generation's roots, executed after a newer `Materialize`,
/// would sweep the fresh blocks the next durable root is about to name.)
///
/// One cursor per LANE, not per endpoint: the lane is what must be serial, and a lane shared by a
/// dead endpoint and its successor is exactly the case the incarnation half of the order catches.
#[derive(Debug, Default)]
pub struct BlockJobCursor {
  last: Option<(u64, u64)>,
}

impl BlockJobCursor {
  /// A fresh cursor for a lane that has executed nothing.
  pub const fn new() -> Self {
    Self { last: None }
  }

  /// Records `id` as executed, asserting it strictly follows the previous execution.
  fn admit(&mut self, id: JobId) {
    let next = (id.incarnation(), id.seq());
    if let Some(last) = self.last {
      assert!(
        next > last,
        "block job executed out of issue order: {next:?} after {last:?} — the storage lane must \
         execute serially in issue order (a reordered Gc/Materialize pair can free blocks a durable \
         checkpoint root is about to name)",
      );
    }
    self.last = Some(next);
  }
}

/// Executes one [`BlockJob`] against `store` and returns its completion — the SINGLE place block
/// jobs touch a store, shared by every driver and harness.
///
/// Runs OFF the consensus pump (the whole point of the seam); the caller owns `cursor` for the lane
/// and passes it on every call so issue-order violations fail loudly here. See the
/// [module docs](self) for the full contract.
pub fn execute_block_job<S: StateMachine>(
  cursor: &mut BlockJobCursor,
  job: BlockJob<S>,
  store: &mut dyn BlockStore,
) -> BlockJobDone<S> {
  cursor.admit(job.id);
  let output = match job.kind {
    BlockJobKind::Materialize { image, sessions } => {
      // Write-all-then-flush: the SM DAG, then the session DAG, then the barrier — so a
      // checkpoint's blocks are durable before its completion lets the endpoint submit the
      // superblock pointer naming them.
      let sm_root = S::materialize(&image, store);
      let sessions_root = session_blocks::encode_sessions(sessions.as_map(), store);
      let flush = store.flush();
      BlockJobOutput::Materialized {
        sm_root,
        sessions_root,
        flush,
      }
    }
    BlockJobKind::Flush => BlockJobOutput::Flushed(store.flush()),
    BlockJobKind::Gc {
      sm_roots,
      session_roots,
    } => {
      // The typed per-DAG walks: each root set is followed ONLY by its own resolver, and the store
      // unions the marked sets (over-marking retains; under-marking is impossible).
      store.gc(&[
        BlockDagWalk::new(&sm_roots, &|block| S::block_references(block)),
        BlockDagWalk::new(&session_roots, &session_blocks::session_block_references),
      ]);
      BlockJobOutput::Gced
    }
  };
  BlockJobDone {
    id: job.id,
    output,
    _sm: core::marker::PhantomData,
  }
}

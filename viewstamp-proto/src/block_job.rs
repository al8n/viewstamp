//! The typed block-storage job seam: the unit of block I/O the consensus pump EMITS instead of
//! executing.
//!
//! The endpoint never touches a [`BlockStore`] — no entry point of it takes one. Where it used to
//! materialize a checkpoint, flush, sweep, serve a peer's block, rebuild the state machine, or walk a
//! transfer's missing-block frontier inline, it now queues a [`BlockJob`] (drained via
//! `Endpoint::poll_block_job`) and later consumes the matching [`BlockJobDone`] (fed back via
//! `Endpoint::on_block_done`). The embedder executes each job against its store with
//! [`execute_block_job`] — the ONE place block work touches a store, and the one that sequences
//! write-all-then-flush for a materialize, runs the typed per-DAG GC walks, reconstructs into a
//! detached seed, and advances a transfer's frontiers — on whatever execution context it chooses (a
//! driver storage lane, a blocking pool, or inline for a deterministic harness).
//!
//! # Supersession
//!
//! A job executes against state that may be abandoned while it runs, so every completion carrying a
//! result re-validates its own correlation token before it can publish anything: a checkpoint's
//! materialize/flush against the in-flight checkpoint's step token, a reconstruct against the
//! obligation (or recovery bookkeeping) that owes it, a frontier walk against the transfer still
//! waiting on THAT walk. A completion that no longer matches is dropped and counted
//! (`Endpoint::block_jobs_superseded`), never grafted onto the state that replaced it. Only a serve
//! needs no token: the requester rides on the job, and a served block carries no authority (it
//! self-verifies by content address).
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

use bytes::Bytes;

use crate::{
  JobId, OpNumber, Peer,
  block_store::{
    BlockAddress, BlockDagWalk, BlockStore, BlockStoreError, VerifiedView, read_verified_block,
  },
  endpoint::{Session, SessionImage, block_sync::BlockWalks, session_blocks},
  state_machine::{RestoreError, StateMachine},
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
  /// A verified read of one block, to answer a peer's `RequestBlock`.
  Serve,
  /// Reconstruction of the client-session table and the state machine from a checkpoint's two DAGs.
  Restore,
  /// One step of a checkpoint transfer's missing-block frontier: ingest a fetched block, then drain
  /// the locally-present prefix of both DAGs to find the next missing address.
  Walk,
}

impl BlockJobTag {
  /// The tag's stable lower-case name, for logs and metric labels.
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Materialize => "materialize",
      Self::Flush => "flush",
      Self::Gc => "gc",
      Self::Serve => "serve",
      Self::Restore => "restore",
      Self::Walk => "walk",
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
  /// A durability barrier over the two DAGs a completed transfer already wrote, named by their roots
  /// so the executor can check they are still HELD before the barrier that lets a durable checkpoint
  /// pointer name them.
  Flush {
    sm_root: BlockAddress,
    sessions_root: BlockAddress,
  },
  /// Mark-and-sweep from the live roots, each DAG walked by its own resolver.
  Gc {
    sm_roots: std::vec::Vec<BlockAddress>,
    session_roots: std::vec::Vec<BlockAddress>,
  },
  /// Read one block for a peer that requested it, through the verify-on-read predicate. `to` rides
  /// on the job so the completion needs no endpoint-side correlation table: the requester is
  /// answered from the completion itself.
  Serve { to: Peer, addr: BlockAddress },
  /// Rebuild the client-session table from `sessions_root` and the state machine from `sm_root`,
  /// both through the verify-on-read path. The SM is rebuilt into a DETACHED `seed` the endpoint
  /// swaps in only when the whole reconstruct succeeds, so a fault can never leave the live SM
  /// partially mutated.
  Restore {
    sm_root: BlockAddress,
    sessions_root: BlockAddress,
    seed: S,
    purpose: RestorePurpose,
  },
  /// Advance a checkpoint transfer's missing-block frontier. The walk is intrinsically
  /// STORE-DRIVEN — it drains the locally-present prefix by READING each block and following its
  /// edges — so the frontiers themselves are moved into the job and moved back on its completion,
  /// rather than pumped with a store in hand.
  Walk {
    walks: BlockWalks<S>,
    /// A block just fetched from the donor, to ingest before draining. `None` for a bare re-drive.
    fetched: Option<(BlockAddress, Bytes)>,
    purpose: WalkPurpose,
  },
}

/// What a completed [`BlockJobKind::Walk`] resumes — the continuation of the frontier drive that
/// issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkPurpose {
  /// A freshly ARMED (or re-pinned) transfer's first drain: a fully-present DAG installs, otherwise
  /// the first pull goes out.
  Arm,
  /// An SM-reconstruct obligation's re-armed fetch. A fully-present DAG does NOT install here — the
  /// reconstruct that just failed would immediately re-fail on the same block and spin, so a drained
  /// re-arm only frees the fetch and lets the re-solicit drive the next attempt. `retry` is set only
  /// when a FRESH donor reply armed it (donor failover): the reply is the new evidence that makes one
  /// immediate reconstruct worthwhile, and it is bounded by the inbound replies.
  Rearm { retry: bool },
  /// The stop-and-wait ARQ's bare re-drive of the one outstanding pull.
  Arq,
  /// A donor's `BlockResponse` was ingested: the response continuation, which routes on whether the
  /// reply CARRIED a block and whether it answered the currently-outstanding front.
  Response {
    /// The authenticated sender, checked against the pinned donor before any re-solicit.
    from: Peer,
    /// The address the reply answered.
    addr: BlockAddress,
    /// Whether the reply carried bytes (an ABSENT reply drives the pruned-front re-solicit instead
    /// of the ordinary next pull).
    present: bool,
  },
  /// The cold-start LOCAL presence probe over this replica's own durable checkpoint: it fetches
  /// nothing, only proving every block of both DAGs is present before the reconstruct is issued.
  RecoverProbe(RecoveredCheckpoint),
}

/// Which reconstruction a [`BlockJobKind::Restore`] answers — the completion routes on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestorePurpose {
  /// A SYNCED checkpoint's content, owed as an `SmReconstruct` obligation (the first attempt after
  /// the re-persist root lands, and every re-pull retry, are the same job).
  SyncedCheckpoint,
  /// This replica's OWN durable checkpoint, read back at cold start.
  RecoveredCheckpoint(RecoveredCheckpoint),
}

/// The durable checkpoint a cold-start reconstruct is rebuilding from: the verified op plus the two
/// DAG roots the completion records as the live GC roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveredCheckpoint {
  /// The checkpoint op the read was verified against — what the restored SM will hold.
  pub(crate) op: OpNumber,
  /// The SM DAG root.
  pub(crate) sm_root: BlockAddress,
  /// The session-table DAG root.
  pub(crate) sessions_root: BlockAddress,
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
      BlockJobKind::Flush { .. } => BlockJobTag::Flush,
      BlockJobKind::Gc { .. } => BlockJobTag::Gc,
      BlockJobKind::Serve { .. } => BlockJobTag::Serve,
      BlockJobKind::Restore { .. } => BlockJobTag::Restore,
      BlockJobKind::Walk { .. } => BlockJobTag::Walk,
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
pub(crate) enum BlockJobOutput<S: StateMachine> {
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
  /// The verified read for a peer's `RequestBlock`: `block` is `None` when the store does not hold
  /// the address OR its bytes do not hash back to it (a corrupt block is served as ABSENT, never
  /// handed over to fail the requester's verify).
  Served {
    to: Peer,
    addr: BlockAddress,
    block: Option<Bytes>,
  },
  /// The reconstruct's verdict: on success the FILLED seed plus the decoded session table, which the
  /// endpoint installs together; on a missing/corrupt block in EITHER DAG the address that failed.
  /// The seed is dropped on the error path, so nothing partially rebuilt can reach the endpoint.
  Restored {
    purpose: RestorePurpose,
    result: Result<(S, std::collections::BTreeMap<u128, Session>), RestoreError>,
  },
  /// The frontier step's verdict, with the walks handed back to the transfer that owns them.
  Walked(WalkDone<S>),
}

/// The verdict of one [`BlockJobKind::Walk`].
pub(crate) struct WalkDone<S> {
  /// The frontiers, handed back to the transfer that owns them.
  pub(crate) walks: BlockWalks<S>,
  /// Whether the ingested block ADVANCED either frontier (the transfer-progress signal the bounded
  /// quarantine probe reads).
  pub(crate) accepted: bool,
  /// The next missing address, `Ok(None)` when BOTH DAGs are fully present, or `Err(())` when a walk
  /// breached its reachable-block bound (a malformed / foreign / oversized DAG).
  pub(crate) next: Result<Option<BlockAddress>, ()>,
  /// What this step resumes.
  pub(crate) purpose: WalkPurpose,
}

/// The completion of one [`BlockJob`], fed back into the issuing endpoint. Opaque to the driver;
/// completions MUST be delivered in the same order their jobs were issued.
pub struct BlockJobDone<S: StateMachine> {
  pub(crate) id: JobId,
  pub(crate) output: BlockJobOutput<S>,
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
    BlockJobKind::Flush {
      sm_root,
      sessions_root,
    } => {
      // THE ROOTS ARE STILL HELD. A clean barrier here is what lets the endpoint submit a durable
      // checkpoint pointer NAMING these two roots, so a store that no longer holds them would publish
      // a checkpoint over blocks it has swept. This cannot happen — the endpoint keeps an owed install
      // as a live GC root for exactly this window, so every sweep that runs between the transfer's
      // drain and this barrier marks both DAGs — but the argument spans the GC-root set, the sweep's
      // reachability contract, and the jobs' serial order, so it is CHECKED here, at the one point
      // that both holds the store and knows which roots the barrier is for.
      debug_assert!(
        store.has_block(sm_root) && store.has_block(sessions_root),
        "the durability barrier for a transfer's checkpoint runs over a store that no longer holds \
         its roots (sm {sm_root:?}, sessions {sessions_root:?}) — a live GC root was swept",
      );
      BlockJobOutput::Flushed(store.flush())
    }
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
    BlockJobKind::Serve { to, addr } => BlockJobOutput::Served {
      to,
      addr,
      block: read_verified_block(store, addr),
    },
    BlockJobKind::Restore {
      sm_root,
      sessions_root,
      mut seed,
      purpose,
    } => {
      // Reconstruct the SESSION table first, then the SM into the detached seed — both through the
      // verify-on-read path, so a block that bit-rotted or was misdirected since the frontier drained
      // reads as ABSENT and aborts the reconstruct rather than rebuilding committed state from
      // garbage under a valid checkpoint id.
      let result = match session_blocks::decode_sessions(sessions_root, &*store) {
        None => Err(RestoreError::new(sessions_root)),
        Some(sessions) => {
          let verified = VerifiedView::new(&*store);
          match seed.restore(sm_root, &verified) {
            Ok(()) => Ok((seed, sessions)),
            Err(e) => Err(e),
          }
        }
      };
      BlockJobOutput::Restored { purpose, result }
    }
    BlockJobKind::Walk {
      mut walks,
      fetched,
      purpose,
    } => {
      // Ingest first (a fetched block's children extend the frontier), then drain the
      // locally-present prefix. A bound breach at either step aborts the drain: the transfer is
      // dropped by the completion, so there is nothing for a further walk to advance.
      let mut accepted = false;
      let mut capped = false;
      if let Some((addr, bytes)) = fetched {
        match walks.accept(addr, bytes, store) {
          Ok(a) => accepted = a,
          Err(()) => capped = true,
        }
      }
      let next = if capped {
        Err(())
      } else {
        walks.next_missing(&*store)
      };
      BlockJobOutput::Walked(WalkDone {
        walks,
        accepted,
        next,
        purpose,
      })
    }
  };
  BlockJobDone { id: job.id, output }
}

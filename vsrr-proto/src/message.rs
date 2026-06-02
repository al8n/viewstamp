//! Wire message types for the Viewstamped Replication protocol.

use bytes::Bytes;
use std::vec::Vec;

use crate::{ClientId, OpNumber, Recipient, ReplicaId, RequestNumber, View};

/// A client request to the primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Request {
  /// Creates a client request.
  pub fn new(client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      client,
      request,
      body,
    }
  }

  /// The issuing client.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The per-client monotonic request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application payload as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application payload as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Primary → backups: replicate a prepared operation. Carries the primary's
/// current commit number (piggybacked) and its latest durable `checkpoint_op` (the state-sync
/// trigger signal — `Commit`/`PrepareOk` carry it too, so a lagging backup that only ever sees a
/// `Prepare` from a fresh primary still learns the cluster's checkpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepare {
  view: View,
  op: OpNumber,
  commit: OpNumber,
  checkpoint_op: OpNumber,
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Prepare {
  /// Creates a prepare.
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    checkpoint_op: OpNumber,
    client: ClientId,
    request: RequestNumber,
    body: Bytes,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      checkpoint_op,
      client,
      request,
      body,
    }
  }

  /// The view in which this prepare was created.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number assigned to this operation.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The primary's commit number at send time.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number of the sender's latest durable checkpoint (the state-sync trigger signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The issuing client.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The client request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application payload as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application payload as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Backup → primary: acknowledge a prepared op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOk {
  view: View,
  op: OpNumber,
  replica: ReplicaId,
  checkpoint_op: OpNumber,
}

impl PrepareOk {
  /// Creates a prepare acknowledgement.
  pub const fn new(view: View, op: OpNumber, replica: ReplicaId, checkpoint_op: OpNumber) -> Self {
    Self {
      view,
      op,
      replica,
      checkpoint_op,
    }
  }

  /// The view of the acknowledged prepare.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number acknowledged.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The acknowledging replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The op number of the sender's latest durable checkpoint (the quorum signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }
}

/// Primary → client: the result of a committed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
  view: View,
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl Reply {
  /// Creates a client reply.
  pub fn new(view: View, client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      view,
      client,
      request,
      body,
    }
  }

  /// The view that produced the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The client the reply is for.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The request number this reply answers.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application result as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application result as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Primary → backups: commit heartbeat advancing the commit number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
  view: View,
  commit: OpNumber,
  checkpoint_op: OpNumber,
}

impl Commit {
  /// Creates a commit heartbeat.
  pub const fn new(view: View, commit: OpNumber, checkpoint_op: OpNumber) -> Self {
    Self {
      view,
      commit,
      checkpoint_op,
    }
  }

  /// The current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The primary's commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The op number of the primary's latest durable checkpoint (the quorum signal).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }
}

/// One log entry carried in a `DoViewChange`/`StartView` (the full prepared op).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEntry {
  op: OpNumber,
  client: ClientId,
  request: RequestNumber,
  body: Bytes,
}

impl PreparedEntry {
  /// Creates a prepared-log entry.
  pub fn new(op: OpNumber, client: ClientId, request: RequestNumber, body: Bytes) -> Self {
    Self {
      op,
      client,
      request,
      body,
    }
  }

  /// The op number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The issuing client.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn client(&self) -> ClientId {
    self.client
  }

  /// The client request number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn request(&self) -> RequestNumber {
    self.request
  }

  /// The opaque application payload as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body(&self) -> &[u8] {
    &self.body
  }

  /// The opaque application payload as owned `Bytes`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn body_bytes(&self) -> Bytes {
    self.body.clone()
  }
}

/// Backup → all: "leave the current view" (TB exit_view). `view` is the view to ENTER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartViewChange {
  view: View,
  replica: ReplicaId,
}

impl StartViewChange {
  /// Creates a StartViewChange.
  pub const fn new(view: View, replica: ReplicaId) -> Self {
    Self { view, replica }
  }

  /// The view this replica proposes to enter.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The sending replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }
}

/// Replica → prospective new primary (TB join_view): the sender's full log + position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoViewChange {
  view: View,
  log_view: View,
  op: OpNumber,
  commit: OpNumber,
  replica: ReplicaId,
  log: Vec<PreparedEntry>,
}

impl DoViewChange {
  /// Creates a DoViewChange.
  pub fn new(
    view: View,
    log_view: View,
    op: OpNumber,
    commit: OpNumber,
    replica: ReplicaId,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      log_view,
      op,
      commit,
      replica,
      log,
    }
  }

  /// The view being entered.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The latest view in which the sender changed its head log.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn log_view(&self) -> View {
    self.log_view
  }

  /// The sender's head op.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The sender's commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The sending replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The sender's in-memory log as a slice — the OFFSET tail `(checkpoint .. op]` for a
  /// recover-from-checkpoint / state-synced sender (its committed prefix lives in its SM snapshot),
  /// or dense `[1..=op]` otherwise. The new primary's `select_canonical_log` is offset-aware and
  /// UNIONs these across DVCs, so an offset slice drops no committed op at view change.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the log vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// New primary → all backups (TB view): the canonical log + new view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartView {
  view: View,
  op: OpNumber,
  commit: OpNumber,
  replica: ReplicaId,
  log: Vec<PreparedEntry>,
}

impl StartView {
  /// Creates a StartView.
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    replica: ReplicaId,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      replica,
      log,
    }
  }

  /// The new view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The canonical head op.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The canonical commit number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The new primary.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The canonical log as a slice — the new primary's UNIONed offset tail `(min_floor .. op]` (B3),
  /// which an adopter merges with its own preserved committed ops (it is not necessarily dense
  /// `[1..=op]` if the primary itself checkpointed/state-synced).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the log vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// Lagging backup → prospective primary (TB get_view): request the current `StartView`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetView {
  view: View,
  replica: ReplicaId,
  nonce: u64,
}

impl GetView {
  /// Creates a GetView.
  pub const fn new(view: View, replica: ReplicaId, nonce: u64) -> Self {
    Self {
      view,
      replica,
      nonce,
    }
  }

  /// The view being requested.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The requesting replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// Freshness nonce echoed in the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// Replica → peers (TB request_prepare): solicit a single committed op whose body this replica read
/// back permanently faulty (bit-rot / torn) from its own durable WAL. A replica holding a hole at a
/// committed op `op` (below its head, above its applied frontier) broadcasts this; any peer that
/// holds `op` answers with the [`Prepare`] carrying it. The repair fills the hole so the replica can
/// resume applying its committed prefix in order — it NEVER advances its commit past the hole until
/// the op arrives. The view is carried for routing/freshness; the op's committed content is
/// view-independent, so a reply from any view that holds `op` is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestPrepare {
  view: View,
  op: OpNumber,
  replica: ReplicaId,
}

impl RequestPrepare {
  /// Creates a RequestPrepare for the missing committed op `op`.
  pub const fn new(view: View, op: OpNumber, replica: ReplicaId) -> Self {
    Self { view, op, replica }
  }

  /// The requester's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number being requested (a committed op missing locally).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The requesting replica (the reply is addressed back to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }
}

/// Recovering replica → all (TB recovery): solicit the canonical head when the local head slot is
/// permanently faulty. A `RecoveringHead` replica that cannot trust its own durable head broadcasts
/// this; peers answer with a [`RecoveryResponse`]. The `nonce` is a freshness token echoed back so a
/// stale response (from a prior recovery attempt) is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
  replica: ReplicaId,
  nonce: u64,
}

impl Recovery {
  /// Creates a Recovery solicitation.
  pub const fn new(replica: ReplicaId, nonce: u64) -> Self {
    Self { replica, nonce }
  }

  /// The recovering replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// Freshness nonce echoed in the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// Replica → recovering replica (TB recovery response): the sender's view, position, and — from the
/// view's primary — its canonical log + head + commit, so a `RecoveringHead` replica can re-establish
/// a head it cannot read locally. A non-primary answers with only its view + echoed `nonce` (empty
/// `log`, zero `op`/`commit`): it has no authority to hand out a canonical head, but its view lets the
/// recovering replica learn the current generation. The `nonce` echoes the soliciting [`Recovery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryResponse {
  view: View,
  op: OpNumber,
  commit: OpNumber,
  replica: ReplicaId,
  nonce: u64,
  log: Vec<PreparedEntry>,
}

impl RecoveryResponse {
  /// Creates a RecoveryResponse. The primary fills `op`/`commit`/`log` from its canonical state; a
  /// backup passes `op = commit = 0` and an empty `log` (view + nonce only).
  pub fn new(
    view: View,
    op: OpNumber,
    commit: OpNumber,
    replica: ReplicaId,
    nonce: u64,
    log: Vec<PreparedEntry>,
  ) -> Self {
    Self {
      view,
      op,
      commit,
      replica,
      nonce,
      log,
    }
  }

  /// The responder's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The canonical head op (from the primary; `0` from a backup).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn op(&self) -> OpNumber {
    self.op
  }

  /// The canonical commit number (from the primary; `0` from a backup).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn commit(&self) -> OpNumber {
    self.commit
  }

  /// The responding replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness nonce echoed from the soliciting [`Recovery`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The canonical log as a slice (empty from a backup) — a primary's UNIONed offset tail
  /// `(min_floor .. op]` (B3), merged by the adopter with its own preserved committed ops; not
  /// necessarily dense `[1..=op]`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn log_slice(&self) -> &[PreparedEntry] {
    &self.log
  }

  /// Consumes the message and returns the log vector.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_log(self) -> Vec<PreparedEntry> {
    self.log
  }
}

/// Lagging replica → peers (state-sync solicitation): "my checkpoint is stale; send me the latest
/// checkpoint". Broadcast (like `RequestPrepare`/`Recovery`) when a replica learns the cluster has
/// checkpointed PAST its own WAL head — it cannot catch its tail by retransmit/peer-repair because
/// the ops below the cluster checkpoint may already be pruned at the source. Any `Normal` replica
/// whose durable checkpoint is strictly newer answers with a [`SyncCheckpoint`]. `checkpoint_op` is
/// the requester's CURRENT (stale) checkpoint, so a peer can cheaply skip answering if it has nothing
/// newer; `nonce` is a freshness token echoed in the reply (a stale reply from a prior solicitation is
/// ignored). `view` is carried for routing/freshness only — a committed checkpoint's content is
/// view-independent, so a reply from any view that holds a newer checkpoint is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestSync {
  view: View,
  checkpoint_op: OpNumber,
  replica: ReplicaId,
  nonce: u64,
  recovery: bool,
}

impl RequestSync {
  /// Creates a RequestSync advertising the requester's current (stale) `checkpoint_op`. `recovery` is
  /// set only on the recovery peer-fetch escalation (a replica whose OWN durable checkpoint snapshot
  /// read back permanently corrupt) — there a peer at the SAME `checkpoint_op` must still serve, since
  /// the requester's local bytes are unusable; ordinary state-sync leaves it `false` (a peer answers
  /// only with something strictly newer).
  pub const fn new(
    view: View,
    checkpoint_op: OpNumber,
    replica: ReplicaId,
    nonce: u64,
    recovery: bool,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      replica,
      nonce,
      recovery,
    }
  }

  /// The requester's current view.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The requester's CURRENT (stale) checkpoint op — a peer answers only if it has something newer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The requesting replica (the [`SyncCheckpoint`] reply is addressed back to it).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// Freshness nonce echoed in the reply.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// `true` iff this is a RECOVERY peer-fetch (the requester's own durable checkpoint snapshot is
  /// permanently unreadable). A peer at an EQUAL `checkpoint_op` serves a recovery request (the
  /// requester needs the snapshot bytes even at the same op); an ordinary (`false`) state-sync request
  /// is served only by a strictly-newer checkpoint.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn recovery(&self) -> bool {
    self.recovery
  }
}

/// Peer → lagging replica (state-sync response): the latest durable checkpoint — its op, its content
/// id, and the opaque snapshot envelope (the client-session table + `sm.snapshot()` produced by the
/// proto's `encode_checkpoint`, modelled as one `Bytes`; the wire codec / chunking of a large snapshot
/// is M4). The requester MUST verify `checkpoint_id == checkpoint_id(snapshot)` (a content hash) BEFORE
/// restoring — never restore a corrupt/mismatched checkpoint — then `sm.restore` + restore the session
/// table + set `commit_min == commit_max == checkpoint_op`. `nonce` echoes the soliciting
/// [`RequestSync`] (a stale reply is dropped). Not `Copy` (it carries owned `Bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCheckpoint {
  view: View,
  checkpoint_op: OpNumber,
  checkpoint_id: u128,
  replica: ReplicaId,
  nonce: u64,
  snapshot: Bytes,
}

impl SyncCheckpoint {
  /// Creates a SyncCheckpoint carrying the durable checkpoint snapshot envelope.
  pub fn new(
    view: View,
    checkpoint_op: OpNumber,
    checkpoint_id: u128,
    replica: ReplicaId,
    nonce: u64,
    snapshot: Bytes,
  ) -> Self {
    Self {
      view,
      checkpoint_op,
      checkpoint_id,
      replica,
      nonce,
      snapshot,
    }
  }

  /// The responder's current view (routing/freshness; the checkpoint content is view-independent).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn view(&self) -> View {
    self.view
  }

  /// The op number at which this checkpoint was taken (the new `checkpoint_op` for the requester).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_op(&self) -> OpNumber {
    self.checkpoint_op
  }

  /// The content id of the snapshot — the requester verifies `checkpoint_id(snapshot) == this` before
  /// restoring (the load-bearing integrity gate).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_id(&self) -> u128 {
    self.checkpoint_id
  }

  /// The responding replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The freshness nonce echoed from the soliciting [`RequestSync`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }

  /// The opaque checkpoint snapshot envelope as a slice.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn snapshot(&self) -> &[u8] {
    &self.snapshot
  }

  /// The opaque checkpoint snapshot envelope as a cloned [`Bytes`] handle.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn snapshot_bytes(&self) -> Bytes {
    self.snapshot.clone()
  }
}

/// A Viewstamped Replication protocol message.
///
/// Client traffic is not a separate API: a request arrives as `Message::Request`
/// from a `Peer::Client`, and a reply leaves as `Message::Reply` to that client.
#[derive(
  Debug, Clone, PartialEq, Eq, derive_more::IsVariant, derive_more::Unwrap, derive_more::TryUnwrap,
)]
#[unwrap(ref, ref_mut)]
#[try_unwrap(ref, ref_mut)]
#[non_exhaustive]
pub enum Message {
  /// A client request.
  Request(Request),
  /// A prepare from the primary.
  Prepare(Prepare),
  /// A prepare acknowledgement.
  PrepareOk(PrepareOk),
  /// A reply to a client.
  Reply(Reply),
  /// A commit heartbeat.
  Commit(Commit),
  /// Start a view change.
  StartViewChange(StartViewChange),
  /// Do a view change (to the new primary).
  DoViewChange(DoViewChange),
  /// Start the new view (from the new primary).
  StartView(StartView),
  /// Request the current view (catch-up).
  GetView(GetView),
  /// Solicit a single committed op whose local copy read back faulty (peer fault-repair).
  RequestPrepare(RequestPrepare),
  /// Solicit the canonical head (a `RecoveringHead` replica whose head slot is faulty).
  Recovery(Recovery),
  /// Answer a `Recovery` with the canonical head (from the primary) or just the current view.
  RecoveryResponse(RecoveryResponse),
  /// Solicit the latest durable checkpoint (a replica whose checkpoint is below the cluster's).
  RequestSync(RequestSync),
  /// Answer a `RequestSync` with the latest durable checkpoint (snapshot + op + content id).
  SyncCheckpoint(SyncCheckpoint),
}

impl Message {
  /// The stable variant name of this message (serialization-stable; used in diagnostics and the
  /// emission-chokepoint assert). One source of truth for the message's kind string.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn kind_str(&self) -> &'static str {
    match self {
      Self::Request(_) => "Request",
      Self::Prepare(_) => "Prepare",
      Self::PrepareOk(_) => "PrepareOk",
      Self::Reply(_) => "Reply",
      Self::Commit(_) => "Commit",
      Self::StartViewChange(_) => "StartViewChange",
      Self::DoViewChange(_) => "DoViewChange",
      Self::StartView(_) => "StartView",
      Self::GetView(_) => "GetView",
      Self::RequestPrepare(_) => "RequestPrepare",
      Self::Recovery(_) => "Recovery",
      Self::RecoveryResponse(_) => "RecoveryResponse",
      Self::RequestSync(_) => "RequestSync",
      Self::SyncCheckpoint(_) => "SyncCheckpoint",
    }
  }

  /// True iff this message ADVERTISES AN AUTHORITATIVE / PARTICIPATORY VIEW — i.e. it carries the
  /// sender's `self.view` as an authority claim (a primary head / heartbeat / repair-serve, a recovery
  /// head answer, a checkpoint serve) OR as a vote the recipient counts toward forming/committing in
  /// that view. Such a message must NEVER leave a replica whose current view is not yet DURABLE on its
  /// own superblock (`pending_sb.is_some()`), because `self.view` is then the not-yet-persisted view a
  /// crash would roll back — the durable-view-before-participate invariant (codex R8-F1). This is the
  /// GATED set the single emission chokepoint ([`Endpoint::emit`](crate::Endpoint)) asserts on; it
  /// equals the set the VOPR durable-view checker flags.
  ///
  /// The complement — `StartViewChange` (a REQUEST to change view, not a vote), the solicitations
  /// (`GetView`/`RequestPrepare`/`Recovery`/`RequestSync`), and the client-facing `Request`/`Reply`
  /// (view-independent) — may be emitted while a view write is in flight, so they return `false`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn advertises_authoritative_view(&self) -> bool {
    match self {
      // Primary append broadcast / retransmit, AND the `on_request_prepare` repair serve — advertises
      // `self.view` as the authoritative view of the op (R8-F1 / R17-F1).
      Self::Prepare(_)
      // A backup's VOTE the primary counts toward a COMMIT quorum (carries `self.view`).
      | Self::PrepareOk(_)
      // The primary's heartbeat / commit-advance authority broadcast (carries `self.view`).
      | Self::Commit(_)
      // A VOTE the prospective primary counts toward FORMING the new view (R16-F1).
      | Self::DoViewChange(_)
      // The new primary's "I am the canonical primary of view V" head broadcast.
      | Self::StartView(_)
      // The PRIMARY's recovery-handshake answer (the head-bearing equivalent of a StartView).
      | Self::RecoveryResponse(_)
      // The state-sync serve advertises `self.view` (R18-F1).
      | Self::SyncCheckpoint(_) => true,
      // Solicitations / requests-to-change / client-facing — view-independent, never an authority claim.
      Self::Request(_)
      | Self::Reply(_)
      | Self::StartViewChange(_)
      | Self::GetView(_)
      | Self::RequestPrepare(_)
      | Self::Recovery(_)
      | Self::RequestSync(_) => false,
    }
  }
}

/// A message the state machine wants the driver to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
  to: Recipient,
  msg: Message,
}

impl Outgoing {
  /// Creates an outgoing message.
  pub const fn new(to: Recipient, msg: Message) -> Self {
    Self { to, msg }
  }

  /// The destination set.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn to(&self) -> Recipient {
    self.to
  }

  /// A reference to the message.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn msg_ref(&self) -> &Message {
    &self.msg
  }

  /// Consumes the outgoing wrapper and returns the message.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn into_msg(self) -> Message {
    self.msg
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ClientId, OpNumber, ReplicaId, RequestNumber, View};

  #[test]
  fn commit_and_prepare_ok_carry_checkpoint_op() {
    let c = Commit::new(View::with(1), OpNumber::with(5), OpNumber::with(4));
    assert_eq!(c.checkpoint_op(), OpNumber::with(4));
    let ok = PrepareOk::new(
      View::with(1),
      OpNumber::with(5),
      ReplicaId::new(2),
      OpNumber::with(4),
    );
    assert_eq!(ok.checkpoint_op(), OpNumber::with(4));
  }

  #[test]
  fn prepare_carries_checkpoint_op() {
    let p = Prepare::new(
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(4),
      OpNumber::with(2), // checkpoint_op
      ClientId::new(7),
      RequestNumber::with(5),
      Bytes::from_static(b"x"),
    );
    assert_eq!(p.checkpoint_op(), OpNumber::with(2));
  }

  #[test]
  fn construct_and_match() {
    let m = Message::Prepare(Prepare::new(
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::copy_from_slice(&[1, 2, 3]),
    ));
    match m {
      Message::Prepare(p) => assert_eq!(p.op(), OpNumber::with(1)),
      _ => panic!("wrong variant"),
    }
  }

  #[test]
  fn view_change_messages_construct_and_predicate() {
    use crate::ReplicaId;
    let svc = Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2)));
    assert!(svc.is_start_view_change());
    let dvc = Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(1),
      ReplicaId::new(2),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"x"),
      )],
    ));
    assert_eq!(dvc.unwrap_do_view_change().op(), OpNumber::with(3));
  }

  #[test]
  fn recovery_messages_construct_and_round_trip() {
    use crate::ReplicaId;
    // A RecoveringHead replica broadcasts Recovery{replica, nonce}.
    let rec = Message::Recovery(Recovery::new(ReplicaId::new(2), 0xABCD));
    assert!(rec.is_recovery());
    let r = rec.unwrap_recovery();
    assert_eq!(r.replica(), ReplicaId::new(2));
    assert_eq!(r.nonce(), 0xABCD);

    // The primary's RecoveryResponse carries its view + head + commit + canonical log, echoing nonce.
    let resp = Message::RecoveryResponse(RecoveryResponse::new(
      View::with(3),
      OpNumber::with(5),
      OpNumber::with(4),
      ReplicaId::new(0),
      0xABCD,
      std::vec![PreparedEntry::new(
        OpNumber::with(5),
        ClientId::new(7),
        RequestNumber::with(5),
        bytes::Bytes::from_static(b"e"),
      )],
    ));
    assert!(resp.is_recovery_response());
    let rr = resp.unwrap_recovery_response();
    assert_eq!(rr.view(), View::with(3));
    assert_eq!(rr.op(), OpNumber::with(5));
    assert_eq!(rr.commit(), OpNumber::with(4));
    assert_eq!(rr.replica(), ReplicaId::new(0));
    assert_eq!(rr.nonce(), 0xABCD);
    assert_eq!(rr.log_slice().len(), 1);
    assert_eq!(rr.into_log().len(), 1);
  }

  #[test]
  fn request_prepare_constructs_and_round_trips() {
    use crate::ReplicaId;
    // A replica holding a faulty committed op `op` broadcasts RequestPrepare{view, op, replica}.
    let m = Message::RequestPrepare(RequestPrepare::new(
      View::with(2),
      OpNumber::with(7),
      ReplicaId::new(3),
    ));
    assert!(m.is_request_prepare());
    let rp = m.unwrap_request_prepare();
    assert_eq!(rp.view(), View::with(2));
    assert_eq!(rp.op(), OpNumber::with(7));
    assert_eq!(rp.replica(), ReplicaId::new(3));
  }

  #[test]
  fn sync_messages_construct_and_round_trip() {
    use crate::ReplicaId;
    // A lagging replica solicits with its CURRENT (stale) checkpoint + a nonce.
    let rq = Message::RequestSync(RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      false,
    ));
    assert!(rq.is_request_sync());
    let r = rq.unwrap_request_sync();
    assert_eq!(r.view(), View::with(4));
    assert_eq!(r.checkpoint_op(), OpNumber::with(2));
    assert_eq!(r.replica(), ReplicaId::new(3));
    assert_eq!(r.nonce(), 0xBEEF);
    assert!(!r.recovery(), "ordinary state-sync request");
    // A recovery peer-fetch sets the flag (a peer at an EQUAL checkpoint serves it).
    let rec = RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      true,
    );
    assert!(rec.recovery());

    // The peer answers with the newer checkpoint: op, id, opaque snapshot, echoed nonce.
    let snap = Bytes::from_static(b"snapshot-envelope");
    let sc = Message::SyncCheckpoint(SyncCheckpoint::new(
      View::with(4),
      OpNumber::with(8),
      0x1234_5678_9abc,
      ReplicaId::new(0),
      0xBEEF,
      snap.clone(),
    ));
    assert!(sc.is_sync_checkpoint());
    let s = sc.unwrap_sync_checkpoint();
    assert_eq!(s.view(), View::with(4));
    assert_eq!(s.checkpoint_op(), OpNumber::with(8));
    assert_eq!(s.checkpoint_id(), 0x1234_5678_9abc);
    assert_eq!(s.replica(), ReplicaId::new(0));
    assert_eq!(s.nonce(), 0xBEEF);
    assert_eq!(s.snapshot(), b"snapshot-envelope");
    assert_eq!(s.snapshot_bytes(), snap);
  }

  #[test]
  fn advertises_authoritative_view_is_exactly_the_gated_set() {
    use crate::ReplicaId;
    let body = Bytes::from_static(b"x");
    let entry = || {
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone(),
      )
    };
    // The GATED set (a view-advertising authority / participation message) — must return `true`.
    let gated: std::vec::Vec<Message> = std::vec![
      Message::Prepare(Prepare::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0),
        OpNumber::with(0),
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone()
      )),
      Message::PrepareOk(PrepareOk::new(
        View::with(1),
        OpNumber::with(1),
        ReplicaId::new(2),
        OpNumber::with(0)
      )),
      Message::Commit(Commit::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0)
      )),
      Message::DoViewChange(DoViewChange::new(
        View::with(1),
        View::with(0),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(2),
        std::vec![entry()]
      )),
      Message::StartView(StartView::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(0),
        std::vec![entry()]
      )),
      Message::RecoveryResponse(RecoveryResponse::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(1),
        ReplicaId::new(0),
        0,
        std::vec![entry()]
      )),
      Message::SyncCheckpoint(SyncCheckpoint::new(
        View::with(1),
        OpNumber::with(2),
        0,
        ReplicaId::new(0),
        0,
        body.clone()
      )),
    ];
    for m in &gated {
      assert!(
        m.advertises_authoritative_view(),
        "{} must be gated",
        m.kind_str()
      );
    }
    // The NON-gated set (solicitations / requests-to-change / client-facing) — must return `false`.
    let ungated: std::vec::Vec<Message> = std::vec![
      Message::Request(Request::new(
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone()
      )),
      Message::Reply(Reply::new(
        View::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        body.clone()
      )),
      Message::StartViewChange(StartViewChange::new(View::with(1), ReplicaId::new(2))),
      Message::GetView(GetView::new(View::with(1), ReplicaId::new(2), 0)),
      Message::RequestPrepare(RequestPrepare::new(
        View::with(1),
        OpNumber::with(1),
        ReplicaId::new(2)
      )),
      Message::Recovery(Recovery::new(ReplicaId::new(2), 0)),
      Message::RequestSync(RequestSync::new(
        View::with(1),
        OpNumber::with(0),
        ReplicaId::new(2),
        0,
        false
      )),
    ];
    for m in &ungated {
      assert!(
        !m.advertises_authoritative_view(),
        "{} must NOT be gated",
        m.kind_str()
      );
    }
    // Every variant is covered exactly once across the two sets (no Message kind missed).
    assert_eq!(
      gated.len() + ungated.len(),
      14,
      "all 14 Message variants are classified"
    );
    assert_eq!(
      Message::Commit(Commit::new(
        View::with(1),
        OpNumber::with(1),
        OpNumber::with(0)
      ))
      .kind_str(),
      "Commit"
    );
  }

  #[test]
  fn backup_recovery_response_carries_no_log() {
    use crate::ReplicaId;
    // A non-primary's RecoveryResponse carries only its view + nonce (no canonical log/head/commit).
    let rr = RecoveryResponse::new(
      View::with(3),
      OpNumber::new(),
      OpNumber::new(),
      ReplicaId::new(2),
      0xFEED,
      std::vec![],
    );
    assert!(rr.log_slice().is_empty());
    assert_eq!(rr.nonce(), 0xFEED);
    assert_eq!(rr.view(), View::with(3));
  }
}

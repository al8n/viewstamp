//! Wire message types for the Viewstamped Replication protocol.

use alloc::vec::Vec;
use bytes::Bytes;

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
/// current commit number (piggybacked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepare {
  view: View,
  op: OpNumber,
  commit: OpNumber,
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
    client: ClientId,
    request: RequestNumber,
    body: Bytes,
  ) -> Self {
    Self {
      view,
      op,
      commit,
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
}

impl PrepareOk {
  /// Creates a prepare acknowledgement.
  pub const fn new(view: View, op: OpNumber, replica: ReplicaId) -> Self {
    Self { view, op, replica }
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
}

impl Commit {
  /// Creates a commit heartbeat.
  pub const fn new(view: View, commit: OpNumber) -> Self {
    Self { view, commit }
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

  /// The sender's full in-memory log `[1..=op]` as a slice.
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

  /// The canonical full log `[1..=op]` as a slice.
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
  use crate::{ClientId, OpNumber, RequestNumber, View};

  #[test]
  fn construct_and_match() {
    let m = Message::Prepare(Prepare::new(
      View::with(0),
      OpNumber::with(1),
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
      alloc::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"x"),
      )],
    ));
    assert_eq!(dvc.unwrap_do_view_change().op(), OpNumber::with(3));
  }
}

//! Wire message types for the Viewstamped Replication protocol.

use alloc::vec::Vec;
use bytes::Bytes;

use crate::{ClientId, OpNumber, Recipient, ReplicaId, RequestNumber, View};

/// A client request to the primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
  /// Issuing client.
  pub client: ClientId,
  /// Per-client monotonic request number.
  pub request: RequestNumber,
  /// Opaque application payload (interpreted only by the `StateMachine`).
  pub body: Bytes,
}

/// Primary → backups: replicate a prepared operation. Carries the primary's
/// current commit number (piggybacked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepare {
  /// View in which this prepare was created.
  pub view: View,
  /// The op number assigned to this operation.
  pub op: OpNumber,
  /// The primary's commit number at send time.
  pub commit: OpNumber,
  /// Issuing client.
  pub client: ClientId,
  /// Client request number.
  pub request: RequestNumber,
  /// Opaque application payload.
  pub body: Bytes,
}

/// Backup → primary: acknowledge a prepared op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareOk {
  /// View of the acknowledged prepare.
  pub view: View,
  /// Op number acknowledged.
  pub op: OpNumber,
  /// Acknowledging replica.
  pub replica: ReplicaId,
}

/// Primary → client: the result of a committed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
  /// View that produced the reply.
  pub view: View,
  /// Client the reply is for.
  pub client: ClientId,
  /// Request number this reply answers.
  pub request: RequestNumber,
  /// Opaque application result.
  pub body: Bytes,
}

/// Primary → backups: commit heartbeat advancing the commit number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
  /// Current view.
  pub view: View,
  /// The primary's commit number.
  pub commit: OpNumber,
}

/// One log entry carried in a `DoViewChange`/`StartView` (the full prepared op).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEntry {
  /// The op number.
  pub op: OpNumber,
  /// Issuing client.
  pub client: ClientId,
  /// Client request number.
  pub request: RequestNumber,
  /// Opaque application payload.
  pub body: Bytes,
}

/// Backup → all: "leave the current view" (TB exit_view). `view` is the view to ENTER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartViewChange {
  /// The view this replica proposes to enter.
  pub view: View,
  /// The sending replica.
  pub replica: ReplicaId,
}

/// Replica → prospective new primary (TB join_view): the sender's full log + position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoViewChange {
  /// The view being entered.
  pub view: View,
  /// The latest view in which the sender changed its head log.
  pub log_view: View,
  /// The sender's head op.
  pub op: OpNumber,
  /// The sender's commit number.
  pub commit: OpNumber,
  /// The sending replica.
  pub replica: ReplicaId,
  /// The sender's full in-memory log `[1..=op]`.
  pub log: Vec<PreparedEntry>,
}

/// New primary → all backups (TB view): the canonical log + new view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartView {
  /// The new view.
  pub view: View,
  /// The canonical head op.
  pub op: OpNumber,
  /// The canonical commit number.
  pub commit: OpNumber,
  /// The new primary.
  pub replica: ReplicaId,
  /// The canonical full log `[1..=op]`.
  pub log: Vec<PreparedEntry>,
}

/// Lagging backup → prospective primary (TB get_view): request the current `StartView`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetView {
  /// The view being requested.
  pub view: View,
  /// The requesting replica.
  pub replica: ReplicaId,
  /// Freshness nonce echoed in the reply.
  pub nonce: u64,
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
  /// Destination set.
  pub to: Recipient,
  /// The message.
  pub msg: Message,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ClientId, OpNumber, RequestNumber, View};

  #[test]
  fn construct_and_match() {
    let m = Message::Prepare(Prepare {
      view: View::with(0),
      op: OpNumber::with(1),
      commit: OpNumber::with(0),
      client: ClientId::new(9),
      request: RequestNumber::with(1),
      body: Bytes::copy_from_slice(&[1, 2, 3]),
    });
    match m {
      Message::Prepare(p) => assert_eq!(p.op, OpNumber::with(1)),
      _ => panic!("wrong variant"),
    }
  }

  #[test]
  fn view_change_messages_construct_and_predicate() {
    use crate::ReplicaId;
    let svc = Message::StartViewChange(StartViewChange {
      view: View::with(1),
      replica: ReplicaId::new(2),
    });
    assert!(svc.is_start_view_change());
    let dvc = Message::DoViewChange(DoViewChange {
      view: View::with(1),
      log_view: View::with(0),
      op: OpNumber::with(3),
      commit: OpNumber::with(1),
      replica: ReplicaId::new(2),
      log: alloc::vec![PreparedEntry {
        op: OpNumber::with(1),
        client: ClientId::new(7),
        request: RequestNumber::with(1),
        body: bytes::Bytes::from_static(b"x"),
      }],
    });
    assert_eq!(dvc.unwrap_do_view_change().op, OpNumber::with(3));
  }
}

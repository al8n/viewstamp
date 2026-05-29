//! Wire message types for the Viewstamped Replication protocol.

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

/// A Viewstamped Replication protocol message.
///
/// Client traffic is not a separate API: a request arrives as `Message::Request`
/// from a `Peer::Client`, and a reply leaves as `Message::Reply` to that client.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

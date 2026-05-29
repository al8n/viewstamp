//! Identity types for replicas, clients, and message routing.

/// Index of a replica within a cluster, in `0..replica_count`.
///
/// This is the protocol identity. The mapping from `ReplicaId` to a network
/// address is a driver concern, not the state machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ReplicaId(u8);

impl ReplicaId {
  /// Creates a replica id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(index: u8) -> Self {
    Self(index)
  }

  /// The replica index.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn get(self) -> u8 {
    self.0
  }
}

impl core::fmt::Display for ReplicaId {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    self.0.fmt(f)
  }
}

/// A globally-unique client identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ClientId(u128);

impl ClientId {
  /// Creates a client id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(id: u128) -> Self {
    Self(id)
  }

  /// The raw client id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn get(self) -> u128 {
    self.0
  }
}

/// The source or destination of a protocol message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
  /// A peer replica.
  Replica(ReplicaId),
  /// A client.
  Client(ClientId),
}

impl Peer {
  /// True iff this is a replica peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_replica(&self) -> bool {
    matches!(self, Self::Replica(_))
  }

  /// True iff this is a client peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_client(&self) -> bool {
    matches!(self, Self::Client(_))
  }

  /// The replica id, if this is a replica peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_replica(&self) -> Option<ReplicaId> {
    match self {
      Self::Replica(r) => Some(*r),
      Self::Client(_) => None,
    }
  }
}

/// The intended destination set for an outgoing message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recipient {
  /// A single peer.
  To(Peer),
  /// Every replica except this one.
  Backups,
  /// Every replica including this one (loopback handled by the driver).
  AllReplicas,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn peer_predicates() {
    let r = Peer::Replica(ReplicaId::new(2));
    let c = Peer::Client(ClientId::new(7));
    assert!(r.is_replica() && !r.is_client());
    assert_eq!(r.as_replica(), Some(ReplicaId::new(2)));
    assert!(c.is_client() && c.as_replica().is_none());
    assert_eq!(ReplicaId::new(2).get(), 2);
    assert_eq!(ClientId::new(7).get(), 7);
  }
}

//! Identity types for replicas, clients, and message routing.

/// Index of a replica within a cluster, in `0..node_count`. A voting replica
/// has an id `< replica_count`; the remaining ids are non-voting replicas.
///
/// This is the protocol identity. The mapping from `ReplicaId` to a network
/// address is a driver concern, not the state machine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ReplicaId(u16);

impl ReplicaId {
  /// Creates a replica id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(index: u16) -> Self {
    Self(index)
  }

  /// The replica index.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn get(self) -> u16 {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

  /// The client id, if this is a client peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_client(&self) -> Option<ClientId> {
    match self {
      Self::Client(c) => Some(*c),
      Self::Replica(_) => None,
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

impl Recipient {
  /// True iff this targets a single peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_to(&self) -> bool {
    matches!(self, Self::To(_))
  }

  /// True iff this targets every backup (every replica but this one).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_backups(&self) -> bool {
    matches!(self, Self::Backups)
  }

  /// True iff this targets every replica.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_all_replicas(&self) -> bool {
    matches!(self, Self::AllReplicas)
  }

  /// The single peer, if this targets one.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_to(&self) -> Option<Peer> {
    match self {
      Self::To(p) => Some(*p),
      _ => None,
    }
  }
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

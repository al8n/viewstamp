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

/// A globally-unique, slot-decoupled replica identity. Stable across
/// reconfigurations: a `MemberId` occupies a [`ReplicaId`] slot in the active
/// membership, and a node is resolved by its `MemberId`, not its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MemberId(u128);

impl MemberId {
  /// Creates a member id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(id: u128) -> Self {
    Self(id)
  }

  /// The raw member id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn get(self) -> u128 {
    self.0
  }
}

impl core::fmt::Display for MemberId {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    self.0.fmt(f)
  }
}

/// A configuration version. Monotone across reconfigurations; high-order to the
/// view in `(epoch, view)` leadership (view resets to 0 each epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Epoch(u64);

impl Epoch {
  /// Creates an epoch.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(n: u64) -> Self {
    Self(n)
  }

  /// The raw epoch number.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn get(self) -> u64 {
    self.0
  }

  /// The next epoch (saturating).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn next(self) -> Self {
    Self(self.0.saturating_add(1))
  }
}

impl core::fmt::Display for Epoch {
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
  /// The reserved pseudo-client a primary mints CONSENSUS-internal operations under — today the
  /// `Body::Reconfigure` membership-change op. A reconfiguration op needs a `(client, request)`
  /// identity for content-addressing/dedup exactly like a client op, but it originates from the
  /// primary (the operator's intent), not from any real client session. This id (`u128::MAX`) is the
  /// reserved high sentinel: it is never assigned to a real client, so a reconfiguration op cannot
  /// collide with or evict a genuine client session, and a reconfiguration op's identity is
  /// distinguished from every client op's at the content-address level.
  pub const RECONFIGURATION: Self = Self(u128::MAX);

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
  /// A replica peer addressed by its stable cross-reconfiguration identity — the handshake
  /// self-claim and the coordinator's attested identity for a validated stream conn. DISTINCT from
  /// `Replica(slot)`: `Member` is the handshake-attested stable id; `Replica` is the routing key
  /// the coordinator resolves it to. A `Member` id is NEVER a routing target in the router's
  /// `peers` map — only `Replica(slot)` conns are routed.
  Member(MemberId),
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

  /// True iff this is a `Member` peer (stable handshake-attested identity, not a routing slot).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_member(&self) -> bool {
    matches!(self, Self::Member(_))
  }

  /// The replica id, if this is a replica peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_replica(&self) -> Option<ReplicaId> {
    match self {
      Self::Replica(r) => Some(*r),
      _ => None,
    }
  }

  /// The client id, if this is a client peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_client(&self) -> Option<ClientId> {
    match self {
      Self::Client(c) => Some(*c),
      _ => None,
    }
  }

  /// The stable member id, if this is a `Member` peer.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_member(&self) -> Option<MemberId> {
    match self {
      Self::Member(m) => Some(*m),
      _ => None,
    }
  }
}

/// The intended destination set for an outgoing message. A fan-out variant
/// spans the full configured membership — every voting and non-voting replica
/// — which the driver resolves against its live connection table; the core
/// never enumerates ids for a fan-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recipient {
  /// A single peer.
  To(Peer),
  /// Every other replica, voting or not (every member except this one).
  Backups,
  /// Every replica including this one, voting or not (loopback handled by the driver).
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

  #[test]
  fn member_id_and_epoch_round_trip() {
    let m = MemberId::new(0xDEAD_BEEF_0000_0001_0000_0000_0000_0002);
    assert_eq!(m.get(), 0xDEAD_BEEF_0000_0001_0000_0000_0000_0002);
    assert_eq!(MemberId::new(7), MemberId::new(7));
    assert_ne!(MemberId::new(7), MemberId::new(8));
    let e = Epoch::new(5);
    assert_eq!(e.get(), 5);
    assert!(Epoch::new(0) < Epoch::new(1));
    assert_eq!(Epoch::new(4).next(), Epoch::new(5));
    assert_eq!(std::format!("{}", MemberId::new(42)), "42");
  }
}

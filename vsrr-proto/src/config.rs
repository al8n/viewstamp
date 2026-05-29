use crate::{ReplicaId, View};

/// Static cluster configuration for one replica. Immutable in v1
/// (reconfiguration is deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  cluster: u128,
  replica: ReplicaId,
  replica_count: u8,
}

impl Config {
  /// Creates a configuration.
  ///
  /// # Panics
  /// Panics if `replica_count == 0`, `replica.get() >= replica_count`, or `replica_count > 64`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(cluster: u128, replica: ReplicaId, replica_count: u8) -> Self {
    assert!(replica_count > 0, "replica_count must be > 0");
    assert!(replica.get() < replica_count, "replica index out of range");
    assert!(
      replica_count <= 64,
      "replica_count must be <= 64 (prepare-ok quorum uses a u64 bitset)"
    );
    Self {
      cluster,
      replica,
      replica_count,
    }
  }

  /// The cluster id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn cluster(&self) -> u128 {
    self.cluster
  }

  /// This replica's id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica(&self) -> ReplicaId {
    self.replica
  }

  /// The number of replicas in the cluster.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica_count(&self) -> u8 {
    self.replica_count
  }

  /// The replication / view-change quorum size: `floor(n/2) + 1`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn quorum(&self) -> usize {
    (self.replica_count as usize) / 2 + 1
  }

  /// The primary for a given view: `view % replica_count`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn primary(&self, view: View) -> ReplicaId {
    ReplicaId::new((view.get() % self.replica_count as u64) as u8)
  }

  /// Whether this replica is the primary for `view`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_primary(&self, view: View) -> bool {
    self.primary(view).get() == self.replica.get()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{ReplicaId, View};

  #[test]
  fn quorum_and_primary() {
    let c = Config::new(42, ReplicaId::new(1), 3);
    assert_eq!(c.replica_count(), 3);
    assert_eq!(c.quorum(), 2); // floor(3/2)+1
    assert_eq!(c.primary(View::with(0)), ReplicaId::new(0));
    assert_eq!(c.primary(View::with(1)), ReplicaId::new(1));
    assert_eq!(c.primary(View::with(4)), ReplicaId::new(1)); // 4 % 3
    assert!(c.is_primary(View::with(1)));
    assert!(!c.is_primary(View::with(0)));
  }

  #[test]
  fn quorum_five() {
    let c = Config::new(0, ReplicaId::new(0), 5);
    assert_eq!(c.quorum(), 3);
  }
}

use crate::{ReplicaId, View};

/// Error constructing a [`Config`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
  /// `replica_count` was zero.
  #[error("replica_count must be > 0")]
  ZeroReplicaCount,
  /// `replica` index is not in `0..replica_count`.
  #[error("replica index {index} out of range for a {count}-replica cluster")]
  ReplicaIndexOutOfRange {
    /// The offending replica index.
    index: u8,
    /// The cluster size.
    count: u8,
  },
  /// `replica_count` exceeds the 64-replica limit (the prepare-ok quorum uses a u64 bitset).
  #[error("replica_count {count} exceeds the maximum of 64 (prepare-ok quorum uses a u64 bitset)")]
  TooManyReplicas {
    /// The offending cluster size.
    count: u8,
  },
}

/// Static cluster configuration for one replica. Immutable in v1
/// (reconfiguration is deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  cluster: u128,
  replica: ReplicaId,
  replica_count: u8,
}

impl Config {
  /// Creates a configuration, validating the cluster invariants.
  ///
  /// # Errors
  /// Returns [`ConfigError`] if `replica_count == 0`, `replica >= replica_count`,
  /// or `replica_count > 64`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn try_new(
    cluster: u128,
    replica: ReplicaId,
    replica_count: u8,
  ) -> Result<Self, ConfigError> {
    if replica_count == 0 {
      return Err(ConfigError::ZeroReplicaCount);
    }
    if replica.get() >= replica_count {
      return Err(ConfigError::ReplicaIndexOutOfRange {
        index: replica.get(),
        count: replica_count,
      });
    }
    if replica_count > 64 {
      return Err(ConfigError::TooManyReplicas {
        count: replica_count,
      });
    }
    Ok(Self {
      cluster,
      replica,
      replica_count,
    })
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

  /// The view-change / DoViewChange quorum: `replica_count − quorum + 1`.
  ///
  /// Intersects every replication quorum (`quorum + quorum_view_change > replica_count`),
  /// so a view change cannot start while normal commit is still possible.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn quorum_view_change(&self) -> usize {
    self.replica_count as usize - self.quorum() + 1
  }

  /// The nack-prepare quorum (used by view change to truncate uncommitted ops):
  /// `replica_count − quorum + 1`. Equal to `quorum_view_change`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn quorum_nack_prepare(&self) -> usize {
    self.replica_count as usize - self.quorum() + 1
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
    let c = Config::try_new(42, ReplicaId::new(1), 3).expect("valid cluster config");
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
    let c = Config::try_new(0, ReplicaId::new(0), 5).expect("valid cluster config");
    assert_eq!(c.quorum(), 3);
  }

  #[test]
  fn view_change_and_nack_quorums() {
    // N=3: quorum=2, vc=nack=3-2+1=2.  N=5: quorum=3, vc=nack=3.  N=4: quorum=3, vc=nack=2.
    let c3 = Config::try_new(0, ReplicaId::new(0), 3).unwrap();
    assert_eq!(c3.quorum_view_change(), 2);
    assert_eq!(c3.quorum_nack_prepare(), 2);
    let c5 = Config::try_new(0, ReplicaId::new(0), 5).unwrap();
    assert_eq!(c5.quorum_view_change(), 3);
    let c4 = Config::try_new(0, ReplicaId::new(0), 4).unwrap();
    assert_eq!(c4.quorum_view_change(), 2); // 4 - 3 + 1
  }

  #[test]
  fn try_new_errors() {
    assert_eq!(
      Config::try_new(0, ReplicaId::new(0), 0),
      Err(ConfigError::ZeroReplicaCount)
    );
    assert_eq!(
      Config::try_new(0, ReplicaId::new(3), 3),
      Err(ConfigError::ReplicaIndexOutOfRange { index: 3, count: 3 })
    );
    assert_eq!(
      Config::try_new(0, ReplicaId::new(0), 65),
      Err(ConfigError::TooManyReplicas { count: 65 })
    );
  }
}

use crate::{ReplicaId, View};

/// Default ops between checkpoints (matches a small TB-style interval for fast sim coverage).
pub const DEFAULT_CHECKPOINT_OPS: u64 = 32;
/// Upper bound on the checkpoint interval: keeps the WAL/pipeline headroom finite so the maps
/// stay bounded and a checkpoint cannot be outrun by in-flight prepares.
pub const MAX_CHECKPOINT_OPS: u64 = 1 << 20;

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
  /// `checkpoint_ops` was zero.
  #[error("checkpoint_ops must be > 0")]
  ZeroCheckpointOps,
  /// `checkpoint_ops` exceeds the maximum interval.
  #[error("checkpoint_ops {ops} exceeds the maximum of 2^20")]
  CheckpointOpsTooLarge {
    /// The offending interval.
    ops: u64,
  },
}

/// Static cluster configuration for one replica. Immutable in v1
/// (reconfiguration is deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  cluster: u128,
  replica: ReplicaId,
  replica_count: u8,
  checkpoint_ops: u64,
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
      checkpoint_ops: DEFAULT_CHECKPOINT_OPS,
    })
  }

  /// Like [`Config::try_new`] but with an explicit checkpoint interval.
  ///
  /// # Errors
  /// In addition to [`Config::try_new`]'s errors: [`ConfigError::ZeroCheckpointOps`] if
  /// `checkpoint_ops == 0`, [`ConfigError::CheckpointOpsTooLarge`] if it exceeds [`MAX_CHECKPOINT_OPS`].
  pub const fn with_checkpoint_ops(
    cluster: u128,
    replica: ReplicaId,
    replica_count: u8,
    checkpoint_ops: u64,
  ) -> Result<Self, ConfigError> {
    if checkpoint_ops == 0 {
      return Err(ConfigError::ZeroCheckpointOps);
    }
    if checkpoint_ops > MAX_CHECKPOINT_OPS {
      return Err(ConfigError::CheckpointOpsTooLarge {
        ops: checkpoint_ops,
      });
    }
    match Self::try_new(cluster, replica, replica_count) {
      Ok(c) => Ok(Self {
        cluster: c.cluster,
        replica: c.replica,
        replica_count: c.replica_count,
        checkpoint_ops,
      }),
      Err(e) => Err(e),
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

  /// Ops between checkpoints (a checkpoint is taken when commit_min reaches checkpoint_op + this).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_ops(&self) -> u64 {
    self.checkpoint_ops
  }

  /// The checkpoint lag (in ops) at which a `Normal` primary FORFEITS primacy and steps down via a
  /// view change: if a quorum has durably checkpointed at least this many ops beyond the
  /// primary's own `checkpoint_op` — continuously for the grace window — the primary is genuinely
  /// stuck (it cannot checkpoint because it is repairing/syncing while the cluster raced ahead) and
  /// proposes a view change so a caught-up replica leads.
  ///
  /// Derived from `checkpoint_ops` (one full checkpoint interval), so it scales with the config and a
  /// small-interval sim does not false-fire: a healthy primary checkpoints in lock-step with the
  /// cluster and never falls a whole interval behind a quorum. No constructor argument.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn forfeit_checkpoint_lag(&self) -> u64 {
    self.checkpoint_ops
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
  fn checkpoint_ops_is_validated_and_accessible() {
    let c = Config::try_new(0, ReplicaId::new(0), 3).unwrap();
    assert_eq!(c.checkpoint_ops(), DEFAULT_CHECKPOINT_OPS); // default interval
    let c2 = Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 8).unwrap();
    assert_eq!(c2.checkpoint_ops(), 8);
    // zero interval is rejected (a checkpoint every 0 ops is meaningless / would loop)
    assert_eq!(
      Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, 0),
      Err(ConfigError::ZeroCheckpointOps)
    );
    // an interval beyond the pipeline-headroom cap is rejected
    assert_eq!(
      Config::with_checkpoint_ops(0, ReplicaId::new(0), 3, MAX_CHECKPOINT_OPS + 1),
      Err(ConfigError::CheckpointOpsTooLarge {
        ops: MAX_CHECKPOINT_OPS + 1
      })
    );
  }

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

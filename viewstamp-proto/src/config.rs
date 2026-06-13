use crate::{ReplicaId, View};

/// Default ops between checkpoints (matches a small TB-style interval for fast sim coverage).
pub const DEFAULT_CHECKPOINT_OPS: u64 = 32;
/// Upper bound on the checkpoint interval. It keeps the WAL/pipeline headroom finite (so the maps stay
/// bounded and a checkpoint cannot be outrun by in-flight prepares) AND bounds the HEADER-ONLY
/// view-change band so its carrier fits the transport frame cap, by construction.
///
/// The `DoViewChange` / `StartView` / `RecoveryResponse` log carriers emit every entry HEADER-ONLY
/// (a fixed `PER_HEADER_ENTRY_BYTES` of 49 bytes each — see
/// [`Endpoint::log_entries`](crate::Endpoint)), so a carrier of a `d`-op uncheckpointed band
/// `(checkpoint_op .. op]` encodes to `d × 49 + framing` bytes regardless of body sizes. The deepest such
/// band is bounded by the WAL/checkpoint geometry. The un-checkpointed COMMITTED prefix `commit_min −
/// checkpoint_op` is at most about `2 × checkpoint_ops` (a checkpoint triggers at `checkpoint_op +
/// checkpoint_ops`, and during the async checkpoint window `commit_min` advances by at most another
/// interval before the next trigger). The uncommitted tail `op − commit_min` is at most the WAL ring
/// capacity, which the bounded sims size at `checkpoint_ops × k` (with `k` up to 6) plus headroom (and
/// the capacity contract requires capacity above `checkpoint_ops + pipeline` for liveness either way). So
/// the band depth is at most about `6 × checkpoint_ops + headroom`. Capping `checkpoint_ops` at `2^15`
/// keeps even that worst case (`6 × 2^15 + 8 = 196_616`) at or below
/// `MAX_HEADER_ONLY_BAND_DEPTH` (`(16 MiB − 64) / 49 =
/// 342_391`), so a header-only carrier of the deepest band stays sub-frame-cap regardless of body sizes.
/// (A `2^20` cap would let a `49 × 2^20 ≈ 51 MiB` carrier overflow the 16 MiB frame.)
/// [`Endpoint::log_entries`](crate::Endpoint) additionally `debug_assert`s each band against
/// `MAX_HEADER_ONLY_BAND_DEPTH`, catching a bounded-WAL embedder that sized capacity beyond the `6×`
/// geometry the cap assumes. `DEFAULT_CHECKPOINT_OPS` (32) and the sim's largest interval (about 768) sit
/// far below this cap, so it never clips a realistic configuration.
pub const MAX_CHECKPOINT_OPS: u64 = 1 << 15;

/// Default cap on the client-session table (`Endpoint`'s `clients` map): the maximum number of
/// APPLIED client sessions a replica retains for at-most-once dedup (TigerBeetle's `clients_max`).
///
/// **The eviction contract.** The table rides every checkpoint envelope, so it must stay bounded and
/// replica-deterministic. When applying a committed op would grow the applied-session count past this
/// cap, the session with the OLDEST `last_op` (the op number of its last applied request; ties broken
/// by lowest client id) is EVICTED — at APPLY time, on every replica identically, so the tables (and
/// hence the checkpoint envelopes) never diverge. An EVICTED client loses its dedup watermark and its
/// cached reply: the at-most-once guarantee is **bounded by table residency** (TigerBeetle has the
/// same property). A client that returns after eviction is a NEW session — only its request 1 opens
/// one; a retry of any later request number is silently dropped, so an evicted client must restart
/// its session numbering (re-register) rather than resume. Conversely this is what UN-wedges a client
/// that restarts with a lost request counter: once its stale session is evicted, its fresh `request 1`
/// is accepted instead of being deduped against the old watermark forever.
///
/// Sized so the checkpoint envelope stays reasonable: 4096 sessions at a few hundred bytes each
/// (client id + watermark + one cached reply) keep the session prefix of the envelope in the low MBs
/// even with large replies. Tunable per cluster via [`Config::with_max_client_sessions`] (the value is
/// part of the cluster configuration and MUST be identical on every replica — eviction determinism
/// depends on every replica enforcing the same cap).
pub const MAX_CLIENT_SESSIONS: u32 = 4096;

/// Default cap (bytes) on the checkpoint envelope a state-sync RECEIVER admits from a donor's
/// chunked-transfer announce (`SyncCheckpointMeta.total_len`): 4 GiB.
///
/// **Why a receiver-side cap.** An honest donor derives `total_len` from a VERIFIED read of its own
/// durable checkpoint, but the announce itself is a small wire frame carrying an unproven claim: the
/// receiver sizes its reassembly staging from that claim BEFORE any chunk or hash evidence exists, so
/// a buggy (in-model, crash-fault) peer could claim an absurd length and drive an unbounded
/// allocation. This cap bounds the staging by CONFIGURATION instead of by the wire: an announce above
/// it is IGNORED — never pinned, never displacing a live pin — leaving the sync solicitation armed so
/// a sane donor's next announce proceeds.
///
/// **Why 4 GiB.** The envelope is the bound op (8 bytes) + the client-session table + the SM
/// snapshot. At the default [`MAX_CLIENT_SESSIONS`] (4096) the session prefix reaches the low GiBs
/// only under wildly outsized cached replies (every session holding a near-frame-cap reply), and a
/// state-machine snapshot beyond a few GiB is past what a single stop-and-wait chunked transfer is
/// designed to move. 4 GiB therefore dominates any sane checkpoint while still refusing the
/// pathological claims (up to `u64::MAX`) this gate exists for.
///
/// Tunable per receiver via [`Config::with_max_sync_envelope_len`]. Unlike `max_client_sessions`
/// this is an ADMISSION bound, not a determinism input: replicas may disagree without a safety risk.
/// A receiver whose cap is below the cluster's real checkpoint envelope merely refuses every chunked
/// transfer (its sync stays armed and unsatisfiable until the cap is raised) — it never installs
/// different state.
pub const MAX_SYNC_ENVELOPE_LEN: u64 = 4 * 1024 * 1024 * 1024;

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
    index: u16,
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
  #[error("checkpoint_ops {ops} exceeds the maximum of 2^15")]
  CheckpointOpsTooLarge {
    /// The offending interval.
    ops: u64,
  },
  /// `max_client_sessions` was zero (a zero cap would evict every session at first apply).
  #[error("max_client_sessions must be > 0")]
  ZeroMaxClientSessions,
  /// `max_sync_envelope_len` was zero (no checkpoint envelope is empty, so a zero cap would refuse
  /// every chunked state-sync transfer).
  #[error("max_sync_envelope_len must be > 0")]
  ZeroMaxSyncEnvelopeLen,
}

/// Static cluster configuration for one replica. Immutable in v1
/// (reconfiguration is deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  cluster: u128,
  replica: ReplicaId,
  replica_count: u8,
  checkpoint_ops: u64,
  max_client_sessions: u32,
  max_sync_envelope_len: u64,
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
    if replica.get() >= replica_count as u16 {
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
      max_client_sessions: MAX_CLIENT_SESSIONS,
      max_sync_envelope_len: MAX_SYNC_ENVELOPE_LEN,
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
        max_client_sessions: c.max_client_sessions,
        max_sync_envelope_len: c.max_sync_envelope_len,
      }),
      Err(e) => Err(e),
    }
  }

  /// Returns this configuration with the client-session cap replaced (chainable; consumes the copy).
  /// The cap MUST be identical on every replica of the cluster — eviction is deterministic only when
  /// every replica enforces the same bound (see [`MAX_CLIENT_SESSIONS`] for the eviction contract).
  ///
  /// # Errors
  /// [`ConfigError::ZeroMaxClientSessions`] if `max == 0`.
  pub const fn with_max_client_sessions(self, max: u32) -> Result<Self, ConfigError> {
    if max == 0 {
      return Err(ConfigError::ZeroMaxClientSessions);
    }
    Ok(Self {
      max_client_sessions: max,
      ..self
    })
  }

  /// Returns this configuration with the state-sync envelope admission cap replaced (chainable;
  /// consumes the copy). A `SyncCheckpointMeta` announcing a `total_len` above the cap is ignored,
  /// so the cap must be at least the cluster's real checkpoint envelope size or every chunked
  /// transfer is refused — see [`MAX_SYNC_ENVELOPE_LEN`] for the sizing rationale (a too-small cap
  /// only refuses transfers; it cannot corrupt state).
  ///
  /// # Errors
  /// [`ConfigError::ZeroMaxSyncEnvelopeLen`] if `max == 0`.
  pub const fn with_max_sync_envelope_len(self, max: u64) -> Result<Self, ConfigError> {
    if max == 0 {
      return Err(ConfigError::ZeroMaxSyncEnvelopeLen);
    }
    Ok(Self {
      max_sync_envelope_len: max,
      ..self
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

  /// Ops between checkpoints (a checkpoint is taken when commit_min reaches checkpoint_op + this).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn checkpoint_ops(&self) -> u64 {
    self.checkpoint_ops
  }

  /// The client-session table cap (applied sessions; deterministic apply-time eviction past it).
  /// Defaults to [`MAX_CLIENT_SESSIONS`]; see that constant for the eviction contract.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn max_client_sessions(&self) -> u32 {
    self.max_client_sessions
  }

  /// The state-sync envelope admission cap (bytes): a donor announce (`SyncCheckpointMeta`)
  /// claiming a `total_len` above this is ignored rather than staged. Defaults to
  /// [`MAX_SYNC_ENVELOPE_LEN`]; see that constant for the bound's rationale.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn max_sync_envelope_len(&self) -> u64 {
    self.max_sync_envelope_len
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
    ReplicaId::new((view.get() % self.replica_count as u64) as u16)
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
  fn max_client_sessions_is_validated_and_accessible() {
    let c = Config::try_new(0, ReplicaId::new(0), 3).unwrap();
    assert_eq!(c.max_client_sessions(), MAX_CLIENT_SESSIONS); // the default cap
    let c2 = c.with_max_client_sessions(8).unwrap();
    assert_eq!(c2.max_client_sessions(), 8);
    // the other fields are preserved by the chainable setter
    assert_eq!(c2.replica_count(), 3);
    assert_eq!(c2.checkpoint_ops(), c.checkpoint_ops());
    // a zero cap is rejected (it would evict every session at first apply)
    assert_eq!(
      c.with_max_client_sessions(0),
      Err(ConfigError::ZeroMaxClientSessions)
    );
  }

  #[test]
  fn max_sync_envelope_len_is_validated_and_accessible() {
    let c = Config::try_new(0, ReplicaId::new(0), 3).unwrap();
    assert_eq!(c.max_sync_envelope_len(), MAX_SYNC_ENVELOPE_LEN); // the default cap
    let c2 = c.with_max_sync_envelope_len(1 << 20).unwrap();
    assert_eq!(c2.max_sync_envelope_len(), 1 << 20);
    // the other fields are preserved by the chainable setter
    assert_eq!(c2.replica_count(), 3);
    assert_eq!(c2.max_client_sessions(), c.max_client_sessions());
    // a zero cap is rejected (it would refuse every chunked transfer)
    assert_eq!(
      c.with_max_sync_envelope_len(0),
      Err(ConfigError::ZeroMaxSyncEnvelopeLen)
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

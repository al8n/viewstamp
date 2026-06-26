use crate::MemberId;

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
/// `MAX_HEADER_ONLY_BAND_DEPTH` (`(16 MiB − 80) / 49 =
/// 342_390`), so a header-only carrier of the deepest band stays sub-frame-cap regardless of body sizes.
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

/// Error constructing a [`Config`].
///
/// The cluster-shape invariants (voting count, learner count, member uniqueness) moved to
/// [`Membership`](crate::Membership) — `Config` now validates only the static per-node parameters,
/// so this enum carries only their errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
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
}

/// The static, per-node parameters for one replica: the cluster id, this node's stable
/// [`MemberId`], and the local tuning knobs (checkpoint interval + the two admission caps).
///
/// It is decoupled from the cluster SHAPE — who votes, who leads, the quorum sizes, and this node's
/// slot — which is epoch-versioned and now lives in the active [`Membership`](crate::Membership) the
/// [`Endpoint`](crate::Endpoint) holds. A node is resolved against that membership by its `MemberId`,
/// so a reconfiguration can move it between slots (or remove it) without rewriting its `Config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  cluster: u128,
  local: MemberId,
  checkpoint_ops: u64,
  max_client_sessions: u32,
}

impl Config {
  /// Creates a configuration for one node, identified by its stable [`MemberId`]. The cluster shape
  /// (the voting set, learners, and this node's slot) is supplied separately as the active
  /// [`Membership`](crate::Membership) — `Config` carries only the static per-node parameters.
  ///
  /// This is infallible at the `Config` layer: the only static parameters are caps that default to
  /// valid values and the `MemberId`, which is opaque. The cluster-shape invariants are validated by
  /// [`Membership::genesis`](crate::Membership::genesis).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn try_new(cluster: u128, local: MemberId) -> Result<Self, ConfigError> {
    Ok(Self {
      cluster,
      local,
      checkpoint_ops: DEFAULT_CHECKPOINT_OPS,
      max_client_sessions: MAX_CLIENT_SESSIONS,
    })
  }

  /// Like [`Config::try_new`] but with an explicit checkpoint interval.
  ///
  /// # Errors
  /// [`ConfigError::ZeroCheckpointOps`] if `checkpoint_ops == 0`,
  /// [`ConfigError::CheckpointOpsTooLarge`] if it exceeds [`MAX_CHECKPOINT_OPS`].
  pub const fn with_checkpoint_ops(
    cluster: u128,
    local: MemberId,
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
    Ok(Self {
      cluster,
      local,
      checkpoint_ops,
      max_client_sessions: MAX_CLIENT_SESSIONS,
    })
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

  /// Returns this configuration with the checkpoint interval replaced (chainable; consumes the copy).
  /// The interval MUST be identical on every replica of the cluster. This is the path to set a
  /// non-default interval on a config built via [`Config::try_new`],
  /// mirroring the interval [`Config::with_checkpoint_ops`] takes at construction.
  ///
  /// # Errors
  /// [`ConfigError::ZeroCheckpointOps`] if `checkpoint_ops == 0`; [`ConfigError::CheckpointOpsTooLarge`]
  /// if it exceeds [`MAX_CHECKPOINT_OPS`].
  pub const fn with_checkpoint_interval(self, checkpoint_ops: u64) -> Result<Self, ConfigError> {
    if checkpoint_ops == 0 {
      return Err(ConfigError::ZeroCheckpointOps);
    }
    if checkpoint_ops > MAX_CHECKPOINT_OPS {
      return Err(ConfigError::CheckpointOpsTooLarge {
        ops: checkpoint_ops,
      });
    }
    Ok(Self {
      checkpoint_ops,
      ..self
    })
  }

  /// The cluster id.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn cluster(&self) -> u128 {
    self.cluster
  }

  /// This node's stable [`MemberId`]. A node is resolved against the active
  /// [`Membership`](crate::Membership) by this id (which slot it occupies, or whether it has been
  /// removed), so it survives a reconfiguration that moves the node between slots.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn local(&self) -> MemberId {
    self.local
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
}

#[cfg(test)]
mod tests;

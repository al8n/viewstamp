//! Deterministic, single-threaded simulation harness for `viewstamp-proto`.
//!
//! Runs N endpoints + client models in one thread over a typed-message virtual
//! network with a virtual clock and one seeded PRNG, so a whole cluster is a
//! deterministic function of its seed.

pub mod batching;
pub mod block_store;
pub mod checker;
pub mod client;
pub mod clock;
pub mod cluster;
pub mod network;
pub mod sm;
pub mod storage;
pub mod vopr;

pub use batching::{BatchingConfig, check_batching};
pub use block_store::MemBlockStore;
pub use checker::{
  AppliedOnceChecker, BoundednessChecker, CheckResult, ConfigLineageChecker, DurabilityChecker,
  DurableQuorumChecker, EpochViewMonotonicChecker, MembershipMonotonicChecker,
  ReconfigureAppliedOnceChecker, StalenessChecker, ViewMonotonicChecker, check_safety,
};
pub use cluster::{AppliedEvent, Cluster, OfflineReconfig};
pub use network::{Faults, SlowProfile};
pub use storage::{InMemorySuperblock, InMemoryWal, StorageFaults};
pub use vopr::{
  DEFAULT_TICKS, VoprReport, run_vopr, run_vopr_one, run_vopr_with_asym, run_vopr_with_batching,
  run_vopr_with_block_delay, run_vopr_with_block_faults, run_vopr_with_churn, run_vopr_with_hold,
  run_vopr_with_learners, run_vopr_with_reconfig, run_vopr_with_reconfig_live,
  run_vopr_with_restart_in_place, run_vopr_with_sb_reorder, run_vopr_with_slow,
  run_vopr_with_stale_read, run_vopr_with_swap_root_rebuild, run_vopr_with_torn_headers,
  run_vopr_with_wipe, run_vopr_with_wipe_learners, run_vopr_with_write_chaos,
};

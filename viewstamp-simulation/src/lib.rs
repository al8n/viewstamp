//! Deterministic, single-threaded simulation harness for `viewstamp-proto`.
//!
//! Runs N endpoints + client models in one thread over a typed-message virtual
//! network with a virtual clock and one seeded PRNG, so a whole cluster is a
//! deterministic function of its seed.

pub mod checker;
pub mod client;
pub mod clock;
pub mod cluster;
pub mod network;
pub mod sm;
pub mod storage;
pub mod vopr;

pub use checker::{
  BoundednessChecker, CheckResult, DurabilityChecker, ViewMonotonicChecker, check_safety,
};
pub use cluster::Cluster;
pub use network::Faults;
pub use storage::{InMemorySuperblock, InMemoryWal, StorageFaults};
pub use vopr::{DEFAULT_TICKS, VoprReport, run_vopr, run_vopr_one};

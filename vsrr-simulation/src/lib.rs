//! Deterministic, single-threaded simulation harness for `vsrr-proto`.
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

pub use cluster::Cluster;
pub use network::Faults;

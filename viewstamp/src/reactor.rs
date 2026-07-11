//! The runtime-agnostic reactor (tokio / smol) QUIC and TCP/TLS drivers.
//!
//! Re-export of [`viewstamp_reactor`]: readiness-I/O drivers generic over any
//! [`agnostic::Runtime`]. For a runtime already chosen, prefer the `crate::tokio` / `crate::smol`
//! modules, which pin `R` so callers never name it.

pub use viewstamp_reactor::*;

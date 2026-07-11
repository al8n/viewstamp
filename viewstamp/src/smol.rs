//! viewstamp on the smol runtime (via the runtime-agnostic reactor drivers).
//!
//! The full [`viewstamp_reactor`] surface is re-exported, with the runtime pinned to smol so
//! callers never name the `R` parameter. The unpinned drivers stay available under the
//! `crate::reactor` module.

pub use viewstamp_reactor::*;

/// The runtime these aliases bind.
pub type Runtime = agnostic::smol::SmolRuntime;

/// A smol-backed QUIC driver — [`viewstamp_reactor::ReactorQuicDriver`] with its runtime pinned
/// to smol.
pub type ReactorQuicDriver<S, W, B, L, I> =
  viewstamp_reactor::ReactorQuicDriver<Runtime, S, W, B, L, I>;

/// A smol-backed TCP/TLS stream driver — [`viewstamp_reactor::ReactorStreamDriver`] with its
/// runtime pinned to smol.
pub type ReactorStreamDriver<S, T, W, B, L> =
  viewstamp_reactor::ReactorStreamDriver<Runtime, S, T, W, B, L>;

//! viewstamp on the tokio runtime (via the runtime-agnostic reactor drivers).
//!
//! The full [`viewstamp_reactor`] surface is re-exported, with the runtime pinned to tokio so
//! callers never name the `R` parameter. The unpinned drivers stay available under the
//! `crate::reactor` module.

pub use viewstamp_reactor::*;

/// The runtime these aliases bind.
pub type Runtime = agnostic::tokio::TokioRuntime;

/// A tokio-backed QUIC driver — [`viewstamp_reactor::ReactorQuicDriver`] with its runtime pinned
/// to tokio.
pub type ReactorQuicDriver<S, W, B, L, I> =
  viewstamp_reactor::ReactorQuicDriver<Runtime, S, W, B, L, I>;

/// A tokio-backed TCP/TLS stream driver — [`viewstamp_reactor::ReactorStreamDriver`] with its
/// runtime pinned to tokio.
pub type ReactorStreamDriver<S, T, W, B, L> =
  viewstamp_reactor::ReactorStreamDriver<Runtime, S, T, W, B, L>;

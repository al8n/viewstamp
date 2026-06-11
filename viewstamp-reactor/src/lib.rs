//! Reactor-I/O (readiness) QUIC driver for `viewstamp-proto`.
//!
//! One task owns a [`viewstamp_proto::QuicCoordinator`] plus the embedder's
//! [`viewstamp_proto::Wal`]/[`viewstamp_proto::Superblock`] and a UDP socket, and drives
//! consensus over real sockets on any runtime implementing [`agnostic::Runtime`] — tokio or smol,
//! pulled in by this crate's `tokio`/`smol` features (the driver itself is generic over the
//! runtime parameter and compiles against the abstraction alone). The driver is generic over the
//! state machine, storage, and identity source — it bundles no backend.
//!
//! One consensus group is one serial state machine: a single [`ReactorQuicDriver`] owns its
//! endpoint, storage, and socket, and `run()` drives them as ONE task — the driver spawns
//! nothing. The `run()` future is `Send` (given `Send` state-machine/storage/identity types), so
//! a multi-threaded runtime schedules or migrates it like any other task; parallelism comes from
//! running N independent consensus groups as N driver tasks. A [`Handle`] is the cross-thread
//! surface — `Send + Sync` and O(1) to clone, so any thread may `submit` to any group and await
//! the committed reply.

mod driver;

pub use driver::ReactorQuicDriver;
pub use viewstamp_driver::{Clock, Command, DriverConfig, DriverError, Handle, Reply};

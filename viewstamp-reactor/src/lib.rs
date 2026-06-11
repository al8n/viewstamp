//! Reactor-I/O (readiness) QUIC and TCP/TLS drivers for `viewstamp-proto`.
//!
//! One task owns a [`viewstamp_proto::QuicCoordinator`] ([`ReactorQuicDriver`]) or a
//! [`viewstamp_proto::StreamCoordinator`] ([`ReactorStreamDriver`]) plus the embedder's
//! [`viewstamp_proto::Wal`]/[`viewstamp_proto::Superblock`] and its socket, and drives
//! consensus over real sockets on any runtime implementing [`agnostic::Runtime`] — tokio or smol,
//! pulled in by this crate's `tokio`/`smol` features (the drivers themselves are generic over the
//! runtime parameter and compile against the abstraction alone). The drivers are generic over the
//! state machine, storage, and (for QUIC) identity source — they bundle no backend, and all
//! TLS/framing lives in-process in the proto coordinators; the drivers only move raw bytes.
//!
//! One consensus group is one serial state machine: a single driver owns its endpoint, storage,
//! and socket, and `run()` drives them as ONE task — the QUIC driver spawns nothing, and the
//! stream driver spawns only per-connection read/write bridge tasks (plus dial tasks) whose
//! handles it owns abort-on-drop, so they die with their connection. The `run()` future is `Send`
//! (given `Send` state-machine/storage/identity types), so a multi-threaded runtime schedules or
//! migrates it like any other task; parallelism comes from running N independent consensus groups
//! as N driver tasks. A [`Handle`] is the cross-thread surface — `Send + Sync` and O(1) to clone,
//! so any thread may `submit` to any group and await the committed reply.

mod bridge;
mod driver;
mod stream_driver;
mod task;

pub use driver::ReactorQuicDriver;
pub use stream_driver::ReactorStreamDriver;
pub use viewstamp_driver::{Clock, Command, DriverConfig, DriverError, Handle, Reply};

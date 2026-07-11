#![doc(html_logo_url = "https://raw.githubusercontent.com/al8n/viewstamp/main/art/logo_72x72.png")]
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
//! # Scaling across cores
//!
//! One consensus group is one serial state machine: a single driver owns its endpoint, storage,
//! and socket, and `run()` drives them as ONE task — the QUIC driver spawns nothing, and the
//! stream driver spawns only per-connection read/write bridge tasks (plus dial tasks) whose
//! handles it owns abort-on-drop, so they die with their connection. There is no parallelism
//! inside a group, and none would help: consensus applies committed operations in log order, so
//! one group's throughput ceiling is one core by design.
//!
//! Unlike the compio drivers, whose `!Send` tasks are pinned to the thread that spawned them, the
//! `run()` future is `Send` (given `Send` state-machine/storage/identity types): a work-stealing
//! multi-threaded runtime schedules or migrates it like any other task, and the group stays
//! serial because it is one task, not because of any thread pinning. Scale-out is N INDEPENDENT
//! groups as N driver tasks on one shared runtime — each driver binds its own socket/port, owns
//! its own WAL/superblock store, and forms its own replica mesh, so groups share nothing and the
//! runtime spreads them across cores. For explicit core pinning, run N single-thread runtimes
//! (e.g. tokio's `current_thread` flavor, one per pinned core) with one driver task each; the
//! caveat is that a socket must be polled by the runtime that registered it, and construction
//! binds the sockets, so construct AND `run()` a driver inside the runtime that owns it — never
//! build it on one runtime and ship it to another.
//!
//! [`Handle`]s are the cross-thread surface: a `Handle` is `Send + Sync` and O(1) to clone, so
//! any thread may `submit` to any group and await the committed reply — the bounded command
//! channel and the per-submit reply channel do the crossing.

mod bridge;
mod driver;
mod stream_driver;
mod task;

pub use driver::ReactorQuicDriver;
pub use stream_driver::ReactorStreamDriver;
pub use viewstamp_driver::{Clock, Command, DriverConfig, DriverError, Handle, Reply};

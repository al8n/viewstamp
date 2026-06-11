//! Proactor (compio) QUIC driver for `viewstamp-proto`.
//!
//! A single compio task owns a [`viewstamp_proto::QuicCoordinator`] plus the embedder's
//! [`viewstamp_proto::Wal`]/[`viewstamp_proto::Superblock`] and a UDP socket, and drives consensus
//! over real I/O. The driver is generic over the state machine, storage, and identity source — it
//! bundles no backend.
//!
//! # Scaling across cores
//!
//! One consensus group is one serial state machine: a single [`CompioQuicDriver`] /
//! [`CompioStreamDriver`] owns its endpoint, storage, and socket, and `run()` drives them on one
//! thread. The compio runtime's `spawn` takes plain `!Send` futures and never migrates a task, so
//! every task a driver creates — the run loop, its persistent recv/accept task, the per-connection
//! bridges — stays on the thread that spawned it, by construction. There is no parallelism inside
//! a group, and none would help: consensus applies committed operations in log order, so one
//! group's throughput ceiling is one core by design.
//!
//! Scale-out is therefore N INDEPENDENT groups, not more threads in one group: one driver plus
//! one compio `Runtime` per thread (optionally pinned to a core via the runtime builder's
//! `thread_affinity`), each driver binding its own socket/port and forming its own replica mesh.
//! Groups share nothing — separate endpoints, separate WAL/superblock stores, separate sockets —
//! so N groups scale to N cores with no cross-group coordination.
//!
//! [`Handle`]s are the only objects meant to cross threads: a `Handle` is `Send + Sync` and O(1)
//! to clone, so any thread may `submit` to any group and await the committed reply — the bounded
//! command channel and the per-submit reply channel do the crossing.
//!
//! The one footgun: a compio socket attaches to the proactor of the thread that CONSTRUCTS it,
//! exactly once, so each driver must be constructed AND run on its own thread — build it inside
//! that thread's `Runtime` (e.g. at the top of its `block_on`), never on a coordinator thread
//! that then ships it elsewhere. The stream driver enforces this structurally: its `Rc`
//! connection factories make the driver `!Send`, so it cannot leave the thread that built it. The
//! QUIC driver has no equivalent structural guard, so keeping construction and `run()` on one
//! thread is the embedder's contract there. (A runnable multi-group example is future work; the
//! single-group embedding is `examples/three_node.rs`.)

mod bridge;
mod driver;
mod stream_driver;

pub use driver::CompioQuicDriver;
pub use stream_driver::CompioStreamDriver;
pub use viewstamp_driver::{Clock, Command, DriverConfig, DriverError, Handle, Reply};

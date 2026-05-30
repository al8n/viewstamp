//! Sans-I/O state machine for the Viewstamped Replication protocol.
//!
//! Modeled on `quinn-proto`: a pure state machine that takes events as inputs
//! (`handle_*`) and emits actions as outputs (`poll_*`), owning no I/O, no clock,
//! and no randomness source. TigerBeetle's `src/vsr/replica.zig` is the
//! correctness reference for the protocol logic.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

// no_std switch: alias `alloc` to the name `std` so genuine-heap `std::` paths
// (Vec, String, BTreeMap, …) resolve to their `alloc::` home unchanged in
// no_std+alloc builds, and to real `std` when the `std` feature is on.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

mod config;
mod endpoint;
mod event;
mod id;
mod message;
mod number;
mod prng;
mod state_machine;
mod status;
mod storage;
mod time;
pub use config::{Config, ConfigError, DEFAULT_CHECKPOINT_OPS, MAX_CHECKPOINT_OPS};
pub use endpoint::Endpoint;
pub use event::{Committed, Event};
pub use id::{ClientId, Peer, Recipient, ReplicaId};
pub use message::{
  Commit, DoViewChange, GetView, Message, Outgoing, Prepare, PrepareOk, PreparedEntry, Recovery,
  RecoveryResponse, Reply, Request, RequestPrepare, StartView, StartViewChange,
};
pub use number::{OpNumber, RequestNumber, View};
pub use prng::Prng;
pub use state_machine::StateMachine;
pub use status::Status;
pub use storage::{
  CheckpointRead, HEADER_VERSION, Header, OpId, ReadOk, SlotStatus, Superblock, SuperblockDone,
  VsrState, VsrStateError, Wal, WalDone, checkpoint_id,
};
pub use time::Instant;

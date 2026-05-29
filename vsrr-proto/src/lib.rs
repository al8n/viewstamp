//! Sans-I/O state machine for the Viewstamped Replication protocol.
//!
//! Modeled on `quinn-proto`: a pure state machine that takes events as inputs
//! (`handle_*`) and emits actions as outputs (`poll_*`), owning no I/O, no clock,
//! and no randomness source. TigerBeetle's `src/vsr/replica.zig` is the
//! correctness reference for the protocol logic.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// Modules are declared here as empty placeholders in this task. Each later task
// fills its module and appends the matching `pub use` re-export. Do NOT add any
// `pub use` lines now — the modules are empty.
mod config;
mod endpoint;
mod event;
mod id;
mod message;
mod number;
mod prng;
mod state_machine;
mod status;
mod time;
pub use config::Config;
pub use endpoint::Endpoint;
pub use event::Event;
pub use id::{ClientId, Peer, Recipient, ReplicaId};
pub use message::{Commit, Message, Outgoing, Prepare, PrepareOk, Reply, Request};
pub use number::{OpNumber, RequestNumber, View};
pub use prng::Prng;
pub use state_machine::StateMachine;
pub use status::Status;
pub use time::Instant;

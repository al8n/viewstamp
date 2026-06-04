//! Sans-I/O state machine for the Viewstamped Replication protocol.
//!
//! Modeled on `quinn-proto`: a pure state machine that takes events as inputs
//! (`handle_*`) and emits actions as outputs (`poll_*`), owning no I/O, no clock,
//! and no randomness source. TigerBeetle's `src/vsr/replica.zig` is the
//! correctness reference for the protocol logic.
//!
//! # Threat model (non-Byzantine, crash-fault-tolerant)
//!
//! vsrr is a **crash-fault-tolerant** Viewstamped Replication implementation for a **TRUSTED**
//! cluster — exactly like TigerBeetle, and explicitly **NOT** a Byzantine-fault-tolerant /
//! blockchain system. Authenticating a replica message's sender is the **DRIVER's** responsibility:
//! the driver sets the `from: Peer` it passes to [`Endpoint::handle_message`] to the AUTHENTICATED
//! transport peer (mirroring TigerBeetle's `message_bus.zig` `set_and_verify_peer`), and the proto
//! TRUSTS that `from`. As a cheap **defense-in-depth** backstop, `handle_message`'s ingress binds each
//! message's own self-claimed sender to `from` and drops any mismatch, so a BUGGY or misrouting driver
//! (or a trivially-mislabeled message) cannot let a forged/misrouted message spoof a quorum vote — the
//! ingress analogue of the single egress emission chokepoint. Full message authentication against a
//! genuinely MALICIOUS sender (cryptographic signatures, Byzantine fault tolerance) is **OUT OF
//! SCOPE** — a BFT/blockchain concern, not a crash-fault-tolerant one.
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

mod codec;
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
#[cfg(feature = "tcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcp")))]
mod transport;
pub use codec::{CodecError, WIRE_VERSION};
pub use config::{Config, ConfigError, DEFAULT_CHECKPOINT_OPS, MAX_CHECKPOINT_OPS};
pub use endpoint::Endpoint;
pub use event::{Committed, Event};
pub use id::{ClientId, Peer, Recipient, ReplicaId};
pub use message::{
  Commit, DoViewChange, GetView, Message, Outgoing, Prepare, PrepareOk, PreparedEntry, Recovery,
  RecoveryResponse, Reply, Request, RequestPrepare, RequestSync, StartView, StartViewChange,
  SyncCheckpoint,
};
pub use number::{OpNumber, RequestNumber, View};
pub use prng::Prng;
pub use state_machine::StateMachine;
pub use status::Status;
pub use storage::{
  CheckpointRead, HEADER_ENCODED_LEN, HEADER_VERSION, Header, OpId, ReadOk, SlotStatus, Superblock,
  SuperblockDone, VsrState, VsrStateError, Wal, WalDone, checkpoint_id,
};
pub use time::Instant;
#[cfg(feature = "tcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcp")))]
pub use transport::{
  Conn, ConnId, Intake, LabelOptions, Labeled, Passthrough, PeerRouter, StreamCoordinator,
  StreamTransport, TransportError,
};
#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use transport::{TlsOptions, TlsRecords};

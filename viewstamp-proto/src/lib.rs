#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/al8n/viewstamp/main/art/logo_72x72.png")]
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

mod batch;
mod block_store;
mod codec;
mod config;
mod endpoint;
mod event;
mod id;
mod membership;
mod message;
mod number;
mod prng;
mod reconfigure_plan;
mod state_machine;
mod status;
mod storage;
mod time;
#[cfg(feature = "tcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcp")))]
mod transport;
mod wire;
pub use batch::{
  BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchBuilder, BatchFull, BatchMalformed, BatchUnits,
  BatchView, EmptyBatch, ReplyBuilder, ReplyPushError, ReplyView,
};
pub use block_store::{BlockAddress, BlockDagWalk, BlockStore, BlockStoreError, block_address};
pub use codec::CodecError;
pub use config::{
  Config, ConfigError, DEFAULT_CHECKPOINT_OPS, MAX_CHECKPOINT_OPS, MAX_CLIENT_SESSIONS,
};
pub use endpoint::{
  Endpoint, FormatError, Genesis, ProposeMembershipError, Reconfig, ReconfigError, RecoverError,
  Recovered, RestartOnly, Retired, SingleChange, format, prepare_restart,
};
pub use event::{Committed, Event, MembershipChanged, RepairStarted, ViewChanged};
pub use id::{ClientId, Epoch, MemberId, Peer, Recipient, ReplicaId};
pub use membership::{AcceptReducedFaultTolerance, Membership, MembershipError, SingleVoterDelta};
pub use message::{
  BlockResponse, Commit, DoViewChange, EpochAhead, GetView, HealthProof, LearnerProof,
  LearnerStatus, Message, Nack, Outgoing, Prepare, PrepareBatch, PrepareOk, PreparedEntry,
  REPLY_ENCODE_OVERHEAD, ReconfigurePayload, Recovery, RecoveryResponse, RepairBatch, Reply,
  Request, RequestHealthProof, RequestLearnerProof, RequestPrepare, RequestPrepareRange,
  RequestSync, StartView, StartViewChange, SyncCheckpoint, max_reply_body_len,
};
pub use number::{OpNumber, RequestNumber, View};
pub use prng::Prng;
pub use reconfigure_plan::{
  MembershipTarget, PlanError, plan_next_step, plan_reconfiguration, shrink_candidates,
};
pub use state_machine::{RestoreError, StateMachine};
pub use status::Status;
pub use storage::{
  BodyFaulty, CheckpointRead, HEADER_ENCODED_LEN, HEADER_VERSION, Header, OpId, ReadId, ReadOk,
  SUPERBLOCK_VERSION, SlotStatus, Superblock, SuperblockDone, VsrState, VsrStateError, Wal,
  WalDone, WriteId, checkpoint_id,
};
pub use time::Instant;
#[cfg(feature = "quic")]
#[cfg_attr(docsrs, doc(cfg(feature = "quic")))]
pub use transport::{
  AttestedId, CertOid, ClusterTls, DEFAULT_CONNECTION_RECEIVE_WINDOW, DEFAULT_IDLE_TIMEOUT_MILLIS,
  DEFAULT_INITIAL_RTT_MILLIS, DEFAULT_STREAM_RECEIVE_WINDOW, DialError, Hello, Identified,
  IdentityConfig, IdentityCtx, IdentityOutcome, IdentitySource, ProvidedIdentity, QuicCoordinator,
  QuicOptions, QuicTuning, StreamLayout,
};
#[cfg(feature = "tcp")]
#[cfg_attr(docsrs, doc(cfg(feature = "tcp")))]
pub use transport::{
  CloseCause, Conn, ConnId, Intake, LabelOptions, Labeled, MAX_FRAME_LEN, Passthrough, PeerRouter,
  StreamCoordinator, StreamTransport, TransportError, max_request_body_len,
};
#[cfg(feature = "tls")]
#[cfg_attr(docsrs, doc(cfg(feature = "tls")))]
pub use transport::{TlsOptions, TlsRecords};
pub use wire::{decode_message, encode_message};

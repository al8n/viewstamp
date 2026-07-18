//! The reconfiguration capability seam and the offline-restart successor-root helper.
//!
//! Offline reconfiguration is OPERATOR-COORDINATED: the whole cluster is stopped, a
//! successor durable root is pre-written on every node by [`prepare_restart`], and the cluster is
//! restarted into the new [`Membership`](crate::Membership). There is no online consensus on the
//! change at [`RestartOnly`] — that is the [`SingleChange`] work, over which a driver-level
//! decompose planner delivers arbitrary-target reconfiguration by sequencing single-member deltas.
//!
//! The capability is a COMPILE-TIME type-state: [`Endpoint`](crate::Endpoint)`<S, R: Reconfig>`
//! carries a zero-sized `R` marker so a future online-reconfiguration API surface gates on it
//! statically. The marker DEFAULTS to [`RestartOnly`], so the bare `Endpoint<S>` spelling keeps
//! resolving and every existing call site compiles unchanged. The variants ([`RestartOnly`],
//! [`SingleChange`]) form a capability ladder; a stronger marker subsumes a weaker one's surface.

use std::vec::Vec;

use crate::{
  id::{Epoch, MemberId},
  membership::MembershipError,
  storage::{VsrState, VsrStateError},
};

mod sealed {
  /// Seals [`super::Reconfig`]: only the types in this crate that implement this private supertrait
  /// can implement `Reconfig`, so a downstream crate cannot add its own capability marker.
  pub trait Sealed {}
}

/// The reconfiguration capability marker selecting an [`Endpoint`](crate::Endpoint)'s membership-change
/// surface at compile time. [`RestartOnly`] is the offline-restart base; [`SingleChange`] adds the
/// online single-member-delta surface. The capability ladder is two consensus rungs (RestartOnly ⊂
/// SingleChange); arbitrary membership change is a pure-policy planner over SingleChange, not a third rung.
///
/// Sealed: implementable only inside this crate (a private `Sealed` supertrait), so a downstream
/// crate cannot mint its own capability marker.
pub trait Reconfig: sealed::Sealed {}

/// The offline-restart reconfiguration capability: the cluster is stopped, a successor
/// durable root is pre-written by [`prepare_restart`], and every node restarts into the new
/// configuration. The base [`Reconfig`] variant and the DEFAULT marker on
/// [`Endpoint`](crate::Endpoint) — so `Endpoint<S>` is `Endpoint<S, RestartOnly>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestartOnly;

impl sealed::Sealed for RestartOnly {}
impl Reconfig for RestartOnly {}

/// The online single-member-change reconfiguration capability: one voter/learner is added or
/// removed per change while the cluster stays up, the change driven through consensus. An
/// [`Endpoint`](crate::Endpoint)`<S, SingleChange>` opts into that surface; it subsumes
/// [`RestartOnly`]'s offline-restart capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SingleChange;

impl sealed::Sealed for SingleChange {}
impl Reconfig for SingleChange {}

/// An error building the offline-restart successor durable root in [`prepare_restart`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReconfigError {
  /// `cur` carried no membership — a membership-less root that predates the configuration epoch. A
  /// membership-less root has no `config_id` lineage to chain the successor from, so it cannot be
  /// reconfigured offline; bring the cluster up once (which migrates it to a root carrying the
  /// genesis membership) before pre-writing a successor.
  #[error("cannot reconfigure a membership-less root: it has no config_id lineage to chain")]
  NoMembership,
  /// The requested successor membership was structurally invalid (zero `replica_count`, too many
  /// voters, a member-count mismatch, or a duplicate member). Carries the underlying
  /// [`MembershipError`].
  #[error("successor membership is invalid: {0}")]
  Membership(#[from] MembershipError),
  /// The successor durable root failed the [`VsrState`] frontier/epoch invariants. Carries the
  /// underlying [`VsrStateError`]. Not reachable for a well-formed `cur` (the successor reuses
  /// `cur`'s already-validated consensus frontier and a freshly-chained membership whose epoch
  /// matches by construction); surfaced rather than panicked so a corrupt `cur` degrades cleanly.
  #[error("successor durable root is invalid: {0}")]
  State(#[from] VsrStateError),
}

/// An error rejecting a live single-member reconfiguration proposal in
/// [`Endpoint::propose_membership`](crate::Endpoint::propose_membership).
///
/// The proposal is single-writer: only the primary, only while `Normal`, and only one change in
/// flight at a time. `Invalid` carries the underlying [`MembershipError`] from validating the delta.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProposeMembershipError {
  /// This replica is not the primary; only the primary proposes a reconfiguration (the client/operator
  /// retries against the primary).
  #[error("not the primary: only the primary proposes a reconfiguration")]
  NotPrimary,
  /// This replica's status is not `Normal` (it is mid-view-change or recovering); a reconfiguration op
  /// can only be minted from a `Normal` primary.
  #[error("not in the Normal status: a reconfiguration is proposed only while Normal")]
  NotNormal,
  /// A reconfiguration op is already in flight (uncommitted). Only one membership change is in flight
  /// at a time — the single-writer latch — so the proposer awaits the in-flight change's commit before
  /// proposing the next.
  #[error("a reconfiguration is already in flight")]
  AlreadyInFlight,
  /// The single-voter delta was invalid for the current configuration (an unknown/duplicate member, a
  /// promotion of a non-learner, or the removal of the last voter). Carries the underlying
  /// [`MembershipError`].
  #[error("the membership delta is invalid: {0}")]
  Invalid(#[from] MembershipError),
  /// A `PromoteLearner` has NO fresh validated catch-up proof yet: the gate solicited a
  /// `RequestLearnerProof` from the target (or is awaiting the matching `LearnerProof`), so it cannot
  /// safely mint the promotion this turn. RETRYABLE — exactly the existing transient-retry contract of
  /// [`Self::Busy`]/[`Self::AtCapacity`]: the caller retries, and once the learner's fresh
  /// `LearnerProof` reports a contiguous applied frontier covering the head the retry mints the op. A
  /// regressed / stale-nonce / cross-epoch / missing reply keeps the gate returning this (fail-closed),
  /// so a learner that honestly fell below a repair hole across a crash is never promoted on a banked
  /// stale-high self-report. The safety input is the FRESH proof re-grounded in the learner's durable
  /// storage at propose time, never an accumulated frontier.
  #[error("the learner-promotion proof is pending: a fresh catch-up proof was solicited — retry")]
  ProofPending,
  /// A direct `AddVoter` is not an accepted proposal, at ANY cluster size. A brand-new voter holds NO
  /// committed prefix — it was never a member, so it never appended, let alone committed, any prior op —
  /// yet as a voter it counts toward the successor's view-change quorum. A successor view-change quorum
  /// formed WITHOUT the prefix-holding retained voters can then elect a leader that drops a committed op:
  /// the old-write-quorum / new-view-change-quorum intersection fails. The extreme is the single-voter
  /// predecessor, where `AddVoter` yields a 2-voter successor with `quorum_view_change == 1`, so the new
  /// voter alone forms the E+1 view-change quorum and can elect itself with an empty log. Rather than
  /// admit the larger sizes and reject only that extreme, every direct `AddVoter` is rejected uniformly.
  /// The safe way to add a voter — at any size — is `AddLearner` the member, let it durably catch up to
  /// the head, then `PromoteLearner`, so the promote-time challenge proves it holds the committed prefix
  /// before it ever votes (the catch-up-then-promote path). The planner never emits `AddVoter`; it only
  /// ever stages that learner-first path.
  #[error(
    "a direct AddVoter is not supported: a brand-new voter holds no committed prefix and could break \
     the cross-config quorum intersection — add the member as a learner (AddLearner), catch it up, \
     then promote it (PromoteLearner)"
  )]
  DirectAddVoterUnsupported,
  /// A TRANSIENT op-admission fence is up — the SAME backpressure a client request hits before a new op
  /// is minted: a pending durable-view / state-sync / checkpoint write, a flagged forfeit step-down, or a
  /// committed-but-unapplied prefix (a repair hole). Minting now would advertise an op in a view this node
  /// may roll back, reuse an op number a reset is about to free, or double-execute a retry. RETRYABLE: the
  /// proposer retries once the in-flight work settles (it is not a permanent rejection). The catch-all for
  /// the non-capacity transient fences (capacity backpressure is the separate [`Self::AtCapacity`]).
  #[error(
    "a transient op-admission fence is up (a pending write, a step-down, or a commit gap) — retry"
  )]
  Busy,
  /// The accepted-but-uncommitted pipeline OR the bounded WAL / view-change-carrier band is at capacity:
  /// minting the next op would overflow the WAL ring or push the carrier band past its frame-fit depth —
  /// the SAME physical back-pressure the client-request path applies. RETRYABLE: it self-releases as the
  /// quorum checkpoints forward and the GC frees slots, so the proposer retries.
  #[error("the op pipeline / WAL is at capacity — retry once the cluster checkpoints forward")]
  AtCapacity,
}

/// Push a just-superseded `config_id` onto a recent-prior lineage `ring` (most-recent-first), bounded to
/// the [`LINEAGE_RING`](super::LINEAGE_RING) width — the durable-root analogue of the endpoint's in-memory
/// `push_lineage`, operating on the decoded `prior_config_ids` of a durable root. The result is the
/// successor's lineage: `superseded` first, then the most-recent retained ids, truncated to the ring width.
fn push_lineage_ring(ring: &[u128], superseded: u128) -> Vec<u128> {
  let mut out = Vec::with_capacity(super::LINEAGE_RING);
  out.push(superseded);
  out.extend(
    ring
      .iter()
      .copied()
      .take(super::LINEAGE_RING.saturating_sub(1)),
  );
  out
}

/// Builds the SUCCESSOR durable root for an offline, operator-coordinated restart.
///
/// The operator pre-writes this root on every node while the cluster is stopped; the node then
/// restarts into the successor membership. It chains the new configuration off `cur`'s membership
/// via [`Membership::reconfigure`](crate::Membership::reconfigure) (the epoch bumps, the `config_id` chains) and carries ALL of
/// `cur`'s consensus frontier UNCHANGED — view, log_view, commit, checkpoint_op, checkpoint_id, and
/// the committed-band headers — so a coordinated restart changes ONLY the configuration, never the
/// replicated log.
///
/// The ONLINE install fence (a committed `Reconfigure` op may not seat a brand-new voter — see
/// `Membership::first_new_voter`) deliberately does NOT apply to this offline lane: here the
/// pre-written root itself is the committed-prefix evidence. It carries `cur`'s commit frontier and
/// committed-band headers verbatim on EVERY node — a freshly added voter included — so a restarted
/// voter proves the committed prefix in a view change from its own durable root rather than from a
/// replicated history, and the operator may stage an arbitrary successor.
///
/// The resulting [`VsrState`] is a membership-bearing root whose scalar `epoch` is the successor
/// membership's epoch, whose `prev_epoch` is `cur.epoch()` (the durable backward link of the
/// lineage), and whose membership is the successor.
///
/// # Precondition: seal the committed frontier, then stop from a quiesced cluster
///
/// The successor copies `cur.commit()` — the DURABLE-root commit, which lags the live `commit_max`
/// between checkpoints. The operator MUST therefore call
/// [`Endpoint::seal_committed_frontier`](crate::Endpoint::seal_committed_frontier) on every node and
/// await its superblock write BEFORE reading the root passed here, so `cur.commit()` is the true
/// committed frontier. Without the seal, a coordinated restart can strand a committed op that sits
/// above every node's stale durable commit (no peer holds a higher commit to repair from).
///
/// The operator MUST also stop the cluster from a QUIESCED state — every voter `Normal` at a COMMON
/// view. Because the successor preserves each node's own `view`,
/// a quiesced stop leaves every node at the same view, so if a head-fault wave on the restart drives
/// a voting quorum into `RecoveringHead`, they all escalate to the SAME next view and the cluster
/// re-forms. Stopping mid-view-change — leaving a `>= 2` view stagger across the voting set — is OUT
/// OF CONTRACT: each wedged node would escalate to its own `view + 1` with no agreed target and the
/// re-formation could fail to converge. (A no-stagger stop is the standard operator model; the
/// committed prefix is preserved unconditionally either way.)
///
/// # Errors
///
/// - [`ReconfigError::NoMembership`] if `cur` is a membership-less root — it has no
///   `config_id` lineage to chain a successor from.
/// - [`ReconfigError::Membership`] if `(replica_count, learner_count, members)` is structurally
///   invalid.
/// - [`ReconfigError::State`] if the successor root fails the [`VsrState`] invariants (not reachable
///   for a well-formed `cur`).
pub fn prepare_restart(
  cur: &VsrState,
  replica_count: u8,
  learner_count: u16,
  members: Vec<MemberId>,
) -> Result<VsrState, ReconfigError> {
  let current = cur.membership_opt().ok_or(ReconfigError::NoMembership)?;
  let successor = current.reconfigure(replica_count, learner_count, members)?;
  let prev_epoch: Epoch = cur.epoch();
  let epoch = successor.epoch();
  // The successor's recent-prior lineage: the predecessor (`cur`'s) `config_id` shifted onto the front of
  // `cur`'s retained lineage, bounded to the same ring width — so a node restarted off this root restores
  // the post-swap lineage and still admits a retained old-epoch laggard's cross-epoch catch-up. `cur` may
  // carry an empty lineage (no prior reconfiguration); then the ring is just the predecessor id.
  let prior_config_ids = push_lineage_ring(cur.prior_config_ids(), current.config_id());
  let state = VsrState::try_new_v4(
    cur.view(),
    cur.log_view(),
    cur.commit(),
    cur.checkpoint_op(),
    cur.checkpoint_id(),
    cur.committed_headers_slice().to_vec(),
    epoch,
    prev_epoch,
    successor,
    prior_config_ids,
    // An OFFLINE reconfiguration: the successor membership takes effect as of `cur`'s checkpoint, so carry
    // `cur.checkpoint_op()` as `config_install_op`. The operator guarantees the committed prefix through the
    // checkpoint is durable at restart, so `checkpoint_op >= config_install_op` holds with equality and a
    // node restarted off this root may serve the new membership immediately (the gate withholds only the
    // LIVE swap window where the checkpoint genuinely trails the reconfigure op).
    cur.checkpoint_op(),
  )?
  // The predecessor root's vouched carried-log floor, carried verbatim: the offline successor changes
  // only the configuration, and the floor evidence (what some checkpoint in the cluster vouches) is
  // unchanged by deriving a successor.
  .with_log_floor(cur.log_floor())?
  // Carry the predecessor's WAL-geometry pair: an offline reconfiguration changes only the
  // configuration, not the storage geometry, so the successor root must remain FORMATTED (a node
  // restarted off it must see the format witness — otherwise it would fail-stop as an unformatted
  // sole voter, or abdicate as an unformatted primary, defeating the reconfiguration).
  .with_wal_geometry(cur.checkpoint_ops(), cur.wal_capacity());
  Ok(state)
}

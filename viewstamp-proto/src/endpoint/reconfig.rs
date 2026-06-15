//! The reconfiguration capability seam and the offline-restart successor-root helper.
//!
//! Offline reconfiguration is OPERATOR-COORDINATED: the whole cluster is stopped, a
//! successor durable root is pre-written on every node by [`prepare_restart`], and the cluster is
//! restarted into the new [`Membership`](crate::Membership). There is no online consensus on the change — that is the
//! later `SingleChange`/`Joint` work — so the only capability marker this milestone defines is
//! [`RestartOnly`], and the [`Endpoint`](crate::Endpoint)`<S, R: Reconfig>` type-state is NOT wired
//! yet (a generic would gate nothing while `RestartOnly` is the sole variant).

use std::vec::Vec;

use crate::id::{Epoch, MemberId};
use crate::membership::MembershipError;
use crate::storage::{VsrState, VsrStateError};

mod sealed {
  /// Seals [`super::Reconfig`]: only the types in this crate that implement this private supertrait
  /// can implement `Reconfig`, so a downstream crate cannot add its own capability marker.
  pub trait Sealed {}
}

/// The reconfiguration capability marker; [`RestartOnly`] is the offline-restart base.
/// `SingleChange` and `Joint` join in later milestones, and the
/// [`Endpoint`](crate::Endpoint)`<S, R: Reconfig>` type-state is wired then.
///
/// Sealed: implementable only inside this crate (a private `Sealed` supertrait).
pub trait Reconfig: sealed::Sealed {}

/// The offline-restart reconfiguration capability: the cluster is stopped, a successor
/// durable root is pre-written by [`prepare_restart`], and every node restarts into the new
/// configuration. The only [`Reconfig`] variant this milestone defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestartOnly;

impl sealed::Sealed for RestartOnly {}
impl Reconfig for RestartOnly {}

/// An error building the offline-restart successor durable root in [`prepare_restart`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReconfigError {
  /// `cur` carried no membership — a legacy (v1-3) root that predates the configuration epoch. A
  /// pre-membership root has no `config_id` lineage to chain the successor from, so it cannot be
  /// reconfigured offline; bring the cluster up once (which migrates it to a v4 root carrying the
  /// genesis membership) before pre-writing a successor.
  #[error(
    "cannot reconfigure a legacy (pre-membership) root: it has no config_id lineage to chain"
  )]
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

/// Builds the SUCCESSOR durable root for an offline, operator-coordinated restart.
///
/// The operator pre-writes this root on every node while the cluster is stopped; the node then
/// restarts into the successor membership. It chains the new configuration off `cur`'s membership
/// via [`Membership::reconfigure`](crate::Membership::reconfigure) (the epoch bumps, the `config_id` chains) and carries ALL of
/// `cur`'s consensus frontier UNCHANGED — view, log_view, commit, checkpoint_op, checkpoint_id, and
/// the committed-band headers — so a coordinated restart changes ONLY the configuration, never the
/// replicated log.
///
/// The resulting [`VsrState`] is a v4 root whose scalar `epoch` is the successor membership's epoch,
/// whose `prev_epoch` is `cur.epoch()` (the durable backward link of the lineage), and whose
/// membership is the successor.
///
/// # Precondition: stop from a quiesced cluster
///
/// The operator MUST stop the cluster from a QUIESCED state — every voter `Normal` at a COMMON view —
/// before pre-writing the successor roots. Because the successor preserves each node's own `view`,
/// a quiesced stop leaves every node at the same view, so if a head-fault wave on the restart drives
/// a voting quorum into `RecoveringHead`, they all escalate to the SAME next view and the cluster
/// re-forms. Stopping mid-view-change — leaving a `>= 2` view stagger across the voting set — is OUT
/// OF CONTRACT: each wedged node would escalate to its own `view + 1` with no agreed target and the
/// re-formation could fail to converge. (A no-stagger stop is the standard operator model; the
/// committed prefix is preserved unconditionally either way.)
///
/// # Errors
///
/// - [`ReconfigError::NoMembership`] if `cur` is a legacy (pre-membership) root — it has no
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
  )?;
  Ok(state)
}

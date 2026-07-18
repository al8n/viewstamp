//! The active configuration descriptor: epoch-versioned membership with a
//! `config_id` lineage chain. The single source of truth for who votes and who
//! leads in the current epoch; carried durably in the superblock `VsrState`.

use std::{boxed::Box, vec::Vec};

use crate::{
  View,
  id::{Epoch, MemberId, ReplicaId},
  storage::fnv1a_128,
};

/// The voting-set cap (the prepare-ok quorum uses a u64 bitset). Matches the
/// existing `ConfigError::TooManyReplicas` bound in `config.rs`.
const MAX_VOTING_REPLICAS: u8 = 64;

/// An error rejecting an invalid [`Membership`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MembershipError {
  /// The voting `replica_count` was zero; a configuration needs at least one voter.
  #[error("replica_count must be non-zero")]
  ZeroReplicaCount,
  /// The voting `replica_count` exceeded the 64-voter cap (the prepare-ok bitset width).
  #[error("too many voting replicas: {count}")]
  TooManyReplicas {
    /// The rejected voting count.
    count: u8,
  },
  /// `replica_count + learner_count` exceeds the number of representable replica ids: every replica
  /// occupies a [`ReplicaId`](crate::ReplicaId) slot, and a slot is a `u16`.
  #[error(
    "node_count {count} exceeds the maximum of {} (a replica id is a u16)",
    u16::MAX
  )]
  TooManyNodes {
    /// The rejected total node count (`replica_count + learner_count`).
    count: u32,
  },
  /// The member-list length did not equal `replica_count + learner_count`.
  #[error("members length {len} != replica_count + learner_count {expected}")]
  MemberCountMismatch {
    /// The supplied member-list length.
    len: usize,
    /// The required length (`replica_count + learner_count`).
    expected: usize,
  },
  /// Two slots resolved to the same [`MemberId`]; member ids must be unique.
  #[error("duplicate member id")]
  DuplicateMember,
  /// A membership delta tried to add a [`MemberId`] already present in the configuration (as a voter
  /// or a learner).
  #[error("member already present")]
  AlreadyAMember,
  /// A membership delta referenced a [`MemberId`] absent from the configuration (a remove, a
  /// demotion, or a learner-promotion of an id that is not a member).
  #[error("member not present")]
  UnknownMember,
  /// A `PromoteLearner` delta named a [`MemberId`] that is a voter, not a learner; only a learner can
  /// be promoted into the voting set.
  #[error("member is not a learner")]
  NotALearner,
  /// A `RemoveVoter`/`DemoteVoter` delta named a [`MemberId`] that is present but a learner, not a
  /// voter; only a voter can be removed from or demoted out of the voting set (a learner is removed
  /// with `RemoveLearner`).
  #[error("member is not a voter")]
  NotAVoter,
  /// Removing or demoting the named voter would drop `replica_count` to zero; a configuration needs
  /// at least one voter.
  #[error("removing or demoting the voter would leave no voters")]
  WouldRemoveLastVoter,
  /// A peer-carried successor configuration (a cross-epoch state-sync answer) did NOT hash to the
  /// `config_id` it claims: the recomputed `hash(membership, prev_config_id)` differs from the carried
  /// id, so it is a forged / corrupt / wrong-lineage configuration and MUST NOT be installed.
  #[error("reconstructed config_id does not match the claimed lineage id")]
  ForkedConfigId,
}

/// An epoch-versioned cluster configuration. Immutable once built; a change
/// produces a new `Membership` via [`Self::reconfigure`] with a chained
/// `config_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
  epoch: Epoch,
  replica_count: u8,
  learner_count: u16,
  members: Box<[MemberId]>,
  config_id: u128,
}

impl Membership {
  /// The genesis configuration (epoch 0, `prev_config_id = 0`).
  pub fn genesis(
    replica_count: u8,
    learner_count: u16,
    members: Vec<MemberId>,
  ) -> Result<Self, MembershipError> {
    Self::build(Epoch::new(0), replica_count, learner_count, members, 0)
  }

  /// A successor configuration: the epoch bumps and `config_id` chains from `self`.
  pub fn reconfigure(
    &self,
    replica_count: u8,
    learner_count: u16,
    members: Vec<MemberId>,
  ) -> Result<Self, MembershipError> {
    Self::build(
      self.epoch.next(),
      replica_count,
      learner_count,
      members,
      self.config_id,
    )
  }

  fn build(
    epoch: Epoch,
    replica_count: u8,
    learner_count: u16,
    members: Vec<MemberId>,
    prev_config_id: u128,
  ) -> Result<Self, MembershipError> {
    let members = Self::validate_structure(replica_count, learner_count, members)?;
    let config_id = Self::compute_config_id(
      epoch,
      replica_count,
      learner_count,
      &members,
      prev_config_id,
    );
    Ok(Self {
      epoch,
      replica_count,
      learner_count,
      members,
      config_id,
    })
  }

  /// Reconstructs a `Membership` from its DURABLE parts (the bytes a v4 superblock root stores),
  /// validating STRUCTURE but TRUSTING the supplied `config_id`.
  ///
  /// `config_id(K) = hash(membership_K, config_id(K-1))` chains from the PREVIOUS config's id, which a
  /// single durable root does not retain — so it cannot be recomputed here. The superblock's
  /// crash-atomic checksummed envelope already protects these bytes (exactly as it protects
  /// `checkpoint_id`, which is likewise stored and read back, never re-derived), so `decode` reads the
  /// stored `config_id` straight into the rebuilt `Membership`. Only the self-contained invariants are
  /// re-checked (non-zero `replica_count`, the 64-voter cap, `members.len() == replica_count +
  /// learner_count`, no duplicate members); `compute_config_id` is deliberately NOT called.
  ///
  /// Public so a downstream crate's TEST fixtures can reconstruct a membership with a chosen
  /// `config_id` (the integration/loopback/simulation harnesses build a `config_id = 0` genesis so
  /// hand-built test messages, which carry 0, pass the strict `(epoch, config_id)` ingress gate);
  /// production builds its lineage through [`Self::genesis`] / [`Self::reconfigure`] (real hashes) and
  /// reads durable state back through the superblock decode path, never re-derives the id.
  pub fn from_durable_parts(
    epoch: Epoch,
    replica_count: u8,
    learner_count: u16,
    members: Vec<MemberId>,
    config_id: u128,
  ) -> Result<Self, MembershipError> {
    let members = Self::validate_structure(replica_count, learner_count, members)?;
    Ok(Self {
      epoch,
      replica_count,
      learner_count,
      members,
      config_id,
    })
  }

  /// Validates the structural invariants shared by every constructor (non-zero `replica_count`, the
  /// 64-voter cap, `members.len() == replica_count + learner_count`, no duplicate members) and returns
  /// the boxed member slice. Does NOT touch `config_id` — that is the caller's (computed or durable).
  fn validate_structure(
    replica_count: u8,
    learner_count: u16,
    members: Vec<MemberId>,
  ) -> Result<Box<[MemberId]>, MembershipError> {
    if replica_count == 0 {
      return Err(MembershipError::ZeroReplicaCount);
    }
    if replica_count > MAX_VOTING_REPLICAS {
      return Err(MembershipError::TooManyReplicas {
        count: replica_count,
      });
    }
    // Every node occupies a `ReplicaId` (u16) slot, so the TOTAL must fit u16 — else `node_count`
    // wraps and `slot_of` aliases a high-index member onto a low slot, corrupting MemberId→slot
    // routing. (The relocation of the quorum logic onto `Membership` must keep this `Config`-era
    // invariant, not just the 64-voter cap above.)
    let node_count = replica_count as u32 + learner_count as u32;
    if node_count > u16::MAX as u32 {
      return Err(MembershipError::TooManyNodes { count: node_count });
    }
    let expected = replica_count as usize + learner_count as usize;
    if members.len() != expected {
      return Err(MembershipError::MemberCountMismatch {
        len: members.len(),
        expected,
      });
    }
    for i in 0..members.len() {
      for j in (i + 1)..members.len() {
        if members[i] == members[j] {
          return Err(MembershipError::DuplicateMember);
        }
      }
    }
    Ok(members.into_boxed_slice())
  }

  /// Recompute the canonical lineage hash `config_id(K) = hash(membership_K, config_id(K-1))` from a
  /// successor's parts and its predecessor's `config_id`. Used by the cross-epoch state-sync install
  /// path ([`ReconfigurePayload::to_membership_verified`](crate::message::ReconfigurePayload)) to VERIFY
  /// a peer-carried `(epoch, config_id, membership)` reconstructs to the SAME `config_id` it claims —
  /// the "never install an unverifiable configuration" gate. (The durable-root decode path deliberately
  /// does NOT recompute — its bytes are already checksum-protected by the superblock envelope.)
  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn recompute_config_id(
    epoch: Epoch,
    replica_count: u8,
    learner_count: u16,
    members: &[MemberId],
    prev_config_id: u128,
  ) -> u128 {
    Self::compute_config_id(epoch, replica_count, learner_count, members, prev_config_id)
  }

  fn compute_config_id(
    epoch: Epoch,
    replica_count: u8,
    learner_count: u16,
    members: &[MemberId],
    prev: u128,
  ) -> u128 {
    let mut buf = Vec::with_capacity(8 + 1 + 2 + members.len() * 16 + 16);
    buf.extend_from_slice(&epoch.get().to_be_bytes());
    buf.push(replica_count);
    buf.extend_from_slice(&learner_count.to_be_bytes());
    for m in members {
      buf.extend_from_slice(&m.get().to_be_bytes());
    }
    buf.extend_from_slice(&prev.to_be_bytes());
    fnv1a_128(&buf)
  }

  /// The configuration version (epoch 0 at genesis, bumped per reconfiguration).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The lineage hash chaining this configuration to its predecessor.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn config_id(&self) -> u128 {
    self.config_id
  }

  /// The number of voting replicas (slots `0..replica_count`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn replica_count(&self) -> u8 {
    self.replica_count
  }

  /// The number of non-voting learner replicas.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn learner_count(&self) -> u16 {
    self.learner_count
  }

  /// The total node count: voting replicas plus learners (`replica_count + learner_count`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn node_count(&self) -> u16 {
    self.replica_count as u16 + self.learner_count
  }

  /// The members, indexed by [`ReplicaId`] slot.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn members_slice(&self) -> &[MemberId] {
    &self.members
  }

  /// Resolves a member to its slot, if present.
  pub fn slot_of(&self, who: MemberId) -> Option<ReplicaId> {
    self
      .members
      .iter()
      .position(|&m| m == who)
      .map(|i| ReplicaId::new(i as u16))
  }

  /// Resolves a slot to its member, if in range.
  pub fn member_at(&self, slot: ReplicaId) -> Option<MemberId> {
    self.members.get(slot.get() as usize).copied()
  }

  /// The replication / view-change quorum size: `floor(n/2) + 1`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn quorum(&self) -> usize {
    (self.replica_count as usize) / 2 + 1
  }

  /// The view-change / DoViewChange quorum: `replica_count − quorum + 1`.
  ///
  /// Intersects every replication quorum (`quorum + quorum_view_change > replica_count`),
  /// so a view change cannot start while normal commit is still possible.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn quorum_view_change(&self) -> usize {
    self.replica_count as usize - self.quorum() + 1
  }

  /// The nack-prepare quorum (used by view change to truncate uncommitted ops):
  /// `replica_count − quorum + 1`. Equal to `quorum_view_change`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn quorum_nack_prepare(&self) -> usize {
    self.replica_count as usize - self.quorum() + 1
  }

  /// The primary for a given view: `view % replica_count`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn primary(&self, view: View) -> ReplicaId {
    ReplicaId::new((view.get() % self.replica_count as u64) as u16)
  }

  /// Whether `slot` is the primary for `view`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_primary_slot(&self, slot: ReplicaId, view: View) -> bool {
    self.primary(view).get() == slot.get()
  }

  /// Whether `id` is a voting replica (one in `0..replica_count`). Voting replicas drive every
  /// quorum; learners do not vote.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_voter(&self, id: ReplicaId) -> bool {
    id.get() < self.replica_count as u16
  }

  /// Whether `id` is a non-voting learner replica (one in `[replica_count, node_count)`). An id at
  /// or beyond `node_count` is out of range — neither a voter nor a learner.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_learner(&self, id: ReplicaId) -> bool {
    id.get() >= self.replica_count as u16 && id.get() < self.node_count()
  }

  /// Whether `who` already occupies a slot (voter or learner) in this configuration.
  fn contains(&self, who: MemberId) -> bool {
    self.members.contains(&who)
  }

  /// The first id that `successor_members` seats as a VOTER (one of its first
  /// `successor_replica_count` slots) without being a member — voter or learner — of `self`:
  /// `Some(id)` names the offending member, `None` means every successor voter is already admitted.
  ///
  /// This is the voter-admission predicate the install path evaluates against a successor's EXACT
  /// predecessor (`self`). Every legitimate single-voter delta passes: a retained voter and a
  /// promoted learner are members of the predecessor, and adding/removing a learner or removing a
  /// voter seats no id as a voter that was not already a member. Only a successor that admits a
  /// BRAND-NEW voter directly trips it — such a node holds no committed prefix, yet as a voter it
  /// counts toward the successor's view-change quorum, so a quorum formed without the prefix-holding
  /// retained voters could elect a leader that drops a committed op. Quantified over every successor
  /// voter rather than classifying a delta, so a payload not derived from exactly one delta still
  /// classifies, conservatively.
  ///
  /// Deliberately NOT folded into [`Self::reconfigure`]: the offline restart lane
  /// ([`prepare_restart`](crate::prepare_restart)) legitimately derives wholesale successors there,
  /// with a different committed-prefix argument (the pre-written root itself).
  pub(crate) fn first_new_voter(
    &self,
    successor_replica_count: u8,
    successor_members: &[MemberId],
  ) -> Option<MemberId> {
    successor_members
      .iter()
      .take(successor_replica_count as usize)
      .copied()
      .find(|&who| !self.contains(who))
  }

  /// Applies a single-voter membership delta, returning the successor configuration (epoch bumped,
  /// `config_id` chained from `self` via [`Self::reconfigure`]) or a [`MembershipError`] if the delta
  /// is invalid for this configuration.
  ///
  /// The successor's member-slot layout preserves the partition voters occupy `[0, replica_count')`
  /// and learners occupy `[replica_count', node_count')`: an added voter is appended to the end of the
  /// voter range (just before the learners), an added learner to the end of the learner range, a
  /// removed member's slot is closed up, a promoted learner is moved from the learner range to the
  /// end of the voter range, and a demoted voter from the voter range to the end of the learner
  /// range. Every delta changes the voter count by at most one — Add/Remove/Promote/Demote voter by
  /// exactly ±1, Add/RemoveLearner by 0 — which holds by construction here.
  pub fn apply_delta(&self, d: &SingleVoterDelta) -> Result<Self, MembershipError> {
    let voters = self.replica_count as usize;
    // The members split cleanly into the voter prefix and the learner suffix.
    let (current_voters, current_learners) = self.members.split_at(voters);

    let (replica_count, learner_count, members) = match d {
      SingleVoterDelta::AddVoter(who) => {
        if self.contains(*who) {
          return Err(MembershipError::AlreadyAMember);
        }
        // Append the new voter at the end of the voter range, before the learners.
        let mut members = Vec::with_capacity(self.members.len() + 1);
        members.extend_from_slice(current_voters);
        members.push(*who);
        members.extend_from_slice(current_learners);
        (self.replica_count + 1, self.learner_count, members)
      }
      SingleVoterDelta::RemoveVoter(who) => {
        let slot = self.slot_of(*who).ok_or(MembershipError::UnknownMember)?;
        if !self.is_voter(slot) {
          // Present, but a learner — `RemoveVoter` targets a voter; a learner is removed with
          // `RemoveLearner`, so this delta does not apply.
          return Err(MembershipError::NotAVoter);
        }
        if self.replica_count == 1 {
          return Err(MembershipError::WouldRemoveLastVoter);
        }
        let members = self
          .members
          .iter()
          .copied()
          .filter(|&m| m != *who)
          .collect();
        (self.replica_count - 1, self.learner_count, members)
      }
      SingleVoterDelta::PromoteLearner(who) => {
        let slot = self.slot_of(*who).ok_or(MembershipError::UnknownMember)?;
        if !self.is_learner(slot) {
          return Err(MembershipError::NotALearner);
        }
        // Move the learner to the end of the voter range: the voter prefix grows by one, the learner
        // suffix loses the promoted id.
        let mut members = Vec::with_capacity(self.members.len());
        members.extend_from_slice(current_voters);
        members.push(*who);
        members.extend(current_learners.iter().copied().filter(|&m| m != *who));
        (self.replica_count + 1, self.learner_count - 1, members)
      }
      SingleVoterDelta::DemoteVoter(who) => {
        let slot = self.slot_of(*who).ok_or(MembershipError::UnknownMember)?;
        if !self.is_voter(slot) {
          return Err(MembershipError::NotAVoter);
        }
        if self.replica_count == 1 {
          return Err(MembershipError::WouldRemoveLastVoter);
        }
        // Move the voter to the end of the learner range: the voter prefix loses the demoted id, the
        // learner suffix gains it. The node count is unchanged — the member keeps a seat, only its
        // kind changes.
        let mut members = Vec::with_capacity(self.members.len());
        members.extend(current_voters.iter().copied().filter(|&m| m != *who));
        members.extend_from_slice(current_learners);
        members.push(*who);
        (self.replica_count - 1, self.learner_count + 1, members)
      }
      SingleVoterDelta::AddLearner(who) => {
        if self.contains(*who) {
          return Err(MembershipError::AlreadyAMember);
        }
        // Append the new learner at the end of the learner range; the voter range is untouched.
        let mut members = Vec::with_capacity(self.members.len() + 1);
        members.extend_from_slice(&self.members);
        members.push(*who);
        (self.replica_count, self.learner_count + 1, members)
      }
      SingleVoterDelta::RemoveLearner(who) => {
        let slot = self.slot_of(*who).ok_or(MembershipError::UnknownMember)?;
        if !self.is_learner(slot) {
          // Present, but a voter — use RemoveVoter; this delta must not change the voter count.
          return Err(MembershipError::NotALearner);
        }
        let members = self
          .members
          .iter()
          .copied()
          .filter(|&m| m != *who)
          .collect();
        (self.replica_count, self.learner_count - 1, members)
      }
    };

    self.reconfigure(replica_count, learner_count, members)
  }
}

/// A single-step change to the voting set, applied to a [`Membership`] via [`Membership::apply_delta`]
/// to produce the successor configuration. Each variant moves the voter count by at most one: an
/// add/remove/promote/demote of a voter by exactly ±1, an add/remove of a learner by 0.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SingleVoterDelta {
  /// Add a brand-new [`MemberId`] as a voter.
  ///
  /// This is NOT an accepted `propose_membership` delta. A brand-new voter holds no committed prefix (it
  /// was never a member, so it never committed a prior op), which can break the cross-config quorum
  /// intersection; `propose_membership` therefore rejects a direct `AddVoter` at every cluster size, and
  /// the planner never emits one. To add a voter, `AddLearner` the member, let it catch up, then
  /// `PromoteLearner`. The variant is retained for the membership arithmetic ([`Membership::apply_delta`])
  /// and the rejection tests.
  AddVoter(MemberId),
  /// Remove a voting [`MemberId`] from the configuration.
  RemoveVoter(MemberId),
  /// Promote an existing learner [`MemberId`] into the voting set.
  PromoteLearner(MemberId),
  /// Demote a voting [`MemberId`] to a non-voting learner. The inverse of `PromoteLearner`: the
  /// member keeps its seat (the node count is unchanged) but leaves the voting set, so it stops
  /// counting toward any quorum while remaining a live, replicated participant — a retained durable
  /// copy of the committed prefix, a repair/state-sync donor, and re-promotable without re-seating.
  DemoteVoter(MemberId),
  /// Add a brand-new [`MemberId`] as a non-voting learner.
  AddLearner(MemberId),
  /// Remove a learner [`MemberId`] from the configuration.
  RemoveLearner(MemberId),
}

impl SingleVoterDelta {
  /// The stable string name of this delta (snake_case, serialization-stable).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::AddVoter(_) => "add_voter",
      Self::RemoveVoter(_) => "remove_voter",
      Self::PromoteLearner(_) => "promote_learner",
      Self::DemoteVoter(_) => "demote_voter",
      Self::AddLearner(_) => "add_learner",
      Self::RemoveLearner(_) => "remove_learner",
    }
  }

  /// The [`MemberId`] this delta acts on.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn member(&self) -> MemberId {
    match self {
      Self::AddVoter(m)
      | Self::RemoveVoter(m)
      | Self::PromoteLearner(m)
      | Self::DemoteVoter(m)
      | Self::AddLearner(m)
      | Self::RemoveLearner(m) => *m,
    }
  }

  /// True iff this is [`Self::AddVoter`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_add_voter(&self) -> bool {
    matches!(self, Self::AddVoter(_))
  }

  /// True iff this is [`Self::RemoveVoter`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_remove_voter(&self) -> bool {
    matches!(self, Self::RemoveVoter(_))
  }

  /// True iff this is [`Self::PromoteLearner`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_promote_learner(&self) -> bool {
    matches!(self, Self::PromoteLearner(_))
  }

  /// True iff this is [`Self::DemoteVoter`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_demote_voter(&self) -> bool {
    matches!(self, Self::DemoteVoter(_))
  }

  /// True iff this is [`Self::AddLearner`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_add_learner(&self) -> bool {
    matches!(self, Self::AddLearner(_))
  }

  /// True iff this is [`Self::RemoveLearner`].
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_remove_learner(&self) -> bool {
    matches!(self, Self::RemoveLearner(_))
  }
}

/// An explicit operator acknowledgement that a proposed membership change REDUCES the cluster's
/// crash tolerance: `f(successor) < f(current)`, where `f(n) = n − quorum(n) = ⌊(n−1)/2⌋` is the
/// number of simultaneous voter crashes a configuration survives. Among the single-voter deltas
/// that is exactly a voter-count decrement from an ODD voter count (3 → 2 loses the only tolerated
/// crash; 5 → 4 tolerates one instead of two).
///
/// [`Endpoint::propose_membership`](crate::Endpoint::propose_membership) rejects an f-reducing delta
/// with [`ReducedFaultToleranceUnacknowledged`](crate::ProposeMembershipError::ReducedFaultToleranceUnacknowledged)
/// unless this token accompanies it, so crash tolerance is never reduced silently; a superfluous
/// token on a non-reducing delta is accepted and ignored. The token is NOT an unforgeable
/// capability — any caller can construct it, and the caller IS the operator. Its value is that the
/// acceptance must be NAMED at the call site (deliberately no `Default`), leaving every
/// tolerance-reducing proposal explicit in the code that makes it and greppable in review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptReducedFaultTolerance;

#[cfg(test)]
mod tests;

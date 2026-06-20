//! The active configuration descriptor: epoch-versioned membership with a
//! `config_id` lineage chain. The single source of truth for who votes and who
//! leads in the current epoch; carried durably in the superblock `VsrState`.

use std::boxed::Box;
use std::vec::Vec;

use crate::View;
use crate::id::{Epoch, MemberId, ReplicaId};
use crate::storage::fnv1a_128;

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
  /// A membership delta referenced a [`MemberId`] absent from the configuration (a remove or a
  /// learner-promotion of an id that is not a member).
  #[error("member not present")]
  UnknownMember,
  /// A `PromoteLearner` delta named a [`MemberId`] that is a voter, not a learner; only a learner can
  /// be promoted into the voting set.
  #[error("member is not a learner")]
  NotALearner,
  /// A `RemoveVoter` delta would drop `replica_count` to zero; a configuration needs at least one
  /// voter.
  #[error("removing the voter would leave no voters")]
  WouldRemoveLastVoter,
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

  /// Applies a single-voter membership delta, returning the successor configuration (epoch bumped,
  /// `config_id` chained from `self` via [`Self::reconfigure`]) or a [`MembershipError`] if the delta
  /// is invalid for this configuration.
  ///
  /// The successor's member-slot layout preserves the partition voters occupy `[0, replica_count')`
  /// and learners occupy `[replica_count', node_count')`: an added voter is appended to the end of the
  /// voter range (just before the learners), an added learner to the end of the learner range, a
  /// removed member's slot is closed up, and a promoted learner is moved from the learner range to the
  /// end of the voter range. Every delta changes the voter count by at most one — Add/Remove/Promote
  /// voter by exactly ±1, Add/RemoveLearner by 0 — which holds by construction here.
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
          // Present, but a learner — removing it does not change the voter count.
          return Err(MembershipError::NotALearner);
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
/// add/remove/promote of a voter by exactly ±1, an add/remove of a learner by 0.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SingleVoterDelta {
  /// Add a brand-new [`MemberId`] as a voter.
  AddVoter(MemberId),
  /// Remove a voting [`MemberId`] from the configuration.
  RemoveVoter(MemberId),
  /// Promote an existing learner [`MemberId`] into the voting set.
  PromoteLearner(MemberId),
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn config_id_chains_and_detects_forks() {
    let m0 = Membership::genesis(
      3,
      0,
      std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
    )
    .unwrap();
    // genesis config_id is determined purely by the membership tuple.
    assert_eq!(m0.epoch(), Epoch::new(0));
    let m0b = Membership::genesis(
      3,
      0,
      std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
    )
    .unwrap();
    assert_eq!(
      m0.config_id(),
      m0b.config_id(),
      "same genesis membership => same config_id"
    );

    // A legitimate successor chains from m0.
    let m1 = m0
      .reconfigure(
        3,
        0,
        std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(4)],
      )
      .unwrap();
    assert_eq!(m1.epoch(), Epoch::new(1));
    assert_ne!(m1.config_id(), m0.config_id());

    // A FORK: a different successor of m0 at the same epoch has a different config_id.
    let fork = m0
      .reconfigure(
        3,
        0,
        std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(5)],
      )
      .unwrap();
    assert_eq!(fork.epoch(), m1.epoch());
    assert_ne!(
      fork.config_id(),
      m1.config_id(),
      "divergent successors must differ"
    );
  }

  #[test]
  fn membership_quorum_and_slots() {
    let m = Membership::genesis(4, 0, (1..=4).map(MemberId::new).collect()).unwrap();
    assert_eq!(m.quorum(), 3); // floor(4/2)+1
    assert_eq!(m.quorum_view_change(), 2); // 4 - 3 + 1
    assert_eq!(m.replica_count(), 4);
    assert_eq!(m.node_count(), 4);
    assert_eq!(m.slot_of(MemberId::new(3)), Some(ReplicaId::new(2)));
    assert_eq!(m.member_at(ReplicaId::new(2)), Some(MemberId::new(3)));
    assert_eq!(m.slot_of(MemberId::new(99)), None);
    assert!(m.is_voter(ReplicaId::new(0)));
  }

  #[test]
  fn membership_rejects_dupes_and_bad_counts() {
    assert!(matches!(
      Membership::genesis(0, 0, std::vec![]),
      Err(MembershipError::ZeroReplicaCount)
    ));
    assert!(
      Membership::genesis(2, 0, std::vec![MemberId::new(1), MemberId::new(1)]).is_err(),
      "duplicate member"
    );
    assert!(
      Membership::genesis(2, 0, std::vec![MemberId::new(1)]).is_err(),
      "len != replica_count+learner_count"
    );
  }

  #[test]
  fn membership_rejects_a_node_count_above_the_u16_slot_space() {
    // `replica_count + learner_count` must fit the u16 `ReplicaId` slot space — else `node_count`
    // wraps and `slot_of` aliases a high member onto a low slot. The check fires BEFORE the
    // member-count / duplicate checks, so an empty member list reaches it (kept cheap — the duplicate
    // scan is O(n^2)). The maximal shape (64 voters + 65535 learners) and the just-over
    // boundary (1 + 65535 = 65536) both reject with `TooManyNodes`, NOT a wrap or panic.
    assert!(matches!(
      Membership::genesis(64, u16::MAX, std::vec::Vec::new()),
      Err(MembershipError::TooManyNodes { count: 65599 })
    ));
    assert!(matches!(
      Membership::genesis(1, u16::MAX, std::vec::Vec::new()),
      Err(MembershipError::TooManyNodes { count: 65536 })
    ));
    // node_count == u16::MAX exactly is the accepted boundary (1 voter + 65534 learners); validated
    // here via the count path without materializing 65535 members (the O(n^2) scan would be slow).
    assert!(matches!(
      Membership::genesis(1, u16::MAX - 1, std::vec::Vec::new()),
      Err(MembershipError::MemberCountMismatch {
        expected: 65535,
        ..
      })
    ));
  }

  #[test]
  fn from_durable_parts_trusts_config_id_but_validates_structure() {
    // `from_durable_parts` reconstructs a `Membership` from a v4 superblock root: it RE-VALIDATES the
    // self-contained structural invariants but TRUSTS the supplied config_id verbatim (the lineage id
    // chains from the previous config's id, which a single root does not retain, so it cannot be
    // recomputed — the crash-atomic superblock envelope protects these bytes).
    let arbitrary_config_id = 0xDEAD_BEEF_F00D_u128;
    let m = Membership::from_durable_parts(
      Epoch::new(5),
      2,
      1,
      std::vec![MemberId::new(7), MemberId::new(8), MemberId::new(9)],
      arbitrary_config_id,
    )
    .unwrap();
    assert_eq!(m.epoch(), Epoch::new(5));
    assert_eq!(m.replica_count(), 2);
    assert_eq!(m.learner_count(), 1);
    assert_eq!(
      m.config_id(),
      arbitrary_config_id,
      "the durable config_id is carried through, NOT recomputed"
    );

    // The same membership tuple built through `genesis`/`reconfigure` would have a hash-derived
    // config_id — proving `from_durable_parts` did not run the chaining hash.
    let recomputed = Membership::genesis(
      2,
      1,
      std::vec![MemberId::new(7), MemberId::new(8), MemberId::new(9)],
    )
    .unwrap()
    .config_id();
    assert_ne!(
      m.config_id(),
      recomputed,
      "from_durable_parts must not recompute the lineage id"
    );

    // Structure is still validated: a zero replica_count, a count mismatch, and a duplicate all reject.
    assert!(matches!(
      Membership::from_durable_parts(Epoch::new(0), 0, 0, std::vec![], 1),
      Err(MembershipError::ZeroReplicaCount)
    ));
    assert!(matches!(
      Membership::from_durable_parts(Epoch::new(0), 2, 0, std::vec![MemberId::new(1)], 1),
      Err(MembershipError::MemberCountMismatch { .. })
    ));
    assert!(matches!(
      Membership::from_durable_parts(
        Epoch::new(0),
        2,
        0,
        std::vec![MemberId::new(1), MemberId::new(1)],
        1
      ),
      Err(MembershipError::DuplicateMember)
    ));
  }

  #[test]
  fn leadership_is_per_epoch_the_same_view_can_elect_a_different_member() {
    // `(epoch, view)` leadership: the primary SLOT is `view % replica_count`, but the slot resolves to
    // a different MEMBER when the membership changes across an epoch. A successor that reorders the
    // members elects a different MemberId for the very same view number — so leadership is anchored to
    // `(epoch, view)`, not to `view` alone.
    let m0 = Membership::genesis(
      3,
      0,
      std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
    )
    .unwrap();
    let m1 = m0
      .reconfigure(
        3,
        0,
        std::vec![MemberId::new(2), MemberId::new(3), MemberId::new(1)],
      )
      .unwrap();

    // Both configurations pick the SAME slot for view 1 (slot 1 = view % 3)...
    assert_eq!(m0.primary(View::with(1)), ReplicaId::new(1));
    assert_eq!(m1.primary(View::with(1)), ReplicaId::new(1));
    // ...but that slot is a DIFFERENT member in each epoch.
    assert_eq!(
      m0.member_at(m0.primary(View::with(1))),
      Some(MemberId::new(2))
    );
    assert_eq!(
      m1.member_at(m1.primary(View::with(1))),
      Some(MemberId::new(3))
    );
    // The epoch is high-order: the successor's epoch strictly exceeds its predecessor's.
    assert!(m1.epoch() > m0.epoch());
  }

  /// A 3-voter, 1-learner base membership: voter slots `0..3` hold members 1..3, the learner slot 3
  /// holds member 10.
  fn base_3v_1l() -> Membership {
    Membership::genesis(
      3,
      1,
      std::vec![
        MemberId::new(1),
        MemberId::new(2),
        MemberId::new(3),
        MemberId::new(10),
      ],
    )
    .unwrap()
  }

  #[test]
  fn single_voter_delta_predicates_and_accessors() {
    let add = SingleVoterDelta::AddVoter(MemberId::new(7));
    assert!(add.is_add_voter());
    assert!(!add.is_remove_voter());
    assert_eq!(add.member(), MemberId::new(7));
    assert_eq!(add.as_str(), "add_voter");

    let rm = SingleVoterDelta::RemoveVoter(MemberId::new(2));
    assert!(rm.is_remove_voter());
    assert_eq!(rm.member(), MemberId::new(2));
    assert_eq!(rm.as_str(), "remove_voter");

    let promote = SingleVoterDelta::PromoteLearner(MemberId::new(10));
    assert!(promote.is_promote_learner());
    assert_eq!(promote.as_str(), "promote_learner");

    let add_l = SingleVoterDelta::AddLearner(MemberId::new(11));
    assert!(add_l.is_add_learner());
    assert_eq!(add_l.as_str(), "add_learner");

    let rm_l = SingleVoterDelta::RemoveLearner(MemberId::new(10));
    assert!(rm_l.is_remove_learner());
    assert_eq!(rm_l.as_str(), "remove_learner");
  }

  #[test]
  fn add_voter_grows_replica_count_bumps_epoch_chains_config_id() {
    let m0 = base_3v_1l();
    let m1 = m0
      .apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(7)))
      .unwrap();

    // The voter count grows by one; the learner count is untouched.
    assert_eq!(m1.replica_count(), m0.replica_count() + 1);
    assert_eq!(m1.learner_count(), m0.learner_count());
    // The epoch bumps by exactly one.
    assert_eq!(m1.epoch(), Epoch::new(m0.epoch().get() + 1));
    // The lineage id chains: it differs from the predecessor.
    assert_ne!(m1.config_id(), m0.config_id());

    // The new voter occupies a voter slot, ahead of the learners; the prior learner is still a learner.
    assert!(m1.is_voter(m1.slot_of(MemberId::new(7)).unwrap()));
    assert!(m1.is_learner(m1.slot_of(MemberId::new(10)).unwrap()));

    // `apply_delta` chains exactly as a `reconfigure` to the same successor members would: a new voter
    // is appended after the existing voters, before the learners.
    let expected = m0
      .reconfigure(
        4,
        1,
        std::vec![
          MemberId::new(1),
          MemberId::new(2),
          MemberId::new(3),
          MemberId::new(7),
          MemberId::new(10),
        ],
      )
      .unwrap();
    assert_eq!(m1.config_id(), expected.config_id());
    assert_eq!(m1.members_slice(), expected.members_slice());
  }

  #[test]
  fn remove_voter_shrinks_replica_count() {
    let m0 = base_3v_1l();
    let m1 = m0
      .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(2)))
      .unwrap();
    assert_eq!(m1.replica_count(), m0.replica_count() - 1);
    assert_eq!(m1.learner_count(), m0.learner_count());
    assert_eq!(m1.epoch(), Epoch::new(m0.epoch().get() + 1));
    assert_ne!(m1.config_id(), m0.config_id());
    // The removed member is gone; the surviving voters keep their relative order and stay voters.
    assert_eq!(m1.slot_of(MemberId::new(2)), None);
    assert!(m1.is_voter(m1.slot_of(MemberId::new(1)).unwrap()));
    assert!(m1.is_voter(m1.slot_of(MemberId::new(3)).unwrap()));
    // The learner remains a learner in the shrunk configuration.
    assert!(m1.is_learner(m1.slot_of(MemberId::new(10)).unwrap()));
  }

  #[test]
  fn promote_learner_moves_id_from_learner_range_into_voter_range() {
    let m0 = base_3v_1l();
    assert!(m0.is_learner(m0.slot_of(MemberId::new(10)).unwrap()));

    let m1 = m0
      .apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(10)))
      .unwrap();
    // replica_count + 1, learner_count − 1.
    assert_eq!(m1.replica_count(), m0.replica_count() + 1);
    assert_eq!(m1.learner_count(), m0.learner_count() - 1);
    assert_eq!(m1.epoch(), Epoch::new(m0.epoch().get() + 1));
    assert_ne!(m1.config_id(), m0.config_id());
    // The promoted id is now a voter, occupying a slot in the voter range.
    let slot = m1.slot_of(MemberId::new(10)).unwrap();
    assert!(m1.is_voter(slot));
    assert!(!m1.is_learner(slot));
  }

  #[test]
  fn add_learner_grows_learner_count_keeps_replica_count() {
    let m0 = base_3v_1l();
    let m1 = m0
      .apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(11)))
      .unwrap();
    assert_eq!(m1.replica_count(), m0.replica_count());
    assert_eq!(m1.learner_count(), m0.learner_count() + 1);
    assert_eq!(m1.epoch(), Epoch::new(m0.epoch().get() + 1));
    assert_ne!(m1.config_id(), m0.config_id());
    // The new learner sits in the learner range, after the existing learners.
    assert!(m1.is_learner(m1.slot_of(MemberId::new(11)).unwrap()));
    // Existing voters/learners keep their kind.
    assert!(m1.is_voter(m1.slot_of(MemberId::new(1)).unwrap()));
    assert!(m1.is_learner(m1.slot_of(MemberId::new(10)).unwrap()));
  }

  #[test]
  fn remove_learner_shrinks_learner_count() {
    let m0 = base_3v_1l();
    let m1 = m0
      .apply_delta(&SingleVoterDelta::RemoveLearner(MemberId::new(10)))
      .unwrap();
    assert_eq!(m1.replica_count(), m0.replica_count());
    assert_eq!(m1.learner_count(), m0.learner_count() - 1);
    assert_eq!(m1.epoch(), Epoch::new(m0.epoch().get() + 1));
    assert_ne!(m1.config_id(), m0.config_id());
    assert_eq!(m1.slot_of(MemberId::new(10)), None);
  }

  #[test]
  fn apply_delta_rejects_removing_the_last_voter() {
    // A single-voter configuration: removing its sole voter would leave a zero-voter cluster.
    let m = Membership::genesis(1, 0, std::vec![MemberId::new(1)]).unwrap();
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(1))),
      Err(MembershipError::WouldRemoveLastVoter)
    ));
  }

  #[test]
  fn apply_delta_rejects_unknown_member_for_removals_and_promotion() {
    let m = base_3v_1l();
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(99))),
      Err(MembershipError::UnknownMember)
    ));
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::RemoveLearner(MemberId::new(99))),
      Err(MembershipError::UnknownMember)
    ));
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(99))),
      Err(MembershipError::UnknownMember)
    ));
  }

  #[test]
  fn apply_delta_rejects_promoting_an_existing_voter() {
    let m = base_3v_1l();
    // Member 1 is already a voter; promoting it is not a learner→voter move.
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(1))),
      Err(MembershipError::NotALearner)
    ));
  }

  #[test]
  fn apply_delta_rejects_adding_a_duplicate() {
    let m = base_3v_1l();
    // Member 2 is already a voter; member 10 is already a learner.
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(2))),
      Err(MembershipError::AlreadyAMember)
    ));
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::AddVoter(MemberId::new(10))),
      Err(MembershipError::AlreadyAMember)
    ));
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(10))),
      Err(MembershipError::AlreadyAMember)
    ));
    assert!(matches!(
      m.apply_delta(&SingleVoterDelta::AddLearner(MemberId::new(1))),
      Err(MembershipError::AlreadyAMember)
    ));
  }

  #[test]
  fn apply_delta_changes_voter_count_by_at_most_one() {
    // For every successful delta variant, the voter count moves by at most one. AddLearner /
    // RemoveLearner leave it unchanged; Add/Remove/Promote voter move it by exactly one.
    let m = base_3v_1l();
    let deltas = std::vec![
      SingleVoterDelta::AddVoter(MemberId::new(7)),
      SingleVoterDelta::RemoveVoter(MemberId::new(2)),
      SingleVoterDelta::PromoteLearner(MemberId::new(10)),
      SingleVoterDelta::AddLearner(MemberId::new(11)),
      SingleVoterDelta::RemoveLearner(MemberId::new(10)),
    ];
    for d in &deltas {
      let next = m.apply_delta(d).unwrap();
      let before = i32::from(m.replica_count());
      let after = i32::from(next.replica_count());
      assert!(
        (after - before).abs() <= 1,
        "delta {} moved the voter count by more than one ({before} -> {after})",
        d.as_str(),
      );
    }
  }
}

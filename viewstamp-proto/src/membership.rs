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
}

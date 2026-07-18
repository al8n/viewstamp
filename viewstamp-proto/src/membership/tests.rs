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
fn membership_rejects_a_voting_replica_count_above_the_64_voter_cap() {
  // The TooManyReplicas check fires before the member-count-mismatch check, so an empty member
  // list still reaches it cheaply (no need to materialize 65 real members).
  assert!(matches!(
    Membership::genesis(65, 0, std::vec![]),
    Err(MembershipError::TooManyReplicas { count: 65 })
  ));
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
  let promote = SingleVoterDelta::PromoteLearner(MemberId::new(10));
  assert!(promote.is_promote_learner());
  assert!(!promote.is_demote_voter());
  assert_eq!(promote.as_str(), "promote_learner");
  assert_eq!(promote.member(), MemberId::new(10));

  let demote = SingleVoterDelta::DemoteVoter(MemberId::new(2));
  assert!(demote.is_demote_voter());
  assert!(!demote.is_promote_learner());
  assert_eq!(demote.as_str(), "demote_voter");
  assert_eq!(demote.member(), MemberId::new(2));

  let add_l = SingleVoterDelta::AddLearner(MemberId::new(11));
  assert!(add_l.is_add_learner());
  assert_eq!(add_l.as_str(), "add_learner");
  assert_eq!(add_l.member(), MemberId::new(11));

  let rm_l = SingleVoterDelta::RemoveLearner(MemberId::new(10));
  assert!(rm_l.is_remove_learner());
  assert_eq!(rm_l.as_str(), "remove_learner");
  assert_eq!(rm_l.member(), MemberId::new(10));
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
fn demote_voter_moves_id_from_voter_range_into_learner_range() {
  let m0 = base_3v_1l();
  assert!(m0.is_voter(m0.slot_of(MemberId::new(2)).unwrap()));

  let m1 = m0
    .apply_delta(&SingleVoterDelta::DemoteVoter(MemberId::new(2)))
    .unwrap();
  // replica_count − 1, learner_count + 1: the node count is invariant across a demote.
  assert_eq!(m1.replica_count(), m0.replica_count() - 1);
  assert_eq!(m1.learner_count(), m0.learner_count() + 1);
  assert_eq!(m1.node_count(), m0.node_count());
  assert_eq!(m1.epoch(), Epoch::new(m0.epoch().get() + 1));
  assert_ne!(m1.config_id(), m0.config_id());
  // The demoted id is now a learner, occupying a slot in the learner range.
  let slot = m1.slot_of(MemberId::new(2)).unwrap();
  assert!(m1.is_learner(slot));
  assert!(!m1.is_voter(slot));

  // `apply_delta` chains exactly as a `reconfigure` to the same successor members would: the demoted
  // voter is appended at the END of the learner range, after the existing learners.
  let expected = m0
    .reconfigure(
      2,
      2,
      std::vec![
        MemberId::new(1),
        MemberId::new(3),
        MemberId::new(10),
        MemberId::new(2),
      ],
    )
    .unwrap();
  assert_eq!(m1.config_id(), expected.config_id());
  assert_eq!(m1.members_slice(), expected.members_slice());
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
fn apply_delta_rejects_demoting_the_last_voter() {
  // A single-voter configuration: demoting its sole voter would leave a zero-voter cluster.
  let m = Membership::genesis(1, 0, std::vec![MemberId::new(1)]).unwrap();
  assert!(matches!(
    m.apply_delta(&SingleVoterDelta::DemoteVoter(MemberId::new(1))),
    Err(MembershipError::WouldRemoveLastVoter)
  ));
}

#[test]
fn apply_delta_rejects_unknown_member_for_removals_and_promotion() {
  let m = base_3v_1l();
  assert!(matches!(
    m.apply_delta(&SingleVoterDelta::RemoveLearner(MemberId::new(99))),
    Err(MembershipError::UnknownMember)
  ));
  assert!(matches!(
    m.apply_delta(&SingleVoterDelta::PromoteLearner(MemberId::new(99))),
    Err(MembershipError::UnknownMember)
  ));
  assert!(matches!(
    m.apply_delta(&SingleVoterDelta::DemoteVoter(MemberId::new(99))),
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
fn apply_delta_rejects_removing_a_voter_with_remove_learner() {
  let m = base_3v_1l();
  // Member 1 is a voter, not a learner; `RemoveLearner` targets the learner set — a voter leaves the
  // voting set only via `DemoteVoter`, so this reports `NotALearner`. This validity rule is what
  // makes the learner-GC step of a demote-first shrink unproposable until the demote's successor
  // (in which the member IS a learner) has installed at the proposer.
  assert!(matches!(
    m.apply_delta(&SingleVoterDelta::RemoveLearner(MemberId::new(1))),
    Err(MembershipError::NotALearner)
  ));
}

#[test]
fn apply_delta_rejects_demoting_a_learner() {
  let m = base_3v_1l();
  // Member 10 is a learner, not a voter; `DemoteVoter` moves a voter out of the voting set (a
  // learner is removed with `RemoveLearner`), so this reports `NotAVoter`.
  assert!(matches!(
    m.apply_delta(&SingleVoterDelta::DemoteVoter(MemberId::new(10))),
    Err(MembershipError::NotAVoter)
  ));
}

#[test]
fn apply_delta_rejects_adding_a_duplicate() {
  let m = base_3v_1l();
  // Member 1 is already a voter; member 10 is already a learner.
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
  // RemoveLearner leave it unchanged; Promote/DemoteVoter move it by exactly one.
  let m = base_3v_1l();
  let deltas = std::vec![
    SingleVoterDelta::PromoteLearner(MemberId::new(10)),
    SingleVoterDelta::DemoteVoter(MemberId::new(2)),
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

#[test]
fn first_new_voter_admits_every_legitimate_delta_and_names_a_direct_add() {
  // The voter-admission predicate quantifies over the SUCCESSOR's voter prefix against the
  // predecessor's member set: every legitimate single-voter delta yields a successor whose voters
  // were all already members (a retained voter, or a promoted learner — a demoted voter is a
  // predecessor member too, seated as a learner), so only a successor seating a brand-new voter
  // trips it — and it names that member.
  let pred = base_3v_1l();

  let legitimate = std::vec![
    SingleVoterDelta::AddLearner(MemberId::new(11)),
    SingleVoterDelta::PromoteLearner(MemberId::new(10)),
    SingleVoterDelta::DemoteVoter(MemberId::new(2)),
    SingleVoterDelta::RemoveLearner(MemberId::new(10)),
  ];
  for d in &legitimate {
    let succ = pred.apply_delta(d).unwrap();
    assert_eq!(
      pred.first_new_voter(succ.replica_count(), succ.members_slice()),
      None,
      "the {} successor seats no brand-new voter",
      d.as_str(),
    );
  }

  // The demote-then-GC trajectory passes at EVERY step against its own predecessor: the demote's
  // successor seats only retained voters, and the GC's successor (the demoted seat removed) shrinks
  // no voter prefix and seats nobody new.
  let demoted = pred
    .apply_delta(&SingleVoterDelta::DemoteVoter(MemberId::new(2)))
    .unwrap();
  let gced = demoted
    .apply_delta(&SingleVoterDelta::RemoveLearner(MemberId::new(2)))
    .unwrap();
  assert_eq!(
    demoted.first_new_voter(gced.replica_count(), gced.members_slice()),
    None,
    "the learner-GC successor seats no brand-new voter against the installed demote successor",
  );

  // A successor seating a never-a-member id as a voter — not derivable from any delta; assembled
  // wholesale exactly as a forged/corrupt payload would be: the predicate names it.
  let direct = pred
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
  assert_eq!(
    pred.first_new_voter(direct.replica_count(), direct.members_slice()),
    Some(MemberId::new(7)),
    "the direct-add successor names the unadmitted voter",
  );

  // Not delta-shaped: a wholesale voter list smuggling an unknown id classifies too (conservatively),
  // and the LEARNER suffix is exempt — an unknown id seated as a learner is not a voter admission.
  assert_eq!(
    pred.first_new_voter(2, &[MemberId::new(1), MemberId::new(9), MemberId::new(12)]),
    Some(MemberId::new(9)),
    "an arbitrary successor shape still names the first unadmitted voter",
  );
  assert_eq!(
    pred.first_new_voter(2, &[MemberId::new(1), MemberId::new(2), MemberId::new(12)]),
    None,
    "an unknown id in the learner suffix is not a voter admission",
  );
}

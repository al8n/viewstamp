//! Routing regression for replica ids at or beyond 256: a `ReplicaId` is a `u16`, so a member id
//! such as 258 must route, index, and partition as itself and never truncate or alias a low id
//! (258 & 0xFF == 2). This builds a cluster whose membership spans past 256 and proves a high-id
//! member is reached by the primary's fan-out, and that the partition / one-way-block / per-replica
//! vector-indexing paths address it distinctly from the low id it would alias under an 8-bit
//! truncation.

use viewstamp_simulation::Cluster;

/// A high member id and the low id it would COLLIDE with if a replica id were truncated to 8 bits.
/// `258 & 0xFF == 2`, the first learner id, so the high id and its truncation-alias are both
/// non-voting members — keeping the partition/commit logic about two learners.
const HIGH_ID: usize = 258;
const ALIAS_ID: usize = HIGH_ID & 0xFF; // 2

/// Build a cluster of two voters {0, 1} plus enough learners that the membership spans `0..=HIGH_ID`,
/// so both `ALIAS_ID` (2) and `HIGH_ID` (258) are real, distinct members. The voting set stays at 2
/// (quorum 2); the learners are non-voting members the voters' fan-out reaches.
fn cluster() -> Cluster {
  let voters: u8 = 2;
  let learners: u16 = (HIGH_ID as u16) + 1 - voters as u16; // ids 0..=HIGH_ID
  // Two clients, a modest request budget, and a small checkpoint interval — enough committed traffic
  // to replicate to the learners without a heavy run.
  Cluster::with_members(voters, learners, 2, 50, 0xC0FFEE, 8)
}

#[test]
fn high_member_id_is_reached_by_the_fan_out() {
  let mut c = cluster();

  // The membership is sized by the TOTAL node count; the voting count is unchanged.
  assert_eq!(c.node_count(), HIGH_ID + 1);
  assert_eq!(c.voting_count(), 2);

  // The two voters form a quorum and commit; their `AllReplicas` / `Backups` fan-out spans the full
  // membership, so EVERY learner — including the high-id one at index 258 — receives the prepares and
  // applies the committed prefix. Delivery indexes `replicas[258]`; if the id truncated, the traffic
  // would have landed on `replicas[2]` and 258 would never advance.
  for _ in 0..4_000 {
    c.tick();
    if c.replica_commit(HIGH_ID).get() > 0 && c.replica_commit(ALIAS_ID).get() > 0 {
      break;
    }
  }
  assert!(
    c.replica_commit(HIGH_ID).get() > 0,
    "the high-id learner {HIGH_ID} received the fan-out and applied committed ops (commit {}) — \
     traffic routed to index {HIGH_ID}, not its 8-bit alias {ALIAS_ID}",
    c.replica_commit(HIGH_ID).get()
  );
  assert!(
    c.replica_commit(ALIAS_ID).get() > 0,
    "the aliasable low-id learner {ALIAS_ID} also advanced (commit {})",
    c.replica_commit(ALIAS_ID).get()
  );
}

#[test]
fn high_member_id_partitions_and_blocks_distinctly_from_its_alias() {
  let mut c = cluster();

  // The directed one-way matrix indexes the high id as itself: a leg out of 258 is independent of
  // the leg out of 2. Under an 8-bit truncation `block_one_way(258, …)` would have written 2's row,
  // flipping ALIAS_ID's leg too — assert it did not, and that the matrix is not symmetric (the
  // reverse leg to 258 still flows).
  c.block_one_way(HIGH_ID as u16, 1);
  assert!(
    c.one_way_blocked(HIGH_ID as u16, 1),
    "the high id's own outbound leg is blocked"
  );
  assert!(
    !c.one_way_blocked(ALIAS_ID as u16, 1),
    "the low id it would alias under truncation is untouched"
  );
  assert!(
    !c.one_way_blocked(1, HIGH_ID as u16),
    "the reverse leg to the high id still flows (directed, not symmetric)"
  );
  c.heal();
  assert!(
    !c.one_way_blocked(HIGH_ID as u16, 1),
    "heal clears the high id's leg"
  );

  // Partition the high-id learner ALONE into the minority (group 1); every voter and every other
  // learner — including ALIAS_ID — stays in the majority (group 0). The symmetric `partitioned`
  // probe must see 258 cut from the majority while 2 is not, proving the group vector indexes the
  // high id distinctly (a truncation would have placed 2 in group 1 too).
  let mut groups = vec![0u8; c.node_count()];
  groups[HIGH_ID] = 1;
  c.partition(groups);
  assert!(
    c.partitioned(HIGH_ID as u16, 0),
    "the high id is cut from the majority"
  );
  assert!(
    !c.partitioned(ALIAS_ID as u16, 0),
    "the aliasable low id stays in the majority"
  );

  // Drive the cluster while 258 is cut: the two voters still commit and their fan-out reaches the
  // in-majority learner 2, which advances; the cut high-id learner 258 receives nothing and stalls
  // at commit 0. If 258 aliased 2, partitioning 258 would have stalled 2 as well — so a strictly
  // advancing 2 next to a stalled 258 is direct proof the two ids route as distinct replicas.
  for _ in 0..4_000 {
    c.tick();
    if c.replica_commit(ALIAS_ID).get() > 0 {
      break;
    }
  }
  assert!(
    c.replica_commit(ALIAS_ID).get() > 0,
    "the in-majority learner {ALIAS_ID} advanced while {HIGH_ID} was cut"
  );
  assert_eq!(
    c.replica_commit(HIGH_ID).get(),
    0,
    "the partitioned high-id learner {HIGH_ID} stalled at commit 0 — distinct from id {ALIAS_ID}, \
     so its id did not truncate/alias into the majority group"
  );
}

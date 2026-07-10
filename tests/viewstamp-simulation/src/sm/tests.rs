use super::*;
use crate::block_store::MemBlockStore;

#[test]
fn apply_records_and_counts() {
  let mut sm = LogSm::default();
  assert_eq!(
    sm.apply(OpNumber::with(1), b"a").as_ref(),
    &1u64.to_be_bytes()
  );
  assert_eq!(
    sm.apply(OpNumber::with(2), b"b").as_ref(),
    &2u64.to_be_bytes()
  );
  assert_eq!(sm.applied().len(), 2);
}

#[test]
fn snapshot_round_trips() {
  let mut sm = LogSm::default();
  sm.apply(OpNumber::with(1), b"a");
  sm.apply(OpNumber::with(2), b"bb");
  let mut store = MemBlockStore::new();
  let root = sm.checkpoint(&mut store);
  let mut restored = LogSm::default();
  restored
    .restore(root, &store)
    .expect("the whole DAG is present");
  assert_eq!(restored.applied(), sm.applied());
}

/// Builds a batch body from `units` via the real codec.
fn batch_body(units: &[&[u8]]) -> Bytes {
  let mut b = viewstamp_proto::BatchBuilder::new(SIM_REPLY_BODY_BUDGET);
  for u in units {
    b.push(u).expect("test unit fits");
  }
  b.finish().expect("non-empty")
}

/// Decodes a reply body into its per-unit 8-byte big-endian counts.
fn reply_counts(body: &[u8]) -> Vec<u64> {
  viewstamp_proto::ReplyView::parse(body)
    .expect("BatchSm seals codec-valid replies")
    .units()
    .map(|u| u64::from_be_bytes(u.try_into().expect("8-byte unit replies")))
    .collect()
}

#[test]
fn batch_sm_applies_units_in_order_and_replies_with_global_unit_counts() {
  let mut sm = BatchSm::default();
  let r1 = sm.apply(OpNumber::with(1), &batch_body(&[b"a", b"bb", b""]));
  assert_eq!(reply_counts(&r1), vec![1, 2, 3]);
  let r2 = sm.apply(OpNumber::with(2), &batch_body(&[b"cc"]));
  assert_eq!(reply_counts(&r2), vec![4], "the unit count is global");
  assert_eq!(sm.applied().len(), 2, "one applied entry per OP");
  let units: Vec<(u64, u32, &[u8])> = sm
    .units()
    .iter()
    .map(|(op, idx, b)| (*op, *idx, b.as_ref()))
    .collect();
  assert_eq!(
    units,
    vec![(1, 0, &b"a"[..]), (1, 1, b"bb"), (1, 2, b""), (2, 0, b"cc"),],
    "per-unit history records (op, unit_index, unit_bytes) in apply order"
  );
}

#[test]
fn batch_sm_snapshot_round_trips_the_unit_history() {
  let mut sm = BatchSm::default();
  sm.apply(OpNumber::with(1), &batch_body(&[b"a", b"bb"]));
  sm.apply(OpNumber::with(2), &batch_body(&[b"c"]));
  let mut store = MemBlockStore::new();
  let root = sm.checkpoint(&mut store);
  let mut restored = BatchSm::default();
  restored
    .restore(root, &store)
    .expect("the whole DAG is present");
  assert_eq!(restored.applied(), sm.applied());
  assert_eq!(
    restored.units(),
    sm.units(),
    "the unit history is rebuilt from the restored bodies"
  );
  // Applying past the restore keeps the global unit count consistent with the rebuilt history.
  let r = restored.apply(OpNumber::with(3), &batch_body(&[b"d"]));
  assert_eq!(reply_counts(&r), vec![4]);
}

#[test]
#[should_panic(expected = "malformed body")]
fn batch_sm_panics_loudly_on_a_non_batch_body() {
  // A plain 8-byte LogSm-style body starts with 4 zero bytes (a zero unit count) — malformed for
  // the batch codec, which in a batching-mode sim means a non-codec-built body leaked through.
  BatchSm::default().apply(OpNumber::with(1), &1u64.to_be_bytes());
}

/// Walks the checkpoint DAG rooted at `root` via `S::block_references`, returning every reachable
/// block address (root included). Every reachable block is required to be present in `store`,
/// matching the proto contract that the sync frontier drains before reconstruction.
fn reachable<S: StateMachine>(
  root: BlockAddress,
  store: &MemBlockStore,
) -> std::collections::BTreeSet<BlockAddress> {
  let mut seen = std::collections::BTreeSet::new();
  let mut stack = vec![root];
  while let Some(addr) = stack.pop() {
    if !seen.insert(addr) {
      continue;
    }
    let block = store
      .read_block(addr)
      .expect("every reachable block is present in the store");
    for child in S::block_references(&block) {
      stack.push(child);
    }
  }
  seen
}

#[test]
fn incremental_checkpoint_rewrites_only_changed_blocks() {
  // A log of several FULL leaves: with DAG_LEAF_RUN == 4, 20 ops is exactly 5 full leaves, so the
  // earlier leaves are unaffected by a later append and must keep their content addresses.
  let mut sm = LogSm::default();
  for op in 1..=20u64 {
    sm.apply(OpNumber::with(op), format!("body-{op}").as_bytes());
  }
  assert_eq!(
    sm.applied().len() % DAG_LEAF_RUN,
    0,
    "fixture is full leaves"
  );

  let mut store = MemBlockStore::new();
  let root1 = sm.checkpoint(&mut store);
  let set1 = reachable::<LogSm>(root1, &store);
  // 5 leaves + 1 index root.
  assert_eq!(set1.len(), 6, "5 full leaves plus the index root");

  // One more op: a new partial leaf (1 entry) plus a new index root that names six leaves.
  sm.apply(OpNumber::with(21), b"body-21");
  let root2 = sm.checkpoint(&mut store);
  let set2 = reachable::<LogSm>(root2, &store);

  assert_ne!(
    root2, root1,
    "the root changed: the index now names a new leaf"
  );

  // Blocks a holder of root1's set would have to fetch to materialize root2: exactly the blocks
  // reachable from root2 that were NOT already reachable from root1.
  let missing: std::collections::BTreeSet<_> = set2.difference(&set1).copied().collect();
  assert_eq!(
    missing.len(),
    2,
    "only the new partial leaf and the new index root are unshared: {missing:?}"
  );
  // The real incrementality claim: the diff is a small constant, STRICTLY fewer than a full
  // re-fetch of root2 (7 blocks). The five earlier full leaves are shared by identical address.
  assert_eq!(set2.len(), 7, "6 leaves plus the index root");
  assert!(
    missing.len() < set2.len(),
    "incremental fetch ({}) << full re-fetch ({})",
    missing.len(),
    set2.len()
  );
  let shared = set1.intersection(&set2).count();
  assert_eq!(
    shared, 5,
    "the five earlier full leaves are shared verbatim"
  );

  // Faithful reconstruction: a fresh SM rebuilt from root2 reproduces the applied history.
  let mut fresh = LogSm::default();
  fresh
    .restore(root2, &store)
    .expect("the whole DAG is present");
  assert_eq!(fresh.applied(), sm.applied());
}

#[test]
fn dag_checkpoint_round_trips_partial_and_empty_logs() {
  // A partial trailing leaf (6 ops = one full leaf + a 2-entry leaf) round-trips faithfully.
  for n in [0u64, 1, 3, 6, 9] {
    let mut sm = LogSm::default();
    for op in 1..=n {
      sm.apply(OpNumber::with(op), format!("x{op}").as_bytes());
    }
    let mut store = MemBlockStore::new();
    let root = sm.checkpoint(&mut store);
    let mut fresh = LogSm::default();
    fresh
      .restore(root, &store)
      .expect("all blocks present after checkpoint");
    assert_eq!(fresh.applied(), sm.applied(), "round-trip with {n} ops");
  }
}

#[test]
fn dag_checkpoint_and_restore_carry_batch_units() {
  let mut sm = BatchSm::default();
  for op in 1..=6u64 {
    sm.apply(OpNumber::with(op), &batch_body(&[b"a", b"bb"]));
  }
  let mut store = MemBlockStore::new();
  let root = sm.checkpoint(&mut store);
  let mut fresh = BatchSm::default();
  fresh
    .restore(root, &store)
    .expect("all blocks present after checkpoint");
  assert_eq!(fresh.applied(), sm.applied());
  assert_eq!(
    fresh.units(),
    sm.units(),
    "the unit history is rebuilt from the restored bodies, as restore does"
  );
}

#[test]
fn sim_sm_delegates_dag_per_variant() {
  // Plain and Batch both route the DAG methods to their inner SM; the variant restored matches.
  let mut plain = SimSm::Plain(LogSm::default());
  for op in 1..=5u64 {
    plain.apply(OpNumber::with(op), format!("p{op}").as_bytes());
  }
  let mut store = MemBlockStore::new();
  let root = plain.checkpoint(&mut store);
  let mut fresh = SimSm::Plain(LogSm::default());
  fresh
    .restore(root, &store)
    .expect("all blocks present after checkpoint");
  assert_eq!(fresh.applied(), plain.applied());

  let mut batch = SimSm::Batch(BatchSm::default());
  for op in 1..=5u64 {
    batch.apply(OpNumber::with(op), &batch_body(&[b"u"]));
  }
  let mut bstore = MemBlockStore::new();
  let broot = batch.checkpoint(&mut bstore);
  let mut bfresh = SimSm::Batch(BatchSm::default());
  bfresh
    .restore(broot, &bstore)
    .expect("all blocks present after checkpoint");
  assert_eq!(bfresh.applied(), batch.applied());
  assert_eq!(bfresh.units(), batch.units());
}

#[test]
fn sim_sm_delegates_per_variant() {
  let mut plain = SimSm::Plain(LogSm::default());
  assert_eq!(
    plain.apply(OpNumber::with(1), b"x").as_ref(),
    &1u64.to_be_bytes(),
    "the plain variant is LogSm verbatim"
  );
  assert_eq!(plain.applied().len(), 1);
  assert!(plain.units().is_empty(), "no unit structure in plain mode");
  // The plain variant checkpoints byte-compatibly with LogSm: the content-addressed root over the
  // same applied history is identical, so a holder cannot distinguish the two checkpoints.
  let mut log = LogSm::default();
  log.apply(OpNumber::with(1), b"x");
  let mut plain_store = MemBlockStore::new();
  let mut log_store = MemBlockStore::new();
  assert_eq!(
    plain.checkpoint(&mut plain_store),
    log.checkpoint(&mut log_store)
  );

  let mut batch = SimSm::Batch(BatchSm::default());
  batch.apply(OpNumber::with(1), &batch_body(&[b"u1", b"u2"]));
  assert_eq!(batch.applied().len(), 1);
  assert_eq!(batch.units().len(), 2);
  let mut store = MemBlockStore::new();
  let root = batch.checkpoint(&mut store);
  let mut restored = SimSm::Batch(BatchSm::default());
  restored
    .restore(root, &store)
    .expect("all blocks present after checkpoint");
  assert_eq!(restored.units(), batch.units());
}

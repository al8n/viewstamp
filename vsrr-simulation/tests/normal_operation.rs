use vsrr_simulation::{CheckResult, Cluster, Faults, check_safety};

#[test]
fn backups_converge_via_commit_heartbeat() {
  // 3 clients x 5 = 15 ops. Latency + jitter (reorder), no drops. Each backup must
  // reach the SAME 15-op log as the primary; the final op's commit arrives only via
  // the Commit heartbeat (no later Prepare piggybacks it), so this requires on_commit.
  let mut c = Cluster::new(3, 3, 5, /*seed*/ 12345);
  c.set_faults(vsrr_simulation::Faults {
    latency: core::time::Duration::from_millis(2),
    jitter: core::time::Duration::from_millis(8),
    drop_per_mille: 0,
  });
  for _ in 0..5000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  let r0: Vec<(u64, Vec<u8>)> = c.replica_sm(0).applied().to_vec();
  assert_eq!(r0.len(), 15, "primary applied 15 ops");
  for (i, (op, _)) in r0.iter().enumerate() {
    assert_eq!(*op, (i as u64) + 1, "contiguous, no duplicate apply");
  }
  for ri in 1..3 {
    assert_eq!(
      c.replica_sm(ri).applied(),
      r0.as_slice(),
      "backup {ri} must converge to the primary's exact log (content)"
    );
  }
}

#[test]
fn single_replica_commits_one_client() {
  // 1 replica -> quorum 1 -> primary commits on its own prepare.
  let mut c = Cluster::new(1, 1, 3, /*seed*/ 1);
  for _ in 0..200 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  assert!(c.client(0).is_done(), "client should receive all 3 replies");
  assert_eq!(c.replica_sm(0).applied().len(), 3, "all 3 ops applied");
}

#[test]
fn three_replicas_commit_no_faults() {
  let mut c = Cluster::new(3, 2, 4, /*seed*/ 5);
  for _ in 0..2000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  for i in 0..c.client_count() {
    assert!(c.client(i).is_done(), "client {i} should finish");
  }
  // Agreement: all replicas applied the same op sequence (shorter is a prefix of longer).
  let r0: Vec<u64> = c
    .replica_sm(0)
    .applied()
    .iter()
    .map(|(op, _)| *op)
    .collect();
  for i in 1..3 {
    let ri: Vec<u64> = c
      .replica_sm(i)
      .applied()
      .iter()
      .map(|(op, _)| *op)
      .collect();
    let n = r0.len().min(ri.len());
    assert_eq!(&r0[..n], &ri[..n], "replica {i} log diverges");
  }
  assert_eq!(
    r0.len(),
    8,
    "2 clients * 4 requests committed on the primary"
  );
}

#[test]
fn progress_under_message_loss() {
  // 20% drop. Liveness requires BOTH the primary's prepare retransmit AND the
  // client's request retransmit. Sweep seeds so no single lucky seed can mask a
  // dead retransmit path (seed 0 deadlocks unless the primary actually retransmits).
  for seed in 0..32u64 {
    let mut c = Cluster::new(3, 2, 4, seed);
    c.set_faults(vsrr_simulation::Faults {
      latency: core::time::Duration::from_millis(2),
      jitter: core::time::Duration::from_millis(4),
      drop_per_mille: 200,
    });
    let mut done = false;
    for _ in 0..200_000 {
      c.tick();
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: all clients must finish despite 20% message loss"
    );
  }
}

#[test]
fn fault_sweep_safety_and_liveness() {
  // Per seed: a faulty phase (loss + delay + reorder) during which SAFETY must
  // hold at every step; then heal, after which LIVENESS holds (all clients done)
  // and safety still holds. Safety is prefix-agreement (a lagging backup is a
  // valid prefix); liveness is "every client got its replies".
  for seed in 0..32u64 {
    let mut c = Cluster::new(3, 3, 4, seed);
    c.set_faults(Faults {
      latency: core::time::Duration::from_millis(2),
      jitter: core::time::Duration::from_millis(10),
      drop_per_mille: 150,
    });
    for _ in 0..10_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety violated during faults"
      );
    }
    c.set_faults(Faults::none());
    let mut done = false;
    for _ in 0..200_000 {
      c.tick();
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(done, "seed {seed}: clients did not finish after healing");
    assert_eq!(
      check_safety(&c),
      CheckResult::Ok,
      "seed {seed}: safety violated after heal"
    );
  }
}

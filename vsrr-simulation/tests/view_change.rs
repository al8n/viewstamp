use std::time::Duration;

use vsrr_simulation::{CheckResult, Cluster, Faults, check_safety};

#[test]
fn primary_crash_elects_new_primary_and_clients_finish() {
  // 3 replicas, 2 clients x 3 requests. Let a couple of ops commit, crash the primary,
  // and assert the cluster elects a new primary and every client finishes.
  let mut c = Cluster::new(3, 2, 3, /*seed*/ 42);

  // run until at least one op commits on the primary (replica 0, view 0)
  for _ in 0..2000 {
    c.tick();
    if c.replica_sm(0).applied().len() >= 2 {
      break;
    }
  }
  assert!(
    c.replica_sm(0).applied().len() >= 2,
    "warm-up should commit a couple ops"
  );

  // crash the primary; the backups must view-change and finish the clients' work.
  c.crash(0);
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
    "clients must finish after the primary crashes and a new primary is elected"
  );

  // Safety: across the view change, no committed op was lost or diverged.
  assert_eq!(
    check_safety(&c),
    CheckResult::Ok,
    "applied logs must agree across the view change (no divergence, no lost commit)"
  );

  // a surviving replica must have advanced past view 0.
  let survivor_view_advanced = (1..3).any(|i| c.replica_view(i).get() >= 1);
  assert!(
    survivor_view_advanced,
    "a surviving replica must have moved to a new view"
  );
}

#[test]
fn no_faults_means_no_view_change() {
  // Regression guard for the `primary_idle` reset: with a healthy primary, backups must NOT
  // spuriously start a view change. Every replica stays in view 0.
  let mut c = Cluster::new(3, 2, 4, /*seed*/ 7);
  for _ in 0..5000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  assert!(
    (0..c.client_count()).all(|i| c.client(i).is_done()),
    "clients finish"
  );
  for i in 0..c.replica_count() {
    assert_eq!(
      c.replica_view(i).get(),
      0,
      "replica {i} must stay in view 0 with a healthy primary (no spurious view change)"
    );
  }
}

#[test]
fn primary_crash_with_uncommitted_tail_preserves_committed_ops() {
  // Drops create an uncommitted tail on the primary; crashing it forces the new primary to
  // run canonical selection. Committed ops must survive and no replica may diverge.
  let mut c = Cluster::new(3, 2, 3, /*seed*/ 9);
  c.set_faults(Faults {
    latency: Duration::from_millis(1),
    jitter: Duration::from_millis(4),
    drop_per_mille: 80, // lossy: the primary will have uncommitted ops in flight
    duplicate_per_mille: 0,
  });

  // Warm up until the primary has committed at least one op (a shared committed prefix exists).
  for _ in 0..20_000 {
    c.tick();
    if !c.replica_sm(0).applied().is_empty() {
      break;
    }
  }
  assert!(
    !c.replica_sm(0).applied().is_empty(),
    "warm-up commits at least one op"
  );
  let committed_prefix = c.replica_sm(0).applied().to_vec();

  c.crash(0);
  let mut done = false;
  for _ in 0..1_000_000 {
    c.tick();
    // Safety must hold at every step of the recovery.
    assert_eq!(
      check_safety(&c),
      CheckResult::Ok,
      "no divergence during/after view change"
    );
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      done = true;
      break;
    }
  }
  assert!(done, "clients finish after the crash (majority survives)");

  // Every op the old primary had committed survives on a surviving replica, in order.
  let survivor = c.replica_sm(1).applied().to_vec();
  let n = committed_prefix.len().min(survivor.len());
  assert_eq!(
    committed_prefix[..n],
    survivor[..n],
    "committed prefix preserved across the view change"
  );
}

#[test]
fn two_primary_crashes_escalate_to_a_live_primary() {
  // N=5. Crash the view-0 primary, let the change reach view 1, then crash the view-1 primary too;
  // the cluster must reach a live primary (view ≥ 2) and finish the clients' work.
  let mut c = Cluster::new(5, 2, 3, /*seed*/ 11);
  for _ in 0..20_000 {
    c.tick();
    if !c.replica_sm(0).applied().is_empty() {
      break;
    }
  }
  c.crash(0); // primary of view 0
  for _ in 0..50_000 {
    c.tick();
    if c.replica_view(2).get() >= 1 {
      break; // a change toward view 1 has reached replica 2
    }
  }
  c.crash(1); // primary of view 1 — forces a further change toward view 2 (replica 2)

  let mut done = false;
  for _ in 0..1_000_000 {
    c.tick();
    assert_eq!(
      check_safety(&c),
      CheckResult::Ok,
      "safety throughout the double failover"
    );
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      done = true;
      break;
    }
  }
  assert!(done, "clients finish after surviving two dead primaries");
  assert!(
    c.replica_view(2).get() >= 2,
    "reached at least view 2 (a live primary)"
  );
}

#[test]
fn partition_isolating_primary_then_heal_converges() {
  // N=5. Isolate the primary (replica 0) with replica 4 (minority {0,4}); the majority {1,2,3}
  // elects a new primary. After heal, the minority catches up via GetView and everyone converges.
  let mut c = Cluster::new(5, 2, 3, /*seed*/ 13);
  for _ in 0..20_000 {
    c.tick();
    if !c.replica_sm(0).applied().is_empty() {
      break;
    }
  }
  c.partition(vec![1, 0, 0, 0, 1]); // group 0 = {1,2,3} (majority), group 1 = {0,4}
  for _ in 0..100_000 {
    c.tick();
    assert_eq!(
      check_safety(&c),
      CheckResult::Ok,
      "safety while partitioned"
    );
    if c.replica_view(1).get() >= 1 {
      break; // majority elected a new primary
    }
  }
  assert!(
    c.replica_view(1).get() >= 1,
    "majority elects a new primary while the old one is isolated"
  );

  c.heal();
  let mut done = false;
  for _ in 0..1_000_000 {
    c.tick();
    assert_eq!(check_safety(&c), CheckResult::Ok, "safety after heal");
    if (0..c.client_count()).all(|i| c.client(i).is_done()) {
      done = true;
      break;
    }
  }
  assert!(
    done,
    "after heal, the minority catches up and all clients finish"
  );
}

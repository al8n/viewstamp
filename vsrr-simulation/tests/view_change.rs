use vsrr_simulation::{CheckResult, Cluster, check_safety};

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

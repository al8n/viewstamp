//! Durable-view gate: durable-view-before-participate + recover-restores-view.
//!
//! A replica that advanced its view via a view change, then crashed, must recover that view on
//! restart — never regressing to an earlier view (which would risk a cross-view double-vote /
//! split-brain). We crash the primary to force a real view change on the survivors, wait until a
//! chosen backup survivor is durably in view >= 1 (durable-view-before-participate guarantees a
//! replica observed participating in a view has that view durable), then crash + restart it and
//! assert it recovers view >= the view it held. `check_safety` + view-monotonicity hold throughout.
//!
//! Uses N=5 so that crashing the primary AND a survivor still leaves a 3-of-5 quorum — the cluster
//! keeps committing the whole time and the restarted replica rejoins a live quorum.

use viewstamp_simulation::{CheckResult, Cluster, ViewMonotonicChecker, check_safety};

#[test]
fn view_changed_replica_recovers_its_view_after_crash() {
  for seed in 0..16u64 {
    let mut c = Cluster::new(5, 2, 3, seed);
    let mut vm = ViewMonotonicChecker::new(5);

    // Warm up until the initial primary (replica 0, view 0) has committed a couple of ops.
    let mut warm = false;
    for _ in 0..30_000 {
      c.tick();
      assert_eq!(
        vm.observe(&c),
        CheckResult::Ok,
        "seed {seed}: view monotonic (warm-up)"
      );
      if c.replica_sm(0).applied().len() >= 2 {
        warm = true;
        break;
      }
    }
    assert!(warm, "seed {seed}: warm-up commits >= 2 ops");

    // Crash the primary → the surviving {1,2,3,4} (a 4-replica majority) run a view change.
    c.crash(0);

    // Wait until a BACKUP survivor (replica 2) is observed in view >= 1. Because a replica persists
    // the new view to its superblock BEFORE participating in it, observing replica 2 at view >= 1
    // means view >= 1 is durable in replica 2's superblock.
    let survivor = 2usize;
    let mut advanced = false;
    for _ in 0..200_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety during failover"
      );
      assert_eq!(
        vm.observe(&c),
        CheckResult::Ok,
        "seed {seed}: view monotonic during failover"
      );
      if c.replica_view(survivor).get() >= 1 {
        advanced = true;
        break;
      }
    }
    assert!(advanced, "seed {seed}: survivor advanced to view >= 1");
    let view_before = c.replica_view(survivor).get();
    assert!(view_before >= 1);

    // Crash the survivor, let virtual time pass, then restart it: recover() rebuilds it from its
    // durable WAL + superblock. {1,3,4} remain — still a 3-of-5 quorum.
    c.crash(survivor);
    for _ in 0..2_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety while survivor down"
      );
    }
    c.restart(survivor);

    // THE GATE: the restarted replica recovered its advanced view — it did NOT regress below it.
    let view_after = c.replica_view(survivor).get();
    assert!(
      view_after >= view_before,
      "seed {seed}: recovered view {view_after} regressed below the durable view {view_before} \
       (durable-view-before-participate violated → cross-view double-vote risk)"
    );

    // The cluster stays safe + monotonic as the restarted replica rejoins, and the clients finish.
    let mut done = false;
    for _ in 0..200_000 {
      c.tick();
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety after restart"
      );
      assert_eq!(
        vm.observe(&c),
        CheckResult::Ok,
        "seed {seed}: view monotonic after restart"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: clients finish after the survivor rejoins"
    );
  }
}

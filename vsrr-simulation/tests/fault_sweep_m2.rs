use core::time::Duration;
use vsrr_simulation::{CheckResult, Cluster, Faults, ViewMonotonicChecker, check_safety};

/// Crash-stop sweep: N=5, crash one replica (often the primary). A 4-replica majority always
/// survives, so safety AND liveness must hold under message loss + jitter, for every seed.
#[test]
fn m2_sweep_crash_stop_safety_and_liveness() {
  for seed in 0..32u64 {
    let mut c = Cluster::new(5, 2, 3, seed);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(5),
      drop_per_mille: 30,
    });
    let mut vm = ViewMonotonicChecker::new(5);

    for _ in 0..30_000 {
      c.tick();
      assert!(
        vm.observe(&c).is_ok(),
        "seed {seed}: view monotonic (warm-up)"
      );
      if !c.replica_sm(0).applied().is_empty() {
        break;
      }
    }
    c.crash((seed % 2) as usize); // crash replica 0 or 1 (frequently the active primary)

    let mut done = false;
    for _ in 0..2_000_000 {
      c.tick();
      assert!(vm.observe(&c).is_ok(), "seed {seed}: view monotonic");
      assert_eq!(check_safety(&c), CheckResult::Ok, "seed {seed}: safety");
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: a 4-of-5 majority survives → clients must finish"
    );
  }
}

/// Partition sweep: N=5, isolate the primary into a minority; the majority {1,2,3} fails over.
/// Safety must hold throughout; after heal, liveness must hold.
#[test]
fn m2_sweep_partition_heal_safety_and_liveness() {
  for seed in 0..32u64 {
    let mut c = Cluster::new(5, 2, 3, seed);
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(3),
      drop_per_mille: 10,
    });
    let mut vm = ViewMonotonicChecker::new(5);

    for _ in 0..30_000 {
      c.tick();
      if !c.replica_sm(0).applied().is_empty() {
        break;
      }
    }

    c.partition(vec![1, 0, 0, 0, 1]); // majority {1,2,3} | minority {0,4} (old primary isolated)
    for _ in 0..200_000 {
      c.tick();
      assert!(
        vm.observe(&c).is_ok(),
        "seed {seed}: view monotonic (partition)"
      );
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (partition)"
      );
      if c.replica_view(1).get() >= 1 {
        break;
      }
    }

    c.heal();
    let mut done = false;
    for _ in 0..2_000_000 {
      c.tick();
      assert!(vm.observe(&c).is_ok(), "seed {seed}: view monotonic (heal)");
      assert_eq!(
        check_safety(&c),
        CheckResult::Ok,
        "seed {seed}: safety (heal)"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        done = true;
        break;
      }
    }
    assert!(
      done,
      "seed {seed}: after heal, the minority catches up and clients finish"
    );
  }
}

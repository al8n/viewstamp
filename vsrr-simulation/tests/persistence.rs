//! M3.1a gate: committed operations survive a clean crash + restart.
//!
//! Crash a backup, let the cluster keep committing on the surviving quorum, then restart the
//! backup so it recovers from its durable WAL. The restarted replica must re-apply its committed
//! prefix with no divergence. The primary stays up throughout, so there is no view change — this
//! isolates durable normal-op + recovery.

use vsrr_simulation::{CheckResult, Cluster, check_safety};

#[test]
fn committed_ops_survive_clean_crash_and_restart() {
  let mut c = Cluster::new(3, 2, 3, /*seed*/ 7);

  // Warm up until the BACKUP we will crash (replica 1) has durably committed + applied >= 2 ops,
  // so it has a non-trivial durable prefix to recover. Append-before-ack means "applied" implies
  // those ops were durable in replica 1's own WAL.
  let mut warm = false;
  for _ in 0..50_000 {
    c.tick();
    if c.replica_sm(1).applied().len() >= 2 {
      warm = true;
      break;
    }
  }
  assert!(warm, "replica 1 commits >= 2 ops before the crash");

  c.crash(1); // crash a backup; primary 0 stays up => no view change
  for _ in 0..2_000 {
    c.tick(); // the cluster keeps committing on the {0,2} quorum
  }
  c.restart(1); // recover replica 1 from its durable WAL
  assert!(
    c.replica_sm(1).applied().is_empty(),
    "recovery resets the SM; the prefix below is genuinely re-applied from the WAL, not retained"
  );

  // Run until the clients finish AND the restarted replica has re-applied a non-trivial prefix.
  // check_safety runs every tick: an empty-body or diverged recovery would trip it here.
  let mut done = false;
  for _ in 0..200_000 {
    c.tick();
    assert_eq!(
      check_safety(&c),
      CheckResult::Ok,
      "no divergence across crash + restart"
    );
    let clients_done = (0..c.client_count()).all(|i| c.client(i).is_done());
    if clients_done && c.replica_sm(1).applied().len() >= 2 {
      done = true;
      break;
    }
  }
  assert!(
    done,
    "clients finish and the restarted replica re-applies its prefix"
  );

  // Non-vacuous: the restarted replica re-applied a real committed prefix from its WAL bodies...
  let restarted = c.replica_sm(1).applied().to_vec();
  let primary = c.replica_sm(0).applied().to_vec();
  let n = primary.len().min(restarted.len());
  assert!(
    n >= 2,
    "the prefix comparison is non-vacuous (both replicas applied >= 2 ops)"
  );
  // ...and it agrees byte-for-byte with the primary's committed log on the common prefix.
  assert_eq!(
    primary[..n],
    restarted[..n],
    "restarted replica's committed prefix agrees with the primary"
  );
}

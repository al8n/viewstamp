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

/// R4-F1 liveness: a PRIMARY crash + restart must not freeze the cluster.
///
/// Before the fix, a recovered primary resumed `Normal` with an EMPTY pipeline (`inflight`) and a
/// session table only at `checkpoint_op`. It kept heartbeating `Commit(checkpoint_op)` (so backups
/// never started a view change) while every re-acked `PrepareOk` dropped on the empty `inflight` —
/// commit FROZE at `checkpoint_op` (a liveness deadlock), and a client request retried in
/// `(checkpoint_op, op]` could execute twice. The fix abdicates the recovered primary to `view + 1`:
/// the cluster runs a clean view change, rebuilds the pipeline via DVC collection, and makes
/// progress; `on_request` returns early while not Normal, closing the double-execute hazard.
///
/// This crashes the primary and restarts it IMMEDIATELY (before the backups time out into their own
/// view change), so the restarted replica recovers as the primary of its restored view and must
/// abdicate. The cluster must then complete a view change AND advance commit past the pre-crash
/// checkpoint, with no safety divergence.
#[test]
fn primary_crash_and_restart_does_not_freeze_commit() {
  // checkpoint_ops = 2 so a checkpoint is reached during warm-up (the freeze, if any, pins commit at
  // checkpoint_op > 0 — making the "commit advanced past checkpoint_op" assertion non-vacuous).
  // 3 clients x 6 requests = 18 ops of work, far past the first checkpoint.
  let mut c = Cluster::with_checkpoint_ops(3, 3, 6, /*seed*/ 7, /*checkpoint_ops*/ 2);

  // Warm up until the primary (replica 0, view 0) has durably checkpointed at least once AND has
  // uncommitted/committed ops beyond that checkpoint in its pipeline — so a recovered-primary freeze
  // would be observable (commit stuck at checkpoint_op while ops above it exist).
  let mut warm = false;
  for _ in 0..50_000 {
    c.tick();
    if c.replica_checkpoint_op(0).get() >= 2
      && c.replica_op(0).get() > c.replica_checkpoint_op(0).get()
    {
      warm = true;
      break;
    }
  }
  assert!(
    warm,
    "the primary checkpoints (>=2) and holds ops beyond the checkpoint before the crash"
  );
  assert!(
    c.replica_is_primary(0),
    "replica 0 leads view 0 before the crash"
  );
  let checkpoint_before = c.replica_checkpoint_op(0).get();

  // Crash the primary and restart it IMMEDIATELY (before the backups escalate a view change), so it
  // recovers AS the primary of view 0 and must abdicate rather than resume with an empty pipeline.
  c.crash(0);
  c.tick(); // a single tick: not enough for the backups' primary-idle to fire
  c.restart(0);

  // Liveness: the cluster must finish every client AND advance commit past the pre-crash checkpoint.
  // Safety is checked every tick: an empty-body / diverged / double-executed op would trip it.
  let mut done = false;
  for _ in 0..400_000 {
    c.tick();
    assert_eq!(
      check_safety(&c),
      CheckResult::Ok,
      "no divergence / double-execute across the primary crash + restart"
    );
    let clients_done = (0..c.client_count()).all(|i| c.client(i).is_done());
    if clients_done {
      done = true;
      break;
    }
  }
  assert!(
    done,
    "the cluster makes progress after a primary restart (no commit freeze at checkpoint_op)"
  );

  // A real view change occurred (the recovered ex-primary abdicated off view 0).
  assert!(
    c.any_replica_view_advanced_beyond(0),
    "the recovered primary abdicated → the cluster advanced past view 0"
  );

  // Commit advanced strictly past the pre-crash checkpoint on a live replica — the deadlock is gone.
  let max_commit = (0..c.replica_count())
    .filter(|&i| !c.is_crashed(i))
    .map(|i| c.replica_commit(i).get())
    .max()
    .unwrap_or(0);
  assert!(
    max_commit > checkpoint_before,
    "commit advanced past the pre-crash checkpoint ({max_commit} > {checkpoint_before}), not frozen"
  );
}

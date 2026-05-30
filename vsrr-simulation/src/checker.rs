//! Safety / agreement checks over a cluster run.

use crate::cluster::Cluster;

/// Outcome of checking a cluster's invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
  /// All checked invariants hold.
  Ok,
  /// An invariant was violated, with a human-readable reason.
  Violation(String),
}

impl CheckResult {
  /// True iff all invariants held.
  pub const fn is_ok(&self) -> bool {
    matches!(self, Self::Ok)
  }

  /// True iff an invariant was violated.
  pub const fn is_violation(&self) -> bool {
    matches!(self, Self::Violation(_))
  }
}

/// Checks the M1 safety invariants:
/// 1. **Contiguity/uniqueness** — each replica's applied ops are `1,2,3,…` (no gap, no duplicate).
/// 2. **Agreement** — across replicas, the shorter applied `(op, body)` sequence is a prefix of
///    the longer (full content comparison, not just op numbers).
/// 3. **Client safety** — each client's replies are for strictly increasing request numbers `1..=n`.
pub fn check_safety(cluster: &Cluster) -> CheckResult {
  let mut logs: Vec<Vec<(u64, Vec<u8>)>> = Vec::new();
  for i in 0..cluster.replica_count() {
    let applied: Vec<(u64, Vec<u8>)> = cluster.replica_sm(i).applied().to_vec();
    for (idx, (op, _)) in applied.iter().enumerate() {
      if *op != idx as u64 + 1 {
        return CheckResult::Violation(format!(
          "replica {i}: applied op {op} at position {idx} (expected {})",
          idx + 1
        ));
      }
    }
    logs.push(applied);
  }
  for i in 1..logs.len() {
    let n = logs[0].len().min(logs[i].len());
    if logs[0][..n] != logs[i][..n] {
      return CheckResult::Violation(format!(
        "replica {i} diverges from replica 0 (content mismatch in applied prefix)"
      ));
    }
  }
  for i in 0..cluster.client_count() {
    for (idx, (rn, _)) in cluster.client(i).replies().iter().enumerate() {
      if *rn != (idx as u64) + 1 {
        return CheckResult::Violation(format!(
          "client {i}: reply for request {rn} at position {idx} (expected {})",
          idx + 1
        ));
      }
    }
  }
  CheckResult::Ok
}

/// Stateful **durability** checker: every committed op survives crash + storage-fault + restart.
///
/// `check_safety` proves agreement *at one instant*; this checker proves it *across time*, including
/// a crash + restart window. It maintains the cluster's **committed history** — the longest applied
/// `(op, body)` prefix ever observed on any replica (monotonically extended) — and on each
/// [`observe`](Self::observe) enforces, for every replica:
///
/// 1. **No committed op is ever rewritten** — a replica's applied log must agree (content) with the
///    committed history on their common prefix. (The across-time strengthening of `check_safety`: a
///    recovery that re-applied a *different* body for a committed op trips here.)
/// 2. **`checkpoint_op` is monotone non-decreasing** per replica (a durable checkpoint never goes
///    backwards — it is a committed+applied watermark).
///
/// [`check`](Self::check) then enforces the no-loss property: the committed history must still be
/// **fully present on at least one operational, non-crashed replica** — i.e. recovery never lost a
/// committed op cluster-wide. (A lagging or still-catching-up recovered replica is allowed to be
/// *behind* the committed history, as long as some replica still holds it — what matters is that the
/// op survived *somewhere*, which is exactly the durability guarantee a quorum provides.)
#[derive(Debug)]
pub struct DurabilityChecker {
  /// The longest applied `(op, body)` prefix ever observed (the committed history high-water).
  committed: Vec<(u64, Vec<u8>)>,
  /// Per-replica high-water of `checkpoint_op` (monotonicity guard).
  checkpoint_hw: Vec<u64>,
}

impl DurabilityChecker {
  /// A durability checker for a cluster of `replica_count` replicas.
  pub fn new(replica_count: usize) -> Self {
    Self {
      committed: Vec::new(),
      checkpoint_hw: vec![0; replica_count],
    }
  }

  /// Folds one set of per-replica applied logs + checkpoint-ops into the committed history, returning
  /// a violation on a rewritten committed op or a regressed checkpoint. Pure over its inputs so the
  /// monotonicity logic is unit-testable without a live `Cluster`.
  fn fold(&mut self, applied: &[Vec<(u64, Vec<u8>)>], checkpoint_ops: &[u64]) -> CheckResult {
    for (i, a) in applied.iter().enumerate() {
      // (1) No committed op rewritten: agree with the committed history on the common prefix.
      let n = a.len().min(self.committed.len());
      if a[..n] != self.committed[..n] {
        return CheckResult::Violation(format!(
          "replica {i}: applied prefix diverges from the committed history (a committed op was \
           rewritten/lost across time)"
        ));
      }
      // Extend the committed history if this replica is strictly ahead (and agrees on the prefix).
      if a.len() > self.committed.len() {
        self.committed = a.clone();
      }
    }
    for (i, &cp) in checkpoint_ops.iter().enumerate() {
      if cp < self.checkpoint_hw[i] {
        return CheckResult::Violation(format!(
          "replica {i}: checkpoint_op regressed to {cp} (was {})",
          self.checkpoint_hw[i]
        ));
      }
      self.checkpoint_hw[i] = cp;
    }
    CheckResult::Ok
  }

  /// Sample the cluster: update the committed history and return a violation if any replica rewrote a
  /// committed op or regressed its `checkpoint_op`. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let applied: Vec<Vec<(u64, Vec<u8>)>> = (0..cluster.replica_count())
      .map(|i| cluster.replica_sm(i).applied().to_vec())
      .collect();
    let checkpoint_ops: Vec<u64> = (0..cluster.replica_count())
      .map(|i| cluster.replica_checkpoint_op(i).get())
      .collect();
    self.fold(&applied, &checkpoint_ops)
  }

  /// Final durability assertion: the full committed history must still be present on at least one
  /// operational, non-crashed replica — proving no committed op was lost across crash + storage-fault
  /// + restart. (Returns `Ok` vacuously if nothing was ever committed.)
  pub fn check(&self, cluster: &Cluster) -> CheckResult {
    if self.committed.is_empty() {
      return CheckResult::Ok;
    }
    let survived = (0..cluster.replica_count()).any(|i| {
      !cluster.is_crashed(i)
        && cluster.replica_status_is_operational(i)
        && cluster.replica_sm(i).applied().len() >= self.committed.len()
        && cluster.replica_sm(i).applied()[..self.committed.len()] == self.committed[..]
    });
    if survived {
      CheckResult::Ok
    } else {
      CheckResult::Violation(format!(
        "no operational replica retains the committed history of {} ops — a committed op was lost \
         across crash + storage-fault + restart",
        self.committed.len()
      ))
    }
  }
}

/// Stateful checker: each replica's `view` must never decrease across observations.
#[derive(Debug)]
pub struct ViewMonotonicChecker {
  max_view: Vec<u64>,
}

impl ViewMonotonicChecker {
  /// A checker for a cluster of `replica_count` replicas (all start at view 0).
  pub fn new(replica_count: usize) -> Self {
    Self {
      max_view: vec![0; replica_count],
    }
  }

  /// Sample the cluster: returns a violation if any replica's view dropped below a prior maximum.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      let v = cluster.replica_view(i).get();
      if v < self.max_view[i] {
        return CheckResult::Violation(format!(
          "replica {i}: view regressed to {v} (was {})",
          self.max_view[i]
        ));
      }
      self.max_view[i] = v;
    }
    CheckResult::Ok
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Cluster;

  #[test]
  fn clean_run_is_ok() {
    let mut c = Cluster::new(3, 2, 3, 1);
    for _ in 0..2000 {
      c.tick();
      if c.is_quiescent() {
        break;
      }
    }
    assert_eq!(check_safety(&c), CheckResult::Ok);
  }

  #[test]
  fn durability_checker_flags_a_regressed_committed_prefix() {
    // A committed op that is rewritten (or vanishes) across observations is a durability violation.
    let mut dur = DurabilityChecker::new(2);
    // Observation 1: both replicas agree on [1,2,3] → committed history is 3 ops.
    let o1 = vec![
      vec![(1, b"a".to_vec()), (2, b"b".to_vec()), (3, b"c".to_vec())],
      vec![(1, b"a".to_vec()), (2, b"b".to_vec()), (3, b"c".to_vec())],
    ];
    assert!(dur.fold(&o1, &[0, 0]).is_ok());
    // Observation 2: replica 1's op 2 now reads back a DIFFERENT body → a committed op was rewritten.
    let o2 = vec![
      vec![(1, b"a".to_vec()), (2, b"b".to_vec()), (3, b"c".to_vec())],
      vec![(1, b"a".to_vec()), (2, b"X".to_vec()), (3, b"c".to_vec())],
    ];
    assert!(
      dur.fold(&o2, &[0, 0]).is_violation(),
      "a rewritten committed op must be flagged"
    );
  }

  #[test]
  fn durability_checker_flags_a_regressed_checkpoint() {
    let mut dur = DurabilityChecker::new(1);
    assert!(dur.fold(&[vec![]], &[5]).is_ok());
    assert!(
      dur.fold(&[vec![]], &[4]).is_violation(),
      "a checkpoint_op that goes backwards must be flagged"
    );
  }

  #[test]
  fn durability_checker_allows_a_lagging_recovered_replica() {
    // A replica that is BEHIND the committed history (e.g. just recovered, still catching up) is NOT
    // a violation — only a rewrite or cluster-wide loss is. observe must stay Ok.
    let mut dur = DurabilityChecker::new(2);
    let ahead = vec![
      vec![(1, b"a".to_vec()), (2, b"b".to_vec()), (3, b"c".to_vec())],
      vec![(1, b"a".to_vec())], // replica 1 is behind, agrees on its (short) prefix
    ];
    assert!(
      dur.fold(&ahead, &[0, 0]).is_ok(),
      "a replica behind the committed history is fine as long as it agrees on its prefix"
    );
  }

  #[test]
  fn durability_checker_clean_run_passes() {
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut dur = DurabilityChecker::new(c.replica_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    assert!(
      dur.check(&c).is_ok(),
      "a clean run loses no committed op and keeps checkpoints monotone"
    );
  }

  #[test]
  fn views_are_monotonic_across_a_crash() {
    let mut c = Cluster::new(3, 1, 2, 5);
    let mut vm = ViewMonotonicChecker::new(c.replica_count());
    for _ in 0..2000 {
      c.tick();
      assert!(vm.observe(&c).is_ok(), "no view regression");
      if c.is_quiescent() {
        break;
      }
    }
    c.crash(0);
    for _ in 0..200_000 {
      c.tick();
      assert!(vm.observe(&c).is_ok(), "no view regression after failover");
      if c.client(0).is_done() {
        break;
      }
    }
  }
}

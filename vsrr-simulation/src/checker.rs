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

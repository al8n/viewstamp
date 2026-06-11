//! Safety / agreement checks over a cluster run.

use bytes::Bytes;
use smol_str::SmolStr;

use crate::cluster::Cluster;

/// Outcome of checking a cluster's invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
  /// All checked invariants hold.
  Ok,
  /// An invariant was violated, with a human-readable reason.
  Violation(SmolStr),
}

impl CheckResult {
  /// Constructs a [`Self::Violation`] from any string-ish reason (`&str` / `String` / `SmolStr`).
  #[inline]
  pub fn violation(reason: impl Into<SmolStr>) -> Self {
    Self::Violation(reason.into())
  }

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
  let mut logs: Vec<Vec<(u64, Bytes)>> = Vec::new();
  for i in 0..cluster.replica_count() {
    let applied: Vec<(u64, Bytes)> = cluster.replica_sm(i).applied().to_vec();
    for (idx, (op, _)) in applied.iter().enumerate() {
      if *op != idx as u64 + 1 {
        return CheckResult::violation(format!(
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
      return CheckResult::violation(format!(
        "replica {i} diverges from replica 0 (content mismatch in applied prefix)"
      ));
    }
  }
  for i in 0..cluster.client_count() {
    for (idx, (rn, _)) in cluster.client(i).replies().iter().enumerate() {
      if *rn != (idx as u64) + 1 {
        return CheckResult::violation(format!(
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
  committed: Vec<(u64, Bytes)>,
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
  fn fold(&mut self, applied: &[Vec<(u64, Bytes)>], checkpoint_ops: &[u64]) -> CheckResult {
    for (i, a) in applied.iter().enumerate() {
      // (1) No committed op rewritten: agree with the committed history on the common prefix.
      let n = a.len().min(self.committed.len());
      if a[..n] != self.committed[..n] {
        // Pinpoint the first diverging op for the audit: which committed op, and the two bodies.
        let pos = (0..n).find(|&p| a[p] != self.committed[p]).unwrap_or(0);
        let (cop, cbody) = &self.committed[pos];
        let (aop, abody) = &a[pos];
        return CheckResult::violation(format!(
          "replica {i}: applied prefix diverges from the committed history at op {cop} (a committed \
           op was rewritten/lost across time): committed=({cop},{cbody:?}) replica=({aop},{abody:?})"
        ));
      }
      // Extend the committed history if this replica is strictly ahead (and agrees on the prefix).
      if a.len() > self.committed.len() {
        self.committed = a.clone();
      }
    }
    for (i, &cp) in checkpoint_ops.iter().enumerate() {
      if cp < self.checkpoint_hw[i] {
        return CheckResult::violation(format!(
          "replica {i}: checkpoint_op regressed to {cp} (was {})",
          self.checkpoint_hw[i]
        ));
      }
      self.checkpoint_hw[i] = cp;
    }
    CheckResult::Ok
  }

  /// Record that replica `i`'s durable storage was WIPED ([`Cluster::wipe_and_restart`]): its
  /// per-replica `checkpoint_op` monotonicity baseline is forfeit with the disk (the replica
  /// legitimately restarts at checkpoint 0 — its OWN pre-wipe durable state is gone, which is not by
  /// itself a violation under the `<= f` lost-state budget). The CLUSTER-level guarantees are
  /// deliberately NOT relaxed: the committed history is kept as-is, so the wiped replica's re-applied
  /// prefix must still agree with it (a divergent re-application — the amnesia hazard breaking quorum
  /// intersection — still trips [`observe`](Self::observe)), and [`check`](Self::check) still demands
  /// the full history survive on an operational replica.
  pub fn note_wipe(&mut self, i: usize) {
    self.checkpoint_hw[i] = 0;
  }

  /// Sample the cluster: update the committed history and return a violation if any replica rewrote a
  /// committed op or regressed its `checkpoint_op`. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let applied: Vec<Vec<(u64, Bytes)>> = (0..cluster.replica_count())
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
      CheckResult::violation(format!(
        "no operational replica retains the committed history of {} ops — a committed op was lost \
         across crash + storage-fault + restart",
        self.committed.len()
      ))
    }
  }
}

/// Stateful checker: each replica's **DURABLE (superblock) view** must never decrease across
/// observations.
///
/// The quantity tracked is the durable view ([`Cluster::replica_durable_view`]), **not** the volatile
/// in-memory `view`. The in-memory view is NOT monotone across a crash + restart, and correctly so: a
/// self-driven view change advances `self.view` to the new view *before* the matching superblock
/// durable-view write lands, and the proto defers EVERY binding participation in a view (PrepareOk /
/// DoViewChange / StartView / Prepare / Commit) until that write completes (durable-view-before-
/// participate). So a replica that bumped its in-memory view, did not yet persist it, and crashed has
/// **acted in no higher view than its durable view** — on restart `recover()` legitimately restores
/// the durable view, regressing the in-memory view, and the replica is self-correcting (the next
/// higher-view message re-catches it up). Asserting monotonicity on the in-memory view would flag this
/// safe, expected behaviour (a replica enters a view change for view 1, crashes before the view-1
/// root is durable, and recovers to view 0 — having sent NOTHING in view 1). The DURABLE view is
/// the right invariant: it only advances when a view-change/adoption root
/// write lands, so it is monotone AND it is exactly "the highest view the replica could have acted in".
/// A regression THERE would be a real durable-state safety violation.
#[derive(Debug)]
pub struct ViewMonotonicChecker {
  max_view: Vec<u64>,
}

impl ViewMonotonicChecker {
  /// A checker for a cluster of `replica_count` replicas (all start at durable view 0).
  pub fn new(replica_count: usize) -> Self {
    Self {
      max_view: vec![0; replica_count],
    }
  }

  /// Record that replica `i`'s durable storage was WIPED ([`Cluster::wipe_and_restart`]): its
  /// durable-view monotonicity baseline is forfeit with the disk — the fresh superblock honestly
  /// reads view 0, and that REGRESSION IS the amnesia hazard, not a checker artifact (the replica may
  /// have voted in views its new disk has no memory of). Whether that ever lets it double-participate
  /// and break agreement is judged by the safety/durability checkers, which are NOT relaxed.
  pub fn note_wipe(&mut self, i: usize) {
    self.max_view[i] = 0;
  }

  /// Sample the cluster: returns a violation if any replica's DURABLE view dropped below a prior
  /// maximum (a real durable-view regression — never legitimate). Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      let v = cluster.replica_durable_view(i).get();
      if v < self.max_view[i] {
        return CheckResult::violation(format!(
          "replica {i}: durable view regressed to {v} (was {})",
          self.max_view[i]
        ));
      }
      self.max_view[i] = v;
    }
    CheckResult::Ok
  }
}

/// Asserts the per-op in-memory maps (`log` cache, `inflight` pipeline) and each replica's durable
/// WAL stay **bounded** over a run — the guarantee that post-checkpoint GC bounds the structures
/// that previously grew without bound in op count.
///
/// Without GC these grow with the total committed-op count (one `log`/WAL entry per op forever); with
/// GC they plateau near the un-checkpointed tail (a few `checkpoint_ops` intervals) plus pipeline
/// headroom. The bounds are generous constants chosen so a real leak (no GC) trips while normal
/// fluctuation does not. The `clients` table is bounded separately by the active client set (one
/// session per client), so it is checked against a client-count-derived bound, not the per-op bound.
#[derive(Debug)]
pub struct BoundednessChecker {
  /// Max allowed entries in any per-op map (`log`, `inflight`) and any WAL.
  max_per_op: usize,
  /// Max allowed client-session entries on any replica.
  max_clients: usize,
}

impl BoundednessChecker {
  /// A checker bounding each per-op map + WAL to `max_per_op` entries and each session table to
  /// `max_clients` entries.
  pub const fn new(max_per_op: usize, max_clients: usize) -> Self {
    Self {
      max_per_op,
      max_clients,
    }
  }

  /// Sample the cluster; a violation if any per-op map, WAL, or session table exceeds its bound.
  /// Call every tick — a single over-bound observation anywhere in the run fails the gate.
  pub fn observe(&self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      let log = cluster.replica_log_len(i);
      if log > self.max_per_op {
        return CheckResult::violation(format!(
          "replica {i}: log cache {log} exceeds bound {} (GC not bounding the per-op cache)",
          self.max_per_op
        ));
      }
      let inflight = cluster.replica_inflight_len(i);
      if inflight > self.max_per_op {
        return CheckResult::violation(format!(
          "replica {i}: inflight {inflight} exceeds bound {}",
          self.max_per_op
        ));
      }
      let wal = cluster.wal_len(i);
      if wal > self.max_per_op {
        return CheckResult::violation(format!(
          "replica {i}: WAL {wal} exceeds bound {} (prune not freeing slots below the checkpoint)",
          self.max_per_op
        ));
      }
      let clients = cluster.replica_clients_len(i);
      if clients > self.max_clients {
        return CheckResult::violation(format!(
          "replica {i}: client sessions {clients} exceeds bound {}",
          self.max_clients
        ));
      }
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
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
    ];
    assert!(dur.fold(&o1, &[0, 0]).is_ok());
    // Observation 2: replica 1's op 2 now reads back a DIFFERENT body → a committed op was rewritten.
    let o2 = vec![
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"X")),
        (3, Bytes::from_static(b"c")),
      ],
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
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
      vec![(1, Bytes::from_static(b"a"))], // replica 1 is behind, agrees on its (short) prefix
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
  fn durability_checker_final_assertion_stays_strict_when_no_operational_replica_retains_the_history()
   {
    // The end-of-run durability assertion (which the VOPR driver's final QUIESCE phase runs AFTER
    // draining) must stay STRICT: if NO operational replica retains the committed history, it is a
    // Violation. This is the "a committed op held by no operational holder still FAILS" direction — it
    // pins that the quiesce fix (drain THEN assert) did not weaken the no-loss guarantee.
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut dur = DurabilityChecker::new(c.replica_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    // Sanity: a real committed history was recorded and (healthy) it passes.
    assert!(c.replica_commit(0).get() >= 1, "the cluster committed ops");
    assert!(
      dur.check(&c).is_ok(),
      "healthy: the history survives operational"
    );
    // Now crash EVERY replica: none is operational, so no replica retains the committed history in an
    // operational state → the strict no-loss assertion must fire (it is NOT silently satisfied).
    for i in 0..c.replica_count() {
      c.crash(i);
    }
    assert!(
      dur.check(&c).is_violation(),
      "with no operational replica retaining the committed history the final assertion must FAIL — \
       the quiesce fix drains before this check but never relaxes its strictness"
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

  #[test]
  fn view_checker_tracks_the_durable_view_across_an_undurable_catch_up_regression() {
    // A replica that caught its IN-MEMORY view up to a higher view via the higher-view rule
    // (`catch_up_to_view` — a non-binding GetView probe, NO durable write, NO participation), then
    // crashed and recovered to its (lower) DURABLE view, legitimately regresses its in-memory view.
    // That is SAFE (it acted in no higher view than it persisted), so the view-monotonic checker —
    // which tracks the DURABLE view — must stay Ok, even though a naive in-memory-view checker WOULD
    // have fired.
    //
    // Construction: a 5-node cluster, crash the primary (r0) so the survivors fail over to view 1. A
    // lagging backup catches its in-memory view up to 1 BEFORE persisting it (the un-durable window:
    // `replica_view > replica_durable_view`). We crash that backup IN that window and restart it — it
    // recovers to durable view 0, regressing its in-memory view. The durable-view checker stays Ok
    // throughout; we also assert the in-memory view actually regressed (non-vacuity: the bug this fixes
    // would have tripped here).
    use crate::Faults;
    use core::time::Duration;

    let mut c = Cluster::new(5, 2, 200, 151);
    // Lossy network: drops keep a behind backup in the `catch_up_to_view` GetView-probe state (its
    // in-memory view bumped via the higher-view rule, the StartView that would persist it delayed), so
    // the un-durable window `replica_view > replica_durable_view` stays open long enough to observe.
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(2),
      drop_per_mille: 200,
      duplicate_per_mille: 0,
      hold_per_mille: 0,
    });
    let mut vm = ViewMonotonicChecker::new(c.replica_count());
    // Warm up.
    for _ in 0..5_000 {
      c.tick();
      assert!(vm.observe(&c).is_ok());
      if c.replica_commit(0).get() >= 3 {
        break;
      }
    }
    // Crash the view-0 primary; the survivors fail over toward higher views. Search (re-crashing the
    // rotating primary to force fresh catch-ups) for a replica in the un-durable catch-up window.
    c.crash(0);
    let mut victim = None;
    for step in 0..200_000usize {
      c.tick();
      assert!(
        vm.observe(&c).is_ok(),
        "durable view never regresses (pre-crash)"
      );
      if let Some(i) = (0..c.replica_count())
        .find(|&i| !c.is_crashed(i) && c.replica_view(i).get() > c.replica_durable_view(i).get())
      {
        victim = Some(i);
        break;
      }
      // Periodically crash whichever replica currently leads (the live primary) and restart a crashed
      // one, to churn views and repeatedly drive lagging backups through the catch-up probe.
      if step % 4_000 == 3_999 {
        let leader = (0..c.replica_count())
          .filter(|&i| !c.is_crashed(i))
          .max_by_key(|&i| c.replica_view(i).get());
        if let Some(l) = leader {
          let live = (0..c.replica_count()).filter(|&i| !c.is_crashed(i)).count();
          // Keep a quorum up (5 replicas → never knock the live set below 3).
          if live > 3 {
            c.crash(l);
          }
        }
        for i in 0..c.replica_count() {
          if c.is_crashed(i) {
            c.restart(i);
            break;
          }
        }
      }
    }
    let v =
      victim.expect("a replica entered the un-durable catch-up window (in-memory view > durable)");
    let inmem_before = c.replica_view(v).get();
    let durable_before = c.replica_durable_view(v).get();
    assert!(
      inmem_before > durable_before,
      "the victim's in-memory view {inmem_before} leads its durable view {durable_before}"
    );
    // Crash + restart the victim: it recovers to its DURABLE view, regressing the in-memory view.
    c.crash(v);
    c.restart(v);
    let inmem_after = c.replica_view(v).get();
    assert!(
      inmem_after <= durable_before,
      "after recovery the in-memory view ({inmem_after}) is back at the durable view (<= {durable_before})"
    );
    assert!(
      inmem_after < inmem_before,
      "non-vacuity: the in-memory view genuinely REGRESSED ({inmem_before} -> {inmem_after}) — a naive \
       in-memory-view checker would have fired here"
    );
    // The durable-view checker stays Ok across the regression and the subsequent re-convergence.
    assert!(
      vm.observe(&c).is_ok(),
      "the durable-view checker tolerates the in-memory regression (the higher view was never durable)"
    );
    // Heal + run on: the durable view must stay monotone as the recovered replica re-catches up.
    c.set_faults(Faults::none());
    for i in 0..c.replica_count() {
      if c.is_crashed(i) {
        c.restart(i);
      }
    }
    for _ in 0..50_000 {
      c.tick();
      assert!(
        vm.observe(&c).is_ok(),
        "durable view stays monotone as the recovered replica re-catches up"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
  }
}

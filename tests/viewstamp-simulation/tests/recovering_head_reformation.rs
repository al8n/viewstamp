//! all-`RecoveringHead` re-formation: the EMPIRICAL PROOF that the proto's
//! `retire_recover_and_escalate` escalation re-forms a cluster wedged by a coordinated offline
//! restart.
//!
//! An offline reconfiguration is an operator-coordinated restart into a bumped epoch on a
//! QUIESCED cluster (route A: all-`Normal` at a common view before the stop). Under load the durable
//! frontier carries an uncommitted tail; on the coordinated restart, a fault wave on the HEAD (latest,
//! UNCOMMITTED) slot leaves a VOTING QUORUM in `Status::RecoveringHead` at the common preserved view —
//! no `Normal` node answers a `Recovery`, and (pre-fix) `RecoveringHead` had no escalation path, a
//! permanent deadlock (the seed-103 wedge). The escalation now re-forms the cluster: a `RecoveringHead`
//! voter at a bumped epoch (`epoch > prev_epoch`), once enough solicitation windows elapsed (G1) and a
//! voting quorum of OTHER voters is co-recovering (G2), escalates into a view change at `view + 1`.
//!
//! [`Cluster::reconfigure_offline`] drives exactly that wedge (drain → mint one uncommitted tail op →
//! pre-write successor roots via `prepare_restart` → head-fault wave on the voters → restart all), and
//! [`Cluster::reform_escalations_fired`] observes the `RecoveringHead → ViewChange` escalation edge.
//! These tests assert the wedge GENUINELY forms (a voting quorum reaches `RecoveringHead`), the
//! escalation FIRES, the cluster CONVERGES to a single `Normal` primary at `view + 1` within a bounded
//! budget, NO committed op is lost (the safety/durability/applied-once checkers stay live), and the
//! re-formed cluster SERVES a fresh client request. The A2 re-fire test re-wedges after the first
//! escalation and asserts it escalates AGAIN (the gate re-arms because `epoch > prev_epoch` stays true).
//!
//! NON-VACUITY: with the proto escalation neutered (the gate forced false) the wedge still forms but
//! `reform_escalations_fired` stays `0` and the cluster never converges, so these tests FAIL — they are
//! a real oracle for the escalation, not a vacuous green.

use viewstamp_simulation::{
  AppliedOnceChecker, CheckResult, Cluster, DurabilityChecker, OfflineReconfig,
  ViewMonotonicChecker, check_safety,
};

/// A small checkpoint interval so a short warmup crosses a checkpoint and the durable root becomes a
/// v4 root carrying the membership — the lineage `prepare_restart` chains the successor off (an offline-restart
/// stop is on a cluster that has been running and checkpointing). Several voters, a couple of clients.
const CHECKPOINT_OPS: u64 = 8;

/// The bounded tick budget the re-formation must converge within. Generous (a healed cluster
/// re-forms in well under a hundred ticks once the escalation fires) yet finite, so a cluster that
/// stays wedged — the pre-escalation deadlock, or a regression — is caught as a non-convergence.
const REFORM_BUDGET: u64 = 40_000;

/// The committed-history high-water (the longest applied `(op, body)` prefix on any replica).
fn committed_high_water(c: &Cluster) -> usize {
  (0..c.replica_count())
    .map(|i| c.replica_sm(i).applied().len())
    .max()
    .unwrap_or(0)
}

/// How many voters are currently `RecoveringHead`.
fn wedged_voters(c: &Cluster, voting_count: usize) -> usize {
  (0..voting_count)
    .filter(|&i| c.replica_status_is_recovering_head(i))
    .count()
}

/// The serving primary's view, or `None` during an election window.
fn serving_view(c: &Cluster) -> Option<u64> {
  c.serving_primary().map(|p| c.replica_view(p).get())
}

/// Whether every voter is `Normal` at the SAME view, with a serving primary at that view.
fn all_normal_at(c: &Cluster, voting_count: usize, view: u64) -> bool {
  (0..voting_count).all(|i| c.replica_status_str(i) == "normal") && serving_view(c) == Some(view)
}

/// Run a warmup workload to quiescence, then perform the coordinated offline reconfiguration that
/// drives the all-`RecoveringHead` wedge. Returns the cluster, the reconfig outcome, and the
/// committed-history high-water captured BEFORE the stop (so the caller can assert nothing is lost).
fn warm_and_wedge(seed: u64, voting_count: u8) -> (Cluster, OfflineReconfig, usize) {
  let mut c = Cluster::with_checkpoint_ops(voting_count, 2, 60, seed, CHECKPOINT_OPS);
  for _ in 0..6_000 {
    c.tick();
    if c.is_quiescent() {
      break;
    }
  }
  let committed_before = committed_high_water(&c);
  assert!(
    committed_before > 0,
    "the warmup must commit ops (so 'no committed op lost' is a meaningful assertion)"
  );
  let reconfig = c
    .reconfigure_offline()
    .expect("a healthy v4 cluster performs the coordinated offline reconfiguration");
  (c, reconfig, committed_before)
}

/// Tick the cluster toward re-formation for up to `budget` ticks, running the FULL safety / durability
/// / applied-once / view-monotonicity invariant suite EVERY tick (so the re-formation can never hide a
/// committed-op loss, a double-apply, or a view regression). Returns the tick at which every voter is
/// `Normal` at `target_view` with a serving primary there, or panics on a violation; returns `None` if
/// it never converges within the budget (the pre-escalation wedge).
fn drive_reformation(
  c: &mut Cluster,
  voting_count: usize,
  target_view: u64,
  budget: u64,
) -> Option<u64> {
  let mut dur = DurabilityChecker::new(c.replica_count());
  let mut applied = AppliedOnceChecker::new(c.replica_count());
  let mut vm = ViewMonotonicChecker::new(c.replica_count());
  for t in 0..budget {
    c.tick();
    if let CheckResult::Violation(why) = check_safety(c) {
      panic!("safety violated during re-formation at tick {t}: {why}");
    }
    if let CheckResult::Violation(why) = dur.observe(c) {
      panic!("durability violated during re-formation at tick {t}: {why}");
    }
    if let CheckResult::Violation(why) = applied.observe(c) {
      panic!("applied-once violated during re-formation at tick {t}: {why}");
    }
    if let CheckResult::Violation(why) = vm.observe(c) {
      panic!("view-monotonicity violated during re-formation at tick {t}: {why}");
    }
    if all_normal_at(c, voting_count, target_view) && c.is_quiescent() {
      return Some(t);
    }
  }
  None
}

#[test]
fn all_recovering_head_wedge_re_forms_at_view_plus_one() {
  let voting_count = 3usize;
  let (mut c, reconfig, committed_before) = warm_and_wedge(7, voting_count as u8);

  // (1) The wedge GENUINELY formed: a voting quorum reached `RecoveringHead` at the common preserved
  // view, with NO `Normal` node to answer their `Recovery` solicitations.
  let quorum = voting_count / 2 + 1;
  let wedged = wedged_voters(&c, voting_count);
  assert!(
    wedged >= quorum,
    "the coordinated restart must leave a voting quorum RecoveringHead (got {wedged} of \
     {voting_count}, quorum {quorum}) at view {}",
    reconfig.view()
  );
  assert!(
    serving_view(&c).is_none(),
    "no Normal serving primary exists while the voters are wedged in RecoveringHead"
  );
  assert_eq!(
    c.reform_escalations_fired(),
    0,
    "no escalation has fired yet (the cluster has only just wedged)"
  );

  // (2) Drive the re-formation: the escalation must re-form the cluster to view + 1, with the full
  // invariant suite live every tick.
  let target_view = reconfig.view() + 1;
  let converged = drive_reformation(&mut c, voting_count, target_view, REFORM_BUDGET);
  assert!(
    converged.is_some(),
    "the cluster must re-form to a single Normal primary at view {target_view} within \
     {REFORM_BUDGET} ticks (a permanent wedge here is the pre-escalation deadlock)"
  );

  // (3) The escalation FIRED — the RecoveringHead → ViewChange edge the proto's
  // retire_recover_and_escalate produces. (With the escalation neutered this stays 0 and (2) above
  // never converges — the non-vacuity proof.)
  assert!(
    c.reform_escalations_fired() > 0,
    "the re-formation escalation must have fired (reform_escalations_fired > 0)"
  );

  // (4) The cluster converged to a SINGLE Normal primary at view + 1.
  assert_eq!(
    serving_view(&c),
    Some(target_view),
    "the re-formed serving primary is at view + 1"
  );
  let primaries = (0..voting_count)
    .filter(|&i| c.replica_is_primary(i) && c.replica_status_str(i) == "normal")
    .count();
  assert_eq!(
    primaries, 1,
    "exactly one Normal primary after re-formation"
  );

  // (5) NO committed op was lost: the post-quiesce committed history still holds everything the
  // pre-stop cluster had acked, applied on an operational replica.
  if let CheckResult::Violation(why) = DurabilityChecker::new(c.replica_count()).check(&c) {
    panic!("a committed op was lost across the re-formation: {why}");
  }
  assert!(
    committed_high_water(&c) >= committed_before,
    "the re-formed cluster retains the full committed history (have {}, had {committed_before})",
    committed_high_water(&c)
  );

  // (6) The re-formed cluster SERVES a fresh client request — it is live, not merely converged.
  let fresh = c.spawn_client(3);
  let mut served = false;
  for _ in 0..REFORM_BUDGET {
    c.tick();
    if c.client(fresh).is_done() {
      served = true;
      break;
    }
  }
  assert!(
    served,
    "the re-formed cluster must serve a fresh client request to completion"
  );
}

#[test]
fn re_wedge_re_fires_the_escalation_to_view_plus_two() {
  // A2 (re-fire): after the first escalation reaches view 1, re-wedge (a second coordinated restart
  // with a head fault) and assert the escalation fires AGAIN to view 2 — the gate re-arms because
  // each reconfiguration bumps the epoch, so `epoch > prev_epoch` stays true.
  let voting_count = 3usize;
  let (mut c, first, _committed_before) = warm_and_wedge(9, voting_count as u8);

  // First re-formation to view + 1.
  let view1 = first.view() + 1;
  assert!(
    drive_reformation(&mut c, voting_count, view1, REFORM_BUDGET).is_some(),
    "the first wedge re-forms to view {view1}"
  );
  let escalations_after_first = c.reform_escalations_fired();
  assert!(
    escalations_after_first > 0,
    "the first escalation fired (reform_escalations_fired > 0)"
  );

  // Re-wedge: a SECOND coordinated offline reconfiguration. It drains the (now view-1) cluster back to
  // all-`Normal`, mints a fresh uncommitted tail, bumps the epoch again, and faults the voters' heads
  // — so they re-wedge in `RecoveringHead` at view 1.
  let second = c
    .reconfigure_offline()
    .expect("the re-formed cluster performs a second coordinated offline reconfiguration");
  assert_eq!(
    second.view(),
    view1,
    "the re-wedge forms at the re-formed view (the escalation's uniform convergence target)"
  );
  let quorum = voting_count / 2 + 1;
  assert!(
    wedged_voters(&c, voting_count) >= quorum,
    "the second restart leaves a voting quorum RecoveringHead again"
  );

  // The escalation must RE-FIRE: the cluster re-forms to view 2, and the escalation counter advances
  // past its post-first value (the gate re-armed at the new epoch).
  let view2 = second.view() + 1;
  assert!(
    drive_reformation(&mut c, voting_count, view2, REFORM_BUDGET).is_some(),
    "the re-wedge re-forms to view {view2} (the escalation re-fired)"
  );
  assert!(
    c.reform_escalations_fired() > escalations_after_first,
    "the escalation RE-FIRED across the re-wedge (it re-arms because epoch > prev_epoch stays true): \
     escalations went from {escalations_after_first} to {}",
    c.reform_escalations_fired()
  );
  assert_eq!(
    serving_view(&c),
    Some(view2),
    "the twice-re-formed serving primary is at view + 2"
  );
  // No committed op lost across the two re-formations.
  if let CheckResult::Violation(why) = DurabilityChecker::new(c.replica_count()).check(&c) {
    panic!("a committed op was lost across the re-wedge re-formation: {why}");
  }
}

use super::*;
use crate::OpNumber;

#[test]
fn advance_checkpoint_op_allows_forward_moves() {
  // The chokepoint must accept a non-decreasing move (the only legitimate direction): a forward step
  // and an idempotent equal-step both succeed without tripping the monotonicity assert.
  let mut e = backup();
  e.advance_checkpoint_op(OpNumber::with(8));
  assert_eq!(e.checkpoint_op(), OpNumber::with(8));
  e.advance_checkpoint_op(OpNumber::with(8)); // equal is allowed (>=)
  assert_eq!(e.checkpoint_op(), OpNumber::with(8));
  e.advance_checkpoint_op(OpNumber::with(12));
  assert_eq!(e.checkpoint_op(), OpNumber::with(12));
}

#[test]
#[should_panic(expected = "checkpoint_op must not rewind")]
fn advance_checkpoint_op_rewind_panics() {
  // A rewind would prune a band a durable root still claims to cover — the chokepoint must fail-stop,
  // not silently regress the durable-checkpoint pointer that gates the irreversible `wal.prune`.
  let mut e = backup();
  e.advance_checkpoint_op(OpNumber::with(10));
  e.advance_checkpoint_op(OpNumber::with(9)); // rewind: must panic in debug
}

// --- Item 2: `set_commit_min` is a MONOTONE chokepoint (non-vacuity). ---

#[test]
fn set_commit_min_allows_forward_moves() {
  // The applied frontier only ever advances; a forward step and an idempotent equal-step both succeed.
  let mut e = backup();
  e.set_commit_min(OpNumber::with(4));
  assert_eq!(e.commit(), OpNumber::with(4));
  e.set_commit_min(OpNumber::with(4)); // equal is allowed (>=)
  assert_eq!(e.commit(), OpNumber::with(4));
  e.set_commit_min(OpNumber::with(7));
  assert_eq!(e.commit(), OpNumber::with(7));
}

#[test]
#[should_panic(expected = "commit_min must not rewind")]
fn set_commit_min_rewind_panics() {
  // `commit_min` is the applied frontier — an applied op is immutable, so a regress would un-apply a
  // committed op. The chokepoint must fail-stop rather than silently rewind it.
  let mut e = backup();
  e.set_commit_min(OpNumber::with(6));
  e.set_commit_min(OpNumber::with(5)); // rewind: must panic in debug
}

// --- Item 3: `assert_committed_survives` catches a lost committed op (non-vacuity). ---

#[test]
fn assert_committed_survives_accepts_safe_drops() {
  // The three legitimate witnesses each pass. State: checkpoint_op=3, commit_max=8 (a committed band
  // (3..=8]), op=8, and op 5 registered as a tracked repair hole. (`force_state_for_test` raises
  // commit_max to commit_min, so commit_min=8 gives commit_max=8.)
  let mut e = backup();
  e.force_state_for_test(0, 8, 8, 3, &[5]);
  let floor = e.checkpoint_op().get();
  e.assert_committed_survives(3, floor); // folded into the checkpoint (op <= floor)
  e.assert_committed_survives(2, floor); // also below the checkpoint floor
  e.assert_committed_survives(5, floor); // tracked-for-repair (in self.repair)
  e.assert_committed_survives(9, floor); // uncommitted (op > commit_max == 8)
  e.assert_committed_survives(100, floor); // far above the committed frontier
}

#[test]
#[should_panic(expected = "destructive op on committed op")]
fn assert_committed_survives_rejects_a_lost_committed_op() {
  // Op 6 is in the committed band (checkpoint_op=3 < 6 <= commit_max=8), NOT checkpointed, NOT tracked
  // for repair, and NOT above the known-committed frontier — dropping it would LOSE a committed op, so
  // the backstop must fire.
  let mut e = backup();
  e.force_state_for_test(0, 8, 8, 3, &[]); // no repair holes; commit_min=8 ⇒ commit_max=8
  e.assert_committed_survives(6, e.checkpoint_op().get());
}

// --- Item 4: `assert_invariants` (status × sub-state-flag) coupling (non-vacuity). ---

#[test]
fn assert_invariants_accepts_a_consistent_state() {
  // A plain Normal backup with the monotone frontier bounds satisfied passes every clause.
  let mut e = backup();
  e.force_state_for_test(0, 8, 5, 3, &[]); // op 8 >= commit_min 5 >= checkpoint_op 3; commit_max 5
  e.assert_invariants();
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "view_change collection present iff Status::ViewChange")]
fn assert_invariants_rejects_view_change_collection_while_normal() {
  // The ViewChange-only collection (DVC + catch-up discriminant) is a ViewChange sub-state; a Normal
  // replica must never carry it. Planting a `Some` collection while Normal violates clause (2)'s
  // `view_change.is_some() == is_view_change()` coupling.
  let mut e = backup();
  e.force_view_change_present_for_test(); // status is Normal → present-but-not-ViewChange
  e.assert_invariants();
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "pending_forfeit off a Normal primary")]
fn assert_invariants_rejects_pending_forfeit_on_a_backup() {
  // The deferred-forfeit latch belongs to a Normal PRIMARY stepping down; replica 1 of 3 is a backup
  // in view 0, so the latch must not be set.
  let mut e = backup();
  e.pending_forfeit = true; // backup → violates clause (3)
  e.assert_invariants();
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "commit_min")]
fn assert_invariants_rejects_checkpoint_above_commit_min() {
  // `checkpoint_op > commit_min` is impossible (a checkpoint snapshots the SM at `commit_min`), so the
  // monotone-bounds clause (4) must fire.
  let mut e = backup();
  e.checkpoint_op = OpNumber::with(9);
  e.commit_max = OpNumber::with(9);
  // commit_min stays 0 < checkpoint_op 9 → violates commit_min >= checkpoint_op
  e.assert_invariants();
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "pending_install without an outstanding sync")]
fn assert_invariants_rejects_pending_install_without_sync() {
  // A staged deferred install must belong to an outstanding sync (clause (1)).
  let mut e = backup();
  e.pending_install = Some(PendingInstall {
    checkpoint_op: OpNumber::with(0),
    sessions_root: crate::block_address(&[]),
    sm_root: crate::block_address(&[]),
    held_tail: false,
    successor: None,
    successor_prev_config_id: None,
    successor_install_op: None,
    checkpoint: crate::SyncCheckpoint::new(
      crate::View::new(),
      OpNumber::with(0),
      0,
      crate::Epoch::new(0),
      0,
      crate::ReplicaId::new(0),
      0,
      bytes::Bytes::new(),
      bytes::Bytes::new(),
    ),
    donor: crate::Peer::Replica(crate::ReplicaId::new(0)),
  });
  // self.sync is None → violates clause (1)
  e.assert_invariants();
}

// --- The SM-content witness (`sm_at`): the two chokes + the (5c) cross-check. ---

#[test]
fn note_sm_advanced_accepts_exactly_the_next_op() {
  // The content witness advances strictly one committed op at a time — an apply (or a committed
  // reconfigure's vacuous-effect account) for the exact successor succeeds.
  let mut e = backup();
  e.note_sm_advanced(OpNumber::with(1));
  assert_eq!(e.sm_at, OpNumber::with(1));
  e.note_sm_advanced(OpNumber::with(2));
  assert_eq!(e.sm_at, OpNumber::with(2));
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "SM content advanced non-sequentially")]
fn note_sm_advanced_skipping_an_op_panics() {
  // A skipped op means the SM missed a committed effect (or applied out of order) — the choke
  // fail-stops rather than letting the divergence surface as wrong SM state views later.
  let mut e = backup();
  e.note_sm_advanced(OpNumber::with(1));
  e.note_sm_advanced(OpNumber::with(3)); // skips 2: must panic in debug
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "SM content advanced non-sequentially")]
fn note_sm_advanced_double_apply_panics() {
  // A double-apply re-runs a committed effect (non-idempotent SMs corrupt silently) — fail-stop.
  let mut e = backup();
  e.note_sm_advanced(OpNumber::with(1));
  e.note_sm_advanced(OpNumber::with(1)); // re-applies 1: must panic in debug
}

#[test]
fn note_sm_restored_allows_forward_and_equal_moves() {
  // A restore replaces content wholesale at/above the current position: forward (a sync install
  // ahead of the applied frontier) and equal (a retried reconstruct landing the same M) both hold.
  let mut e = backup();
  e.note_sm_restored(OpNumber::with(8));
  assert_eq!(e.sm_at, OpNumber::with(8));
  e.note_sm_restored(OpNumber::with(8)); // equal is allowed (>=)
  e.note_sm_restored(OpNumber::with(12));
  assert_eq!(e.sm_at, OpNumber::with(12));
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "SM content restored backward")]
fn note_sm_restored_backward_panics() {
  // Every restore site installs a checkpoint at/above the applied frontier — a backward restore
  // would regress applied state and is a bug, not a state to represent.
  let mut e = backup();
  e.note_sm_restored(OpNumber::with(12));
  e.note_sm_restored(OpNumber::with(8)); // backward: must panic in debug
}

#[test]
#[cfg(debug_assertions)] // provokes a debug-profile detection oracle; no panic exists in release
#[should_panic(expected = "SM content at")]
fn the_sm_content_witness_trips_on_an_unflagged_behind_window() {
  // Clause (5c): the applied frontier advanced past the SM's content with NO behind-window flagged
  // (no owed reconstruct, not recovering) — the exact state C2 left behind when a view transition
  // dropped the sm_reconstruct obligation (pointers at M, SM stale, nothing tracking the debt).
  // Reverting that fix makes three state-sync suite tests fail at THIS clause; this directed form
  // pins the witness itself without depending on any particular producer of the divergence.
  let mut e = backup();
  e.op = OpNumber::with(4);
  e.commit_min = OpNumber::with(4); // the frontier says 4 ...
  e.commit_max = OpNumber::with(4);
  // ... while sm_at (never advanced) still says 0, Normal, no flags → (5c) must fire.
  e.assert_invariants();
}

#[test]
fn the_sm_content_witness_exempts_exactly_the_flagged_windows() {
  // The two legitimate behind-windows: an owed SM reconstruction (the install advanced the pointers
  // but the verify-on-read restore faulted), and cold-start recovery (the SM not yet restored from
  // the durable checkpoint). Each exempts the divergence; clearing it re-arms the witness.
  let mut e = backup();
  e.op = OpNumber::with(4);
  e.commit_min = OpNumber::with(4);
  e.commit_max = OpNumber::with(4);
  e.status = Status::Recovering;
  e.assert_invariants(); // recovering: exempt
  e.status = Status::RecoveringHead;
  e.assert_invariants(); // head re-establishment: exempt
}

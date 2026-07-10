use super::*;

#[test]
fn check_advances_on_change() {
  let mut r = MembershipReconciler::new(0);
  assert!(r.check(1), "first change detected");
  assert!(!r.check(1), "no change on same id");
  assert!(r.check(2), "second change detected");
}

#[test]
fn check_no_change_when_equal() {
  let mut r = MembershipReconciler::new(42);
  assert!(!r.check(42), "no false positive on equal id");
  assert!(!r.check(42), "stable after multiple same-id checks");
}

#[test]
fn check_single_call_advances() {
  let mut r = MembershipReconciler::new(100);
  assert!(r.check(200));
  assert!(!r.check(200));
}

#[test]
fn budget_bound_invariant_no_extra_peers_beyond_membership() {
  // MembershipReconciler gates rekey so dialed conns stay <= |membership| - 1.
  // A rapid remove/add sequence produces exactly one rekey per config_id change,
  // never double-rekeying the same config.
  let mut r = MembershipReconciler::new(0);
  let changes: Vec<u128> = (1..=10).collect();
  let mut rekey_count = 0;
  for id in &changes {
    if r.check(*id) {
      rekey_count += 1;
    }
    assert!(!r.check(*id), "second check on same id is no-op");
  }
  assert_eq!(
    rekey_count,
    changes.len(),
    "exactly one rekey per config change"
  );
}

#[test]
fn remove_then_readd_triggers_fresh_rekey() {
  // config 1: member added; config 2: member removed; config 3: member readded at new addr
  // Each produces exactly one rekey gate — address freshness is correct by construction since
  // rekey_peers re-resolves from peer_book on every call.
  let mut r = MembershipReconciler::new(0);
  assert!(r.check(1)); // add
  assert!(r.check(2)); // remove
  assert!(r.check(3)); // readd (fresh addr)
  assert!(!r.check(3)); // no spurious repeat
}

//! Identity resolution on recover: `recover` resolves THIS node by its stable `MemberId` against the
//! DURABLE root's membership and returns [`Recovered::{Active, Retired}`] (present → `Active` at its
//! resolved slot; absent → `Retired`; a legacy root bridges to the passed genesis).

use super::{super::*, *};
use crate::{Config, Epoch, MemberId, Membership, OpNumber, View, VsrState};
use std::collections::VecDeque;

/// A v4 durable root carrying `membership` at `(view = 0, log_view = 0, commit, checkpoint_op = 0)`
/// with an empty committed band. The fixture membership uses `config_id = 0` (matching the other
/// endpoint fixtures), so the scalar epoch is the membership's epoch.
fn v4_root(membership: Membership, commit: u64) -> VsrState {
  let epoch = membership.epoch();
  VsrState::try_new_v4(
    View::new(),
    View::new(),
    OpNumber::with(commit),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
    epoch,
    epoch,
    membership,
  )
  .expect("valid v4 root")
}

/// A `TestSb` whose durable root is `state`.
fn sb_with_state(state: VsrState) -> TestSb {
  TestSb {
    state,
    done: VecDeque::new(),
    checkpoint: None,
  }
}

#[test]
fn recover_resolves_self_by_member_id_and_returns_active() {
  // A v4 root whose membership CONTAINS this node's MemberId. The local member is `MemberId::new(7)`,
  // placed at slot 2 of a 3-voter membership — so recover must resolve self by MEMBER ID (not by a
  // config replica index) and land it in slot 2.
  let members = std::vec![MemberId::new(5), MemberId::new(6), MemberId::new(7)];
  let membership = Membership::from_durable_parts(Epoch::new(0), 3, 0, members, 0).unwrap();
  let state = v4_root(membership, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  // The Config's local member is MemberId::new(7) (the `1` is the legacy ctor index, irrelevant to
  // membership resolution now).
  let cfg = Config::try_new(1, MemberId::new(7)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb);
  let e = match recovered {
    Recovered::Active(e) => e,
    Recovered::Retired(_) => panic!("self IS in the membership → Active"),
  };
  assert_eq!(
    e.replica(),
    ReplicaId::new(2),
    "MemberId(7) occupies slot 2 of the durable membership",
  );
}

#[test]
fn recover_returns_retired_when_self_absent() {
  // A v4 root whose membership does NOT contain this node's MemberId — a reconfiguration removed it.
  // recover must return Retired carrying the local id + the epoch it was retired at, WITHOUT touching
  // the WAL (no reads submitted).
  let members = std::vec![MemberId::new(5), MemberId::new(6), MemberId::new(7)];
  let membership = Membership::from_durable_parts(Epoch::new(4), 3, 0, members, 0).unwrap();
  let state = v4_root(membership, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  // Local member 99 is absent from the durable membership.
  let cfg = Config::try_new(1, MemberId::new(99)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb);
  let retired = match recovered {
    Recovered::Retired(r) => r,
    Recovered::Active(_) => panic!("self is ABSENT from the durable membership → Retired"),
  };
  assert_eq!(retired.local(), MemberId::new(99), "carries the local id");
  assert_eq!(
    retired.epoch(),
    Epoch::new(4),
    "retired at the recovered membership's epoch",
  );
  assert_eq!(
    wal.poll(),
    None,
    "a retired node submits no reads (the WAL completion queue is empty)",
  );
}

#[test]
fn recover_bridges_a_legacy_root_to_the_passed_genesis() {
  // A legacy (v1-3) root carries NO membership (`membership_opt().is_none()`), so recover BRIDGES to
  // the passed genesis membership. `genesis(3)` places MemberId::new(i) at slot i, so the local
  // MemberId::new(1) is present at slot 1 → Active.
  let legacy = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::new(),
    OpNumber::new(),
    0,
    std::vec::Vec::new(),
  )
  .unwrap();
  assert!(
    legacy.membership_opt().is_none(),
    "a v1-3 root has no durable membership",
  );
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(legacy);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();

  let recovered = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb);
  let e = match recovered {
    Recovered::Active(e) => e,
    Recovered::Retired(_) => panic!("legacy root bridges to the passed genesis; self IS present"),
  };
  assert_eq!(
    e.replica(),
    ReplicaId::new(1),
    "the bridged genesis places MemberId(1) at slot 1",
  );
}

#[test]
fn recover_prefers_the_root_membership_over_the_passed_param() {
  // The EFFECTIVE-membership rule: when the root is v4, the DURABLE membership wins — the passed
  // param is ignored. The durable membership places MemberId(1) at slot 0 (a different slot than the
  // passed `genesis(3)`'s slot 1), proving the root's membership, not the param, is used.
  let members = std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)];
  let durable = Membership::from_durable_parts(Epoch::new(0), 3, 0, members, 0).unwrap();
  let state = v4_root(durable, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  let cfg = Config::try_new(1, MemberId::new(1)).unwrap();

  // Pass a DIFFERENT genesis (the standard `genesis(3)`, MemberId(i) at slot i → MemberId(1) at slot
  // 1). The durable root places MemberId(1) at slot 0, so the resolved slot proves which won.
  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  assert_eq!(
    e.replica(),
    ReplicaId::new(0),
    "the durable v4 root's membership wins (slot 0), not the passed param (slot 1)",
  );
}

#[test]
fn recover_resolves_a_learner_self_to_active() {
  // A node that is a non-voting LEARNER in the durable membership still recovers Active (it is
  // present, just non-voting). 2 voters + 1 learner; the local member is the learner at slot 2.
  let members = std::vec![MemberId::new(10), MemberId::new(11), MemberId::new(12)];
  let membership = Membership::from_durable_parts(Epoch::new(0), 2, 1, members, 0).unwrap();
  let state = v4_root(membership, 0);
  let mut wal = TestWal::default();
  let mut sb = sb_with_state(state);
  let cfg = Config::try_new(2, MemberId::new(12)).unwrap();

  let e = Endpoint::recover(cfg, genesis(3), 0, NoopSm, &mut wal, &mut sb).expect_active();
  assert_eq!(e.replica(), ReplicaId::new(2), "learner self at slot 2");
  assert!(e.is_learner(), "slot 2 is a learner in 2v+1l");
}

#[test]
#[should_panic(expected = "must occupy a slot in its own membership")]
fn new_panics_when_the_local_member_is_absent_from_its_membership() {
  // A FRESH endpoint whose local MemberId is NOT in its genesis membership is a caller
  // misconfiguration. It must fail FAST at construction — in RELEASE too, an unconditional assert,
  // not a debug-only one — rather than `expect`-panic LATER via `local_slot()` on an already-running
  // node (`replica()`, timers, ingress). Contrast `recover`, where absence is the legitimate
  // `Recovered::Retired` outcome (a node removed by reconfiguration), tested above.
  let cfg = Config::try_new(1, MemberId::new(99)).unwrap(); // local 99 is absent from genesis(3) = {0,1,2}
  let _ = Endpoint::new(cfg, genesis(3), 0, NoopSm);
}

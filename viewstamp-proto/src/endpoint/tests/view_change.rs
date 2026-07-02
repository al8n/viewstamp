use super::*;
use crate::{
  ClientId, Config, DoViewChange, GetView, Header, OpId, OpNumber, Prepare, PreparedEntry,
  Recovery, ReplicaId, Request, RequestNumber, StartView, StartViewChange, Superblock, View,
  VsrState, Wal,
};

#[test]
fn backup_transitions_on_svc_quorum_and_sends_dvc() {
  // replica 1 of 3. After primary_idle and one peer SVC, the SVC quorum (2) is met:
  // it transitions to ViewChange(view 1) and sends a DoViewChange to primary(1)=replica 1.
  use crate::StartViewChange;
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks); // status=Normal backup → bootstraps primary_idle; not yet due
  let later = now + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks); // primary_idle due → on_primary_idle → broadcast SVC(view 1), own bit set
  assert_eq!(e.status(), Status::Normal); // 1 of 2 — not yet quorum
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  // DoViewChange is deferred until the view is durable — pump storage first.
  e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  // it should have emitted a DoViewChange to primary(view 1) = replica 1 (itself).
  let mut saw_dvc = false;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      assert_eq!(d.view(), View::with(1));
      assert_eq!(d.replica(), ReplicaId::new(1));
      saw_dvc = true;
    }
  }
  assert!(saw_dvc, "must send a DoViewChange to the new primary");
}

#[test]
fn new_primary_adopts_canonical_log_and_starts_view() {
  // replica 1 is primary of view 1. Feed a DVC quorum (2 of 3) of DoViewChange for view 1.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // drive it into ViewChange(view 1) first (reuse the SVC path):
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  ); // primary_idle → SVC(view1), own bit
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange); // now collecting DVCs as primary(view 1)
  while e.poll_message().is_some() {} // discard outgoing so far
  // Feed a DoViewChange from replica 2 with a richer log (log_view 0, op 2, commit 1):
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // replica 1's own DVC (op 0) + replica 2's DVC (op 2) = quorum 2 → adopt op 2, become Normal primary.
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.op(), OpNumber::with(2));
  // StartView is deferred until the view is durable — pump storage first.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  // It must broadcast a StartView carrying the canonical log.
  let mut saw_sv = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartView(sv) = out.into_msg() {
      assert_eq!(sv.op(), OpNumber::with(2));
      assert_eq!(sv.log_slice().len(), 2);
      saw_sv = true;
    }
  }
  assert!(saw_sv, "new primary must broadcast StartView");
}

#[test]
fn new_primary_carries_a_header_only_repairing_op_through_the_dvc_and_repairs_it() {
  // The committed-op-loss closed: a DoViewChange carrying a body-faulty-but-header-durable COMMITTED
  // op (a header-only `Repairing` PreparedEntry — its body did not survive a torn-body fault on the
  // donor, but its canonical identity + body_checksum did) must let the new primary see op 2 as TAKEN.
  // It adopts op 2 repair-pending (NEVER re-mints its number), HOLDS the commit at it, and
  // `request_repair`s the canonical body from a peer. A follow-up peer `Prepare` then fills the body
  // and op 2 commits the canonical value. Before this fix the DVC dropped header-only entries, so the
  // new primary never saw op 2 and re-minted its number for a different request (committed divergence).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Drive replica 1 into ViewChange(view 1) as the prospective primary (reuse the SVC path).
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // Replica 2's DVC: log_view 0, head op 2, commit 2 (BOTH committed). Op 1 has a real body; op 2 is
  // carried HEADER-ONLY as a `Repairing` entry — the donor read its body back faulty but kept its
  // existence + canonical body_checksum.
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Quorum (own op-0 DVC + replica 2's op-2 DVC) → adopt. op_head includes the Repairing op: op 2 is
  // TAKEN, the head is 2, NOT re-minted down to 1.
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the header-only op 2 is counted — the head is 2, its number is taken (never re-minted)"
  );
  // The commit HOLDS at op 2 (its body is absent) and op 2 is registered for peer fault-repair: op 1
  // applies, op 2 does not (no apply over an absent body). `advance_commit` reaches the adopted
  // `Repairing` op 2, finds its body absent, and `request_repair`s it — which converts the held
  // header-only slot into a TRACKED repair hole (`self.repair`), the canonical body to be fetched.
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the commit is HELD at the body-absent op 2 (op 1 applied, op 2 not applied over an absent body)"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is a TRACKED repair hole — its canonical body is solicited, its number stays taken (op == 2)"
  );
  // A RequestPrepare(op 2) is emitted to fetch the canonical body from a peer that holds it. The
  // StartView the new primary broadcasts carries head op 2 as a HEADER-ONLY (`Repairing`) entry — its
  // existence + canonical body_checksum, but NO fabricated body (the body is peer-fetched).
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // pump the deferred StartView / repair solicitation
  let mut solicited = false;
  while let Some(out) = e.poll_message() {
    match out.msg_ref() {
      Message::RequestPrepare(rp) if rp.op() == OpNumber::with(2) => solicited = true,
      Message::StartView(sv) => {
        assert_eq!(
          sv.op(),
          OpNumber::with(2),
          "the StartView head is op 2 (its number is taken)"
        );
        let op2 = sv
          .log_slice()
          .iter()
          .find(|e| e.op() == OpNumber::with(2))
          .expect("op 2 IS carried in the StartView (its existence is taken)");
        assert!(
          op2.is_repairing() && op2.body().is_none(),
          "op 2 is header-only in the StartView (Repairing, no fabricated body — body peer-fetched)"
        );
      }
      _ => {}
    }
  }
  assert!(
    solicited,
    "a RequestPrepare(op 2) fetches the missing canonical body — exactly the missing-slot behavior"
  );
  // The repair Prepare answers with op 2's REAL body (the canonical value a peer holds). Once its
  // append is durable, the held commit resumes and op 2 applies the canonical body — proving the hold
  // was a genuine pause, not a loss, and the op number was never re-minted for a different request.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    repair_prepare(1, 2, 2),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "once the canonical body is repaired + durable, the held commit applies op 2"
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "the repair hole clears once the canonical body fills it"
  );
  let filled = e.log.get(&2).expect("op 2 stays held after repair");
  assert!(
    filled.body.is_present(),
    "op 2's body is now Present (the canonical body was fetched + applied)"
  );
}

#[test]
fn new_primary_votes_a_repaired_uncommitted_repairing_tail_and_commits_with_one_backup_down() {
  // REGRESSION (liveness wedge): a new primary adopts an UNCOMMITTED-tail op carried HEADER-ONLY
  // (`Repairing`) through the DVC. Because it has no body, `adopt_append` cannot re-append it as an
  // `AdoptVote` — it becomes a peer-repair hole with its inflight entry seeded `oks: 0`. After
  // `fill_repair` lands the canonical body durably, the primary holds a durable copy but — before the
  // fix — never cast its OWN vote (the `RepairFill` arm only `advance_commit`s; peer-repair is not a
  // vote). With one backup unavailable it would then collect only ONE backup `PrepareOk` and never
  // reach the 2-of-3 quorum, wedging the view despite holding the op. The fix casts the primary's own
  // vote on the durable fill (append-before-ack), so own vote + one backup ack = quorum and op commits.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // Replica 2's DVC: log_view 0, head op 2, commit 1 — op 1 COMMITTED (real body), op 2 an UNCOMMITTED
  // tail (commit* = 1 < 2) carried HEADER-ONLY as a `Repairing` entry (the donor read its body back
  // faulty but kept its existence + canonical body_checksum). `[2]` is the body `repair_prepare(_,2,_)`
  // supplies, so the canonical checksum matches the eventual repair fill.
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Adopted: head op 2 (its number is TAKEN), commit* = 1 (op 1 applied, op 2 an uncommitted tail).
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 committed; op 2 is the uncommitted Repairing tail"
  );
  // op 2 has an inflight entry seeded with NO own vote (header-only → no AdoptVote append re-stages it).
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(0),
    "the adopted uncommitted Repairing tail op 2 starts with no own vote (no body to re-append)"
  );
  // Pump the durable-view write + repair solicitation. op 2's body is absent, so it is a peer-repair
  // hole and a RequestPrepare(op 2) is emitted; the own vote is STILL absent (the body has not landed).
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is a peer-repair hole until its canonical body is fetched"
  );
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(0),
    "still no own vote before the repaired body is durable (append-before-ack)"
  );
  // A peer answers our RequestPrepare with op 2's REAL canonical body (matching the kept checksum).
  // `fill_repair` stages a durable `RepairFill`; once it lands, the fix casts the primary's OWN vote.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    repair_prepare(1, 2, 1), // commit 1 < op 2: accepted via the kept canonical-checksum path, not a vouch
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let own_bit = 1u64 << 1; // replica 1
  assert!(
    !e.has_repair_hole_for_test(2),
    "the repair hole clears once the canonical body lands durably"
  );
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(own_bit),
    "the primary casts its OWN vote on the durable repaired fill (append-before-ack)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the lone own vote is below quorum (2) — op 2 not yet committed"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2's canonical body was durably appended before its own vote counted"
  );
  // ONE backup (replica 2) acks op 2; the OTHER backup (replica 0) is DOWN and never acks. Own vote +
  // the single backup ack = quorum (2 of 3) → op 2 commits. No wedge despite a backup being down.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(ClientId::new(7), RequestNumber::with(2), op2_checksum),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "op 2 commits on the durable own vote + ONE backup ack — the view does not wedge with a backup down"
  );
}

#[test]
fn committed_repairing_op_survives_a_second_view_change_before_repair() {
  // REGRESSION (committed-op loss one view change later): a primary's StartView must advertise the
  // KNOWN-committed frontier `commit_max`, not the APPLIED frontier `commit_min` (which STALLS below an
  // unrepaired committed `Repairing` hole). A backup that adopts a committed header-only op (op <=
  // commit_max) must LEARN it is committed, so when a SECOND view change collects that backup + laggards
  // BEFORE the body is repaired, the op stays in the committed band (`commit* >= it`) and the nack scan
  // never truncates it. With the OLD `commit_min` advertisement the backup would under-learn the commit,
  // its DVC would report `commit` below the op, `commit*` would fall below it, and the laggard-quorum
  // nack scan would CUT the committed op — re-opening the loss the durable-header work closed.
  //
  // n=5: view 1 primary = replica 1, view 2 primary = replica 2. Op 3 is committed at view 1 but held
  // HEADER-ONLY (`Repairing`) — its body read back faulty on every donor — and the two laggards (replicas
  // 3, 4) never saw op 3 (head op 2). `quorum_nack_prepare = 3`, so three donors with `op < 3` form a
  // nack quorum on op 3 — which would truncate it IF `commit*` sat below 3.
  let now = Instant::ZERO;
  let op3_checksum = crate::storage::fnv1a_128(&[3u8]);
  // A DVC for view 1 carrying ops 1,2 (real bodies) + op 3 HEADER-ONLY (`Repairing`, committed: commit 3).
  let donor_dvc = |replica: u16| {
    DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(3),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(replica),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
        PreparedEntry::repairing(
          OpNumber::with(3),
          ClientId::new(7),
          RequestNumber::with(3),
          op3_checksum,
        ),
      ],
    )
  };

  // ── Stage 1: a REAL view-1 new primary (replica 1) adopts op 3 as a committed Repairing op and
  // BROADCASTS a StartView. Its `commit()` field must be commit_max (= 3), the SENDER half of the fix. ──
  let mut r1 = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  let (mut wal1, mut sb1) = (TestWal::default(), TestSb::default());
  let mut blocks1 = crate::block_store::MemBlockStore::new();
  r1.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal1,
    &mut sb1,
    &mut blocks1,
  );
  // Drive replica 1 into ViewChange(view 1). SVC quorum for n=5 is 3: own bit (from primary_idle above)
  // + two peer SVCs.
  r1.handle_message(
    now,
    &mut wal1,
    &mut sb1,
    &mut blocks1,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  r1.handle_message(
    now,
    &mut wal1,
    &mut sb1,
    &mut blocks1,
    Peer::Replica(ReplicaId::new(3)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(3),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r1.status(), Status::ViewChange);
  while r1.poll_message().is_some() {}
  // Feed a DVC quorum (quorum_view_change = 3): own (op 0, auto-inserted) + replicas 3 and 4 each
  // carrying op 3 committed-Repairing.
  r1.handle_message(
    now,
    &mut wal1,
    &mut sb1,
    &mut blocks1,
    Peer::Replica(ReplicaId::new(3)),
    Message::DoViewChange(donor_dvc(3)),
  );
  r1.handle_message(
    now,
    &mut wal1,
    &mut sb1,
    &mut blocks1,
    Peer::Replica(ReplicaId::new(4)),
    Message::DoViewChange(donor_dvc(4)),
  );
  assert_eq!(
    r1.status(),
    Status::Normal,
    "replica 1 becomes the view-1 primary"
  );
  assert_eq!(
    r1.op(),
    OpNumber::with(3),
    "op 3's number is taken (head 3)"
  );
  assert_eq!(r1.commit_max, OpNumber::with(3), "op 3 is known committed");
  assert_eq!(
    r1.commit(),
    OpNumber::with(2),
    "the commit is HELD at the body-absent Repairing op 3"
  );
  // Pump the durable-view write → `start_view_participate` broadcasts the StartView. Capture it.
  r1.handle_storage(now, &mut wal1, &mut sb1, &mut blocks1);
  let sv = {
    let mut found = None;
    while let Some(out) = r1.poll_message() {
      if let Message::StartView(s) = out.into_msg() {
        found = Some(s);
      }
    }
    found.expect("the view-1 primary broadcasts a StartView")
  };
  // THE SENDER FIX: the StartView advertises the COMMITTED frontier commit_max (3), NOT commit_min (2).
  assert_eq!(
    sv.commit(),
    OpNumber::with(3),
    "the new primary's StartView advertises commit_max (3), not the applied commit_min (2)"
  );
  assert_eq!(sv.op(), OpNumber::with(3));
  assert_eq!(sv.replica(), ReplicaId::new(1), "from the view-1 primary");

  // ── Stage 2: replica 2 adopts that REAL StartView and LEARNS op 3 is committed. ──
  let mut r2 = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  r2.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(
    r2.status(),
    Status::Normal,
    "replica 2 adopts the view-1 head"
  );
  // THE FIX'S EFFECT: replica 2 LEARNS op 3 is committed — `commit_max == 3` — even though it cannot
  // APPLY it yet (the body is absent, so the commit is HELD and op 3 is a peer-repair hole). Before
  // the fix the StartView advertised `commit_min` and replica 2's `commit_max` would stay at 2.
  assert_eq!(
    r2.commit_max,
    OpNumber::with(3),
    "replica 2 learns op 3 is committed (commit_max raised to the advertised committed frontier)"
  );
  // The StartView log carrier is HEADER-ONLY: replica 2 adopts ALL of ops 1, 2, 3 as `Repairing`
  // holes (their bytes peer-repaired after adoption), so the applied frontier HOLDS at the FIRST hole
  // (op 1) — `commit() == 0` — and every band op is solicited via the windowed bulk-repair channel. The
  // load-bearing safety fact this test pins: replica 2 LEARNS `commit_max == 3` (so op 3 stays in the
  // committed band on the next view change), regardless of how far the apply frontier got.
  assert_eq!(
    r2.commit(),
    OpNumber::with(0),
    "the commit is HELD at the first body-absent op (header-only adoption — every band op is a hole)"
  );
  assert!(
    r2.has_repair_hole_for_test(3),
    "op 3 is a peer-repair hole on replica 2 — its body is solicited, not yet repaired"
  );
  // Drain replica 2's outgoing so far (StartView-adopt acks, repair solicitations).
  while r2.poll_message().is_some() {}

  // Now a SECOND view change to view 2 (primary = replica 2) begins BEFORE op 3 is repaired. Drive
  // replica 2 into ViewChange(view 2) and capture the DoViewChange it emits: it must report
  // `commit = commit_max = 3` and carry op 3 as a header-only `Repairing` entry (its existence taken).
  r2.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)),
    Message::StartViewChange(StartViewChange::new(
      View::with(2),
      ReplicaId::new(3),
      crate::Epoch::new(0),
      0,
    )),
  );
  r2.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(4)),
    Message::StartViewChange(StartViewChange::new(
      View::with(2),
      ReplicaId::new(4),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r2.status(), Status::ViewChange);
  assert_eq!(r2.view(), View::with(2));
  // Pump the durable-view write so the deferred DoViewChange is emitted.
  r2.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let r2_dvc = {
    let mut found = None;
    while let Some(out) = r2.poll_message() {
      if let Message::DoViewChange(d) = out.into_msg() {
        found = Some(d);
      }
    }
    found.expect("replica 2 emits a DoViewChange for view 2")
  };
  assert_eq!(
    r2_dvc.commit(),
    OpNumber::with(3),
    "replica 2's DVC reports op 3 COMMITTED (commit_max), so commit* cannot fall below it"
  );
  let carries_op3_repairing = r2_dvc
    .log_slice()
    .iter()
    .any(|e| e.op() == OpNumber::with(3) && e.is_repairing());
  assert!(
    carries_op3_repairing,
    "replica 2's DVC carries op 3 header-only (its existence is taken — never re-minted)"
  );

  // Feed replica 2's REAL DVC + two laggard DVCs (replicas 3,4: head op 2, never saw op 3) into the
  // view-2 prospective primary's canonical-log selection. Three donors with `op < 3` (the laggards plus
  // r2 is the ONLY donor at op 3) form a nack quorum on op 3 — so a `commit*` below 3 WOULD truncate it.
  let mut selector = Endpoint::new(
    Config::try_new(2, MemberId::new(2)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), r2_dvc);
  // Two laggards in an OLDER generation (log_view 0) at head op 2, commit 2: they nack op 3.
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), dvc(3, 0, 2, 2));
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(4), dvc(4, 0, 2, 2));
  let (log, op_head, commit_star, _) = selector.select_canonical_log();
  // THE SAFETY PROPERTY: op 3 survives. `commit* >= 3` (replica 2 reported it committed), so op 3 is in
  // the committed band and the nack scan (which only truncates the UNCOMMITTED tail `> commit*`) cannot
  // cut it. Before the fix `commit*` would be 2 and op 3 — a COMMITTED op — would be truncated to op 2.
  assert!(
    commit_star >= 3,
    "commit* is at least 3 — replica 2's committed-frontier DVC keeps op 3 in the committed band, got {commit_star}"
  );
  assert!(
    op_head >= 3,
    "op_head is not truncated below the committed op 3, got {op_head}"
  );
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  assert!(
    present.contains(&3),
    "the committed op 3 is STILL in the canonical log after the second view change — never truncated or re-minted"
  );
}

#[test]
fn new_primary_does_not_vote_for_an_adopted_op_before_its_wal_append() {
  // REGRESSION (the cardinal append-before-ack invariant): a new primary that adopts an
  // uncommitted-tail op it learned from a PEER's DVC (it did NOT hold the op before) must NOT count
  // its OWN vote for that op — and must NOT commit it — until the op's WAL append is durable. The
  // own vote could only be cast from memory before, so a crash+recover would lose the op it voted
  // for. Here replica 1 becomes primary of view 1 and adopts op 2 (uncommitted: commit* = 1) supplied
  // ONLY by replica 2's DVC; replica 1's own DVC holds op 0, so op 2 is peer-learned + memory-only.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  ); // primary_idle → SVC(view1), own bit
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Now the new primary (replica 1) is Normal with op 2 adopted, commit* = 1 — BEFORE any storage.
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 applied; op 2 still uncommitted"
  );
  let own_bit = 1u64 << 1; // replica 1
  // THE INVARIANT: op 2's inflight entry carries NO own vote yet — the WAL append has not completed.
  // Fail-before (the bug): the own vote was seeded immediately (`oks: own`), so this was `own_bit`.
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(0),
    "the new primary must NOT vote for the adopted op 2 before its WAL append is durable"
  );

  // Pump storage: the AdoptVote append for op 2 completes → on_wal_done sets the own vote; the
  // durable-view write completes → start_view_participate broadcasts StartView + try_commit. With a
  // 3-cluster quorum of 2, the lone own vote still cannot commit op 2.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(own_bit),
    "after the WAL append completes the own vote is recorded (append-before-ack honoured)"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the own vote alone is below quorum (2) — op 2 is not yet committed"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 was durably appended to the WAL before its own vote was counted"
  );

  // A backup PrepareOk for op 2 now reaches quorum (own + backup) → op 2 commits.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(7),
        RequestNumber::with(2),
        crate::storage::fnv1a_128(b"b"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "op 2 commits once the durable own vote + a backup ack reach quorum"
  );
}

#[test]
fn new_primary_adopted_vote_survives_crash_before_checkpoint() {
  // REGRESSION: after the new primary records its OWN vote for an adopted peer-learned
  // op, that op MUST be in its durable WAL — so a crash+recover BEFORE any checkpoint still produces
  // it. We drive the adoption, pump until the AdoptVote append lands (own vote recorded), then CRASH
  // (drop all in-memory state) and RECOVER from the durable WAL+Superblock; op 2 must be present.
  // Fail-before: the vote was memory-only, so the op was absent from the WAL and lost on recover.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Pump until the AdoptVote append is durable (the own vote is recorded only then).
  let own_bit = 1u64 << 1;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    if e.inflight.get(&2).map(|i| i.oks) == Some(own_bit) {
      break;
    }
  }
  assert_eq!(
    e.inflight.get(&2).map(|i| i.oks),
    Some(own_bit),
    "precondition: the new primary recorded its own vote for op 2"
  );

  // CRASH: discard `e` (all in-memory state) and RECOVER from the durable WAL + Superblock — exactly
  // what the simulation's crash/restart does. The op the primary voted for must survive.
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect_active();
  for _ in 0..16 {
    recovered.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    if !recovered.status().is_recovering() {
      break;
    }
  }
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 the new primary voted for is in the durable WAL after crash+recover"
  );
  assert!(
    recovered.op().get() >= 2,
    "the recovered replica re-establishes its head through the voted-for op (it was durable)"
  );
}

#[test]
fn backup_adopted_ack_survives_crash_before_checkpoint() {
  // REGRESSION (backup side): after a backup sends its PrepareOk for an adopted
  // StartView tail op, that op MUST be in its durable WAL — a crash+recover before any checkpoint
  // still produces it. Drive the adoption, pump until the PrepareOk is emitted (its AdoptAck append
  // landed), then CRASH + RECOVER; op 2 must be present. Fail-before: the ack was memory-only.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  // Pump until the PrepareOk for op 2 is emitted (which is gated on its AdoptAck append landing).
  let mut acked = false;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg()
        && ok.op() == OpNumber::with(2)
      {
        acked = true;
      }
    }
    if acked {
      break;
    }
  }
  assert!(acked, "precondition: the backup acked the adopted op 2");

  // CRASH + RECOVER from durable storage.
  drop(e);
  let mut recovered = Endpoint::recover(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect_active();
  for _ in 0..16 {
    recovered.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    if !recovered.status().is_recovering() {
      break;
    }
  }
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 the backup acked is in the durable WAL after crash+recover"
  );
  assert!(
    recovered.op().get() >= 2,
    "the recovered backup re-establishes its head through the acked op (it was durable)"
  );
}

#[test]
fn new_primary_truncates_an_uncommitted_interior_canonical_log_gap() {
  // CONSENSUS-CRITICAL: a replica that recovered with a genuine header-less INTERIOR slot (here
  // checkpoint 0, head 3, op 2's slot NEVER durably held — no header) drops op 2 from its cache, so its
  // log is `{1, 3}` with an interior GAP at op 2. It then becomes the new primary via a DVC quorum where
  // no donor supplies op 2 (op 2 is uncommitted and unique — no quorum holds it). The adopted canonical
  // log is `{1, 3}`, op_head 3, commit* 0; op 2 is ABOVE the committed frontier (commit* == 0) yet held by
  // NO canonical donor, so it is provably UNCOMMITTED (a committed op would be held by a quorum and thus by
  // some canonical donor → present in the offset-union).
  //
  // A header-less slot is the true-gap case: recovery cannot classify it `Verified`, so it drops it —
  // unlike a body-faulty slot whose durable header IS `Verified`, which recovery KEEPS header-only (that op
  // is instead carried as a candidate and nack-truncated on the new primary — a different path).
  //
  // Fail-before: the seeding loop registered an `inflight` entry for EVERY op in `(commit_min, op_head]`
  // and `adopt_append`ed each — but `adopt_append` only appends ops PRESENT in `self.log`, so the gap op
  // 2 was silently skipped, its own vote was never recorded (`inflight[2].oks == 0` forever), and
  // `try_commit` (strictly in order) wedged at op 2 — no fresh client op above it could ever commit, and
  // no peer can supply the unique uncommitted op. The fix truncates the head at the first gap above
  // commit* BEFORE seeding, dropping the uncommitted suffix `{2, 3}`.
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let mut wal = ScriptedWal::with_entries(3);
  wal.remove_entry_for_test(OpNumber::with(2)); // op 2 header-less: a genuine interior gap
  let mut sb = TestSb::default();
  let mut r = Endpoint::recover(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
    &mut wal,
    &mut sb,
    &mut blocks,
  )
  .expect_active();
  drive_recovery(&mut r, &mut wal, &mut sb, &mut blocks, now);
  assert_eq!(r.op(), OpNumber::with(3), "recovered head is op 3");
  assert!(
    !r.log.contains_key(&2),
    "precondition: the header-less op 2 is absent from the cache (interior gap)"
  );
  assert!(
    !r.has_repair_hole_for_test(2),
    "precondition: op 2 is uncommitted, so it is NOT a repair hole"
  );
  while r.poll_message().is_some() {} // discard the recovery-time chatter

  // Drive replica 1 to primary of view 1: an SVC quorum (own + replica 0) enters ViewChange(1); pump
  // the durable-view write so it sends its own DVC; then a peer DVC reaches the DVC quorum.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(r.status(), Status::ViewChange, "SVC quorum → ViewChange(1)");
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // complete the SendDoViewChange durable-view write
  while r.poll_message().is_some() {}
  // Replica 2's DVC ALSO lacks op 2 (uncommitted+unique: no quorum holds it), same generation
  // (log_view 0), head 3, commit 0 → the offset-union still has the interior gap at op 2.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::copy_from_slice(&[1u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(3),
          ClientId::new(7),
          RequestNumber::with(3),
          bytes::Bytes::copy_from_slice(&[3u8]),
        ),
      ],
    )),
  );
  assert!(r.is_primary(), "replica 1 became the primary of view 1");

  // The head is truncated to op 1 (just below the uncommitted gap at op 2); the uncommitted suffix
  // `{2, 3}` is dropped from the cache.
  assert_eq!(
    r.op(),
    OpNumber::with(1),
    "the head is truncated below the first uncommitted interior gap (op 2)"
  );
  assert!(
    !r.log.contains_key(&2) && !r.log.contains_key(&3),
    "the uncommitted suffix above the gap is dropped from the cache"
  );
  assert!(
    !r.has_repair_hole_for_test(2) && !r.has_repair_hole_for_test(3),
    "an uncommitted gap above commit* is truncated, NOT left as a (futile) repair hole"
  );
  assert!(
    !r.inflight.contains_key(&2),
    "no stuck inflight entry for the gap op (fail-before: inflight[2].oks == 0 forever)"
  );

  // Pump the StartViewAsPrimary durable-view write so the new primary begins participating.
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while r.poll_message().is_some() {}
  // Land the AdoptVote append for the surviving tail op 1 (its own vote is recorded then).
  for _ in 0..4 {
    r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  }

  // Liveness: a fresh client request is accepted (commit_max == commit_min == 0, repair empty) and —
  // crucially — COMMITS. It is assigned op 2 (the truncated head + 1), and with a backup ack it reaches
  // the commit quorum, proving `try_commit` is NOT wedged at the former gap.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"fresh"),
    )),
  );
  assert_eq!(
    r.op(),
    OpNumber::with(2),
    "the fresh client op fills the truncated head's next slot (op 2), not op 4"
  );
  for _ in 0..4 {
    r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // land the fresh op's own-vote append
  }
  // Both backups ack the surviving tail op 1 AND the fresh op 2 → each reaches the quorum of 2.
  for ack_op in [1u64, 2] {
    // Content-address each ack to that op's full identity: op 1's surviving tail carries client 7's
    // canonical [1u8] body (request 1); the fresh op 2 carries client 9's b"fresh" request (request 1).
    let ack_identity = if ack_op == 1 {
      crate::storage::prepare_identity(
        ClientId::new(7),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(&[1u8]),
      )
    } else {
      crate::storage::prepare_identity(
        ClientId::new(9),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"fresh"),
      )
    };
    for backup in [0u16, 2] {
      r.handle_message(
        now,
        &mut wal,
        &mut sb,
        &mut blocks,
        Peer::Replica(ReplicaId::new(backup)),
        Message::PrepareOk(PrepareOk::new(
          View::with(1),
          OpNumber::with(ack_op),
          ReplicaId::new(backup),
          OpNumber::new(),
          ack_identity,
          crate::Epoch::new(0),
          0,
        )),
      );
    }
  }
  assert_eq!(
    r.commit(),
    OpNumber::with(2),
    "commit progresses through the fresh op — try_commit is not wedged at the former interior gap"
  );
}

#[test]
fn new_primary_does_not_truncate_a_committed_interior_gap_it_repairs_it() {
  // COMPLEMENT — a COMMITTED gap must NOT be truncated. Same faulty-interior-slot
  // replica (checkpoint 0, head 3, op 2 absent), but this time the DVC quorum reports commit* == 3, so
  // op 2 is BELOW the committed frontier — a real repair hole the offset-union could not carry, NOT
  // an uncommitted gap. The seeding-site truncation only scans `(commit* .. op]`, so op 2 (≤ commit*)
  // is OUTSIDE it: the head is NOT truncated, op 2 stays a `repair` hole, the commit is HELD at op 1,
  // and a peer-supplied (committed-vouching) Prepare fills it and resumes the held commit. This guards
  // the truncation from over-reaching into a committed op (which would silently drop it).
  let (mut r, mut wal, mut sb) = recovering_with_hole(3, 2);
  let mut blocks = crate::block_store::MemBlockStore::new();
  while r.poll_message().is_some() {}
  let now = Instant::ZERO;
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // complete the SendDoViewChange durable-view write
  while r.poll_message().is_some() {}
  // Replica 2's DVC: same generation (log_view 0), head 3, but commit 3 (it committed past op 2). Its
  // own offset log still lacks op 2, so the union has the gap at op 2 — but commit* now == 3.
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(3),
      OpNumber::with(3),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::copy_from_slice(&[1u8]),
        ),
        PreparedEntry::new(
          OpNumber::with(3),
          ClientId::new(7),
          RequestNumber::with(3),
          bytes::Bytes::copy_from_slice(&[3u8]),
        ),
      ],
    )),
  );
  assert!(r.is_primary(), "replica 1 became the primary of view 1");

  // The head is NOT truncated (op 2 is committed, ≤ commit* == 3) — it stays at op 3 — and op 2 is a
  // repair hole with the commit HELD at op 1 (the apply loop never skips the committed hole).
  assert_eq!(
    r.op(),
    OpNumber::with(3),
    "a committed interior gap does NOT truncate the head (op 2 ≤ commit*)"
  );
  assert!(
    r.has_repair_hole_for_test(2),
    "the committed gap is a repair hole (on-demand repair), not silently dropped"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(1),
    "the commit is HELD below the committed hole until a peer supplies op 2"
  );

  // Pump the StartViewAsPrimary durable-view write, then a peer answers our RequestPrepare with op 2's
  // committed-vouching Prepare (commit 3 >= op 2) → fill the hole and resume the held commit to op 3.
  // The fill is a durability barrier: complete the repaired append before the hole clears.
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while r.poll_message().is_some() {}
  r.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    repair_prepare(0, 2, 3),
  );
  r.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → clear hole + resume
  assert!(
    !r.has_repair_hole_for_test(2),
    "the committed-vouching Prepare fills the hole"
  );
  assert_eq!(
    r.commit(),
    OpNumber::with(3),
    "the held commit resumes once the committed gap is repaired (op 2 then 3 apply in order)"
  );
}

#[test]
fn new_primary_reconstructs_sessions_so_retries_dedup() {
  // replica 1 becomes primary of view 1, adopting client 7's requests 1 (committed) and 2.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  ); // primary_idle → SVC
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b"),
        ),
      ],
    )),
  );
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2));
  while e.poll_message().is_some() {}
  // The new primary deferred participation until its view is durable; pump storage so the
  // durable-view write completes and it may serve requests (durable-view-before-participate).
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}

  // A retry of request 1 (already adopted+committed) must NOT create a new op (dedup, no re-exec).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"a"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "retry of an adopted request must be deduplicated, not re-executed"
  );

  // A genuinely new request (3) IS accepted → op advances to 3.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(3),
      bytes::Bytes::from_static(b"c"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(3),
    "a new request after the adopted ones is accepted"
  );
}

#[test]
fn canonical_selection_prefers_highest_log_view_over_longer_log() {
  // r0 has the newest generation (log_view 2) but a SHORTER log; r1/r2 are longer but stale.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 2, 3, 1));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 1, 5, 1));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc(2, 1, 5, 1));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(op_head, 3, "newest log_view wins, not the longer stale log");
  assert_eq!(log.len(), 3);
  assert_eq!(commit_star, 1);
}

#[test]
fn nack_prepare_truncates_provably_uncommitted_tail() {
  // N=5 → quorum_nack_prepare = 3. Head op 5 held only by r0; r1,r2,r3 stop at op 2.
  // ops 3..=5 each get 3 nacks (r1,r2,r3) ≥ 3 → truncated to op 2.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 1, 5, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 1, 2, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc(2, 1, 2, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), dvc(3, 1, 2, 2));
  let (log, op_head, _, _) = e.select_canonical_log();
  assert_eq!(op_head, 2, "ops 3..=5 had a nack quorum → truncated");
  assert_eq!(log.len(), 2);
}

#[test]
fn committed_ops_are_never_truncated() {
  // commit* = 4: op 5 is the only uncommitted op, nacked by 3 → truncated; 1..=4 survive.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 1, 5, 4));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 1, 4, 4));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc(2, 1, 4, 4));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), dvc(3, 1, 4, 4));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(commit_star, 4);
  assert_eq!(
    op_head, 4,
    "uncommitted op 5 truncated, committed 1..=4 kept"
  );
  assert_eq!(log.len(), 4);
}

#[test]
fn no_truncation_at_minimal_quorum() {
  // Documents the contiguous-model property: with exactly quorum_view_change=3 DVCs,
  // the head-holder (r0) prevents a nack quorum (≤ 2 nacks < 3) → adopt whole.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 1, 5, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc(1, 1, 2, 2));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc(2, 1, 2, 2));
  let (_, op_head, _, _) = e.select_canonical_log();
  assert_eq!(
    op_head, 5,
    "no nack quorum possible at minimal quorum → no truncation"
  );
}

#[test]
fn stalled_view_change_escalates_to_the_next_view() {
  // replica 3 of 5 (a backup at views 0,1,2). Drive it into ViewChange(1); the new primary(1)
  // never sends a StartView, so view_change_status escalates it toward view 2.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(3)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let t = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(t, &mut wal, &mut sb, &mut blocks); // primary_idle → propose view 1 (own bit, 1/3)
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  ); // 2/3
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(1),
      crate::Epoch::new(0),
      0,
    )),
  ); // 3/3 → ViewChange(1)
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.status(), Status::ViewChange);

  // Stuck: fire view_change_status (~500ms after transition) → escalate, proposing view 2.
  let t2 = t + core::time::Duration::from_millis(600);
  e.handle_timeout(t2, &mut wal, &mut sb, &mut blocks);
  // Two peers also propose view 2 → quorum → transition to view 2.
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(2),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(
      View::with(2),
      ReplicaId::new(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.view(), View::with(2), "escalated to the next view");
  assert_eq!(e.status(), Status::ViewChange);
}

#[test]
fn backup_adopts_start_view() {
  // replica 2 of 3 receives a StartView for view 1 from primary(1)=replica 1.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.log_view(), View::with(1));
  assert_eq!(e.op(), OpNumber::with(2));
  assert_eq!(e.commit(), OpNumber::with(1)); // op 1 applied
  // The adoption surfaced as an observability event: view 1, adopted as a BACKUP. (Status stayed
  // Normal→Normal across the direct adoption, so no StatusChanged accompanies it here.)
  assert!(
    core::iter::from_fn(|| e.poll_event())
      .any(|ev| ev == Event::ViewChanged(crate::ViewChanged::new(View::with(1), false))),
    "adopting a StartView emits ViewChanged for the new view"
  );
  // the PrepareOk for the held uncommitted op (op 2) is deferred until BOTH the new
  // view is durable AND op 2 is durably (re-)appended to the WAL (append-before-ack). Two sequential
  // storage steps: (1) the durable-view write completes → `start_view_acks` submits the WAL append;
  // (2) the append completes → `on_wal_done` sends the PrepareOk. Pump until it appears (bounded).
  let mut acked_op2 = false;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg()
        && ok.op() == OpNumber::with(2)
      {
        acked_op2 = true;
      }
    }
    if acked_op2 {
      break;
    }
  }
  assert!(
    acked_op2,
    "backup must ack its held uncommitted ops in the new view"
  );
  // Append-before-ack: op 2 is in the durable WAL by the time it is acked (so a crash+recover after
  // the ack still produces it). The committed op 1 below the ack range is also durably present.
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "the acked op 2 was durably (re-)appended to the WAL before the PrepareOk"
  );
}

/// NO old-generation in-flight state survives a view transition. Each of the THREE
/// transition entries — `enter_view_change` (self-driven), `catch_up_to_view` (higher-view catch-up),
/// and `adopt_canonical_head` (adopt an authoritative head) — must tear down the SAME union of
/// old-view sub-state via the single `reset_for_view_transition` chokepoint. This seeds the FULL set
/// (quorum collection, in-flight appends, peer-checkpoint reports, in-flight checkpoint, the
/// state-sync `sync`+`pending_install` pair + its solicit timer, and the forfeit sub-state) before
/// each transition and asserts the chokepoint cleared it — freezing the invariant the helper
/// centralizes so a future field added to one path but not the others is caught here.
#[test]
fn no_old_generation_state_survives_a_view_transition() {
  let mut sb = TestSb::default();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // (1) enter_view_change (the self-driven entry, reached here via the recovery wrapper that shares
  // the identical body). A backup at view 0 → view 1: catching_up must end FALSE.
  let mut e = backup();
  e.seed_old_generation_state_for_test();
  e.enter_view_change_from_recovery(now, &mut sb, View::with(1));
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.old_generation_state_cleared_for_test(),
    "enter_view_change must clear the entire old-generation in-flight set"
  );
  assert!(
    !e.catching_up(),
    "a self-driven view change ends catching_up"
  );
  while e.poll_message().is_some() {}

  // (2) catch_up_to_view (the higher-view catch-up entry). A backup at view 0 → view 1: catching_up
  // must end TRUE (the one field the shared reset sets false and this entry re-sets after).
  let mut e = backup();
  e.seed_old_generation_state_for_test();
  e.catch_up_to_view(now, View::with(1));
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.old_generation_state_cleared_for_test(),
    "catch_up_to_view must clear the entire old-generation in-flight set"
  );
  assert!(
    e.catching_up(),
    "catch_up_to_view re-sets the catch-up flag"
  );
  assert!(
    !e.pending_sb_for_test(),
    "catch-up issues no durable-view write"
  );
  while e.poll_message().is_some() {}

  // (3) adopt_canonical_head (adopt an authoritative StartView head → Normal). op 1, commit 0 so the
  // adoption neither rewinds nor needs to advance the commit. catching_up must end FALSE.
  let mut e = backup();
  e.seed_old_generation_state_for_test();
  e.adopt_canonical_head(
    now,
    &mut sb,
    &mut blocks,
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    &[PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"a"),
    )],
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.old_generation_state_cleared_for_test(),
    "adopt_canonical_head must clear the entire old-generation in-flight set"
  );
  assert!(!e.catching_up(), "adoption ends catching_up");
}

#[test]
fn higher_view_prepare_triggers_get_view_catch_up() {
  // replica 0 at view 0 receives a Prepare for view 1 → catch up, sending GetView to primary(1)=1.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"x"),
    )),
  );
  assert_eq!(e.view(), View::with(1));
  assert_eq!(e.status(), Status::ViewChange);
  let mut saw_get_view = false;
  while let Some(out) = e.poll_message() {
    if let Message::GetView(g) = out.into_msg() {
      assert_eq!(g.view(), View::with(1));
      saw_get_view = true;
    }
  }
  assert!(
    saw_get_view,
    "catch-up sends GetView (not a StartViewChange)"
  );

  // The StartView reply ends the catch-up: replica 0 becomes Normal in view 1.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"x"),
      )],
    )),
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
  // The full transition arc surfaced as observability events, in order: the catch-up flipped status
  // to ViewChange, the adoption flipped it back to Normal and reported the adopted view.
  let events: std::vec::Vec<Event> = core::iter::from_fn(|| e.poll_event()).collect();
  let transitions: std::vec::Vec<&Event> = events
    .iter()
    .filter(|ev| matches!(ev, Event::StatusChanged(_) | Event::ViewChanged(_)))
    .collect();
  assert_eq!(
    transitions,
    std::vec![
      &Event::StatusChanged(Status::ViewChange),
      &Event::StatusChanged(Status::Normal),
      &Event::ViewChanged(crate::ViewChanged::new(View::with(1), false)),
    ],
    "the catch-up + adoption emit the status/view transition events in order"
  );
}

#[test]
fn normal_primary_answers_get_view_with_start_view() {
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  assert_eq!(e.header_only_carriers_emitted(), 0, "no carrier built yet");
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::GetView(GetView::new(
      View::with(0),
      ReplicaId::new(1),
      5,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut saw_sv = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartView(sv) = out.into_msg() {
      assert_eq!(sv.view(), View::with(0));
      assert_eq!(sv.replica(), ReplicaId::new(0));
      saw_sv = true;
    }
  }
  assert!(saw_sv, "a Normal primary answers GetView with a StartView");
  assert_eq!(
    e.header_only_carriers_emitted(),
    1,
    "the StartView answer's log payload was built via the log_entries chokepoint (counted once)"
  );
}

#[test]
fn lone_high_svc_is_ignored_not_driven() {
  // A single StartViewChange for a far-future view must NOT inflate our view (C1 guard):
  // an SVC is not evidence a primary exists at that view.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(100),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.view(),
    View::new(),
    "a lone high SVC must not inflate our view"
  );
  assert_eq!(e.status(), Status::Normal);
}

#[test]
#[should_panic(expected = "must not rewind below our committed op")]
fn on_start_view_rewind_below_commit_panics() {
  // Adopt a StartView for view 1 with op 2 (commit 2), then a StartView for view 2 with op 1
  // (< our committed op 2). The second must fail-stop, not silently rewind.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)), // primary of view 1
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(2),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(1),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a")
        ),
        PreparedEntry::new(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          bytes::Bytes::from_static(b"b")
        ),
      ],
    )),
  );
  assert_eq!(e.commit(), OpNumber::with(2));
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)), // primary of view 2
    Message::StartView(StartView::new(
      View::with(2),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a")
      )],
    )),
  );
}

#[test]
fn adopting_a_canonical_head_truncates_the_wal_above_it() {
  // REGRESSION, the source-side half of the committed-divergence fix. When a replica
  // adopts a new view's canonical head, any WAL slot ABOVE that head is an UNCOMMITTED earlier-view proposal
  // (the canonical head is the new view's authoritative head — nothing above it is committed). Leaving such a
  // slot in the WAL lets a later `recover` re-load it and apply its stale body for a committed op the new view
  // assigns at that number. So adoption must physically TRUNCATE the WAL above the adopted head — dropping only
  // uncommitted ops (no durability dip). Here replica 2 of 3 holds a stale tail op 3 in its WAL, then adopts a
  // StartView for view 1 whose head is op 2; the WAL must no longer contain op 3.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Seed the WAL with a stale uncommitted tail op 3 (as if appended in an earlier generation).
  let stale = Header::new(
    OpNumber::with(3),
    View::new(),
    ClientId::new(9),
    RequestNumber::with(99),
    &[0xAA],
  );
  wal.submit_append(
    OpId::new(999),
    OpNumber::with(3),
    stale,
    Bytes::copy_from_slice(&[0xAA]),
  );
  while wal.poll().is_some() {} // discard the seed completion
  assert_eq!(
    wal.op_head(),
    OpNumber::with(3),
    "precondition: the WAL holds the stale tail op 3"
  );

  // Adopt a StartView for view 1 (from primary(1) = replica 1) whose canonical head is op 2.
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        Bytes::from_static(b"a"),
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        Bytes::from_static(b"b"),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.op(), OpNumber::with(2), "adopted the canonical head op 2");
  // The crux: the stale slot 3 was TRUNCATED from the WAL (FAIL-BEFORE: it lingered, to be re-loaded by a
  // later recover and applied as a stale committed body).
  assert!(
    !wal.entries.contains_key(&3),
    "FAIL-BEFORE: the uncommitted tail op 3 above the adopted head must be truncated from the WAL"
  );
  assert!(
    wal.op_head().get() <= 2,
    "the WAL head no longer sits above the adopted canonical head"
  );
}

#[test]
fn dvc_is_deferred_until_view_is_durable() {
  use crate::StartViewChange;
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let later = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    later,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  let mut saw_dvc_before = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::DoViewChange(_)) {
      saw_dvc_before = true;
    }
  }
  assert!(
    !saw_dvc_before,
    "DoViewChange must NOT be sent before the view is durable"
  );
  assert_eq!(
    sb.state().view(),
    View::with(1),
    "new view submitted to the superblock"
  );
  e.handle_storage(later, &mut wal, &mut sb, &mut blocks);
  let mut saw_dvc_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      assert_eq!(d.view(), View::with(1));
      saw_dvc_after = true;
    }
  }
  assert!(
    saw_dvc_after,
    "DoViewChange is sent once the view is durable"
  );
}

#[test]
fn dvc_retransmit_waits_for_the_durable_view_write() {
  // REGRESSION (durable-view-before-participate, CONSENSUS-CRITICAL). A ViewChange
  // replica arms `dvc_message` (the DVC retransmit) AND submits the SendDoViewChange durable-view
  // write in `enter_view_change`. The INITIAL DVC is deferred to `on_sb_done` (see
  // `dvc_is_deferred_until_view_is_durable`), BUT if the async superblock write is slower than
  // `VC_MESSAGE_RETRANSMIT` the `dvc_message` retransmit would (pre-fix) fire FIRST and CAST a DVC
  // vote — which the new primary counts toward forming the view — BEFORE this replica has PERSISTED
  // the view. A crash before the write lands recovers the OLD view after this replica helped form a
  // quorum for the new one: the exact durable-view-before-participate hazard, in the retransmit path.
  // FAIL-BEFORE: a DoViewChange is emitted at the `dvc_message` deadline while `pending_sb` is set.
  // PASS-AFTER: silent across many retransmit cadences while the write is inflight; the DVC fires once
  // the view is durable (`on_sb_done`), and retransmits resume thereafter.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), StepSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let mut now = Instant::ZERO;
  // Drive replica 0 into ViewChange(view 1) as a DRIVER (primary(1) = replica 1, a peer): its own
  // idle-SVC + replica 2's SVC meet the SVC quorum (2), so `enter_view_change` fires.
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks); // bootstrap primary_idle
  now = now + core::time::Duration::from_millis(300);
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks); // primary_idle due → propose view 1 (own SVC)
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.pending_sb_for_test(),
    "the SendDoViewChange durable-view write is in flight"
  );
  assert!(
    sb.has_inflight(),
    "the superblock view write is inflight (not yet durable)"
  );
  while e.poll_message().is_some() {} // drain the StartViewChange(s) emitted by entering ViewChange

  // Drive the `dvc_message` retransmit cadence (100ms) MANY times WITHOUT flushing the superblock —
  // the view stays non-durable across every retransmit deadline.
  for _ in 0..6 {
    now = now + VC_MESSAGE_RETRANSMIT;
    e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
    assert!(
      e.pending_sb_for_test(),
      "the view write is still inflight across the retransmit cadence"
    );
    while let Some(out) = e.poll_message() {
      assert!(
        !matches!(out.into_msg(), Message::DoViewChange(_)),
        "a ViewChange replica must NOT retransmit its DoViewChange vote before the view is durable"
      );
    }
  }

  // Now make the view durable: the deferred initial DVC fires from `on_sb_done`.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let mut saw_dvc_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      assert_eq!(d.view(), View::with(1));
      assert_eq!(d.replica(), ReplicaId::new(0));
      saw_dvc_after = true;
    }
  }
  assert!(
    saw_dvc_after,
    "the DoViewChange fires once the view is durable (on_sb_done)"
  );

  // And the retransmit cadence RESUMES now that the view is durable.
  now = now + VC_MESSAGE_RETRANSMIT;
  e.handle_timeout(now, &mut wal, &mut sb, &mut blocks);
  let mut saw_dvc_retransmit = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::DoViewChange(_)) {
      saw_dvc_retransmit = true;
    }
  }
  assert!(
    saw_dvc_retransmit,
    "the DoViewChange retransmit resumes once the view is durable"
  );
}

#[test]
fn superseded_view_write_is_ignored() {
  use crate::StartViewChange;
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(3)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let t = Instant::ZERO + core::time::Duration::from_millis(300);
  e.handle_timeout(t, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    t,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.view(), View::with(1));
  while e.poll_message().is_some() {}
  let t2 = t + core::time::Duration::from_millis(600);
  e.handle_timeout(t2, &mut wal, &mut sb, &mut blocks);
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(2),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    t2,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartViewChange(StartViewChange::new(
      View::with(2),
      ReplicaId::new(1),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.view(), View::with(2));
  while e.poll_message().is_some() {}
  e.handle_storage(t2, &mut wal, &mut sb, &mut blocks);
  let mut dvc_views = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::DoViewChange(d) = out.into_msg() {
      dvc_views.push(d.view().get());
    }
  }
  assert!(
    !dvc_views.contains(&1),
    "superseded view-1 DoViewChange must never be sent"
  );
  assert!(
    dvc_views.contains(&2),
    "live view-2 DoViewChange is sent once view 2 is durable"
  );
}

#[test]
fn backup_does_not_prepare_ok_before_start_view_is_durable() {
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a")
      ),
      PreparedEntry::new(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        bytes::Bytes::from_static(b"b")
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal);
  assert_eq!(e.view(), View::with(1));
  assert!(
    e.poll_message().is_none(),
    "backup must NOT PrepareOk before the view is durable"
  );
  assert_eq!(sb.state().view(), View::with(1));
  // the re-ack now ALSO waits for op 2's WAL (re-)append (append-before-ack), so it
  // arrives after two sequential storage steps (durable-view → submit append; append → PrepareOk).
  let mut acked_op2 = false;
  for _ in 0..4 {
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
    while let Some(out) = e.poll_message() {
      if let Message::PrepareOk(ok) = out.into_msg()
        && ok.op() == OpNumber::with(2)
      {
        acked_op2 = true;
      }
    }
    if acked_op2 {
      break;
    }
  }
  assert!(
    acked_op2,
    "held uncommitted ops re-acked once the new view AND their WAL append are durable"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2 is durable in the WAL before its PrepareOk"
  );
}

#[test]
fn new_prepare_not_acked_while_view_write_pending() {
  // Durable-view completeness: after adopting a StartView the backup is Normal in the new view but
  // the view is not yet durable (pending_sb armed). A new prepare arriving in this window must NOT
  // be acked until the view is durable; the primary retransmits it afterward.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Adopt a StartView for view 1 with op 1 fully committed (no held re-acks to muddy the assertion).
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"a"),
    )],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal);
  let prep2 = || {
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(2),
      OpNumber::with(1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(2),
      bytes::Bytes::from_static(b"b"),
    ))
  };
  // A new prepare (op 2) arrives BEFORE the durable-view write is pumped (pending_sb still armed).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    prep2(),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // drains the StartView write; would pump op 2 if accepted
  let mut acked_op2 = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg()
      && ok.op() == OpNumber::with(2)
    {
      acked_op2 = true;
    }
  }
  assert!(
    !acked_op2,
    "a new prepare must NOT be acked while the view-change write is pending"
  );
  // Re-deliver (as the primary retransmits) now that the view is durable → it is acked.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    prep2(),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // append-before-ack: pump the WAL append
  let mut acked_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::PrepareOk(ok) = out.into_msg()
      && ok.op() == OpNumber::with(2)
    {
      acked_after = true;
    }
  }
  assert!(
    acked_after,
    "once the view is durable, the retransmitted prepare is acked"
  );
}

#[test]
fn new_primary_does_not_answer_get_view_while_its_view_write_is_pending() {
  // REGRESSION (durable-view-before-participate, CONSENSUS-CRITICAL). A replica that
  // just became primary of a new view but has not yet PERSISTED that view (the StartView broadcast
  // is deferred to `on_sb_done`) must NOT answer a delayed/duplicate `GetView` with a `StartView`
  // for the not-yet-durable view: on crash it could regress out of a view it had already vouched
  // for, double-participating across views. FAIL-BEFORE: a `StartView` appears in the pending_sb
  // window. PASS-AFTER: silent in the window; the deferred `StartView` fires once the view is
  // durable, and a later `GetView` is then answered.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // A peer solicits the canonical head for view 1 — delivered WHILE the view write is pending.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(GetView::new(
      View::with(1),
      ReplicaId::new(2),
      9,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut sv_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::StartView(_)) {
      sv_in_window = true;
    }
  }
  assert!(
    !sv_in_window,
    "a primary must NOT hand out a StartView for a view that is not yet durable"
  );
  // Make the view durable: the deferred StartView broadcast fires now (start_view_participate).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.pending_sb_for_test(),
    "the view is now durable (pending_sb cleared)"
  );
  let mut sv_after = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartView(s) = out.msg_ref() {
      assert_eq!(s.op(), OpNumber::with(2));
      sv_after = true;
    }
  }
  assert!(
    sv_after,
    "once the view is durable the deferred StartView broadcast fires"
  );
  // And a fresh GetView is now answered (the gate has lifted).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(GetView::new(
      View::with(1),
      ReplicaId::new(2),
      10,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut answered = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::StartView(_)) {
      answered = true;
    }
  }
  assert!(
    answered,
    "after the view is durable, a GetView is answered with a StartView"
  );
}

#[test]
fn new_primary_does_not_answer_recovery_while_its_view_write_is_pending() {
  // REGRESSION: same window, the Recovery-solicitation path. A primary in the
  // pending_sb window must NOT answer a peer's `Recovery` with its canonical `(op, commit, log)` in
  // the not-yet-durable view. FAIL-BEFORE: a `RecoveryResponse` appears in the window. PASS-AFTER:
  // silent in the window; once the view is durable a Recovery is answered normally.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(
      ReplicaId::new(2),
      4242,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut rr_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::RecoveryResponse(_)) {
      rr_in_window = true;
    }
  }
  assert!(
    !rr_in_window,
    "a primary must NOT answer a Recovery in a view that is not yet durable"
  );
  // Make the view durable, then a fresh Recovery IS answered (with the canonical head).
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {} // discard the deferred StartView broadcast
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::Recovery(Recovery::new(
      ReplicaId::new(2),
      4243,
      crate::Epoch::new(0),
      0,
    )),
  );
  let mut answered = false;
  while let Some(out) = e.poll_message() {
    if let Message::RecoveryResponse(rr) = out.msg_ref() {
      assert_eq!(rr.op(), OpNumber::with(2), "the canonical head op");
      assert_eq!(rr.nonce(), 4243, "the echoed nonce");
      answered = true;
    }
  }
  assert!(
    answered,
    "after the view is durable, a Recovery is answered with a RecoveryResponse"
  );
}

#[test]
fn new_primary_does_not_heartbeat_or_retransmit_while_its_view_write_is_pending() {
  // REGRESSION: the timer path. A primary in the pending_sb window must NOT emit a
  // `Commit` heartbeat nor retransmit `Prepare`s — those assert its authority in a view that is not
  // yet durable. FAIL-BEFORE: a `Commit`/`Prepare` appears when `primary_timeouts` fires in the
  // window. PASS-AFTER: silent in the window; heartbeats resume once the view is durable.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let mut blocks = crate::block_store::MemBlockStore::new();
  // Tick the primary TWICE while the view write is still pending: the first tick would BOOTSTRAP the
  // commit/prepare timers (the deferred `start_view_participate` has not armed them yet), the second
  // — well past those deadlines — would FIRE the heartbeat/retransmit if the gate were absent. Both
  // ticks happen entirely inside the pending_sb window (we never flush the superblock between them),
  // exactly the multi-tick window a real driver leaves open. Nothing must be emitted in either.
  let later = Instant::ZERO + core::time::Duration::from_secs(5);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
  let later_fire = later + core::time::Duration::from_secs(1); // >> COMMIT_HEARTBEAT/PREPARE_RETRANSMIT
  e.handle_timeout(later_fire, &mut wal, &mut sb, &mut blocks);
  let mut emitted_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(
      out.msg_ref(),
      Message::Commit(_) | Message::Prepare(_) | Message::StartView(_)
    ) {
      emitted_in_window = true;
    }
  }
  assert!(
    !emitted_in_window,
    "a primary must not heartbeat/retransmit/StartView in a not-yet-durable view"
  );
  assert!(
    e.pending_sb_for_test(),
    "the ticks must not have force-completed the view write"
  );
  // Once the view is durable, the heartbeat resumes (start_view_participate arms the timers).
  sb.flush();
  e.handle_storage(later_fire, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {} // discard the deferred StartView
  let later2 = later_fire + core::time::Duration::from_secs(5);
  e.handle_timeout(later2, &mut wal, &mut sb, &mut blocks);
  let mut heartbeat_after = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::Commit(_)) {
      heartbeat_after = true;
    }
  }
  assert!(
    heartbeat_after,
    "once the view is durable the primary heartbeats normally"
  );
}

#[test]
fn on_request_prepare_does_not_serve_during_the_durable_view_window() {
  // REGRESSION (durable-view-before-participate, CONSENSUS-CRITICAL). A replica in its
  // `pending_sb` window — here a NEW PRIMARY that just adopted view 1 but has NOT yet persisted it (the
  // StartView broadcast is deferred to `on_sb_done`) — is `Normal` but its view is not yet recoverable.
  // The repair-server path `on_request_prepare` previously gated only on `status.is_normal()` and then
  // served `Prepare::new(self.view, ..)` for a held committed op, ADVERTISING the not-yet-durable view:
  // on crash it could regress out of a view it had already vouched for to a soliciting peer (the same
  // cross-view hazard the primary `Prepare`/`Commit`/`StartView` paths gate on). FAIL-BEFORE: a
  // `Prepare` appears in the window. PASS-AFTER: silent in the window; once the view is durable the same
  // `RequestPrepare` IS answered with a `Prepare` carrying the now-durable view.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the new primary committed op 1 (so op 1 is a committed op it may serve as a repair source)"
  );
  // A peer solicits the committed op 1 (op <= commit_min) — delivered WHILE the view write is pending.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      0,
      0,
    )),
  );
  let mut prepare_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::Prepare(_)) {
      prepare_in_window = true;
    }
  }
  assert!(
    !prepare_in_window,
    "a replica must NOT serve a repair Prepare (which advertises self.view) in a not-yet-durable view"
  );
  assert!(
    e.pending_sb_for_test(),
    "handling the RequestPrepare must not have force-completed the view write"
  );
  // Make the view durable (this fires the deferred StartView broadcast — discard it), then the SAME
  // RequestPrepare IS answered with a Prepare carrying the now-durable view 1.
  sb.flush();
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.pending_sb_for_test(),
    "the view is now durable (pending_sb cleared)"
  );
  while e.poll_message().is_some() {} // discard the deferred StartView broadcast
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestPrepare(crate::RequestPrepare::new(
      View::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      0,
      0,
    )),
  );
  let mut served = false;
  while let Some(out) = e.poll_message() {
    if let Message::Prepare(p) = out.msg_ref() {
      assert_eq!(
        p.op(),
        OpNumber::with(1),
        "serves the requested committed op"
      );
      assert_eq!(
        p.view(),
        View::with(1),
        "the served Prepare advertises the now-durable view"
      );
      served = true;
    }
  }
  assert!(
    served,
    "after the view is durable, the RequestPrepare is answered with a Prepare"
  );
}

#[test]
fn serve_sync_checkpoint_does_not_serve_during_the_durable_view_window() {
  // REGRESSION (durable-view-before-participate, CONSENSUS-CRITICAL). A replica in its
  // `pending_sb` window — here a NEW PRIMARY that just adopted view 1 but has NOT yet persisted it (the
  // StartView broadcast is deferred to `on_sb_done`) — is `Normal` but its view is not yet recoverable.
  // The state-sync serve path `serve_sync_checkpoint` previously gated only on `status.is_normal()` and
  // then shipped `SyncCheckpoint::new(self.view, ..)` for a held durable checkpoint, ADVERTISING the
  // not-yet-durable view: on crash it could regress out of a view it had already vouched for to a
  // soliciting peer (the same cross-view hazard the primary `Prepare`/`Commit`/`StartView` and the
  // `on_request_prepare` paths gate on). FAIL-BEFORE: a `SyncCheckpoint` appears in the window.
  // PASS-AFTER: silent in the window; once the view is durable the same `RequestSync` IS answered with
  // a `SyncCheckpoint` carrying the now-durable view.
  let (mut e, mut wal, mut sb) = primed_new_primary_in_pending_view_window();
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Give this primed primary a DURABLE checkpoint to serve: a `checkpoint_op` of 1 (a committed op it
  // holds — its `commit_min` is 1) and a readable snapshot envelope in the StepSb at that op. The
  // serve's ship-time gate requires `cr.op() == self.checkpoint_op`, so the injected op must match;
  // the integrity gate additionally requires the read bytes to hash to the DURABLE checkpoint id,
  // so the durable ROOT must NAME this snapshot — set `sb.state` to a root at checkpoint_op 1 whose
  // `checkpoint_id == checkpoint_id(snapshot)` (a genuinely durable checkpoint, not a half-faked one).
  // The view stays 0 (the prior, still-durable view): the view-1 write is the one held inflight, which
  // is exactly the not-yet-durable-view window this test exercises.
  let snapshot = Bytes::from_static(b"durable-checkpoint-snapshot");
  e.set_own_checkpoint_for_test(1);
  sb.checkpoint = Some((OpNumber::with(1), snapshot.clone()));
  sb.state = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(1),
    OpNumber::with(1),
    crate::checkpoint_id(&snapshot),
    std::vec::Vec::new(),
  )
  .expect("durable root: commit == checkpoint_op, log_view <= view");
  // A lagging peer solicits the checkpoint (its own `checkpoint_op` is 0, strictly below ours) — the
  // RequestSync is delivered WHILE the view write is pending. `on_request_sync` submits the checkpoint
  // read (it does not itself gate on `pending_sb`); the read completes into `serve_sync_checkpoint`,
  // which is the load-bearing SHIP-time gate.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      View::with(1),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xD18F,
      false,
      0, // ordinary state-sync (not a recovery peer-fetch)
    )),
  );
  // Pump storage so the checkpoint read completes (StepSb serves reads eagerly into `ready`) and
  // `serve_sync_checkpoint` runs — but WITHOUT flushing the inflight view write, so the window stays
  // open. The serve must DROP (no SyncCheckpoint) because our view is not yet durable.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  let mut sync_checkpoint_in_window = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.msg_ref(), Message::SyncCheckpoint(_)) {
      sync_checkpoint_in_window = true;
    }
  }
  assert!(
    !sync_checkpoint_in_window,
    "a replica must NOT serve a SyncCheckpoint (which advertises self.view) in a not-yet-durable view"
  );
  assert!(
    e.pending_sb_for_test(),
    "handling the RequestSync / read completion must not have force-completed the view write"
  );
  // Make the view durable (this fires the deferred StartView broadcast — discard it), then the SAME
  // RequestSync IS answered with a SyncCheckpoint carrying the now-durable view 1.
  sb.flush();
  // The flushed view-1 root was SUBMITTED by the shared harness before the checkpoint was injected
  // (when the durable root was `initial()`), so the StepSb published it with checkpoint_op/id 0 — a
  // harness artifact: the real `submit_durable_view` PRESERVES the durable checkpoint (see its doc).
  // Re-establish the proto-correct durable root (now at view 1, still naming the op-1 checkpoint) BEFORE
  // draining storage, so the durable `checkpoint_op` matches the in-memory `checkpoint_op == 1` the
  // settled-frontier invariant (`assert_invariants` exit) checks — and so the integrity gate sees the
  // genuine durable id the post-flush serve must match.
  sb.state = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(1),
    crate::checkpoint_id(&snapshot),
    std::vec::Vec::new(),
  )
  .expect("durable root: commit == checkpoint_op, log_view <= view");
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.pending_sb_for_test(),
    "the view is now durable (pending_sb cleared)"
  );
  while e.poll_message().is_some() {} // discard the deferred StartView broadcast
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::RequestSync(crate::RequestSync::new(
      View::with(1),
      OpNumber::with(0),
      ReplicaId::new(2),
      0xD18F,
      false,
      0,
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the checkpoint read completes → ship SyncCheckpoint
  let mut served = false;
  while let Some(out) = e.poll_message() {
    if let Message::SyncCheckpoint(s) = out.msg_ref() {
      assert_eq!(
        s.checkpoint_op(),
        OpNumber::with(1),
        "serves the durable checkpoint op"
      );
      assert_eq!(
        s.view(),
        View::with(1),
        "the served SyncCheckpoint advertises the now-durable view"
      );
      assert_eq!(s.nonce(), 0xD18F, "echoes the soliciting nonce");
      assert_eq!(
        crate::checkpoint_id(s.snapshot()),
        s.checkpoint_id(),
        "shipped snapshot provably matches its advertised id"
      );
      served = true;
    }
  }
  assert!(
    served,
    "after the view is durable, the RequestSync is answered with a SyncCheckpoint"
  );
}

#[test]
fn canonical_selection_with_a_checkpoint_offset_log_is_safe() {
  // A canonical generation where one DVC's log starts above op 1 (its donor was state-synced to
  // checkpoint 4, commit 4) must not be mis-truncated, and the commit* <= op_head fail-stop must not
  // trip for a synced participant (its commit == op_head == checkpoint when tail-empty).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  // r0: a full-from-1 log (head 5, commit 4). r1: the SAME generation but state-synced — its log
  // starts at op 5 (checkpoint 4), head 5, commit 4. Same log_view → both canonical.
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 1, 5, 4));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_offset(1, 1, 4, 5, 4));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(
    op_head, 5,
    "the offset log does not shorten the canonical head"
  );
  assert_eq!(commit_star, 4, "commit* preserved");
  assert!(
    commit_star <= op_head,
    "the fail-stop invariant holds for an offset-log participant"
  );
  // The UNION covers [1..=5]: r0 supplies the prefix the offset r1 omits, so no op is dropped.
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  assert_eq!(
    present,
    (1..=5u64).collect::<std::collections::BTreeSet<u64>>(),
    "the union of r0's full log and r1's offset log covers ops 1..=5"
  );
}

#[test]
fn view_change_abandons_an_outstanding_sync() {
  // State-sync and view change are mutually exclusive by status: a higher-view message arriving
  // while a sync is outstanding takes the replica into ViewChange and clears the stale sync (so the
  // sync_solicit timer does not linger). The replica re-triggers state-sync from Normal if still
  // behind.
  let mut e = sync_backup();
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Trigger a sync (in view 0).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    primary_peer(),
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(8),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  assert!(e.poll_timeout().is_some(), "sync armed");
  // A higher-view Commit arrives → catch_up_to_view → ViewChange, which must clear the sync.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(8),
      OpNumber::with(8),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  assert!(
    e.sync.is_none(),
    "the outstanding sync is abandoned on entering a view change"
  );
  assert!(
    e.timers.sync_solicit.is_none(),
    "the sync solicit timer is cleared"
  );
}

#[test]
fn canonical_selection_with_a_fully_checkpoint_synced_participant_is_safe() {
  // The extreme: a state-synced participant whose tail is EMPTY (head == commit == checkpoint 4, no
  // log entries at all). select_canonical_log must handle commit == op_head with an empty offset log
  // without panicking or fabricating ops.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 1, 5, 4));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_offset(1, 1, 4, 4, 4)); // tail-empty synced participant
  let (_log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(op_head, 5);
  assert_eq!(commit_star, 4);
  assert!(commit_star <= op_head);
}

// ── offset-aware canonical-log selection (UNION committed entries across DVCs) ──

#[test]
fn select_canonical_log_unions_committed_ops_across_different_floor_dvcs() {
  // The reproduction (offset-aware canonical-log selection): TWO different-floor offset DVCs in the SAME
  // canonical generation, both head op 10 commit 8. r0 (floor 4) holds ops 5..=10; r1 (floor 8) holds
  // only 9,10. Both tie at op 10, so the OLD `max_by_key(op)` (ties → highest replica id) picks r1's
  // log [9,10] and SILENTLY DROPS committed ops 5,6,7 — which only r0 holds. The `commit* <= op_head`
  // fail-stop does NOT trip (the dropped ops are interior). select_canonical_log MUST instead UNION:
  // the returned canonical log must cover EVERY committed op (5..=8) that ANY canonical DVC holds.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc_offset(0, 1, 4, 10, 8)); // floor 4: holds 5,6,7,8,9,10
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_offset(1, 1, 8, 10, 8)); // floor 8: holds 9,10 only
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(op_head, 10, "canonical head is the generation's head");
  assert_eq!(commit_star, 8, "commit* is the greatest commit");
  // The committed band the union MUST cover: ops 5..=8 (above the lowest floor 4, up to commit*).
  // Without the union fix the log would be just [9,10] and these would be absent.
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  for op in 5..=8u64 {
    assert!(
      present.contains(&op),
      "committed op {op} (held only by r0's offset log) must be in the canonical log, not dropped"
    );
  }
  // And the uncommitted tail r0 holds (9,10) is included too (no nack quorum truncates it here).
  assert!(
    present.contains(&9) && present.contains(&10),
    "the head ops are present"
  );
  // The entries are the real ones (op-tagged bodies), not fabricated.
  for entry in &log {
    assert_eq!(
      entry.body(),
      Some(&entry.op().get().to_be_bytes()[..]),
      "each unioned entry carries the donor's real body"
    );
  }
}

#[test]
fn select_canonical_log_stitches_the_band_across_three_offset_donors() {
  // Three canonical-generation donors with staggered floors must be STITCHED so the committed band
  // is fully covered even though NO single donor holds it all. N=5, quorum_view_change=3.
  //   r0: floor 0, holds 1,2,3 (head 3)         — the prefix
  //   r1: floor 3, holds 4,5,6 (head 6)         — the middle
  //   r2: floor 6, holds 7,8 (head 8, commit 8) — the suffix + the committed frontier
  // commit* = 8, op_head = 8. The union must produce a dense [1..=8] — dropping any of 1..=8 would
  // lose a committed op some lower-floor adopter needs.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc_offset(0, 1, 0, 3, 3));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_offset(1, 1, 3, 6, 6));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc_offset(2, 1, 6, 8, 8));
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert_eq!(op_head, 8);
  assert_eq!(commit_star, 8);
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  assert_eq!(
    present,
    (1..=8u64).collect::<std::collections::BTreeSet<u64>>(),
    "the union stitches all three offset donors into a gapless committed band 1..=8"
  );
}

#[test]
fn select_canonical_log_bounds_a_dvc_claiming_a_huge_op() {
  // REGRESSION (unbounded nack-scan + overflow): DoViewChanges whose CLAIMED `op` is enormous
  // (here `u64::MAX`) but whose `log_slice()` carries only a few real entries must NOT make the
  // nack-truncation loop scan `commit*+1 ..= u64::MAX` op-by-op. The UNBOUNDED case is when a NACK
  // quorum's worth of donors claim a huge op: then the loop's nack count never reaches the threshold
  // for any finite op, so the OLD `while op <= op_head { ...; op += 1 }` would iterate ~u64::MAX
  // times and finally OVERFLOW `op += 1` at `u64::MAX`. With the fix the scan is derived from the
  // sorted donor ops (bounded by the DVC count) and `op_head` is bounded to the represented log.
  // N=3 → quorum_nack_prepare = 2, so we make TWO donors claim the phantom head.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  // r0: honest — holds ops 1,2,3 (head 3, commit 2).
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(0), dvc(0, 1, 3, 2));
  // r1, r2 (SAME generation): MALFORMED — each claims op == u64::MAX but carries only ops 1..=3.
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(1), dvc_claiming(1, 1, u64::MAX, 2, 3));
  e.dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), dvc_claiming(2, 1, u64::MAX, 2, 3));
  // Must return PROMPTLY (no unbounded scan, no overflow panic) and bound op_head to the represented
  // log: the max op actually present across the canonical donors is 3, so op_head <= 3.
  let (log, op_head, commit_star, _) = e.select_canonical_log();
  assert!(
    op_head <= 3,
    "op_head must be bounded to the represented log (<= 3), not the claimed u64::MAX, got {op_head}"
  );
  assert_eq!(commit_star, 2, "commit* is the greatest claimed commit");
  assert!(
    commit_star <= op_head,
    "the fail-stop invariant still holds"
  );
  // The merged log contains only real, present entries — never a phantom op near u64::MAX.
  for entry in &log {
    assert!(
      entry.op().get() <= 3,
      "no fabricated entry above the represented log"
    );
  }
}

#[test]
fn floored_union_of_two_frame_valid_offset_bands_fits_one_carrier() {
  // THE UNION-OVERFLOW SCENARIO: two INDIVIDUALLY frame-valid header-only offset DVCs (disjoint deep
  // bands, SAME log_view — the staggered case). Donor A is a partitioned laggard whose ancient band
  // `(0 .. cap]` never state-synced (every sync trigger requires RECEIVING a higher-checkpoint
  // message); donor B is the current replica, checkpointed at `x` with band `(x .. x+cap]`. Each
  // band alone is at the gated maximum (`MAX_HEADER_ONLY_BAND_DEPTH` entries — its carrier fits the
  // frame); their UNFLOORED union is ~2 bands ≈ twice the frame cap, which the new primary would
  // adopt into `self.log` and re-emit as an UNSENDABLE StartView/DVC (the transport drops it → a
  // wedged view change). The union floor `floor* = max(canonical checkpoint_op) = x` drops the
  // checkpoint-subsumed prefix — A's entire ancient band is at/below B's durable checkpoint — so the
  // floored union is B's band alone: one gated span, one frame.
  use crate::message::{MAX_FRAME_LEN, MAX_HEADER_ONLY_BAND_DEPTH};
  let cap = MAX_HEADER_ONLY_BAND_DEPTH as u64;
  let x = cap + 1_000; // B's durable checkpoint; the bands are disjoint (A's head < x)
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  let a = dvc_header_band(0, 1, 0, 0, cap, cap); // laggard: floor 0, ops 1..=cap
  let b = dvc_header_band(1, 1, x, x, x + cap, x + cap); // current: floor x, ops x+1..=x+cap
  // The PREMISE: each donor's carrier fits the frame, but a carrier of the unfloored union does not.
  assert!(
    Message::DoViewChange(a.clone()).encoded_len() <= MAX_FRAME_LEN as usize,
    "donor A's band is individually frame-valid"
  );
  assert!(
    Message::DoViewChange(b.clone()).encoded_len() <= MAX_FRAME_LEN as usize,
    "donor B's band is individually frame-valid"
  );
  let unfloored: std::vec::Vec<PreparedEntry> = a
    .log_slice()
    .iter()
    .chain(b.log_slice().iter())
    .cloned()
    .collect();
  assert!(
    Message::DoViewChange(DoViewChange::new(
      View::with(11),
      View::with(1),
      OpNumber::with(x + cap),
      OpNumber::with(x + cap),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      unfloored,
    ))
    .encoded_len()
      > MAX_FRAME_LEN as usize,
    "the UNFLOORED union of the two bands exceeds the frame cap (the wedge being prevented)"
  );
  e.dvc_from_mut_for_test().insert(ReplicaId::new(0), a);
  e.dvc_from_mut_for_test().insert(ReplicaId::new(1), b);
  let (log, op_head, commit_star, floor_star) = e.select_canonical_log();
  assert_eq!(op_head, x + cap);
  assert_eq!(commit_star, x + cap);
  assert_eq!(
    floor_star, x,
    "the union floor is the canonical generation's max vouched checkpoint"
  );
  assert!(
    log.len() <= MAX_HEADER_ONLY_BAND_DEPTH,
    "the floored union is within one band cap, got {} entries",
    log.len()
  );
  assert!(
    log.iter().all(|entry| entry.op().get() > x),
    "every checkpoint-subsumed op (<= floor*) was dropped from the union"
  );
  assert_eq!(
    log.len() as u64,
    cap,
    "the floored union is exactly B's band (nothing above the floor was lost)"
  );
  // The adopted carrier — the same header-only entries a real `log_entries()` re-emission ships
  // (a `DoViewChange` here; it ties `RecoveryResponse` for the LARGEST carrier framing, so the
  // `StartView` fits a fortiori). `encoded_len()` is pinned to `encode().len()` by the codec tests.
  let carrier = Message::DoViewChange(
    DoViewChange::new(
      View::with(11),
      View::with(1),
      OpNumber::with(op_head),
      OpNumber::with(commit_star),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      log,
    )
    .with_checkpoint_op(OpNumber::with(floor_star)),
  );
  assert!(
    carrier.encoded_len() <= MAX_FRAME_LEN as usize,
    "the floored canonical carrier fits the frame: {} > {}",
    carrier.encoded_len(),
    MAX_FRAME_LEN
  );
}

#[test]
fn floored_union_keeps_a_committed_op_held_only_by_the_low_floor_donor() {
  // SAFETY of the floor: the union drops ONLY ops `<= floor*` (checkpoint-subsumed at a canonical
  // donor). An op in `(floor* .. commit*]` held by the LOW-floor donor but ABSENT from the
  // high-floor donor (whose copy was, say, recovery-dropped — its log starts above its own durable
  // checkpoint) MUST still ride the union. Donors (same log_view, head 10, commit 8):
  //   r0: vouched floor 4, holds 5..=10  — the low-floor donor;
  //   r1: vouched floor 6, holds 9,10    — its 7,8 are interior recovery losses (a log floor above
  //       its advertised checkpoint — the span-exceeds-len shape).
  // floor* = 6: ops 5,6 are dropped (subsumed by r1's checkpoint); ops 7,8 — committed, held ONLY
  // by r0 — survive via the union.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  e.dvc_from_mut_for_test().insert(
    ReplicaId::new(0),
    dvc_offset(0, 1, 4, 10, 8).with_checkpoint_op(OpNumber::with(4)),
  );
  e.dvc_from_mut_for_test().insert(
    ReplicaId::new(1),
    dvc_offset(1, 1, 8, 10, 8).with_checkpoint_op(OpNumber::with(6)),
  );
  assert_eq!(
    e.unions_floored(),
    0,
    "no selection has floored a union yet"
  );
  let (log, op_head, commit_star, floor_star) = e.select_canonical_log();
  assert_eq!(op_head, 10);
  assert_eq!(commit_star, 8);
  assert_eq!(floor_star, 6);
  assert_eq!(
    e.unions_floored(),
    1,
    "this selection's floor dropped carried entries (ops 5,6) — the floored-union witness counts it"
  );
  let present: std::collections::BTreeSet<u64> = log.iter().map(|e| e.op().get()).collect();
  for op in 7..=8u64 {
    assert!(
      present.contains(&op),
      "committed op {op} in (floor* .. commit*], held only by the low-floor donor, must survive the floor"
    );
  }
  assert!(
    !present.contains(&5) && !present.contains(&6),
    "ops at/below floor* are checkpoint-subsumed and do not ride the view change"
  );
  assert!(
    present.contains(&9) && present.contains(&10),
    "the head ops are present"
  );
}

#[test]
fn laggard_adopter_of_a_floored_start_view_trims_its_ancient_band_and_state_syncs_the_gap() {
  // THE LAGGARD-ADOPTER LEG: a low-floor backup adopts a FLOORED canonical log (a StartView whose
  // `checkpoint_op` floor is far above the adopter's applied frontier). Three properties:
  //  (1) BOUNDED LOG: its own ancient applied band is trimmed at the carried floor (it is
  //      checkpoint-subsumed at a canonical donor), so its own next re-emitted carrier is the
  //      adopted band alone — never two bands;
  //  (2) NOT SILENTLY LOST: the sub-floor gap holds the commit, and the next heartbeat-driven
  //      `advance_commit` re-registers the hole and ESCALATES to a forced state-sync targeting the
  //      carried floor (`log_floor`, raised at adoption, feeds `max_peer_checkpoint_op`);
  //  (3) the re-emitted DVC carries exactly the adopted band — the adopter's own carrier stays
  //      frame-bounded.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  // The laggard's own ancient state: applied 1..=6 (commit_min == commit_max == 6), head 6, the
  // band 1..=6 held Present, nothing checkpointed.
  e.commit_min = OpNumber::with(6);
  e.commit_max = OpNumber::with(6);
  e.op = OpNumber::with(6);
  for op in 1..=6u64 {
    e.log.insert(
      op,
      LogEntry::present(
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::copy_from_slice(&op.to_be_bytes()),
      ),
    );
  }
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // The floored canonical StartView from view 1's primary: floor 600, band 601..=605 (head 605,
  // commit 605). The adopter's whole world (1..=6) is below the floor.
  let entries: std::vec::Vec<PreparedEntry> = (601..=605u64)
    .map(|op| {
      PreparedEntry::new(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::copy_from_slice(&op.to_be_bytes()),
      )
    })
    .collect();
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(605),
    OpNumber::with(605),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    entries,
  )
  .with_checkpoint_op(OpNumber::with(600));
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal, "adoption completes");
  // (1) BOUNDED: the ancient band 1..=6 (<= floor 600) is trimmed; only the adopted band remains.
  assert_eq!(
    e.min_log_op(),
    Some(601),
    "the adopter's sub-floor ancient band is trimmed at the carried floor"
  );
  assert_eq!(e.log_len(), 5, "the log is exactly the adopted band");
  // (2a) The gap is HELD, not skipped: nothing above the adopter's applied frontier has applied.
  assert_eq!(
    e.commit(),
    OpNumber::with(6),
    "the commit holds below the sub-floor gap"
  );
  assert_eq!(
    e.commit_max(),
    OpNumber::with(605),
    "the known-committed frontier is learned from the canonical head"
  );
  // Pump the durable-view write (start_view_acks has no uncommitted tail to re-ack here).
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  while e.poll_message().is_some() {}
  // (2b) The ESCAPE engages: a Commit heartbeat re-registers the sub-floor hole and the force-sync
  // escalation fires — its floor includes the adoption-raised `log_floor`, so the hole at op 7
  // (<= 600) escalates to a FORCED sync targeting the carried floor (a snapshot at/above it is
  // vouched to exist at a canonical donor), instead of soliciting an unservable prepare forever.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::Commit(crate::Commit::new(
      View::with(1),
      OpNumber::with(605),
      OpNumber::new(),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert!(
    e.sync_is_forced_for_test(),
    "the sub-floor gap escalates to a FORCED state-sync (not an eternal futile RequestPrepare)"
  );
  assert_eq!(
    e.sync_target_for_test(),
    Some(600),
    "the forced sync targets the carried floor"
  );
  let mut solicited = false;
  while let Some(out) = e.poll_message() {
    if matches!(out.into_msg(), Message::RequestSync(_)) {
      solicited = true;
    }
  }
  assert!(
    solicited,
    "the escalation broadcast a RequestSync for the vouched snapshot"
  );
  // (3) The re-emitted DVC carrier is the adopted band alone — the ancient band does not ride.
  let dvc_entries = e.log_entries();
  assert_eq!(
    dvc_entries.len(),
    5,
    "the re-emitted carrier holds exactly the adopted band (no two-band union)"
  );
  assert!(
    dvc_entries.iter().all(|en| en.op().get() > 600),
    "no sub-floor entry rides the adopter's own carrier"
  );
}

#[test]
fn adopt_canonical_head_keeps_committed_ops_an_offset_canonical_log_omits() {
  // offset-aware gate, CORRECTED to the safe semantics (this is a correctness CORRECTION, not a weakening — see
  // below). A backup holds committed ops 5..=8 in its OFFSET log; the lower band 5,6 it has APPLIED
  // (commit_min == 6), the upper band 7,8 it has NOT (committed by a prior-view quorum but unapplied;
  // op == 8). It adopts a StartView whose canonical log is itself OFFSET, starts at op 9 (does NOT
  // carry 5..=8), commit 8. The two bands are now handled DIFFERENTLY, and that distinction is the fix:
  //
  //   * APPLIED & omitted (5,6, `op <= commit_min`): a committed op the adopter ITSELF applied is
  //     immutable (VSR committed-op survival ⇒ no other view committed a different value), so its local
  //     copy is canonical. It is PRESERVED directly from `self.log` (kept, never re-fetched).
  //   * UNAPPLIED & omitted (7,8, `op in (commit_min, commit]`): the held body is unapplied and may be a
  //     STALE superseded proposal from an earlier view — `LogEntry` has no per-entry view to tell. It is
  //     therefore DROPPED and REPAIRED: `advance_commit` HOLDS the commit at the first such op and
  //     `request_repair`s the CANONICAL value from a committed-vouching peer.
  //
  // Why this is a CORRECTION, not a weakening of the original canonical-log safety property: its invariant is "no
  // committed op an offset canonical log omits is ever LOST." That still holds end-to-end here — the
  // omitted committed band ends up correct (applied to the SM after repair), never silently skipped. The
  // ONLY change is the SOURCE for the UNAPPLIED band: a possibly-stale local copy (which, under an
  // adversarial schedule, can diverge the committed log) is replaced by the quorum's canonical value
  // fetched via peer-repair.
  // The original stranding bug (clearing the whole log + then `repair.clear()` stranding the op) stays fixed:
  // the omitted committed op is never forgotten — it is a held hole until its canonical value arrives.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  // Hand-build the offset-backup state: checkpoint 4, applied through 6 (commit_min == commit_max == 6;
  // the [1..=6] prefix lives in the checkpoint, not the empty CountSm), head 8, offset tail 5..=8 held.
  e.checkpoint_op = OpNumber::with(4);
  e.log_floor = OpNumber::with(4); // the coupling a real checkpoint advance maintains
  e.commit_min = OpNumber::with(6);
  e.commit_max = OpNumber::with(6);
  e.op = OpNumber::with(8);
  for op in 5..=8u64 {
    e.log.insert(
      op,
      LogEntry::present(
        ClientId::new(7),
        RequestNumber::with(op),
        Bytes::copy_from_slice(&op.to_be_bytes()),
      ),
    );
  }
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // The canonical StartView for view 1 from primary 1: an OFFSET log starting at op 9 (head 10),
  // commit 8. It does NOT carry ops 5..=8.
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(10),
    OpNumber::with(8),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(9),
        ClientId::new(7),
        RequestNumber::with(9),
        Bytes::copy_from_slice(&9u64.to_be_bytes()),
      ),
      PreparedEntry::new(
        OpNumber::with(10),
        ClientId::new(7),
        RequestNumber::with(10),
        Bytes::copy_from_slice(&10u64.to_be_bytes()),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal, "adoption completes");
  // APPLIED & omitted (5,6): PRESERVED directly — still in the log cache, never turned into a hole.
  assert!(
    e.log.contains_key(&5) && e.log.contains_key(&6),
    "an omitted committed op the adopter HAS applied is preserved directly from its own log"
  );
  assert!(
    !e.has_repair_hole_for_test(5) && !e.has_repair_hole_for_test(6),
    "the applied-and-preserved ops are not repaired"
  );
  // UNAPPLIED & omitted (7,8): REPAIRED. The commit is HELD at the first (6) until the canonical value
  // arrives; op 7 is a registered hole (op 8 becomes one after 7 fills). The held copy was DROPPED.
  assert_eq!(
    e.commit(),
    OpNumber::with(6),
    "commit is HELD at the unapplied omitted band until the canonical value is repaired"
  );
  assert!(
    e.has_repair_hole_for_test(7) && !e.log.contains_key(&7),
    "the first unapplied omitted committed op (7) is a repair hole, its held body dropped"
  );
  // A committed-vouching peer (commit 8 >= op) supplies the canonical value for the repaired band. Each
  // fill is a durability barrier: the repaired append must complete before the op applies and
  // the NEXT hole (op 8) is registered — so drive each fill to durability in turn.
  for op in [7u64, 8] {
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(1)),
      repair_prepare(1, op, 8),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply + register next hole
  }
  assert_eq!(
    e.commit(),
    OpNumber::with(8),
    "commit reaches 8: the omitted committed band is repaired, not lost (the canonical-log safety property holds)"
  );
  // The SM applied exactly the unapplied band 7,8 (5,6 lived below commit_min, never re-applied; 1..=4
  // in the checkpoint). SAFETY: no committed op the offset StartView omitted was lost.
  let applied: std::vec::Vec<u64> = e.sm.applied().iter().map(|(op, _)| *op).collect();
  assert_eq!(
    applied,
    std::vec![7, 8],
    "the unapplied omitted committed band 7..=8 is repaired to the SM (canonical value, not stale local)"
  );
  assert!(
    e.repair.is_empty(),
    "no committed op is left stranded in the repair set"
  );
}

#[test]
fn adopt_log_does_not_preserve_a_stale_unapplied_held_copy_for_a_committed_op() {
  // SAFETY REGRESSION: the "preserve the omitted committed op from the adopter's
  // own log" rule is only sound for ops the adopter has APPLIED (`op <= commit_min`) — those are
  // committed+immutable. For a committed op in `(commit_min .. adopted_commit]` the adopter holds a
  // body it has NOT applied: it can be a STALE UNCOMMITTED proposal from an earlier view that a later
  // view overwrote with a DIFFERENT committed value (`LogEntry` carries no per-entry view, so the
  // proto cannot tell a canonical-lineage held op from a superseded one). Preserving it diverges the
  // adopter's committed log from the quorum's. The fix: preserve ONLY `op <= commit_min`; the omitted
  // committed band `(commit_min .. adopted_commit]` becomes repair holes whose CANONICAL value is
  // fetched from a committed-vouching peer (commit HELD until then) — never trusted from local.
  //
  // Setup: the adopter holds the two committed ops 5,6 TRANSPOSED (op 5 -> body[6],
  // op 6 -> body[5] — stale superseded proposals), while the cluster committed op 5 -> body[5], op 6
  // -> body[6]. checkpoint == commit_min == 4 (those held bodies are UNAPPLIED), op == 8. The adopted
  // offset StartView (head 10, commit 8) OMITS 5,6 (its log starts at op 7).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(2)).unwrap(),
    genesis(3),
    0,
    CountSm::default(),
  );
  e.checkpoint_op = OpNumber::with(4);
  e.log_floor = OpNumber::with(4); // the coupling a real checkpoint advance maintains
  e.commit_min = OpNumber::with(4);
  e.commit_max = OpNumber::with(4);
  e.op = OpNumber::with(8);
  // The STALE, TRANSPOSED held copies for the (commit_min .. commit] band: op 5 holds op 6's body and
  // vice-versa. (Bodies are single-byte `[op]`, matching `repair_prepare`'s canonical encoding, so the
  // post-repair canonical value `[5]`/`[6]` is provably DIFFERENT from the preserved-stale `[6]`/`[5]`.)
  e.log.insert(
    5,
    LogEntry::present(
      ClientId::new(7),
      RequestNumber::with(5),
      Bytes::copy_from_slice(&[6u8]),
    ),
  );
  e.log.insert(
    6,
    LogEntry::present(
      ClientId::new(7),
      RequestNumber::with(6),
      Bytes::copy_from_slice(&[5u8]),
    ),
  );
  // op 7,8 are also in the (commit_min .. commit] band and OMITTED below; they ride the same repair
  // path. Give the adopter NO held copy for them, so they are pure holes filled only from the peer.
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // The canonical offset StartView for view 1 (head 10, commit 8) starts at op 9 — it OMITS 5,6,7,8.
  let sv = StartView::new(
    View::with(1),
    OpNumber::with(10),
    OpNumber::with(8),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(1),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(9),
        ClientId::new(7),
        RequestNumber::with(9),
        Bytes::copy_from_slice(&[9u8]),
      ),
      PreparedEntry::new(
        OpNumber::with(10),
        ClientId::new(7),
        RequestNumber::with(10),
        Bytes::copy_from_slice(&[10u8]),
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::StartView(sv),
  );
  assert_eq!(e.status(), Status::Normal, "adoption completes");
  // The stale held copies are DROPPED, not preserved: op 5 is a repair hole and the commit is HELD at
  // the first omitted op (4) — never advanced past op 5 with the stale `[6]` body. (Fail-before: the
  // old rule kept 5->[6] and 6->[5], APPLIED both, and commit jumped to 6 — the transposition — before
  // holding at op 7, with NO hole at 5 or 6.)
  assert_eq!(
    e.commit(),
    OpNumber::with(4),
    "commit is HELD at the first omitted committed op (the stale body is not applied)"
  );
  // `advance_commit` registers a hole at the FIRST unfetched committed op (op 5) and HOLDS there —
  // ops 6,7,8 become holes lazily as each fill resumes the apply loop. The decisive safety fact is
  // that op 5's STALE held body `[6]` was DROPPED, so the commit could not advance past it. (Fail-
  // before: the old rule kept 5->[6], 6->[5], applied them, and commit jumped to 6 with NO hole at 5.)
  assert!(
    e.has_repair_hole_for_test(5),
    "the first omitted, unapplied committed op (5) becomes a repair hole (canonical value to be fetched)"
  );
  assert!(
    !e.log.contains_key(&5) && !e.log.contains_key(&6),
    "neither stale transposed body survives in the log cache"
  );
  assert!(
    e.sm.applied().is_empty(),
    "NOTHING is applied yet — no stale transposed body reached the SM"
  );
  // A committed-vouching peer Prepare (commit 8 >= op) supplies the CANONICAL value for each hole in
  // order: op 5 -> body[5], op 6 -> body[6] (the un-transposed quorum values), then op 7,8. Each fill is
  // a durability barrier: once the repaired append is durable the apply loop resumes, which
  // then registers the NEXT hole — so drive each fill to durability in turn.
  for op in [5u64, 6, 7, 8] {
    assert!(
      e.has_repair_hole_for_test(op),
      "op {op} is a registered repair hole before its canonical Prepare arrives"
    );
    e.handle_message(
      now,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(1)),
      repair_prepare(1, op, 8),
    );
    e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the repaired append completes → apply + register next hole
  }
  assert!(
    e.repair.is_empty(),
    "every committed hole is filled from the peer's canonical value"
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(8),
    "commit resumes to 8 once the canonical band is repaired"
  );
  // The applied log matches the QUORUM (op 5 -> [5], op 6 -> [6]) — NOT the adopter's stale transpose.
  // This is the exact equality `check_safety` enforces; fail-before it would be [(5,[6]),(6,[5]),...].
  assert_eq!(
    e.sm.applied(),
    &[
      (5, std::vec![5u8]),
      (6, std::vec![6u8]),
      (7, std::vec![7u8]),
      (8, std::vec![8u8]),
    ],
    "the repaired committed band carries the canonical (un-transposed) quorum values"
  );
}

// ── Nack-counting truncation: a header-only `Repairing` op ABOVE commit* that no canonical donor holds
// `Present` is a repair-OR-truncate candidate. The new primary solicits it AND counts the negative
// answers: a peer that durably LACKS it replies a `Nack`, a holder answers with the `Present` body. A
// `Present` fill KEEPS the op (it was committed after all); once `f+1` DISTINCT voters nack a candidate
// it is provably uncommitted (a commit needs a write-quorum to hold it, and every write-quorum member
// keeps at least a header, so never nacks) and the uncommitted tail is truncated — closing the
// permanent-wedge a genuinely-uncommitted header-only op would cause, while a candidate a second holder
// still vouches (< f+1 nacks) BLOCKS rather than risk truncating a possibly-committed op. ──

#[test]
fn b_uncommitted_repairing_tail_with_no_body_truncates_after_grace_and_progresses() {
  // Liveness (the bug this closes). A new primary adopts an above-commit* header-only `Repairing` op it
  // is the SOLE holder of: the other two voters durably LACK it (one never held it, the other's copy was
  // never durable), so no peer ever answers the RequestPrepare with a body. BEFORE the fix the op is kept
  // forever as an unfillable repair hole → `on_request`'s `!repair.is_empty()` guard drops every client →
  // permanent wedge. AFTER the fix each of the other voters answers the RequestPrepare with a `Nack`;
  // once `f+1` (= 2 of 3) DISTINCT voters have nacked, op 2 is provably uncommitted (> f voters lack it,
  // so no write-quorum ever held it), the uncommitted tail is truncated, the hole clears, and the primary
  // commits a fresh client request.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // Replica 2's DVC: head op 2, commit 1 — op 1 COMMITTED (real body), op 2 an UNCOMMITTED tail
  // (commit* = 1 < 2) carried HEADER-ONLY as a `Repairing` entry. NO canonical donor holds op 2
  // `Present` (the own DVC holds op 0; replica 2 holds it header-only), so op 2 is a truncation candidate.
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // durable-view write → start_view_participate; repair solicit
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2), "op 2's number is taken (head 2)");
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 committed; the body-absent op 2 holds the commit"
  );
  // THE WEDGE (the bug): op 2 is a peer-repair hole, so `on_request` drops every client and the commit
  // can never advance — even with a healthy quorum, because op 2's body exists nowhere.
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is an unfillable repair hole (its body is absent everywhere)"
  );
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  assert!(
    e.poll_message().is_none(),
    "the wedge: the primary drops the client while the unfillable repair hole stands"
  );
  // THE COUNTING PROOF: the two OTHER voters durably lack op 2 and answer its RequestPrepare with a
  // `Nack`. One nack is below the `f+1` quorum, so the candidate still stands (a lone lack does not prove
  // it uncommitted); the second DISTINCT voter's nack reaches `f+1`, proving `> f` voters lack it, so no
  // write-quorum ever held it → truncate.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "one nack is below the f+1 quorum — the candidate is still held + repaired (never truncated early)"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "head unchanged before the nack quorum forms"
  );
  // The second DISTINCT voter's nack reaches f+1 → the candidate is truncated and the tail above it drops.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "the f+1-th distinct-voter nack proves op 2 uncommitted → it is truncated, the hole clears"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the head drops to op 1 (the op below the truncated candidate)"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_none(),
    "the truncated op 2's WAL slot is dropped (no resurrection on a later recover)"
  );
  // The wedge is cleared: the primary serves clients again and commits a FRESH client request at the
  // (now reusable) op number 2 — proving liveness was restored, not a committed op lost.
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the own append lands → own vote
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the primary serves the client again, minting a fresh op 2 (the wedge is gone)"
  );
  // CROSS-OPERATION SAFETY (content-addressed votes): a DELAYED PrepareOk for the OLD truncated op 2 —
  // its FULL identity (client 7, request 2, op2_checksum) — arrives now from a THIRD replica, after op 2
  // was re-minted for client 9's b"x". Counted by op number alone it would form a phantom quorum (own +
  // this) and commit the fresh op 2 on a vote for an operation the primary is NOT driving. It MUST be
  // dropped: its identity is the OLD operation's, not the re-minted one's. (This is the op-reuse
  // vote-confusion class the bounded sim network cannot otherwise reach: a vote outliving its op's
  // truncation + reuse.)
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(ClientId::new(7), RequestNumber::with(2), op2_checksum),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "the delayed vote for the OLD operation is dropped — commit stays at op 1, the fresh op 2 does \
     NOT phantom-commit on an (own + stale) quorum"
  );
  // One backup ack reaches quorum (own + backup) → the fresh op 2 commits.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(0),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(9),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"x"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the fresh client request commits — the primary makes progress again after the truncation"
  );
}

#[test]
fn a_committed_repairing_op_is_kept_when_a_present_holder_answers_within_the_grace() {
  // Safety. A COMMITTED header-only `Repairing` op whose single `Present` donor was partitioned out of
  // the DVC quorum is adopted as an UNCOMMITTED-tail candidate (commit* = 1, no `Present` donor), so it
  // is a repair-or-truncate candidate. A lone laggard even nacks it — but the body HOLDER becomes
  // reachable and answers the RequestPrepare with the `Present` body FIRST. The fill turns the op
  // `Present` (no longer a candidate), drops its nack tally, and the op is KEPT — it was committed after
  // all, and having a holder means it can never reach the `f+1` nack quorum that would truncate it.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(2));
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is repaired (candidate) — grace armed"
  );
  while e.poll_message().is_some() {}
  // A lone laggard nacks op 2 (it durably lacks it) — one nack, below the f+1 quorum, so the candidate
  // still stands but now carries a tally.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    1,
    "the laggard's nack is tallied (below the f+1 quorum, so no truncation yet)"
  );
  // The Present holder becomes reachable and answers the RequestPrepare with op 2's real canonical body
  // (matching the kept checksum). `commit 1 < op 2` is accepted via the kept canonical-checksum path. The
  // fill lands durably → the op is `Present` and its nack tally is dropped (a holder answered).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    repair_prepare(1, 2, 1),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.has_repair_hole_for_test(2),
    "the canonical body filled the hole — op 2 is no longer a candidate"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_present()),
    "op 2's body is now Present (kept — it was committed after all)"
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "the fill dropped op 2's nack tally — a stale nack can never re-fire a truncation on the filled op"
  );
  // A second, third nack now arriving cannot truncate the filled op: it is `Present`, not a candidate, so
  // `on_nack` ignores it. op 2 is KEPT — a `Present` holder vouched its body.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "op 2 is KEPT — a Present holder vouched its body, so it is never truncated"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_present()),
    "op 2 stays Present"
  );
  // It commits on a backup ack (own vote was cast on the durable fill) — proving it was applied, not lost.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      OpNumber::new(),
      crate::storage::prepare_identity(ClientId::new(7), RequestNumber::with(2), op2_checksum),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the kept op 2 commits its canonical value — it was never truncated"
  );
}

#[test]
fn c_committed_repairing_op_kept_across_view_changes_and_repaired_within_the_grace() {
  // Safety. A committed `Repairing` op whose `Present` donor flaps must be KEPT (TAKEN — op_head >= it)
  // across view changes and eventually repaired, NEVER truncated. Two halves:
  //   1. ACROSS VIEW CHANGES: re-run the canonical-log selection for a SECOND view change while the
  //      donor that vouches op 2 committed is collected with laggards — op 2 stays in the canonical log
  //      (op_head >= it), never truncated by the DVC-time nack scan, as the durable-header property requires.
  //   2. AT THE NEW PRIMARY: a new primary that adopts op 2 as a header-only candidate (the donor was
  //      partitioned out of THIS quorum, so commit* < op 2) solicits it; a laggard nacks it (below the
  //      f+1 quorum) but the `Present` holder answers with the body FIRST — the fill keeps op 2 and drops
  //      its tally, so a later nack can never truncate it. A committed op is never truncated because a
  //      holder answers.
  let now = Instant::ZERO;
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);

  // ── Half 1: op 2 stays TAKEN across a SECOND view-change selection. A view-1 donor reports op 2
  // COMMITTED (commit 2) header-only; two laggards (older generation, head op 1) nack op 2. With the
  // committed-frontier DVC present, commit* >= 2, so the nack scan cannot cut op 2. ──
  let committed_donor = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  let mut selector = Endpoint::new(
    Config::try_new(2, MemberId::new(2)).unwrap(),
    genesis(5),
    0,
    NoopSm,
  );
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(2), committed_donor);
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(3), dvc(3, 0, 1, 1)); // laggard, head op 1, nacks op 2
  selector
    .dvc_from_mut_for_test()
    .insert(ReplicaId::new(4), dvc(4, 0, 1, 1)); // laggard, head op 1, nacks op 2
  let (log, op_head, commit_star, _) = selector.select_canonical_log();
  assert!(
    commit_star >= 2 && op_head >= 2,
    "across the second view change the committed op 2 stays in the band (commit* {commit_star}, op_head {op_head}) — never nack-truncated"
  );
  assert!(
    log.iter().any(|e| e.op() == OpNumber::with(2)),
    "op 2 is STILL in the canonical log after the second view change (TAKEN, never re-minted)"
  );

  // ── Half 2: a new primary adopts op 2 as a header-only candidate (commit* = 1 here — the Present
  // donor was partitioned out of THIS quorum), arms the grace, and the holder answers within it. ──
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(2),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![
        PreparedEntry::new(
          OpNumber::with(1),
          ClientId::new(7),
          RequestNumber::with(1),
          bytes::Bytes::from_static(b"a"),
        ),
        PreparedEntry::repairing(
          OpNumber::with(2),
          ClientId::new(7),
          RequestNumber::with(2),
          op2_checksum,
        ),
      ],
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.op(), OpNumber::with(2), "op 2 is TAKEN (head 2)");
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is repaired (an above-commit* candidate)"
  );
  while e.poll_message().is_some() {}
  // A lone laggard nacks op 2 (below the f+1 quorum), then the `Present` holder answers with op 2's real
  // canonical body (kept checksum matches). `commit 1 < op 2` is accepted via the canonical-checksum path.
  // The fill turns op 2 `Present` and drops its nack tally — a holder answered, so it was committed.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    repair_prepare(1, 2, 1),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.has_repair_hole_for_test(2),
    "op 2 is filled (a Present holder answered) — no longer a candidate"
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "the fill dropped op 2's nack tally"
  );
  // A further nack cannot truncate the filled op: it is `Present`, not a candidate, so `on_nack` ignores it.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "op 2 survives view-change churn + a nack — a Present holder answered, so it is never truncated"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_present()),
    "op 2's canonical body is held (repaired, not lost)"
  );
}

#[test]
fn repair_fill_in_flight_across_the_grace_is_never_truncated() {
  // Safety. The repair path is ASYNC: a peer `Prepare` ACCEPTS the canonical body (`fill_repair` stages a
  // `Pending::RepairFill` + marks the op `appending`), but its WAL append completes later. The entry
  // stays `Repairing` (the hole stays open) until `on_wal_done` lands the durable append, so a truncation
  // that re-derived body-absence purely from `self.log` would drop op 2 — a COMMITTED op whose body was
  // FOUND in time. The fix treats a staged/in-flight fill as body-present: `fill_repair`'s acceptance
  // drops op 2's nack tally (a holder answered ⇒ committed) and marks it `appending`, which
  // `is_repair_or_truncate_candidate` excludes — so `on_nack` IGNORES even an `f+1` nack burst arriving
  // while the fill is mid-flight, and op 2 is never truncated.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // Replica 2's DVC: head op 2, commit 1 — op 1 COMMITTED, op 2 an UNCOMMITTED tail (commit* = 1)
  // carried HEADER-ONLY. No canonical donor holds op 2 `Present`, so op 2 is a truncation candidate.
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // durable-view write → repair solicit
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2), "op 2's number is TAKEN (head 2)");
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is a peer-repair hole (an above-commit* candidate)"
  );
  while e.poll_message().is_some() {}
  // A holder answers the RequestPrepare with op 2's REAL canonical body (matching the kept checksum).
  // `fill_repair` ACCEPTS it: it stages a `Pending::RepairFill`, marks op 2 `appending`, and KEEPS the
  // hole `Repairing` until the append is durable. We do NOT drain storage, so the fill is still in flight
  // — the entry is still `Repairing` in `self.log`.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    repair_prepare(1, 2, 1), // commit 1 < op 2: accepted via the kept canonical-checksum path
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "the hole stays OPEN (Repairing) until the staged fill's append is durable"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_repairing()),
    "op 2 is still header-only in the log while its repair fill is in flight"
  );
  // NOW an `f+1` nack burst arrives WHILE the fill is mid-flight (before its append lands). A truncation
  // that re-derived body-absence purely from `self.log` would drop op 2 (still `Repairing` above
  // commit_max) → a committed op whose body was found in time. But the accept marked op 2 `appending`, so
  // `is_repair_or_truncate_candidate` excludes it — `on_nack` records nothing and never truncates.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "op 2 is KEPT — its repair fill was accepted, so an appending op is never a nack candidate"
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "no nack is tallied against the appending (answered) op — the burst is ignored"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2's hole is still open (the fill has not yet landed) — but it was NOT truncated"
  );
  // Drain the in-flight append: the staged canonical body lands durably → op 2 becomes Present, the
  // hole clears, and the primary casts its own vote (append-before-ack). The op was applied, not lost.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.has_repair_hole_for_test(2),
    "the repair hole clears once the staged body lands durably (after the grace)"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_present()),
    "op 2's canonical body is now Present — it was kept + applied, never truncated"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_some(),
    "op 2's durable WAL slot survives (no mid-flight truncation dropped it)"
  );
  // It commits on a backup ack (own vote was cast on the durable fill) — proving it was applied.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(0),
      OpNumber::new(),
      crate::storage::prepare_identity(ClientId::new(7), RequestNumber::with(2), op2_checksum),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the kept op 2 commits its canonical value — the in-flight fill was never truncated"
  );
}

#[test]
fn repair_or_truncate_does_not_fire_in_pending_sb_window() {
  // Safety. While the new-primary view write is still in flight (`pending_sb`), the view is NOT yet
  // durable — a crash would regress out of it, so the primary must NOT yet mutate its tail. `on_nack`
  // self-gates on `participates_as_primary()` (which requires `!pending_durable_view()`), so even an
  // `f+1` nack burst in this window records nothing and truncates nothing; once the view is durable the
  // burst is re-elicited on the ordinary repair cadence and then truncates.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  // Adopt the DVC but DO NOT drain storage: status is Normal-primary but the durable-view write is
  // still in flight (`pending_sb` armed), so op 2 is an above-commit* candidate but the view is not durable.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert!(
    e.pending_sb_for_test(),
    "the new-primary view write is still in flight (non-serviceable window)"
  );
  assert_eq!(e.op(), OpNumber::with(2), "op 2's number is TAKEN (head 2)");
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is a candidate before the view is durable"
  );
  // An `f+1` nack burst while `pending_sb` holds must NOT truncate: `on_nack`'s `participates_as_primary()`
  // gate is false (the view is not durable), so it records nothing and mutates nothing.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "no truncation in the pending_sb window — the head is unchanged"
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "the gate returns BEFORE recording — nothing is tallied while the view is not durable"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_repairing()),
    "op 2 is still held (Repairing) — the non-durable-view window must not mutate the tail"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2's repair hole is untouched in the pending_sb window"
  );
  // Drain the durable-view write (the view becomes durable, `pending_sb` clears). The nacks are
  // re-elicited on the ordinary repair cadence; re-delivering the `f+1` burst now truncates the
  // still-absent candidate — proving the gate suspended (did not permanently reject) the decision.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(!e.pending_sb_for_test(), "the view is now durable");
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "once the view is durable the f+1 nacks truncate the candidate — the head lowers"
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "the candidate is truncated once the view is durable and the nack quorum re-forms"
  );
}

#[test]
fn repair_or_truncate_does_not_fire_in_pending_forfeit_window() {
  // Safety. An `f+1` nack burst must NOT truncate while the primary is stepping down (`pending_forfeit`):
  // `on_nack` self-gates on `!pending_forfeit`, so it records nothing and mutates nothing in this window.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  // Make the view durable (clears `pending_sb`), so the ONLY non-serviceable cause under test is the
  // forfeit latch — the candidate persists.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert!(!e.pending_sb_for_test(), "the view is durable");
  assert!(e.has_repair_hole_for_test(2), "op 2 is a candidate");
  // Latch a deferred forfeit (the step-down a primary raises off the force-sync/sync-checkpoint strand).
  e.defer_forfeit_for_test(now);
  assert!(
    e.pending_forfeit_for_test(),
    "the primary is stepping down (pending_forfeit latched)"
  );
  // An `f+1` nack burst must NOT truncate while stepping down: `on_nack`'s `!pending_forfeit` gate is hit.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "no truncation in the pending_forfeit window — the head is unchanged"
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "the `!pending_forfeit` gate returns BEFORE recording — nothing is tallied while stepping down"
  );
  assert!(
    e.log.get(&2).is_some_and(|x| x.body.is_repairing()),
    "op 2 is still held (Repairing) — a stepping-down primary must not mutate the tail"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2's repair hole is untouched in the pending_forfeit window: a truncation would have removed op 2 \
     from the log and lowered the head"
  );
}

#[test]
fn uncommitted_candidate_does_not_forfeit_and_truncation_fires_on_the_nack_quorum() {
  // Liveness. A new primary `request_repair`s the above-commit* repair-or-truncate candidate, putting it
  // in `self.repair`. The forfeit path treats a non-empty `repair` as a stuck COMMITTED hole and would
  // latch `pending_forfeit` after the FORFEIT_GRACE (300ms) — and a forfeiting primary refuses to
  // truncate (`on_nack`'s `!pending_forfeit` gate), so the wedge would persist. The forfeit "stuck
  // committed hole" condition is restricted to `repair` ops `<= commit_max`, so an above-commit*
  // candidate never latches `pending_forfeit` no matter how long it stands; the candidate is instead
  // resolved by the counting proof — an `f+1` distinct-voter nack quorum truncates it (progress
  // restored) WITHOUT the primary ever forfeiting.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  while e.poll_message().is_some() {}
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // make the view durable
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2), "op 2's number is TAKEN (head 2)");
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is an uncommitted candidate (above commit_max) in self.repair"
  );
  // No peer answers the RequestPrepare, so the candidate stands. Advance virtual time well past
  // 2×FORFEIT_GRACE (300ms), firing the Normal-primary heartbeat each step: the candidate is
  // `> commit_max`, so it must NEVER arm the forfeit grace nor latch `pending_forfeit` — a forfeit would
  // wedge the cluster (a forfeiting primary refuses to truncate, and a solo-view-change primary cannot
  // fail over).
  let mut clock = now;
  for _ in 0..8 {
    clock = clock + core::time::Duration::from_millis(200);
    e.handle_timeout(clock, &mut wal, &mut sb, &mut blocks);
    e.handle_storage(clock, &mut wal, &mut sb, &mut blocks);
    while e.poll_message().is_some() {}
    assert!(
      !e.forfeit_armed_for_test(),
      "the forfeit grace must NEVER arm on an above-commit* candidate"
    );
    assert!(
      !e.pending_forfeit_for_test(),
      "the above-commit* candidate must NEVER latch pending_forfeit (it is resolved by truncation)"
    );
  }
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 still stands after 2×FORFEIT_GRACE — no timer truncates it, and it never forfeited"
  );
  // The counting proof resolves it: `f+1` distinct voters nack op 2 (no timer involved) → truncated,
  // the head lowers, progress is restored, and `pending_forfeit` was NEVER latched.
  e.handle_message(
    clock,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    clock,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the head drops to op 1 — the uncommitted candidate was truncated on the nack quorum"
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "the repair hole clears (truncated, not forfeited)"
  );
  assert!(
    !e.pending_forfeit_for_test(),
    "the candidate was resolved by truncation — the primary never forfeited"
  );
  use crate::Wal as _;
  assert!(
    wal.header(OpNumber::with(2)).is_none(),
    "the truncated op 2's WAL slot is dropped"
  );
}

#[test]
fn repair_tail_truncation_clears_inflight_for_a_higher_suffix_op() {
  // Safety (repair-tail truncation leaves stale per-op side state). The truncation drops the WHOLE
  // suffix `[gap ..= head]`, but a HIGHER op in that suffix can legitimately have an in-flight
  // `Pending::RepairFill` (a peer answered its repair OUT OF ORDER) while the LOWER `gap` candidate is
  // still body-absent. Before the fix the truncation dropped `log`/`repair`/`inflight` for the suffix but
  // NOT `pending`/`appending`, so the higher op's stale append lingered: the WAL completion was still
  // queued, and on delivery `on_wal_done`'s `RepairFill` arm RESURRECTED the truncated op back into
  // `self.log` ABOVE the lowered `self.op` — and meanwhile `appending` stayed set, so
  // `has_inflight_storage()` was permanently true (a stuck in-flight that never drains).
  //
  // Shape: a new primary of view 1 adopts op 1 COMMITTED (commit* = 1) + ops 2 AND 3 header-only
  // (`Repairing`), neither held `Present` by any canonical donor. Both become above-commit* candidates
  // and are solicited. A holder then answers op 3's RequestPrepare OUT OF ORDER (op 2 stays absent), so
  // `fill_repair` stages a `Pending::RepairFill` for op 3 and marks it `appending` — but op 2 is still a
  // candidate. An `f+1` nack quorum then forms on op 2: the gap is op 2 (op 3 is excluded by
  // `appending`), so the suffix `[2 ..= 3]` truncates while op 3's RepairFill append is STILL IN FLIGHT.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let op3_checksum = crate::storage::fnv1a_128(&[3u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(3),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(7),
        RequestNumber::with(2),
        op2_checksum,
      ),
      PreparedEntry::repairing(
        OpNumber::with(3),
        ClientId::new(7),
        RequestNumber::with(3),
        op3_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // durable-view write → solicit ops 2 + 3
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(3), "head 3 (ops 2 + 3 taken)");
  assert!(e.has_repair_hole_for_test(2) && e.has_repair_hole_for_test(3));
  while e.poll_message().is_some() {}
  // Drain the storage queue so the ONLY outstanding WAL completion is op 3's RepairFill append. (The
  // adoption staged no AdoptVote append for the header-only ops 2 + 3 — there is no body to write.)
  while wal.poll().is_some() {}

  // A holder answers op 3's RequestPrepare OUT OF ORDER (op 2 stays absent). `fill_repair` ACCEPTS it
  // (kept canonical checksum matches), stages a `Pending::RepairFill` for op 3, and marks op 3
  // `appending` — the hole stays open until the append is durable. We do NOT drain storage, so the fill
  // is in flight. op 2 is still a candidate.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    repair_prepare(1, 3, 1), // commit 1 < op 3: accepted via the kept canonical-checksum path
  );
  assert!(
    e.has_inflight_storage(),
    "op 3's RepairFill append is genuinely in flight before the truncation"
  );
  assert!(
    e.log.get(&3).is_some_and(|x| x.body.is_repairing()),
    "op 3 stays header-only while its repair fill is in flight"
  );

  // `f+1` distinct voters nack op 2 (the only remaining candidate — op 3 is `appending`, excluded). The
  // gap is op 2, so the suffix `[2 ..= 3]` truncates — INCLUDING op 3, whose RepairFill is still in flight.
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the head drops to op 1 — the whole body-absent suffix [2..=3] is truncated"
  );
  assert!(
    !e.has_repair_hole_for_test(2) && !e.has_repair_hole_for_test(3),
    "both suffix repair holes are cleared by the truncation"
  );
  // FAIL-BEFORE: the truncation left op 3's `Pending::RepairFill` + `appending` membership behind, so a
  // permanently-stuck in-flight append remained. AFTER the fix the suffix `pending`/`appending` is
  // cleared too, so no in-flight storage lingers.
  assert!(
    !e.has_inflight_storage(),
    "no stuck in-flight append survives the truncation \
     (FAIL-BEFORE: op 3's RepairFill/appending lingered → has_inflight_storage stayed true forever)"
  );

  // The WAL completion for op 3's now-abandoned append is STILL queued (it was staged before the
  // truncation). Delivering it must NOT resurrect op 3 into `self.log` above the lowered `self.op`, nor
  // cast any vote/commit — the abandoned completion finds no `pending` entry and is a no-op.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks);
  assert!(
    !e.has_log_entry_for_test(3),
    "the abandoned RepairFill completion does NOT resurrect op 3 into self.log above self.op \
     (FAIL-BEFORE: on_wal_done's RepairFill arm re-inserted the truncated op 3 above the head)"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the head stays at op 1 — no resurrection raised it"
  );
  assert!(
    !e.has_inflight_storage(),
    "still no in-flight storage after the stale completion is drained"
  );

  // Liveness restored: the primary serves a FRESH client request, minting the now-reusable op 2, and
  // commits it on a backup ack — proving the truncation cleaned up fully (no phantom vote, no stuck op).
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the own append lands → own vote
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the primary mints a fresh op 2 (the wedge is gone, the slot is reusable)"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(0),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(9),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"x"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "the fresh request commits — progress is fully restored after the suffix truncation"
  );
}

#[test]
fn repair_tail_truncation_lets_a_truncated_clients_retry_be_processed_fresh() {
  // Liveness (repair-tail truncation leaves a stale client session watermark). New-primary adoption
  // backfilled the client-session request high-water from the adopted in-memory log tail, INCLUDING an
  // UNCOMMITTED header-only (`Repairing`) tail op. After the nack quorum truncates that op the op is
  // gone, but the seeded watermark remained with NO cached reply — so the client's ORIGINAL retry of that
  // request hit `on_request`'s dedup as a duplicate, found no cached reply, and was silently dropped →
  // the client hangs forever. The fix rolls the watermark back on truncation (and seeds it only on APPLY
  // of a committed op), so a truncated uncommitted request leaves no phantom watermark and the client's
  // retry is processed fresh.
  //
  // Shape: op 1 COMMITTED for client 7 (request 1); op 2 an UNCOMMITTED header-only `Repairing` tail op
  // whose ONLY client is client 9 (request 1) — it exists nowhere `Present`, so no peer answers with a
  // body; the two other voters nack it, and the `f+1` quorum truncates it. Client 9's request 1 lived
  // ONLY in the truncated op 2.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // op 2's canonical body is client 9 / request 1 / body [2]; carried header-only as `Repairing`.
  let op2_checksum = crate::storage::fnv1a_128(&[2u8]);
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(2),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![
      PreparedEntry::new(
        OpNumber::with(1),
        ClientId::new(7),
        RequestNumber::with(1),
        bytes::Bytes::from_static(b"a"),
      ),
      PreparedEntry::repairing(
        OpNumber::with(2),
        ClientId::new(9), // op 2's only client is client 9
        RequestNumber::with(1),
        op2_checksum,
      ),
    ],
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // make the view durable
  assert_eq!(e.status(), Status::Normal);
  assert!(e.is_primary());
  assert_eq!(e.op(), OpNumber::with(2), "op 2's number is TAKEN (head 2)");
  assert!(
    e.has_repair_hole_for_test(2),
    "op 2 is an above-commit* candidate"
  );
  // Adoption seeds client 9's watermark from the adopted in-memory tail (op 2 is `Present`-or-header in
  // `self.log`, so the backfill loop advances `clients[9].request` to 1). That seeding is correct for an
  // op that will commit, but op 2's body is absent and the nack quorum will truncate it — so the watermark
  // MUST be rolled back when the op is dropped (asserted after the truncation below).
  assert_eq!(
    e.session_request_for_test(9),
    Some(1),
    "adoption seeded client 9's watermark from the adopted tail op 2 (it is rolled back on truncation)"
  );

  // No holder answers op 2's RequestPrepare; the two other voters nack it → the `f+1` quorum truncates
  // the body-absent op 2.
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(1),
    "the body-absent op 2 is truncated (head drops to op 1)"
  );
  assert!(!e.has_repair_hole_for_test(2), "the repair hole clears");
  // The truncation ROLLED BACK client 9's stale watermark (its only request lived in the truncated op 2,
  // and no reply was cached for it). FAIL-BEFORE: the watermark stayed at 1, so the retry below deduped.
  assert!(
    e.session_request_for_test(9).is_none_or(|r| r == 0),
    "client 9's watermark is rolled back to 0 after its only op (op 2) is truncated \
     (FAIL-BEFORE: it stayed at request 1, so the client's retry was deduped to a no-reply hang)"
  );

  // Client 9's ORIGINAL request 1 (the one that lived only in the truncated op 2) is RETRIED. It must
  // be processed FRESH — minted as a new op and broadcast as a Prepare — NOT silently dropped as a
  // duplicate of a phantom watermark with no cached reply.
  while e.poll_message().is_some() {}
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Client(ClientId::new(9)),
    Message::Request(Request::new(
      ClientId::new(9),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "client 9's retry is processed fresh — a new op 2 is minted \
     (FAIL-BEFORE: the phantom watermark made it a duplicate, so no op was minted and the client hung)"
  );
  let prepared = e.poll_message().expect(
    "the retried request is broadcast as a Prepare (processed fresh, not dropped as a duplicate)",
  );
  match prepared.into_msg() {
    Message::Prepare(p) => {
      assert_eq!(
        p.op(),
        OpNumber::with(2),
        "the fresh op 2 carries client 9's request"
      );
      assert_eq!(p.client(), ClientId::new(9));
      assert_eq!(p.request(), RequestNumber::with(1));
    }
    other => panic!("expected a Prepare for the re-minted request, got {other:?}"),
  }
  // And it commits on a backup ack — the client gets a reply, proving the hang is gone.
  e.handle_storage(now, &mut wal, &mut sb, &mut blocks); // the own append lands → own vote
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(2),
      ReplicaId::new(0),
      OpNumber::new(),
      crate::storage::prepare_identity(
        ClientId::new(9),
        RequestNumber::with(1),
        crate::storage::fnv1a_128(b"x"),
      ),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.commit(),
    OpNumber::with(2),
    "client 9's retried request commits — it was processed fresh, never hung"
  );
}

// ── `on_nack` admission + the f+1 counting gate: only a DISTINCT CURRENT-VOTER's durable lack of a
// still-open candidate counts, and the tail truncates exactly when the tally reaches `quorum_nack_prepare`
// (= f+1). ──

#[test]
fn on_nack_truncates_at_the_f_plus_one_voter_quorum() {
  // The counting gate directly (n=3, quorum_nack_prepare = f+1 = 2). A new primary holds a sole-holder
  // above-commit* `Repairing` candidate. One voter's nack is below the quorum — the candidate stands; the
  // second DISTINCT voter's nack reaches f+1, proving > f voters lack it, so it is truncated.
  let (mut e, mut wal, mut sb, mut blocks) = new_primary_with_op2_candidate(genesis(3));
  let now = Instant::ZERO;
  assert!(e.has_repair_hole_for_test(2), "op 2 is the candidate");
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert_eq!(e.nack_voters_for_test(2), 1, "one voter nack is tallied");
  assert!(
    e.has_repair_hole_for_test(2),
    "one nack is below f+1 — the candidate is NOT truncated"
  );
  assert_eq!(e.op(), OpNumber::with(2), "head unchanged below the quorum");
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "the f+1-th distinct-voter nack truncates the candidate"
  );
  assert_eq!(e.op(), OpNumber::with(1), "the head drops to op 1");
}

#[test]
fn a_stale_nack_from_a_superseded_generation_is_not_counted() {
  // A nack echoes the generation of the `RequestPrepare` it answers, and the primary counts a nack only
  // against its CURRENT solicitation. A voter that nacked a candidate, then repaired the op and joined its
  // write-quorum, stops nacking the next round — so its earlier nack (a superseded generation) MUST NOT
  // linger in the tally as a stale durable-lack claim, or a since-committed op could reach the quorum.
  let (mut e, mut wal, mut sb, mut blocks) = new_primary_with_op2_candidate(genesis(3));
  let now = Instant::ZERO;
  let stale_gen = e.solicit_gen_for_test();
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(stale_gen, 1, 2, 0),
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    1,
    "the current-generation nack tallies"
  );

  // A repair round opens: the generation bumps and the tally clears (the candidate is re-solicited afresh).
  let later = now + core::time::Duration::from_millis(500);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
  assert!(
    e.solicit_gen_for_test() > stale_gen,
    "the repair round bumped the solicitation generation"
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "the tally cleared for the new round"
  );

  // The two voters' ORIGINAL nacks (the superseded generation) arrive late — both dropped, so the quorum is
  // never reached on stale evidence.
  for r in [0u16, 2] {
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(r)),
      nack(stale_gen, 1, 2, r),
    );
  }
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "stale-generation nacks are dropped — never counted toward the truncation quorum"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "so the candidate is not truncated by stale nacks"
  );

  // Fresh nacks at the CURRENT generation from f+1 distinct voters DO truncate — liveness is intact.
  let fresh_gen = e.solicit_gen_for_test();
  for r in [0u16, 2] {
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(r)),
      nack(fresh_gen, 1, 2, r),
    );
  }
  assert!(
    !e.has_repair_hole_for_test(2),
    "f+1 current-generation nacks truncate the candidate"
  );
}

#[test]
fn a_lost_first_request_prepare_still_gathers_nacks_and_truncates() {
  // The repair retry re-emits a PER-OP `RequestPrepare` for each candidate (not only the committed-band
  // range serve), so a dropped first solicit or first nack is re-elicited and the truncate-or-repair
  // decision keeps making progress. Here the initial solicitation's nacks never arrive; the retry round
  // re-solicits, and the f+1 nacks it gathers truncate the genuinely-uncommitted candidate.
  let (mut e, mut wal, mut sb, mut blocks) = new_primary_with_op2_candidate(genesis(3));
  let now = Instant::ZERO;
  assert!(e.has_repair_hole_for_test(2), "op 2 is the candidate");
  let later = now + core::time::Duration::from_millis(500);
  e.handle_timeout(later, &mut wal, &mut sb, &mut blocks);
  let current_gen = e.solicit_gen_for_test();
  for r in [0u16, 2] {
    e.handle_message(
      later,
      &mut wal,
      &mut sb,
      &mut blocks,
      Peer::Replica(ReplicaId::new(r)),
      nack(current_gen, 1, 2, r),
    );
  }
  assert!(
    !e.has_repair_hole_for_test(2),
    "the retry re-elicited nacks and the f+1 quorum truncated the candidate"
  );
  assert_eq!(e.op(), OpNumber::with(1), "the uncommitted tail is dropped");
}

#[test]
fn on_nack_ignores_a_non_voter_nack() {
  // A learner holds no write-quorum, so its durable lack is irrelevant to the counting proof: `on_nack`
  // filters it (`is_voter`). Config n=3 + 1 learner (slot 3). The learner's nack is never tallied, so the
  // candidate needs f+1 DISTINCT VOTERS to truncate — proving the learner never counted.
  let (mut e, mut wal, mut sb, mut blocks) =
    new_primary_with_op2_candidate(genesis_with_learners(3, 1));
  let now = Instant::ZERO;
  assert!(e.has_repair_hole_for_test(2), "op 2 is the candidate");
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(3)), // the learner
    nack(e.solicit_gen_for_test(), 1, 2, 3),
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    0,
    "the learner's nack is not tallied (a non-voter holds no write-quorum)"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)), // a voter
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert_eq!(e.nack_voters_for_test(2), 1, "only the voter is tallied");
  assert!(
    e.has_repair_hole_for_test(2),
    "one voter (plus the ignored learner) is below f+1 — NOT truncated"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)), // a second voter
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "two DISTINCT voters (the learner never counted) reach f+1 → truncated"
  );
}

#[test]
fn on_nack_ignores_a_nack_for_a_committed_op() {
  // A nack for an op at/below `commit_max` is not a repair-or-truncate candidate (a committed op is never
  // truncated), so `on_nack` drops it before recording. Feeding f+1 nacks for the committed op 1 records
  // nothing and truncates nothing.
  let (mut e, mut wal, mut sb, mut blocks) = new_primary_with_op2_candidate(genesis(3));
  let now = Instant::ZERO;
  assert_eq!(
    e.commit(),
    OpNumber::with(1),
    "op 1 is committed (commit_max = 1)"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 1, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 1, 2),
  );
  assert_eq!(
    e.nack_voters_for_test(1),
    0,
    "a committed op accrues no nack tally (it is not a candidate)"
  );
  assert_eq!(
    e.op(),
    OpNumber::with(2),
    "the head is unchanged — a committed op is never truncated"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "the genuine candidate op 2 is untouched by nacks aimed at op 1"
  );
}

#[test]
fn on_nack_counts_a_repeated_member_once() {
  // The tally is a MemberId-keyed set, so a member nacking the same op twice counts ONCE — f+1 requires
  // f+1 DISTINCT members. Voter 0 nacks op 2 twice (tally size 1, below f+1); a second DISTINCT voter then
  // reaches f+1 and truncates.
  let (mut e, mut wal, mut sb, mut blocks) = new_primary_with_op2_candidate(genesis(3));
  let now = Instant::ZERO;
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)), // the SAME member again
    nack(e.solicit_gen_for_test(), 1, 2, 0),
  );
  assert_eq!(
    e.nack_voters_for_test(2),
    1,
    "a repeated member counts once (the tally is a MemberId-keyed set)"
  );
  assert!(
    e.has_repair_hole_for_test(2),
    "one distinct voter is below f+1 — NOT truncated"
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    nack(e.solicit_gen_for_test(), 1, 2, 2),
  );
  assert!(
    !e.has_repair_hole_for_test(2),
    "the second DISTINCT voter reaches f+1 → truncated"
  );
  assert_eq!(e.op(), OpNumber::with(1), "the head drops to op 1");
}

// ── Frame-fit: the header-only view-change carriers + the byte-bounded RepairBatch serve stay
// under the transport frame cap regardless of body size (the symptom oracle for the header-only
// carriers — a full-body carrier of the same band would overflow the frame by many MiB). ──

#[test]
fn large_bodied_view_change_carriers_and_repair_serve_fit_the_frame() {
  use crate::message::{MAX_FRAME_LEN, PER_HEADER_ENTRY_BYTES, present_entry_encoded_len};

  let cap = MAX_FRAME_LEN as usize;
  // A fixture log of several ops, EACH with a body near half the frame cap. A full-body carrier of
  // this band would be ~8 * 8 MiB = ~64 MiB — many times the 16 MiB frame — so the header-only
  // carriers are the only thing that keeps it deliverable.
  const ENTRIES: u64 = 8;
  let big = cap / 2;
  let body = bytes::Bytes::from(std::vec![0xABu8; big]);

  // A Normal primary (replica 0 of 3) holding the band Present in its in-memory log, applied through
  // its head — exactly the state a primary serves a DoViewChange / StartView / RepairBatch from.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  e.view = View::with(1);
  e.log_view = View::with(1);
  e.op = OpNumber::with(ENTRIES);
  e.commit_min = OpNumber::with(ENTRIES);
  e.commit_max = OpNumber::with(ENTRIES);
  for op in 1..=ENTRIES {
    e.log.insert(
      op,
      LogEntry::present(ClientId::new(7), RequestNumber::with(op), body.clone()),
    );
  }

  // The REAL header-only carriers built through the production `log_entries()` (every entry emitted
  // `Repairing`, body bytes dropped). Each entry is a fixed `PER_HEADER_ENTRY_BYTES` regardless of
  // the op's body, so the whole band is ~`ENTRIES * 49 + carrier framing` — a few hundred bytes.
  let entries = e.log_entries();
  assert_eq!(entries.len() as u64, ENTRIES);
  assert!(
    entries.iter().all(|x| x.is_repairing()),
    "log_entries() must carry every op header-only"
  );
  let dvc = Message::DoViewChange(crate::DoViewChange::new(
    View::with(1),
    View::with(1),
    OpNumber::with(ENTRIES),
    OpNumber::with(ENTRIES),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    e.log_entries(),
  ));
  let sv = Message::StartView(StartView::new(
    View::with(1),
    OpNumber::with(ENTRIES),
    OpNumber::with(ENTRIES),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    e.log_entries(),
  ));
  let rr = Message::RecoveryResponse(crate::RecoveryResponse::new(
    View::with(1),
    OpNumber::with(ENTRIES),
    OpNumber::with(ENTRIES),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    0xC0FFEE,
    e.log_entries(),
  ));

  // Each header-only carrier encodes far under the frame cap — and at a SIZE INDEPENDENT of body
  // size: it is bounded by the fixed per-header-entry geometry, NOT the (~8 MiB each) bodies.
  let header_band = ENTRIES as usize * PER_HEADER_ENTRY_BYTES;
  for m in [&dvc, &sv, &rr] {
    let n = m.encode().len();
    assert!(
      n <= cap,
      "header-only {} must fit the frame cap: {n} > {cap}",
      m.kind_str()
    );
    // ~fixed carrier framing + header_band, NOT the multi-MiB bodies. A generous bound that a
    // full-body re-encoding (which would be > the cap) could never satisfy.
    assert!(
      n < header_band + 1024,
      "{} is body-size-insensitive (header-only): {n} should be ~{header_band} + framing",
      m.kind_str()
    );
  }
  // The converse, in-line: a FULL-body carrier of the SAME band would overflow the frame by many
  // MiB — exactly the overflow the header-only carriers exist to prevent. Build the same
  // DoViewChange but with `Present` bodies and show it exceeds the cap.
  let full_body_dvc = Message::DoViewChange(crate::DoViewChange::new(
    View::with(1),
    View::with(1),
    OpNumber::with(ENTRIES),
    OpNumber::with(ENTRIES),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    (1..=ENTRIES)
      .map(|op| {
        PreparedEntry::new(
          OpNumber::with(op),
          ClientId::new(7),
          RequestNumber::with(op),
          body.clone(),
        )
      })
      .collect(),
  ));
  assert!(
    full_body_dvc.encode().len() > cap,
    "a full-body DoViewChange of the same band MUST exceed the frame cap (the old, fixed bug)"
  );

  // The RepairBatch serve path: the windowed peer-repair answer is THE body carrier. Drive the
  // real `on_request_prepare_range` over the whole large-bodied run and assert the produced batch is
  // a BYTE-BOUNDED PREFIX under the frame cap that still makes forward progress (serves >= the first
  // op). The serve self-gates on `Normal` + a durable view (`pending_sb.is_none()`); this endpoint is
  // `Normal` with no view write in flight.
  let now = Instant::ZERO;
  e.on_request_prepare_range(
    now,
    Peer::Replica(ReplicaId::new(1)),
    crate::RequestPrepareRange::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(ENTRIES),
      ReplicaId::new(1),
      0,
    ),
  );
  let out = e
    .poll_message()
    .expect("the holder serves a RepairBatch for the solicited run");
  let batch = match out.into_msg() {
    Message::RepairBatch(b) => b,
    other => panic!("expected a RepairBatch serve, got {other:?}"),
  };
  assert_eq!(
    e.repair_batches_served(),
    1,
    "the non-empty serve is counted (the bulk-repair non-vacuity witness)"
  );
  let served = batch.log_slice().len();
  assert!(
    served >= 1,
    "the byte-bounded serve must make forward progress — serve at least the first op"
  );
  // With each body ~half the frame, only the first op fits the per-frame budget (a second would
  // push the running size past the cap), so the served prefix is strictly shorter than the run.
  assert!(
    (served as u64) < ENTRIES,
    "a large-bodied run is served as a strict PREFIX, not the whole run (served={served})"
  );
  let encoded = Message::RepairBatch(batch.clone()).encode().len();
  assert!(
    encoded <= cap,
    "the served RepairBatch must fit the frame cap: {encoded} > {cap}"
  );
  // The served prefix sits within a frame of the first served op's body — the byte-bounded budget at
  // work (a single max-ish body plus framing, never the unbounded multi-op run).
  assert!(
    encoded <= present_entry_encoded_len(big) + 1024,
    "the serve is byte-bounded to ~one body + framing, not the whole run: {encoded}"
  );
}

// ── Serve-side window bound: `on_request_prepare_range` clamps the (untrusted) decoded `hi` to the
// SAME window the requester solicits, so a buggy authenticated peer sending `hi:u64::MAX` against a
// high-`self.op` sparse log forces only a `REPAIR_WINDOW`-bounded, frame-bounded answer — never
// O(self.op) work nor an over-cap batch. ──

#[test]
fn repair_range_serve_clamps_a_huge_hi_to_the_window_against_a_sparse_high_op_log() {
  use crate::message::MAX_FRAME_LEN;

  let cap = MAX_FRAME_LEN as usize;
  // A Normal primary (replica 0 of 3) with a HIGH head but a SPARSE log: it holds only a handful of
  // Present ops at the low end of a `RequestPrepareRange`, then nothing for the (vast) remainder of a
  // `u64::MAX` claimed run. A numeric `lo..=hi` walk would iterate billions of absent ops; the
  // window clamp + `self.log.range` make the cost the present entries within one window only.
  let head: u64 = 1_000_000;
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  e.view = View::with(1);
  e.log_view = View::with(1);
  e.op = OpNumber::with(head);
  e.commit_min = OpNumber::with(head);
  e.commit_max = OpNumber::with(head);
  // Present ops only at `[lo, lo+SPARSE)` — a sparse low-end prefix of the solicited run; every other
  // slot (including the whole window's tail and the billions above it) is a hole we do not hold.
  let lo: u64 = 100;
  const SPARSE: u64 = 5;
  let body = bytes::Bytes::from(std::vec![0x33u8; 4096]);
  for op in lo..lo + SPARSE {
    e.log.insert(
      op,
      LogEntry::present(ClientId::new(7), RequestNumber::with(op), body.clone()),
    );
  }
  // Also seed a Present op just ABOVE the window top: if the serve walked the requester's claimed
  // `hi` (or even `self.op`) instead of the window, it could pull this op into the batch — it must NOT
  // (a request for `[lo, lo+REPAIR_WINDOW)` is answered only within that window).
  let above_window = lo + REPAIR_WINDOW + 10;
  e.log.insert(
    above_window,
    LogEntry::present(
      ClientId::new(7),
      RequestNumber::with(above_window),
      body.clone(),
    ),
  );

  // Solicit with a MALICIOUSLY-HUGE `hi` (`u64::MAX`) — the untrusted decoded top.
  let now = Instant::ZERO;
  e.on_request_prepare_range(
    now,
    Peer::Replica(ReplicaId::new(1)),
    crate::RequestPrepareRange::new(
      View::with(1),
      OpNumber::with(lo),
      OpNumber::with(u64::MAX),
      ReplicaId::new(1),
      0,
    ),
  );
  let out = e
    .poll_message()
    .expect("the holder serves a RepairBatch for the solicited low-end prefix");
  let batch = match out.into_msg() {
    Message::RepairBatch(b) => b,
    other => panic!("expected a RepairBatch serve, got {other:?}"),
  };
  // Only the sparse low-end ops are served: the window-clamped scan never reached the op above the
  // window (nor the billions of phantom ops up to the claimed `u64::MAX` head).
  let served_ops: std::vec::Vec<u64> = batch.log_slice().iter().map(|e| e.op().get()).collect();
  assert_eq!(
    served_ops,
    (lo..lo + SPARSE).collect::<std::vec::Vec<_>>(),
    "the serve is bounded to the present ops WITHIN the window, not the claimed huge run"
  );
  assert!(
    served_ops.iter().all(|&op| op < lo + REPAIR_WINDOW),
    "no served op may lie at/above the window top {} (the op above the window must be excluded)",
    lo + REPAIR_WINDOW
  );
  // And the produced batch is frame-bounded regardless of the huge claimed `hi`.
  let encoded = Message::RepairBatch(batch).encode().len();
  assert!(
    encoded <= cap,
    "the window-bounded serve must fit the frame cap even for a u64::MAX hi: {encoded} > {cap}"
  );
}

// ── Sender-binding at ingress: a message's self-claimed sender must agree with the
// authenticated `from`, or it is dropped. A non-Byzantine, cheap defense-in-depth backstop against a
// buggy/misrouting driver (or a trivially-mislabeled message) spoofing a quorum vote. ──

#[test]
fn new_primary_session_backfill_over_a_floored_log_matches_the_dense_scan() {
  // The new primary's session-watermark backfill iterates the RETAINED log (only held entries
  // contribute — an absent op adds nothing), so over a high-floor canonical log it must produce
  // exactly the table a dense `1..=op` probe of the same log would: the held band's per-client
  // request maxima, and nothing else.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  // Into ViewChange for view 1 (replica 1 is its primary): the idle timeout proposes, r0's SVC
  // completes the quorum.
  e.handle_timeout(
    now + core::time::Duration::from_millis(300),
    &mut wal,
    &mut sb,
    &mut blocks,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::ViewChange);
  while e.poll_message().is_some() {}
  // r2's DVC: a FLOORED canonical log — vouched checkpoint floor 10_000, holding ONLY ops
  // 10_001..=10_005 (two clients alternating, request == op), commit 10_002. Everything below the
  // floor is checkpoint-subsumed at the donor and rides no carrier.
  let log: std::vec::Vec<PreparedEntry> = (10_001..=10_005u64)
    .map(|op| {
      PreparedEntry::new(
        OpNumber::with(op),
        ClientId::new(1 + (op as u128 % 2)),
        RequestNumber::with(op),
        Bytes::copy_from_slice(&op.to_be_bytes()),
      )
    })
    .collect();
  let dvc = DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(10_005),
    OpNumber::with(10_002),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    log,
  )
  .with_checkpoint_op(OpNumber::with(10_000));
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::DoViewChange(dvc),
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "the new primary formed the view"
  );
  assert!(e.is_primary());
  assert_eq!(
    e.op(),
    OpNumber::with(10_005),
    "the floored head is adopted"
  );
  assert_eq!(
    e.min_log_op(),
    Some(10_001),
    "nothing below the floor is held"
  );
  // The ORACLE: the dense numeric probe over `1..=op` of the SAME post-adoption log (`get` is
  // `None` for every op below the floor, so only the held band contributes).
  let mut expected: BTreeMap<u128, u64> = BTreeMap::new();
  for op in 1..=e.op().get() {
    if let Some(entry) = e.log.get(&op) {
      let w = expected.entry(entry.client.get()).or_default();
      *w = (*w).max(entry.request.get());
    }
  }
  assert_eq!(
    expected,
    [(1u128, 10_004u64), (2u128, 10_005u64)]
      .into_iter()
      .collect(),
    "sanity: the dense scan yields each client's held-band request maximum"
  );
  assert_eq!(
    e.clients_len(),
    expected.len(),
    "the rebuilt session table has exactly the dense scan's clients"
  );
  for (client, request) in expected {
    assert_eq!(
      e.clients.get(&client).map(|s| s.request.get()),
      Some(request),
      "client {client}'s rebuilt watermark equals the dense scan's"
    );
  }
}

// ── View-scalar plausibility: an absurd advertised view (a buggy in-threat-model peer's corrupted
// scalar, up to u64::MAX) must neither be adopted by the bare-scalar catch-up nor panic/wrap the
// view+1 escalation arithmetic — while every legitimately-earnable jump still catches up. ──

#[test]
fn implausible_view_claims_are_ignored_and_the_replica_stays_serviceable() {
  // Replica 1 of 3 at view 0 receives view = u64::MAX on each bare-scalar catch-up carrier
  // (Commit / Prepare / PrepareOk). Without the clamp it would adopt the claim wholesale: stranded
  // in ViewChange at the top of the view space, where no real primary answers the GetView, every
  // genuine cluster message is "stale" (< u64::MAX), and the view+1 escalation could only
  // overflow (debug) or saturate-and-spin — one corrupt scalar would permanently eject the replica
  // from every quorum. The clamp drops the claim at ingress; the replica stays Normal in its
  // real view. (In n=3 replica 0 leads view u64::MAX — (2^64 - 1) % 3 == 0 — so the
  // primary-authority sender bindings pass and the claims genuinely reach the handlers.)
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;
  let absurd = View::with(u64::MAX);
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Commit(Commit::new(
      absurd,
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::Prepare(Prepare::new(
      absurd,
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"x"),
    )),
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::PrepareOk(PrepareOk::new(
      absurd,
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::with(0),
      0,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.view(),
    View::new(),
    "an implausible advertised view is never adopted"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "the replica stays serviceable in its real view (not wedged in ViewChange)"
  );
  while e.poll_message().is_some() {}
  // Not wedged: a legitimate higher view still catches up afterwards (the clamp gates only the
  // absurd; primary(2) == replica 2 in n=3, so the sender binding passes).
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::Commit(Commit::new(
      View::with(2),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.view(), View::with(2));
  assert_eq!(
    e.status(),
    Status::ViewChange,
    "a legitimate jump still drives the GetView catch-up"
  );
}

#[test]
fn view_jump_clamp_accepts_the_bound_and_rejects_just_above_it() {
  // The clamp predicate is `claimed > local + MAX_VIEW_JUMP`: a claim exactly AT the bound is the
  // most generous accepted jump (catch-up proceeds), one view past it is dropped. Replica 0 of 3 at
  // view 0; primary(2^32) = replica 1 and primary(2^32 + 1) = replica 2 (2^32 ≡ 1 mod 3), so both
  // claims pass the Commit sender binding and the difference below is the clamp alone.
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  let now = Instant::ZERO;

  // One past the bound: rejected (stays Normal at view 0).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::Commit(Commit::new(
      View::with(MAX_VIEW_JUMP + 1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.view(),
    View::new(),
    "local + MAX_VIEW_JUMP + 1 is rejected"
  );
  assert_eq!(e.status(), Status::Normal);

  // Exactly the bound: accepted (the catch-up adopts it and solicits the view's primary).
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(0)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  e.handle_message(
    now,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(1)),
    Message::Commit(Commit::new(
      View::with(MAX_VIEW_JUMP),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(
    e.view(),
    View::with(MAX_VIEW_JUMP),
    "a jump AT the bound is still accepted"
  );
  assert_eq!(e.status(), Status::ViewChange);
}

#[test]
fn svc_and_get_view_at_view_max_neither_panic_nor_wrap() {
  // A replica pinned at the very top of the view space (view == u64::MAX, Normal): an incoming
  // StartViewChange{u64::MAX} crosses `on_start_view_change`'s next-view comparison — a raw
  // `view + 1` there would overflow in debug builds; the saturating `View::next()` makes the target
  // simply stale (`<= our view`) and ignored. A GetView{u64::MAX} performs no view arithmetic and
  // a backup stays silent on it. Neither message may panic, wrap the view to 0, or move status.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.view = View::with(u64::MAX);
  e.log_view = View::with(u64::MAX);
  e.svc_target = View::with(u64::MAX);
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    Message::StartViewChange(StartViewChange::new(
      View::with(u64::MAX),
      ReplicaId::new(0),
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.view(), View::with(u64::MAX), "the view never moves");
  assert_eq!(e.status(), Status::Normal);
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(2)),
    Message::GetView(GetView::new(
      View::with(u64::MAX),
      ReplicaId::new(2),
      9,
      crate::Epoch::new(0),
      0,
    )),
  );
  assert_eq!(e.status(), Status::Normal);
  while let Some(out) = e.poll_message() {
    assert!(
      !matches!(out.msg_ref(), Message::StartView(_)),
      "a backup never answers a GetView with a StartView"
    );
  }
}

#[test]
fn escalation_at_view_max_saturates_instead_of_wrapping() {
  // The escalation target is the SATURATING `View::next()`: proposing off view u64::MAX pins the
  // target at u64::MAX rather than computing `u64::MAX + 1` (debug panic; release wrap to view 0,
  // which would un-fence every monotone-view guard behind a "view 0" the cluster believes is
  // ancient). The proposal degrades to a no-quorum SVC{u64::MAX} broadcast — inert, not corrupt.
  let mut e = Endpoint::new(
    Config::try_new(1, MemberId::new(1)).unwrap(),
    genesis(3),
    0,
    NoopSm,
  );
  let mut sb = TestSb::default();
  e.view = View::with(u64::MAX);
  e.log_view = View::with(u64::MAX);
  e.svc_target = View::with(u64::MAX);
  e.propose_next_view(Instant::ZERO, &mut sb);
  assert_eq!(
    e.view(),
    View::with(u64::MAX),
    "the view itself never moves"
  );
  assert_eq!(
    e.status(),
    Status::Normal,
    "no self-transition without an SVC quorum"
  );
  let mut saw_svc = false;
  while let Some(out) = e.poll_message() {
    if let Message::StartViewChange(svc) = out.into_msg() {
      assert_eq!(
        svc.view(),
        View::with(u64::MAX),
        "the proposed target saturates at u64::MAX, never wraps to 0"
      );
      saw_svc = true;
    }
  }
  assert!(
    saw_svc,
    "the proposal is still broadcast (liveness intent kept)"
  );
}

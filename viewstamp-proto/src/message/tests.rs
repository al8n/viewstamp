use super::*;
use crate::{ClientId, OpNumber, ReplicaId, RequestNumber, View};

#[test]
fn commit_and_prepare_ok_carry_checkpoint_op() {
  let c = Commit::new(
    View::with(1),
    OpNumber::with(5),
    OpNumber::with(4),
    crate::Epoch::new(0),
    0,
  );
  assert_eq!(c.checkpoint_op(), OpNumber::with(4));
  let ok = PrepareOk::new(
    View::with(1),
    OpNumber::with(5),
    ReplicaId::new(2),
    OpNumber::with(4),
    0x1234_5678_9abc_def0_1122_3344_5566_7788,
    crate::Epoch::new(0),
    0,
  );
  assert_eq!(ok.checkpoint_op(), OpNumber::with(4));
  // The vote is content-addressed: it carries the operation-identity checksum verbatim.
  assert_eq!(
    ok.prepare_checksum(),
    0x1234_5678_9abc_def0_1122_3344_5566_7788
  );
}

#[test]
fn prepare_ok_prepare_checksum_round_trips_through_the_wire_codec() {
  // The content-addressed vote field must survive encode→decode unchanged (a u128 edge value),
  // since the primary's `on_prepare_ok` matches it against the operation it is driving at that op.
  let ok = Message::PrepareOk(PrepareOk::new(
    View::with(7),
    OpNumber::with(9),
    ReplicaId::new(3),
    OpNumber::with(4),
    u128::MAX,
    crate::Epoch::new(0),
    0,
  ));
  let back = Message::decode(&ok.encode()).expect("round-trips");
  assert_eq!(back, ok);
  let p = back.unwrap_prepare_ok();
  assert_eq!(p.prepare_checksum(), u128::MAX);
  assert_eq!(p.op(), OpNumber::with(9));
}

#[test]
fn learner_status_round_trips_through_the_wire_codec_and_carries_no_vote() {
  // The learner's durable-frontier report survives encode→decode unchanged (edge scalars), and
  // carries its sender slot + the STRICT epoch-policy pair — but NO content-addressed vote field
  // (`prepare_checksum`): it is a progress report, never counted toward any quorum.
  let m = Message::LearnerStatus(LearnerStatus::new(
    ReplicaId::new(300), // a slot above a single byte exercises both u16 bytes
    OpNumber::with(u64::MAX),
    OpNumber::with(42),
    crate::Epoch::new(9),
    0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00,
  ));
  let back = Message::decode(&m.encode()).expect("round-trips");
  assert_eq!(back, m, "decode(encode(m)) == m");
  let ls = back.unwrap_learner_status();
  assert_eq!(ls.replica(), ReplicaId::new(300));
  assert_eq!(ls.durable_commit_min(), OpNumber::with(u64::MAX));
  assert_eq!(ls.durable_op(), OpNumber::with(42));
  assert_eq!(ls.epoch(), crate::Epoch::new(9));
  assert_eq!(ls.config_id(), 0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00);
  // It advertises NO authoritative/participatory view — it carries no vote/lead authority, so the
  // emit chokepoint never blocks it on an in-flight view write.
  assert!(
    !m.advertises_authoritative_view(),
    "a learner progress report claims no participatory view",
  );
}

#[test]
fn prepare_carries_checkpoint_op() {
  let p = Prepare::new(
    View::with(1),
    OpNumber::with(5),
    OpNumber::with(4),
    OpNumber::with(2),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(5),
    Bytes::from_static(b"x"),
  );
  assert_eq!(p.checkpoint_op(), OpNumber::with(2));
}

#[test]
fn construct_and_match() {
  let m = Message::Prepare(Prepare::new(
    View::with(0),
    OpNumber::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(9),
    RequestNumber::with(1),
    Bytes::copy_from_slice(&[1, 2, 3]),
  ));
  match m {
    Message::Prepare(p) => assert_eq!(p.op(), OpNumber::with(1)),
    _ => panic!("wrong variant"),
  }
}

#[test]
fn view_change_messages_construct_and_predicate() {
  use crate::ReplicaId;
  let svc = Message::StartViewChange(StartViewChange::new(
    View::with(1),
    ReplicaId::new(2),
    crate::Epoch::new(0),
    0,
  ));
  assert!(svc.is_start_view_change());
  let dvc = Message::DoViewChange(DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(3),
    OpNumber::with(1),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    std::vec![PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      bytes::Bytes::from_static(b"x"),
    )],
  ));
  assert_eq!(dvc.unwrap_do_view_change().op(), OpNumber::with(3));
}

#[test]
fn recovery_messages_construct_and_round_trip() {
  use crate::ReplicaId;
  // A RecoveringHead replica broadcasts Recovery{replica, nonce}.
  let rec = Message::Recovery(Recovery::new(
    ReplicaId::new(2),
    0xABCD,
    crate::Epoch::new(0),
    0,
  ));
  assert!(rec.is_recovery());
  let r = rec.unwrap_recovery();
  assert_eq!(r.replica(), ReplicaId::new(2));
  assert_eq!(r.nonce(), 0xABCD);

  // The primary's RecoveryResponse carries its view + head + commit + canonical log, echoing nonce.
  let resp = Message::RecoveryResponse(RecoveryResponse::new(
    View::with(3),
    OpNumber::with(5),
    OpNumber::with(4),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    0xABCD,
    std::vec![PreparedEntry::new(
      OpNumber::with(5),
      ClientId::new(7),
      RequestNumber::with(5),
      bytes::Bytes::from_static(b"e"),
    )],
  ));
  assert!(resp.is_recovery_response());
  let rr = resp.unwrap_recovery_response();
  assert_eq!(rr.view(), View::with(3));
  assert_eq!(rr.op(), OpNumber::with(5));
  assert_eq!(rr.commit(), OpNumber::with(4));
  assert_eq!(rr.replica(), ReplicaId::new(0));
  assert_eq!(rr.nonce(), 0xABCD);
  assert_eq!(rr.log_slice().len(), 1);
  assert_eq!(rr.into_log().len(), 1);
}

#[test]
fn request_prepare_constructs_and_round_trips() {
  use crate::ReplicaId;
  // A replica holding a faulty committed op `op` broadcasts RequestPrepare{view, op, replica}.
  let m = Message::RequestPrepare(RequestPrepare::new(
    View::with(2),
    OpNumber::with(7),
    ReplicaId::new(3),
    0,
    42,
  ));
  assert!(m.is_request_prepare());
  let rp = m.unwrap_request_prepare();
  assert_eq!(rp.view(), View::with(2));
  assert_eq!(rp.op(), OpNumber::with(7));
  assert_eq!(rp.replica(), ReplicaId::new(3));
  assert_eq!(rp.generation(), 42);
}

#[test]
fn nack_constructs_and_round_trips() {
  // The NEGATIVE answer to a RequestPrepare: a replica declares it durably LACKS `op`. Carries
  // view/op/replica/config_id, round-trips byte-for-byte, and — like its paired RequestPrepare — is
  // NEVER an authoritative-view claim (so it may be emitted while a view write is in flight).
  let m = Message::Nack(Nack::new(
    View::with(2),
    OpNumber::with(7),
    ReplicaId::new(3),
    0xCAFE,
    99,
  ));
  assert!(
    !m.advertises_authoritative_view(),
    "a Nack is a view-independent 'I lack this op' fact, never a view-authority claim"
  );
  let back = Message::decode(&m.encode()).expect("round-trip decodes");
  assert_eq!(back, m, "decode(encode(nack)) == nack");
  let Message::Nack(n) = back else {
    panic!("expected a Nack")
  };
  assert_eq!(n.view(), View::with(2));
  assert_eq!(n.op(), OpNumber::with(7));
  assert_eq!(n.replica(), ReplicaId::new(3));
  assert_eq!(n.config_id(), 0xCAFE);
  assert_eq!(n.generation(), 99);
}

#[test]
fn sync_messages_construct_and_round_trip() {
  use crate::ReplicaId;
  // A lagging replica solicits with its CURRENT (stale) checkpoint + a nonce.
  let rq = Message::RequestSync(RequestSync::new(
    View::with(4),
    OpNumber::with(2),
    ReplicaId::new(3),
    0xBEEF,
    false,
    0,
  ));
  assert!(rq.is_request_sync());
  let r = rq.unwrap_request_sync();
  assert_eq!(r.view(), View::with(4));
  assert_eq!(r.checkpoint_op(), OpNumber::with(2));
  assert_eq!(r.replica(), ReplicaId::new(3));
  assert_eq!(r.nonce(), 0xBEEF);
  assert!(!r.recovery(), "ordinary state-sync request");
  // A recovery peer-fetch sets the flag (a peer at an EQUAL checkpoint serves it).
  let rec = RequestSync::new(
    View::with(4),
    OpNumber::with(2),
    ReplicaId::new(3),
    0xBEEF,
    true,
    0,
  );
  assert!(rec.recovery());

  // The peer answers with the newer checkpoint: op, id, opaque snapshot, echoed nonce.
  let snap = Bytes::from_static(b"snapshot-envelope");
  let memb = Bytes::from_static(b"membership-encoding");
  let sc = Message::SyncCheckpoint(SyncCheckpoint::new(
    View::with(4),
    OpNumber::with(8),
    0x1234_5678_9abc,
    crate::Epoch::new(5),
    0,
    ReplicaId::new(0),
    0xBEEF,
    snap.clone(),
    memb.clone(),
  ));
  assert!(sc.is_sync_checkpoint());
  let s = sc.unwrap_sync_checkpoint();
  assert_eq!(s.view(), View::with(4));
  assert_eq!(s.checkpoint_op(), OpNumber::with(8));
  assert_eq!(s.checkpoint_id(), 0x1234_5678_9abc);
  assert_eq!(s.epoch(), crate::Epoch::new(5));
  assert_eq!(s.replica(), ReplicaId::new(0));
  assert_eq!(s.nonce(), 0xBEEF);
  assert_eq!(s.snapshot(), b"snapshot-envelope");
  assert_eq!(s.snapshot_bytes(), snap);
  assert_eq!(s.membership(), b"membership-encoding");
  assert_eq!(s.membership_bytes(), memb);
}

#[test]
fn advertises_authoritative_view_is_exactly_the_gated_set() {
  use crate::ReplicaId;
  let body = Bytes::from_static(b"x");
  let entry = || {
    PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      body.clone(),
    )
  };
  // The GATED set (a view-advertising authority / participation message) — must return `true`.
  let gated: std::vec::Vec<Message> = std::vec![
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(1),
      body.clone(),
    )),
    Message::PrepareOk(PrepareOk::new(
      View::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      OpNumber::with(0),
      0,
      crate::Epoch::new(0),
      0,
    )),
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    )),
    Message::DoViewChange(DoViewChange::new(
      View::with(1),
      View::with(0),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(2),
      std::vec![entry()],
    )),
    Message::StartView(StartView::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      std::vec![entry()],
    )),
    Message::RecoveryResponse(RecoveryResponse::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(1),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      0,
      std::vec![entry()],
    )),
    Message::SyncCheckpoint(SyncCheckpoint::new(
      View::with(1),
      OpNumber::with(2),
      0,
      crate::Epoch::new(0),
      0,
      ReplicaId::new(0),
      0,
      body.clone(),
      Bytes::new(),
    )),
    Message::RepairBatch(RepairBatch::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      0,
      std::vec![entry()]
    )),
    // The batched prepare retransmit advertises `self.view` exactly like each per-op `Prepare`
    // it replaces.
    Message::PrepareBatch(PrepareBatch::new(
      View::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      std::vec![entry()],
    )),
  ];
  for m in &gated {
    assert!(
      m.advertises_authoritative_view(),
      "{} must be gated",
      m.kind_str()
    );
  }
  // The NON-gated set (solicitations / requests-to-change / client-facing) — must return `false`.
  let ungated: std::vec::Vec<Message> = std::vec![
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      body.clone()
    )),
    Message::Reply(Reply::new(
      View::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      body.clone()
    )),
    Message::StartViewChange(StartViewChange::new(
      View::with(1),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0
    )),
    Message::GetView(GetView::new(
      View::with(1),
      ReplicaId::new(2),
      0,
      crate::Epoch::new(0),
      0
    )),
    Message::RequestPrepare(RequestPrepare::new(
      View::with(1),
      OpNumber::with(1),
      ReplicaId::new(2),
      0,
      0,
    )),
    Message::Recovery(Recovery::new(ReplicaId::new(2), 0, crate::Epoch::new(0), 0)),
    Message::RequestSync(RequestSync::new(
      View::with(1),
      OpNumber::with(0),
      ReplicaId::new(2),
      0,
      false,
      0
    )),
    Message::RequestPrepareRange(RequestPrepareRange::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(2),
      ReplicaId::new(2),
      0
    )),
  ];
  for m in &ungated {
    assert!(
      !m.advertises_authoritative_view(),
      "{} must NOT be gated",
      m.kind_str()
    );
  }
  // Every variant is covered exactly once across the two sets (no Message kind missed).
  assert_eq!(
    gated.len() + ungated.len(),
    17,
    "all 17 classified Message variants are covered"
  );
  assert_eq!(
    Message::Commit(Commit::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
    ))
    .kind_str(),
    "Commit"
  );
}

#[test]
fn backup_recovery_response_carries_no_log() {
  use crate::ReplicaId;
  // A non-primary's RecoveryResponse carries only its view + nonce (no canonical log/head/commit).
  let rr = RecoveryResponse::new(
    View::with(3),
    OpNumber::new(),
    OpNumber::new(),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(2),
    0xFEED,
    std::vec![],
  );
  assert!(rr.log_slice().is_empty());
  assert_eq!(rr.nonce(), 0xFEED);
  assert_eq!(rr.view(), View::with(3));
}

// ── wire codec: all 20 Message variants ──

use crate::codec::CodecError;

fn entry(op: u64, body: &[u8]) -> PreparedEntry {
  PreparedEntry::new(
    OpNumber::with(op),
    ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
    RequestNumber::with(op),
    Bytes::copy_from_slice(body),
  )
}

/// One representative [`Message`] per variant, deliberately exercising the edge cases each
/// variant's codec must handle: an EMPTY body (`Request`), a POPULATED body (`Prepare`/`Reply`/
/// `SyncCheckpoint`/`BlockResponse`), an EMPTY log slice (`StartView`), a POPULATED multi-entry log
/// (`DoViewChange`/`RecoveryResponse`), the `recovery` bool both ways, and `u64::MAX`/`u128::MAX`
/// edge scalars. Covers all 24 tags so the round-trip + fuzz tests sweep the whole surface.
fn one_of_each_variant() -> std::vec::Vec<Message> {
  std::vec![
    Message::Request(Request::new(
      ClientId::new(u128::MAX),
      RequestNumber::with(0),
      Bytes::new(), // empty body edge
    )),
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(u64::MAX),
      OpNumber::with(2),
      OpNumber::with(3),
      crate::Epoch::new(0),
      0,
      ClientId::new(7),
      RequestNumber::with(9),
      Bytes::from_static(b"prepare-body"),
    )),
    Message::PrepareOk(PrepareOk::new(
      View::with(4),
      OpNumber::with(5),
      ReplicaId::new(255),
      OpNumber::with(6),
      0xCAFE_F00D_DEAD_BEEF_0102_0304_0506_0708,
      crate::Epoch::new(0),
      0,
    )),
    Message::Reply(Reply::new(
      View::with(2),
      ClientId::new(8),
      RequestNumber::with(3),
      Bytes::from_static(b"reply-body"),
    )),
    Message::Commit(Commit::new(
      View::with(4),
      OpNumber::with(9),
      OpNumber::with(7),
      crate::Epoch::new(0),
      0,
    )),
    Message::StartViewChange(StartViewChange::new(
      View::with(11),
      ReplicaId::new(2),
      crate::Epoch::new(0),
      0
    )),
    Message::DoViewChange(
      DoViewChange::new(
        View::with(3),
        View::with(2),
        OpNumber::with(6),
        OpNumber::with(4),
        crate::Epoch::new(0),
        0,
        ReplicaId::new(6),
        std::vec![
          entry(4, b""),
          entry(5, b"hi"),
          PreparedEntry::repairing(
            OpNumber::with(6),
            ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
            RequestNumber::with(6),
            0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
          ),
        ],
      )
      .with_checkpoint_op(OpNumber::with(3)), // non-zero advertised floor — round-trips
    ),
    Message::StartView(
      StartView::new(
        View::with(7),
        OpNumber::with(0),
        OpNumber::with(0),
        crate::Epoch::new(0),
        0,
        ReplicaId::new(0),
        std::vec![],
      )
      .with_checkpoint_op(OpNumber::with(u64::MAX)), // edge scalar floor — round-trips
    ),
    Message::GetView(GetView::new(
      View::with(5),
      ReplicaId::new(3),
      u64::MAX,
      crate::Epoch::new(0),
      0
    )),
    Message::RequestPrepare(RequestPrepare::new(
      View::with(2),
      OpNumber::with(7),
      ReplicaId::new(3),
      0,
      13,
    )),
    Message::Recovery(Recovery::new(
      ReplicaId::new(9),
      0xABCD,
      crate::Epoch::new(0),
      0
    )),
    Message::RecoveryResponse(
      RecoveryResponse::new(
        View::with(3),
        OpNumber::with(5),
        OpNumber::with(4),
        crate::Epoch::new(0),
        0,
        ReplicaId::new(0),
        0xBEEF,
        std::vec![entry(5, b"e")],
      )
      .with_checkpoint_op(OpNumber::with(2)), // non-zero advertised floor — round-trips
    ),
    Message::RequestSync(RequestSync::new(
      View::with(4),
      OpNumber::with(2),
      ReplicaId::new(3),
      0xBEEF,
      true,
      0, // recovery flag set
    )),
    Message::SyncCheckpoint(SyncCheckpoint::new(
      View::with(4),
      OpNumber::with(8),
      u128::MAX,
      crate::Epoch::new(1), // non-zero successor epoch — round-trips
      0,
      ReplicaId::new(0),
      0xBEEF,
      Bytes::from_static(b"snapshot-envelope"),
      // A populated successor-membership encoding so the round-trip + `encoded_len` equivalence
      // exercise the carried length-prefixed `membership` Bytes (a cross-epoch sync ships it).
      ReconfigurePayload::new(
        3,
        1,
        std::vec![
          crate::MemberId::new(1),
          crate::MemberId::new(2),
          crate::MemberId::new(3),
          crate::MemberId::new(4),
        ]
        .into_boxed_slice(),
        0,
      )
      .encode_body(),
    )),
    Message::RequestPrepareRange(RequestPrepareRange::new(
      View::with(2),
      OpNumber::with(7),
      OpNumber::with(70),
      ReplicaId::new(3),
      0,
    )),
    Message::RepairBatch(RepairBatch::new(
      View::with(4),
      OpNumber::with(9),
      OpNumber::with(7),
      0,
      // Populated: an empty-body Present entry, a populated Present entry, a header-only Repairing
      // entry, AND a Reconfigure entry — exercises all THREE body-state wire tags inside the batch
      // log slice.
      std::vec![
        entry(7, b""),
        entry(8, b"hi"),
        PreparedEntry::repairing(
          OpNumber::with(9),
          ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
          RequestNumber::with(9),
          0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
        ),
        PreparedEntry::reconfigure(
          OpNumber::with(10),
          ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
          RequestNumber::with(10),
          ReconfigurePayload::new(
            3,
            1,
            std::vec![
              crate::MemberId::new(1),
              crate::MemberId::new(2),
              crate::MemberId::new(3),
              crate::MemberId::new(4),
            ]
            .into_boxed_slice(),
            0,
          ),
        ),
      ],
    )),
    Message::PrepareBatch(PrepareBatch::new(
      View::with(4),
      OpNumber::with(9),
      OpNumber::with(7),
      crate::Epoch::new(0),
      0,
      std::vec![
        entry(10, b""),
        entry(11, b"hi"),
        PreparedEntry::repairing(
          OpNumber::with(12),
          ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
          RequestNumber::with(12),
          0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
        ),
      ],
    )),
    Message::LearnerStatus(LearnerStatus::new(
      ReplicaId::new(4),
      OpNumber::with(u64::MAX), // edge scalar durable_commit_min — round-trips
      OpNumber::with(7),
      crate::Epoch::new(0),
      0,
    )),
    Message::EpochAhead(EpochAhead::new(
      crate::Epoch::new(u64::MAX), // edge scalar epoch — round-trips
      OpNumber::with(8),
    )),
    Message::RequestLearnerProof(RequestLearnerProof::new(
      ReplicaId::new(300),      // a slot above a single byte exercises both u16 bytes
      OpNumber::with(u64::MAX), // edge scalar at_op — round-trips
      0xBEEF,
      crate::Epoch::new(0),
      0,
    )),
    Message::LearnerProof(LearnerProof::new(
      ReplicaId::new(4),
      0xBEEF,
      OpNumber::with(u64::MAX), // edge scalar frontier — round-trips
      crate::Epoch::new(0),
      0,
    )),
    Message::RequestBlock(crate::block_store::block_address(b"test-block")),
    Message::BlockResponse(BlockResponse::new(
      crate::block_store::block_address(b"test-block"),
      Some(Bytes::from_static(b"test-block")),
    )),
    Message::Nack(Nack::new(
      View::with(3),
      OpNumber::with(u64::MAX), // edge scalar op — round-trips
      ReplicaId::new(300),      // a slot above a single byte exercises both u16 bytes
      0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, // non-zero config lineage — round-trips
      u64::MAX,                 // edge generation — round-trips
    )),
  ]
}

#[test]
fn encoded_len_matches_encode_len_for_every_variant() {
  // The preflight size must exactly equal the encoded length for every variant (incl. empty and
  // populated bodies/log slices), so the transport's pre-encode frame-cap check can never disagree
  // with the bytes a subsequent encode would actually produce.
  for m in one_of_each_variant() {
    assert_eq!(
      m.encoded_len(),
      m.encode().len(),
      "encoded_len() must equal encode().len() for {}",
      m.kind_str()
    );
  }
  // Also the recovery=false RequestSync, whose bool is the only field that differs by value.
  let rq = Message::RequestSync(RequestSync::new(
    View::with(4),
    OpNumber::with(2),
    ReplicaId::new(3),
    0xBEEF,
    false,
    0,
  ));
  assert_eq!(rq.encoded_len(), rq.encode().len());
}

#[test]
fn max_reply_body_len_is_tight_against_the_reply_carrier() {
  // The reply-size contract is tight to the byte: a reply body of exactly `max_reply_body_len()`
  // encodes as a `Reply` of exactly `MAX_FRAME_LEN` (deliverable), and one byte more exceeds the
  // cap (the transport refuses the send — unrecoverable for an already-committed op, which is why
  // `StateMachine::apply` carries the bound as an embedder obligation).
  let reply_of = |len: usize| {
    Message::Reply(Reply::new(
      View::with(1),
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from(std::vec![0u8; len]),
    ))
  };
  let max = max_reply_body_len();
  let cap = MAX_FRAME_LEN as usize;
  assert_eq!(
    reply_of(max).encode().len(),
    cap,
    "a max-size reply body lands exactly on MAX_FRAME_LEN"
  );
  assert!(
    reply_of(max + 1).encode().len() > cap,
    "one byte over the max pushes the Reply past the frame cap"
  );
  // The overhead const matches the Reply encode arm widths (header 3 + view 8 + client 16 +
  // request 8 + body length prefix 4).
  assert_eq!(REPLY_ENCODE_OVERHEAD, 39);
  assert_eq!(reply_of(0).encode().len(), REPLY_ENCODE_OVERHEAD);
}

#[test]
fn prepare_batch_is_tight_against_the_frame_cap() {
  // The batched-retransmit frame arithmetic, pinned by REAL encodings (not just the modelled
  // consts): the carrier const matches the encode arm widths, a max-fill one-entry PrepareBatch
  // lands EXACTLY on MAX_FRAME_LEN, one byte more exceeds it, and a multi-entry batch whose
  // per-entry costs sum exactly to the budget also lands exactly on the cap — so the retransmit
  // accumulator (budget = MAX_FRAME_LEN - PREPARE_BATCH_CARRIER_OVERHEAD, cost =
  // present_entry_encoded_len) can never produce an oversized frame, and wastes nothing.
  let cap = MAX_FRAME_LEN as usize;
  let batch_of = |entries: std::vec::Vec<PreparedEntry>| {
    Message::PrepareBatch(PrepareBatch::new(
      View::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      entries,
    ))
  };
  let entry_of = |op: u64, len: usize| {
    PreparedEntry::new(
      OpNumber::with(op),
      ClientId::new(7),
      RequestNumber::with(op),
      Bytes::from(std::vec![0u8; len]),
    )
  };
  // The carrier const matches the encode arm widths (header 3 + view/commit/checkpoint_op 24 + the
  // strict epoch(8)+config_id(16) 24 + log count prefix 4) — an empty batch encodes to exactly the
  // carrier.
  assert_eq!(PREPARE_BATCH_CARRIER_OVERHEAD, 55);
  assert_eq!(
    batch_of(std::vec![]).encode().len(),
    PREPARE_BATCH_CARRIER_OVERHEAD
  );
  let budget = cap - PREPARE_BATCH_CARRIER_OVERHEAD;
  // Max-fill single entry: a body whose entry cost is exactly the budget lands exactly on the cap
  // (the first-entry-progress case — one such op still ships); one byte more exceeds it.
  let max = budget - present_entry_encoded_len(0);
  assert_eq!(
    batch_of(std::vec![entry_of(1, max)]).encode().len(),
    cap,
    "a max-fill one-entry PrepareBatch lands exactly on MAX_FRAME_LEN"
  );
  assert!(
    batch_of(std::vec![entry_of(1, max + 1)]).encode().len() > cap,
    "one byte over the max pushes the PrepareBatch past the frame cap"
  );
  // Multi-entry max-fill: two entries whose costs sum exactly to the budget land exactly on the
  // cap — the running-cost accumulation models the encoding to the byte across entries.
  let half = budget / 2;
  let (a, b) = (
    half - present_entry_encoded_len(0),
    (budget - half) - present_entry_encoded_len(0),
  );
  assert_eq!(
    present_entry_encoded_len(a) + present_entry_encoded_len(b),
    budget
  );
  assert_eq!(
    batch_of(std::vec![entry_of(1, a), entry_of(2, b)])
      .encode()
      .len(),
    cap,
    "two entries summing exactly to the budget land exactly on MAX_FRAME_LEN"
  );
}

/// The transport's `max_request_body_len()` is the largest client body deliverable on EVERY message
/// that can carry it, and it is tight to the byte. The view-change log carriers
/// (`DoViewChange` / `StartView` / `RecoveryResponse`) are HEADER-ONLY (they ship no body — see
/// `Endpoint::log_entries`), so the SAME body bytes travel only as the `Request` the client sends, the
/// `Prepare` the primary replicates, and — once the op is logged — a single `Body::Present`
/// `PreparedEntry` inside a `RepairBatch` (the windowed peer-repair answer) or a `PrepareBatch` (the
/// primary's batched retransmit). The epoch-policy matrix makes the STRICT `PrepareBatch` carrier
/// (epoch + config_id) strictly larger than the AGNOSTIC `RepairBatch` carrier (config_id only), so
/// the two batch carriers no longer TIE — `PrepareBatch` is the sole BINDING carrier. This proves,
/// via the ACTUAL `encode().len()` (real messages, not just the modelled `encoded_len()`), that a
/// body of exactly the bound fits `MAX_FRAME_LEN` on ALL of those carriers, that the binding
/// single-entry `PrepareBatch` lands EXACTLY on the cap (and a `RepairBatch` sits just under it by the
/// strict/agnostic 8-byte carrier gap), that one byte more pushes the binding `PrepareBatch` past the
/// cap, and — separately — that a header-only `DoViewChange` is INSENSITIVE to body size (a whole band
/// of max-body ops stays far under cap as fixed-size headers). Enumerating every carrier here means a
/// future message that wraps the body in MORE framing fails this test until the bound accounts for it.
#[cfg(feature = "tcp")]
#[test]
fn max_request_body_len_is_tight_against_every_body_carrier() {
  use crate::{MAX_FRAME_LEN, max_request_body_len};

  let max = max_request_body_len();
  let cap = MAX_FRAME_LEN as usize;

  let client = ClientId::new(7);
  let request = RequestNumber::with(1);

  // Each closure builds a real message that carries a body of `len` bytes. The `RepairBatch` and
  // `PrepareBatch` wrap it in a single-entry `Body::Present` log slice — the worst case for one
  // maximal body (a multi-entry batch only spreads more fixed framing across more bodies; the
  // byte-bounded serve/retransmit never exceeds the cap).
  let body_of = |len: usize| Bytes::from(std::vec![0u8; len]);
  let request_of = |len: usize| Message::Request(Request::new(client, request, body_of(len)));
  let prepare_of = |len: usize| {
    Message::Prepare(Prepare::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      client,
      request,
      body_of(len),
    ))
  };
  let repair_batch_of = |len: usize| {
    Message::RepairBatch(RepairBatch::new(
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(0),
      0,
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        client,
        request,
        body_of(len),
      )],
    ))
  };
  let prepare_batch_of = |len: usize| {
    Message::PrepareBatch(PrepareBatch::new(
      View::with(1),
      OpNumber::with(0),
      OpNumber::with(0),
      crate::Epoch::new(0),
      0,
      std::vec![PreparedEntry::new(
        OpNumber::with(1),
        client,
        request,
        body_of(len),
      )],
    ))
  };

  // Every BODY carrier of a max-size body, paired with its builder, checked by its REAL encoded length.
  let carriers: [(&str, &dyn Fn(usize) -> Message); 4] = [
    ("Request", &request_of),
    ("Prepare", &prepare_of),
    ("RepairBatch", &repair_batch_of),
    ("PrepareBatch", &prepare_batch_of),
  ];

  // At the max: every body carrier fits the frame cap (the bound is the MAX over all per-carrier
  // overheads, so the body fits the tightest carrier and a fortiori the rest).
  let mut tightest = 0usize;
  for (name, build) in carriers {
    let encoded = build(max).encode().len();
    assert!(
      encoded <= cap,
      "a max-size body carried by {name} must fit the frame cap: {encoded} > {cap}"
    );
    tightest = tightest.max(encoded);
  }
  // Tight: the tightest carrier sits EXACTLY at the cap, so the bound wastes nothing. The single-entry
  // STRICT `PrepareBatch` is this binding max — larger than the `Prepare` hop by the per-entry log
  // framing, and larger than the AGNOSTIC `RepairBatch` by the strict epoch (the +8 epoch field; the
  // +16 config_id is shared).
  assert_eq!(
    tightest, cap,
    "the tightest body carrier lands exactly on MAX_FRAME_LEN at the max body"
  );
  let pb_at = prepare_batch_of(max).encode().len();
  assert_eq!(
    pb_at, cap,
    "the binding one-entry PrepareBatch lands exactly on MAX_FRAME_LEN"
  );
  // The agnostic `RepairBatch` carrier is 8 bytes smaller (no `epoch`), so a max-size body in a
  // one-entry RepairBatch sits exactly 8 bytes under the cap — comfortably deliverable, never the
  // binding carrier.
  let rb_at = repair_batch_of(max).encode().len();
  assert_eq!(
    rb_at,
    cap - 8,
    "a one-entry RepairBatch sits 8 bytes under the cap (it lacks the strict epoch field)"
  );

  // One byte more: the BINDING carrier (`PrepareBatch`) exceeds the cap, so the transport would drop
  // it. The smaller-overhead carriers (`Request`, `Prepare`, `RepairBatch`) may still fit at max+1 — it
  // is enough that the binding one does not, which is exactly why the bound subtracts the LARGEST
  // per-carrier overhead.
  let pb_over = prepare_batch_of(max + 1).encode().len();
  assert!(
    pb_over > cap,
    "one byte over the max must push a one-entry PrepareBatch past the frame cap: {pb_over} <= {cap}"
  );
  // The RepairBatch still fits at max+1 (it had 8 bytes of headroom): this documents that it is NOT
  // the binding carrier — only the strict PrepareBatch is.
  let rb_over = repair_batch_of(max + 1).encode().len();
  assert!(
    rb_over <= cap,
    "a one-entry RepairBatch still fits at max+1 (it is not the binding carrier): {rb_over} > {cap}"
  );

  // The header-only view-change carriers are INSENSITIVE to body size: a `DoViewChange` whose entry is
  // header-only (`Repairing`) encodes the same whether the op's body is empty or `max` bytes — it ships
  // only the 16-byte `body_checksum`. So a max-body op rides a view change far under the frame cap, the
  // whole point of the header-only carrier. (The DEEP-band fit is bounded separately by
  // `MAX_HEADER_ONLY_BAND_DEPTH` / the `MAX_CHECKPOINT_OPS` cap.)
  let header_only_dvc = Message::DoViewChange(DoViewChange::new(
    View::with(1),
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    std::vec![PreparedEntry::repairing(
      OpNumber::with(1),
      client,
      request,
      0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
    )],
  ));
  assert!(
    header_only_dvc.encode().len() < cap / 2,
    "a header-only DoViewChange entry is body-size-insensitive and well under the frame cap"
  );
}

#[test]
fn every_variant_round_trips_through_the_wire_codec() {
  let all = one_of_each_variant();
  assert_eq!(all.len(), 24, "every Message variant is represented");
  for m in &all {
    let bytes = m.encode();
    let back = Message::decode(&bytes).expect("round-trip decodes");
    assert_eq!(&back, m, "decode(encode(m)) == m for {}", m.kind_str());
    // The encoding leads with the wire version then the variant tag.
    assert_eq!(
      &bytes[..2],
      &crate::WIRE_VERSION.to_be_bytes(),
      "leads with WIRE_VERSION"
    );
  }
  // Also exercise an ordinary state-sync (recovery = false) so both bool encodings round-trip.
  let rq = Message::RequestSync(RequestSync::new(
    View::with(4),
    OpNumber::with(2),
    ReplicaId::new(3),
    0xBEEF,
    false,
    0,
  ));
  assert_eq!(Message::decode(&rq.encode()).unwrap(), rq);
}

#[test]
fn a_replica_id_above_a_byte_round_trips_through_the_wire_codec() {
  // The replica id is a u16 on the wire (two big-endian bytes), so an index that does not fit a
  // single byte survives encode→decode unchanged on every replica-bearing variant. 300 = 0x012C
  // exercises both bytes.
  let id = ReplicaId::new(300);
  assert!(
    id.get() > u16::from(u8::MAX),
    "the id is above a single byte"
  );
  let carriers = std::vec![
    Message::PrepareOk(PrepareOk::new(
      View::with(4),
      OpNumber::with(5),
      id,
      OpNumber::with(6),
      0xCAFE_F00D_DEAD_BEEF_0102_0304_0506_0708,
      crate::Epoch::new(0),
      0,
    )),
    Message::StartViewChange(StartViewChange::new(
      View::with(11),
      id,
      crate::Epoch::new(0),
      0
    )),
    Message::DoViewChange(DoViewChange::new(
      View::with(3),
      View::with(2),
      OpNumber::with(6),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
      id,
      std::vec![entry(5, b"hi")],
    )),
    Message::Recovery(Recovery::new(id, 0xABCD, crate::Epoch::new(0), 0)),
  ];
  for m in &carriers {
    let back = Message::decode(&m.encode()).expect("round-trips");
    assert_eq!(&back, m, "decode(encode(m)) == m for {}", m.kind_str());
  }
  // The big-endian id occupies exactly two bytes: a `Recovery` leads its body with the replica id
  // right after the 3-byte header, so bytes [3..5] are `0x01, 0x2C`.
  let rec = Message::Recovery(Recovery::new(id, 0, crate::Epoch::new(0), 0)).encode();
  assert_eq!(
    &rec[3..5],
    &300u16.to_be_bytes(),
    "the replica id is a 2-byte big-endian field"
  );
}

#[test]
fn commit_golden_bytes_pin_the_wire_layout() {
  // A small STRICT variant pinned exactly: WIRE_VERSION(u16=14) ++ tag 4 ++ view ++ commit ++
  // checkpoint_op ++ the strict epoch-policy pair epoch(u64) ++ config_id(u128).
  let c = Message::Commit(Commit::new(
    View::with(4),
    OpNumber::with(9),
    OpNumber::with(7),
    crate::Epoch::new(0),
    0,
  ));
  let expected: std::vec::Vec<u8> = std::vec![
    0, 14, 4, // version 14, tag 4 (Commit)
    0, 0, 0, 0, 0, 0, 0, 4, // view = 4
    0, 0, 0, 0, 0, 0, 0, 9, // commit = 9
    0, 0, 0, 0, 0, 0, 0, 7, // checkpoint_op = 7
    0, 0, 0, 0, 0, 0, 0, 0, // epoch = 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // config_id = 0 (u128)
  ];
  assert_eq!(c.encode(), expected, "Commit wire layout is pinned");
}

#[test]
fn do_view_change_golden_bytes_pin_the_nested_log_layout() {
  // A nested STRICT variant pinned exactly: header (ver 11 + tag 6), scalars (incl. the advertised
  // checkpoint floor after the commit, then the strict epoch-policy pair epoch(u64)+config_id(u128)
  // before the u16 replica id), then a 1-entry log slice (count=1, op, client, request, body-state
  // tag 0 = Present, length-prefixed body "hi").
  let dvc = Message::DoViewChange(
    DoViewChange::new(
      View::with(3),
      View::with(2),
      OpNumber::with(5),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(6),
      std::vec![PreparedEntry::new(
        OpNumber::with(5),
        ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
        RequestNumber::with(9),
        Bytes::from_static(b"hi"),
      )],
    )
    .with_checkpoint_op(OpNumber::with(3)),
  );
  let expected: std::vec::Vec<u8> = std::vec![
    0, 14, 6, // version 14, tag 6 (DoViewChange)
    0, 0, 0, 0, 0, 0, 0, 3, // view = 3
    0, 0, 0, 0, 0, 0, 0, 2, // log_view = 2
    0, 0, 0, 0, 0, 0, 0, 5, // op = 5
    0, 0, 0, 0, 0, 0, 0, 4, // commit = 4
    0, 0, 0, 0, 0, 0, 0, 3, // checkpoint_op = 3
    0, 0, 0, 0, 0, 0, 0, 0, // epoch = 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // config_id = 0 (u128)
    0, 6, // replica = 6 (u16)
    0, 0, 0, 1, // log count = 1
    0, 0, 0, 0, 0, 0, 0, 5, // entry op = 5
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // entry client (u128)
    0, 0, 0, 0, 0, 0, 0, 9, // entry request = 9
    0, // body-state tag 0 = Present
    0, 0, 0, 2, 104, 105, // body length 2, "hi"
  ];
  assert_eq!(dvc.encode(), expected, "DoViewChange wire layout is pinned");
}

#[test]
fn do_view_change_golden_bytes_pin_a_repairing_entry() {
  // The header-only (Repairing) entry layout pinned exactly: same scalars (incl. the advertised
  // checkpoint floor after the commit, then the strict epoch-policy pair epoch(u64)+config_id(u128)
  // before the u16 replica id), then body-state tag 1 = Repairing, followed by the 16-byte
  // body_checksum (NO length-prefixed body).
  let dvc = Message::DoViewChange(
    DoViewChange::new(
      View::with(3),
      View::with(2),
      OpNumber::with(5),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(6),
      std::vec![PreparedEntry::repairing(
        OpNumber::with(5),
        ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
        RequestNumber::with(9),
        0x1112_1314_1516_1718_191A_1B1C_1D1E_1F20,
      )],
    )
    .with_checkpoint_op(OpNumber::with(3)),
  );
  let expected: std::vec::Vec<u8> = std::vec![
    0, 14, 6, // version 14, tag 6 (DoViewChange)
    0, 0, 0, 0, 0, 0, 0, 3, // view = 3
    0, 0, 0, 0, 0, 0, 0, 2, // log_view = 2
    0, 0, 0, 0, 0, 0, 0, 5, // op = 5
    0, 0, 0, 0, 0, 0, 0, 4, // commit = 4
    0, 0, 0, 0, 0, 0, 0, 3, // checkpoint_op = 3
    0, 0, 0, 0, 0, 0, 0, 0, // epoch = 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // config_id = 0 (u128)
    0, 6, // replica = 6 (u16)
    0, 0, 0, 1, // log count = 1
    0, 0, 0, 0, 0, 0, 0, 5, // entry op = 5
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // entry client (u128)
    0, 0, 0, 0, 0, 0, 0, 9, // entry request = 9
    1, // body-state tag 1 = Repairing
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, // body_checksum (u128)
  ];
  assert_eq!(
    dvc.encode(),
    expected,
    "DoViewChange Repairing-entry wire layout is pinned"
  );
  // And it round-trips, preserving the op/client/request/checksum with no body bytes.
  let back = Message::decode(&dvc.encode()).expect("round-trips");
  let e = &back.unwrap_do_view_change().into_log()[0];
  assert!(e.is_repairing(), "decoded back as a Repairing entry");
  assert_eq!(e.op(), OpNumber::with(5));
  assert_eq!(
    e.client(),
    ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10)
  );
  assert_eq!(e.request(), RequestNumber::with(9));
  assert_eq!(e.body(), None, "a Repairing entry carries no bytes");
  assert_eq!(e.body_checksum(), 0x1112_1314_1516_1718_191A_1B1C_1D1E_1F20);
}

/// Builds a [`MemberId`] list `[1, 2, ..., n]` for a payload of `n` members.
fn member_ids(n: usize) -> std::vec::Vec<crate::MemberId> {
  (1..=n as u128).map(crate::MemberId::new).collect()
}

#[test]
fn reconfigure_body_round_trips_through_the_wire_codec() {
  // A Reconfigure body rides the log slice like any op; its successor membership
  // (replica_count, learner_count, and the full member list) must survive encode→decode unchanged.
  let payload = ReconfigurePayload::new(3, 2, member_ids(5).into_boxed_slice(), 0);
  let dvc = Message::DoViewChange(DoViewChange::new(
    View::with(3),
    View::with(2),
    OpNumber::with(5),
    OpNumber::with(4),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(6),
    std::vec![PreparedEntry::reconfigure(
      OpNumber::with(5),
      ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
      RequestNumber::with(9),
      payload.clone(),
    )],
  ));
  let back = Message::decode(&dvc.encode()).expect("round-trips");
  let e = &back.unwrap_do_view_change().into_log()[0];
  assert!(e.is_reconfigure(), "decoded back as a Reconfigure entry");
  assert_eq!(e.op(), OpNumber::with(5));
  assert_eq!(
    e.client(),
    ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10)
  );
  assert_eq!(e.request(), RequestNumber::with(9));
  assert_eq!(
    e.body(),
    None,
    "a Reconfigure entry carries no client bytes"
  );
  let decoded = e
    .body_state()
    .as_reconfigure()
    .expect("the decoded body is a Reconfigure payload");
  assert_eq!(decoded, &payload, "the successor membership survives");
  assert_eq!(decoded.replica_count(), 3);
  assert_eq!(decoded.learner_count(), 2);
  assert_eq!(decoded.members(), member_ids(5).as_slice());
}

#[test]
fn a_reconfigure_body_is_not_mistaken_for_present_or_repairing() {
  // The three body-state wire tags are distinct: a Reconfigure body decodes as a Reconfigure,
  // never as a Present (client bytes) or a Repairing (header-only) entry.
  let payload = ReconfigurePayload::new(1, 0, member_ids(1).into_boxed_slice(), 0);
  let rb = Message::RepairBatch(RepairBatch::new(
    View::with(4),
    OpNumber::with(9),
    OpNumber::with(7),
    0,
    std::vec![
      entry(7, b"client-bytes"),
      PreparedEntry::repairing(
        OpNumber::with(8),
        ClientId::new(0xAA),
        RequestNumber::with(8),
        0xDEAD_BEEF_CAFE_F00D_0102_0304_0506_0708,
      ),
      PreparedEntry::reconfigure(
        OpNumber::with(9),
        ClientId::new(0xBB),
        RequestNumber::with(9),
        payload.clone(),
      ),
    ],
  ));
  let log = Message::decode(&rb.encode())
    .expect("round-trips")
    .unwrap_repair_batch()
    .into_log();
  assert!(log[0].body_state().is_present(), "entry 0 is Present");
  assert!(log[1].body_state().is_repairing(), "entry 1 is Repairing");
  assert!(log[2].is_reconfigure(), "entry 2 is Reconfigure");
  assert!(!log[2].body_state().is_present(), "not Present");
  assert!(!log[2].is_repairing(), "not Repairing");
  assert_eq!(log[2].body_state().as_reconfigure(), Some(&payload));
}

#[test]
fn reconfigure_body_golden_bytes_pin_the_wire_layout() {
  // The Reconfigure entry layout pinned exactly: same scalars as the other DoViewChange goldens,
  // then body-state tag 2 = Reconfigure, followed by replica_count(u8) learner_count(u16), a
  // u32-count-prefixed member list (each MemberId a 16-byte big-endian u128), and the trailing
  // prev_config_id(u128) pinning the predecessor the successor chains from.
  let payload = ReconfigurePayload::new(
    2,
    1,
    std::vec![
      crate::MemberId::new(0x0000_0000_0000_0000_0000_0000_0000_00AA),
      crate::MemberId::new(0x0000_0000_0000_0000_0000_0000_0000_00BB),
      crate::MemberId::new(0x0000_0000_0000_0000_0000_0000_0000_00CC),
    ]
    .into_boxed_slice(),
    0x0000_0000_0000_0000_0000_0000_0000_00DD,
  );
  let dvc = Message::DoViewChange(
    DoViewChange::new(
      View::with(3),
      View::with(2),
      OpNumber::with(5),
      OpNumber::with(4),
      crate::Epoch::new(0),
      0,
      ReplicaId::new(6),
      std::vec![PreparedEntry::reconfigure(
        OpNumber::with(5),
        ClientId::new(0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10),
        RequestNumber::with(9),
        payload,
      )],
    )
    .with_checkpoint_op(OpNumber::with(3)),
  );
  let expected: std::vec::Vec<u8> = std::vec![
    0, 14, 6, // version 14, tag 6 (DoViewChange)
    0, 0, 0, 0, 0, 0, 0, 3, // view = 3
    0, 0, 0, 0, 0, 0, 0, 2, // log_view = 2
    0, 0, 0, 0, 0, 0, 0, 5, // op = 5
    0, 0, 0, 0, 0, 0, 0, 4, // commit = 4
    0, 0, 0, 0, 0, 0, 0, 3, // checkpoint_op = 3
    0, 0, 0, 0, 0, 0, 0, 0, // epoch = 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // config_id = 0 (u128)
    0, 6, // replica = 6 (u16)
    0, 0, 0, 1, // log count = 1
    0, 0, 0, 0, 0, 0, 0, 5, // entry op = 5
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // entry client (u128)
    0, 0, 0, 0, 0, 0, 0, 9, // entry request = 9
    2, // body-state tag 2 = Reconfigure
    2, // replica_count = 2 (u8)
    0, 1, // learner_count = 1 (u16)
    0, 0, 0, 3, // member count = 3
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xAA, // member 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xBB, // member 1
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xCC, // member 2
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, // prev_config_id (u128)
  ];
  assert_eq!(
    dvc.encode(),
    expected,
    "DoViewChange Reconfigure-entry wire layout is pinned"
  );
}

#[test]
fn reconfigure_encoded_len_matches_encode_and_respects_the_frame_cap() {
  // The full-voting-set successor membership (64 voters) is the worst case for one Reconfigure
  // entry; its preflight size matches encode and stays well under the frame cap.
  let payload = ReconfigurePayload::new(64, 0, member_ids(64).into_boxed_slice(), 0);
  let rb = Message::RepairBatch(RepairBatch::new(
    View::with(4),
    OpNumber::with(9),
    OpNumber::with(7),
    0,
    std::vec![PreparedEntry::reconfigure(
      OpNumber::with(9),
      ClientId::new(0xBB),
      RequestNumber::with(9),
      payload,
    )],
  ));
  let encoded = rb.encode();
  assert_eq!(
    rb.encoded_len(),
    encoded.len(),
    "encoded_len preflight matches the actual encoding"
  );
  assert!(
    (encoded.len() as u32) < MAX_FRAME_LEN,
    "a max-membership Reconfigure entry fits the frame cap"
  );
}

#[test]
fn distinct_reconfigure_successors_have_distinct_operation_identities() {
  // A Reconfigure op is content-addressed like any op: its body folds into prepare_identity via the
  // body_checksum, so two entries with DIFFERENT successor memberships have DIFFERENT identities.
  let a = ReconfigurePayload::new(3, 0, member_ids(3).into_boxed_slice(), 0);
  let b = ReconfigurePayload::new(3, 1, member_ids(4).into_boxed_slice(), 0);
  let client = ClientId::new(0x1234);
  let request = RequestNumber::with(7);
  let id_a = crate::storage::prepare_identity(
    client,
    request,
    Body::Reconfigure(a.clone()).body_checksum(),
  );
  let id_b =
    crate::storage::prepare_identity(client, request, Body::Reconfigure(b).body_checksum());
  assert_ne!(
    id_a, id_b,
    "different successor memberships content-address differently"
  );
  // The same successor under the same (client, request) is stable.
  let id_a2 =
    crate::storage::prepare_identity(client, request, Body::Reconfigure(a).body_checksum());
  assert_eq!(id_a, id_a2, "a Reconfigure identity is deterministic");
}

#[test]
fn decode_rejects_bad_version_unknown_tag_and_truncation_without_panicking() {
  let bytes = Message::Commit(Commit::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
  ))
  .encode();
  // Empty / too-short to even hold the version → Truncated.
  assert!(matches!(
    Message::decode(&[]),
    Err(CodecError::Truncated { .. })
  ));
  assert!(matches!(
    Message::decode(&[0]),
    Err(CodecError::Truncated { .. })
  ));
  // A bad leading version → UnknownVersion (0x00FF is well above any real WIRE_VERSION).
  let mut badver = bytes.to_vec();
  badver[1] = 0xFF;
  assert!(matches!(
    Message::decode(&badver),
    Err(CodecError::UnknownVersion(0xFF))
  ));
  // An unknown variant tag (99) → UnknownTag.
  let mut badtag = bytes.to_vec();
  badtag[2] = 99;
  assert!(matches!(
    Message::decode(&badtag),
    Err(CodecError::UnknownTag(99))
  ));
  // Truncating a variant mid-field → Truncated (never an OOB panic).
  assert!(matches!(
    Message::decode(&bytes[..bytes.len() - 1]),
    Err(CodecError::Truncated { .. })
  ));
  // Trailing bytes after a fully-decoded variant → TrailingBytes.
  let mut over = bytes.to_vec();
  over.push(0);
  assert!(matches!(
    Message::decode(&over),
    Err(CodecError::TrailingBytes(1))
  ));
}

#[test]
fn decode_rejects_an_oversized_length_prefix_without_panicking() {
  // A SyncCheckpoint's snapshot length prefix overstated past the buffer → LengthOverflow, not
  // an out-of-range slice.
  let sc = Message::SyncCheckpoint(SyncCheckpoint::new(
    View::with(1),
    OpNumber::with(1),
    0,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    0,
    Bytes::from_static(b"abc"),
    Bytes::new(),
  ));
  let mut bytes = sc.encode().to_vec();
  // The encoding ends with the snapshot (4-byte length prefix + 3 body bytes) followed by the empty
  // membership (4-byte length prefix + 0 bytes), so the SNAPSHOT length prefix sits 4 + 3 + 4 = 11
  // bytes from the end (the membership Bytes was added AFTER the snapshot).
  let n = bytes.len();
  bytes[n - 11..n - 7].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
  assert!(matches!(
    Message::decode(&bytes),
    Err(CodecError::LengthOverflow { .. })
  ));

  // A DoViewChange whose log COUNT is absurd → LengthOverflow, caught before allocating.
  let dvc = Message::DoViewChange(DoViewChange::new(
    View::with(1),
    View::with(0),
    OpNumber::with(1),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    std::vec![entry(1, b"x")],
  ));
  let mut d = dvc.encode().to_vec();
  // Locate the log count (after the strict epoch-policy pair epoch(8)+config_id(16) added before the
  // replica id): ver(2)+tag(1)+view(8)+log_view(8)+op(8)+commit(8)+checkpoint_op(8)+epoch(8)+
  // config_id(16)+replica(2) = 69.
  d[69..73].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
  assert!(matches!(
    Message::decode(&d),
    Err(CodecError::LengthOverflow { .. })
  ));
}

#[test]
fn decode_never_panics_on_truncations_or_random_bytes() {
  // Fuzz-style no-panic sweep: every prefix of every variant's encoding, plus a pseudo-random
  // stream of growing length (with a valid version/tag header sometimes prepended), must always
  // yield a typed error — never a panic / out-of-range index.
  for m in one_of_each_variant() {
    let enc = m.encode();
    for n in 0..=enc.len() {
      let _ = Message::decode(&enc[..n]);
    }
  }
  let mut x = 0x1357_9bdfu32;
  for len in 0..600usize {
    let mut v = std::vec::Vec::with_capacity(len + 3);
    // Sometimes prepend a well-formed version + a random tag to drive deeper into the parsers.
    if len % 3 == 0 {
      v.extend_from_slice(&crate::WIRE_VERSION.to_be_bytes());
      v.push((len as u8) % 16);
    }
    for _ in 0..len {
      x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
      v.push((x >> 24) as u8);
    }
    let _ = Message::decode(&v); // must not panic
  }
}

#[test]
fn request_block_and_block_response_round_trip_through_the_wire_codec() {
  let addr = crate::block_store::block_address(b"some-block-bytes");

  // RequestBlock: a fixed 16-byte payload carrying the content address.
  let req = Message::RequestBlock(addr);
  let back = Message::decode(&req.encode()).expect("RequestBlock round-trips");
  assert_eq!(back, req, "decode(encode(RequestBlock)) == RequestBlock");
  assert!(
    !req.advertises_authoritative_view(),
    "a block solicitation carries no view authority",
  );

  // BlockResponse with a present block.
  let block_bytes = Bytes::from_static(b"some-block-bytes");
  let present = Message::BlockResponse(BlockResponse::new(addr, Some(block_bytes.clone())));
  let back = Message::decode(&present.encode()).expect("BlockResponse(Some) round-trips");
  assert_eq!(
    back, present,
    "decode(encode(BlockResponse(Some))) == present"
  );
  let br = back.unwrap_block_response();
  assert_eq!(br.addr(), addr);
  assert_eq!(br.block(), Some(block_bytes.as_ref()));

  // BlockResponse with an absent block (donor does not hold this address).
  let absent = Message::BlockResponse(BlockResponse::new(addr, None));
  let back = Message::decode(&absent.encode()).expect("BlockResponse(None) round-trips");
  assert_eq!(
    back, absent,
    "decode(encode(BlockResponse(None))) == absent"
  );
  let br = back.unwrap_block_response();
  assert_eq!(br.addr(), addr);
  assert_eq!(br.block(), None);
  assert!(br.is_absent(), "None block is absent");
  assert!(!br.is_present(), "None block is not present");

  // encoded_len matches encode().len() for both shapes.
  assert_eq!(present.encoded_len(), present.encode().len());
  assert_eq!(absent.encoded_len(), absent.encode().len());
}

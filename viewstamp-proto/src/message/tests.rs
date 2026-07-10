use super::*;
use crate::{ClientId, OpNumber, ReplicaId, RequestNumber, View, decode_message, encode_message};

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
  let back = decode_message(encode_message(&ok)).expect("round-trips");
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
  let back = decode_message(encode_message(&m)).expect("round-trips");
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
  ));
  assert!(m.is_request_prepare());
  let rp = m.unwrap_request_prepare();
  assert_eq!(rp.view(), View::with(2));
  assert_eq!(rp.op(), OpNumber::with(7));
  assert_eq!(rp.replica(), ReplicaId::new(3));
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
  ));
  assert!(
    !m.advertises_authoritative_view(),
    "a Nack is a view-independent 'I lack this op' fact, never a view-authority claim"
  );
  let back = decode_message(encode_message(&m)).expect("round-trip decodes");
  assert_eq!(back, m, "decode(encode(nack)) == nack");
  let Message::Nack(n) = back else {
    panic!("expected a Nack")
  };
  assert_eq!(n.view(), View::with(2));
  assert_eq!(n.op(), OpNumber::with(7));
  assert_eq!(n.replica(), ReplicaId::new(3));
  assert_eq!(n.config_id(), 0xCAFE);
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
      0
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
    )),
  ]
}

#[test]
fn encoded_len_matches_encode_message_len_for_every_variant() {
  // The preflight size must exactly equal the encoded length for every variant (incl. empty and
  // populated bodies/log slices), so the transport's pre-encode frame-cap check can never disagree
  // with the bytes a subsequent encode_message would actually produce.
  for m in one_of_each_variant() {
    assert_eq!(
      m.encoded_len(),
      encode_message(&m).len(),
      "encoded_len() must equal encode_message().len() for {}",
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
  assert_eq!(rq.encoded_len(), encode_message(&rq).len());
}

#[test]
fn a_reply_with_worst_case_scalars_at_the_body_bound_fits_the_frame_cap() {
  // `max_reply_body_len()` subtracts `REPLY_ENCODE_OVERHEAD` — the protobuf WORST-CASE overhead,
  // every scalar charged its varint-widest — from the frame cap, so a reply body of exactly the
  // bound must fit `MAX_FRAME_LEN` even when every other field genuinely encodes at that widest
  // (u64::MAX view/request, u128::MAX client). Load-bearing: an already-committed op has no
  // in-protocol recovery if its cached reply cannot be sent (`StateMachine::apply` carries the
  // bound as an embedder obligation), so the bound must hold for EVERY field value, not just small
  // ones whose varints shrink.
  let reply = Message::Reply(Reply::new(
    View::with(u64::MAX),
    ClientId::new(u128::MAX),
    RequestNumber::with(u64::MAX),
    Bytes::from(std::vec![0u8; max_reply_body_len()]),
  ));
  let encoded = encode_message(&reply).len();
  let cap = MAX_FRAME_LEN as usize;
  assert!(
    encoded <= cap,
    "a worst-case-scalar Reply at the body bound must fit the frame cap: {encoded} > {cap}"
  );
}

#[test]
fn batch_carriers_with_worst_case_scalars_at_the_modeled_budget_fit_the_frame_cap() {
  // The byte-bounded serve (`RepairBatch`) and the batched retransmit (`PrepareBatch`) accumulate
  // entries against `MAX_FRAME_LEN - *_CARRIER_OVERHEAD` charging `present_entry_encoded_len` per
  // entry — both protobuf WORST-CASE models. A batch built to exactly fill that modeled budget must
  // fit the frame once actually encoded, even with every scalar at its varint-widest (u64::MAX
  // ops/views, u128::MAX ids), as a single entry or split across two — so the accumulators can
  // never emit an oversized frame whatever the field values.
  let cap = MAX_FRAME_LEN as usize;
  let entry_of = |len: usize| {
    PreparedEntry::new(
      OpNumber::with(u64::MAX),
      ClientId::new(u128::MAX),
      RequestNumber::with(u64::MAX),
      Bytes::from(std::vec![0u8; len]),
    )
  };
  let prepare_batch_of = |entries: std::vec::Vec<PreparedEntry>| {
    Message::PrepareBatch(PrepareBatch::new(
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      crate::Epoch::new(u64::MAX),
      u128::MAX,
      entries,
    ))
  };
  let repair_batch_of = |entries: std::vec::Vec<PreparedEntry>| {
    Message::RepairBatch(RepairBatch::new(
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      u128::MAX,
      entries,
    ))
  };

  for (name, carrier_overhead, batch_of) in [
    (
      "PrepareBatch",
      PREPARE_BATCH_CARRIER_OVERHEAD,
      &prepare_batch_of as &dyn Fn(std::vec::Vec<PreparedEntry>) -> Message,
    ),
    (
      "RepairBatch",
      REPAIR_BATCH_CARRIER_OVERHEAD,
      &repair_batch_of,
    ),
  ] {
    let budget = cap - carrier_overhead;
    // Single entry filling the whole modeled budget.
    let max = budget - present_entry_encoded_len(0);
    let one = encode_message(&batch_of(std::vec![entry_of(max)])).len();
    assert!(
      one <= cap,
      "a worst-case-scalar one-entry {name} filling the modeled budget must fit the frame cap: \
       {one} > {cap}"
    );
    // Two entries splitting the modeled budget.
    let half = budget / 2;
    let (a, b) = (
      half - present_entry_encoded_len(0),
      (budget - half) - present_entry_encoded_len(0),
    );
    assert_eq!(
      present_entry_encoded_len(a) + present_entry_encoded_len(b),
      budget
    );
    let two = encode_message(&batch_of(std::vec![entry_of(a), entry_of(b)])).len();
    assert!(
      two <= cap,
      "a worst-case-scalar two-entry {name} splitting the modeled budget must fit the frame cap: \
       {two} > {cap}"
    );
  }
}

/// The transport's `max_request_body_len()` bounds the largest client body deliverable on EVERY
/// message that can carry it. The view-change log carriers (`DoViewChange` / `StartView` /
/// `RecoveryResponse`) are HEADER-ONLY (they ship no body — see `Endpoint::log_entries`), so the
/// SAME body bytes travel only as the `Request` the client sends, the `Prepare` the primary
/// replicates, and — once the op is logged — a single `Body::Present` `PreparedEntry` inside a
/// `RepairBatch` (the windowed peer-repair answer) or a `PrepareBatch` (the primary's batched
/// retransmit). `MAX_REQUEST_BODY_OVERHEAD` is the protobuf WORST-CASE overhead over all of those
/// carriers, so this builds each with EVERY scalar at its varint-widest (u64::MAX views/ops/epochs/
/// request, u128::MAX ids) plus a body of exactly the bound and checks the ACTUAL
/// `encode_message(..).len()` fits `MAX_FRAME_LEN` — the maximal-scalar case is precisely the one a
/// small-value fixture would mask. Also pins the header-only `DoViewChange` staying INSENSITIVE to
/// body size. Enumerating every carrier here means a future message that wraps the body in MORE
/// framing fails this test until the bound accounts for it.
#[cfg(feature = "tcp")]
#[test]
fn every_body_carrier_with_worst_case_scalars_at_the_body_bound_fits_the_frame_cap() {
  use crate::{MAX_FRAME_LEN, max_request_body_len};

  let max = max_request_body_len();
  let cap = MAX_FRAME_LEN as usize;

  let client = ClientId::new(u128::MAX);
  let request = RequestNumber::with(u64::MAX);

  // Each closure builds a real message that carries a body of `len` bytes. The `RepairBatch` and
  // `PrepareBatch` wrap it in a single-entry `Body::Present` log slice — the worst case for one
  // maximal body (a multi-entry batch only spreads more fixed framing across more bodies; the
  // byte-bounded serve/retransmit never exceeds the cap).
  let body_of = |len: usize| Bytes::from(std::vec![0u8; len]);
  let request_of = |len: usize| Message::Request(Request::new(client, request, body_of(len)));
  let prepare_of = |len: usize| {
    Message::Prepare(Prepare::new(
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      crate::Epoch::new(u64::MAX),
      u128::MAX,
      client,
      request,
      body_of(len),
    ))
  };
  let repair_batch_of = |len: usize| {
    Message::RepairBatch(RepairBatch::new(
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      u128::MAX,
      std::vec![PreparedEntry::new(
        OpNumber::with(u64::MAX),
        client,
        request,
        body_of(len),
      )],
    ))
  };
  let prepare_batch_of = |len: usize| {
    Message::PrepareBatch(PrepareBatch::new(
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      crate::Epoch::new(u64::MAX),
      u128::MAX,
      std::vec![PreparedEntry::new(
        OpNumber::with(u64::MAX),
        client,
        request,
        body_of(len),
      )],
    ))
  };

  // Every BODY carrier of a bound-size body, paired with its builder, checked by its REAL encoded
  // length at maximal scalars.
  let carriers: [(&str, &dyn Fn(usize) -> Message); 4] = [
    ("Request", &request_of),
    ("Prepare", &prepare_of),
    ("RepairBatch", &repair_batch_of),
    ("PrepareBatch", &prepare_batch_of),
  ];
  for (name, build) in carriers {
    let encoded = encode_message(&build(max)).len();
    assert!(
      encoded <= cap,
      "a worst-case-scalar {name} carrying a bound-size body must fit the frame cap: \
       {encoded} > {cap}"
    );
  }

  // The header-only view-change carriers are INSENSITIVE to body size: a `DoViewChange` whose entry
  // is header-only (`Repairing`) encodes the same whether the op's body is empty or `max` bytes —
  // it ships only the 16-byte `body_checksum`. So a max-body op rides a view change far under the
  // frame cap, the whole point of the header-only carrier. (The DEEP-band fit is pinned separately
  // by `a_worst_case_header_only_band_at_max_depth_fits_the_frame_cap`.)
  let header_only_dvc = Message::DoViewChange(DoViewChange::new(
    View::with(u64::MAX),
    View::with(u64::MAX),
    OpNumber::with(u64::MAX),
    OpNumber::with(u64::MAX),
    crate::Epoch::new(u64::MAX),
    u128::MAX,
    ReplicaId::new(u16::MAX),
    std::vec![PreparedEntry::repairing(
      OpNumber::with(u64::MAX),
      client,
      request,
      u128::MAX,
    )],
  ));
  assert!(
    encode_message(&header_only_dvc).len() < cap / 2,
    "a header-only DoViewChange entry is body-size-insensitive and well under the frame cap"
  );
}

#[test]
fn a_worst_case_header_only_band_at_max_depth_fits_the_frame_cap() {
  // `MAX_HEADER_ONLY_BAND_DEPTH` divides the frame budget (less a fixed carrier allowance) by
  // `PER_HEADER_ENTRY_BYTES`, the protobuf WORST-CASE size of one header-only (`Repairing`) entry.
  // A band of exactly that many entries with EVERY scalar at its varint-widest (u64::MAX op and
  // request, u128::MAX client and checksum), riding the two largest-carrier view-change messages
  // (`DoViewChange` and `RecoveryResponse` tie, with maximal carrier scalars too), must encode
  // within `MAX_FRAME_LEN` — the deepest band the admission gate ever lets accumulate stays
  // deliverable whatever the field values.
  let cap = MAX_FRAME_LEN as usize;
  let entry = PreparedEntry::repairing(
    OpNumber::with(u64::MAX),
    ClientId::new(u128::MAX),
    RequestNumber::with(u64::MAX),
    u128::MAX,
  );
  let band: std::vec::Vec<PreparedEntry> = std::vec![entry; MAX_HEADER_ONLY_BAND_DEPTH];
  let dvc = Message::DoViewChange(
    DoViewChange::new(
      View::with(u64::MAX),
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      crate::Epoch::new(u64::MAX),
      u128::MAX,
      ReplicaId::new(u16::MAX),
      band.clone(),
    )
    .with_checkpoint_op(OpNumber::with(u64::MAX)),
  );
  let rr = Message::RecoveryResponse(
    RecoveryResponse::new(
      View::with(u64::MAX),
      OpNumber::with(u64::MAX),
      OpNumber::with(u64::MAX),
      crate::Epoch::new(u64::MAX),
      u128::MAX,
      ReplicaId::new(u16::MAX),
      u64::MAX,
      band,
    )
    .with_checkpoint_op(OpNumber::with(u64::MAX)),
  );
  for m in [&dvc, &rr] {
    let encoded = encode_message(m).len();
    assert!(
      encoded <= cap,
      "a worst-case-scalar {} carrying a MAX_HEADER_ONLY_BAND_DEPTH band must fit the frame cap: \
       {encoded} > {cap}",
      m.kind_str()
    );
  }
}

#[test]
fn every_variant_round_trips_through_the_wire_codec() {
  let all = one_of_each_variant();
  assert_eq!(all.len(), 24, "every Message variant is represented");
  for m in &all {
    let bytes = encode_message(m);
    let back = decode_message(bytes).expect("round-trip decodes");
    assert_eq!(&back, m, "decode(encode(m)) == m for {}", m.kind_str());
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
  assert_eq!(decode_message(encode_message(&rq)).unwrap(), rq);
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
    let back = decode_message(encode_message(m)).expect("round-trips");
    assert_eq!(&back, m, "decode(encode(m)) == m for {}", m.kind_str());
  }
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
  let back = decode_message(encode_message(&dvc)).expect("round-trips");
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
  let log = decode_message(encode_message(&rb))
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
fn reconfigure_encoded_len_matches_encode_and_respects_the_frame_cap() {
  // The full-voting-set successor membership (64 voters) is the worst case for one Reconfigure
  // entry; its preflight size matches encode_message and stays well under the frame cap.
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
  let encoded = encode_message(&rb);
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
fn decode_never_panics_on_truncations_or_random_bytes() {
  // Fuzz-style no-panic sweep: every prefix of every variant's encoding, plus a pseudo-random
  // stream of growing length, must always yield a typed error (or, for a prefix short enough to
  // still be a structurally-valid — if incomplete — protobuf message, an `Ok`) — never a panic or
  // out-of-range index.
  for m in one_of_each_variant() {
    let enc = encode_message(&m);
    for n in 0..=enc.len() {
      let _ = decode_message(enc.slice(..n));
    }
  }
  let mut x = 0x1357_9bdfu32;
  for len in 0..600usize {
    let mut v = std::vec::Vec::with_capacity(len);
    for _ in 0..len {
      x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
      v.push((x >> 24) as u8);
    }
    let _ = decode_message(Bytes::from(v)); // must not panic
  }
}

#[test]
fn request_block_and_block_response_round_trip_through_the_wire_codec() {
  let addr = crate::block_store::block_address(b"some-block-bytes");

  // RequestBlock: a fixed 16-byte payload carrying the content address.
  let req = Message::RequestBlock(addr);
  let back = decode_message(encode_message(&req)).expect("RequestBlock round-trips");
  assert_eq!(back, req, "decode(encode(RequestBlock)) == RequestBlock");
  assert!(
    !req.advertises_authoritative_view(),
    "a block solicitation carries no view authority",
  );

  // BlockResponse with a present block.
  let block_bytes = Bytes::from_static(b"some-block-bytes");
  let present = Message::BlockResponse(BlockResponse::new(addr, Some(block_bytes.clone())));
  let back = decode_message(encode_message(&present)).expect("BlockResponse(Some) round-trips");
  assert_eq!(
    back, present,
    "decode(encode(BlockResponse(Some))) == present"
  );
  let br = back.unwrap_block_response();
  assert_eq!(br.addr(), addr);
  assert_eq!(br.block(), Some(block_bytes.as_ref()));

  // BlockResponse with an absent block (donor does not hold this address).
  let absent = Message::BlockResponse(BlockResponse::new(addr, None));
  let back = decode_message(encode_message(&absent)).expect("BlockResponse(None) round-trips");
  assert_eq!(
    back, absent,
    "decode(encode(BlockResponse(None))) == absent"
  );
  let br = back.unwrap_block_response();
  assert_eq!(br.addr(), addr);
  assert_eq!(br.block(), None);
  assert!(br.is_absent(), "None block is absent");
  assert!(!br.is_present(), "None block is not present");

  // encoded_len matches encode_message().len() for both shapes.
  assert_eq!(present.encoded_len(), encode_message(&present).len());
  assert_eq!(absent.encoded_len(), encode_message(&absent).len());
}

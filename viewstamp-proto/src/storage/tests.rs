use super::*;
use crate::{ClientId, Epoch, MemberId, Membership, OpNumber, RequestNumber, View};

#[test]
fn checkpoint_id_is_deterministic_and_sensitive() {
  let a = checkpoint_id(b"snapshot-bytes");
  assert_eq!(a, checkpoint_id(b"snapshot-bytes"), "deterministic");
  assert_ne!(
    a,
    checkpoint_id(b"snapshot-byteS"),
    "a flipped byte changes the id"
  );
  assert_ne!(a, checkpoint_id(b""), "empty differs from non-empty");
}

#[test]
fn header_checksum_detects_corruption() {
  let h = Header::new(
    OpNumber::with(1),
    View::with(0),
    ClientId::new(7),
    RequestNumber::with(1),
    b"hello",
  );
  assert!(h.verify(b"hello"));
  assert!(!h.verify(b"hellp")); // a flipped body byte fails verification
  assert_eq!(h.version(), HEADER_VERSION);

  // A tampered header field (without recomputing the checksum) must also fail verify.
  let mut tampered = h;
  tampered.op = OpNumber::with(2);
  assert!(
    !tampered.verify(b"hello"),
    "a tampered header field must fail verify"
  );
}

#[test]
fn vsr_state_rejects_bad_invariants() {
  assert!(
    VsrState::try_new(
      View::with(1),
      View::with(2),
      OpNumber::with(0),
      OpNumber::with(0),
      0,
      std::vec::Vec::new(),
    )
    .is_err()
  );
  assert!(
    VsrState::try_new(
      View::with(2),
      View::with(1),
      OpNumber::with(1),
      OpNumber::with(3),
      0,
      std::vec::Vec::new(),
    )
    .is_err()
  );
  let s = VsrState::try_new(
    View::with(3),
    View::with(3),
    OpNumber::with(5),
    OpNumber::with(4),
    99,
    std::vec::Vec::new(),
  )
  .unwrap();
  assert_eq!(s.commit(), OpNumber::with(5));
  assert_eq!(s.checkpoint_id(), 99);
  assert!(s.committed_headers_slice().is_empty());
}

#[test]
fn vsr_state_keeps_a_sparse_in_band_header_set_verbatim() {
  // Build canonical headers for ops in the committed band above checkpoint_op = 2, commit = 5.
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::with(1),
      ClientId::new(1),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // A contiguous full band (3,4,5) is kept verbatim.
  let s = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::with(5),
    OpNumber::with(2),
    0,
    std::vec![mk(3), mk(4), mk(5)],
  )
  .unwrap();
  assert_eq!(s.committed_headers_slice().len(), 3);
  assert_eq!(s.committed_headers_slice()[0].op(), OpNumber::with(3));

  // A GAP after op 3 (3, then 5 — op 4 a hole) is now KEPT verbatim: the held op 5
  // above the op-4 hole retains its canonical header so recovery can verify it individually.
  let holed = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::with(5),
    OpNumber::with(2),
    0,
    std::vec![mk(3), mk(5)],
  )
  .unwrap();
  assert_eq!(
    holed
      .committed_headers_slice()
      .iter()
      .map(|h| h.op().get())
      .collect::<std::vec::Vec<_>>(),
    std::vec![3, 5],
    "the sparse set (gap at op 4) is kept verbatim, not truncated at the gap"
  );

  // A header ABOVE commit is REJECTED (only the committed band is persisted): commit = 3, op 4 > commit.
  assert_eq!(
    VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(3),
      OpNumber::with(2),
      0,
      std::vec![mk(3), mk(4)],
    ),
    Err(VsrStateError::HeaderOutOfBand)
  );
}

#[test]
fn vsr_state_accepts_a_sparse_in_band_header_set_but_rejects_a_malformed_one() {
  // the committed-band header set is now a SPARSE canonical-header set over the held
  // committed ops, NOT a contiguous prefix. `try_new` ACCEPTS an in-range, strictly-increasing set
  // even with GAPS (a held op above a lower hole keeps its header), but REJECTS an out-of-range,
  // non-ascending, or duplicate set rather than silently truncating a valid sparse list.
  let mk = |op: u64| {
    Header::new(
      OpNumber::with(op),
      View::with(1),
      ClientId::new(1),
      RequestNumber::with(op),
      &[op as u8],
    )
  };
  // ACCEPT: a sparse set [op1, op3] with commit = 3, checkpoint = 0 — the gap at op 2 is allowed and
  // BOTH headers are kept verbatim (op 3 is a held canonical op above the op-2 hole).
  let sparse = VsrState::try_new(
    View::with(1),
    View::with(1),
    OpNumber::with(3),
    OpNumber::new(),
    0,
    std::vec![mk(1), mk(3)],
  )
  .unwrap();
  assert_eq!(
    sparse
      .committed_headers_slice()
      .iter()
      .map(|h| h.op().get())
      .collect::<std::vec::Vec<_>>(),
    std::vec![1, 3],
    "a sparse in-band set is kept verbatim (the gap at op 2 is allowed)"
  );

  // REJECT: an op AT/BELOW the checkpoint (out of band below).
  assert_eq!(
    VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(5),
      OpNumber::with(2),
      0,
      std::vec![mk(2), mk(3)], // op 2 == checkpoint_op — must be strictly above it
    ),
    Err(VsrStateError::HeaderOutOfBand)
  );
  // REJECT: an op ABOVE commit (out of band above).
  assert_eq!(
    VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(3),
      OpNumber::new(),
      0,
      std::vec![mk(1), mk(4)], // op 4 > commit 3
    ),
    Err(VsrStateError::HeaderOutOfBand)
  );
  // REJECT: a non-ascending set (op 3 then op 1).
  assert_eq!(
    VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(5),
      OpNumber::new(),
      0,
      std::vec![mk(3), mk(1)],
    ),
    Err(VsrStateError::HeadersNotAscending)
  );
  // REJECT: a duplicate op (op 3 twice) — not strictly increasing.
  assert_eq!(
    VsrState::try_new(
      View::with(1),
      View::with(1),
      OpNumber::with(5),
      OpNumber::new(),
      0,
      std::vec![mk(3), mk(3)],
    ),
    Err(VsrStateError::HeadersNotAscending)
  );
}

#[test]
fn slot_status_as_str_and_predicates() {
  assert_eq!(SlotStatus::Faulty.as_str(), "faulty");
  assert!(SlotStatus::Clean.is_clean());
}

#[test]
fn wal_done_variants() {
  let r = ReadOk::new(
    OpId::new(1),
    Header::new(
      OpNumber::with(1),
      View::new(),
      ClientId::new(1),
      RequestNumber::with(1),
      b"x",
    ),
    bytes::Bytes::from_static(b"x"),
  );
  let d = WalDone::ReadOk(r);
  assert!(d.is_read_ok());
  assert_eq!(d.unwrap_read_ok().op(), OpNumber::with(1));
}

#[test]
fn body_faulty_round_trips_id_and_header() {
  let id = OpId::new(42);
  let header = Header::new(
    OpNumber::with(7),
    View::with(2),
    ClientId::new(9),
    RequestNumber::with(3),
    b"payload",
  );
  let bf = BodyFaulty::new(id, header);
  assert_eq!(bf.id(), id, "id round-trips");
  assert_eq!(bf.header(), header, "header round-trips");
  // Can be wrapped in WalDone::BodyFaulty.
  let done = WalDone::BodyFaulty(bf);
  assert!(done.is_body_faulty());
  assert_eq!(done.unwrap_body_faulty().id(), id);
}

// ── disk codec: Header + VsrState ──

use crate::codec::CodecError;

fn mk_header(op: u64, view: u64, client: u128, req: u64, body: &[u8]) -> Header {
  Header::new(
    OpNumber::with(op),
    View::with(view),
    ClientId::new(client),
    RequestNumber::with(req),
    body,
  )
}

#[test]
fn header_round_trips_including_edge_values() {
  for h in [
    Header::new(
      OpNumber::new(),
      View::new(),
      ClientId::new(0),
      RequestNumber::new(),
      b"",
    ),
    mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body"),
    mk_header(u64::MAX, u64::MAX, u128::MAX, u64::MAX, b"max-edge-values"),
  ] {
    let bytes = h.encode();
    assert_eq!(bytes.len(), HEADER_ENCODED_LEN, "fixed-size encoding");
    let back = Header::decode(&bytes).expect("round-trip decodes");
    assert_eq!(back, h, "decode(encode(h)) == h");
  }
}

#[test]
fn header_decode_re_derives_the_same_checksum_and_shares_canonical_bytes() {
  let h = mk_header(
    7,
    3,
    0x1234_5678_9abc_def0_1122_3344_5566_7788,
    9,
    b"payload",
  );
  let bytes = h.encode();
  // The decoded header carries the stored checksum unchanged …
  let back = Header::decode(&bytes).expect("decodes");
  assert_eq!(back.checksum(), h.checksum(), "stored checksum preserved");
  // … and is self-consistent (re-derived checksum == stored) on its original body.
  assert!(back.verify(b"payload"), "decoded header verifies");
  // The encoded buffer's canonical region (after the 16-byte checksum, before the reserved
  // padding) is EXACTLY the bytes compute_checksum hashes — i.e. the codec and the checksum
  // share one definition: hashing the embedded canonical region reproduces the
  // checksum the writer stored.
  let canonical = &bytes[16..16 + HEADER_CANONICAL_LEN];
  assert_eq!(
    fnv1a_128(canonical),
    h.checksum(),
    "the encoded canonical bytes are what the checksum hashes"
  );
}

#[test]
fn header_checksum_value_is_unchanged_by_the_canonical_refactor() {
  // Pin the checksum of a fixed input: if write_canonical ever reorders/rewidens a field
  // (changing the on-disk checksum for already-persisted data), this golden value FAILS,
  // surfacing the format break the task said to STOP on.
  let h = mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body");
  assert_eq!(
    h.checksum(),
    0xe72c_624b_7c30_e993_d822_b02e_38c3_c2d9,
    "the canonical refactor must not change an existing checksum value"
  );
}

#[test]
fn header_golden_bytes_pin_the_layout() {
  // A future field reorder / layout change FAILS this exact-bytes assertion (format-stability
  // guard): checksum(16) ++ version|op|view|client|request|body_checksum (each u128 BE) ++
  // reserved zero padding, totalling HEADER_ENCODED_LEN.
  let h = mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body");
  let expected: [u8; HEADER_ENCODED_LEN] = [
    231, 44, 98, 75, 124, 48, 233, 147, 216, 34, 176, 46, 56, 195, 194, 217, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 105, 137, 79, 111, 118, 117, 114, 119, 184, 6, 233, 126,
    145, 224, 157, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ];
  assert_eq!(h.encode(), expected, "Header wire layout is pinned");
}

#[test]
fn header_decode_rejects_truncation_and_bad_version_without_panicking() {
  let good = mk_header(1, 1, 1, 1, b"x").encode();
  // A short buffer → Truncated, never a panic.
  assert!(matches!(
    Header::decode(&good[..HEADER_ENCODED_LEN - 1]),
    Err(CodecError::Truncated { .. })
  ));
  assert!(matches!(
    Header::decode(&[]),
    Err(CodecError::Truncated { .. })
  ));
  // Trailing bytes beyond the fixed slot → TrailingBytes.
  let mut over = good.to_vec();
  over.push(0);
  assert!(matches!(
    Header::decode(&over),
    Err(CodecError::TrailingBytes(1))
  ));
  // A bad version → UnknownVersion. The version is the widened u128 at bytes 16..32 (after the
  // 16-byte checksum); its significant low byte is index 31. Setting it to 9 makes version_raw
  // = 9 (fits u16), so the report is UnknownVersion(9).
  let mut badver = good;
  badver[31] = 9;
  assert!(matches!(
    Header::decode(&badver),
    Err(CodecError::UnknownVersion(9))
  ));
  // A version whose widened word does not even fit u16 (a high byte set) saturates the report
  // at u16::MAX rather than panicking.
  let mut hugever = good;
  hugever[16] = 1; // top byte of the u128 version word
  assert!(matches!(
    Header::decode(&hugever),
    Err(CodecError::UnknownVersion(u16::MAX))
  ));
}

#[test]
fn header_decode_never_panics_on_arbitrary_short_or_random_bytes() {
  // Fuzz-style no-panic loop over truncations + a pseudo-random stream: every length-checked
  // read returns an error, so no input panics / indexes out of range.
  let good = mk_header(3, 3, 3, 3, b"abc").encode();
  for n in 0..=HEADER_ENCODED_LEN + 4 {
    let mut v = good.to_vec();
    v.truncate(n.min(v.len()));
    while v.len() < n {
      v.push((n as u8).wrapping_mul(31));
    }
    let _ = Header::decode(&v); // must not panic
  }
  let mut x = 0x1234_5678u32;
  for len in 0..300usize {
    let mut v = std::vec::Vec::with_capacity(len);
    for _ in 0..len {
      x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
      v.push((x >> 24) as u8);
    }
    let _ = Header::decode(&v); // must not panic
  }
}

#[test]
fn vsr_state_round_trips_empty_and_populated() {
  // Empty committed-band header set.
  let empty = VsrState::new();
  assert_eq!(
    VsrState::decode(&empty.encode()).expect("empty round-trips"),
    empty
  );
  // Populated, sparse (gap at op 4), with edge scalar values.
  let populated = VsrState::try_new(
    View::with(u64::MAX),
    View::with(u64::MAX - 1),
    OpNumber::with(9),
    OpNumber::with(2),
    u128::MAX,
    std::vec![mk_header(3, 1, 7, 3, b"a"), mk_header(5, 1, 7, 5, b"bb")],
  )
  .unwrap();
  let back = VsrState::decode(&populated.encode()).expect("populated round-trips");
  assert_eq!(back, populated, "decode(encode(state)) == state");
  assert_eq!(
    back
      .committed_headers_slice()
      .iter()
      .map(|h| h.op().get())
      .collect::<std::vec::Vec<_>>(),
    std::vec![3, 5],
    "the sparse header set survives the round-trip verbatim"
  );
}

#[test]
fn vsr_state_golden_bytes_pin_the_layout() {
  // The v6 layout: the byte-identical v1-3 body (version|view|log_view|commit|checkpoint_op|
  // checkpoint_id|header-count|headers), then the v4 epoch/membership tail (epoch|prev_epoch|present,
  // then the membership block when present), then the v5 lineage tail (prior_config_count|ids), then the
  // v6 `config_install_op` scalar (u64). The epoch-1 membership matches the root's epoch-1 scalar; the
  // lineage carries two superseded ids; `config_install_op = 7` is the reconfigure op (appended last).
  let h = mk_header(7, 3, 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10, 9, b"body");
  let mem = Membership::genesis(
    2,
    1,
    std::vec![MemberId::new(10), MemberId::new(11), MemberId::new(12)],
  )
  .unwrap()
  .reconfigure(
    2,
    1,
    std::vec![MemberId::new(10), MemberId::new(11), MemberId::new(13)],
  )
  .unwrap();
  let st = VsrState::try_new_v4(
    View::with(4),
    View::with(2),
    OpNumber::with(7),
    OpNumber::with(5),
    0xAABB_CCDD,
    std::vec![h],
    Epoch::new(1),
    Epoch::new(0),
    mem,
    std::vec![0x1111_2222, 0x3333_4444],
    OpNumber::with(7),
  )
  .unwrap();
  let expected: std::vec::Vec<u8> = std::vec![
    0, 6, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
    0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 187, 204, 221, 0, 0, 0, 1, 231, 44, 98, 75, 124,
    48, 233, 147, 216, 34, 176, 46, 56, 195, 194, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 9, 105, 137, 79, 111, 118, 117, 114, 119, 184, 6, 233, 126, 145, 224, 157, 189, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    192, 68, 74, 98, 107, 133, 78, 12, 26, 29, 162, 224, 5, 155, 168, 242, 0, 0, 0, 0, 0, 0, 0, 1,
    2, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 2, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11, 0x22, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x33,
    0x33, 0x44, 0x44, 0, 0, 0, 0, 0, 0, 0, 7,
  ];
  assert_eq!(st.encode(), expected, "VsrState wire layout is pinned");
  // The pinned golden bytes are a valid decode input too: they round-trip back to the same root.
  assert_eq!(
    VsrState::decode(&expected).unwrap(),
    st,
    "the pinned golden root round-trips through decode"
  );
}

/// The exact bytes of a version-3 (pre-membership) durable root — the layout `VsrState::encode`
/// wrote BEFORE the epoch/membership tail existed. Pinned verbatim so the legacy-migration path
/// (`decode` of a v1-3 root) keeps a real on-disk witness, independent of the live v4 encoder.
fn legacy_v3_golden_bytes() -> std::vec::Vec<u8> {
  std::vec![
    0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
    0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 187, 204, 221, 0, 0, 0, 1, 231, 44, 98, 75, 124,
    48, 233, 147, 216, 34, 176, 46, 56, 195, 194, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 9, 105, 137, 79, 111, 118, 117, 114, 119, 184, 6, 233, 126, 145, 224, 157, 189, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  ]
}

#[test]
fn vsr_state_round_trips_epoch_and_membership() {
  // A v4 root's scalar epoch MUST equal its membership's own epoch (try_new_v4 enforces this), so the
  // epoch-1 root carries an epoch-1 membership: a reconfigured successor of an epoch-0 genesis.
  let mem = Membership::genesis(
    3,
    0,
    std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
  )
  .unwrap()
  .reconfigure(
    3,
    0,
    std::vec![MemberId::new(1), MemberId::new(2), MemberId::new(4)],
  )
  .unwrap();
  assert_eq!(mem.epoch(), Epoch::new(1));
  // The recent-prior lineage (the predecessor genesis id) is carried verbatim and restored.
  let lineage = std::vec![0xDEAD_BEEFu128, 0xC0FF_EE00u128];
  let s = VsrState::try_new_v4(
    View::with(2),
    View::with(2),
    OpNumber::with(9),
    OpNumber::with(4),
    0xABCD,
    std::vec![],
    Epoch::new(1),
    Epoch::new(0),
    mem.clone(),
    lineage.clone(),
    OpNumber::with(6),
  )
  .unwrap();
  let bytes = s.encode();
  let back = VsrState::decode(&bytes).unwrap();
  assert_eq!(back.epoch(), Epoch::new(1));
  assert_eq!(back.prev_epoch(), Epoch::new(0));
  assert_eq!(back.membership(), &mem);
  assert_eq!(
    back.prior_config_ids(),
    lineage.as_slice(),
    "the recent-prior lineage round-trips verbatim"
  );
  assert_eq!(
    back.config_install_op(),
    OpNumber::with(6),
    "config_install_op round-trips verbatim"
  );
  assert_eq!(back, s);
}

#[test]
fn vsr_state_decodes_legacy_v3_as_epoch_zero_without_membership() {
  // A v3 root (no epoch/membership) must decode into a value whose epoch is 0
  // and whose membership is ABSENT (filled by recover from Config).
  let legacy = legacy_v3_golden_bytes();
  let back = VsrState::decode(&legacy).unwrap();
  assert_eq!(back.epoch(), Epoch::new(0));
  assert_eq!(back.prev_epoch(), Epoch::new(0));
  assert!(
    back.membership_opt().is_none(),
    "legacy root carries no membership"
  );
}

#[test]
fn vsr_state_decode_accepts_the_whole_layout_compatible_version_range() {
  // A version names a disk LAYOUT, and decode dispatches per layout. Versions 1..=3 are ONE
  // pre-membership layout (the pre-decoupling message/disk coupling stamped that single body with 1,
  // 2, AND 3), so a root carrying ANY of them decodes to the SAME legacy-bridged state (epoch 0, no
  // membership) and none is stranded. Version 4 is a SECOND layout (body + epoch/membership tail),
  // version 5 a THIRD (that plus the lineage tail), and version 6 (= SUPERBLOCK_VERSION) a FOURTH (that
  // plus the `config_install_op` scalar). Together with the root carrying its OWN version, independent of
  // the message WIRE_VERSION, this keeps the decoupling correct-by-construction — a message-only
  // WIRE_VERSION bump can never invalidate a persisted root.
  //
  // The pre-membership 1..=3 layout: a true v3 body (NOT a relabelled v4/v5/v6 root, whose appended tails
  // would become trailing bytes under the legacy path) decodes identically under every legacy tag.
  let legacy_v3 = legacy_v3_golden_bytes();
  let bridged = VsrState::decode(&legacy_v3).unwrap();
  assert_eq!(bridged.epoch(), Epoch::new(0));
  assert!(bridged.membership_opt().is_none());
  for v in 1u16..=3 {
    let mut tagged = legacy_v3.clone();
    tagged[0..2].copy_from_slice(&v.to_be_bytes());
    assert_eq!(
      VsrState::decode(&tagged).unwrap(),
      bridged,
      "a pre-membership root tagged with legacy version {v} decodes to the same bridged state"
    );
  }
  // The v6 layout: a NEW root is written with SUPERBLOCK_VERSION (= 6) and round-trips under it.
  let mem = Membership::genesis(3, 0, (1..=3).map(MemberId::new).collect()).unwrap();
  let v6 = VsrState::try_new_v4(
    View::with(2),
    View::with(1),
    OpNumber::with(5),
    OpNumber::with(4),
    0xAABB,
    std::vec![],
    Epoch::new(0),
    Epoch::new(0),
    mem,
    std::vec![0x9999u128],
    OpNumber::with(3),
  )
  .unwrap();
  let v6_bytes = v6.encode();
  assert_eq!(
    &v6_bytes[0..2],
    &SUPERBLOCK_VERSION.to_be_bytes(),
    "a new durable root leads with SUPERBLOCK_VERSION"
  );
  assert_eq!(SUPERBLOCK_VERSION, 6, "the accepted decode range is 1..=6");
  assert_eq!(
    VsrState::decode(&v6_bytes).unwrap(),
    v6,
    "the v6 root round-trips"
  );
  // A v5 root (the lineage tail but NO config_install_op tail) still decodes — built by truncating the
  // v6 `config_install_op` scalar (a trailing `u64`) and re-tagging as v5. It decodes with
  // `config_install_op` DEFAULTED to its `checkpoint_op` (the pre-v6 serve behaviour) — so no persisted
  // v5 root is stranded by the bump.
  let mut v5_bytes = v6_bytes.to_vec();
  v5_bytes.truncate(v5_bytes.len() - 8); // drop the config_install_op scalar
  v5_bytes[0..2].copy_from_slice(&5u16.to_be_bytes());
  let v5_decoded = VsrState::decode(&v5_bytes).expect("a v5 root still decodes");
  assert_eq!(
    v5_decoded.config_install_op(),
    OpNumber::with(4),
    "a v5 root defaults config_install_op to its checkpoint_op"
  );
  assert_eq!(
    v5_decoded.prior_config_ids(),
    &[0x9999u128],
    "a v5 root keeps its lineage"
  );
  // A v4 root (the membership tail but NO lineage NOR config_install_op tail) still decodes — built by
  // dropping BOTH the config_install_op scalar (u64) and the lineage block (a count-1 block: its trailing
  // `u32` count + one `u128`) and re-tagging as v4. It decodes with an EMPTY lineage and a defaulted
  // config_install_op (recover seeds the lineage from the current id, the pre-v5 behaviour) — so no
  // persisted v4 root is stranded by the bump.
  let mut v4_bytes = v6_bytes.to_vec();
  v4_bytes.truncate(v4_bytes.len() - 8 - (4 + 16)); // drop config_install_op + the lineage block
  v4_bytes[0..2].copy_from_slice(&4u16.to_be_bytes());
  let v4_decoded = VsrState::decode(&v4_bytes).expect("a v4 root still decodes");
  assert!(
    v4_decoded.prior_config_ids().is_empty(),
    "a v4 root carries no durable lineage (recover seeds from the current id)"
  );
  assert_eq!(
    v4_decoded.config_install_op(),
    OpNumber::with(4),
    "a v4 root defaults config_install_op to its checkpoint_op"
  );
  assert_eq!(v4_decoded.epoch(), Epoch::new(0));
  assert_eq!(
    v4_decoded.membership_opt().map(|m| m.replica_count()),
    Some(3)
  );
  // Versions OUTSIDE the accepted range fail CLEAN (never misparse): 0 and one past the high end.
  for bad in [0u16, SUPERBLOCK_VERSION + 1] {
    let mut wrong = v6_bytes.to_vec();
    wrong[0..2].copy_from_slice(&bad.to_be_bytes());
    assert!(
      matches!(VsrState::decode(&wrong), Err(CodecError::UnknownVersion(v)) if v == bad),
      "version {bad} is outside the accepted range and is rejected as unknown"
    );
  }
}

#[test]
fn vsr_state_decode_rejects_corruption_without_panicking() {
  let st = VsrState::try_new(
    View::with(4),
    View::with(2),
    OpNumber::with(7),
    OpNumber::with(5),
    0xAABB_CCDD,
    std::vec![mk_header(6, 1, 1, 6, b"z")],
  )
  .unwrap();
  // `st` is built via `try_new`, so it encodes as a v6 root whose membership-present flag is 0 (a
  // legacy-bridged shape): version(2) | body | header-count | header | epoch(8) | prev_epoch(8) |
  // present(1) | lineage_count(4) (= 0, no ids) | config_install_op(8). The corruption probes target that
  // exact layout.
  let good = st.encode();
  // Truncation WITHIN the fixed scalar prefix (before the header count) → Truncated (a scalar
  // read ran off the end). `&[]` likewise fails the very first u16 read.
  assert!(matches!(
    VsrState::decode(&good[..40]),
    Err(CodecError::Truncated { .. })
  ));
  assert!(matches!(
    VsrState::decode(&[]),
    Err(CodecError::Truncated { .. })
  ));
  // Dropping the last byte truncates the trailing config_install_op u64, so the read runs off the end →
  // Truncated (an honestly-short tail, not an oversized length).
  assert!(matches!(
    VsrState::decode(&good[..good.len() - 1]),
    Err(CodecError::Truncated { .. })
  ));
  // Dropping the whole trailing config_install_op scalar (8 bytes) ALSO truncates — a v6 root MUST carry
  // it (the read runs off the end after the empty lineage tail).
  assert!(matches!(
    VsrState::decode(&good[..good.len() - 8]),
    Err(CodecError::Truncated { .. })
  ));
  // Bad leading version → UnknownVersion.
  let mut badver = good.to_vec();
  badver[1] = 8;
  assert!(matches!(
    VsrState::decode(&badver),
    Err(CodecError::UnknownVersion(8))
  ));
  // A header-count prefix that overruns the buffer → LengthOverflow (not an OOB slice). The
  // count u32 sits at offset 2+8+8+8+8+16 = 50.
  let mut huge = good.to_vec();
  huge[50..54].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
  assert!(matches!(
    VsrState::decode(&huge),
    Err(CodecError::LengthOverflow { .. })
  ));
  // A `membership_present` flag that is neither 0 nor 1 → InvalidMembershipPresent. The present byte is
  // the THIRTEENTH-from-last byte now (the trailing bytes are lineage_count(4) + config_install_op(8)):
  // `good.len() - 13`.
  let mut bad_flag = good.to_vec();
  let present_off = bad_flag.len() - 13;
  bad_flag[present_off] = 2;
  assert!(matches!(
    VsrState::decode(&bad_flag),
    Err(CodecError::InvalidMembershipPresent(2))
  ));
  // A lineage-count prefix that overruns the buffer → LengthOverflow (each id a fixed 16-byte block, so
  // an impossible count is a corrupt length). The lineage-count u32 sits just BEFORE the trailing
  // config_install_op(8): `good.len() - 12 .. good.len() - 8`.
  let mut huge_lineage = good.to_vec();
  let lineage_off = huge_lineage.len() - 12;
  huge_lineage[lineage_off..lineage_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
  assert!(matches!(
    VsrState::decode(&huge_lineage),
    Err(CodecError::LengthOverflow { .. })
  ));
  // Trailing bytes after a fully-decoded root → TrailingBytes.
  let mut over = good.to_vec();
  over.push(0);
  assert!(matches!(
    VsrState::decode(&over),
    Err(CodecError::TrailingBytes(1))
  ));
  // A structurally-valid buffer whose decoded fields break the invariants (log_view > view) is
  // rejected as InvalidVsrState rather than constructing an illegal root. Build it by hand as a
  // complete v6 root: an empty-header body with log_view = 5 > view = 4, the epoch tail, the
  // empty-lineage tail, and the config_install_op scalar.
  let mut bad = std::vec::Vec::new();
  bad.extend_from_slice(&SUPERBLOCK_VERSION.to_be_bytes());
  bad.extend_from_slice(&4u64.to_be_bytes()); // view
  bad.extend_from_slice(&5u64.to_be_bytes()); // log_view > view
  bad.extend_from_slice(&0u64.to_be_bytes()); // commit
  bad.extend_from_slice(&0u64.to_be_bytes()); // checkpoint_op
  bad.extend_from_slice(&0u128.to_be_bytes()); // checkpoint_id
  bad.extend_from_slice(&0u32.to_be_bytes()); // header count
  bad.extend_from_slice(&0u64.to_be_bytes()); // epoch
  bad.extend_from_slice(&0u64.to_be_bytes()); // prev_epoch
  bad.push(0); // membership_present = absent
  bad.extend_from_slice(&0u32.to_be_bytes()); // lineage count = 0
  bad.extend_from_slice(&0u64.to_be_bytes()); // config_install_op
  assert!(matches!(
    VsrState::decode(&bad),
    Err(CodecError::InvalidVsrState(_))
  ));
}

#[test]
fn vsr_state_decode_never_panics_on_random_bytes() {
  // Fuzz-style no-panic loop: a pseudo-random byte stream of growing length must always yield
  // a typed error, never a panic / OOB index.
  let good = VsrState::try_new(
    View::with(2),
    View::with(2),
    OpNumber::with(3),
    OpNumber::with(1),
    9,
    std::vec![mk_header(2, 2, 2, 2, b"q")],
  )
  .unwrap()
  .encode();
  for n in 0..=good.len() + 2 {
    let _ = VsrState::decode(&good[..n.min(good.len())]); // truncations
  }
  let mut x = 0xDEAD_BEEFu32;
  for len in 0..400usize {
    let mut v = std::vec::Vec::with_capacity(len);
    for _ in 0..len {
      x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
      v.push((x >> 16) as u8);
    }
    let _ = VsrState::decode(&v); // must not panic
  }
}

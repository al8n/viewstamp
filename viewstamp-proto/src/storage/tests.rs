use super::*;
use crate::{ClientId, Epoch, MemberId, Membership, OpNumber, RequestNumber, View};

/// Correlation ids for these fixture tests: the incarnation is immaterial here — the fixture
/// only echoes the id back — so every id in this module shares one.
const TEST_INCARNATION: u64 = 1;
fn read_id(seq: u64) -> ReadId {
  ReadId::new(TEST_INCARNATION, seq)
}

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
  assert_eq!(SlotStatus::Empty.as_str(), "empty");
  assert_eq!(SlotStatus::Dirty.as_str(), "dirty");
  assert_eq!(SlotStatus::Clean.as_str(), "clean");
  assert_eq!(SlotStatus::Faulty.as_str(), "faulty");
  assert!(SlotStatus::Clean.is_clean());
}

#[test]
fn wal_done_variants() {
  let r = ReadOk::new(
    read_id(1),
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
  let id = read_id(42);
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
  // The single current layout: version|view|log_view|commit|checkpoint_op|checkpoint_id|
  // header-count|headers, the epoch pair (epoch|prev_epoch), the membership present-flag then the
  // membership block, the lineage (prior_config_count|ids), the `config_install_op` scalar (u64),
  // the `log_floor` scalar (u64), and the WAL-geometry pair (`checkpoint_ops`|`wal_capacity`, a u64
  // each). The epoch-1 membership matches the root's epoch-1 scalar; the lineage carries two
  // superseded ids; `config_install_op = 7` is the reconfigure op; `log_floor` defaults to the
  // checkpoint (5) — the constructor's floor; the geometry pair is stamped (interval 32, capacity
  // 4096).
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
  .unwrap()
  .with_wal_geometry(32, 4096);
  let expected: std::vec::Vec<u8> = std::vec![
    0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
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
    0x33, 0x44, 0x44, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 32, 0,
    0, 0, 0, 0, 0, 16, 0,
  ];
  assert_eq!(st.encode(), expected, "VsrState wire layout is pinned");
  // The pinned golden bytes are a valid decode input too: they round-trip back to the same root.
  assert_eq!(
    VsrState::decode(&expected).unwrap(),
    st,
    "the pinned golden root round-trips through decode"
  );
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
fn try_new_v4_rejects_a_membership_epoch_that_disagrees_with_the_root_epoch() {
  // The scalar `epoch` argument and the supplied membership's own `epoch()` must agree; the check
  // fires before any of the other scalar/header validation, so trivial values suffice elsewhere.
  let mem = Membership::genesis(1, 0, std::vec![MemberId::new(1)]).unwrap(); // epoch 0
  assert_eq!(
    VsrState::try_new_v4(
      View::with(1),
      View::with(1),
      OpNumber::with(1),
      OpNumber::new(),
      0,
      std::vec![],
      Epoch::new(5),
      Epoch::new(0),
      mem,
      std::vec![],
      OpNumber::new(),
    ),
    Err(VsrStateError::MembershipEpochMismatch {
      root: 5,
      membership: 0,
    })
  );
}

#[test]
fn vsr_state_decode_accepts_exactly_the_current_version() {
  // Decode is an EXACT-MATCH gate on the leading version word — the durable-format fence. A fresh
  // root round-trips under the current [`SUPERBLOCK_VERSION`]; the SAME bytes re-tagged with ANY
  // other version word are refused as `UnknownVersion` without being parsed. The refusal is what
  // keeps a store written under a different contract (a different layout OR a weaker
  // writer-enforced invariant set — superseded numberings included) from ever being recovered,
  // served through state-sync, or seeding an offline restart: the fence holds even for a buffer
  // that is byte-valid in every other respect. The floor is RAISED above the checkpoint and the
  // WAL-geometry pair is STAMPED, so both trailing tails' round-trips are non-vacuous, not
  // constructor defaults.
  let mem = Membership::genesis(3, 0, (1..=3).map(MemberId::new).collect()).unwrap();
  let root = VsrState::try_new_v4(
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
  .unwrap()
  .with_log_floor(OpNumber::with(5))
  .unwrap()
  .with_wal_geometry(16, 128);
  let bytes = root.encode();
  // The writer stamps the current version — pinned symbolically AND concretely, so a version change
  // is a deliberate, visible diff here.
  assert_eq!(
    &bytes[0..2],
    &SUPERBLOCK_VERSION.to_be_bytes(),
    "a new durable root leads with SUPERBLOCK_VERSION"
  );
  assert_eq!(SUPERBLOCK_VERSION, 1, "the accepted version is exactly 1");
  assert_eq!(
    VsrState::decode(&bytes).unwrap(),
    root,
    "the current-version root round-trips (log_floor + WAL geometry included)"
  );
  // Every other version word in the byte range is refused UNPARSED — 0, and 2..=255, which covers
  // every number a superseded layout generation ever stamped.
  for v in (0u16..=255).filter(|&v| v != SUPERBLOCK_VERSION) {
    let mut tagged = bytes.to_vec();
    tagged[0..2].copy_from_slice(&v.to_be_bytes());
    assert!(
      matches!(VsrState::decode(&tagged), Err(CodecError::UnknownVersion(got)) if got == v),
      "version word {v} is refused as unknown"
    );
  }
  // The high-water superseded number is pinned by name, so this refusal is a visible witness on its
  // own — a store written by the last differently-numbered generation can never decode.
  let mut high_water = bytes.to_vec();
  high_water[0..2].copy_from_slice(&8u16.to_be_bytes());
  assert!(
    matches!(
      VsrState::decode(&high_water),
      Err(CodecError::UnknownVersion(8))
    ),
    "the superseded high-water version 8 is refused"
  );
  // Beyond-byte words are refused identically (the version is a full u16).
  for v in [256u16, 0x0800, u16::MAX] {
    let mut tagged = bytes.to_vec();
    tagged[0..2].copy_from_slice(&v.to_be_bytes());
    assert!(
      matches!(VsrState::decode(&tagged), Err(CodecError::UnknownVersion(got)) if got == v),
      "version word {v} is refused as unknown"
    );
  }
}

#[test]
fn an_ancient_pre_membership_layout_fails_structurally_under_the_current_version() {
  // The current version word `1` was also the FIRST numbering an ancient pre-membership layout
  // ever stamped (a body ending right after the committed-band header set — no epoch, membership,
  // lineage, scalar, or geometry tail). The exact-match gate alone cannot distinguish that one
  // colliding number, so this pins the second layer: parsed as the CURRENT layout, such a root
  // runs out of bytes at the mandatory epoch read and is refused `Truncated` — it can never
  // misparse into a live state, so no store of that era decodes even though its leading word
  // matches.
  let mut ancient = std::vec::Vec::new();
  ancient.extend_from_slice(&SUPERBLOCK_VERSION.to_be_bytes()); // the colliding version word
  ancient.extend_from_slice(&4u64.to_be_bytes()); // view
  ancient.extend_from_slice(&2u64.to_be_bytes()); // log_view
  ancient.extend_from_slice(&7u64.to_be_bytes()); // commit
  ancient.extend_from_slice(&5u64.to_be_bytes()); // checkpoint_op
  ancient.extend_from_slice(&0xAABB_CCDDu128.to_be_bytes()); // checkpoint_id
  ancient.extend_from_slice(&0u32.to_be_bytes()); // header count — the ancient layout ENDS here
  assert!(
    matches!(
      VsrState::decode(&ancient),
      Err(CodecError::Truncated { .. })
    ),
    "an ancient-layout body under the current version word is refused at the epoch read"
  );
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
  // `st` is built via `try_new`, so it encodes as a current-version root whose membership-present
  // flag is 0 (the membership-less shape): version(2) | body | header-count | header | epoch(8) | prev_epoch(8) |
  // present(1) | lineage_count(4) (= 0, no ids) | config_install_op(8) | log_floor(8) |
  // checkpoint_ops(8) | wal_capacity(8). The corruption probes target that exact layout.
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
  // Dropping the last byte truncates the trailing wal_capacity u64, so the read runs off the end →
  // Truncated (an honestly-short tail, not an oversized length).
  assert!(matches!(
    VsrState::decode(&good[..good.len() - 1]),
    Err(CodecError::Truncated { .. })
  ));
  // Dropping the whole trailing geometry pair (16 bytes) ALSO truncates — the current layout MUST carry
  // it (the read runs off the end after the log_floor scalar).
  assert!(matches!(
    VsrState::decode(&good[..good.len() - 16]),
    Err(CodecError::Truncated { .. })
  ));
  // Bad leading version → UnknownVersion.
  let mut badver = good.to_vec();
  badver[1] = 9;
  assert!(matches!(
    VsrState::decode(&badver),
    Err(CodecError::UnknownVersion(9))
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
  // the THIRTY-SEVENTH-from-last byte now (the trailing bytes are lineage_count(4) + config_install_op(8)
  // + log_floor(8) + the geometry pair(16)): `good.len() - 37`.
  let mut bad_flag = good.to_vec();
  let present_off = bad_flag.len() - 37;
  bad_flag[present_off] = 2;
  assert!(matches!(
    VsrState::decode(&bad_flag),
    Err(CodecError::InvalidMembershipPresent(2))
  ));
  // A lineage-count prefix that overruns the buffer → LengthOverflow (each id a fixed 16-byte block, so
  // an impossible count is a corrupt length). The lineage-count u32 sits just BEFORE the trailing
  // scalars (config_install_op(8) + log_floor(8) + geometry(16)): `good.len() - 36 .. good.len() - 32`.
  let mut huge_lineage = good.to_vec();
  let lineage_off = huge_lineage.len() - 36;
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
  // complete current-version root: an empty-header body with log_view = 5 > view = 4, the epoch tail, the
  // empty-lineage tail, the two trailing scalars, and the geometry pair.
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
  bad.extend_from_slice(&0u64.to_be_bytes()); // log_floor
  bad.extend_from_slice(&0u64.to_be_bytes()); // checkpoint_ops (geometry, not recorded)
  bad.extend_from_slice(&0u64.to_be_bytes()); // wal_capacity (geometry, not recorded)
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

#[test]
fn vsr_state_with_log_floor_validates_against_the_checkpoint() {
  let st = VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(6),
    OpNumber::with(4),
    0,
    std::vec![],
  )
  .unwrap();
  assert_eq!(
    st.log_floor(),
    OpNumber::with(4),
    "the constructors default the floor to the root's own checkpoint"
  );
  // Raising to (or above) the checkpoint is the adoption-learned floor a writer carries.
  let raised = st.clone().with_log_floor(OpNumber::with(6)).unwrap();
  assert_eq!(raised.log_floor(), OpNumber::with(6));
  assert_eq!(
    VsrState::decode(&raised.encode()).unwrap().log_floor(),
    OpNumber::with(6),
    "a raised floor round-trips through the v7 scalar"
  );
  // A floor below the checkpoint contradicts "the own checkpoint vouches its own prefix": rejected,
  // and a hand-corrupted v7 scalar is rejected at decode through the same validation. The floor
  // scalar sits just above the trailing geometry pair (16 bytes).
  assert!(matches!(
    st.with_log_floor(OpNumber::with(3)),
    Err(VsrStateError::LogFloorBelowCheckpoint)
  ));
  let mut corrupt = raised.encode().to_vec();
  let floor_off = corrupt.len() - 16 - 8;
  corrupt[floor_off..floor_off + 8].copy_from_slice(&1u64.to_be_bytes()); // floor 1 < checkpoint 4
  assert!(matches!(
    VsrState::decode(&corrupt),
    Err(CodecError::InvalidVsrState(_))
  ));
}

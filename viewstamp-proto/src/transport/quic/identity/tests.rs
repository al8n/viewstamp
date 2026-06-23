use super::*;
use crate::MemberId;

/// The attested replica id for member `m`.
fn replica(m: u128) -> AttestedId {
  AttestedId::Replica(MemberId::new(m))
}

#[test]
fn attested_id_predicates() {
  let r = AttestedId::Replica(MemberId::new(2));
  assert!(r.is_replica());
  assert!(!r.is_client());
  assert_eq!(r.as_replica(), Some(MemberId::new(2)));
  assert_eq!(r.as_client(), None);
  let c = AttestedId::Client(ClientId::new(9));
  assert!(c.is_client());
  assert!(!c.is_replica());
  assert_eq!(c.as_client(), Some(ClientId::new(9)));
  assert_eq!(c.as_replica(), None);
}

#[test]
fn outcome_predicates() {
  let id = IdentityOutcome::Identified(Identified::new(replica(2), 0x5151));
  assert!(id.is_identified());
  assert!(IdentityOutcome::Pending.is_pending());
  assert!(IdentityOutcome::Rejected.is_rejected());
  let unwrapped = id.try_unwrap_identified().unwrap();
  assert_eq!(unwrapped.id(), replica(2));
  assert_eq!(
    unwrapped.cluster(),
    0x5151,
    "the attested cluster is carried"
  );
}

#[test]
fn hello_preface_round_trips() {
  let cluster = 0x5151_u128;
  let src = Hello::new(cluster);
  let mut frame = Vec::new();
  src.write_control_preface(replica(1), &mut frame);
  let id = src
    .authenticate(&IdentityCtx::new(&[], Some(&frame), cluster))
    .try_unwrap_identified()
    .unwrap();
  assert_eq!(id.id(), replica(1));
  assert_eq!(
    id.cluster(),
    cluster,
    "Hello reports the attested cluster for the coordinator's cross-check"
  );
  // Wrong cluster → Rejected
  assert!(
    Hello::new(0x9999)
      .authenticate(&IdentityCtx::new(&[], Some(&frame), 0x9999))
      .is_rejected()
  );
}

/// A replica's attested identity is its FULL u128 [`MemberId`] — including beyond `u16::MAX` — and it
/// round-trips through BOTH the cert-OID extension AND the Hello preface with NO slot narrowing. This
/// pins that the old `u16::try_from` narrowing is gone: the whole member id is carried either way.
#[test]
fn a_member_id_beyond_u16_round_trips_through_the_cert_and_the_hello() {
  use crate::transport::quic::crypto::test_ca;

  let cluster = 0x5151_u128;
  let big = u128::from(u16::MAX) + 1; // 0x1_0000 — does NOT fit u16
  let attested = AttestedId::Replica(MemberId::new(big));

  // Cert-OID path: a CA-attested ext for the big member id parses back to the same MemberId.
  let ca = test_ca();
  let cert = ca.issue_replica_with_member_oid(0, MemberId::new(big), cluster);
  let der = [cert.end_entity_der()];
  assert_eq!(
    CertOid::new(cluster)
      .authenticate(&IdentityCtx::new(&der, None, cluster))
      .try_unwrap_identified()
      .unwrap()
      .id(),
    attested,
    "the cert-OID carries the full u128 MemberId (no u16 narrowing)"
  );

  // Hello path: the same big member id round-trips through the preface codec.
  let mut frame = Vec::new();
  Hello::new(cluster).write_control_preface(attested, &mut frame);
  assert_eq!(
    Hello::new(cluster)
      .authenticate(&IdentityCtx::new(&[], Some(&frame), cluster))
      .try_unwrap_identified()
      .unwrap()
      .id(),
    attested,
    "the Hello preface carries the full u128 MemberId (no u16 narrowing)"
  );

  // And the raw extension value parses to the big MemberId directly.
  let ext = encode_identity_ext(cluster, attested);
  assert_eq!(
    ext.len(),
    33,
    "the id field stays 16 bytes (no wire-size change)"
  );
  assert_eq!(
    parse_identity_ext(&ext, cluster)
      .try_unwrap_identified()
      .unwrap()
      .id(),
    attested
  );
}

/// On QUIC the delivered control frame is the WHOLE first Control frame, not a byte-stream prefix
/// with a legitimate post-tail. So a valid hello PREFIX followed by ANY trailing bytes must be
/// REJECTED, never validated on the prefix: a valid-cert but buggy/version-skew peer could otherwise
/// frame a valid hello plus junk and still authenticate. The total-parse check (`consumed == frame
/// len`) closes that. (The TCP record path's `classify_hello` prefix behaviour is deliberately
/// unchanged — there a post-hello tail is the next record's bytes; only this QUIC `authenticate` is
/// total-parse.)
#[test]
fn a_hello_with_trailing_bytes_is_rejected_not_validated_on_the_prefix() {
  let cluster = 0x5151_u128;
  let src = Hello::new(cluster);

  // The exact hello validates.
  let mut exact = Vec::new();
  src.write_control_preface(replica(1), &mut exact);
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(&exact), cluster))
      .is_identified(),
    "the exact encoded hello validates (the bridge frames it as one exact Control frame)"
  );

  // The SAME valid hello with one trailing byte must be rejected — not silently validated on the
  // valid prefix (which is the pre-fix bug this pins).
  let mut with_tail = exact.clone();
  with_tail.push(0xAB);
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(&with_tail), cluster))
      .is_rejected(),
    "a valid hello PREFIX + trailing junk must be rejected (total parse), not validated"
  );

  // A larger junk tail behind the valid prefix is likewise rejected.
  let mut with_blob = exact.clone();
  with_blob.extend_from_slice(&[0u8; 16]);
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(&with_blob), cluster))
      .is_rejected(),
    "any trailing bytes behind a valid hello are rejected"
  );
}

/// `Hello::authenticate` distinguishes the NO-frame cert-only probe (`control_frame() == None`) from a
/// DELIVERED first Control frame (`Some(..)`). The probe waits (`Pending`); a delivered frame is the
/// SOLE Hello opportunity, so a short/empty/partial first frame is REJECTED there — never `Pending`,
/// which would leave the connection `Authenticating` for a LATER frame to bind.
///
/// On QUIC `control_head` is a COMPLETE popped frame with no "more bytes of this frame" to come, so
/// the same `HelloOutcome::Incomplete` that legitimately means "wait" on the TCP byte-stream path
/// must mean "reject" here. This pins that disambiguation at the source level; the loopback
/// `a_short_first_control_frame_does_not_let_a_later_frame_authenticate` proves it end-to-end through
/// the coordinator.
///
/// NEUTER CHECK: revert the delivered-frame arm to `Incomplete => Pending` (unconditionally) and the
/// empty/short-frame cases below return `Pending` instead of `Rejected`, so these assertions fail —
/// exactly the gap that lets a later frame authenticate.
#[test]
fn an_incomplete_hello_is_pending_only_with_no_frame_and_rejected_on_a_delivered_frame() {
  let cluster = 0x5151_u128;
  let src = Hello::new(cluster);

  // (probe) NO control frame delivered yet → Pending: the hello rides a Control frame, none has
  // arrived, so wait for the first one. This is the only path to Pending.
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], None, cluster))
      .is_pending(),
    "the cert-only probe (no control frame delivered) must be Pending — wait for the first frame"
  );

  // (delivered, empty) An EMPTY first Control frame is a delivered frame, not the probe. It cannot be
  // a complete hello, and there are no more bytes of it to come, so it must be REJECTED — never
  // Pending (which would let a later frame bind).
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(&[]), cluster))
      .is_rejected(),
    "an EMPTY first Control frame must be REJECTED, not admitted as Pending for a later frame to bind"
  );

  // (delivered, short) A SHORT hello prefix (a valid tag+version but truncated before the peer id) is
  // `HelloOutcome::Incomplete`; as a delivered first frame it must be REJECTED, not Pending.
  let mut full = Vec::new();
  src.write_control_preface(replica(1), &mut full);
  let short = &full[..full.len() - 1]; // drop the last byte → a valid prefix that does not complete
  assert!(
    matches!(
      crate::transport::labeled::classify_hello(short, cluster),
      crate::transport::labeled::HelloOutcome::Incomplete
    ),
    "the truncated hello prefix is genuinely Incomplete (the precondition this test rejects)"
  );
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(short), cluster))
      .is_rejected(),
    "a SHORT hello prefix in the delivered first Control frame must be REJECTED, not Pending"
  );

  // (delivered, complete) The exact hello in the delivered first frame still binds.
  assert!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(&full), cluster))
      .is_identified(),
    "a complete hello in the delivered first frame binds"
  );
}

/// `authenticate` parses against the ENDPOINT's cluster (`ctx.our_cluster()`), NOT the source's own
/// configured field. A source whose field disagrees with the ctx still keys off the ctx — and
/// reports that ctx cluster as the attested one — so the coordinator's single-sourced cross-check is
/// the only authority. (On the live path `with_identity` forces the two equal anyway; this pins that
/// the parse is ctx-driven so a custom/misconfigured source cannot smuggle a foreign cluster past
/// the source self-check.)
#[test]
fn authenticate_parses_against_the_ctx_cluster_not_the_source_field() {
  use crate::transport::quic::crypto::test_ca;

  let endpoint_cluster = 0x5151_u128;
  // Hello: a source CONFIGURED for a different cluster still parses against the ctx and reports it.
  let mut frame = Vec::new();
  Hello::new(endpoint_cluster).write_control_preface(replica(1), &mut frame);
  let id = Hello::new(0xBEEF) // source field intentionally != endpoint cluster
    .authenticate(&IdentityCtx::new(&[], Some(&frame), endpoint_cluster))
    .try_unwrap_identified()
    .unwrap();
  assert_eq!(
    id.cluster(),
    endpoint_cluster,
    "Hello reports the ctx cluster"
  );

  // CertOid: same property against a CA-attested cert minted for the endpoint cluster.
  let ca = test_ca();
  let cert = ca.issue_replica_with_oid(2, endpoint_cluster);
  let der = [cert.end_entity_der()];
  let id = CertOid::new(0xBEEF) // source field intentionally != endpoint cluster
    .authenticate(&IdentityCtx::new(&der, None, endpoint_cluster))
    .try_unwrap_identified()
    .unwrap();
  assert_eq!(id.id(), replica(2));
  assert_eq!(
    id.cluster(),
    endpoint_cluster,
    "CertOid reports the ctx cluster (the OID's cluster, validated against ctx), not its own field"
  );
}

#[test]
fn identity_ext_round_trips_and_rejects_malformed() {
  let cluster = 0x5151_u128;
  // Replica round-trip (the attested value is a MemberId).
  let r = encode_identity_ext(cluster, replica(7));
  assert_eq!(r.len(), 33);
  assert_eq!(
    parse_identity_ext(&r, cluster)
      .try_unwrap_identified()
      .unwrap()
      .id(),
    replica(7)
  );
  // Client round-trip (a full u128 id, exercising the high bits).
  let c = encode_identity_ext(
    cluster,
    AttestedId::Client(ClientId::new(0xDEAD_BEEF_0000_0001)),
  );
  assert_eq!(
    parse_identity_ext(&c, cluster)
      .try_unwrap_identified()
      .unwrap()
      .id(),
    AttestedId::Client(ClientId::new(0xDEAD_BEEF_0000_0001))
  );
  // Cluster mismatch → Rejected.
  assert!(parse_identity_ext(&r, 0x9999).is_rejected());
  // Wrong length → Rejected.
  assert!(parse_identity_ext(&r[..32], cluster).is_rejected());
  assert!(parse_identity_ext(&[], cluster).is_rejected());
  // Unknown kind byte → Rejected.
  let mut bad_kind = r.clone();
  bad_kind[16] = 9;
  assert!(parse_identity_ext(&bad_kind, cluster).is_rejected());
  // A replica member id whose 16-byte field has a high byte set (> u16::MAX) is VALID — the full
  // u128 MemberId range is carried now (the old u16 narrowing is gone), so it round-trips unchanged.
  let mut wide_replica = encode_identity_ext(cluster, replica(2));
  wide_replica[17] = 1; // set a high byte of the 16-byte id → member id 0x0100_0000_0000_0000_0002
  let expected = MemberId::new(u128::from_be_bytes(
    wide_replica[17..33].try_into().unwrap(),
  ));
  assert_eq!(
    parse_identity_ext(&wide_replica, cluster)
      .try_unwrap_identified()
      .unwrap()
      .id(),
    AttestedId::Replica(expected),
    "a member id beyond u16::MAX is carried, not rejected (the u16 narrowing is gone)"
  );
}

#[test]
fn cert_oid_extracts_the_attested_peer_and_rejects_a_cluster_mismatch() {
  use crate::transport::quic::crypto::test_ca;

  let cluster = 0x5151_u128;
  let ca = test_ca();
  let cert2 = ca.issue_replica_with_oid(2, cluster);
  let der = [cert2.end_entity_der()];
  assert_eq!(
    CertOid::new(cluster)
      .authenticate(&IdentityCtx::new(&der, None, cluster))
      .try_unwrap_identified()
      .unwrap()
      .id(),
    replica(2)
  );
  // A verifier for a different cluster rejects the OID-attested cluster mismatch.
  assert!(
    CertOid::new(0x9999)
      .authenticate(&IdentityCtx::new(&der, None, 0x9999))
      .is_rejected()
  );
}

#[test]
fn cert_oid_rejects_a_cert_without_the_extension() {
  use crate::transport::quic::crypto::test_ca;

  let ca = test_ca();
  let plain = ca.issue_replica(3, 0x5151);
  let der = [plain.end_entity_der()];
  assert!(
    CertOid::new(0x5151)
      .authenticate(&IdentityCtx::new(&der, None, 0x5151))
      .is_rejected()
  );
}

#[test]
fn cert_oid_rejects_an_empty_chain() {
  assert!(
    CertOid::new(0x5151)
      .authenticate(&IdentityCtx::new(&[], None, 0x5151))
      .is_rejected()
  );
}

#[test]
fn identity_config_carries_the_cluster_for_both_variants() {
  assert_eq!(IdentityConfig::Hello { cluster: 0x5151 }.cluster(), 0x5151);
  assert_eq!(
    IdentityConfig::CertOid { cluster: 0x9999 }.cluster(),
    0x9999
  );
}

#[test]
fn provided_identity_from_hello_config_authenticates_via_the_preface() {
  // The `Hello` selector produces a source that writes a preface and parses it back to the peer.
  let cluster = 0x5151_u128;
  let src = IdentityConfig::Hello { cluster }.into_source();
  let mut frame = Vec::new();
  src.write_control_preface(replica(1), &mut frame);
  assert!(
    !frame.is_empty(),
    "the Hello scheme writes a non-empty preface"
  );
  assert_eq!(
    src
      .authenticate(&IdentityCtx::new(&[], Some(&frame), cluster))
      .try_unwrap_identified()
      .unwrap()
      .id(),
    replica(1)
  );
}

#[test]
fn provided_identity_from_cert_oid_config_authenticates_via_the_cert() {
  use crate::transport::quic::crypto::test_ca;

  // The `CertOid` selector produces a source that writes NO preface and reads identity from the cert.
  let cluster = 0x5151_u128;
  let src = IdentityConfig::CertOid { cluster }.into_source();
  let mut preface = Vec::new();
  src.write_control_preface(replica(2), &mut preface);
  assert!(
    preface.is_empty(),
    "the CertOid scheme rides in the cert, writing no preface"
  );

  let ca = test_ca();
  let cert2 = ca.issue_replica_with_oid(2, cluster);
  let der = [cert2.end_entity_der()];
  assert_eq!(
    src
      .authenticate(&IdentityCtx::new(&der, None, cluster))
      .try_unwrap_identified()
      .unwrap()
      .id(),
    replica(2)
  );
}

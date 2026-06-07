//! Pluggable peer-identity seam for the QUIC transport.
//!
//! [`IdentitySource`] is the single trait the coordinator calls to (a) write a control-stream
//! preface and (b) authenticate the peer from post-handshake material. The coordinator owns the
//! binding policy (dialed-match / cluster cross-check); the impl owns only the extraction logic.

use std::vec::Vec;

use rustls::pki_types::CertificateDer;

use crate::{ClientId, Peer, ReplicaId};

// ── Identified ────────────────────────────────────────────────────────────────

/// A settled, authenticated peer identity — an UNTRUSTED candidate the coordinator re-checks.
///
/// Carries BOTH the attested peer AND the cluster it was attested for. The source REPORTS the cluster
/// it parsed (from the hello frame or the cert extension); the coordinator then re-asserts that
/// cluster equals its own `Config.cluster`.
///
/// For the PROVIDED sources ([`Hello`] / [`CertOid`]) this re-assertion is an un-bypassable gate: they
/// report the GENUINE attested cluster they parsed from the handshake material, so the coordinator's
/// check rejects any wrong-cluster peer. A [`dangerous_custom_identity`](super::QuicCoordinator::dangerous_custom_identity)
/// source, by its named hazard, owns its own cluster correctness — it can mint an `Identified` with
/// ANY cluster (this constructor is `pub`), so the coordinator's check only re-confirms whatever
/// cluster that source asserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identified {
  who: Peer,
  cluster: u128,
}

impl Identified {
  /// Wrap a claimed peer attested for `cluster` (the coordinator re-checks BOTH before binding). The
  /// provided sources pass the genuine parsed cluster; a custom source is trusted to pass the cluster
  /// it actually attested (see the type docs).
  pub const fn new(who: Peer, cluster: u128) -> Self {
    Self { who, cluster }
  }

  /// The claimed peer identity.
  #[inline(always)]
  pub const fn who(&self) -> Peer {
    self.who
  }

  /// The cluster this identity was attested for. The coordinator binds only when this equals its own
  /// `Config.cluster`.
  #[inline(always)]
  pub const fn cluster(&self) -> u128 {
    self.cluster
  }
}

// ── IdentityOutcome ───────────────────────────────────────────────────────────

/// The result of an [`IdentitySource::authenticate`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::IsVariant, derive_more::TryUnwrap)]
#[try_unwrap(ref)]
#[non_exhaustive]
pub enum IdentityOutcome {
  /// More control-stream bytes are needed before identity can be determined.
  Pending,
  /// A candidate identity was extracted. The coordinator re-checks before binding.
  Identified(Identified),
  /// The peer cannot be authenticated; the coordinator must close the connection.
  Rejected,
}

// ── IdentityCtx ──────────────────────────────────────────────────────────────

/// Read-only handshake material handed to [`IdentitySource::authenticate`].
///
/// Carries NO dialed expectation and NO message body — so `authenticate` cannot collapse the
/// authenticator into the message's self-claim. The coordinator owns the binding policy.
///
/// The control-frame payload is an [`Option`] so a source can tell the two pre-bind calls apart: the
/// coordinator calls `authenticate` ONCE at `Connected` with NO control frame yet (the cert-only
/// probe — [`None`]), then again with the FIRST delivered control frame ([`Some`], even when that
/// frame is empty or short). On QUIC that delivered frame is a COMPLETE, already-popped frame — not a
/// byte-stream prefix with more bytes to come — so it is the SOLE Hello opportunity: a preface source
/// must reject a malformed/short first frame here rather than wait for a later one. See
/// [`Self::control_frame`].
#[non_exhaustive]
pub struct IdentityCtx<'a> {
  peer_certs: &'a [CertificateDer<'a>],
  control_frame: Option<&'a [u8]>,
  our_cluster: u128,
}

impl<'a> IdentityCtx<'a> {
  /// Construct the context from validated handshake material. `control_frame` is [`None`] for the
  /// coordinator's `Connected` cert-only probe (no control frame delivered yet) and [`Some`] for the
  /// first delivered control frame — even an empty/short one (the identity tests also build it
  /// directly).
  pub(crate) const fn new(
    peer_certs: &'a [CertificateDer<'a>],
    control_frame: Option<&'a [u8]>,
    our_cluster: u128,
  ) -> Self {
    Self {
      peer_certs,
      control_frame,
      our_cluster,
    }
  }

  /// The peer's certificate chain as validated by the TLS layer (empty when none was presented).
  #[inline(always)]
  pub const fn peer_certs(&self) -> &[CertificateDer<'a>] {
    self.peer_certs
  }

  /// The peer's first control-stream frame payload, or [`None`] when no control frame has been
  /// delivered yet (the coordinator's `Connected` cert-only probe).
  ///
  /// On QUIC a [`Some`] payload is a COMPLETE control FRAME the bridge already popped — never a
  /// byte-stream prefix awaiting more bytes. So a preface-based source treats [`Some`] as the SOLE
  /// Hello opportunity (a short/empty/partial frame must be REJECTED, not deferred), and [`None`] as
  /// "wait for the first frame". A cert-only source ([`CertOid`]) ignores this entirely.
  #[inline(always)]
  pub const fn control_frame(&self) -> Option<&[u8]> {
    self.control_frame
  }

  /// The cluster id this coordinator was built for.
  #[inline(always)]
  pub const fn our_cluster(&self) -> u128 {
    self.our_cluster
  }
}

// ── IdentitySource ────────────────────────────────────────────────────────────

/// Establishes the authenticated [`Peer`] for a QUIC connection.
///
/// One impl per cluster, chosen at coordinator construction. Requires cluster-private roots +
/// mandatory mTLS (supplied via [`ClusterTls`](super::ClusterTls)).
///
/// The coordinator — never the impl — applies the binding policy: `authenticate` returns an
/// UNTRUSTED candidate; the coordinator does the dialed→match-or-abort / accepted→adopt step and
/// the unconditional `cluster == Config.cluster` cross-check.
pub trait IdentitySource {
  /// Append this node's control-channel preface to `out`. Written as the FIRST frame on the
  /// control send-stream. Impls whose identity rides entirely in the TLS certificate write nothing.
  ///
  /// # Size contract
  ///
  /// The appended preface MUST be at most
  /// [`MAX_FRAME_LEN`](crate::transport::frame::MAX_FRAME_LEN) bytes — it is sent as a single frame,
  /// and a peer's frame decoder fatally rejects any declared length above that cap. The provided
  /// [`Hello`] / [`CertOid`] schemes honour this trivially (a few dozen bytes, or none). A custom
  /// source supplied through
  /// [`dangerous_custom_identity`](super::QuicCoordinator::dangerous_custom_identity) that violates it
  /// does not panic the transport: the bridge counts the oversized preface and tears the connection
  /// down (it can never authenticate, since the frame would not decode).
  fn write_control_preface(&self, me: Peer, out: &mut Vec<u8>);

  /// Authenticate the peer from handshake material only.
  ///
  /// The returned `who` inside [`IdentityOutcome::Identified`] is a CANDIDATE the coordinator
  /// re-checks (dialed-match / cluster cross-check) — never a binding.
  fn authenticate(&self, ctx: &IdentityCtx<'_>) -> IdentityOutcome;
}

// ── Hello ─────────────────────────────────────────────────────────────────────

/// Identity via the [`labeled`](crate::transport::labeled) hello codec as the first control-stream
/// frame. The hello encodes `cluster || peer_kind || peer_id`; `authenticate` parses it against
/// `our_cluster` and returns the claimed peer as a candidate.
pub struct Hello {
  cluster: u128,
}

impl Hello {
  /// Build a `Hello` identity source for the given cluster.
  pub const fn new(cluster: u128) -> Self {
    Self { cluster }
  }

  /// The cluster this source writes into its [`write_control_preface`](IdentitySource::write_control_preface)
  /// hello. It MUST equal the coordinator's `Config.cluster` (enforced at construction); the
  /// authenticated-peer parse uses the endpoint's cluster, not this field.
  #[inline(always)]
  pub const fn cluster(&self) -> u128 {
    self.cluster
  }
}

impl IdentitySource for Hello {
  fn write_control_preface(&self, me: Peer, out: &mut Vec<u8>) {
    crate::transport::labeled::encode_hello(self.cluster, me, out);
  }

  fn authenticate(&self, ctx: &IdentityCtx<'_>) -> IdentityOutcome {
    use crate::transport::labeled::HelloOutcome;
    // No control frame delivered yet (the `Connected` cert-only probe): the hello rides a CONTROL
    // frame, none of which has arrived, so wait for the first one. This is the ONLY path to `Pending`
    // — once a frame is delivered below, it is the sole Hello opportunity and an incomplete parse is a
    // hard reject, not a deferral.
    let Some(frame) = ctx.control_frame() else {
      return IdentityOutcome::Pending;
    };
    // Parse against the ENDPOINT's cluster (`ctx.our_cluster()`), not this source's configured field:
    // the coordinator single-sources the cluster, and the attested cluster it reports below is the one
    // the coordinator re-asserts. `classify_hello` already rejects a hello whose encoded cluster is not
    // `our_cluster`, so on `Accepted` the attested cluster is `our_cluster`.
    match crate::transport::labeled::classify_hello(frame, ctx.our_cluster()) {
      // TOTAL parse: `frame` is the WHOLE first Control frame on QUIC (not a byte-stream prefix with a
      // legitimate post-tail, as on the TCP record path). `classify_hello` accepts a valid hello PREFIX,
      // so require the consumed length to equal the frame's full length — any trailing byte (a valid-cert
      // but buggy/version-skew peer framing a hello plus junk) is rejected, not validated on the prefix.
      // The bridge frames our own hello as one exact Control frame, so a legitimate hello satisfies this.
      HelloOutcome::Accepted(peer, consumed) if consumed == frame.len() => {
        IdentityOutcome::Identified(Identified::new(peer, ctx.our_cluster()))
      }
      HelloOutcome::Accepted(..) => IdentityOutcome::Rejected,
      // A DELIVERED first Control frame is the SOLE Hello opportunity (the bridge already popped the whole
      // frame — no "more bytes of this frame" come on QUIC), so `Incomplete` is a hard REJECT: admitting it
      // as `Pending` would leave the connection `Authenticating` for a LATER frame to authenticate. (The
      // TCP byte-stream path, where a hello prefix completes in a later record, does not use this.)
      HelloOutcome::Incomplete | HelloOutcome::Rejected => IdentityOutcome::Rejected,
    }
  }
}

// ── CertOid ─────────────────────────────────────────────────────────────────

/// The OID of the viewstamp identity extension carried in a cluster's own certificates.
///
/// `1.3.6.1.4.1.58888.1` lives under the IANA Private Enterprise Numbers arc
/// (`1.3.6.1.4.1.<enterprise>`). `58888` is a viewstamp-internal, deliberately
/// **unregistered** enterprise number and `.1` is the identity-extension leaf. The value is never
/// published or cross-referenced against any registry: it is written by this cluster's own cert
/// issuer and read back only by this cluster's own [`CertOid`] verifier, so any fixed private arc
/// serves. Treat it as an opaque label private to viewstamp, NOT a standard/registered OID.
pub(crate) const IDENTITY_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 58888, 1];

/// Byte kind tag for a replica identity in the extension value.
const KIND_REPLICA: u8 = 0;
/// Byte kind tag for a client identity in the extension value.
const KIND_CLIENT: u8 = 1;
/// Fixed extension-value length: `cluster(16) || kind(1) || id(16)`.
const IDENTITY_EXT_LEN: usize = 16 + 1 + 16;

/// Encode the fixed `cluster(16 BE) || kind(1) || id(16 BE)` identity extension value (33 bytes).
///
/// A replica's id is its `u8` index widened to the 16-byte field; a client's id is its full `u128`.
#[cfg_attr(
  not(test),
  expect(dead_code, reason = "only the #[cfg(test)] cert generator encodes")
)]
pub(crate) fn encode_identity_ext(cluster: u128, who: Peer) -> Vec<u8> {
  let mut out = Vec::with_capacity(IDENTITY_EXT_LEN);
  out.extend_from_slice(&cluster.to_be_bytes());
  match who {
    Peer::Replica(r) => {
      out.push(KIND_REPLICA);
      out.extend_from_slice(&u128::from(r.get()).to_be_bytes());
    }
    Peer::Client(c) => {
      out.push(KIND_CLIENT);
      out.extend_from_slice(&c.get().to_be_bytes());
    }
  }
  out
}

/// Total-parse the identity extension value against `expected_cluster`.
///
/// Rejects: any length other than 33; a cluster that is not `expected_cluster`; an unknown kind
/// byte; and a replica id whose 16-byte field exceeds `u8::MAX` (a replica index must fit
/// [`ReplicaId`]). On success returns the attested peer AND the attested cluster as a candidate the
/// coordinator re-checks (the cluster equals `expected_cluster`, which on the live path is the
/// endpoint's own cluster — so the coordinator re-asserts it against `Config.cluster`).
fn parse_identity_ext(value: &[u8], expected_cluster: u128) -> IdentityOutcome {
  if value.len() != IDENTITY_EXT_LEN {
    return IdentityOutcome::Rejected;
  }
  let cluster = u128::from_be_bytes(value[..16].try_into().expect("16 bytes"));
  if cluster != expected_cluster {
    return IdentityOutcome::Rejected;
  }
  let kind = value[16];
  let id = u128::from_be_bytes(value[17..33].try_into().expect("16 bytes"));
  let who = match kind {
    KIND_REPLICA => match u8::try_from(id) {
      Ok(index) => Peer::Replica(ReplicaId::new(index)),
      Err(_) => return IdentityOutcome::Rejected,
    },
    KIND_CLIENT => Peer::Client(ClientId::new(id)),
    _ => return IdentityOutcome::Rejected,
  };
  IdentityOutcome::Identified(Identified::new(who, cluster))
}

/// Identity from a binary OID extension ([`IDENTITY_OID`]) in the validated peer certificate. The
/// extension value is the same `cluster || kind || id` layout the [`Hello`] codec uses, but
/// CA-attested instead of self-claimed; `authenticate` parses it ONCE from the end-entity cert at
/// `Connected` (by OID, irrespective of the extension's criticality flag).
///
/// The extension is carried NON-critical: it is a private viewstamp OID the general-purpose WebPki chain
/// verifier does not recognise, and RFC 5280 requires such a verifier to reject any unrecognised CRITICAL
/// extension — so a critical marking would make the stock cluster-CA verifier reject the whole chain
/// before this reader ever runs. Non-critical, WebPki ignores it (still validating membership via the
/// chain) while this reader extracts it by OID.
///
/// A binary extension is used deliberately rather than a string SAN: string SANs are injection-prone and
/// ambiguous to parse, whereas a fixed-length binary field is total-parsed with no escaping.
///
/// `authenticate` matches the OID's cluster against the ENDPOINT's cluster (`ctx.our_cluster()`,
/// single-sourced from `Config.cluster`) and REPORTS it; the coordinator then re-asserts that same
/// reported cluster against `Config.cluster` (the un-bypassable gate). The configured `cluster` field
/// here is what the source would write into a preface — `CertOid` writes none — and is held only so
/// the construction-time `with_identity` check can require it to equal the endpoint's cluster.
pub struct CertOid {
  cluster: u128,
}

impl CertOid {
  /// Build a `CertOid` identity source for the given cluster.
  pub const fn new(cluster: u128) -> Self {
    Self { cluster }
  }

  /// The cluster this source was configured for. It MUST equal the coordinator's `Config.cluster`
  /// (enforced at construction); the authenticated-peer parse uses the endpoint's cluster
  /// (`ctx.our_cluster()`), not this field, so the coordinator single-sources the cross-check.
  #[inline(always)]
  pub const fn cluster(&self) -> u128 {
    self.cluster
  }
}

impl IdentitySource for CertOid {
  fn write_control_preface(&self, _me: Peer, _out: &mut Vec<u8>) {
    // Empty: a `CertOid` peer's identity rides in the validated certificate, not the control stream.
  }

  fn authenticate(&self, ctx: &IdentityCtx<'_>) -> IdentityOutcome {
    let Some(end_entity) = ctx.peer_certs().first() else {
      return IdentityOutcome::Rejected;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(end_entity.as_ref()) else {
      return IdentityOutcome::Rejected;
    };
    let Ok(oid) = x509_parser::oid_registry::Oid::from(IDENTITY_OID) else {
      return IdentityOutcome::Rejected;
    };
    // Parse against the ENDPOINT's cluster (`ctx.our_cluster()`), not this source's own field: the
    // coordinator single-sources the cluster and re-asserts the attested cluster reported below.
    match cert.get_extension_unique(&oid) {
      Ok(Some(ext)) => parse_identity_ext(ext.value, ctx.our_cluster()),
      _ => IdentityOutcome::Rejected,
    }
  }
}

// ── IdentityConfig / ProvidedIdentity ─────────────────────────────────────────

/// Selects one of the two provided identity schemes at coordinator construction.
///
/// Both schemes require cluster-private roots + mandatory mTLS (supplied via
/// [`ClusterTls`](super::ClusterTls)); the variant only chooses HOW the authenticated peer is
/// established on top of that:
///
/// - [`IdentityConfig::Hello`] — the peer announces itself with the [`Hello`] preface as the first
///   control-stream frame (no per-replica cert extension required). On the ACCEPT side the announced
///   replica index is SELF-asserted: the mTLS handshake proves cluster membership, not the index, so
///   an operator wanting index-level attestation on inbound connections chooses [`CertOid`].
/// - [`IdentityConfig::CertOid`] — the peer's identity is the [`CertOid`] binary extension carried
///   in its validated certificate (CA-attested; no control-stream preface).
///
/// Construct a coordinator with [`QuicCoordinator::with_identity`](super::QuicCoordinator::with_identity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityConfig {
  /// Identity via the [`Hello`] control-stream preface for `cluster`.
  Hello {
    /// The cluster id this coordinator authenticates for.
    cluster: u128,
  },
  /// Identity via the [`CertOid`] certificate extension for `cluster`.
  CertOid {
    /// The cluster id this coordinator authenticates for.
    cluster: u128,
  },
}

impl IdentityConfig {
  /// The cluster id this configuration authenticates for (shared by both variants).
  #[inline(always)]
  pub const fn cluster(&self) -> u128 {
    match self {
      Self::Hello { cluster } | Self::CertOid { cluster } => *cluster,
    }
  }

  /// Produce the sealed [`ProvidedIdentity`] source this configuration selects. Crate-internal: the
  /// only constructor of a `ProvidedIdentity`, so the common path is reachable solely through this
  /// selector (and thus through [`QuicCoordinator::with_identity`](super::QuicCoordinator::with_identity)).
  pub(crate) fn into_source(self) -> ProvidedIdentity {
    match self {
      Self::Hello { cluster } => ProvidedIdentity::Hello(Hello::new(cluster)),
      Self::CertOid { cluster } => ProvidedIdentity::CertOid(CertOid::new(cluster)),
    }
  }
}

/// The sealed [`IdentitySource`] an [`IdentityConfig`] produces — it dispatches to the selected
/// [`Hello`] or [`CertOid`] scheme.
///
/// `pub` only so it can name the default identity type parameter of
/// [`QuicCoordinator`](super::QuicCoordinator); it is constructible ONLY by selecting an
/// [`IdentityConfig`] and passing it to
/// [`QuicCoordinator::with_identity`](super::QuicCoordinator::with_identity) (its variant payloads
/// have no public constructor reachable except through that path). Embedders supplying their own
/// [`IdentitySource`] use
/// [`QuicCoordinator::dangerous_custom_identity`](super::QuicCoordinator::dangerous_custom_identity).
pub enum ProvidedIdentity {
  /// The [`Hello`] preface scheme.
  Hello(Hello),
  /// The [`CertOid`] certificate-extension scheme.
  CertOid(CertOid),
}

impl IdentitySource for ProvidedIdentity {
  fn write_control_preface(&self, me: Peer, out: &mut Vec<u8>) {
    match self {
      Self::Hello(h) => h.write_control_preface(me, out),
      Self::CertOid(c) => c.write_control_preface(me, out),
    }
  }

  fn authenticate(&self, ctx: &IdentityCtx<'_>) -> IdentityOutcome {
    match self {
      Self::Hello(h) => h.authenticate(ctx),
      Self::CertOid(c) => c.authenticate(ctx),
    }
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn outcome_predicates() {
    let id = IdentityOutcome::Identified(Identified::new(Peer::Replica(ReplicaId::new(2)), 0x5151));
    assert!(id.is_identified());
    assert!(IdentityOutcome::Pending.is_pending());
    assert!(IdentityOutcome::Rejected.is_rejected());
    let unwrapped = id.try_unwrap_identified().unwrap();
    assert_eq!(unwrapped.who(), Peer::Replica(ReplicaId::new(2)));
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
    src.write_control_preface(Peer::Replica(ReplicaId::new(1)), &mut frame);
    let id = src
      .authenticate(&IdentityCtx::new(&[], Some(&frame), cluster))
      .try_unwrap_identified()
      .unwrap();
    assert_eq!(id.who(), Peer::Replica(ReplicaId::new(1)));
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
    src.write_control_preface(Peer::Replica(ReplicaId::new(1)), &mut exact);
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
    src.write_control_preface(Peer::Replica(ReplicaId::new(1)), &mut full);
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
    Hello::new(endpoint_cluster)
      .write_control_preface(Peer::Replica(ReplicaId::new(1)), &mut frame);
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
    assert_eq!(id.who(), Peer::Replica(ReplicaId::new(2)));
    assert_eq!(
      id.cluster(),
      endpoint_cluster,
      "CertOid reports the ctx cluster (the OID's cluster, validated against ctx), not its own field"
    );
  }

  #[test]
  fn identity_ext_round_trips_and_rejects_malformed() {
    use crate::ClientId;

    let cluster = 0x5151_u128;
    // Replica round-trip.
    let r = encode_identity_ext(cluster, Peer::Replica(ReplicaId::new(7)));
    assert_eq!(r.len(), 33);
    assert_eq!(
      parse_identity_ext(&r, cluster)
        .try_unwrap_identified()
        .unwrap()
        .who(),
      Peer::Replica(ReplicaId::new(7))
    );
    // Client round-trip (a full u128 id, exercising the high bits).
    let c = encode_identity_ext(cluster, Peer::Client(ClientId::new(0xDEAD_BEEF_0000_0001)));
    assert_eq!(
      parse_identity_ext(&c, cluster)
        .try_unwrap_identified()
        .unwrap()
        .who(),
      Peer::Client(ClientId::new(0xDEAD_BEEF_0000_0001))
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
    // Replica index that does not fit u8 (id high bytes set with kind=Replica) → Rejected.
    let mut wide_replica = encode_identity_ext(cluster, Peer::Replica(ReplicaId::new(2)));
    wide_replica[17] = 1; // set a high id byte so the 17-byte id is > 255
    assert!(parse_identity_ext(&wide_replica, cluster).is_rejected());
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
        .who(),
      Peer::Replica(ReplicaId::new(2))
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
    src.write_control_preface(Peer::Replica(ReplicaId::new(1)), &mut frame);
    assert!(
      !frame.is_empty(),
      "the Hello scheme writes a non-empty preface"
    );
    assert_eq!(
      src
        .authenticate(&IdentityCtx::new(&[], Some(&frame), cluster))
        .try_unwrap_identified()
        .unwrap()
        .who(),
      Peer::Replica(ReplicaId::new(1))
    );
  }

  #[test]
  fn provided_identity_from_cert_oid_config_authenticates_via_the_cert() {
    use crate::transport::quic::crypto::test_ca;

    // The `CertOid` selector produces a source that writes NO preface and reads identity from the cert.
    let cluster = 0x5151_u128;
    let src = IdentityConfig::CertOid { cluster }.into_source();
    let mut preface = Vec::new();
    src.write_control_preface(Peer::Replica(ReplicaId::new(2)), &mut preface);
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
        .who(),
      Peer::Replica(ReplicaId::new(2))
    );
  }
}

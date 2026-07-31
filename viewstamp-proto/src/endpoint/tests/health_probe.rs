//! The reconfiguration-shrink voter-liveness probe: the primary's `solicit_health_proofs` round, the
//! `on_request_health_proof` reply, the `on_health_proof` recorder, and the `proven_live_voters`
//! accessor. The probe is the SOLE positive liveness source the driver's shrink policy consumes. Each
//! round lives one `lifetime` (retransmitted on cadence, superseded only at expiry), and every read is
//! fail-closed: empty off a Normal primary, empty absent a fresh round, empty past the round's expiry,
//! and config-scoped (a cross-epoch challenge/reply never counts). A round never survives an epoch swap
//! (`install_membership`) or a view transition (`reset_for_view_transition`).

use super::*;
use crate::{Config, HealthProof, ReplicaId, RequestHealthProof, SingleVoterDelta};
use core::time::Duration;

/// A 3-voter cluster (ids 0,1,2) with 2 learners (ids 3,4), self = voter 0 — the PRIMARY of view 0.
fn primary_self() -> Endpoint<NoopSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(0)).expect("valid 3-voter + 2-learner config"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  )
}

/// The same cluster, but self = voter 1 — a BACKUP of view 0 (primary is slot 0).
fn backup_self() -> Endpoint<NoopSm> {
  Endpoint::<_, RestartOnly>::genesis_unchecked(
    Config::try_new(1, MemberId::new(1)).expect("valid 3-voter + 2-learner config"),
    genesis_with_learners(3, 2),
    0,
    NoopSm,
    u64::MAX,
  )
}

/// The first learner id (`replica_count == 3`, so id 3 is the first non-voting member).
const LEARNER: u16 = 3;

/// The driver's probe retransmit cadence (`health_probe_interval`): a re-solicit this often within a
/// live round retransmits its nonce rather than superseding it.
const INTERVAL: Duration = Duration::from_millis(250);
/// The round lifetime (`health_proof_max_age`): the round is retransmitted until this age, then a fresh
/// nonce is drawn; `proven_live_voters` trusts the round's evidence only within it.
const LIFETIME: Duration = Duration::from_secs(1);

/// Deliver a `HealthProof` to the primary at arrival time `now` (the recorder is time-independent, but
/// a realistic arrival keeps the driver-supplied clock monotonic across a round's retransmits).
fn deliver_proof(
  e: &mut Endpoint<NoopSm>,
  from_slot: u16,
  nonce: u64,
  epoch: u64,
  config_id: u128,
  now: Instant,
) {
  let (wal, sb) = (TestWal::default(), TestSb::default());
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    now,
    &mut storage,
    Peer::Replica(ReplicaId::new(from_slot)),
    Message::HealthProof(HealthProof::new(
      ReplicaId::new(from_slot),
      nonce,
      crate::Epoch::new(epoch),
      config_id,
    )),
  );
}

#[test]
fn a_normal_primary_solicits_one_request_per_voter_except_self() {
  // The soliciting side: a Normal PRIMARY emits exactly one `RequestHealthProof` per CURRENT VOTER
  // except itself (never to a learner), each carrying its own slot, the round nonce, and the live
  // (epoch, config_id). This is the active liveness round the shrink policy gates on.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e
    .health_probe
    .as_ref()
    .expect("a round was solicited")
    .nonce;

  let mut targets = std::collections::BTreeSet::new();
  while let Some(out) = e.poll_message() {
    if let Message::RequestHealthProof(m) = out.msg_ref() {
      assert_eq!(
        m.from(),
        ReplicaId::new(0),
        "the soliciting primary's own slot"
      );
      assert_eq!(m.nonce(), nonce, "every request carries the round nonce");
      assert_eq!(m.epoch(), crate::Epoch::new(0), "the live epoch");
      assert_eq!(m.config_id(), 0, "the live config_id");
      let crate::Recipient::To(Peer::Replica(slot)) = out.to() else {
        panic!("a health request is addressed to a specific voter slot");
      };
      assert!(targets.insert(slot.get()), "no duplicate request per voter");
    }
  }
  assert_eq!(
    targets,
    std::collections::BTreeSet::from([1u16, 2]),
    "one request per current VOTER except self (0); never to a learner (3, 4)"
  );
}

#[test]
fn a_backup_does_not_solicit() {
  // Fail-closed gate: only a Normal PRIMARY probes. A backup (self is not the primary of the view)
  // solicits nothing and arms no round.
  let mut e = backup_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  assert!(
    e.health_probe.is_none(),
    "a backup arms no liveness-probe round"
  );
  assert!(
    !core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.into_msg(), Message::RequestHealthProof(_))),
    "a backup emits no health request"
  );
}

#[test]
fn a_primary_that_is_not_normal_does_not_solicit() {
  // Fail-closed gate, the other half: a PRIMARY mid-recovery (not Normal) is not authoritative for its
  // configuration yet, so it solicits nothing and arms no round — matching the same rule
  // `propose_membership` enforces for minting a reconfiguration op.
  let mut e = primary_self();
  e.status = crate::Status::Recovering;
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  assert!(
    e.health_probe.is_none(),
    "a non-Normal primary arms no liveness-probe round"
  );
  assert!(
    !core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.into_msg(), Message::RequestHealthProof(_))),
    "a non-Normal primary emits no health request"
  );
}

#[test]
fn a_retransmit_keeps_the_round_and_expiry_resets_it() {
  // Within its lifetime a re-solicit RETRANSMITS the same nonce and KEEPS the answers already collected
  // (a lost request is re-sent without discarding evidence), and it does NOT move the round's timeline.
  // Once the round has expired a FRESH nonce is drawn and the responders RESET, so a voter counts only
  // while it keeps answering the current round.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let probe0 = e.health_probe.as_ref().unwrap().clone();
  // Seed a responder so we can observe whether the reset happens.
  e.health_probe
    .as_mut()
    .unwrap()
    .responders
    .insert(MemberId::new(1));

  // Re-solicit still WITHIN the round lifetime (250ms < 1s): same nonce, responders kept, and the
  // round's solicited_at/expires_at are unchanged — a retransmit does not extend the round.
  e.solicit_health_proofs(Instant::ZERO + INTERVAL, LIFETIME);
  let probe = e.health_probe.as_ref().unwrap();
  assert_eq!(
    probe.nonce, probe0.nonce,
    "a re-solicit within the lifetime keeps the nonce"
  );
  assert_eq!(
    probe.solicited_at, probe0.solicited_at,
    "a retransmit does not move the round's start"
  );
  assert_eq!(
    probe.expires_at, probe0.expires_at,
    "a retransmit does not extend the round's expiry"
  );
  assert!(
    probe.responders.contains(&MemberId::new(1)),
    "the collected answers are kept on a retransmit"
  );

  // Re-solicit AT the round's expiry (now == expires_at): fresh nonce, responders reset.
  e.solicit_health_proofs(Instant::ZERO + LIFETIME, LIFETIME);
  let probe = e.health_probe.as_ref().unwrap();
  assert_ne!(
    probe.nonce, probe0.nonce,
    "a re-solicit at the round's expiry draws a fresh nonce"
  );
  assert!(
    probe.responders.is_empty(),
    "a fresh round resets the responders"
  );
}

#[test]
fn a_proof_past_the_probe_interval_still_records_within_the_round_lifetime() {
  // The RTT case: a voter whose reply round-trips in more than one probe INTERVAL but within the round
  // LIFETIME still answers the round's (retransmitted, unchanged) nonce, so its proof records and it is
  // proven live. The driver retransmits every INTERVAL while each round lives for LIFETIME, so the
  // nonce is stable across a full round and a reply is admissible for the whole lifetime — a reply
  // landing past one interval is no longer lost to a nonce that a per-interval fresh draw would have
  // superseded.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e.health_probe.as_ref().unwrap().nonce;

  // The driver's cadence retransmits at each interval, all within the round lifetime — the nonce is
  // stable, so a reply for it stays admissible the whole round.
  e.solicit_health_proofs(Instant::ZERO + INTERVAL, LIFETIME);
  e.solicit_health_proofs(Instant::ZERO + INTERVAL * 2, LIFETIME);
  assert_eq!(
    e.health_probe.as_ref().unwrap().nonce,
    nonce,
    "the round nonce is stable across interval retransmits within its lifetime"
  );

  // A voter's reply for that nonce, arriving 600ms after the round opened (past the 250ms interval, well
  // within the 1s lifetime), still matches the outstanding nonce and records.
  deliver_proof(
    &mut e,
    1,
    nonce,
    0,
    0,
    Instant::ZERO + Duration::from_millis(600),
  );
  assert_eq!(
    e.proven_live_voters(Instant::ZERO + Duration::from_millis(600)),
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    "a reply within the round lifetime proves the voter live even past the retransmit interval"
  );
}

#[test]
fn a_voter_answers_a_health_challenge_with_a_live_proof() {
  // The reply side: a voter answers a `RequestHealthProof` with a `HealthProof` self-identifying by its
  // slot, echoing the challenge nonce, and carrying the live (epoch, config_id). A crashed voter never
  // answers, so a missing reply is honest evidence of absence.
  let mut e = backup_self(); // self = voter 1
  let (wal, sb) = (TestWal::default(), TestSb::default());

  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)), // from the primary
    Message::RequestHealthProof(RequestHealthProof::new(
      ReplicaId::new(0),
      0xBEEF,
      crate::Epoch::new(0),
      0,
    )),
  );

  let mut replies = std::vec::Vec::new();
  while let Some(out) = e.poll_message() {
    if let Message::HealthProof(p) = out.msg_ref() {
      assert_eq!(
        out.to(),
        crate::Recipient::To(Peer::Replica(ReplicaId::new(0))),
        "the proof is addressed to the soliciting primary",
      );
      replies.push(*p);
    }
  }
  assert_eq!(replies.len(), 1, "exactly one HealthProof per challenge");
  let proof = replies[0];
  assert_eq!(
    proof.replica(),
    ReplicaId::new(1),
    "self-identifies by the answerer's slot"
  );
  assert_eq!(proof.nonce(), 0xBEEF, "the challenge nonce is echoed");
  assert_eq!(proof.epoch(), crate::Epoch::new(0), "the live epoch");
  assert_eq!(proof.config_id(), 0, "the live config_id");
}

#[test]
fn a_cross_config_health_challenge_is_dropped() {
  // A voter answers ONLY for its live configuration: a `RequestHealthProof` carrying a foreign epoch is
  // inadmissible at the strict ingress gate AND dropped by the handler, so a stale-config challenge can
  // never elicit a proof a later round under that stale config could consume.
  let mut e = backup_self();
  let (wal, sb) = (TestWal::default(), TestSb::default());

  let foreign = Message::RequestHealthProof(RequestHealthProof::new(
    ReplicaId::new(0),
    0xBEEF,
    crate::Epoch::new(1), // foreign epoch
    0,
  ));
  assert!(
    !e.epoch_authority_admits(&foreign),
    "a cross-epoch challenge is inadmissible at ingress"
  );
  let mut storage = Storage::new(wal, sb);
  e.handle_message(
    Instant::ZERO,
    &mut storage,
    Peer::Replica(ReplicaId::new(0)),
    foreign,
  );
  assert!(
    !core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.into_msg(), Message::HealthProof(_))),
    "a cross-epoch challenge elicits no proof reply",
  );
}

#[test]
fn the_recorder_admits_a_matching_proof_and_drops_every_falsifier() {
  // The recorder side: `on_health_proof` records a voter into `responders` ONLY on a matching round —
  // Some outstanding round, matching nonce, live (epoch, config_id), and a CURRENT VOTER sender. Every
  // falsifier (stale nonce, foreign config, non-voter sender, no round) is dropped.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e.health_probe.as_ref().unwrap().nonce;

  // A matching proof from voter 1 records.
  deliver_proof(&mut e, 1, nonce, 0, 0, Instant::ZERO);
  assert!(
    e.health_probe
      .as_ref()
      .unwrap()
      .responders
      .contains(&MemberId::new(1)),
    "a matching proof from a current voter records"
  );

  // A stale-nonce (replayed) proof from voter 2 is dropped.
  deliver_proof(&mut e, 2, nonce.wrapping_add(1), 0, 0, Instant::ZERO);
  // A foreign-config proof from voter 2 is dropped.
  deliver_proof(&mut e, 2, nonce, 1, 0, Instant::ZERO);
  // A non-voter (learner slot 3) proof, even with the right nonce/config, is dropped.
  deliver_proof(&mut e, LEARNER, nonce, 0, 0, Instant::ZERO);
  let responders = &e.health_probe.as_ref().unwrap().responders;
  assert!(
    !responders.contains(&MemberId::new(2)),
    "stale-nonce/foreign-config replies drop"
  );
  assert!(
    !responders.contains(&MemberId::new(LEARNER as u128)),
    "a non-voter (learner) reply is never positive quorum evidence"
  );
  assert_eq!(responders.len(), 1, "only the one matching voter recorded");

  // With NO outstanding round, a proof records nothing (dropped, no panic).
  e.health_probe = None;
  deliver_proof(&mut e, 1, nonce, 0, 0, Instant::ZERO);
  assert!(
    e.health_probe.is_none(),
    "an unsolicited proof arms no round"
  );
}

#[test]
fn proven_live_voters_is_fail_closed_and_unions_self_within_a_live_round() {
  // The accessor: empty with NO round; else the responders UNION self within a live round; empty again
  // once the round has expired (fail-closed — a stale round proves nothing). The expiry bound is the
  // round's own `expires_at` (= the lifetime the round was solicited with), NOT a separate knob.
  let mut e = primary_self();
  assert!(
    e.proven_live_voters(Instant::ZERO).is_empty(),
    "no round → empty (self is NOT counted absent a live round)"
  );

  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e.health_probe.as_ref().unwrap().nonce;
  deliver_proof(&mut e, 1, nonce, 0, 0, Instant::ZERO);

  // Within the round lifetime: responders {1} ∪ self {0}.
  assert_eq!(
    e.proven_live_voters(Instant::ZERO + Duration::from_millis(10)),
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    "a live round yields the responders ∪ self"
  );

  // Past the round's expiry: empty (fail-closed), even though a responder answered.
  assert!(
    e.proven_live_voters(Instant::ZERO + Duration::from_secs(2))
      .is_empty(),
    "a round past its expiry proves nothing"
  );
}

#[test]
fn proven_live_voters_is_empty_off_a_normal_primary() {
  // Read-side fail-closed parity with solicit's write gate: `proven_live_voters` returns empty unless
  // this node is a Normal PRIMARY, even with an outstanding round carrying recorded answers.

  // (a) A primary that is not Normal proves nothing.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e.health_probe.as_ref().unwrap().nonce;
  deliver_proof(&mut e, 1, nonce, 0, 0, Instant::ZERO);
  assert_eq!(
    e.proven_live_voters(Instant::ZERO),
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    "a Normal primary within a live round counts its responders ∪ self"
  );
  e.status = crate::Status::Recovering;
  assert!(
    e.proven_live_voters(Instant::ZERO).is_empty(),
    "a non-Normal primary proves nothing, even with an outstanding round"
  );

  // (b) A Normal node that is not the primary proves nothing (force a round onto a backup directly).
  let mut b = backup_self();
  b.health_probe = Some(HealthProbeState {
    nonce: 7,
    solicited_at: Instant::ZERO,
    expires_at: Instant::ZERO + LIFETIME,
    responders: std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(2)]),
  });
  assert!(
    b.proven_live_voters(Instant::ZERO).is_empty(),
    "a backup proves nothing, even with an outstanding round"
  );
}

#[test]
fn reset_for_view_transition_clears_the_probe_round() {
  // A generation that ends must not carry its liveness-probe round into the successor generation: a
  // view transition wipes the outstanding round, symmetric with the install-boundary clear, so a
  // pre-transition answer can never gate a post-transition shrink.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e.health_probe.as_ref().unwrap().nonce;
  deliver_proof(&mut e, 1, nonce, 0, 0, Instant::ZERO);
  assert!(
    e.health_probe.is_some(),
    "a round is outstanding before the transition"
  );

  let mut storage = Storage::new(TestWal::default(), TestSb::default());
  e.reset_for_view_transition(Instant::ZERO, &mut storage);
  assert!(
    e.health_probe.is_none(),
    "the view transition wiped the outstanding probe round"
  );
}

#[test]
fn install_membership_clears_the_probe_round() {
  // The install-boundary clear makes per-removal freshness STRUCTURAL: every epoch swap wipes the
  // outstanding round, so a round solicited under the OLD configuration can never gate a shrink in the
  // successor. Reverting the `self.health_probe = None` clear in `install_membership` fails this test.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, LIFETIME);
  let nonce = e.health_probe.as_ref().unwrap().nonce;
  deliver_proof(&mut e, 1, nonce, 0, 0, Instant::ZERO);
  assert!(
    e.health_probe.is_some(),
    "a round is outstanding before the swap"
  );

  // Install a successor configuration (a wholesale cross-epoch install, `reconfigure_op = None`).
  let successor = e
    .membership()
    .apply_delta(&SingleVoterDelta::DemoteVoter(MemberId::new(2)))
    .expect("a valid shrink successor");
  e.install_membership(Instant::ZERO, None, successor);

  assert!(
    e.health_probe.is_none(),
    "the epoch swap wiped the outstanding probe round"
  );
  assert!(
    e.proven_live_voters(Instant::ZERO).is_empty(),
    "and the accessor is fail-closed empty after the swap"
  );
}

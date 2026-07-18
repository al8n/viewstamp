//! The reconfiguration-shrink voter-liveness probe: the primary's `solicit_health_proofs` round, the
//! `on_request_health_proof` reply, the `on_health_proof` recorder, and the `proven_live_voters`
//! accessor. The probe is the SOLE positive liveness source the driver's shrink policy consumes, and
//! it is fail-closed (empty absent a fresh round) + config-scoped (a cross-epoch challenge/reply never
//! counts) + install-cleared (a pre-swap round never gates a successor shrink).

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

const REUSE: Duration = Duration::from_millis(250);
const MAX_AGE: Duration = Duration::from_secs(1);

#[test]
fn a_normal_primary_solicits_one_request_per_voter_except_self() {
  // The soliciting side: a Normal PRIMARY emits exactly one `RequestHealthProof` per CURRENT VOTER
  // except itself (never to a learner), each carrying its own slot, the round nonce, and the live
  // (epoch, config_id). This is the active liveness round the shrink policy gates on.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, REUSE);
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
  e.solicit_health_proofs(Instant::ZERO, REUSE);
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
  e.solicit_health_proofs(Instant::ZERO, REUSE);
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
fn resolicit_within_the_reuse_window_retransmits_the_same_nonce() {
  // Within `reuse_within` a re-solicit RETRANSMITS the same nonce and KEEPS the answers already
  // collected (a lost request is re-sent without discarding evidence). Beyond it a FRESH nonce is drawn
  // and the responders RESET, so a voter counts only while it keeps answering the current round.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, REUSE);
  let n0 = e.health_probe.as_ref().unwrap().nonce;
  // Seed a responder so we can observe whether the reset happens.
  e.health_probe
    .as_mut()
    .unwrap()
    .responders
    .insert(MemberId::new(1));

  // Re-solicit still WITHIN the reuse window (100ms < 250ms): same nonce, responders kept.
  e.solicit_health_proofs(Instant::ZERO + Duration::from_millis(100), REUSE);
  let probe = e.health_probe.as_ref().unwrap();
  assert_eq!(
    probe.nonce, n0,
    "a re-solicit within the window keeps the nonce"
  );
  assert!(
    probe.responders.contains(&MemberId::new(1)),
    "the collected answers are kept on a retransmit"
  );

  // Re-solicit BEYOND the reuse window (300ms > 250ms): fresh nonce, responders reset.
  e.solicit_health_proofs(Instant::ZERO + Duration::from_millis(300), REUSE);
  let probe = e.health_probe.as_ref().unwrap();
  assert_ne!(
    probe.nonce, n0,
    "a re-solicit past the window draws a fresh nonce"
  );
  assert!(
    probe.responders.is_empty(),
    "a fresh round resets the responders"
  );
}

#[test]
fn a_voter_answers_a_health_challenge_with_a_live_proof() {
  // The reply side: a voter answers a `RequestHealthProof` with a `HealthProof` self-identifying by its
  // slot, echoing the challenge nonce, and carrying the live (epoch, config_id). A crashed voter never
  // answers, so a missing reply is honest evidence of absence.
  let mut e = backup_self(); // self = voter 1
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();

  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
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
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();

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
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
    Peer::Replica(ReplicaId::new(0)),
    foreign,
  );
  assert!(
    !core::iter::from_fn(|| e.poll_message())
      .any(|out| matches!(out.into_msg(), Message::HealthProof(_))),
    "a cross-epoch challenge elicits no proof reply",
  );
}

/// Deliver a `HealthProof` to the primary and return whether the sender was recorded as proven live.
fn deliver_proof(
  e: &mut Endpoint<NoopSm>,
  from_slot: u16,
  nonce: u64,
  epoch: u64,
  config_id: u128,
) {
  let (mut wal, mut sb) = (TestWal::default(), TestSb::default());
  let mut blocks = crate::block_store::MemBlockStore::new();
  e.handle_message(
    Instant::ZERO,
    &mut wal,
    &mut sb,
    &mut blocks,
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
fn the_recorder_admits_a_matching_proof_and_drops_every_falsifier() {
  // The recorder side: `on_health_proof` records a voter into `responders` ONLY on a matching round —
  // Some outstanding round, matching nonce, live (epoch, config_id), and a CURRENT VOTER sender. Every
  // falsifier (stale nonce, foreign config, non-voter sender, no round) is dropped.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, REUSE);
  let nonce = e.health_probe.as_ref().unwrap().nonce;

  // A matching proof from voter 1 records.
  deliver_proof(&mut e, 1, nonce, 0, 0);
  assert!(
    e.health_probe
      .as_ref()
      .unwrap()
      .responders
      .contains(&MemberId::new(1)),
    "a matching proof from a current voter records"
  );

  // A stale-nonce (replayed) proof from voter 2 is dropped.
  deliver_proof(&mut e, 2, nonce.wrapping_add(1), 0, 0);
  // A foreign-config proof from voter 2 is dropped.
  deliver_proof(&mut e, 2, nonce, 1, 0);
  // A non-voter (learner slot 3) proof, even with the right nonce/config, is dropped.
  deliver_proof(&mut e, LEARNER, nonce, 0, 0);
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
  deliver_proof(&mut e, 1, nonce, 0, 0);
  assert!(
    e.health_probe.is_none(),
    "an unsolicited proof arms no round"
  );
}

#[test]
fn proven_live_voters_is_fail_closed_and_unions_self_within_a_live_round() {
  // The accessor: empty with NO round; else the responders UNION self within a live round; empty again
  // once the round is older than `max_age` (fail-closed — a stale round proves nothing).
  let mut e = primary_self();
  assert!(
    e.proven_live_voters(Instant::ZERO, MAX_AGE).is_empty(),
    "no round → empty (self is NOT counted absent a live round)"
  );

  e.solicit_health_proofs(Instant::ZERO, REUSE);
  let nonce = e.health_probe.as_ref().unwrap().nonce;
  deliver_proof(&mut e, 1, nonce, 0, 0);

  // Within max_age: responders {1} ∪ self {0}.
  assert_eq!(
    e.proven_live_voters(Instant::ZERO + Duration::from_millis(10), MAX_AGE),
    std::collections::BTreeSet::from([MemberId::new(0), MemberId::new(1)]),
    "a live round yields the responders ∪ self"
  );

  // Older than max_age: empty (fail-closed), even though a responder answered.
  assert!(
    e.proven_live_voters(Instant::ZERO + Duration::from_secs(2), MAX_AGE)
      .is_empty(),
    "a round older than max_age proves nothing"
  );
}

#[test]
fn install_membership_clears_the_probe_round() {
  // The install-boundary clear makes per-removal freshness STRUCTURAL: every epoch swap wipes the
  // outstanding round, so a round solicited under the OLD configuration can never gate a shrink in the
  // successor. Reverting the `self.health_probe = None` clear in `install_membership` fails this test.
  let mut e = primary_self();
  e.solicit_health_proofs(Instant::ZERO, REUSE);
  let nonce = e.health_probe.as_ref().unwrap().nonce;
  deliver_proof(&mut e, 1, nonce, 0, 0);
  assert!(
    e.health_probe.is_some(),
    "a round is outstanding before the swap"
  );

  // Install a successor configuration (a wholesale cross-epoch install, `reconfigure_op = None`).
  let successor = e
    .membership()
    .apply_delta(&SingleVoterDelta::RemoveVoter(MemberId::new(2)))
    .expect("a valid shrink successor");
  e.install_membership(None, successor);

  assert!(
    e.health_probe.is_none(),
    "the epoch swap wiped the outstanding probe round"
  );
  assert!(
    e.proven_live_voters(Instant::ZERO, MAX_AGE).is_empty(),
    "and the accessor is fail-closed empty after the swap"
  );
}

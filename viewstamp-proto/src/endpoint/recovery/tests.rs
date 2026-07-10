use super::{SlotVerdict, classify_committed_slot};
use crate::{ClientId, RequestNumber};

// The slot's own identity (what the read returned), and a DIFFERENT identity (a stale slot's, or a
// same-payload-different-client slot's). The third tuple field is the body_checksum (`u128`).
const SLOT: (ClientId, RequestNumber, u128) = (ClientId::new(7), RequestNumber::with(3), 0xABCD);
// Differs in EVERY field — a header-mismatch under any of client/request/body is StaleCommitted; one
// representative is enough since the verdict compares the tuples for equality as a whole.
const OTHER: (ClientId, RequestNumber, u128) = (ClientId::new(9), RequestNumber::with(4), 0x1234);

/// FREEZE the totality of `classify_committed_slot` as a test contract: enumerate the FULL
/// cross-product {header present / absent} × {identity matches / mismatches} × {op <= / > durable_commit}
/// × {slot_view < / >= durable_log_view} and assert the verdict for EVERY cell, documenting WHY. The
/// function is total ONLY by arm ordering; this test fails a future reorder that re-opens a
/// stale-committed-body hole (the worst class) — a unit failure, not a rare schedule.
#[test]
fn classify_committed_slot_is_total_over_the_staleness_space() {
  // Fixed reference frontiers; we move `op`/`slot_view` around them to flip the C and V dimensions.
  const DURABLE_COMMIT: u64 = 100;
  const DURABLE_LOG_VIEW: u64 = 5;
  // op <= durable_commit (C = true, KNOWN-COMMITTED) vs op > durable_commit (C = false, above-band).
  let op_committed = 100; // == durable_commit ⇒ known-committed
  let op_above = 101; // > durable_commit ⇒ above the committed frontier
  // slot_view < durable_log_view (V = true, SUPERSEDED) vs >= (V = false, current generation). The
  // `>=` arm must hold at BOTH strictly-greater and EQUAL, so we test the `==` boundary explicitly.
  let view_superseded = 4; // < 5 ⇒ an abandoned earlier-view proposal
  let view_current_eq = 5; // == 5 ⇒ current generation (boundary of the `>=` predicate)
  let view_current_gt = 6; // > 5 ⇒ current generation

  let verdict = |canonical, op, slot_view| {
    classify_committed_slot(
      SLOT,
      canonical,
      op,
      slot_view,
      DURABLE_COMMIT,
      DURABLE_LOG_VIEW,
    )
  };

  // ── HEADER PRESENT + identity MATCHES (canonical == slot) ────────────────────────────────────────
  // a locally-held canonical committed op is KEPT — its own sparse header vouches it, so this
  // replica's only surviving copy is not destroyed. The match VERDICT is independent of op/view: a held
  // committed op above a LOWER header-less hole is still Verified. All 4 (C × V) cells → Verified.
  for &op in &[op_committed, op_above] {
    for &v in &[view_superseded, view_current_gt] {
      assert_eq!(
        verdict(Some(SLOT), op, v),
        SlotVerdict::Verified,
        "header present + identity match is ALWAYS Verified: op={op}, view={v}"
      );
    }
  }

  // ── HEADER PRESENT + identity MISMATCHES (canonical != slot) ─────────────────────────────────────
  // the persisted `vsr_headers` say a different body, OR the same body under a different
  // client/request — a superseded/stale slot. The mismatch VERDICT is independent of op/view:
  // a header that disagrees is authoritative. All 4 (C × V) cells → StaleCommitted.
  for &op in &[op_committed, op_above] {
    for &v in &[view_superseded, view_current_gt] {
      assert_eq!(
        verdict(Some(OTHER), op, v),
        SlotVerdict::StaleCommitted,
        "header present + identity mismatch is ALWAYS StaleCommitted: op={op}, view={v}"
      );
    }
  }

  // ── HEADER ABSENT + KNOWN-COMMITTED (op <= durable_commit) ───────────────────────────────────────
  // the sparse set has one header per committed-band op the writer HELD, so NO header ⇒ the
  // writer did not hold this committed op (a genuine hole / stale leftover the headers do not vouch).
  // The local self-verifying body is UNPROVEN and must be peer-repaired. The VERDICT is independent of
  // the view (the committed-band arm wins before the view is even consulted). Both V cells →
  // StaleCommitted.
  for &v in &[view_superseded, view_current_gt] {
    assert_eq!(
      verdict(None, op_committed, v),
      SlotVerdict::StaleCommitted,
      "header absent + known-committed is StaleCommitted: view={v}"
    );
  }

  // ── HEADER ABSENT + ABOVE-commit (op > durable_commit) + SUPERSEDED view (slot_view < log_view) ───
  // An above-band tail op from a generation we have already superseded — we advanced
  // `log_view` past its view, so its body is an abandoned earlier-view proposal. → StaleCommitted.
  assert_eq!(
    verdict(None, op_above, view_superseded),
    SlotVerdict::StaleCommitted,
    "header absent + above-commit + superseded view is StaleCommitted"
  );

  // ── HEADER ABSENT + ABOVE-commit (op > durable_commit) + CURRENT-generation view (>= log_view) ────
  // A current uncommitted tail op (no canonical header, not superseded): kept to be re-acked. → Verified.
  // Tested at BOTH the `==` boundary and strictly-greater so the `>=` predicate is pinned.
  for &v in &[view_current_eq, view_current_gt] {
    assert_eq!(
      verdict(None, op_above, v),
      SlotVerdict::Verified,
      "header absent + above-commit + current-generation view is Verified (current tail): view={v}"
    );
  }

  // ── Boundary corollary: the KNOWN-COMMITTED predicate is `op <= durable_commit` (INCLUSIVE). An op
  // EXACTLY AT durable_commit with no header is StaleCommitted (covered above via op_committed == 100);
  // the very next op (durable_commit + 1) with no header + current view is Verified (op_above above).
  // This pins the `<=` boundary so an off-by-one to `<` cannot silently trust a not-held committed op.
  assert_eq!(
    verdict(None, DURABLE_COMMIT, view_current_gt),
    SlotVerdict::StaleCommitted,
    "op == durable_commit (no header) is known-committed ⇒ StaleCommitted (the `<=` boundary)"
  );
  assert_eq!(
    verdict(None, DURABLE_COMMIT + 1, view_current_gt),
    SlotVerdict::Verified,
    "op == durable_commit + 1 (no header, current view) is above-band ⇒ Verified"
  );
}

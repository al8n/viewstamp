use bytes::Bytes;

use super::*;
use crate::{ReplyBody, ReplyTooLarge};

#[test]
fn committed_carries_the_outcome_it_was_built_from() {
  let payload = Bytes::from_static(b"reply-payload");
  let committed = Committed::new(
    OpNumber::with(3),
    ClientId::new(9),
    RequestNumber::with(1),
    ReplyOutcome::from_applied(payload.clone()),
  );
  assert_eq!(
    committed.outcome().as_ok().map(ReplyBody::as_bytes),
    Some(payload.as_ref())
  );
  // The borrowing accessor leaves the record intact for the consuming one.
  assert_eq!(committed.clone().into_outcome(), *committed.outcome());
}

#[test]
fn committed_carries_a_refusal_as_the_outcome() {
  let err = ReplyTooLarge::new(ReplyBody::max_len() + 1, ReplyBody::max_len());
  let committed = Committed::new(
    OpNumber::with(3),
    ClientId::new(9),
    RequestNumber::with(1),
    ReplyOutcome::TooLarge(err),
  );
  assert!(committed.outcome().is_too_large());
  assert_eq!(committed.outcome().as_too_large(), Some(&err));
}

#[test]
fn view_changed_reports_the_view_and_the_primary_role() {
  let primary = ViewChanged::new(View::with(4), true);
  let backup = ViewChanged::new(View::with(4), false);
  assert_eq!(primary.view(), View::with(4));
  assert!(primary.is_primary());
  assert_eq!(backup.view(), View::with(4));
  assert!(!backup.is_primary());
}

#[test]
fn repair_started_reports_the_solicited_hole_band_bounds() {
  let repair = RepairStarted::new(OpNumber::with(5), OpNumber::with(9));
  assert_eq!(repair.lo(), OpNumber::with(5));
  assert_eq!(repair.hi(), OpNumber::with(9));
}

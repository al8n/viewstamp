use super::*;

#[test]
fn committed_reply_bytes_clones_the_reply_payload() {
  let payload = Bytes::from_static(b"reply-payload");
  let committed = Committed::new(
    OpNumber::with(3),
    ClientId::new(9),
    RequestNumber::with(1),
    payload.clone(),
  );
  assert_eq!(committed.reply_bytes(), payload);
  // `reply_bytes` clones rather than consumes: the borrowing accessor still reads the same bytes.
  assert_eq!(committed.reply(), payload.as_ref());
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

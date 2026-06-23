use super::*;

#[test]
fn phase_predicates_are_correct() {
  assert!(Phase::Handshaking.is_handshaking());
  assert!(!Phase::Handshaking.is_authenticating());
  assert!(!Phase::Handshaking.is_validated());
  assert!(!Phase::Handshaking.is_closed());

  assert!(Phase::Authenticating.is_authenticating());
  assert!(!Phase::Authenticating.is_handshaking());
  assert!(!Phase::Authenticating.is_validated());
  assert!(!Phase::Authenticating.is_closed());

  assert!(Phase::Validated.is_validated());
  assert!(!Phase::Validated.is_handshaking());
  assert!(!Phase::Validated.is_authenticating());
  assert!(!Phase::Validated.is_closed());

  assert!(Phase::Closed.is_closed());
  assert!(!Phase::Closed.is_handshaking());
  assert!(!Phase::Closed.is_authenticating());
  assert!(!Phase::Closed.is_validated());
}

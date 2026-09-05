use super::*;

#[test]
fn close_cause_as_str_names_every_variant() {
  assert_eq!(CloseCause::RecordRejected.as_str(), "record_rejected");
  assert_eq!(CloseCause::FrameTooLong.as_str(), "frame_too_long");
  assert_eq!(CloseCause::BadFrame.as_str(), "bad_frame");
  assert_eq!(CloseCause::TruncatedFrame.as_str(), "truncated_frame");
  assert_eq!(CloseCause::PeerClosed.as_str(), "peer_closed");
  assert_eq!(CloseCause::OutboundOverflow.as_str(), "outbound_overflow");
  assert_eq!(CloseCause::IdentityRejected.as_str(), "identity_rejected");
  assert_eq!(CloseCause::AuthDeadline.as_str(), "auth_deadline");
  assert_eq!(CloseCause::AcceptCapacity.as_str(), "accept_capacity");
  assert_eq!(CloseCause::IdleTimeout.as_str(), "idle_timeout");
  assert_eq!(CloseCause::Superseded.as_str(), "superseded");
  assert_eq!(CloseCause::UnsolicitedStream.as_str(), "unsolicited_stream");
  // The derived Display forwards to as_str.
  assert_eq!(
    std::format!("{}", CloseCause::Superseded),
    "superseded",
    "Display renders the same stable name as_str returns"
  );
}

#[test]
fn close_cause_from_transport_error_maps_every_variant() {
  assert_eq!(
    CloseCause::from(&TransportError::FrameTooLong { len: 10, max: 5 }),
    CloseCause::FrameTooLong
  );
  assert_eq!(
    CloseCause::from(&TransportError::TruncatedFrame { remaining: 3 }),
    CloseCause::TruncatedFrame
  );
  assert_eq!(
    CloseCause::from(&TransportError::RecordRejected),
    CloseCause::RecordRejected
  );
  assert_eq!(
    CloseCause::from(&TransportError::Decode(crate::CodecError::Truncated {
      expected: 1,
      got: 0
    })),
    CloseCause::BadFrame
  );
}

use super::*;

#[test]
fn peer_predicates() {
  let r = Peer::Replica(ReplicaId::new(2));
  let c = Peer::Client(ClientId::new(7));
  assert!(r.is_replica() && !r.is_client());
  assert_eq!(r.as_replica(), Some(ReplicaId::new(2)));
  assert!(c.is_client() && c.as_replica().is_none());
  assert_eq!(ReplicaId::new(2).get(), 2);
  assert_eq!(ClientId::new(7).get(), 7);
}

#[test]
fn replica_id_display_matches_the_raw_index() {
  assert_eq!(std::format!("{}", ReplicaId::new(9)), "9");
}

#[test]
fn epoch_display_matches_the_raw_number() {
  assert_eq!(std::format!("{}", Epoch::new(3)), "3");
}

#[test]
fn peer_member_variant_predicates_and_accessors() {
  let m = Peer::Member(MemberId::new(11));
  let r = Peer::Replica(ReplicaId::new(2));
  let c = Peer::Client(ClientId::new(7));

  // is_member is true only for the Member variant.
  assert!(m.is_member());
  assert!(!r.is_member());
  assert!(!c.is_member());

  // as_member is Some only for the Member variant.
  assert_eq!(m.as_member(), Some(MemberId::new(11)));
  assert_eq!(r.as_member(), None);
  assert_eq!(c.as_member(), None);

  // as_client is Some only for the Client variant.
  assert_eq!(c.as_client(), Some(ClientId::new(7)));
  assert_eq!(r.as_client(), None);
  assert_eq!(m.as_client(), None);
}

#[test]
fn recipient_predicates_and_as_to_accessor() {
  let to = Recipient::To(Peer::Replica(ReplicaId::new(4)));
  let backups = Recipient::Backups;
  let all = Recipient::AllReplicas;

  assert!(to.is_to());
  assert!(!backups.is_to());
  assert!(!all.is_to());

  assert!(!to.is_all_replicas());
  assert!(!backups.is_all_replicas());
  assert!(all.is_all_replicas());

  assert_eq!(to.as_to(), Some(Peer::Replica(ReplicaId::new(4))));
  assert_eq!(backups.as_to(), None);
  assert_eq!(all.as_to(), None);
}

#[test]
fn member_id_and_epoch_round_trip() {
  let m = MemberId::new(0xDEAD_BEEF_0000_0001_0000_0000_0000_0002);
  assert_eq!(m.get(), 0xDEAD_BEEF_0000_0001_0000_0000_0000_0002);
  assert_eq!(MemberId::new(7), MemberId::new(7));
  assert_ne!(MemberId::new(7), MemberId::new(8));
  let e = Epoch::new(5);
  assert_eq!(e.get(), 5);
  assert!(Epoch::new(0) < Epoch::new(1));
  assert_eq!(Epoch::new(4).next(), Epoch::new(5));
  assert_eq!(std::format!("{}", MemberId::new(42)), "42");
}

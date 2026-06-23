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

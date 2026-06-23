use super::*;

#[test]
fn same_seed_same_sequence() {
  let mut a = Prng::new(0xDEAD_BEEF);
  let mut b = Prng::new(0xDEAD_BEEF);
  for _ in 0..100 {
    assert_eq!(a.next_u64(), b.next_u64());
  }
  let mut c = Prng::new(1);
  assert_ne!(c.next_u64(), Prng::new(2).next_u64());
  // bounded
  let mut d = Prng::new(7);
  for _ in 0..1000 {
    assert!(d.below(10) < 10);
  }
}

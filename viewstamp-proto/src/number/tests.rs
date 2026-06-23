use super::*;

#[test]
fn next_and_get() {
  assert_eq!(View::new().get(), 0);
  assert_eq!(OpNumber::new().next().get(), 1);
  assert_eq!(RequestNumber::with(5).get(), 5);
  assert_eq!(OpNumber::with(3).next(), OpNumber::with(4));
}

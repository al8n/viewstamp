use super::*;
use std::string::ToString;

#[test]
fn as_str_and_display() {
  assert_eq!(Status::Normal.as_str(), "normal");
  assert_eq!(Status::RecoveringHead.as_str(), "recovering_head");
  assert_eq!(Status::ViewChange.to_string(), "view_change");
  assert!(Status::Normal.is_normal());
  assert!(!Status::Recovering.is_normal());
}

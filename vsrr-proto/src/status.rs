//! Replica operating status.

/// The operating status of a replica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Display)]
#[display("{}", self.as_str())]
#[non_exhaustive]
#[repr(u8)]
pub enum Status {
  /// Normal operation (processing client requests).
  Normal,
  /// Performing a view change.
  ViewChange,
  /// Recovering at startup with intact persistent state.
  Recovering,
  /// Recovering at startup with corrupt persistent state; cannot vote until a
  /// `StartView` re-establishes the head.
  RecoveringHead,
}

impl Status {
  /// The stable string name of this status (snake_case, serialization-stable).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Normal => "normal",
      Self::ViewChange => "view_change",
      Self::Recovering => "recovering",
      Self::RecoveringHead => "recovering_head",
    }
  }

  /// True iff `self == Status::Normal`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_normal(&self) -> bool {
    matches!(self, Self::Normal)
  }

  /// True iff `self == Status::ViewChange`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_view_change(&self) -> bool {
    matches!(self, Self::ViewChange)
  }

  /// True iff `self == Status::Recovering`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_recovering(&self) -> bool {
    matches!(self, Self::Recovering)
  }

  /// True iff `self == Status::RecoveringHead`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_recovering_head(&self) -> bool {
    matches!(self, Self::RecoveringHead)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use alloc::string::ToString;

  #[test]
  fn as_str_and_display() {
    assert_eq!(Status::Normal.as_str(), "normal");
    assert_eq!(Status::RecoveringHead.as_str(), "recovering_head");
    assert_eq!(Status::ViewChange.to_string(), "view_change");
    assert!(Status::Normal.is_normal());
    assert!(!Status::Recovering.is_normal());
  }
}

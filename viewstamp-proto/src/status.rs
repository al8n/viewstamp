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
  /// Removed from the configuration by a reconfiguration — the local member holds neither a voting
  /// nor a learner slot. A Retired replica is no longer a cluster member: it participates in NOTHING
  /// (the central ingress drops every consensus message, it services no timer, it casts no vote and
  /// serves no request), mirroring the recovery-time `Recovered::Retired` outcome for a node that
  /// discovers its own removal on restart. The structural close for the removed-member class: a
  /// removed node cannot reach any voter path (nor a panicking `local_slot()`) by construction. The
  /// embedder, observing the `MembershipChanged` that removed it, shuts the node down.
  Retired,
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
      Self::Retired => "retired",
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

  /// True iff `self == Status::Retired` — removed from the configuration; no longer a cluster member.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_retired(&self) -> bool {
    matches!(self, Self::Retired)
  }
}

#[cfg(test)]
mod tests {
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
}

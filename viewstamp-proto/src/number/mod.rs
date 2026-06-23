//! Counter newtypes used throughout the protocol.

macro_rules! counter {
  ($(#[$meta:meta])* $name:ident) => {
    $(#[$meta])*
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct $name(u64);

    impl Default for $name {
      #[cfg_attr(not(tarpaulin), inline(always))]
      fn default() -> Self {
        Self::new()
      }
    }

    impl $name {
      #[doc = concat!("Creates a `", stringify!($name), "` with value 0.")]
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn new() -> Self {
        Self(0)
      }

      #[doc = concat!("Creates a `", stringify!($name), "` with the given value.")]
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn with(n: u64) -> Self {
        Self(n)
      }

      /// The underlying value.
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn get(self) -> u64 {
        self.0
      }

      /// The successor value (saturating at `u64::MAX`).
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
      }
    }

    impl core::fmt::Display for $name {
      #[cfg_attr(not(tarpaulin), inline(always))]
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
      }
    }

    impl From<$name> for u64 {
      #[cfg_attr(not(tarpaulin), inline(always))]
      fn from(v: $name) -> Self {
        v.0
      }
    }
  };
}

counter!(
  /// A view number in the Viewstamped Replication protocol.
  View
);
counter!(
  /// An operation (log) number in the Viewstamped Replication protocol.
  OpNumber
);
counter!(
  /// A per-client monotonic request number (at-most-once dedup key).
  RequestNumber
);

#[cfg(test)]
mod tests;

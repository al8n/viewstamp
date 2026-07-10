/// Runtime-agnostic membership-config gate. Owns the last-seen `config_id`; `check` advances it
/// and returns `true` iff the id changed — the single place where QUIC and stream drivers agree on
/// what "a new config" means.
pub struct MembershipReconciler {
  last_config_id: u128,
}

impl MembershipReconciler {
  pub const fn new(last_config_id: u128) -> Self {
    Self { last_config_id }
  }

  /// Returns `true` and advances the stored id iff `config_id` differs from the last seen value.
  /// O(1) on the no-change path (the common case in the hot loop).
  pub fn check(&mut self, config_id: u128) -> bool {
    if config_id == self.last_config_id {
      return false;
    }
    self.last_config_id = config_id;
    true
  }
}

#[cfg(test)]
mod tests;

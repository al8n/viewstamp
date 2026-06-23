/// A small deterministic PRNG (SplitMix64). Used for protocol backoff jitter and
/// by the simulation harness for fault scheduling. Deterministic given its seed.
#[derive(Debug, Clone)]
pub struct Prng(u64);

impl Prng {
  /// Creates a PRNG from a seed.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new(seed: u64) -> Self {
    Self(seed)
  }

  /// Returns the next pseudo-random `u64` and advances the state.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn next_u64(&mut self) -> u64 {
    self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = self.0;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
  }

  /// Returns a value in `0..bound` (unbiased enough for simulation; `bound > 0`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn below(&mut self, bound: u64) -> u64 {
    debug_assert!(bound > 0);
    self.next_u64() % bound
  }

  /// Returns `true` with probability `numerator / denominator`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn chance(&mut self, numerator: u32, denominator: u32) -> bool {
    debug_assert!(denominator > 0);
    self.below(denominator as u64) < numerator as u64
  }
}

#[cfg(test)]
mod tests;

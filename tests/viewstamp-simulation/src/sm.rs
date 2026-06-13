use bytes::Bytes;
use viewstamp_proto::{BatchView, OpNumber, ReplyBuilder, StateMachine};

/// The per-unit reply ceiling [`BatchSm`] declares to its [`ReplyBuilder`] and the batching client
/// model budgets each body against. Every [`BatchSm`] unit reply is exactly 8 bytes (the LogSm-style
/// big-endian count), so 32 is comfortably above the real size — the ceiling-priced reply budget is
/// then a strictly looser bound than reality, exactly the aggregator's worst-case-pricing contract.
pub const SIM_UNIT_REPLY_CEILING: usize = 32;

/// The reply-body budget [`BatchSm`] seals each reply batch to, and the second axis of the batching
/// client model's dual-budget packing rule: a body is admitted only while its CEILING-priced reply
/// (`BATCH_COUNT_OVERHEAD + units * (BATCH_UNIT_OVERHEAD + SIM_UNIT_REPLY_CEILING)`) fits this.
/// Far below the real `max_reply_body_len()` so the unit-count cap genuinely binds in the sim
/// (28 units per body) instead of being dwarfed by the request-byte budget.
pub const SIM_REPLY_BODY_BUDGET: usize = 1024;

/// A deterministic state machine that records the sequence of applied operations.
/// The reply is the post-apply length encoded as 8 big-endian bytes — enough for
/// the linearizability checker to verify ordering and uniqueness.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LogSm {
  applied: Vec<(u64, Bytes)>,
}

impl LogSm {
  /// The ordered list of applied `(op, body)` pairs.
  pub fn applied(&self) -> &[(u64, Bytes)] {
    &self.applied
  }
}

impl StateMachine for LogSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), Bytes::copy_from_slice(body)));
    Bytes::from((self.applied.len() as u64).to_be_bytes().to_vec())
  }

  fn snapshot(&self) -> Bytes {
    let mut out = Vec::new();
    out.extend_from_slice(&(self.applied.len() as u64).to_be_bytes());
    for (op, body) in &self.applied {
      out.extend_from_slice(&op.to_be_bytes());
      out.extend_from_slice(&(body.len() as u64).to_be_bytes());
      out.extend_from_slice(body);
    }
    Bytes::from(out)
  }

  fn restore(&mut self, snapshot: &[u8]) {
    let mut applied = Vec::new();
    let mut i = 0usize;
    let count = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
    i += 8;
    for _ in 0..count {
      let op = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
      i += 8;
      let len = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap()) as usize;
      i += 8;
      applied.push((op, Bytes::copy_from_slice(&snapshot[i..i + len])));
      i += len;
    }
    self.applied = applied;
  }
}

/// A batch-aware [`LogSm`]: every committed op body is a [`BatchView`]-encoded batch of units, each
/// applied in order with LogSm's per-apply semantics (record it; reply = the post-apply UNIT count
/// as 8 big-endian bytes), the per-unit replies sealed into one reply body by a [`ReplyBuilder`].
///
/// Two histories are recorded:
/// - the per-OP `(op, whole body)` log ([`Self::applied`]) — the same shape as [`LogSm::applied`],
///   so every existing op-level checker (agreement, durability, digests) judges batched runs
///   unchanged;
/// - the per-UNIT `(op, unit_index, unit_bytes)` log ([`Self::units`]) — what the per-unit oracle
///   asserts submitted units against. Derivable from the op log by re-parsing each body, which is
///   exactly how [`StateMachine::restore`] rebuilds it, so the snapshot stays byte-compatible with
///   [`LogSm`]'s encoding while still round-tripping the unit history.
///
/// The sim only produces codec-built bodies (the batching client model and the single-unit wrap
/// both go through the real [`BatchBuilder`](viewstamp_proto::BatchBuilder)), so a malformed body
/// reaching `apply` is a sim bug: it panics loudly rather than degrading into a parse-error path
/// the protocol would never see.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BatchSm {
  applied: Vec<(u64, Bytes)>,
  units: Vec<(u64, u32, Bytes)>,
}

impl BatchSm {
  /// The ordered list of applied `(op, body)` pairs (whole batch bodies, one per op).
  pub fn applied(&self) -> &[(u64, Bytes)] {
    &self.applied
  }

  /// The ordered per-unit history: `(op, unit_index, unit_bytes)`, one entry per applied unit, in
  /// apply order. The deterministic reply of the unit at position `k` is `(k + 1)` as 8 big-endian
  /// bytes — the LogSm count semantics, counting units instead of ops.
  pub fn units(&self) -> &[(u64, u32, Bytes)] {
    &self.units
  }

  /// Parses `body` as a batch and appends its units to the unit history. The single decode path
  /// shared by `apply` and `restore`, so the rebuilt-from-snapshot history is the applied history.
  fn record_units(&mut self, op: u64, body: &[u8]) -> usize {
    let view = match BatchView::parse(body) {
      Ok(view) => view,
      Err(err) => panic!(
        "BatchSm got a malformed body at op {op} ({} bytes): {err} — the sim only produces \
         codec-built bodies, so this is a sim bug",
        body.len()
      ),
    };
    let before = self.units.len();
    for (idx, unit) in view.units().enumerate() {
      self
        .units
        .push((op, idx as u32, Bytes::copy_from_slice(unit)));
    }
    self.units.len() - before
  }
}

impl StateMachine for BatchSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    self.applied.push((op.get(), Bytes::copy_from_slice(body)));
    let first = self.units.len();
    let count = self.record_units(op.get(), body);
    let mut reply = ReplyBuilder::new(SIM_REPLY_BODY_BUDGET, SIM_UNIT_REPLY_CEILING);
    for k in first..first + count {
      // The per-unit LogSm reply: the global unit count after this unit, 8 big-endian bytes.
      reply
        .push(&((k as u64 + 1).to_be_bytes()))
        .expect("8-byte unit replies of a model-capped batch fit the sim reply budget");
    }
    reply
      .finish()
      .expect("a parsed batch carries at least one unit")
  }

  fn snapshot(&self) -> Bytes {
    // Byte-identical to LogSm's encoding over the per-op log; the unit history is derived state.
    let mut out = Vec::new();
    out.extend_from_slice(&(self.applied.len() as u64).to_be_bytes());
    for (op, body) in &self.applied {
      out.extend_from_slice(&op.to_be_bytes());
      out.extend_from_slice(&(body.len() as u64).to_be_bytes());
      out.extend_from_slice(body);
    }
    Bytes::from(out)
  }

  fn restore(&mut self, snapshot: &[u8]) {
    let mut applied = Vec::new();
    let mut i = 0usize;
    let count = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
    i += 8;
    for _ in 0..count {
      let op = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap());
      i += 8;
      let len = u64::from_be_bytes(snapshot[i..i + 8].try_into().unwrap()) as usize;
      i += 8;
      applied.push((op, Bytes::copy_from_slice(&snapshot[i..i + len])));
      i += len;
    }
    self.units.clear();
    for (op, body) in &applied {
      self.record_units(*op, body);
    }
    self.applied = applied;
  }
}

/// The cluster's state-machine type: every replica runs one of these, and the whole cluster runs
/// the SAME variant (the mode is cluster configuration, fixed before the run starts). `Plain` is
/// the plain [`LogSm`] — the default, leaving per-seed schedules byte-identical — and
/// `Batch` is the batching lane's [`BatchSm`]. Delegation only: no extra state, no PRNG, identical
/// snapshot bytes per variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimSm {
  /// The plain op-level recorder (the default).
  Plain(LogSm),
  /// The batch-aware recorder (the batching lane).
  Batch(BatchSm),
}

impl SimSm {
  /// The ordered list of applied `(op, body)` pairs — the op-level history every existing checker
  /// reads, identical in shape across both variants.
  pub fn applied(&self) -> &[(u64, Bytes)] {
    match self {
      Self::Plain(sm) => sm.applied(),
      Self::Batch(sm) => sm.applied(),
    }
  }

  /// The per-unit history `(op, unit_index, unit_bytes)` — empty for the plain variant (no body is
  /// unit-structured there).
  pub fn units(&self) -> &[(u64, u32, Bytes)] {
    match self {
      Self::Plain(_) => &[],
      Self::Batch(sm) => sm.units(),
    }
  }
}

impl StateMachine for SimSm {
  fn apply(&mut self, op: OpNumber, body: &[u8]) -> Bytes {
    match self {
      Self::Plain(sm) => sm.apply(op, body),
      Self::Batch(sm) => sm.apply(op, body),
    }
  }

  fn snapshot(&self) -> Bytes {
    match self {
      Self::Plain(sm) => sm.snapshot(),
      Self::Batch(sm) => sm.snapshot(),
    }
  }

  fn restore(&mut self, snapshot: &[u8]) {
    match self {
      Self::Plain(sm) => sm.restore(snapshot),
      Self::Batch(sm) => sm.restore(snapshot),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn apply_records_and_counts() {
    let mut sm = LogSm::default();
    assert_eq!(
      sm.apply(OpNumber::with(1), b"a").as_ref(),
      &1u64.to_be_bytes()
    );
    assert_eq!(
      sm.apply(OpNumber::with(2), b"b").as_ref(),
      &2u64.to_be_bytes()
    );
    assert_eq!(sm.applied().len(), 2);
  }

  #[test]
  fn snapshot_round_trips() {
    let mut sm = LogSm::default();
    sm.apply(OpNumber::with(1), b"a");
    sm.apply(OpNumber::with(2), b"bb");
    let snap = sm.snapshot();
    let mut restored = LogSm::default();
    restored.restore(&snap);
    assert_eq!(restored.applied(), sm.applied());
  }

  /// Builds a batch body from `units` via the real codec.
  fn batch_body(units: &[&[u8]]) -> Bytes {
    let mut b = viewstamp_proto::BatchBuilder::new(SIM_REPLY_BODY_BUDGET);
    for u in units {
      b.push(u).expect("test unit fits");
    }
    b.finish().expect("non-empty")
  }

  /// Decodes a reply body into its per-unit 8-byte big-endian counts.
  fn reply_counts(body: &[u8]) -> Vec<u64> {
    viewstamp_proto::ReplyView::parse(body)
      .expect("BatchSm seals codec-valid replies")
      .units()
      .map(|u| u64::from_be_bytes(u.try_into().expect("8-byte unit replies")))
      .collect()
  }

  #[test]
  fn batch_sm_applies_units_in_order_and_replies_with_global_unit_counts() {
    let mut sm = BatchSm::default();
    let r1 = sm.apply(OpNumber::with(1), &batch_body(&[b"a", b"bb", b""]));
    assert_eq!(reply_counts(&r1), vec![1, 2, 3]);
    let r2 = sm.apply(OpNumber::with(2), &batch_body(&[b"cc"]));
    assert_eq!(reply_counts(&r2), vec![4], "the unit count is global");
    assert_eq!(sm.applied().len(), 2, "one applied entry per OP");
    let units: Vec<(u64, u32, &[u8])> = sm
      .units()
      .iter()
      .map(|(op, idx, b)| (*op, *idx, b.as_ref()))
      .collect();
    assert_eq!(
      units,
      vec![(1, 0, &b"a"[..]), (1, 1, b"bb"), (1, 2, b""), (2, 0, b"cc"),],
      "per-unit history records (op, unit_index, unit_bytes) in apply order"
    );
  }

  #[test]
  fn batch_sm_snapshot_round_trips_the_unit_history() {
    let mut sm = BatchSm::default();
    sm.apply(OpNumber::with(1), &batch_body(&[b"a", b"bb"]));
    sm.apply(OpNumber::with(2), &batch_body(&[b"c"]));
    let snap = sm.snapshot();
    let mut restored = BatchSm::default();
    restored.restore(&snap);
    assert_eq!(restored.applied(), sm.applied());
    assert_eq!(
      restored.units(),
      sm.units(),
      "the unit history is rebuilt from the restored bodies"
    );
    // Applying past the restore keeps the global unit count consistent with the rebuilt history.
    let r = restored.apply(OpNumber::with(3), &batch_body(&[b"d"]));
    assert_eq!(reply_counts(&r), vec![4]);
  }

  #[test]
  #[should_panic(expected = "malformed body")]
  fn batch_sm_panics_loudly_on_a_non_batch_body() {
    // A plain 8-byte LogSm-style body starts with 4 zero bytes (a zero unit count) — malformed for
    // the batch codec, which in a batching-mode sim means a non-codec-built body leaked through.
    BatchSm::default().apply(OpNumber::with(1), &1u64.to_be_bytes());
  }

  #[test]
  fn sim_sm_delegates_per_variant() {
    let mut plain = SimSm::Plain(LogSm::default());
    assert_eq!(
      plain.apply(OpNumber::with(1), b"x").as_ref(),
      &1u64.to_be_bytes(),
      "the plain variant is LogSm verbatim"
    );
    assert_eq!(plain.applied().len(), 1);
    assert!(plain.units().is_empty(), "no unit structure in plain mode");
    // Plain snapshots restore into a plain SM byte-compatibly with LogSm.
    let mut log = LogSm::default();
    log.apply(OpNumber::with(1), b"x");
    assert_eq!(plain.snapshot(), log.snapshot());

    let mut batch = SimSm::Batch(BatchSm::default());
    batch.apply(OpNumber::with(1), &batch_body(&[b"u1", b"u2"]));
    assert_eq!(batch.applied().len(), 1);
    assert_eq!(batch.units().len(), 2);
    let snap = batch.snapshot();
    let mut restored = SimSm::Batch(BatchSm::default());
    restored.restore(&snap);
    assert_eq!(restored.units(), batch.units());
  }
}

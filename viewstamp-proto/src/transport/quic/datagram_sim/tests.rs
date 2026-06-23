use super::*;

/// The fault SCHEDULE is reproducible: the same seed yields byte-identical drop/dup/reorder
/// decisions in the same order across two independent pipes. This is the determinism the module
/// claims (the handshake ciphertext is independent OS entropy and is deliberately NOT asserted on).
#[test]
fn fault_schedule_is_deterministic() {
  let faults = Faults {
    drop_per_mille: 100,
    dup_per_mille: 50,
    reorder_per_mille: 100,
  };
  let from = addr(1);

  // Record the (drop, dup, reorder) decision triple for a fixed sequence of enqueues under one
  // seed, by reading the per_mille stream directly in the fixed (drop, dup, reorder) order.
  let decisions = |seed: u64| -> Vec<(bool, bool, bool)> {
    let mut rng = Rng::new(seed);
    (0..256)
      .map(|_| {
        let d = rng.per_mille(faults.drop_per_mille);
        let u = rng.per_mille(faults.dup_per_mille);
        let r = rng.per_mille(faults.reorder_per_mille);
        (d, u, r)
      })
      .collect()
  };
  assert_eq!(
    decisions(0xDEAD_BEEF),
    decisions(0xDEAD_BEEF),
    "the same seed must produce an identical decision stream"
  );
  assert_ne!(
    decisions(1),
    decisions(2),
    "different seeds must diverge (else the sweep is not exploring distinct schedules)"
  );

  // And the pipe ITSELF is deterministic given the seed: same enqueues + same ticks → same
  // delivery sequence. Reordered datagrams (held a few ticks) land after the traffic that
  // overtook them, so the order is not merely the input order.
  let run_pipe = |seed: u64| -> Vec<Vec<u8>> {
    let mut rng = Rng::new(seed);
    let mut pipe = FaultyPipe::default();
    let mut out = Vec::new();
    for tick in 0..256usize {
      pipe.push_faulted(&mut rng, faults, tick, from, std::vec![tick as u8]);
      for (_, bytes) in pipe.pop_due(tick) {
        out.push(bytes);
      }
    }
    out
  };
  assert_eq!(
    run_pipe(0x1234),
    run_pipe(0x1234),
    "the FaultyPipe delivery sequence must be reproducible per seed"
  );
}

/// Both stream layouts converge under MODERATE datagram faults across a seed sweep: a 2-replica
/// cluster commits one small client request on both sides over cluster-private mTLS while the
/// virtual UDP link drops 10%, duplicates 5%, and reorders 10% of every datagram (handshake AND
/// stream traffic), under each of 16 distinct seeds.
///
/// This is the core transport-robustness proof: quinn retransmits lost datagrams, dedupes
/// duplicates at the packet layer, and reassembles reordered stream frames; the proto tolerates a
/// re-delivered or reordered consensus message. The budget is generous (40_000 ticks = 200 s of
/// virtual time) because loss legitimately costs retransmission round-trips — well within the fault
/// rate where a connection survives the 1 s idle timeout. Both `Single` and `ControlBulk` are
/// covered (the per-class reset/reopen and recv-class adoption see the reorder/dup too).
#[test]
fn converges_under_moderate_datagram_faults() {
  let faults = Faults {
    drop_per_mille: 100,
    dup_per_mille: 50,
    reorder_per_mille: 100,
  };
  for layout in [StreamLayout::Single, StreamLayout::ControlBulk] {
    for seed in 0..16u64 {
      assert!(
        converges_under_faults(Scheme::CertOid, layout, seed, faults),
        "layout {layout:?} seed {seed} did not converge under moderate datagram faults"
      );
    }
  }
}

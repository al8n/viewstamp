//! Seeded BEHAVIORAL datagram simulator: drive two [`QuicCoordinator`](super::QuicCoordinator)s over
//! a virtual UDP network that DROPS, REORDERS, and DUPLICATES datagrams under a per-seed fault
//! schedule, and prove the QUIC transport still reaches consensus — for BOTH stream layouts, across a
//! seed sweep.
//!
//! # What this covers (and what it does not)
//!
//! This extends the [`loopback`](super::loopback) harness with an adversarial network. The bare
//! message-level VOPR in `viewstamp-simulation` drives the consensus [`Endpoint`](crate::Endpoint)
//! directly and BYPASSES the transport entirely; this sim is the only place the transport's
//! handshake + per-class streams + reset/reopen machinery sees datagram loss, reorder, and
//! duplication. quinn retransmits the lost datagrams and reassembles the reordered stream frames
//! under a lossy link the instant loopback cannot produce; this sim proves consensus still converges
//! across it.
//!
//! It is also the regression net for the transport's `initial_rtt` tuning (see
//! [`crypto`](super::crypto)): a dropped handshake datagram must retransmit faster than the consensus
//! primary-idle, or a backup would view-change off a not-yet-connected primary and a 2-replica
//! cluster would escalate views without ever converging. A regression in that tuning fails the seed
//! sweep below.
//!
//! ## Seeded, NOT byte-deterministic
//!
//! The fault SCHEDULE is reproducible per seed: the same seed yields the same drop/dup/reorder
//! decisions in the same order (asserted by [`tests::fault_schedule_is_deterministic`]). The
//! real-TLS handshake BYTES are NOT byte-reproducible — quinn + rustls draw key material and
//! connection IDs from OS entropy, so two runs of the same seed exchange different ciphertext. This
//! sim therefore asserts CONVERGENCE (a safety/liveness outcome), never byte-equality. The
//! message-level VOPR remains the deterministic consensus oracle; this sim is a transport robustness
//! net layered beside it, not a replacement for it.
//!
//! ## The three clocks
//!
//! - **quinn transport timers** (loss detection, idle timeout, retransmission) run on the
//!   viewstamp→`std::time::Instant` adapter the coordinator already owns: the ferry advances ONE
//!   continuous monotonic viewstamp clock in 5 ms steps and threads it through every `handle_*`
//!   call, exactly as [`loopback`](super::loopback) does. A >1 s gap would trip the 1 s idle timeout,
//!   so the step stays small and the loop never sleeps while work is pending.
//! - **quinn's `TimeSource`** (retry-token freshness) and **rustls's `TimeProvider`** (certificate
//!   validity) use REAL wall time. That is acceptable here: the certs are minted real-now-valid, and
//!   token / validity timing does not change the convergence OUTCOME under a moderate fault rate —
//!   only the ciphertext, which this behavioral sim does not assert on.
//!
//! ## Known coverage gap: head-of-line isolation under pressure
//!
//! The virtual network has NO bandwidth model — every released datagram is delivered in full on the
//! tick it comes due, so a bulk transfer never actually starves a control heartbeat of window. This
//! sim proves the transport CONVERGES under loss/reorder/dup; it does NOT prove that a large Bulk
//! frame fails to head-of-line block a latency-critical Control frame under congestion. Proving that
//! HOL-isolation property would require a bandwidth / window-pressure model in the virtual network,
//! which is out of scope for a behavioral convergence sim and left as a documented gap.

use core::{net::SocketAddr, time::Duration};

use std::collections::VecDeque;

use bytes::Bytes;

use super::{
  StreamLayout,
  loopback::{Replica, Scheme, applied_one, dial_and_seed, replica},
};
use crate::{
  Instant,
  transport::quic::{crypto::test_ca, testutil::addr},
};

/// A minimal SplitMix64 PRNG. Deterministic given the seed — the source of the reproducible fault
/// SCHEDULE (the handshake ciphertext is independent OS entropy; see the module docs).
struct Rng(u64);

impl Rng {
  /// Seed the generator.
  const fn new(seed: u64) -> Self {
    Self(seed)
  }

  /// The next 64-bit output (SplitMix64: advance the additive state, then avalanche-mix it).
  fn next_u64(&mut self) -> u64 {
    self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = self.0;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
  }

  /// Draw a per-mille event: `true` with probability `rate / 1000`. A draw is ALWAYS taken (even at
  /// `rate == 0`) so each fault axis consumes one slot of the stream per enqueue, keeping the
  /// schedule's shape independent of which rates happen to be zero.
  fn per_mille(&mut self, rate: u32) -> bool {
    (self.next_u64() % 1000) < u64::from(rate)
  }
}

/// The seeded fault model for the virtual UDP link. All probabilities are out of 1000, applied
/// independently per enqueued datagram.
#[derive(Clone, Copy)]
struct Faults {
  /// Per-datagram DROP probability: the datagram is discarded (quinn retransmits).
  drop_per_mille: u32,
  /// Per-datagram DUPLICATE probability: the datagram is delivered a SECOND time (quinn dedupes at
  /// the packet layer; the proto tolerates a re-delivered message).
  dup_per_mille: u32,
  /// Per-datagram REORDER probability: the datagram is stashed and released a few ticks later, so it
  /// arrives out of order relative to datagrams enqueued after it.
  reorder_per_mille: u32,
}

/// How many ticks a reordered datagram is held before release. A few ticks is enough to land it
/// behind later-enqueued traffic without pushing it past the 1 s idle timeout.
const REORDER_DELAY_TICKS: usize = 3;

/// A per-destination faulty datagram queue. On enqueue it applies the seeded faults: DROP discards
/// the datagram, DUP delivers a second copy, REORDER stashes it into `held` for release a few ticks
/// out. [`Self::pop_due`] releases due `held` entries after the in-order `q`, so a reordered datagram
/// re-enters the delivery stream behind the traffic that overtook it.
#[derive(Default)]
struct FaultyPipe {
  /// In-order datagrams awaiting delivery, each tagged with its source address.
  q: VecDeque<(SocketAddr, Vec<u8>)>,
  /// Stashed reordered datagrams: `(release_tick, from, bytes)`. Released once `tick >= release_tick`.
  held: Vec<(usize, SocketAddr, Vec<u8>)>,
}

impl FaultyPipe {
  /// Enqueue one datagram from `from`, applying the seeded faults deterministically via `rng`:
  /// - DROP fires → discard (nothing enqueued).
  /// - else REORDER fires → stash into `held` for release `REORDER_DELAY_TICKS` ticks from `tick`.
  /// - else → push onto the in-order `q`.
  ///
  /// DUP fires INDEPENDENTLY: when it does, a second copy is pushed onto `q` (a duplicate is always
  /// an immediate redelivery — the reorder axis already covers out-of-order copies).
  ///
  /// The three `per_mille` draws are taken in a fixed order (drop, dup, reorder) every call, so the
  /// per-seed decision stream is stable regardless of the configured rates.
  fn push_faulted(
    &mut self,
    rng: &mut Rng,
    faults: Faults,
    tick: usize,
    from: SocketAddr,
    bytes: Vec<u8>,
  ) {
    let drop = rng.per_mille(faults.drop_per_mille);
    let dup = rng.per_mille(faults.dup_per_mille);
    let reorder = rng.per_mille(faults.reorder_per_mille);
    if drop {
      return;
    }
    if reorder {
      self
        .held
        .push((tick + REORDER_DELAY_TICKS, from, bytes.clone()));
    } else {
      self.q.push_back((from, bytes.clone()));
    }
    if dup {
      self.q.push_back((from, bytes));
    }
  }

  /// Drain everything deliverable at `tick`: every in-order `q` entry, plus every `held` entry whose
  /// release tick has arrived (removed from `held`). Held entries are appended AFTER the in-order
  /// queue, so a reordered datagram lands behind the traffic that overtook it during its hold.
  fn pop_due(&mut self, tick: usize) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut out: Vec<(SocketAddr, Vec<u8>)> = self.q.drain(..).collect();
    let mut still_held = Vec::new();
    for (release, from, bytes) in self.held.drain(..) {
      if release <= tick {
        out.push((from, bytes));
      } else {
        still_held.push((release, from, bytes));
      }
    }
    self.held = still_held;
    out
  }
}

/// A faulty variant of [`loopback::run_until_converged`](super::loopback): ferry every emitted
/// datagram through a per-destination [`FaultyPipe`] under a single seeded `Rng`, on the SAME
/// continuous monotonic 5 ms clock, with a GENEROUS budget (loss + retransmission need many more
/// ticks than the clean path). Returns `true` once BOTH state machines have applied exactly one op.
///
/// Both pipes share one `Rng` so the whole run is driven by a single per-seed decision stream; the
/// drain order (r0's transmits, then r1's) is fixed, so the schedule is reproducible.
fn run_until_converged_faulty(
  r0: &mut Replica,
  addr0: SocketAddr,
  r1: &mut Replica,
  addr1: SocketAddr,
  seed: u64,
  faults: Faults,
) -> bool {
  let (r0, wal0, sb0) = r0;
  let (r1, wal1, sb1) = r1;
  let mut now = Instant::ZERO;
  let mut rng = Rng::new(seed);
  let mut to_r0 = FaultyPipe::default();
  let mut to_r1 = FaultyPipe::default();
  for tick in 0..40_000usize {
    now = now + Duration::from_millis(5);
    r0.handle_storage(now, wal0, sb0);
    r1.handle_storage(now, wal1, sb1);
    r0.handle_timeout(now, wal0, sb0);
    r1.handle_timeout(now, wal1, sb1);

    // Collect every outbound datagram from both sides through the seeded faults, routing by
    // destination: r0's traffic to r1 is faulted into the pipe toward r1 (from addr0), and vice
    // versa. Anything not bound for the peer is dropped (a replica never dials its own address).
    while let Some((dst, bytes)) = r0.poll_transmit() {
      if dst == addr1 {
        to_r1.push_faulted(&mut rng, faults, tick, addr0, bytes);
      }
    }
    while let Some((dst, bytes)) = r1.poll_transmit() {
      if dst == addr0 {
        to_r0.push_faulted(&mut rng, faults, tick, addr1, bytes);
      }
    }

    // Deliver everything DUE this tick (in-order plus any reordered datagram whose hold elapsed) to
    // the OTHER coordinator under the same `now`.
    for (from, bytes) in to_r1.pop_due(tick) {
      r1.handle_udp(now, from, None, &bytes, wal1, sb1);
    }
    for (from, bytes) in to_r0.pop_due(tick) {
      r0.handle_udp(now, from, None, &bytes, wal0, sb0);
    }

    if r0.endpoint().state_machine_ref().applied().len() == 1
      && r1.endpoint().state_machine_ref().applied().len() == 1
    {
      return true;
    }
  }
  false
}

/// Build a 2-replica cluster over cluster-private mTLS, seed the primary with one small client
/// request, and drive it to convergence over the FAULTY virtual network (`scheme` identity, `layout`
/// streams, per-seed fault schedule). Returns whether BOTH replicas applied exactly the one seeded
/// op. The body is small, so it rides the Control class under either layout — the convergence here
/// is the transport surviving loss/reorder/dup on the handshake + control stream.
fn converges_under_faults(scheme: Scheme, layout: StreamLayout, seed: u64, faults: Faults) -> bool {
  let ca = test_ca();
  let addr0 = addr(1);
  let addr1 = addr(2);
  // Per-replica RNG seeds derived from the run seed so different seeds also exercise different
  // connection-ID / token streams inside quinn (the handshake itself is non-deterministic, but this
  // keeps the two replicas distinct and the run seed the single knob).
  let mut s0 = [0u8; 32];
  let mut s1 = [0u8; 32];
  s0[..8].copy_from_slice(&seed.to_le_bytes());
  s1[..8].copy_from_slice(&seed.wrapping_add(1).to_le_bytes());
  let mut r0 = replica(&ca, 0, s0, scheme, layout);
  let mut r1 = replica(&ca, 1, s1, scheme, layout);

  dial_and_seed(&mut r0, addr0, &mut r1, addr1, Bytes::from_static(b"x"));
  let converged = run_until_converged_faulty(&mut r0, addr0, &mut r1, addr1, seed, faults);

  if converged {
    assert_eq!(
      r0.0.endpoint().state_machine_ref().applied(),
      applied_one(b"x").as_slice(),
      "primary applied op 1 over the faulty QUIC link"
    );
    assert_eq!(
      r1.0.endpoint().state_machine_ref().applied(),
      applied_one(b"x").as_slice(),
      "backup converged over the faulty QUIC link"
    );
  }
  converged
}

#[cfg(test)]
mod tests {
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
}

//! A VOPR-style deterministic adversarial test driver (TigerBeetle's VOPR, in miniature).
//!
//! [`run_vopr`] runs a single seeded simulation: it builds a cluster (size 2..=6, including even N and
//! the sharp N=2 unanimous-quorum case, a handful of
//! clients, **async WAL** + seeded storage/network faults), then for `ticks` steps applies a
//! seed-chosen mix of adversarial actions — client load, network chaos (reorder / duplicate / drop /
//! delay), storage chaos (async-append delays + transient read faults + occasional permanent
//! torn/bit-rot), crash/restart, and partition/heal — and `cluster.tick()`s. Everything is drawn from
//! the seed via [`Prng`], so a given `(seed, ticks)` is a **pure function**: rerunning a failing seed
//! reproduces the failure exactly.
//!
//! # What makes the liveness check meaningful: the fault budget + calm windows
//!
//! Consensus only guarantees progress while a quorum is connected. So the action chooser enforces a
//! **fault budget**: at any instant the replicas that are crashed OR isolated into the partition
//! minority number at most `⌊(N-1)/2⌋` — a healthy majority component always survives. (Never knock
//! out a quorum: a stall there would be *legitimate*, not a bug.) Then, on a seed-chosen cadence, the
//! driver opens a **calm window**: it heals every partition, restarts every crashed replica, clears
//! all faults, and lets the cluster run undisturbed. Liveness is asserted only across calm windows —
//! if a calm window of reasonable length ends with the cluster stable but no commit progress while
//! client work remains, that is a livelock and the driver panics with the seed + tick.
//!
//! # What is checked, and when
//!
//! - **Safety — EVERY tick, unconditionally** (must hold under ANY faults): [`check_safety`]
//!   (contiguity + cross-replica agreement + per-client reply ordering), [`DurabilityChecker`]
//!   (no committed op rewritten/lost across time; checkpoints monotone), [`ViewMonotonicChecker`]
//!   (no view regression), [`BoundednessChecker`] (per-op maps + WAL stay bounded under GC). Plus the
//!   structural invariants checked directly off the sim state each tick: `op >= commit_min >=
//!   checkpoint_op` and `commit_max >= commit_min` per replica (note `commit_max` is a re-learnable
//!   hint that may exceed the locally-held `op`, so `op >= commit_max` is deliberately NOT asserted);
//!   append-before-ack (no `PrepareOk` for an op whose WAL append has not completed, observed in
//!   [`Cluster::tick`]); and every op in the cluster's committed history stays durably written (WAL
//!   slot occupied — `Clean`/`Faulty` — or `<= checkpoint_op`) on at least a quorum.
//! - **Liveness — over calm windows** (see above).
//! - **End-of-run durability — after a final QUIESCE phase**: once the chaos loop ends, the driver
//!   heals everything, restarts all crashed replicas, drops all faults, and ticks a healthy cluster to
//!   convergence (bounded) — TigerBeetle's VOPR `transition_to_liveness_mode` — and only THEN asserts
//!   the whole committed history is APPLIED on an operational replica. This is because the chaos loop
//!   can stop on an instant where a committed op the survivors hold durably-but-unapplied was applied
//!   only by a since-crashed replica (the per-tick quorum-durability check still passes — the op is
//!   durably retained — but it is not yet applied by an operational replica); VSR's guarantee is
//!   durable-quorum retention, with application a local catch-up that the drain completes. The per-tick
//!   checks stay live through the drain, so a committed op held by NO quorum never converges and the
//!   phase panics with a non-convergence wedge rather than passing.
//!
//! On ANY violation the driver **panics** with `seed`, `tick`, and a one-line description, so the
//! failure is reproducible by re-running that seed (see [`run_vopr_one`]).

use bytes::Bytes;
use core::time::Duration;

use vsrr_proto::{Instant, Prng};

use crate::checker::{BoundednessChecker, DurabilityChecker, ViewMonotonicChecker, check_safety};
use crate::cluster::Cluster;
use crate::network::Faults;
use crate::storage::StorageFaults;

/// A summary of one [`run_vopr`] run — the schedule it actually explored, for observability and to
/// let the sweep assert the run was non-vacuous (it really exercised faults + recovery, not a quiet
/// happy path). All counters are cumulative over the run.
#[derive(Debug, Clone, Default)]
pub struct VoprReport {
  /// The seed this run was derived from.
  seed: u64,
  /// The number of ticks executed.
  ticks: u64,
  /// The replica count chosen for this run (2..=6, including even N and N=2).
  replicas: usize,
  /// The client count chosen for this run.
  clients: usize,
  /// The high-water mark of the cluster's committed-op count (longest applied prefix on any replica).
  max_committed: usize,
  /// How many crash actions fired.
  crashes: u64,
  /// How many restart actions fired.
  restarts: u64,
  /// How many partition (isolate-a-replica) actions fired.
  partitions: u64,
  /// How many heal actions fired (outside calm windows).
  heals: u64,
  /// How many calm windows were opened.
  calm_windows: u64,
  /// The highest view any replica reached (≥1 ⇒ at least one real view change occurred).
  max_view: u64,
  /// Whether every client completed all its requests by the end of the run.
  all_clients_done: bool,
  /// Ticks on which at least one replica was observed in the pending-durable-view window (a
  /// `Normal` primary whose volatile view is ahead of its durable view — a view-change root write in
  /// flight). `> 0` proves the async-superblock mode actually opened the window this run exercises,
  /// so the durable-view-before-participate gate was genuinely tested rather than vacuously skipped.
  pending_view_windows_seen: u64,
  /// The high-water mark of MISDIRECTED WAL reads (a recover read for op X served a different valid
  /// slot's bytes) across the run, summed over replicas. `> 0` proves the misdirected-read axis
  /// genuinely fired, so the proto's recovery placement check (`header.op() == op`) was exercised
  /// rather than merely armed. (Summed since each replica's WAL persists across crash/restart.)
  misdirects_fired: u64,
  /// The high-water mark of the RECOVERED COMMITTED BAND width (`commit_max - checkpoint_op`) sampled
  /// on a replica IMMEDIATELY AFTER a `restart` (i.e. right after `recover` ran). `> ~12` proves the
  /// large-`checkpoint_ops` axis genuinely materialized a NON-trivial committed band on a recovering
  /// replica — so the recover read-window logic (`commit_max` well above `checkpoint_op`) was
  /// exercised over a real multi-hundred-op band, not always the tiny ≈4..=12 the small-interval seeds
  /// produce. Stays far below `RECOVER_TAIL_WINDOW = 8192` (the tick budget caps committed ops at
  /// ~1.1k), so the extreme window-clip case remains unit-tested in the proto.
  recovered_band_max: u64,
  /// Cumulative count of FORCED state-syncs applied across the run, summed over replicas and
  /// accumulated across crash/restart (each `recover` resets the proto's per-replica counter, so this
  /// folds in the value before each reset). A forced sync is the proto's escalation when a replica
  /// cannot recover a committed checkpoint/op from its OWN disk and must FETCH it from a peer — both
  /// the pruned-committed-hole escalation path AND the recover-checkpoint peer-fetch (a replica whose
  /// own durable checkpoint snapshot reads back unusable). It is the observability proxy for
  /// "peer-fetch escalation": the two-slot-superblock fix (finding B) removes the SPURIOUS escalations
  /// (an orphaned checkpoint a redundant-copy backend would still hold locally) while a GENUINELY
  /// far-behind replica (its own checkpoint truly subsumed/gone) still escalates — so this count must
  /// stay `> 0` after the fix, proving the path is still exercised.
  forced_syncs: u64,
  /// The bounded WAL ring size `N` this run was seeded with, or `None` if this seed runs
  /// the UNBOUNDED default (≈2/3 of seeds). When `Some(n)`, every replica's WAL is a fixed `n`-slot ring
  /// (op `K` occupies slot `K mod n`), so the primary STALLS op-assignment before it would physically
  /// wrap an un-pruned slot. `n` is sized `checkpoint_ops * k + headroom` (`k` in 3..=6) — always well
  /// above one checkpoint interval plus pipeline headroom, so the stall ALWAYS releases (see
  /// [`Vopr::build_cluster`]); a tighter ring would WEDGE the primary (a permanent stall → spurious
  /// liveness failure), which is exactly the headroom constraint this sizing honours.
  wal_capacity: Option<u64>,
  /// Cumulative WAL STALLS across all replicas this run (the primary dropped a client request at
  /// op-assignment because minting the next op would overflow its bounded ring — the physical
  /// stall-before-wrap). `0` on an unbounded seed (the ring is `u64::MAX`, never overflows). `> 0` on a
  /// bounded seed proves the ring genuinely FILLED and the stall engaged — wrap was EXERCISED, not
  /// vacuously skipped by an under-filled ring. The committed sweep asserts the SUM across bounded seeds
  /// is `> 0` (Item 3 non-vacuity). Read off the proto's per-replica `wal_stalls` (monotone, persists
  /// across crash/restart since the WAL does), summed each tick and tracked as a high-water.
  wal_stalls: u64,
  /// Cumulative BELOW-RING-WINDOW state-syncs across all replicas this run (a backup received a
  /// head-extending `Prepare` whose ring slot still held an un-pruned op and STATE-SYNCED to the cluster
  /// checkpoint instead of overwriting it — the proto's `maybe_sync_below_ring_window` guard). `0` on an
  /// unbounded seed. Distinct from an ordinary `> self.op` state-sync. This is a RARE confluence under
  /// the VOPR schedule (it needs a sub-quorum laggard adopting a head over a held-commit hole while its
  /// own checkpoint lags below the ring window); the deterministic `bounded_wal.rs` laggard gate covers
  /// it directly, so the committed sweep only NOTES this count rather than forcing a flaky assert.
  below_ring_window_syncs: u64,
  /// `true` iff this is a BOUNDED seed (`wal_capacity.is_some()`) that committed STRICTLY MORE than `N`
  /// ops — i.e. its ring genuinely WRAPPED at least once (an op `K + N` reused op `K`'s physical slot).
  /// This is the strongest single witness that the bounded mode did real work: a seed whose committed
  /// history never reached `N` would exercise the ring slots but never a wrap. The committed sweep
  /// asserts SOME bounded seed wrapped (Item 3), proving the wrap path is non-vacuous.
  bounded_seed_wrapped: bool,
}

impl VoprReport {
  /// The seed this run was derived from.
  pub const fn seed(&self) -> u64 {
    self.seed
  }

  /// The number of ticks executed.
  pub const fn ticks(&self) -> u64 {
    self.ticks
  }

  /// The replica count chosen for this run (2..=6, including even N and N=2).
  pub const fn replicas(&self) -> usize {
    self.replicas
  }

  /// The client count chosen for this run.
  pub const fn clients(&self) -> usize {
    self.clients
  }

  /// The high-water mark of the cluster's committed-op count.
  pub const fn max_committed(&self) -> usize {
    self.max_committed
  }

  /// How many crash actions fired.
  pub const fn crashes(&self) -> u64 {
    self.crashes
  }

  /// How many restart actions fired.
  pub const fn restarts(&self) -> u64 {
    self.restarts
  }

  /// How many partition (isolate-a-replica) actions fired.
  pub const fn partitions(&self) -> u64 {
    self.partitions
  }

  /// How many heal actions fired outside calm windows.
  pub const fn heals(&self) -> u64 {
    self.heals
  }

  /// How many calm windows were opened.
  pub const fn calm_windows(&self) -> u64 {
    self.calm_windows
  }

  /// The highest view any replica reached.
  pub const fn max_view(&self) -> u64 {
    self.max_view
  }

  /// Whether every client completed all its requests by the end of the run.
  pub const fn all_clients_done(&self) -> bool {
    self.all_clients_done
  }

  /// The number of ticks on which at least one replica was in the pending-durable-view window
  /// (a `Normal` primary whose view is not yet durable). `> 0` ⇒ the async-superblock mode genuinely
  /// opened the window this run, so the durable-view-before-participate gate was exercised.
  pub const fn pending_view_windows_seen(&self) -> u64 {
    self.pending_view_windows_seen
  }

  /// The high-water of MISDIRECTED WAL reads across the run (summed over replicas). `> 0` ⇒ the
  /// misdirected-read axis genuinely fired, so the proto's recovery placement check was exercised.
  pub const fn misdirects_fired(&self) -> u64 {
    self.misdirects_fired
  }

  /// The high-water of the RECOVERED COMMITTED BAND width (`commit_max - checkpoint_op`) sampled right
  /// after a `restart`. A value well above the small-interval ceiling (≈12) ⇒ the large-`checkpoint_ops`
  /// axis genuinely had a recovering replica reconstruct a non-trivial committed band via the
  /// recover read-window path, rather than always the trivially-tiny band the small interval yields.
  pub const fn recovered_band_max(&self) -> u64 {
    self.recovered_band_max
  }

  /// The cumulative FORCED-state-sync count across the run (peer-fetch escalation proxy; see the field
  /// docs). `> 0` ⇒ a replica genuinely had to FETCH a checkpoint/op from a peer because its own disk
  /// could not serve it — the path the two-slot-superblock fix must keep exercised (only the SPURIOUS
  /// orphaned-checkpoint escalations are removed, not the genuine far-behind ones).
  pub const fn forced_syncs(&self) -> u64 {
    self.forced_syncs
  }

  /// The bounded WAL ring size `N` this run was seeded with, or `None` for an UNBOUNDED
  /// seed. `Some(n)` ⇒ every WAL is a fixed `n`-slot ring and the primary stalls before wrapping an
  /// un-pruned slot; the sweep uses this to partition seeds into bounded/unbounded for the non-vacuity
  /// assertions (only bounded seeds exercise wrap).
  pub const fn wal_capacity(&self) -> Option<u64> {
    self.wal_capacity
  }

  /// The cumulative WAL-STALL count across the run (the primary dropped a request because minting the
  /// next op would overflow its bounded ring). `0` on an unbounded seed. `> 0` ⇒ the bounded ring
  /// genuinely FILLED and the stall-before-wrap engaged (wrap was exercised, not vacuously skipped).
  pub const fn wal_stalls(&self) -> u64 {
    self.wal_stalls
  }

  /// The cumulative BELOW-RING-WINDOW state-sync count across the run (a backup overflowed its ring
  /// window on a head-extending `Prepare` and state-synced instead of overwriting an un-pruned slot —
  /// the `maybe_sync_below_ring_window` guard). `0` on an unbounded seed; rare under the VOPR schedule
  /// (the `bounded_wal.rs` laggard gate covers it deterministically).
  pub const fn below_ring_window_syncs(&self) -> u64 {
    self.below_ring_window_syncs
  }

  /// `true` iff this is a bounded seed whose ring genuinely WRAPPED — it committed strictly more than
  /// `N` ops, so an op `K + N` physically reused op `K`'s ring slot. The strongest single witness that
  /// the bounded mode did real work (the sweep asserts SOME bounded seed wrapped).
  pub const fn bounded_seed_wrapped(&self) -> bool {
    self.bounded_seed_wrapped
  }
}

/// The driver's own seeded RNG + bookkeeping. Separate from the cluster's internal network/storage
/// PRNGs (those are seeded from the same base seed but advance independently), so the *schedule* of
/// actions is a deterministic function of `seed` alone.
struct Vopr {
  seed: u64,
  prng: Prng,
  n: usize,
  /// `⌊(N-1)/2⌋` — the maximum number of replicas that may be knocked out (crashed ∪ isolated) at any
  /// instant while still leaving a connected majority.
  minority_budget: usize,
  /// Which replicas are currently isolated into the partition minority (group 1). Disjoint from the
  /// crashed set by construction (we never isolate a crashed replica), so `crashed + isolated`
  /// knocked-out replicas are counted without double-counting.
  isolated: Vec<bool>,
  /// `true` while inside a calm window (no faults, all replicas up); the chaos chooser is suppressed.
  calm: bool,
  /// The tick at which the current phase (chaos or calm) ends.
  phase_until: u64,
  /// The VIRTUAL INSTANT at which the current calm window opened. A calm window ends (and liveness is
  /// asserted) only once it has spanned BOTH `CALM_TICKS` ticks AND at least [`CALM_MIN_VIRTUAL`] of
  /// VIRTUAL TIME — because the per-tick virtual-clock advance is NOT constant: under heavy continuous
  /// message churn (a large recovered committed band with no GC, e.g. the large-`checkpoint_ops` axis)
  /// the network always has an imminent delivery, so `clock.advance_to(next_deadline)` steps by mere
  /// microseconds per tick and 800 ticks can span ~2ms — far less than the proto's 100ms
  /// `PREPARE_RETRANSMIT` cadence. Convergence of the un-acked head op to a laggard backup is
  /// retransmit-gated, so a tick-only calm window can end before a single retransmit fires and spuriously
  /// flag a "livelock" that is really just timer-gated catch-up. Liveness must be judged over a
  /// virtual-time-meaningful window, not a raw tick count.
  calm_start_virtual: Instant,
  /// Per-replica last-observed FORCED-state-sync count, for cumulative accumulation across crash/restart
  /// (a `recover` resets the proto's per-replica counter to 0, so we fold each positive delta into the
  /// report's running total and a reset's downward step contributes nothing). Indexed by replica.
  forced_sync_seen: Vec<u64>,
  /// Per-replica last-observed WAL-STALL count, for the same reset-robust cumulative
  /// accumulation as [`Self::forced_sync_seen`]: the proto's `wal_stalls` counter ALSO resets to 0 on
  /// `recover` (it lives on the `Endpoint`, rebuilt each restart — see `recovery.rs`), so a plain
  /// high-water would lose a pre-restart stall burst. Indexed by replica.
  wal_stalls_seen: Vec<u64>,
  /// Per-replica last-observed BELOW-RING-WINDOW-sync count, accumulated reset-robustly
  /// like [`Self::forced_sync_seen`] (this `Endpoint` counter also zeroes on `recover`). Indexed by
  /// replica.
  below_ring_window_syncs_seen: Vec<u64>,
  /// Liveness baseline captured at the START of the current calm window: the cluster's committed-op
  /// high-water and whether any client still had outstanding work. Used to assert progress at the end.
  calm_baseline_committed: usize,
  calm_had_outstanding: bool,
  /// The bounded WAL ring size `N` seeded for this run, or `None` for the UNBOUNDED
  /// default. Held here (not just in the report) because the per-tick RING-RESIDENCY checker
  /// ([`Vopr::check_ring_residency`]) is meaningful ONLY on a bounded seed — on an unbounded WAL every
  /// op is trivially resident, so the checker short-circuits when this is `None`.
  wal_capacity: Option<u64>,
  report: VoprReport,
}

/// Run one VOPR simulation for `ticks` ticks, seeded entirely by `seed`. Returns a [`VoprReport`]
/// summarising the schedule explored. After the chaos loop it runs a bounded final QUIESCE phase
/// (heal everything, restart all, no faults, tick to convergence — the `run_final_quiesce` step)
/// before the end-of-run durability assertion, so the survivors apply any durably-held committed tail
/// first. **Panics** (with `seed` + `tick` + a one-line description) on any safety, durability,
/// view-monotonicity, boundedness, append-before-ack, structural-ordering, or liveness (including
/// final-quiesce non-convergence) violation — so a failing seed is reproducible via [`run_vopr_one`].
pub fn run_vopr(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed);
  let mut c = v.build_cluster();

  let mut dur = DurabilityChecker::new(v.n);
  let mut vm = ViewMonotonicChecker::new(v.n);
  // Generous structural bound: the per-op caches/WAL plateau near a few checkpoint intervals plus
  // pipeline headroom; a real unbounded-growth leak blows well past this. Clients are bounded by the
  // active client set.
  let bound = BoundednessChecker::new(4_096, v.n + v.report.clients + 8);

  for tick in 0..ticks {
    v.step_phase(&mut c, tick);
    v.apply_actions(&mut c, tick);
    c.tick();
    // adversarially probe the pending-durable-view window THIS tick — deliver a GetView +
    // Recovery and fire the primary timers to any replica that is a Normal primary whose view is not
    // yet durable (a `StartViewAsPrimary` root write in flight). The window is short, so this targeted
    // probe (rather than incidental coincidence) is what actually exercises the
    // durable-view-before-participate gates; the checkers below catch any cross-view participation.
    v.report.pending_view_windows_seen += c.probe_pending_view_window();
    v.check_invariants(&mut c, tick, &mut dur, &mut vm, &bound);
    v.update_report(&c);
  }

  // Final QUIESCE phase (TigerBeetle's VOPR `transition_to_liveness_mode`): heal everything, restart
  // every crashed replica, drop all faults, and tick to convergence BEFORE the end-of-run assertions.
  // Rationale: the chaos loop can end on an arbitrary instant where the
  // committed-history high-water op is APPLIED only by a since-crashed replica while the operational
  // survivors hold that op DURABLY on a quorum's WAL but have not yet APPLIED it (commit catch-up in
  // flight). That is NOT a lost op — VSR's guarantee is durable-quorum RETENTION, with application a
  // local catch-up that completes once the cluster is healthy. So we drain first: the survivors apply
  // the durably-held committed tail, and only THEN do we assert the (strict) end-of-run durability +
  // applied invariants. The per-tick checks keep running THROUGHOUT the drain, so the drain can expose
  // (never hide) a divergence, and a genuine loss — a committed op held by NO quorum — still fails (it
  // cannot be reconstructed from a non-existent quorum source, so convergence times out below).
  v.run_final_quiesce(&mut c, ticks, &mut dur, &mut vm, &bound);

  // Final durability assertion: after convergence, the whole committed history survives, applied, on
  // at least one operational replica — proving no committed op was lost across the run.
  if let crate::checker::CheckResult::Violation(why) = dur.check(&c) {
    panic!("vopr seed {seed} tick {ticks} (final, post-quiesce): {why}");
  }
  v.report.ticks = ticks;
  v.report.all_clients_done = (0..c.client_count()).all(|i| c.client(i).is_done());
  v.update_report(&c);
  v.report
}

/// Convenience: run a single seed with the sweep's standard tick budget. Handy for re-running a
/// failing seed in isolation (see the `#[ignore]` replay test in `tests/vopr.rs`).
pub fn run_vopr_one(seed: u64) -> VoprReport {
  run_vopr(seed, DEFAULT_TICKS)
}

/// The standard per-seed tick budget used by the sweep and [`run_vopr_one`].
pub const DEFAULT_TICKS: u64 = 4_000;

/// How long (in ticks) a calm window runs before liveness is asserted. Long enough for a healed,
/// all-up cluster to complete any in-flight view change / peer-repair and commit several new ops, so
/// "no progress here" is a true wedge, not just a slow convergence. A calm window must ALSO span at
/// least [`CALM_MIN_VIRTUAL`] of virtual time (see that constant) — whichever bound is later wins.
const CALM_TICKS: u64 = 800;

/// The minimum VIRTUAL-TIME a calm window must span before its liveness assertion fires. The per-tick
/// virtual-clock advance is variable: under heavy continuous message churn (e.g. a large recovered
/// committed band with no GC — the large-`checkpoint_ops` axis) the network always has an imminent
/// delivery, so the clock steps by microseconds per tick and 800 ticks span only ~2ms — far short of
/// the proto's 100ms `PREPARE_RETRANSMIT` / 50ms `COMMIT_HEARTBEAT` / 500ms `VIEW_CHANGE_STATUS`
/// cadences. Convergence of an un-acked head op to a laggard backup (or completing a view change) is
/// retransmit/heartbeat-gated, so a tick-only window can end before a single retransmit fires and
/// spuriously flag a "livelock" that is really timer-gated catch-up. 3000ms covers ≥30 prepare
/// retransmits / 6 view-change-status periods — ample for a healed cluster to converge — while a
/// cluster still wedged after that much virtual time is a genuine liveness bug. Liveness is a
/// virtual-time property; never judge it on raw tick count under a nanosecond clock.
const CALM_MIN_VIRTUAL: Duration = Duration::from_millis(3_000);

/// The bound (in ticks) on the final QUIESCE phase: a healed, all-up, fault-free cluster must apply
/// the durably-held committed tail and converge well within this. It is generous (several calm windows
/// over) so a legitimately slow drain — a far-behind replica state-syncing, peer-repairing rotted
/// committed slots, or electing a stable primary across a few view changes — has ample room, while a
/// cluster that still cannot converge a committed op a quorum holds durably is a real LIVENESS wedge
/// (or a genuine loss the quorum cannot repair), which the phase then reports.
const FINAL_QUIESCE_TICKS: u64 = 6_000;

impl Vopr {
  fn new(seed: u64) -> Self {
    let mut prng = Prng::new(seed);
    // Cluster size from {2, 3, 4, 5, 6} — including EVEN N and the sharp N=2 case (covering
    // the quorum/nack arithmetic). `Config::try_new` accepts any `1..=64`, and the derived quorums are
    // sane for every size: quorum = ⌊n/2⌋+1, quorum_view_change = quorum_nack_prepare = n − quorum + 1
    // (N=2 → quorum 2 = unanimous, vc/nack 1 = a single DVC/nack suffices; N=4 → 3 / 2; N=6 → 4 / 3),
    // and the replication↔view-change intersection `quorum + quorum_view_change > n` holds for all.
    let n = 2 + (prng.below(5) as usize);
    // ⌊(N−1)/2⌋ — the minority a quorum survives: N=2→0, N=3→1, N=4→1, N=5→2, N=6→2. For N=2 the budget
    // is 0, so the chaos chooser never knocks out a replica (any single fault would break the unanimous
    // quorum 2 and stall progress LEGITIMATELY) — only network drop/dup/jitter and async storage churn
    // apply, which a 2-node cluster must still make progress under.
    let minority_budget = (n - 1) / 2;
    // A handful of clients: 2..=4.
    let clients = 2 + (prng.below(3) as usize);
    Self {
      seed,
      prng,
      n,
      minority_budget,
      isolated: vec![false; n],
      calm: false,
      phase_until: 0,
      calm_start_virtual: Instant::ZERO,
      forced_sync_seen: vec![0; n],
      wal_stalls_seen: vec![0; n],
      below_ring_window_syncs_seen: vec![0; n],
      calm_baseline_committed: 0,
      calm_had_outstanding: false,
      // Set by `build_cluster` (which draws the bounded-WAL decision off the prng); `None` until then.
      wal_capacity: None,
      report: VoprReport {
        seed,
        replicas: n,
        clients,
        ..VoprReport::default()
      },
    }
  }

  /// Builds the cluster for this run: `n` replicas, `clients` clients, a generous per-client request
  /// budget (so the run keeps offering load for the whole tick window), a SMALL checkpoint interval
  /// (so checkpoints + GC + checkpoint-based recovery are exercised on short runs), async WAL with a
  /// seed-chosen per-append delay, and seeded storage + network faults.
  fn build_cluster(&mut self) -> Cluster {
    let clients = self.report.clients as u32;
    // Each client issues many requests; with a few thousand ticks and faults, the run rarely drains
    // them, so there is almost always pending load to commit (keeps the liveness check non-vacuous).
    let requests_per_client = 1_000;
    // Checkpoint interval. MOST seeds use a SMALL interval (4..=12) so a few-thousand-tick run crosses
    // several checkpoints (exercising checkpoint + GC + checkpoint-based recovery repeatedly). But a
    // small interval keeps the durable `checkpoint_op` always close behind `commit_max`, so the
    // RECOVERED COMMITTED BAND (`(checkpoint_op .. commit_max]` — the span the recover
    // read-window logic materializes + re-applies) is ALWAYS trivially tiny. So ~1/3 of seeds instead
    // pick a substantially LARGER interval (256..=768): such a run rarely (or never) reaches the first
    // checkpoint within the tick budget, so `checkpoint_op` stays low while `commit_max` climbs into
    // the hundreds — a restart then recovers a non-trivial committed band, genuinely exercising the
    // recover read-window path (`commit_max` far above `checkpoint_op`) rather than always the ≈4..=12
    // case. Both
    // branches draw from the SAME prng position regardless (the `large_ckpt` roll is unconditional), so
    // the schedule stays a pure function of the seed. NOTE (honest limitation): the 4000-tick budget
    // commits at most ~1.1k ops in a typical run, so even the largest band stays
    // FAR below `RECOVER_TAIL_WINDOW = 8192` — this axis stops the band from being trivially small and
    // exercises the read-window arithmetic over a real multi-hundred-op band, but the EXTREME
    // case (`commit_max > 8192`, where the window cap actually clips a held committed op) remains
    // unit-tested in `vsrr-proto`, not reachable here.
    let large_ckpt = self.prng.chance(1, 3);
    let checkpoint_ops = if large_ckpt {
      256 + self.prng.below(513)
    } else {
      4 + self.prng.below(9)
    };
    // seed-derive a PHYSICAL bounded-WAL ring for ~1/3 of seeds (the rest keep the
    // UNBOUNDED default), so the adversarial sweep finally EXERCISES wrap (stall-before-wrap + recover
    // off a wrapped ring + a below-ring-window backup overflow) UNDER the full fault schedule — crash +
    // partition + disk faults together — covering the "VOPR-green overstates safety" gap.
    //
    // CRITICAL headroom constraint: the primary stalls op-assignment so the un-pruned window
    // `(prune_floor, op]` never exceeds `N` slots, and that stall RELEASES only as the quorum checkpoint
    // rises (lifting the prune floor `min(checkpoint_op, quorum_checkpoint_op)` and freeing slots). So
    // `N` MUST exceed one checkpoint interval plus the in-flight pipeline depth, or the window can never
    // reach the next checkpoint boundary before it would wrap and the primary WEDGES PERMANENTLY (a
    // spurious liveness failure, not a real bug). We size `N = checkpoint_ops * k + HEADROOM` with `k`
    // in 3..=6 — the prune floor lags `checkpoint_op` by at most one interval and the quorum's min
    // checkpoint by at most one more, so `2 * checkpoint_ops + pipeline` bounds the window and `k >= 3`
    // clears it with margin (the `bounded_wal.rs` gate proves checkpoint_ops=4 → N=12=4*3 RELEASES even
    // under a deeper 8-client pipeline; the VOPR's 2..=4 clients are strictly shallower). HEADROOM (8)
    // is a fixed pipeline cushion on top, so the tiniest case (checkpoint_ops=4, k=3) is N=20 — more
    // generous than the gate's proven 12. NOTE: on a LARGE-`checkpoint_ops` seed `N` lands in the
    // thousands while the 4000-tick budget commits at most ~1.1k ops, so the ring never fills — bounded
    // mode is then safe-but-vacuous there; the genuine wrap-exercising seeds are the small-interval ones.
    //
    // The bounded decision is drawn from a SEPARATE per-seed PRNG (`seed ^ BOUNDED_WAL_SEED_MAGIC`), NOT
    // the action stream `self.prng`, for two reasons: (1) it leaves every seed's action schedule +
    // checkpoint_ops + async delays BYTE-IDENTICAL to the unbounded-only sweep, so the ~2/3 unbounded seeds
    // (and every pinned regression seed that lands unbounded) reproduce their EXACT historical scenario —
    // adding draws to `self.prng` here would shift the whole downstream schedule and silently change what
    // those seeds test; (2) it is still a pure deterministic function of `seed`, UNCONDITIONAL (the env
    // mask below only gates APPLYING the capacity, never the draw), so a `VOPR_NO_BOUNDED_WAL` shrink
    // stays on the exact same schedule — the determinism guarantee the `VOPR_NO_*` masks rely on.
    const BOUNDED_WAL_HEADROOM: u64 = 8;
    const BOUNDED_WAL_SEED_MAGIC: u64 = 0xB0DE_D7A1_5EED_0C7A;
    let mut bounded_prng = Prng::new(self.seed ^ BOUNDED_WAL_SEED_MAGIC);
    let bounded_wal = bounded_prng.chance(1, 3);
    let bounded_k = 3 + bounded_prng.below(4); // k in 3..=6
    let wal_capacity = if bounded_wal && !env_flag("VOPR_NO_BOUNDED_WAL") {
      Some(checkpoint_ops * bounded_k + BOUNDED_WAL_HEADROOM)
    } else {
      None
    };
    self.wal_capacity = wal_capacity;
    self.report.wal_capacity = wal_capacity;
    let mut c = Cluster::with_checkpoint_ops(
      self.n as u8,
      clients,
      requests_per_client,
      self.seed,
      checkpoint_ops,
    );
    // Async WAL: a per-append in-flight window of 1..=4 polls (the append-before-ack window).
    let delay = 1 + self.prng.below(4) as u32;
    c.set_async_wal_delay(Some(delay));
    // Async SUPERBLOCK: a per-write in-flight window of 1..=4 polls (the pending durable-view window
    // the durable-view-before-participate gate must survive. With the superblock
    // completing synchronously the `pending_sb` window never opened, so the VOPR could not probe it;
    // staging the view-change/checkpoint root writes opens it. Seeded per-run; a `crash` discards any
    // in-flight write so a not-yet-durable view is genuinely lost.
    // The `sb_delay` is drawn UNCONDITIONALLY (determinism); `VOPR_NO_ASYNC_SB` only suppresses
    // APPLYING it, so a shrink run stays on the exact same PRNG stream/schedule — for root-causing
    // whether a failure is async-superblock-induced (mirrors the `VOPR_NO_*` fault masks). NOT set by
    // the committed sweep.
    let sb_delay = 1 + self.prng.below(4) as u32;
    if !env_flag("VOPR_NO_ASYNC_SB") {
      c.set_async_superblock_delay(Some(sb_delay));
    }
    // Baseline storage + network faults for the chaos phases (toggled around calm windows).
    c.set_storage_faults(self.chaos_storage_faults());
    c.set_faults(self.chaos_network_faults());
    // install the seed-derived bounded ring LAST so its storage rebuild composes over the
    // async-WAL/superblock modes + the storage-fault plan set above (each rebuild preserves the others'
    // settings; `set_wal_capacity` is just the final pass that also fixes `capacity()` to `N`). On an
    // unbounded seed `wal_capacity` is `None` and this is skipped (the WAL keeps its `u64::MAX` default).
    if let Some(n) = wal_capacity {
      c.set_wal_capacity(Some(n));
    }
    c
  }

  /// A seed-chosen network fault plan for chaos phases: small latency, jitter (reorder), modest drop
  /// and duplicate rates. Kept WITHIN a quorum-preserving budget — drops/dups never partition the
  /// cluster (only the partition action does), they just make delivery lossy/duplicative.
  fn chaos_network_faults(&mut self) -> Faults {
    // NOTE: draws happen unconditionally (determinism); the env masks below only ZERO the result, so
    // a shrink run (`VOPR_NO_DUP=1` etc.) keeps the exact same PRNG stream / schedule.
    let jitter = 1 + self.prng.below(5);
    let drop = self.prng.below(60) as u32;
    let dup = self.prng.below(60) as u32;
    Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(if env_flag("VOPR_NO_JITTER") {
        0
      } else {
        jitter
      }),
      drop_per_mille: if env_flag("VOPR_NO_DROP") { 0 } else { drop },
      duplicate_per_mille: if env_flag("VOPR_NO_DUP") { 0 } else { dup },
    }
  }

  /// A seed-chosen storage fault plan for chaos phases: transient read faults always on (recover-loop
  /// retries clear them), an OCCASIONAL low permanent torn/bit-rot rate (a restarted replica may then
  /// have to peer-repair a rotted committed slot), and a TRANSIENT misdirected-read rate (a recover
  /// tail read for op X returns a different valid slot's bytes — the proto's placement check must
  /// reject it). Rates kept low so recovery terminates against the live quorum within the run.
  fn chaos_storage_faults(&mut self) -> StorageFaults {
    // Permanent corruption only sometimes, and low when present — a high permanent rate on every
    // replica's whole log would make recovery arbitrarily slow under the other concurrent faults.
    // To keep a shrink run on the SAME PRNG stream, draws stay in their original order/condition; the
    // env masks only ZERO the already-drawn result, never skip a draw.
    let permanent = self.prng.chance(1, 3);
    let read = self.prng.below(40) as u32;
    let (torn, rot) = if permanent {
      (self.prng.below(20) as u32, self.prng.below(20) as u32)
    } else {
      (0, 0)
    };
    // TRANSIENT misdirected reads (TigerBeetle's misdirected-IO hazard), drawn UNCONDITIONALLY so a
    // `VOPR_NO_MISDIRECT` shrink stays on the same stream. Low rate (0..=39 per mille) so a recover
    // pass does not exhaust its per-slot retry budget on misdirects alone — a misdirected read is
    // rejected by the proto's placement check (`recover`'s `header.op() == op`) and RETRIED, clearing
    // on a later read (it never permanently removes a correct copy, so it is inherently quorum-safe:
    // every replica's own disk still eventually reads each slot correctly).
    let misdirect = self.prng.below(40) as u32;
    // TRANSIENT corrupt-but-PARSEABLE checkpoint reads: a checkpoint read returns the
    // live snapshot with a flipped tail byte — it still DECODES and keeps its bound op, but hashes to a
    // DIFFERENT id than the durable root. The donor's serve path (and recover) must verify against the
    // durable id and DROP it rather than ship/restore corrupt state. Drawn UNCONDITIONALLY (so a
    // `VOPR_NO_CKPT_CORRUPT` shrink stays on the same prng stream); low rate so a sync/recover read
    // eventually returns clean bytes within budget.
    let corrupt_ckpt = self.prng.below(40) as u32;
    let mask_perm = env_flag("VOPR_NO_PERM");
    StorageFaults {
      read_fault_per_mille: if env_flag("VOPR_NO_READFAULT") {
        0
      } else {
        read
      },
      torn_write_per_mille: if mask_perm { 0 } else { torn },
      bit_rot_per_mille: if mask_perm { 0 } else { rot },
      misdirect_read_per_mille: if env_flag("VOPR_NO_MISDIRECT") {
        0
      } else {
        misdirect
      },
      corrupt_checkpoint_read_per_mille: if env_flag("VOPR_NO_CKPT_CORRUPT") {
        0
      } else {
        corrupt_ckpt
      },
    }
  }

  /// Advance the chaos/calm phase machine for this tick: when the current phase expires, flip to the
  /// other. Entering a calm window heals everything, restarts all crashed replicas, and clears faults;
  /// leaving it asserts liveness and re-arms chaos faults.
  fn step_phase(&mut self, c: &mut Cluster, tick: u64) {
    if tick < self.phase_until {
      return;
    }
    if self.calm {
      // The calm window's TICK budget has elapsed — but liveness is a VIRTUAL-TIME property, so do not
      // assert until the window has ALSO spanned `CALM_MIN_VIRTUAL`. Under heavy churn (the large-band
      // axis) 800 ticks can be ~2ms, less than one `PREPARE_RETRANSMIT` (100ms), so a retransmit-gated
      // catch-up would not yet have had a chance to fire. Extend the calm window (keep faults off, all
      // up) by another tick budget and re-check; this loop terminates because each extension ticks the
      // healthy cluster forward and the virtual clock is monotone.
      let spanned = c.now().saturating_duration_since(self.calm_start_virtual);
      if spanned < CALM_MIN_VIRTUAL {
        self.phase_until = tick + CALM_TICKS;
        return;
      }
      // Calm window ending — assert liveness, then return to chaos.
      self.assert_calm_progress(c, tick);
      self.calm = false;
      // Re-arm ONLY the network faults (a fresh seed-chosen plan). We deliberately do NOT rebuild the
      // storage-fault plan here: `set_storage_faults` rebuilds (empty) WALs, which after warm-up would
      // wipe durable state. The storage-fault plan installed at build time stays in force (its
      // transient reads keep churning), so storage chaos persists without a destructive WAL rebuild.
      let nf = self.chaos_network_faults();
      c.set_faults(nf);
      // Length of the next chaos phase: 60..=260 ticks.
      self.phase_until = tick + 60 + self.prng.below(200);
    } else {
      // Chaos phase ending — open a calm window: heal, restart all, clear faults.
      self.enter_calm(c, tick);
    }
  }

  /// Open a calm window: heal every partition, restart every crashed replica, drop all network +
  /// storage faults, and snapshot the liveness baseline. Runs for a stretch long enough for the
  /// cluster to converge.
  fn enter_calm(&mut self, c: &mut Cluster, tick: u64) {
    for i in 0..self.n {
      self.isolated[i] = false;
    }
    c.heal();
    for i in 0..self.n {
      if c.is_crashed(i) {
        self.restart_and_track(c, i);
      }
    }
    // No drops/dups/jitter during the calm window so pending messages actually deliver. (Keep the
    // base async-WAL delay — it is bounded and benign — but turn OFF network chaos entirely.)
    c.set_faults(Faults::none());
    self.calm = true;
    self.report.calm_windows += 1;
    self.calm_baseline_committed = max_committed(c);
    self.calm_had_outstanding = !(0..c.client_count()).all(|i| c.client(i).is_done());
    // Snapshot the virtual instant the window opened: the liveness assertion is deferred until the
    // window spans BOTH `CALM_TICKS` ticks AND `CALM_MIN_VIRTUAL` of virtual time (see `step_phase`),
    // so a retransmit-gated catch-up under heavy churn is not mistaken for a wedge.
    self.calm_start_virtual = c.now();
    // A calm window long enough to commit several ops + finish in-flight view changes / repairs.
    self.phase_until = tick + CALM_TICKS;
  }

  /// At the end of a calm window, assert the cluster made progress. If there was outstanding client
  /// work at the window's start and the cluster is now stable (all up, healed) yet the committed-op
  /// high-water did NOT advance and clients are still not done, that is a livelock → panic.
  fn assert_calm_progress(&self, c: &Cluster, tick: u64) {
    let all_done = (0..c.client_count()).all(|i| c.client(i).is_done());
    if all_done || !self.calm_had_outstanding {
      return; // nothing was owed, or everything finished — no livelock.
    }
    let now_committed = max_committed(c);
    if now_committed <= self.calm_baseline_committed {
      if env_flag("VOPR_DUMP") {
        self.dump_divergence(c, tick);
      }
      panic!(
        "vopr seed {} tick {tick}: LIVELOCK — a calm window of {CALM_TICKS} ticks (all replicas up, \
         network healed, no faults) ended with outstanding client work but committed-op high-water \
         did not advance (still {now_committed}); the cluster is wedged",
        self.seed
      );
    }
  }

  /// The final QUIESCE phase, run once after the chaos loop and BEFORE the end-of-run durability
  /// assertion (TigerBeetle's VOPR `transition_to_liveness_mode`): heal every partition, restart every
  /// crashed replica, drop all faults, then tick a healthy, fully-connected cluster until it converges
  /// — the operational survivors have APPLIED the full committed-history high-water (so the end-of-run
  /// `DurabilityChecker::check` would pass) — or the [`FINAL_QUIESCE_TICKS`] bound is exhausted.
  ///
  /// Why this is a correctness CORRECTION, not a weakening of the durability check: VSR guarantees a
  /// committed op is durably RETAINED on a quorum (WAL/snapshot); APPLYING it is local catch-up that
  /// completes once the cluster is healthy. The chaos loop can stop on an instant where a committed op
  /// the operational replicas hold durably-but-unapplied was applied only by a now-crashed replica
  /// — asserting applied-by-an-operational-replica at that instant is stricter than the true
  /// guarantee. Draining first lets the survivors apply the durably-held tail, so the subsequent
  /// assertion tests the real invariant. It stays STRICT for a genuine loss: the per-tick checks run
  /// throughout the drain (a divergence is exposed, never hidden), and a committed op held by NO quorum
  /// cannot be repaired from a non-existent source — the cluster never converges it, so the drain hits
  /// its bound and this panics with a liveness/non-convergence wedge (a real bug to STOP and report),
  /// rather than silently passing.
  fn run_final_quiesce(
    &mut self,
    c: &mut Cluster,
    ticks: u64,
    dur: &mut DurabilityChecker,
    vm: &mut ViewMonotonicChecker,
    bound: &BoundednessChecker,
  ) {
    // Heal: all partitions cleared, every crashed replica restarted, no network/storage chaos.
    for i in 0..self.n {
      self.isolated[i] = false;
    }
    c.heal();
    for i in 0..self.n {
      if c.is_crashed(i) {
        self.restart_and_track(c, i);
      }
    }
    c.set_faults(Faults::none());

    // Already converged (the common case — nothing was owed)? Then no drain is needed.
    if dur.check(c).is_ok() {
      return;
    }

    for k in 0..FINAL_QUIESCE_TICKS {
      c.tick();
      // Keep the FULL per-tick invariant suite live during the drain: safety/agreement, durable-quorum
      // retention (the strict structural check), append-before-ack, durable-view-before-participate,
      // view-monotonicity, boundedness. The drain must heal, never mask — a divergence surfacing here
      // is a real bug, and the strict quorum-durability invariant continues to hold every tick. (Tick
      // label `ticks + k` locates a drain-phase violation.)
      self.check_invariants(c, ticks + k, dur, vm, bound);
      // Converged once the end-of-run durability assertion would pass: the committed history is
      // applied on an operational replica.
      if dur.check(c).is_ok() {
        self.update_report(c);
        return;
      }
    }

    // Did not converge within the bound: a committed op a quorum holds durably is not being applied by
    // ANY operational replica even after a long, fully-healthy drain. That is a genuine liveness wedge
    // (or a loss the quorum cannot repair) — a real bug to STOP and report, NOT something to paper over.
    if env_flag("VOPR_DUMP") {
      self.dump_divergence(c, ticks);
    }
    let committed = max_committed(c);
    let applied_hw = (0..self.n)
      .filter(|&i| !c.is_crashed(i))
      .map(|i| c.replica_sm(i).applied().len())
      .max()
      .unwrap_or(0);
    panic!(
      "vopr seed {} tick {ticks} (final quiesce): the cluster did NOT converge within \
       {FINAL_QUIESCE_TICKS} ticks of a fully-healed, fault-free drain — committed-history high-water \
       is {committed} but no operational replica has applied past {applied_hw}; a committed op a quorum \
       holds durably is not being applied (a real liveness wedge / unrepairable loss)",
      self.seed
    );
  }

  /// Apply this tick's adversarial actions (suppressed during calm windows). Each action rolls
  /// independently off the seeded PRNG and is gated by the fault budget so a quorum always survives.
  fn apply_actions(&mut self, c: &mut Cluster, tick: u64) {
    if self.calm {
      return; // calm window: no chaos.
    }
    let trace = env_flag("VOPR_TRACE");

    // (a) Network chaos: occasionally re-roll the live network fault plan (toggles drop/dup/jitter in
    // seeded windows). Cheap and quorum-safe (it never partitions).
    if self.prng.chance(1, 64) {
      let nf = self.chaos_network_faults();
      if trace {
        eprintln!(
          "tick {tick}: net drop={} dup={} jitter={}ns",
          nf.drop_per_mille,
          nf.duplicate_per_mille,
          nf.jitter.as_nanos()
        );
      }
      c.set_faults(nf);
    }

    // (b) Crash a replica — only if the budget allows another knocked-out replica.
    if self.prng.chance(1, 80) {
      if let Some(i) = self.pick_crashable(c) {
        if trace {
          eprintln!("tick {tick}: CRASH replica {i}");
        }
        c.crash(i);
        self.report.crashes += 1;
      }
    }

    // (c) Restart a previously-crashed replica (random timing, independent of calm windows).
    if self.prng.chance(1, 60) {
      if let Some(i) = self.pick_crashed(c) {
        if trace {
          eprintln!("tick {tick}: RESTART replica {i}");
        }
        self.restart_and_track(c, i);
      }
    }

    // (d) Partition: isolate a replica into the minority (budget permitting), or heal.
    if self.prng.chance(1, 90) {
      if self.prng.chance(1, 2) {
        if let Some(i) = self.pick_isolatable(c) {
          if trace {
            eprintln!("tick {tick}: PARTITION isolate replica {i}");
          }
          self.isolated[i] = true;
          self.apply_partition(c);
          self.report.partitions += 1;
        }
      } else if self.isolated.iter().any(|&b| b) {
        if trace {
          eprintln!("tick {tick}: HEAL partition");
        }
        for b in &mut self.isolated {
          *b = false;
        }
        c.heal();
        self.report.heals += 1;
      }
    }
  }

  /// Push the current `isolated` set into the cluster as a 2-group partition: isolated replicas →
  /// group 1, the rest (the majority component) → group 0.
  fn apply_partition(&self, c: &mut Cluster) {
    let groups: Vec<u8> = (0..self.n).map(|i| u8::from(self.isolated[i])).collect();
    c.partition(groups);
  }

  /// The number of replicas currently knocked out: crashed plus isolated (disjoint sets).
  fn knocked_out(&self, c: &Cluster) -> usize {
    (0..self.n)
      .filter(|&i| c.is_crashed(i) || self.isolated[i])
      .count()
  }

  /// Pick a replica we may crash without breaking the fault budget: not already crashed, not isolated
  /// (isolating then crashing the same node would be redundant), and only if one more knocked-out
  /// replica still leaves a majority. Returns `None` if the budget is exhausted.
  fn pick_crashable(&mut self, c: &Cluster) -> Option<usize> {
    if self.knocked_out(c) >= self.minority_budget {
      return None;
    }
    let candidates: Vec<usize> = (0..self.n)
      .filter(|&i| !c.is_crashed(i) && !self.isolated[i])
      .collect();
    self.pick(&candidates)
  }

  /// Pick a replica we may isolate into the minority without breaking the budget. Same constraints as
  /// [`Self::pick_crashable`] (crashed + isolated must stay ≤ the minority budget).
  fn pick_isolatable(&mut self, c: &Cluster) -> Option<usize> {
    if self.knocked_out(c) >= self.minority_budget {
      return None;
    }
    let candidates: Vec<usize> = (0..self.n)
      .filter(|&i| !c.is_crashed(i) && !self.isolated[i])
      .collect();
    self.pick(&candidates)
  }

  /// Pick a currently-crashed replica to restart, if any.
  fn pick_crashed(&mut self, c: &Cluster) -> Option<usize> {
    let candidates: Vec<usize> = (0..self.n).filter(|&i| c.is_crashed(i)).collect();
    self.pick(&candidates)
  }

  /// Restart replica `i` and SAMPLE its recovered committed band (`commit_max - checkpoint_op`,
  /// reconstructed by `recover` and reflected immediately because `Cluster::restart` drains the
  /// Recovering loop synchronously). Folds the band into the report high-water so the
  /// large-`checkpoint_ops` axis can be asserted non-vacuous — a recovering replica really did
  /// materialize a non-trivial committed band via the recover read-window path. Every restart site goes
  /// through here so the high-water captures the band wherever recovery fires (chaos action, calm
  /// window, or final quiesce). Bumps the restart counter too (one place).
  fn restart_and_track(&mut self, c: &mut Cluster, i: usize) {
    c.restart(i);
    self.report.restarts += 1;
    self.report.recovered_band_max = self
      .report
      .recovered_band_max
      .max(c.replica_recovered_band(i));
  }

  /// Seeded choice from a candidate list (`None` if empty).
  fn pick(&mut self, candidates: &[usize]) -> Option<usize> {
    if candidates.is_empty() {
      None
    } else {
      Some(candidates[self.prng.below(candidates.len() as u64) as usize])
    }
  }

  /// Run all per-tick invariant checks; panic with `seed`+`tick` on any violation.
  fn check_invariants(
    &mut self,
    c: &mut Cluster,
    tick: u64,
    dur: &mut DurabilityChecker,
    vm: &mut ViewMonotonicChecker,
    bound: &BoundednessChecker,
  ) {
    use crate::checker::CheckResult::Violation;

    // Append-before-ack, observed during the tick we just ran (PrepareOk for a non-durable op).
    if let Some(why) = c.take_append_before_ack_violation() {
      panic!("vopr seed {} tick {tick}: {why}", self.seed);
    }
    // Durable-view-before-participate: a StartView / head-bearing RecoveryResponse for a view
    // above the emitter's durable view, observed during the tick + the pending-view-window probe.
    if let Some(why) = c.take_durable_view_violation() {
      panic!("vopr seed {} tick {tick}: {why}", self.seed);
    }
    if let Violation(why) = check_safety(c) {
      if std::env::var("VOPR_DUMP").is_ok() {
        self.dump_divergence(c, tick);
      }
      panic!("vopr seed {} tick {tick}: safety: {why}", self.seed);
    }
    if let Violation(why) = dur.observe(c) {
      panic!("vopr seed {} tick {tick}: durability: {why}", self.seed);
    }
    if let Violation(why) = vm.observe(c) {
      panic!("vopr seed {} tick {tick}: view-monotonic: {why}", self.seed);
    }
    if let Violation(why) = bound.observe(c) {
      panic!("vopr seed {} tick {tick}: boundedness: {why}", self.seed);
    }
    self.check_structural(c, tick);
    self.check_ring_residency(c, tick);
  }

  /// The structural per-replica invariants, read directly off the sim state each tick:
  /// `op >= commit_min >= checkpoint_op` and `commit_max >= commit_min` — but NOT `op >= commit_max`,
  /// since `commit_max` is a re-learnable HINT that may EXCEED the locally-held head (`commit_max > op`
  /// is a legal tail-gap shape: the replica has heard a higher op is committed but has not yet fetched
  /// it). Plus, for the cluster's committed history, that every committed op is durably present on at
  /// least a quorum (WAL `Clean` or `<= checkpoint_op`).
  fn check_structural(&self, c: &Cluster, tick: u64) {
    for i in 0..self.n {
      let op = c.replica_op(i).get();
      let cmax = c.replica_commit_max(i).get();
      let cmin = c.replica_commit(i).get();
      let cp = c.replica_checkpoint_op(i).get();
      // commit_max is a re-learnable HINT that may exceed the locally-held head (the replica has
      // heard of a higher committed op it has not yet fetched), so `op >= commit_max` is NOT an
      // invariant — only `op >= commit_min >= checkpoint_op` and `commit_max >= commit_min` are.
      if !(op >= cmin && cmin >= cp) {
        panic!(
          "vopr seed {} tick {tick}: replica {i} ordering violated: op={op} commit_min={cmin} \
           checkpoint_op={cp} (want op >= commit_min >= checkpoint_op)",
          self.seed
        );
      }
      if cmax < cmin {
        panic!(
          "vopr seed {} tick {tick}: replica {i} commit_max={cmax} < commit_min={cmin}",
          self.seed
        );
      }
    }

    // Every op in the cluster's committed history must remain durably written on at least a quorum:
    // its WAL slot is occupied (`Clean` or `Faulty` — a committed slot is never dropped by
    // prune/truncate, and bit-rot does not un-occupy it), or it is folded into the durable
    // checkpoint. This is the structural form of "a committed op is never absent from a quorum's
    // durable WAL+snapshot". (We use "append completed / slot occupied" rather than "readable clean"
    // because the sim's permanent rot corrupts the BYTES of an already-durable committed slot after
    // commit — a peer-repaired concern — without ever making the op un-committed.)
    let committed = max_committed(c);
    if committed == 0 {
      return;
    }
    let quorum = self.n / 2 + 1;
    // Check the newest committed op (the one most at risk of not yet being durable on a quorum). It
    // is a sound proxy for the whole prefix: a committed op was, at commit time, durably appended on
    // a quorum, and a committed slot stays occupied thereafter — so if the newest committed op is
    // held by a quorum, every older committed op is too.
    let top = committed as u64;
    let holders = (0..self.n)
      .filter(|&i| c.replica_appended_op(i, vsrr_proto::OpNumber::with(top)))
      .count();
    // The committed-history high-water means at least one replica APPLIED op `top`, which the
    // protocol only does after a quorum durably appended it — so a quorum of occupied holders must
    // persist. A shortfall means a committed op vanished from a quorum's durable medium.
    if holders < quorum {
      panic!(
        "vopr seed {} tick {tick}: committed op {top} is durably held on only {holders} replicas \
         (< quorum {quorum}) — a committed op is not retained durably by a quorum",
        self.seed
      );
    }
  }

  /// The RING-RESIDENCY safety invariant — the PHYSICAL analogue of "no committed op
  /// lost", checked every tick on a BOUNDED seed (a no-op on an unbounded one, where the ring is
  /// `u64::MAX` slots so a wrap is impossible, hence the short-circuit). The invariant, faithful to the
  /// `bounded_wal.rs` `tail_is_ring_resident` intent ("a wrap must NEVER drop an op recover/repair still
  /// needs") but SOUND under the VOPR's full adversarial state: NO committed op above the prune floor is
  /// physically WRAPPED AWAY — i.e. no op `op` with `checkpoint_op < op <= commit_min` (committed +
  /// applied, un-pruned) has its ring slot `op mod N` currently OCCUPIED BY A STRICTLY-LATER congruent op
  /// `op + m·N` (`m >= 1`, `<= head`). That state is the ONLY genuine committed-op wrap: a later
  /// generation evicted a still-needed committed op, so `recover` would read a DIFFERENT op's bytes for
  /// `op` (committed-op-loss class). Combined with [`DurabilityChecker`] (no committed op rewritten/lost
  /// ACROSS TIME) and [`check_safety`] (cross-replica agreement), it closes the wrap-corruption loop.
  ///
  /// Why "slot reused by a later op", NOT merely "slot is `Empty`": a committed op's WAL slot can be
  /// legitimately `Empty` under the adversarial VOPR in ways that are NOT a wrap and that `recover`
  /// repairs/re-syncs cleanly — so flagging every `Empty` slot false-positives. The three benign `Empty`
  /// cases observed (each verified by running the cluster, fix-the-checker-not-the-proto):
  /// (1) **async in-flight** — the freshest tail ops are transiently `Dirty`, not yet durable (the
  /// append-before-ack window); (2) **applied-from-cache** — a BACKUP advances `commit_min` by applying an
  /// op from its in-memory `log` cache once it learns the op is committed, WITHOUT that op being durable in
  /// its OWN WAL (its slot may be `Empty`/`Dirty`/abandoned); `recover` routes such a non-durable tail slot
  /// through the peer-repair path, and durability is held on a quorum elsewhere (a backup at
  /// commit_min=1558 may have op 1554 `Empty` with no later occupant — applied-from-cache, not a wrap); (3)
  /// **state-sync-pruned + deferred-checkpoint** — a just-synced replica has already
  /// `wal.prune(synced_ckpt)`d and advanced `commit_min` to the synced point, while `self.checkpoint_op`
  /// still reads the OLD durable value until the synced ROOT is durable, so the band
  /// `(checkpoint_op .. commit_min]` is full of snapshot-subsumed `Empty` slots (e.g.
  /// commit_min=815, checkpoint_op=804, the 805..815 band snapshot-subsumed). A true WRAP differs from all
  /// three: the slot is occupied by a LATER op (the evicting generation), and the bounded ring keys its
  /// resident map by op number, so a later congruent op being resident is the exact, unambiguous physical
  /// signature of `op` having been overwritten. (Also bound by `commit_min`, not `head`: a backup can
  /// ADOPT a head far ahead of its resident tail with a legitimate un-repaired uncommitted `Empty` gap —
  /// a backup can adopt a head far ahead of its resident tail, e.g. head=1436 over commit_min=1401, which is repair territory, not a wrap.)
  ///
  /// This is the observable analogue of the proto's permanent `append_prepare` debug-assert (which panics
  /// at append time if any append would overwrite an un-pruned slot): both backstop the stall-before-wrap
  /// and `maybe_sync_below_ring_window` guards, this one as an independent per-tick cross-check over the
  /// whole resident committed tail (not relying on debug-assertions being enabled).
  fn check_ring_residency(&self, c: &Cluster, tick: u64) {
    // Unbounded seed: the WAL is `u64::MAX` slots, so a wrap is impossible — nothing to check.
    let Some(n) = self.wal_capacity else {
      return;
    };
    for i in 0..self.n {
      // A crashed replica is powered off — its volatile state is meaningless and its durable WAL is read
      // only on the next `recover`; the residency invariant is checked on the OPERATIONAL replicas (and
      // re-checked on a recovered one once it rejoins). Mirrors the `bounded_wal.rs` gate, which checks
      // the tail before the crash and after the rejoin, never on the powered-off replica.
      if c.is_crashed(i) {
        continue;
      }
      let ckpt = c.replica_checkpoint_op(i).get();
      let commit_min = c.replica_commit(i).get();
      let head = c.replica_op(i).get();
      // Scan the un-pruned COMMITTED band `(checkpoint_op .. commit_min]` for a physical wrap: an op whose
      // ring slot is now held by a strictly-LATER congruent op. (Below `checkpoint_op` a wrap is benign —
      // snapshot-subsumed; above `commit_min` an `Empty` slot is a legitimate repair gap, not a wrap.)
      for op in (ckpt + 1)..=commit_min {
        if c.replica_wal_slot_not_wrapped_away(i, vsrr_proto::OpNumber::with(op)) {
          continue; // `op` itself is still resident (`Clean`/`Faulty`) or its own append is in flight.
        }
        // `op`'s slot is `Empty`. It is a WRAP only if a strictly-later congruent op `op + m·N` (<= head)
        // is RESIDENT — that op physically occupies slot `op mod N`, having evicted the committed `op`. If
        // no later congruent op is resident, the `Empty` is one of the benign cases (async in-flight /
        // applied-from-cache / sync-pruned-deferred) the doc explains — `recover`/repair handles it.
        let mut y = op + n;
        let mut wrapped_by = None;
        while y <= head {
          if c.replica_wal_holds_op(i, vsrr_proto::OpNumber::with(y)) {
            wrapped_by = Some(y);
            break;
          }
          y += n;
        }
        if let Some(y) = wrapped_by {
          if env_flag("VOPR_DUMP") {
            self.dump_divergence(c, tick);
          }
          panic!(
            "vopr seed {} tick {tick}: ring-residency: replica {i} COMMITTED op {op} (checkpoint_op={ckpt}, \
             commit_min={commit_min}, head={head}, ring N={n}) was physically WRAPPED AWAY — its ring slot \
             {} is now occupied by the strictly-later op {y} (a wrap evicted a committed op the cluster \
             still needs; the stall-before-wrap / below-ring-window guard failed — committed-op-loss class)",
            self.seed,
            op % n,
          );
        }
      }
    }
  }

  /// Debug-only (gated by `VOPR_DUMP`): print each replica's role + the applied `(op, body)` around
  /// the first divergence point, so a safety failure can be root-caused.
  fn dump_divergence(&self, c: &Cluster, tick: u64) {
    eprintln!(
      "=== VOPR divergence dump seed {} tick {tick} ===",
      self.seed
    );
    let logs: Vec<Vec<(u64, Bytes)>> = (0..self.n)
      .map(|i| c.replica_sm(i).applied().to_vec())
      .collect();
    // First position where any two replicas disagree.
    let maxlen = logs.iter().map(Vec::len).max().unwrap_or(0);
    let mut diverge_at = maxlen;
    'outer: for pos in 0..maxlen {
      let mut seen: Option<(u64, Bytes)> = None;
      for log in &logs {
        if let Some(e) = log.get(pos) {
          match &seen {
            None => seen = Some(e.clone()),
            Some(s) if s != e => {
              diverge_at = pos;
              break 'outer;
            }
            _ => {}
          }
        }
      }
    }
    for (i, log) in logs.iter().enumerate() {
      eprintln!(
        "  replica {i}: crashed={} view={} op={} commit_min={} commit_max={} checkpoint_op={} applied_len={}",
        c.is_crashed(i),
        c.replica_view(i).get(),
        c.replica_op(i).get(),
        c.replica_commit(i).get(),
        c.replica_commit_max(i).get(),
        c.replica_checkpoint_op(i).get(),
        log.len(),
      );
    }
    let lo = diverge_at.saturating_sub(2);
    let hi = (diverge_at + 3).min(maxlen);
    eprintln!(
      "  divergence at applied position {diverge_at} (op {}):",
      diverge_at as u64 + 1
    );
    for pos in lo..hi {
      eprint!("    pos {pos} (op {}):", pos as u64 + 1);
      for (i, log) in logs.iter().enumerate() {
        match log.get(pos) {
          Some((op, body)) => eprint!(" r{i}=({op},{body:?})"),
          None => eprint!(" r{i}=<none>"),
        }
      }
      eprintln!();
    }
  }

  /// Fold the cluster's current state into the running report (high-waters only). The
  /// pending-view-window counter is maintained by the per-tick probe in [`run_vopr`], not here.
  fn update_report(&mut self, c: &Cluster) {
    self.report.max_committed = self.report.max_committed.max(max_committed(c));
    let mv = (0..self.n)
      .map(|i| c.replica_view(i).get())
      .max()
      .unwrap_or(0);
    self.report.max_view = self.report.max_view.max(mv);
    // MISDIRECTED-read high-water (summed over replicas' persistent WAL counters). Tracked as a max so
    // a mid-run WAL rebuild (none happens in the VOPR, but defensively) cannot lower it.
    let md: u64 = (0..self.n).map(|i| c.wal_misdirects_fired(i)).sum();
    self.report.misdirects_fired = self.report.misdirects_fired.max(md);
    // FORCED-sync (peer-fetch escalation) cumulative accumulation. The proto's per-replica counter
    // resets to 0 on `recover` (each restart), so we fold each POSITIVE delta into the running total
    // and always re-baseline `forced_sync_seen` — a reset's downward step then contributes nothing and
    // the next climb from 0 is counted afresh. This makes `forced_syncs` a true run-cumulative count of
    // peer-fetch escalations, robust to the per-restart reset.
    for i in 0..self.n {
      let cur = c.replica_forced_sync_count(i);
      if cur > self.forced_sync_seen[i] {
        self.report.forced_syncs += cur - self.forced_sync_seen[i];
      }
      self.forced_sync_seen[i] = cur;
    }
    // Bounded-WAL non-vacuity counters. `wal_stalls` (the primary dropped a request rather than wrap
    // an un-pruned ring slot) and `below_ring_window_syncs` (a backup overflowed its ring window and
    // state-synced rather than overwrite an un-pruned slot) BOTH live on the `Endpoint` and reset to 0
    // on `recover`, so they use the SAME reset-robust positive-delta accumulation as `forced_syncs`
    // above (a plain per-tick-sum high-water would lose a pre-restart burst). Always `0` on an unbounded
    // seed (the ring is `u64::MAX`, never overflows), so these stay 0 there and the sweep's
    // bounded-seed-only assertions are sound.
    for i in 0..self.n {
      let stalls = c.replica_wal_stalls(i);
      if stalls > self.wal_stalls_seen[i] {
        self.report.wal_stalls += stalls - self.wal_stalls_seen[i];
      }
      self.wal_stalls_seen[i] = stalls;
      let syncs = c.replica_below_ring_window_syncs(i);
      if syncs > self.below_ring_window_syncs_seen[i] {
        self.report.below_ring_window_syncs += syncs - self.below_ring_window_syncs_seen[i];
      }
      self.below_ring_window_syncs_seen[i] = syncs;
    }
    // Genuine-WRAP witness: a BOUNDED seed whose committed history exceeded its ring size `N` has had an
    // op `K + N` physically reuse op `K`'s slot — the ring truly wrapped (not merely filled). Latches
    // once true. Trivially false on an unbounded seed (`wal_capacity` is `None`).
    if let Some(n) = self.wal_capacity {
      if (self.report.max_committed as u64) > n {
        self.report.bounded_seed_wrapped = true;
      }
    }
  }
}

/// Debug-only shrink switch: true iff the env var `name` is set. Used ONLY to ZERO a fault class for
/// root-causing a sweep failure (the PRNG draws stay unconditional, so masking a class keeps the run
/// on the same schedule). Not consulted by the committed sweep with no env vars set.
fn env_flag(name: &str) -> bool {
  std::env::var(name).is_ok()
}

/// The cluster's committed-op high-water: the length of the longest applied `(op, body)` prefix on
/// any replica. (Agreement — checked every tick — guarantees these prefixes are consistent, so the
/// longest is a sound "committed history length".)
fn max_committed(c: &Cluster) -> usize {
  (0..c.replica_count())
    .map(|i| c.replica_sm(i).applied().len())
    .max()
    .unwrap_or(0)
}

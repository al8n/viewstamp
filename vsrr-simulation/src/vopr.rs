//! A VOPR-style deterministic adversarial test driver (TigerBeetle's VOPR, in miniature).
//!
//! [`run_vopr`] runs a single seeded simulation: it builds a cluster (size 3 or 5, a handful of
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
//!   phase panics with a non-convergence wedge rather than passing (VOPR seed 313).
//!
//! On ANY violation the driver **panics** with `seed`, `tick`, and a one-line description, so the
//! failure is reproducible by re-running that seed (see [`run_vopr_one`]).

use core::time::Duration;

use vsrr_proto::Prng;

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
  /// The replica count chosen for this run (3 or 5).
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
  /// Ticks on which at least one replica was observed in the R8-F1 pending-durable-view window (a
  /// `Normal` primary whose volatile view is ahead of its durable view — a view-change root write in
  /// flight). `> 0` proves the async-superblock mode actually opened the window this run exercises,
  /// so the durable-view-before-participate gate was genuinely tested rather than vacuously skipped.
  pending_view_windows_seen: u64,
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

  /// The replica count chosen for this run (3 or 5).
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

  /// The number of ticks on which at least one replica was in the R8-F1 pending-durable-view window
  /// (a `Normal` primary whose view is not yet durable). `> 0` ⇒ the async-superblock mode genuinely
  /// opened the window this run, so the durable-view-before-participate gate was exercised.
  pub const fn pending_view_windows_seen(&self) -> u64 {
    self.pending_view_windows_seen
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
  /// Liveness baseline captured at the START of the current calm window: the cluster's committed-op
  /// high-water and whether any client still had outstanding work. Used to assert progress at the end.
  calm_baseline_committed: usize,
  calm_had_outstanding: bool,
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
  // active client set. (Mirrors the M3.4b gate's reasoning.)
  let bound = BoundednessChecker::new(4_096, v.n + v.report.clients + 8);

  for tick in 0..ticks {
    v.step_phase(&mut c, tick);
    v.apply_actions(&mut c, tick);
    c.tick();
    // R8-F1: adversarially probe the pending-durable-view window THIS tick — deliver a GetView +
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
  // Rationale (VOPR seed 313): the chaos loop can end on an arbitrary instant where the
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
/// "no progress here" is a true wedge, not just a slow convergence.
const CALM_TICKS: u64 = 800;

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
    // Cluster size from {3, 5}.
    let n = if prng.chance(1, 2) { 3 } else { 5 };
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
      calm_baseline_committed: 0,
      calm_had_outstanding: false,
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
    // Small checkpoint interval (4..=12) so a few-thousand-tick run crosses several checkpoints.
    let checkpoint_ops = 4 + self.prng.below(9);
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
    // the durable-view-before-participate gate must survive, codex R8-F1). With the superblock
    // completing synchronously the `pending_sb` window never opened, so the VOPR could not see R8-F1;
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
  /// retries clear them), plus an OCCASIONAL low permanent torn/bit-rot rate (a restarted replica may
  /// then have to peer-repair a rotted committed slot). Rates kept low so recovery terminates against
  /// the live quorum within the run.
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
    let mask_perm = env_flag("VOPR_NO_PERM");
    StorageFaults {
      read_fault_per_mille: if env_flag("VOPR_NO_READFAULT") {
        0
      } else {
        read
      },
      torn_write_per_mille: if mask_perm { 0 } else { torn },
      bit_rot_per_mille: if mask_perm { 0 } else { rot },
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
        c.restart(i);
        self.report.restarts += 1;
      }
    }
    // No drops/dups/jitter during the calm window so pending messages actually deliver. (Keep the
    // base async-WAL delay — it is bounded and benign — but turn OFF network chaos entirely.)
    c.set_faults(Faults::none());
    self.calm = true;
    self.report.calm_windows += 1;
    self.calm_baseline_committed = max_committed(c);
    self.calm_had_outstanding = !(0..c.client_count()).all(|i| c.client(i).is_done());
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
  /// (VOPR seed 313) — asserting applied-by-an-operational-replica THERE is stricter than the true
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
        c.restart(i);
        self.report.restarts += 1;
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
        c.restart(i);
        self.report.restarts += 1;
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
    // Durable-view-before-participate (R8-F1): a StartView / head-bearing RecoveryResponse for a view
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
  }

  /// The structural per-replica invariants, read directly off the sim state each tick:
  /// `op >= commit_max >= commit_min >= checkpoint_op`, and (for the cluster's committed history) that
  /// every committed op is durably present on at least a quorum (WAL `Clean` or `<= checkpoint_op`).
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

  /// Debug-only (gated by `VOPR_DUMP`): print each replica's role + the applied `(op, body)` around
  /// the first divergence point, so a safety failure can be root-caused.
  fn dump_divergence(&self, c: &Cluster, tick: u64) {
    eprintln!(
      "=== VOPR divergence dump seed {} tick {tick} ===",
      self.seed
    );
    let logs: Vec<Vec<(u64, Vec<u8>)>> = (0..self.n)
      .map(|i| c.replica_sm(i).applied().to_vec())
      .collect();
    // First position where any two replicas disagree.
    let maxlen = logs.iter().map(Vec::len).max().unwrap_or(0);
    let mut diverge_at = maxlen;
    'outer: for pos in 0..maxlen {
      let mut seen: Option<(u64, Vec<u8>)> = None;
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

  /// Fold the cluster's current state into the running report (high-waters only). The R8-F1
  /// pending-view-window counter is maintained by the per-tick probe in [`run_vopr`], not here.
  fn update_report(&mut self, c: &Cluster) {
    self.report.max_committed = self.report.max_committed.max(max_committed(c));
    let mv = (0..self.n)
      .map(|i| c.replica_view(i).get())
      .max()
      .unwrap_or(0);
    self.report.max_view = self.report.max_view.max(mv);
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

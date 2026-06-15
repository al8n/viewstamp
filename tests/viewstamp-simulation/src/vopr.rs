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
//!   (no committed op rewritten/lost across time; checkpoints monotone), [`AppliedOnceChecker`]
//!   (every replica's apply stream is structurally sound per incarnation, and across the run every
//!   `(client, request)` is applied at exactly one op with one reply — the double-apply / op-reuse
//!   oracle), [`ViewMonotonicChecker`]
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

use viewstamp_proto::{Instant, Prng};

use crate::{
  checker::{
    AppliedOnceChecker, BoundednessChecker, DurabilityChecker, EpochViewMonotonicChecker,
    MembershipMonotonicChecker, StalenessChecker, ViewMonotonicChecker, check_safety,
  },
  cluster::Cluster,
  network::Faults,
  storage::StorageFaults,
};

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
  /// Cumulative CHUNKED state-sync transfers completed across the run (an announced over-frame
  /// checkpoint pulled chunk-by-chunk, assembled, and verified — the chunked path genuinely carrying
  /// a sync), summed over replicas and accumulated across crash/restart like [`Self::forced_syncs`]
  /// (the `Endpoint` counter resets on `recover`). `0` under the sweep's default load (its envelopes
  /// stay under one frame); the focused `large_state_sync.rs` gate drives and asserts the chunked
  /// path deterministically, so the sweep only REPORTS this count.
  sync_chunk_transfers: u64,
  /// `true` iff this is a BOUNDED seed (`wal_capacity.is_some()`) that committed STRICTLY MORE than `N`
  /// ops — i.e. its ring genuinely WRAPPED at least once (an op `K + N` reused op `K`'s physical slot).
  /// This is the strongest single witness that the bounded mode did real work: a seed whose committed
  /// history never reached `N` would exercise the ring slots but never a wrap. The committed sweep
  /// asserts SOME bounded seed wrapped (Item 3), proving the wrap path is non-vacuous.
  bounded_seed_wrapped: bool,
  /// How many LARGE-bodied client requests were minted this run (summed across clients, high-water).
  /// `> 0` proves the frame-cap axis is NON-VACUOUS: the client genuinely produced large bodies that
  /// built a large-bodied uncheckpointed band riding the (header-only) view-change carriers + the
  /// byte-bounded `RepairBatch` repair serve. The sweep asserts the total across seeds is `> 0`.
  large_bodies_sent: u64,
  /// How many INTER-REPLICA messages this run dropped for exceeding the transport frame cap
  /// [`MAX_FRAME_LEN`] (the modelled send-path frame guard). For the protocol's own traffic this MUST
  /// stay `0`: header-only carriers + the byte-bounded `RepairBatch` keep every legitimate peer message
  /// at/below the cap regardless of body size. A non-zero value is a REAL bug (a carrier overflowed
  /// the frame, or a bound is incomplete); `run_vopr` asserts it stays `0` every tick, so such a
  /// regression fails fast with its seed + tick.
  oversized_dropped: u64,
  /// How many messages the virtual network HELD this run ([`Faults::hold_per_mille`] fired — delivery
  /// pushed far into the virtual future, past the proto's repair-or-truncate grace). `0` unless the
  /// hold axis is enabled (`VOPR_HOLD`, or [`run_vopr_with_hold`]). `> 0` proves the axis genuinely
  /// fired: a held message can outlive its op's truncation + re-mint and arrive as a stale-body vote —
  /// the op-reuse class the content-addressed vote gate must reject. The committed hold sweep asserts
  /// the sum across its seeds is `> 0`, so that lane can never silently become a no-op.
  holds_fired: u64,
  /// Cumulative count of canonical-log selections that actually FLOORED the union
  /// (`select_canonical_log` dropped at least one canonical-donor entry at/below the vouched
  /// checkpoint floor), summed over replicas and accumulated across crash/restart (the `Endpoint`
  /// counter resets on `recover`, so positive deltas are folded like [`Self::forced_syncs`]). `> 0`
  /// proves the floored-union path did real work this run — it needs donors carrying entries at or
  /// below another donor's vouched checkpoint inside one view change, a rare confluence only a few
  /// seeds per contiguous block reach (the base sweep asserts the cross-seed sum is `> 0`).
  unions_floored: u64,
  /// Cumulative count of NON-EMPTY `RepairBatch`es served (`on_request_prepare_range` genuinely
  /// shipping bodies on the windowed bulk-repair channel), summed over replicas and accumulated
  /// across crash/restart like [`Self::forced_syncs`]. `> 0` proves the byte-bounded repair serve
  /// fired (vs every repair flowing through the per-op `RequestPrepare`); the base sweep asserts the
  /// cross-seed sum is `> 0`.
  repair_batches_served: u64,
  prepare_batches_sent: u64,
  /// Cumulative count of header-only carrier slices built (`log_entries` — the chokepoint every
  /// `DoViewChange`/`StartView`/`RecoveryResponse` log payload flows through), summed over replicas
  /// and accumulated across crash/restart like [`Self::forced_syncs`]. `> 0` proves the header-only
  /// carrier path fired (view changes emit carriers in most seeds); the base sweep asserts the
  /// cross-seed sum is `> 0`.
  header_only_carriers_emitted: u64,
  /// How many WIPE-and-restart actions fired this run (a crashed replica came back with FRESH,
  /// empty durable storage — the amnesia axis). `0` unless the wipe axis is enabled (`VOPR_WIPE`, or
  /// [`run_vopr_with_wipe`]); bounded by the per-run wipe budget. `> 0` proves the axis genuinely
  /// forfeited a replica's durable state; the committed wipe sweep asserts the cross-seed sum is
  /// `> 0`, so that lane can never silently become a no-op.
  wipes_fired: u64,
  /// The high-water of completed WAL appends that LOST their header (the torn-header
  /// contract-violation verdict), summed over replicas. `0` unless the torn-header axis is enabled
  /// (`VOPR_TORN_HEADER`, or [`run_vopr_with_torn_headers`] — the probe lane). `> 0` proves the
  /// probe genuinely made completed appends vanish header-and-all, the exact shape the `Wal`
  /// header-durability contract forbids.
  torn_headers_fired: u64,
  /// How many CLIENT-CHURN actions fired this run (an active client RETIRED + a fresh `ClientId`
  /// spawned in its place). `0` unless the churn axis is enabled (`VOPR_CHURN`, or
  /// [`run_vopr_with_churn`]); bounded by the per-run churn budget. The churn sweep asserts the
  /// cross-seed sum is `> 0` so the lane cannot silently decay into the fixed-client default.
  churns_fired: u64,
  /// Cumulative client-session EVICTIONS across the run (the proto's deterministic apply-time
  /// session-cap eviction engaging), summed over replicas and accumulated reset-robustly across
  /// crash/restart like [`Self::forced_syncs`] (the `Endpoint` counter zeroes on `recover`). `0`
  /// under the default fixed-client schedule (the table never outgrows the cap); the churn sweep —
  /// which pairs client churn with a SMALL seeded `max_client_sessions` — asserts the cross-seed sum
  /// is `> 0`, the non-vacuity witness that the eviction genuinely ran under the full adversarial
  /// schedule while the safety/liveness checkers judged the outcome.
  sessions_evicted: u64,
  /// How many ONE-WAY (asymmetric) partition episodes were installed this run: a directed
  /// `blocked[from][to]` cut a victim's link in ONE direction while the reverse kept flowing — the
  /// shape the symmetric groups cannot express (a primary whose heartbeats flow OUT while the acks
  /// never arrive). `0` unless the asym axis is enabled (`VOPR_ASYM`, or [`run_vopr_with_asym`]).
  /// The committed asym sweep asserts the cross-seed sum is `> 0`.
  asym_episodes: u64,
  /// The high-water of inter-replica messages a directed one-way block DROPPED across the run (the
  /// cluster's monotone counter). `> 0` proves an episode genuinely cut live traffic one-way — the
  /// asym sweep's deep non-vacuity witness.
  one_way_dropped: u64,
  /// How many SLOW-REPLICA (gray failure) episodes were installed this run: one replica's
  /// inter-replica delivery degraded by a seeded extra-delay band over a bounded window — messages
  /// arrive LATE, never dropped (NOT a partition). `0` unless the slow axis is enabled (`VOPR_SLOW`,
  /// or [`run_vopr_with_slow`]). The committed slow sweep asserts the cross-seed sum is `> 0`.
  slow_episodes: u64,
  /// The high-water of inter-replica messages that picked up a slow-replica extra delay across the
  /// run (the cluster's monotone counter). `> 0` proves an episode genuinely delayed live traffic —
  /// the slow sweep's deep non-vacuity witness.
  slow_delays: u64,
  /// How many packed request bodies carried MORE than one unit this run (summed over the batching
  /// clients' monotone counters, high-water — client models persist across replica crashes and
  /// nothing resets them). `0` unless the batching axis is enabled (`VOPR_BATCHING`, or
  /// [`run_vopr_with_batching`]). `> 0` proves batching genuinely ENGAGED — the closed loop queued
  /// 2+ units while a body flew and the model packed them into one consensus op — which is the
  /// batching sweep's headline non-vacuity witness.
  bodies_with_multiple_units: u64,
  /// The largest unit count any single packed body carried this run (max over the batching
  /// clients' monotone high-waters). `0` with the axis off.
  max_units_per_body: u64,
  /// How many atomic GROUPS the batching clients enqueued this run (summed over their monotone
  /// counters, high-water). `0` with the axis off; the batching sweep asserts the cross-seed sum
  /// is `> 0` so the group (whole-or-deferred, never split) path is genuinely exercised.
  groups_submitted: u64,
  /// How many times the STALE-READ lane installed a deaf+mute cut on the cluster's SERVING primary
  /// this run (the cluster's monotone counter, high-water). Identity-sound (only the highest-view
  /// normal primary is ever cut) but NOT a causal failover signal — a cut could be healed before a
  /// failover completes. The sweep asserts [`Self::stale_read_failovers_observed`] instead.
  stale_read_probes_fired: u64,
  /// How many times the lane OBSERVED a probe-induced failover this run: a deposed serving primary
  /// was cut and, while still cut, a DIFFERENT serving primary emerged in a strictly higher view.
  /// This is the lane's CAUSAL non-vacuity witness — it proves the staleness floor was actually
  /// exercised across a completed deposed-primary failover window, not merely that a cut was
  /// installed. `0` unless the stale-read axis is enabled; the committed sweep asserts the
  /// cross-seed sum is `> 0`.
  stale_read_failovers_observed: u64,
  /// Cumulative committed ops APPLIED across all learners this run, summed reset-robustly over the
  /// learner ids (a `recover` re-applies from the durable checkpoint, so positive deltas are folded
  /// like [`Self::forced_syncs`]). `0` with the axis off (no learners). `> 0` proves a learner
  /// genuinely follows the committed log — the headline that a non-voting member applies the same
  /// history as the voters. The learner sweep asserts the cross-seed sum is `> 0`.
  learner_ops_applied: u64,
  /// Cumulative state-syncs a LEARNER completed (fetched + installed a checkpoint past its head) this
  /// run, summed reset-robustly over the learner ids like [`Self::forced_syncs`] (the `Endpoint`
  /// counter zeroes on `recover`). `0` with the axis off. `> 0` proves a learner that fell behind
  /// CAUGHT UP via the repair/state-sync path — a learner is brought current by the same machinery a
  /// lagging voter is. The learner sweep asserts the cross-seed sum is `> 0`.
  learner_repairs_served: u64,
  /// Cumulative view ADVANCES a learner followed this run (each time a learner adopted a strictly
  /// higher view via `GetView`), summed over the learner ids. `0` with the axis off. `> 0` proves a
  /// learner TRACKS view changes — it adopts the new primary's view without ever being an active
  /// view-change participant. The learner sweep asserts the cross-seed sum is `> 0`.
  learner_view_changes_followed: u64,
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

  /// The cumulative CHUNKED state-sync transfer count across the run (an over-frame checkpoint
  /// pulled, assembled, and verified chunk-by-chunk). `0` under the sweep's default load (its
  /// envelopes fit one frame); the focused `large_state_sync.rs` gate drives + asserts the chunked
  /// path deterministically.
  pub const fn sync_chunk_transfers(&self) -> u64 {
    self.sync_chunk_transfers
  }

  /// `true` iff this is a bounded seed whose ring genuinely WRAPPED — it committed strictly more than
  /// `N` ops, so an op `K + N` physically reused op `K`'s ring slot. The strongest single witness that
  /// the bounded mode did real work (the sweep asserts SOME bounded seed wrapped).
  pub const fn bounded_seed_wrapped(&self) -> bool {
    self.bounded_seed_wrapped
  }

  /// How many LARGE-bodied client requests were minted this run (across clients). `> 0` ⇒ the
  /// frame-cap axis genuinely fired — large bodies flowed through view-change/recovery, so the
  /// [`Self::oversized_dropped`]`== 0` guarantee is non-vacuous.
  pub const fn large_bodies_sent(&self) -> u64 {
    self.large_bodies_sent
  }

  /// How many inter-replica messages were dropped for exceeding the transport frame cap this run. For
  /// the protocol's own traffic this is `0` (header-only carriers + the byte-bounded `RepairBatch` keep
  /// every legitimate peer message at/below the cap); a non-zero value is a REAL bug the per-tick
  /// check in [`run_vopr`] already failed on.
  pub const fn oversized_dropped(&self) -> u64 {
    self.oversized_dropped
  }

  /// How many messages the virtual network HELD this run (the unbounded-hold axis fired). `0` with
  /// the axis disabled; `> 0` proves a hold-enabled run genuinely delayed messages past the
  /// repair-or-truncate grace — the non-vacuity witness the committed hold sweep asserts on.
  pub const fn holds_fired(&self) -> u64 {
    self.holds_fired
  }

  /// The run-cumulative count of canonical-log selections that FLOORED the union (dropped a
  /// canonical-donor entry at/below the vouched checkpoint floor). `> 0` ⇒ the floored-union path
  /// genuinely fired this run.
  pub const fn unions_floored(&self) -> u64 {
    self.unions_floored
  }

  /// The run-cumulative count of NON-EMPTY `RepairBatch`es served. `> 0` ⇒ the byte-bounded
  /// bulk-repair serve genuinely fired this run.
  pub const fn repair_batches_served(&self) -> u64 {
    self.repair_batches_served
  }

  /// Total prepare-batch retransmit emissions observed across the run (reset-robust accumulation).
  #[doc(hidden)]
  pub const fn prepare_batches_sent(&self) -> u64 {
    self.prepare_batches_sent
  }

  /// The run-cumulative count of header-only carrier slices built. `> 0` ⇒ the header-only
  /// view-change/recovery carrier path genuinely fired this run.
  pub const fn header_only_carriers_emitted(&self) -> u64 {
    self.header_only_carriers_emitted
  }

  /// How many wipe-and-restart actions fired (a replica's durable state forfeited to a fresh disk).
  /// `0` with the axis disabled; the committed wipe sweep asserts the cross-seed sum is `> 0`.
  pub const fn wipes_fired(&self) -> u64 {
    self.wipes_fired
  }

  /// The high-water of completed WAL appends that lost their header (the torn-header
  /// contract-violation probe). `0` with the axis disabled; the probe lane reads this as its
  /// non-vacuity witness.
  pub const fn torn_headers_fired(&self) -> u64 {
    self.torn_headers_fired
  }

  /// How many client-churn actions fired (a client retired + a fresh `ClientId` spawned). `0` with
  /// the axis disabled; the churn sweep asserts the cross-seed sum is `> 0`.
  pub const fn churns_fired(&self) -> u64 {
    self.churns_fired
  }

  /// The run-cumulative client-session eviction count (the deterministic session-cap eviction
  /// engaging, summed reset-robustly over replicas). The churn sweep's non-vacuity witness.
  pub const fn sessions_evicted(&self) -> u64 {
    self.sessions_evicted
  }

  /// How many ONE-WAY (asymmetric) partition episodes were installed (a directed block cut a
  /// victim's link in one direction while the reverse flowed). `0` with the axis disabled; the
  /// committed asym sweep asserts the cross-seed sum is `> 0`.
  pub const fn asym_episodes(&self) -> u64 {
    self.asym_episodes
  }

  /// How many inter-replica messages a directed one-way block dropped (the cluster's monotone
  /// counter, high-water). `> 0` ⇒ an episode genuinely CUT live traffic one-way (the deep
  /// non-vacuity witness — episodes that never intersected a message would be vacuous).
  pub const fn one_way_dropped(&self) -> u64 {
    self.one_way_dropped
  }

  /// How many SLOW-REPLICA (gray failure) episodes were installed (one replica's inter-replica
  /// delivery degraded by a seeded extra-delay band — late, never dropped). `0` with the axis
  /// disabled; the committed slow sweep asserts the cross-seed sum is `> 0`.
  pub const fn slow_episodes(&self) -> u64 {
    self.slow_episodes
  }

  /// How many inter-replica messages picked up a slow-replica extra delay (the cluster's monotone
  /// counter, high-water). `> 0` ⇒ an episode genuinely DELAYED live traffic (the deep non-vacuity
  /// witness for the slow lane).
  pub const fn slow_delays(&self) -> u64 {
    self.slow_delays
  }

  /// How many packed bodies carried more than one unit (the batching lane's headline non-vacuity
  /// witness: batching genuinely engaged). `0` with the axis off.
  pub const fn bodies_with_multiple_units(&self) -> u64 {
    self.bodies_with_multiple_units
  }

  /// The largest unit count any single packed body carried. `0` with the axis off.
  pub const fn max_units_per_body(&self) -> u64 {
    self.max_units_per_body
  }

  /// How many atomic groups the batching clients enqueued. `0` with the axis off; the batching
  /// sweep asserts the cross-seed sum is `> 0`.
  pub const fn groups_submitted(&self) -> u64 {
    self.groups_submitted
  }

  /// How many times the stale-read lane installed a cut on the serving primary. `0` with the axis
  /// off. Identity-sound but not causal; the sweep asserts [`Self::stale_read_failovers_observed`].
  pub const fn stale_read_probes_fired(&self) -> u64 {
    self.stale_read_probes_fired
  }

  /// How many probe-induced failovers the stale-read lane observed (a deposed serving primary, then
  /// a strictly-higher-view serving primary while it remained cut). `0` with the axis off; the
  /// committed stale-read sweep asserts the cross-seed sum is `> 0` — the staleness floor was
  /// genuinely exercised across a completed deposed-primary failover, not merely a cut install.
  pub const fn stale_read_failovers_observed(&self) -> u64 {
    self.stale_read_failovers_observed
  }

  /// The run-cumulative count of committed ops applied across all learners. `0` with the axis off;
  /// the learner sweep asserts the cross-seed sum is `> 0` — a non-voting learner genuinely follows
  /// the committed log.
  pub const fn learner_ops_applied(&self) -> u64 {
    self.learner_ops_applied
  }

  /// The run-cumulative count of state-syncs a learner completed (it caught up from behind via the
  /// repair/state-sync path). `0` with the axis off; the learner sweep asserts the cross-seed sum is
  /// `> 0`.
  pub const fn learner_repairs_served(&self) -> u64 {
    self.learner_repairs_served
  }

  /// The run-cumulative count of view advances a learner followed (it adopted a higher view via
  /// `GetView`). `0` with the axis off; the learner sweep asserts the cross-seed sum is `> 0`.
  pub const fn learner_view_changes_followed(&self) -> u64 {
    self.learner_view_changes_followed
  }
}

/// The driver's own seeded RNG + bookkeeping. Separate from the cluster's internal network/storage
/// PRNGs (those are seeded from the same base seed but advance independently), so the *schedule* of
/// actions is a deterministic function of `seed` alone.
struct Vopr {
  seed: u64,
  prng: Prng,
  /// The TOTAL membership: voting replicas plus learners. Sizes every per-replica vector, the
  /// routing target space, the cluster construction, and every fan-out / per-replica iteration.
  node_count: usize,
  /// The VOTING-replica count: the quorum-bearing set. Drives [`Self::minority_budget`] and bounds
  /// the budget-charged crash/isolate/asym victim pickers (a learner never consumes the budget).
  /// Equals [`Self::node_count`] when there are no learners.
  voting_count: usize,
  /// `⌊(voting_count-1)/2⌋` — the maximum number of VOTING replicas that may be knocked out
  /// (crashed ∪ isolated ∪ one-way victims) at any instant while still leaving a connected
  /// voting majority, so a quorum can always still commit.
  minority_budget: usize,
  /// Which replicas are currently isolated into the partition minority (group 1). Sized by the total
  /// membership (one slot per member); the budget picker only ever isolates VOTERS, so an isolated
  /// replica always counts against the voting fault budget. Disjoint from the crashed set by
  /// construction (we never isolate a crashed replica), so `crashed + isolated` knocked-out replicas
  /// are counted without double-counting.
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
  /// Per-replica last-observed CHUNKED-transfer-completed count, accumulated reset-robustly like
  /// [`Self::forced_sync_seen`] (this `Endpoint` counter also zeroes on `recover`). Indexed by
  /// replica.
  sync_chunk_transfers_seen: Vec<u64>,
  /// Per-replica last-observed floored-union count, accumulated reset-robustly like
  /// [`Self::forced_sync_seen`] (this `Endpoint` counter also zeroes on `recover`). Indexed by replica.
  unions_floored_seen: Vec<u64>,
  /// Per-replica last-observed served-`RepairBatch` count, accumulated reset-robustly like
  /// [`Self::forced_sync_seen`]. Indexed by replica.
  repair_batches_served_seen: Vec<u64>,
  /// Per-replica last-observed prepare-batch-emission count, accumulated reset-robustly like
  /// [`Self::forced_sync_seen`]. Indexed by replica.
  prepare_batches_sent_seen: Vec<u64>,
  /// Per-replica last-observed header-only-carrier count, accumulated reset-robustly like
  /// [`Self::forced_sync_seen`]. Indexed by replica.
  header_only_carriers_seen: Vec<u64>,
  /// Liveness baseline captured at the START of the current calm window: the cluster's committed-op
  /// high-water and whether any client still had outstanding work. Used to assert progress at the end.
  calm_baseline_committed: usize,
  calm_had_outstanding: bool,
  /// The bounded WAL ring size `N` seeded for this run, or `None` for the UNBOUNDED
  /// default. Held here (not just in the report) because the per-tick RING-RESIDENCY checker
  /// ([`Vopr::check_ring_residency`]) is meaningful ONLY on a bounded seed — on an unbounded WAL every
  /// op is trivially resident, so the checker short-circuits when this is `None`.
  wal_capacity: Option<u64>,
  /// Whether the UNBOUNDED-HOLD network axis is enabled for this run: the `VOPR_HOLD` env var
  /// (captured once at construction, so every `chaos_network_faults` re-roll across the run agrees),
  /// or force-enabled via [`run_vopr_with_hold`] (the committed hold sweep's programmatic override —
  /// no env mutation, so parallel tests in one process cannot race). With the axis OFF the hold draw
  /// is skipped entirely (no PRNG value consumed), keeping the default per-seed schedule
  /// byte-identical; a hold-enabled run is its OWN deterministic baseline.
  hold_axis: bool,
  /// Whether the WIPE-and-restart (amnesia) axis is enabled for this run: the `VOPR_WIPE` env var, or
  /// force-enabled via [`run_vopr_with_wipe`] (the committed wipe sweep). Same discipline as
  /// [`Self::hold_axis`]: with the axis OFF its per-tick chance draw is skipped entirely (no PRNG
  /// value consumed — the default schedule stays byte-identical); a wipe-enabled run is its OWN
  /// deterministic baseline, with the `VOPR_NO_WIPE` shrink mask staying on the same stream (the
  /// draws still happen; only the wipe effect is downgraded to a plain restart).
  wipe_axis: bool,
  /// Whether the TORN-HEADER contract-violation probe axis is enabled: the `VOPR_TORN_HEADER` env
  /// var, or force-enabled via [`run_vopr_with_torn_headers`] (the probe lane). Same discipline as
  /// [`Self::hold_axis`]: with the axis OFF the rate draw is skipped (default schedules
  /// byte-identical); an enabled run is its own baseline, with `VOPR_NO_TORN_HEADER` only zeroing the
  /// applied rate.
  torn_header_axis: bool,
  /// How many wipe ACTIONS this run has taken (counted against [`WIPE_BUDGET`]). Advances whether or
  /// not the `VOPR_NO_WIPE` mask downgraded the effect, so a masked shrink run keeps the exact same
  /// action schedule + PRNG stream as the unmasked run it is diagnosing.
  wipe_actions: u64,
  /// Whether the CLIENT-CHURN axis is enabled for this run: the `VOPR_CHURN` env var, or
  /// force-enabled via [`run_vopr_with_churn`] (the committed churn sweep). Same discipline as
  /// [`Self::hold_axis`]: with the axis OFF its per-tick chance draw (and the build-time session-cap
  /// draw) is skipped entirely — no PRNG value consumed, the default schedule stays byte-identical;
  /// a churn-enabled run is its OWN deterministic baseline.
  churn_axis: bool,
  /// How many churn ACTIONS this run has taken (counted against [`CHURN_BUDGET`]).
  churn_actions: u64,
  /// Whether the ASYMMETRIC (one-way) partition axis is enabled for this run: the `VOPR_ASYM` env
  /// var, or force-enabled via [`run_vopr_with_asym`] (the committed asym sweep). Same discipline as
  /// [`Self::hold_axis`]: with the axis OFF its draws are skipped entirely (no PRNG value consumed —
  /// the default schedule stays byte-identical); an asym-enabled run is its OWN deterministic
  /// baseline, with the `VOPR_NO_ASYM` shrink mask staying on the same stream (the draws and the
  /// budget bookkeeping still happen; only the directed blocks are not installed).
  asym_axis: bool,
  /// Which replicas are currently the VICTIM of a one-way episode. A victim counts against the same
  /// minority budget as crashed/isolated (a one-way-impaired replica cannot complete a round-trip
  /// exchange, so it is budgeted as knocked out — conservative for the single-edge shape), and the
  /// crash/isolate pickers exclude victims so the knocked-out sets stay disjoint. Cleared wherever
  /// partitions heal (the heal actions, calm windows, final quiesce).
  asym_victims: Vec<bool>,
  /// Whether the SLOW-REPLICA (gray failure) axis is enabled for this run: the `VOPR_SLOW` env var,
  /// or force-enabled via [`run_vopr_with_slow`] (the committed slow sweep). Same discipline as
  /// [`Self::hold_axis`]; the `VOPR_NO_SLOW` shrink mask keeps the draws + episode bookkeeping and
  /// only skips installing the delivery profile.
  slow_axis: bool,
  /// The replica currently under a slow episode, if any (one at a time — a single gray box, not a
  /// uniformly slow cluster). NOT counted against the minority budget: a slow replica still
  /// participates (messages arrive, late), which is the point of the axis.
  slow_active: Option<usize>,
  /// The tick at which the active slow episode expires (the bounded episode window; calm windows
  /// and the final quiesce end it early).
  slow_until: u64,
  /// Whether the EDGE-BATCHING axis is enabled for this run: the `VOPR_BATCHING` env var, or
  /// force-enabled via [`run_vopr_with_batching`] (the committed batching sweep). Same discipline
  /// as [`Self::hold_axis`]: with the axis OFF no build-time draw is consumed and the cluster runs
  /// the plain state machine — the default per-seed schedule stays byte-identical; a
  /// batching-enabled run is its OWN deterministic baseline. The per-tick unit emission never
  /// touches the action PRNG at all (each batching client draws from its own seed-derived stream),
  /// so the chaos schedule composes with batching untouched.
  batching_axis: bool,
  /// Whether the STALE-READ axis is enabled for this run: the `VOPR_STALE_READ` env var, or
  /// force-enabled via [`run_vopr_with_stale_read`] (the committed stale-read sweep). Same discipline
  /// as [`Self::hold_axis`]: with the axis OFF its per-tick chance draw is skipped entirely (no PRNG
  /// value consumed — the default per-seed schedule stays byte-identical); a stale-read-enabled run is
  /// its OWN deterministic baseline. The lane deterministically partitions the current primary OUT (a
  /// deaf + mute one-way cut, reusing the asym victim/heal bookkeeping) to force a failover with the
  /// [`StalenessChecker`] live across the view change.
  stale_read_axis: bool,
  /// The stale-read lane's in-flight probe: `(deposed target, the view it served in when cut)`.
  /// `None` between probes. Resolved each tick — a strictly-higher-view serving primary while the
  /// target stays cut is the causal failover witness; a heal first abandons the probe — so the
  /// lane's non-vacuity counts completed failovers, not bare cut installs.
  active_stale_probe: Option<(usize, u64)>,
  /// Whether the LEARNER axis is enabled for this run: the `VOPR_LEARNER` env var, or force-enabled
  /// via [`run_vopr_with_learners`] (the committed learner sweep). When ON, the cluster carries
  /// 1..=3 non-voting learners (ids `[voting_count, node_count)`) drawn from a SEPARATE per-seed PRNG
  /// so the action stream is unperturbed; when OFF no learner draw is consumed and `node_count`
  /// equals `voting_count`, leaving the default per-seed schedule byte-identical. A learner follows
  /// the voting set's committed log, never emits a counted message, is never primary, and may catch
  /// up via state-sync — so a learner outage never reduces voter fault tolerance. Under the axis the
  /// driver also crashes a learner for a sustained window (NOT charged against the minority budget)
  /// to witness that voter progress is independent of learner health.
  learner_axis: bool,
  /// Per-replica last-observed applied-op count on a learner, so [`Self::learner_ops_applied`] folds
  /// the cumulative ops a learner applied across crash/restart (a `recover` re-applies from the
  /// durable checkpoint, so a plain high-water would under- or double-count). Indexed by replica; a
  /// voter slot stays 0 (only learner ids are sampled). The reset-robust positive-delta accumulation
  /// of [`Self::forced_sync_seen`].
  learner_applied_seen: Vec<usize>,
  /// Per-replica last-observed view on a learner, so [`Self::learner_view_changes_followed`] folds
  /// each time a learner ADOPTS a higher view (it caught up to a new primary's view via `GetView`).
  /// Indexed by replica; a voter slot stays 0. A learner view is monotone within an incarnation, so a
  /// plain positive-delta over the run counts the view advances it followed.
  learner_view_seen: Vec<u64>,
  /// Per-replica last-observed COMPLETED-state-sync count on a learner, so
  /// [`Self::learner_repairs_served`] folds each catch-up a learner completed. Indexed by replica; a
  /// voter slot stays 0. The `Endpoint` counter zeroes on `recover`, so this uses the same
  /// reset-robust positive-delta accumulation as [`Self::forced_sync_seen`].
  learner_repairs_seen: Vec<u64>,
  /// The tick at which the active learner-chaos crash window expires (the sustained learner outage
  /// the liveness-independence oracle installs). `0` when no learner is crashed by the axis.
  learner_crash_until: u64,
  /// The learner currently crashed by the learner-chaos behavior, if any (one at a time). Restarted
  /// at [`Self::learner_crash_until`], on calm-window entry, and by the final quiesce. NOT counted
  /// against the minority budget — a learner outage must never reduce voter fault tolerance.
  learner_crashed: Option<usize>,
  /// The durable `(epoch, view)` split-brain regression net, observed every tick. Held on the driver
  /// (not threaded through [`Self::check_invariants`]'s already-long signature) because it is a pure
  /// observation — no PRNG draw, no cluster mutation — so running it every tick leaves the applied
  /// digest byte-identical. It watches the static `(epoch 0, view 0)` lineage the foundation maintains:
  /// the durable `(epoch, view)` pair never regresses lexicographically.
  epoch_view: EpochViewMonotonicChecker,
  /// The `config_id` lineage fork net, observed every tick (same on-driver rationale as
  /// [`Self::epoch_view`]): the durable configuration history is a single non-forking chain.
  membership: MembershipMonotonicChecker,
  /// Per-replica last-observed session-eviction count, accumulated reset-robustly like
  /// [`Self::forced_sync_seen`] (this `Endpoint` counter also zeroes on `recover`). Indexed by replica.
  sessions_evicted_seen: Vec<u64>,
  /// Replicas wiped since the last invariant check, queued so [`Self::check_invariants`] can tell the
  /// stateful checkers their per-replica baselines are forfeit BEFORE they next observe the cluster.
  wiped_pending: Vec<usize>,
  report: VoprReport,
}

/// Run one VOPR simulation for `ticks` ticks, seeded entirely by `seed`. Returns a [`VoprReport`]
/// summarising the schedule explored. After the chaos loop it runs a bounded final QUIESCE phase
/// (heal everything, restart all, no faults, tick to convergence — the `run_final_quiesce` step)
/// before the end-of-run durability + applied-once assertions, so the survivors apply any
/// durably-held committed tail first. **Panics** (with `seed` + `tick` + a one-line description) on
/// any safety, durability, applied-once,
/// view-monotonicity, boundedness, append-before-ack, structural-ordering, or liveness (including
/// final-quiesce non-convergence) violation — so a failing seed is reproducible via [`run_vopr_one`].
pub fn run_vopr(seed: u64, ticks: u64) -> VoprReport {
  run_seeded(Vopr::new(seed, env_flag("VOPR_LEARNER")), ticks)
}

/// Like [`run_vopr`] but with the unbounded-HOLD network axis FORCE-ENABLED, independent of the
/// `VOPR_HOLD` env var (a programmatic override — no env mutation, so concurrently-running tests in
/// one process cannot race each other's schedules). A hold-enabled run is still a pure function of
/// `(seed, ticks)` and is byte-identical to a `VOPR_HOLD=1` run of the same seed; it is its OWN
/// deterministic baseline, distinct from the default schedule (the hold axis consumes extra PRNG
/// draws). The entry point for the committed hold sweep — the axis that reaches the op-reuse /
/// stale-vote class (a held message outliving its op's truncation + re-mint).
pub fn run_vopr_with_hold(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.hold_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the WIPE-and-restart (amnesia) axis FORCE-ENABLED, independent of the
/// `VOPR_WIPE` env var (the same programmatic-override pattern as [`run_vopr_with_hold`]). At most
/// `WIPE_BUDGET` crashed replicas per run come back with FRESH, EMPTY durable storage (a replaced
/// disk) instead of recovering their persisted WAL/superblock — the classic VSR amnesia hazard: the
/// wiped replica re-joins at genesis with no memory of the views it voted in or the committed ops it
/// durably held. Its OWN pre-wipe state is forfeit (within the crash-fault model's `<= f` lost-state
/// budget; the stateful checkers' per-replica baselines are reset accordingly), but every
/// CLUSTER-level invariant stays at full strength: agreement, no committed op rewritten/lost across
/// time, quorum-durable retention (relaxed by exactly the wiped count — see the driver's
/// per-tick structural check), and the end-of-run survival of the whole committed history. A
/// violation here is a REAL protocol finding (amnesia breaking quorum intersection), not a checker
/// artifact. A wipe-enabled run is a pure function of `(seed, ticks)` and its own deterministic
/// baseline (the axis consumes extra PRNG draws); this is the entry point for the committed wipe
/// sweep.
pub fn run_vopr_with_wipe(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.wipe_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the TORN-HEADER contract-violation PROBE axis FORCE-ENABLED,
/// independent of the `VOPR_TORN_HEADER` env var (the same programmatic-override pattern as
/// [`run_vopr_with_hold`]). A seed-chosen per-mille of completed WAL appends LOSE THEIR HEADER: the
/// slot reads back `Absent`/`Empty` with `header() == None`, as if the append had never happened —
/// the exact failure shape the `Wal` header-durability contract FORBIDS an embedder from producing
/// (headers must survive body-level faults; the `Body::Repairing` keep-header-only committed-op
/// survival design leans on it). This lane therefore probes what happens when that documented
/// contract is VIOLATED: a violation surfacing here is EXPECTED EVIDENCE the contract is
/// load-bearing, not a proto bug to fix; a clean sweep would show the proto tolerates even
/// headerless faults. NOT part of the committed gates — see the `#[ignore]`d probe lane in
/// `tests/vopr.rs`.
pub fn run_vopr_with_torn_headers(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.torn_header_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the ASYMMETRIC (one-way) partition axis FORCE-ENABLED, independent of
/// the `VOPR_ASYM` env var (the same programmatic-override pattern as [`run_vopr_with_hold`]). The
/// default schedule's partitions are SYMMETRIC (group membership: either side sees the other, or
/// neither does); this axis installs DIRECTED blocks — `blocked[from][to]` drops `from → to` while
/// `to → from` flows — the one-way reachability real networks produce (a half-dead NIC, an
/// asymmetric route/firewall).
/// The liveness-killer instance is a DEAF primary: its heartbeats flow OUT (suppressing the backups'
/// idle view-change timers) while the acks never ARRIVE (nothing commits) — so the victim draw
/// biases toward a current primary half the time. Victims count against the same minority budget as
/// crash/isolate, episodes heal exactly like symmetric partitions (a heal branch + every calm
/// window/final quiesce restores full bidirectional connectivity), and progress is NOT owed during
/// an episode — a calm window requires full bidirectional connectivity, so the liveness oracle
/// judges recovery-after-heal. Safety/durability are judged as-is, every tick. A violation here is
/// a REAL finding (one-way reachability wedging recovery or splitting commit accounting) — report
/// it with its seed; never mask it. An asym-enabled run is a pure function of `(seed, ticks)` and
/// its own deterministic baseline (the axis consumes extra PRNG draws); this is the entry point for
/// the committed asym sweep.
pub fn run_vopr_with_asym(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.asym_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the SLOW-REPLICA (gray failure) axis FORCE-ENABLED, independent of
/// the `VOPR_SLOW` env var (the same programmatic-override pattern as [`run_vopr_with_hold`]). On a
/// seeded cadence one replica becomes SLOW for a bounded episode window: its inter-replica messages
/// (inbound, outbound, or both — seeded) each pick up an extra delay drawn from a seeded band a few
/// milliseconds wide, on top of the base latency + jitter. This is NOT a partition — every message
/// still ARRIVES, late — and the band sits deliberately BELOW the proto's liveness cadences (50 ms
/// commit heartbeat, 200 ms idle view-change), so the replica is degraded-but-alive: the classic
/// gray failure that neither the crash detector (it never stops) nor the partition model (nothing
/// is dropped) can express. The slow replica still participates and is NOT budgeted as knocked out;
/// episodes are bounded (a seeded tick window) and healed like partitions (calm windows and the
/// final quiesce end them early), so the liveness oracle judges a fully-prompt cluster. A violation
/// here is a REAL finding (consistently-late delivery wedging a timer interaction or splitting
/// agreement) — report it with its seed; never mask it. A slow-enabled run is a pure function of
/// `(seed, ticks)` and its own deterministic baseline; this is the entry point for the committed
/// slow sweep.
pub fn run_vopr_with_slow(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.slow_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the EDGE-BATCHING axis FORCE-ENABLED, independent of the
/// `VOPR_BATCHING` env var (the same programmatic-override pattern as [`run_vopr_with_hold`]). The
/// cluster runs the batch-aware state machine (every committed body is parsed with the REAL batch
/// codec and applied per unit), and a seeded subset of the clients become BATCHING clients driving
/// the deterministic aggregator model: units (and occasional atomic groups) are emitted on a
/// seeded per-tick cadence, queued while a body is in flight, packed FIFO into ONE request body
/// under the aggregator's dual-budget rule, and demultiplexed per unit on the ack — so batching
/// semantics (unit exactly-once, group atomicity, per-unit reply pairing) are judged under the
/// FULL adversarial schedule (crashes, partitions, view changes, repair, state-sync) by the
/// standard checkers plus the per-unit oracle ([`check_batching`](crate::batching::check_batching),
/// run post-quiesce). The remaining clients ride the single-unit wrap, so every body in the run is
/// codec-built.
///
/// The DEFAULT sweep leaves this axis OFF (its build-time draws would shift every pinned
/// regression seed off its historical schedule); batching-enabled runs are their own deterministic
/// baselines, byte-identical to `VOPR_BATCHING=1` runs of the same seeds. Unit emission draws from
/// per-client seed-derived PRNGs — never the action stream — so the chaos schedule composes with
/// batching unperturbed.
pub fn run_vopr_with_batching(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.batching_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the CLIENT-CHURN axis FORCE-ENABLED, independent of the `VOPR_CHURN`
/// env var (the same programmatic-override pattern as [`run_vopr_with_hold`]). The default sweep's
/// client set is FIXED for a whole run, so the session table converges to one row per client and the
/// session-cap eviction can never engage. This lane churns the population: on a seeded cadence
/// (within `CHURN_BUDGET`) an ACTIVE client RETIRES (it stops issuing; its session row goes idle
/// and ages) and a FRESH `ClientId` spawns in its place — so distinct client ids accumulate over the
/// run while the concurrent load stays level. Paired with a SMALL seeded `max_client_sessions`
/// (drawn at build time only on churn-enabled runs), the deterministic apply-time eviction genuinely
/// engages under the full crash + partition + disk-fault schedule; the existing safety / durability /
/// liveness checkers judge the outcome (divergent eviction would diverge the session tables that ride
/// every checkpoint envelope — the class this lane exists to catch). A churn-enabled run is a pure
/// function of `(seed, ticks)` and its own deterministic baseline (the axis consumes extra PRNG
/// draws); this is the entry point for the committed churn sweep.
pub fn run_vopr_with_churn(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.churn_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the STALE-READ axis FORCE-ENABLED, independent of the `VOPR_STALE_READ`
/// env var (the same programmatic-override pattern as [`run_vopr_with_hold`]). On a seeded cadence the
/// lane deterministically partitions the CURRENT primary OUT — every directed inter-replica leg
/// to/from it cut, so it is at once deaf (acks/votes never arrive) and mute (its heartbeats/prepares
/// never reach the survivors, whose idle view-change timers then fire) — forcing the survivors to
/// elect a NEW primary while the deposed one sits in its old view. The episode reuses the asym
/// victim/budget/heal bookkeeping (the deposed primary counts against the minority budget and heals
/// like any one-way episode), and the [`StalenessChecker`] runs LIVE across the failover, so the
/// staleness floor (the committed-history high-water) is asserted MONOTONE through the view change —
/// the real cross-check this lane exercises now.
///
/// The read-specific assertion (the deposed primary cannot serve a STALE read) is DEFERRED to the
/// future read-path step: there is no read path today, so no read is recorded and the staleness
/// enforcement is vacuous — this lane lands now exercising the failover schedule that assertion will
/// later hang on. A stale-read-enabled run is a pure function of `(seed, ticks)` and its own
/// deterministic baseline (the axis consumes extra PRNG draws); this is the entry point for the
/// committed stale-read sweep.
pub fn run_vopr_with_stale_read(seed: u64, ticks: u64) -> VoprReport {
  let mut v = Vopr::new(seed, env_flag("VOPR_LEARNER"));
  v.stale_read_axis = true;
  run_seeded(v, ticks)
}

/// Like [`run_vopr`] but with the LEARNER axis FORCE-ENABLED, independent of the `VOPR_LEARNER` env
/// var (the same programmatic-override pattern as [`run_vopr_with_hold`]). The cluster carries
/// 1..=3 NON-VOTING learners alongside the voting set (ids `[voting_count, node_count)`), drawn from
/// a SEPARATE per-seed PRNG so the action stream is byte-identical to the no-learner run of the same
/// seed at every shared draw — the learner count only GROWS `node_count` (and so the per-replica
/// vectors + the routing fan-out), it does not perturb the chaos schedule. A learner applies the
/// committed log the voters agree on but NEVER emits a counted message (no PrepareOk / StartViewChange
/// / DoViewChange), is NEVER primary, and may catch up via state-sync; it is never an active
/// view-change participant. The oracle witnesses each claim (never-primary, no-learner-emit,
/// convergence) and, UNDER THE AXIS, crashes a learner for a sustained window WITHOUT charging the
/// minority budget — so the calm-window committed-progress assertion must still advance using voters
/// alone, proving voter fault tolerance is independent of learner health. A violation here is a REAL
/// finding (a learner voting/leading, or a learner outage stalling voter progress) — report it with
/// its seed; never mask it. A learner-enabled run is a pure function of `(seed, ticks)` and is
/// byte-identical to a `VOPR_LEARNER=1` run of the same seed; this is the entry point for the
/// committed learner sweep.
pub fn run_vopr_with_learners(seed: u64, ticks: u64) -> VoprReport {
  run_seeded(Vopr::new(seed, true), ticks)
}

/// The shared run loop behind [`run_vopr`] / [`run_vopr_with_hold`]: the driver `v` already carries
/// the seed and the axis configuration.
fn run_seeded(mut v: Vopr, ticks: u64) -> VoprReport {
  let mut c = v.build_cluster();

  let mut dur = DurabilityChecker::new(v.node_count);
  let mut vm = ViewMonotonicChecker::new(v.node_count);
  let mut applied_once = AppliedOnceChecker::new(v.node_count);
  let mut staleness = StalenessChecker::new(v.node_count, v.report.clients);
  // Generous structural bound: the per-op caches/WAL plateau near a few checkpoint intervals plus
  // pipeline headroom; a real unbounded-growth leak blows well past this. Clients are bounded by the
  // active client set — which the churn axis GROWS by up to CHURN_BUDGET distinct ids over the run
  // (each spawn is a fresh id; the proto's own session cap holds the per-replica table far below
  // this, so the headroom only keeps the checker's bound honest about the population).
  let churn_headroom = if v.churn_axis {
    CHURN_BUDGET as usize
  } else {
    0
  };
  let bound = BoundednessChecker::new(4_096, v.node_count + v.report.clients + churn_headroom + 8);

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
    v.check_invariants(
      &mut c,
      tick,
      &mut dur,
      &mut vm,
      &mut applied_once,
      &mut staleness,
      &bound,
    );
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
  v.run_final_quiesce(
    &mut c,
    ticks,
    &mut dur,
    &mut vm,
    &mut applied_once,
    &mut staleness,
    &bound,
  );

  // Final durability assertion: after convergence, the whole committed history survives, applied, on
  // at least one operational replica — proving no committed op was lost across the run.
  if let crate::checker::CheckResult::Violation(why) = dur.check(&c) {
    panic!(
      "vopr seed {} tick {ticks} (final, post-quiesce): {why}",
      v.seed
    );
  }
  // Final applied-once assertion: every client-acked reply is present in the global applied map with
  // a matching reply body (acked-but-never-applied = a lost committed op), and the map is non-empty
  // whenever anything committed — every request a client was acked for was applied exactly once.
  if let crate::checker::CheckResult::Violation(why) = applied_once.check(&c) {
    panic!(
      "vopr seed {} tick {ticks} (final, post-quiesce): applied-once: {why}",
      v.seed
    );
  }
  // Final staleness assertion: the committed-history high-water (the staleness floor) stayed monotone,
  // and every recorded linearizable read reflected every write acked before it issued (vacuous today —
  // no read path records reads — but the acked set is non-empty whenever anything committed, so the
  // capture is non-vacuous). Structurally ready to enforce reads the moment a read path exists.
  if let crate::checker::CheckResult::Violation(why) = staleness.check(&c) {
    panic!(
      "vopr seed {} tick {ticks} (final, post-quiesce): staleness: {why}",
      v.seed
    );
  }
  // Final per-unit batching oracle (a cheap no-op when no client batched): every acked unit is in
  // the recorded unit history exactly once at its request's committed (op, unit_index) with the
  // submitted bytes and the SM's deterministic reply, and groups rode one op on adjacent indices.
  if let crate::checker::CheckResult::Violation(why) = crate::batching::check_batching(&c) {
    panic!(
      "vopr seed {} tick {ticks} (final, post-quiesce): batching: {why}",
      v.seed
    );
  }
  // Final learner-convergence oracle (a cheap no-op with no learners): after the quiesce drain, every
  // non-crashed learner has applied the SAME committed `(op, body)` history as the voters, up to the
  // committed-history high-water — it follows the committed log to convergence.
  v.check_learner_convergence(&c, ticks);
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

/// The per-run WIPE budget: at most this many wipe-and-restart actions per run (wipe-axis runs only).
/// A wipe PERMANENTLY forfeits one replica's durable state, and the cluster-level "committed ops
/// survive" guarantee holds only while at most `f = ⌊(N-1)/2⌋` replicas' durable states are lost
/// within a window the protocol cannot re-replicate across. `1` is `<= f` for every cluster size that
/// can crash at all (N >= 3 ⇒ f >= 1; N = 2 has f = 0, never crashes a replica, and so never wipes —
/// `pick_crashed` finds no candidate). No replica is special-cased: ANY crashed replica may be the
/// one wiped — including the sole quorum-intersection holder — and the checkers judge the outcome;
/// that is the point of the oracle.
const WIPE_BUDGET: u64 = 1;

/// The per-run CLIENT-CHURN budget (churn-axis runs only): at most this many retire+spawn actions
/// per run. Bounds the distinct-`ClientId` population (the boundedness checker's client headroom)
/// while leaving far more churn than the small seeded session cap needs to engage eviction many
/// times over within a run's tick budget.
const CHURN_BUDGET: u64 = 48;

/// The magic mixed into the seed for the learner-count PRNG. A distinct local stream (NOT the action
/// stream `self.prng`), so when the learner axis is OFF no learner draw happens and `node_count`
/// equals `voting_count`, leaving the default per-seed schedule byte-identical; when ON, the learner
/// count is a pure deterministic function of the seed independent of every other draw. Must not
/// collide with `BOUNDED_WAL_SEED_MAGIC` or any other `_MAGIC` in this crate.
const LEARNER_SEED_MAGIC: u64 = 0x1EA2_4E11_5EED_C0DE;

impl Vopr {
  fn new(seed: u64, learner_axis: bool) -> Self {
    let mut prng = Prng::new(seed);
    // VOTING-replica count from {2, 3, 4, 5, 6} — including EVEN N and the sharp N=2 case (covering
    // the quorum/nack arithmetic). `Config::try_new` accepts any `1..=64`, and the derived quorums are
    // sane for every size: quorum = ⌊n/2⌋+1, quorum_view_change = quorum_nack_prepare = n − quorum + 1
    // (N=2 → quorum 2 = unanimous, vc/nack 1 = a single DVC/nack suffices; N=4 → 3 / 2; N=6 → 4 / 3),
    // and the replication↔view-change intersection `quorum + quorum_view_change > n` holds for all.
    let voting_count = 2 + (prng.below(5) as usize);
    // The learner count: 1..=3 NON-VOTING learners when the axis is on, none otherwise. Drawn from a
    // SEPARATE per-seed PRNG (`seed ^ LEARNER_SEED_MAGIC`), NOT the action stream `self.prng`, so with
    // the axis OFF no draw is consumed and `node_count` equals `voting_count` — the default per-seed
    // schedule stays byte-identical. With the axis ON the count is a pure function of the seed,
    // independent of the chaos schedule (it only GROWS the membership, never perturbs the action
    // stream). Kept small (≤3) so the per-replica vectors stay modest.
    let learner_count = if learner_axis {
      Prng::new(seed ^ LEARNER_SEED_MAGIC).below(3) as usize + 1
    } else {
      0
    };
    // The TOTAL membership: voters plus learners. Sizes every per-replica vector + the routing fan-out.
    let node_count = voting_count + learner_count;
    // ⌊(N−1)/2⌋ over the VOTING set — the minority a quorum survives: N=2→0, N=3→1, N=4→1, N=5→2,
    // N=6→2. For N=2 the budget is 0, so the chaos chooser never knocks out a voter (any single fault
    // would break the unanimous quorum 2 and stall progress LEGITIMATELY) — only network
    // drop/dup/jitter and async storage churn apply, which a 2-node cluster must still make progress
    // under.
    let minority_budget = (voting_count - 1) / 2;
    // A handful of clients: 2..=4.
    let clients = 2 + (prng.below(3) as usize);
    Self {
      seed,
      prng,
      node_count,
      voting_count,
      minority_budget,
      isolated: vec![false; node_count],
      calm: false,
      phase_until: 0,
      calm_start_virtual: Instant::ZERO,
      forced_sync_seen: vec![0; node_count],
      wal_stalls_seen: vec![0; node_count],
      below_ring_window_syncs_seen: vec![0; node_count],
      sync_chunk_transfers_seen: vec![0; node_count],
      unions_floored_seen: vec![0; node_count],
      repair_batches_served_seen: vec![0; node_count],
      prepare_batches_sent_seen: vec![0; node_count],
      header_only_carriers_seen: vec![0; node_count],
      calm_baseline_committed: 0,
      calm_had_outstanding: false,
      // Set by `build_cluster` (which draws the bounded-WAL decision off the prng); `None` until then.
      wal_capacity: None,
      hold_axis: env_flag("VOPR_HOLD"),
      wipe_axis: env_flag("VOPR_WIPE"),
      torn_header_axis: env_flag("VOPR_TORN_HEADER"),
      wipe_actions: 0,
      churn_axis: env_flag("VOPR_CHURN"),
      churn_actions: 0,
      asym_axis: env_flag("VOPR_ASYM"),
      asym_victims: vec![false; node_count],
      slow_axis: env_flag("VOPR_SLOW"),
      slow_active: None,
      slow_until: 0,
      batching_axis: env_flag("VOPR_BATCHING"),
      stale_read_axis: env_flag("VOPR_STALE_READ"),
      active_stale_probe: None,
      learner_axis,
      learner_applied_seen: vec![0; node_count],
      learner_view_seen: vec![0; node_count],
      learner_repairs_seen: vec![0; node_count],
      learner_crash_until: 0,
      learner_crashed: None,
      epoch_view: EpochViewMonotonicChecker::new(node_count),
      membership: MembershipMonotonicChecker::new(),
      sessions_evicted_seen: vec![0; node_count],
      wiped_pending: Vec::new(),
      report: VoprReport {
        seed,
        replicas: node_count,
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
    // unit-tested in `viewstamp-proto`, not reachable here.
    let large_ckpt = self.prng.chance(1, 3);
    let checkpoint_ops = if large_ckpt {
      256 + self.prng.below(513)
    } else {
      4 + self.prng.below(9)
    };
    // seed-derive a PHYSICAL bounded-WAL ring for ~1/3 of seeds (the rest keep the
    // UNBOUNDED default), so the adversarial sweep EXERCISES wrap (stall-before-wrap + recover off a
    // wrapped ring + a below-ring-window backup overflow) UNDER the full fault schedule — crash +
    // partition + disk faults together.
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
    let learner_count = self.node_count.saturating_sub(self.voting_count) as u16;
    let mut c = Cluster::with_members(
      self.voting_count as u8,
      learner_count,
      clients,
      requests_per_client,
      self.seed,
      checkpoint_ops,
    );
    // Async WAL: a per-append in-flight window of 1..=4 polls (the append-before-ack window).
    let delay = 1 + self.prng.below(4) as u32;
    c.set_async_wal_delay(Some(delay));
    // Async SUPERBLOCK: a per-write in-flight window of 1..=4 polls (the pending durable-view window
    // the durable-view-before-participate gate must survive; a synchronously-completing superblock
    // never opens it). Seeded per-run; a `crash` discards any
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
    // CHURN axis: pair the churning client population with a SMALL seeded session cap so the
    // deterministic apply-time eviction genuinely engages within the tick budget (the proto default
    // of 4096 needs more distinct committing clients than a run can mint). The cap is drawn with
    // comfortable headroom ABOVE the concurrent active client count (`clients + 4 ..= clients + 7`),
    // so eviction victims are overwhelmingly the RETIRED clients' idle rows — the oldest-activity
    // ordering the rule targets — rather than a live client mid-conversation. The draw is
    // CONDITIONAL on the axis (no PRNG value consumed otherwise — the default per-seed schedule
    // stays byte-identical; a churn-enabled run is its own deterministic baseline, like the hold
    // axis). Set AFTER the other build steps: it rebuilds the (still-fresh) endpoints with the
    // capped config, leaving the storage/fault/ring composition above intact.
    if self.churn_axis {
      let cap = clients + 4 + self.prng.below(4) as u32;
      c.set_max_client_sessions(Some(cap));
    }
    // BATCHING axis: switch the cluster to the batch-aware state machine and turn a seeded subset
    // of the clients into batching clients driving the aggregator model; the rest ride the
    // single-unit wrap so EVERY committed body is codec-built (BatchSm panics on anything else).
    // All draws are CONDITIONAL on the axis (no PRNG value consumed otherwise — the default
    // per-seed schedule stays byte-identical; a batching-enabled run is its own deterministic
    // baseline, like the hold axis), and the per-tick unit emission draws from per-client
    // seed-derived PRNGs, never this action stream, so the chaos schedule composes unperturbed.
    // Ranges are modest by design — unit payloads of at most a few dozen bytes and bodies capped
    // by the small sim budgets — because the lane stresses batching SEMANTICS under chaos, not
    // body size (the frame-cap axis owns size stress).
    if self.batching_axis {
      c.set_batch_mode(true);
      let batching_clients = 1 + self.prng.below(clients as u64) as usize;
      let max_rate = 1 + self.prng.below(3);
      let group_denom = 4 + self.prng.below(9) as u32;
      let max_unit_len = 8 + self.prng.below(41) as usize;
      for i in 0..clients as usize {
        if i < batching_clients {
          c.enable_client_batching(
            i,
            crate::batching::BatchingConfig {
              seed: self.seed,
              client: (i as u128) + 1,
              max_rate,
              group_denom,
              max_unit_len,
              // Generous, like requests_per_client: the run keeps offering unit load for the
              // whole tick window, so the liveness oracle stays non-vacuous.
              auto_units: 4_000,
            },
          );
        } else {
          c.wrap_client_bodies(i);
        }
      }
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
    // The UNBOUNDED-HOLD axis is OPT-IN per run (`VOPR_HOLD`, or force-enabled by
    // `run_vopr_with_hold` — the committed hold sweep). Its draw is CONDITIONAL: with the axis OFF no
    // PRNG value is consumed, so the per-seed schedule is byte-identical to the default schedule (the
    // pinned regression seeds + the 0..N sweep reproduce exactly). A hold-enabled run is its OWN
    // baseline (a shrink keeps the axis on), so the conditional draw does not break shrink
    // determinism. Enabling it lets a `PrepareOk` outlive its op's truncation + re-mint and arrive as
    // a stale-body vote — the op-reuse class the content-addressed vote gate must reject.
    let hold = if self.hold_axis {
      1 + self.prng.below(30) as u32
    } else {
      0
    };
    Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(if env_flag("VOPR_NO_JITTER") {
        0
      } else {
        jitter
      }),
      drop_per_mille: if env_flag("VOPR_NO_DROP") { 0 } else { drop },
      duplicate_per_mille: if env_flag("VOPR_NO_DUP") { 0 } else { dup },
      hold_per_mille: hold,
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
    // The TORN-HEADER contract-violation probe rate is OPT-IN per run (`VOPR_TORN_HEADER`, or
    // force-enabled by `run_vopr_with_torn_headers` — the probe lane). Like the hold axis, its draw
    // is CONDITIONAL: with the axis OFF no PRNG value is consumed, so every default/hold/wipe
    // schedule stays byte-identical. An enabled run is its own baseline; the `VOPR_NO_TORN_HEADER`
    // shrink mask below only ZEROES the applied rate, keeping the stream. Low rate (1..=12 per
    // mille): each hit erases a completed append header-and-all, so a high rate would simply raze the
    // cluster rather than probe the contract's blast radius.
    let torn_header = if self.torn_header_axis {
      1 + self.prng.below(12) as u32
    } else {
      0
    };
    // `VOPR_NO_PERM` masks PERMANENT corruption (torn-write / bit-rot of an already-durable committed
    // slot), leaving the TRANSIENT faults (read / misdirect / corrupt-checkpoint, all of which clear on
    // retry) on — an opt-in escape hatch for isolating a transient-fault repro.
    let mask_perm = env_flag("VOPR_NO_PERM");
    StorageFaults {
      read_fault_per_mille: if env_flag("VOPR_NO_READFAULT") {
        0
      } else {
        read
      },
      torn_write_per_mille: if mask_perm { 0 } else { torn },
      bit_rot_per_mille: if mask_perm { 0 } else { rot },
      torn_header_per_mille: if env_flag("VOPR_NO_TORN_HEADER") {
        0
      } else {
        torn_header
      },
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

  /// Open a calm window: heal every partition (symmetric AND one-way — a calm window requires full
  /// bidirectional connectivity, so an asymmetric episode is never live inside one), end any slow
  /// episode (calm also requires PROMPT delivery), restart every crashed replica, drop all network +
  /// storage faults, and snapshot the liveness baseline. Runs for a stretch long enough for the
  /// cluster to converge.
  ///
  /// The learner-chaos victim is DELIBERATELY left crashed across the calm window (it is restarted on
  /// its OWN window expiry or by the final quiesce, never here): the calm-window committed-progress
  /// assertion must then advance using the VOTERS ALONE while a learner is down — the liveness
  /// independence claim. Because a learner is not a voter, the fully-healed voting majority still
  /// commits, so this is a sound assertion, not a flaky one.
  fn enter_calm(&mut self, c: &mut Cluster, tick: u64) {
    self.heal_all_partitions(c);
    self.end_slow_episode(c);
    for i in 0..self.node_count {
      // A retired (reconfiguration-removed) node is parked crashed-forever — never restart it.
      if c.is_crashed(i) && !c.is_retired(i) && Some(i) != self.learner_crashed {
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
  #[allow(clippy::too_many_arguments)]
  fn run_final_quiesce(
    &mut self,
    c: &mut Cluster,
    ticks: u64,
    dur: &mut DurabilityChecker,
    vm: &mut ViewMonotonicChecker,
    applied_once: &mut AppliedOnceChecker,
    staleness: &mut StalenessChecker,
    bound: &BoundednessChecker,
  ) {
    // Heal: all partitions (symmetric and one-way) cleared, any slow episode ended, every crashed
    // replica restarted (EXCEPT a retired one — a reconfiguration removed it; it stays parked), no
    // network/storage chaos.
    self.heal_all_partitions(c);
    self.end_slow_episode(c);
    for i in 0..self.node_count {
      if c.is_crashed(i) && !c.is_retired(i) {
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
      self.check_invariants(c, ticks + k, dur, vm, applied_once, staleness, bound);
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
    let applied_hw = (0..self.node_count)
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
    if self.prng.chance(1, 80)
      && let Some(i) = self.pick_crashable(c)
    {
      if trace {
        eprintln!("tick {tick}: CRASH replica {i}");
      }
      c.crash(i);
      self.report.crashes += 1;
    }

    // (c) Restart a previously-crashed replica (random timing, independent of calm windows).
    if self.prng.chance(1, 60)
      && let Some(i) = self.pick_crashed(c)
    {
      if trace {
        eprintln!("tick {tick}: RESTART replica {i}");
      }
      self.restart_and_track(c, i);
    }

    // (c') WIPE-and-restart a crashed replica (the amnesia axis): it comes back with FRESH, EMPTY
    // durable storage — a replaced disk — so every promise its pre-wipe durable state made (view
    // participation, durable quorum copies) is forfeit. Only with the axis enabled (a wipe-enabled
    // run is its own deterministic baseline; with the axis OFF no draw is consumed, mirroring the
    // hold axis), and only within [`WIPE_BUDGET`]. The candidate is any crashed replica — never
    // special-cased away from the dangerous one (the sole quorum-intersection holder); the checkers
    // judge the outcome. The chance draw fires UNCONDITIONALLY on a wipe-enabled run (budget checked
    // after), and `wipe_actions` advances whether or not `VOPR_NO_WIPE` downgrades the effect to a
    // plain restart, so a masked shrink run keeps the exact same schedule + stream.
    if self.wipe_axis
      && self.prng.chance(1, 40)
      && self.wipe_actions < WIPE_BUDGET
      && let Some(i) = self.pick_crashed(c)
    {
      self.wipe_actions += 1;
      if env_flag("VOPR_NO_WIPE") {
        if trace {
          eprintln!("tick {tick}: WIPE replica {i} (masked: plain restart)");
        }
        self.restart_and_track(c, i);
      } else {
        if trace {
          eprintln!("tick {tick}: WIPE replica {i} (fresh storage)");
        }
        c.wipe_and_restart(i);
        self.report.restarts += 1;
        self.report.wipes_fired += 1;
        // The stateful checkers' per-replica baselines (durable view, checkpoint high-water) are
        // forfeit with the disk; queue the notice so `check_invariants` resets them BEFORE the
        // next observation. Cluster-level invariants are NOT relaxed there.
        self.wiped_pending.push(i);
      }
    }

    // (c'') CLIENT CHURN (the session-population axis): retire a random ACTIVE client (it stops
    // issuing; its session rows go idle and age toward the cap eviction) and spawn a FRESH ClientId
    // issuing the same load in its place — distinct ids accumulate while concurrency stays level.
    // Only with the axis enabled (a churn-enabled run is its own deterministic baseline; with the
    // axis OFF no draw is consumed, mirroring the hold axis), and only within [`CHURN_BUDGET`] (the
    // chance draw fires unconditionally on a churn-enabled run, budget checked after, so an
    // exhausted budget keeps the same PRNG stream).
    if self.churn_axis && self.prng.chance(1, 48) && self.churn_actions < CHURN_BUDGET {
      let actives: Vec<usize> = (0..c.client_count())
        .filter(|&i| !c.client(i).is_done())
        .collect();
      if let Some(i) = self.pick(&actives) {
        self.churn_actions += 1;
        if trace {
          eprintln!("tick {tick}: CHURN retire client {i}, spawn a fresh ClientId");
        }
        c.retire_client(i);
        c.spawn_client(1_000);
        self.report.churns_fired += 1;
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
        // `Cluster::heal` restores FULL connectivity (groups + one-way blocks), so the driver-side
        // victim bookkeeping must clear with it — the helper keeps both sides in sync.
        self.heal_all_partitions(c);
        self.report.heals += 1;
      }
    }

    // (d') ONE-WAY (asymmetric) partition: install a DIRECTED episode against a victim (budget
    // permitting), or heal all one-way blocks — the install/heal coin mirrors the symmetric action
    // (d). Only with the axis enabled (an asym-enabled run is its own deterministic baseline; with
    // the axis OFF no draw is consumed, mirroring the hold axis). The episode shape is seeded:
    // DEAF (every inbound leg to the victim cut — it sends, it never hears: the liveness-killer
    // when the victim is a primary, whose outgoing heartbeats keep suppressing the backups' idle
    // view-change timers while no ack ever arrives), MUTE (every outbound leg cut — it hears, it is
    // never heard: a silently-ignored voter), or a SINGLE directed edge (the mildest one-way fault).
    // The `VOPR_NO_ASYM` shrink mask keeps every draw + the victim/budget bookkeeping and only skips
    // installing the blocks, so a masked run stays on the exact same action schedule.
    if self.asym_axis && self.prng.chance(1, 90) {
      if self.prng.chance(1, 2) {
        if let Some(v) = self.pick_asym_victim(c) {
          let shape = self.prng.below(3);
          // The single-edge peer + direction draws happen for EVERY install (not just shape 2) so
          // the stream never depends on which shape was drawn. The peer ranges over the full
          // membership: a directed edge can touch any member, voter or learner.
          let mut w = self.prng.below((self.node_count - 1) as u64) as usize;
          if w >= v {
            w += 1;
          }
          let to_victim = self.prng.chance(1, 2);
          self.asym_victims[v] = true;
          if !env_flag("VOPR_NO_ASYM") {
            match shape {
              // DEAF: every peer's messages TO the victim are dropped; the victim's own flow out.
              0 => {
                for x in 0..self.node_count {
                  if x != v {
                    c.block_one_way(x as u16, v as u16);
                  }
                }
              }
              // MUTE: the victim's messages to every peer are dropped; everyone still reaches it.
              1 => {
                for x in 0..self.node_count {
                  if x != v {
                    c.block_one_way(v as u16, x as u16);
                  }
                }
              }
              // SINGLE EDGE: one directed leg between the victim and a seeded peer.
              _ => {
                let (f, t) = if to_victim { (w, v) } else { (v, w) };
                c.block_one_way(f as u16, t as u16);
              }
            }
            self.report.asym_episodes += 1;
          }
          if trace {
            let kind = ["DEAF", "MUTE", "EDGE"][shape as usize];
            eprintln!("tick {tick}: ASYM {kind} victim {v} (peer {w}, to_victim={to_victim})");
          }
        }
      } else if self.asym_victims.iter().any(|&b| b) {
        if trace {
          eprintln!("tick {tick}: HEAL one-way blocks");
        }
        for b in &mut self.asym_victims {
          *b = false;
        }
        c.heal_one_way();
        self.report.heals += 1;
      }
    }

    // (d'') STALE-READ probe: deterministically partition the CURRENT primary OUT (a deaf + mute
    // one-way cut both ways), forcing the survivors to elect a new primary while the deposed one sits
    // in its old view — the failover the staleness floor must stay monotone through. The install/heal
    // coin mirrors the asym action (d'), and the deposed primary reuses the asym victim bookkeeping
    // (it counts against the same minority budget and heals on the one-way heal branch / calm window /
    // final quiesce). Only with the axis enabled (a stale-read-enabled run is its own deterministic
    // baseline; with the axis OFF no draw is consumed, mirroring the hold axis), and only within the
    // minority budget (a quorum of survivors must remain to elect + commit). The
    // [`StalenessChecker`] runs live across the failover; the read-specific assertion (the deposed
    // primary cannot serve a stale read) is deferred to the future read-path step.
    if self.stale_read_axis && self.prng.chance(1, 90) {
      if self.prng.chance(1, 2) {
        // Budget permitting, depose the cluster's SERVING primary (the highest-view normal primary
        // — not a deposed old-view primary that still believes itself primary) if it is a fresh
        // victim (not already crashed, isolated, or one-way-impaired — deposing an already-knocked-out
        // replica would be redundant and double-count the budget).
        if self.knocked_out(c) < self.minority_budget
          && let Some(p) = c
            .serving_primary()
            .filter(|&p| !self.isolated[p] && !self.asym_victims[p])
        {
          self.asym_victims[p] = true;
          let old_view = c.replica_view(p).get();
          let deposed = c.partition_primary_out(p);
          assert!(
            deposed,
            "the budgeted primary {p} must be a live primary the lane actually deposes"
          );
          // Track the probe: the causal witness fires later, when a higher-view serving primary
          // emerges while p remains cut (a heal first abandons it — see `resolve_stale_probe`).
          self.active_stale_probe = Some((p, old_view));
          if trace {
            eprintln!("tick {tick}: STALE-READ depose primary {p}");
          }
        }
      } else if self.asym_victims.iter().any(|&b| b) {
        if trace {
          eprintln!("tick {tick}: HEAL one-way blocks (stale-read)");
        }
        for b in &mut self.asym_victims {
          *b = false;
        }
        // The cut is healed: abandon the probe so a later failover is not mis-attributed to it.
        self.active_stale_probe = None;
        c.heal_one_way();
        self.report.heals += 1;
      }
    }

    // Resolve the in-flight stale-read probe every tick (no PRNG — pure observation of cluster
    // state). A higher-view serving primary emerging while the deposed target stays cut is the
    // causal failover witness; a heal first abandons the probe. Axis-gated, so off-axis is
    // untouched.
    if self.stale_read_axis && self.active_stale_probe.is_some() {
      let target_cut = self
        .active_stale_probe
        .is_some_and(|(t, _)| self.asym_victims[t]);
      let serving = c.serving_primary().map(|p| (p, c.replica_view(p).get()));
      let (next, failed_over) =
        Self::resolve_stale_probe(self.active_stale_probe, target_cut, serving);
      self.active_stale_probe = next;
      if failed_over {
        self.report.stale_read_failovers_observed += 1;
      }
    }

    // (e) SLOW REPLICA (gray failure): degrade ONE replica's delivery for a bounded episode window —
    // every inter-replica message touching its seeded legs (inbound/outbound/both) arrives a few
    // seeded milliseconds LATE, never dropped. NOT a partition and NOT budgeted as knocked out: the
    // replica keeps participating, just consistently behind — the gray zone between healthy and
    // failed that neither the crash nor the partition model expresses. Only with the axis enabled
    // (no draw consumed otherwise, mirroring the hold axis); one episode at a time, expiring at its
    // seeded window end (calm windows and the final quiesce end it early). The `VOPR_NO_SLOW`
    // shrink mask keeps the draws + episode bookkeeping and only skips installing the profile.
    if self.slow_axis {
      if self.slow_active.is_some() && tick >= self.slow_until {
        if trace {
          eprintln!("tick {tick}: SLOW episode expired");
        }
        self.end_slow_episode(c);
      }
      if self.prng.chance(1, 90) && self.slow_active.is_none() {
        let candidates: Vec<usize> = (0..self.node_count).filter(|&i| !c.is_crashed(i)).collect();
        if let Some(v) = self.pick(&candidates) {
          // Legs: 0 ⇒ inbound only (slow to hear), 1 ⇒ outbound only (slow to be heard), 2 ⇒ both.
          let legs = self.prng.below(3);
          // The extra-delay band, in milliseconds: lo in 3..=10, hi = lo + 2..=12 (max 22 ms) —
          // several times the 1 ms base latency yet well under the proto's 50 ms commit-heartbeat /
          // 200 ms idle cadences, so the victim is degraded-but-alive (late acks and heartbeats,
          // never a legitimate knockout the failover machinery OWES a view change for).
          let lo_ms = 3 + self.prng.below(8);
          let hi_ms = lo_ms + 2 + self.prng.below(11);
          // The episode window, in ticks (the chaos-phase length band).
          let window = 60 + self.prng.below(200);
          self.slow_active = Some(v);
          self.slow_until = tick + window;
          if !env_flag("VOPR_NO_SLOW") {
            c.set_slow_replica(
              v,
              Some(crate::network::SlowProfile {
                inbound: legs != 1,
                outbound: legs != 0,
                min_extra: Duration::from_millis(lo_ms),
                max_extra: Duration::from_millis(hi_ms),
              }),
            );
            self.report.slow_episodes += 1;
          }
          if trace {
            eprintln!(
              "tick {tick}: SLOW replica {v} legs={legs} band={lo_ms}..={hi_ms}ms window={window}"
            );
          }
        }
      }
    }

    // (f) LEARNER CHAOS (the liveness-independence axis): crash ONE learner for a sustained window.
    // A learner outage must NEVER reduce voter fault tolerance, so the victim is drawn from the
    // LEARNER range `[voting_count, node_count)` and is NOT charged against `minority_budget` (the
    // `knocked_out`/budget pickers never see it). Meanwhile the calm-window committed-progress
    // assertion must STILL advance using the voters alone — that is the claim this exercises. Only
    // with the axis enabled (a learner-enabled run is its own deterministic baseline; with the axis
    // OFF no draw is consumed, mirroring the hold axis). One episode at a time, a long stretch so the
    // outage spans calm windows where voter progress is owed; the generic restart action, calm-window
    // entry, and the final quiesce can all end it early (each restarts every crashed id), so the
    // expiry only clears bookkeeping if the cluster has not already restarted the learner.
    if self.learner_axis {
      if let Some(l) = self.learner_crashed
        && (tick >= self.learner_crash_until || !c.is_crashed(l))
      {
        if trace {
          eprintln!("tick {tick}: LEARNER-CHAOS episode for learner {l} ended");
        }
        self.end_learner_crash(c);
      }
      if self.prng.chance(1, 80)
        && self.learner_crashed.is_none()
        && self.node_count > self.voting_count
      {
        let candidates: Vec<usize> = (self.voting_count..self.node_count)
          .filter(|&i| !c.is_crashed(i) && !c.is_retired(i))
          .collect();
        if let Some(l) = self.pick(&candidates) {
          // A long outage (a few calm windows wide) so voter progress is genuinely owed while the
          // learner is down — the independence claim is judged across a calm window with the learner
          // crashed throughout.
          let window = 600 + self.prng.below(600);
          c.crash(l);
          self.learner_crashed = Some(l);
          self.learner_crash_until = tick + window;
          if trace {
            eprintln!("tick {tick}: LEARNER-CHAOS crash learner {l} window={window}");
          }
        }
      }
    }
  }

  /// End the active learner-chaos episode: restart the crashed learner if it is still down (the
  /// generic restart action / calm window / final quiesce may have already restarted it) and clear
  /// the bookkeeping. NOT routed through [`Self::restart_and_track`]'s recovered-band sampling caveat:
  /// it simply restores the learner so it rejoins and converges.
  fn end_learner_crash(&mut self, c: &mut Cluster) {
    // `take()` always clears the bookkeeping; the restart runs only if the learner is still down (the
    // generic restart action / calm window / final quiesce may have restarted it already) AND not
    // retired (a reconfiguration could have REMOVED this learner while it was crashed — a retired node
    // is parked, never restarted).
    if let Some(l) = self.learner_crashed.take()
      && c.is_crashed(l)
      && !c.is_retired(l)
    {
      self.restart_and_track(c, l);
    }
    self.learner_crash_until = 0;
  }

  /// Push the current `isolated` set into the cluster as a 2-group partition: isolated replicas →
  /// group 1, the rest (the majority component) → group 0.
  fn apply_partition(&self, c: &mut Cluster) {
    let groups: Vec<u8> = (0..self.node_count)
      .map(|i| u8::from(self.isolated[i]))
      .collect();
    c.partition(groups);
  }

  /// Decide an in-flight stale-read probe's fate from observed state, returning `(next probe, a
  /// failover was observed)`. Pure so the causality is unit-testable. The deposed target must STILL
  /// be cut for any witness — a target no longer cut was healed before its failover, so the cut
  /// cannot have caused the view change (abandoned, no witness, even if a higher-view primary now
  /// exists). With the target still cut, a DIFFERENT serving primary in a strictly higher view is
  /// the causal failover witness (and resolves the probe); otherwise the probe stays pending.
  fn resolve_stale_probe(
    probe: Option<(usize, u64)>,
    target_still_cut: bool,
    serving: Option<(usize, u64)>,
  ) -> (Option<(usize, u64)>, bool) {
    let Some((target, old_view)) = probe else {
      return (None, false);
    };
    if !target_still_cut {
      return (None, false);
    }
    if let Some((p, view)) = serving
      && p != target
      && view > old_view
    {
      return (None, true);
    }
    (probe, false)
  }

  /// The number of VOTING replicas currently knocked out: crashed plus isolated plus one-way victims
  /// (disjoint sets — the pickers exclude each other's members). A one-way victim is budgeted as
  /// knocked out because it cannot complete any round-trip exchange while its episode lasts, so the
  /// connected, fully-bidirectional voting majority must survive WITHOUT it. Counts over the voting
  /// set only: a learner impairment never consumes the voting fault budget.
  fn knocked_out(&self, c: &Cluster) -> usize {
    (0..self.voting_count)
      .filter(|&i| c.is_crashed(i) || self.isolated[i] || self.asym_victims[i])
      .count()
  }

  /// Pick a replica we may crash without breaking the fault budget: not already crashed, not isolated,
  /// not a one-way victim (impairing the same node twice would be redundant and would double-count
  /// the budget), and only if one more knocked-out replica still leaves a majority. Returns `None`
  /// if the budget is exhausted.
  fn pick_crashable(&mut self, c: &Cluster) -> Option<usize> {
    if self.knocked_out(c) >= self.minority_budget {
      return None;
    }
    let candidates: Vec<usize> = (0..self.voting_count)
      .filter(|&i| !c.is_crashed(i) && !self.isolated[i] && !self.asym_victims[i])
      .collect();
    self.pick(&candidates)
  }

  /// Pick a replica we may isolate into the minority without breaking the budget. Same constraints as
  /// [`Self::pick_crashable`] (crashed + isolated + victims must stay ≤ the minority budget).
  fn pick_isolatable(&mut self, c: &Cluster) -> Option<usize> {
    if self.knocked_out(c) >= self.minority_budget {
      return None;
    }
    let candidates: Vec<usize> = (0..self.voting_count)
      .filter(|&i| !c.is_crashed(i) && !self.isolated[i] && !self.asym_victims[i])
      .collect();
    self.pick(&candidates)
  }

  /// Pick the victim of a new one-way episode, within the same minority budget as
  /// [`Self::pick_crashable`]. Half the installs PREFER a current primary among the candidates (the
  /// deaf/mute-primary liveness-killer shapes — a deaf primary's heartbeats keep flowing out while
  /// the acks never arrive, so nothing forces a view change AND nothing commits); the rest draw
  /// uniformly, so backups' one-way shapes (e.g. a deaf backup spamming ever-higher
  /// StartViewChanges the cluster must absorb) stay covered. The bias coin is drawn whenever an
  /// install is attempted, so the stream stays a pure function of the seed.
  fn pick_asym_victim(&mut self, c: &Cluster) -> Option<usize> {
    if self.knocked_out(c) >= self.minority_budget {
      return None;
    }
    let candidates: Vec<usize> = (0..self.voting_count)
      .filter(|&i| !c.is_crashed(i) && !self.isolated[i] && !self.asym_victims[i])
      .collect();
    if candidates.is_empty() {
      return None;
    }
    if self.prng.chance(1, 2) {
      let primaries: Vec<usize> = candidates
        .iter()
        .copied()
        .filter(|&i| c.replica_is_primary(i))
        .collect();
      if let Some(p) = self.pick(&primaries) {
        return Some(p);
      }
    }
    self.pick(&candidates)
  }

  /// Clear every partition, symmetric AND one-way, on both sides of the bookkeeping: the driver's
  /// `isolated`/`asym_victims` sets and the cluster's groups + directed matrix. Every full-heal site
  /// (the heal actions, calm windows, the final quiesce) goes through here so the driver's budget
  /// view can never desync from the cluster's connectivity.
  fn heal_all_partitions(&mut self, c: &mut Cluster) {
    for i in 0..self.node_count {
      self.isolated[i] = false;
      self.asym_victims[i] = false;
    }
    // Abandon any in-flight stale-read probe: its cut is gone, so a later failover cannot be
    // attributed to it (the resolver gates on `target_still_cut`, but clearing here keeps the
    // probe state honest across the calm window, where the resolver does not run).
    self.active_stale_probe = None;
    c.heal();
  }

  /// End the active slow episode, if any: drop the cluster-side delivery profile and the driver-side
  /// bookkeeping. Called at the episode's seeded window end, on calm-window entry, and by the final
  /// quiesce (calm requires prompt delivery).
  fn end_slow_episode(&mut self, c: &mut Cluster) {
    if self.slow_active.take().is_some() {
      c.clear_slow_replicas();
    }
  }

  /// Pick a currently-crashed replica to restart, if any. Excludes a RETIRED node (a reconfiguration
  /// removed it; it is parked crashed-forever and must never be restarted — a restart would recover it
  /// `Retired` and panic).
  fn pick_crashed(&mut self, c: &Cluster) -> Option<usize> {
    let candidates: Vec<usize> = (0..self.node_count)
      .filter(|&i| c.is_crashed(i) && !c.is_retired(i))
      .collect();
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
  #[allow(clippy::too_many_arguments)]
  fn check_invariants(
    &mut self,
    c: &mut Cluster,
    tick: u64,
    dur: &mut DurabilityChecker,
    vm: &mut ViewMonotonicChecker,
    applied_once: &mut AppliedOnceChecker,
    staleness: &mut StalenessChecker,
    bound: &BoundednessChecker,
  ) {
    use crate::checker::CheckResult::Violation;

    // Tell the stateful checkers about any wipe since the last check, BEFORE they observe: the wiped
    // replica's per-replica monotonicity baselines (durable view, checkpoint high-water, durable
    // (epoch, view)) are forfeit with its disk — its fresh superblock honestly reads epoch 0 / view 0
    // / checkpoint 0, which is the amnesia itself, not a checker artifact. Every CLUSTER-level
    // invariant below stays at full strength. (Drained into a local first so the on-driver
    // `epoch_view` checker can be told without a second `&mut self` borrow conflicting with the drain.)
    let wiped: Vec<usize> = self.wiped_pending.drain(..).collect();
    for i in wiped {
      dur.note_wipe(i);
      vm.note_wipe(i);
      self.epoch_view.note_wipe(i);
    }

    // Append-before-ack, observed during the tick we just ran (PrepareOk for a non-durable op).
    if let Some(why) = c.take_append_before_ack_violation() {
      panic!("vopr seed {} tick {tick}: {why}", self.seed);
    }
    // Frame cap: NO legitimate inter-replica message may exceed the transport frame cap. The
    // header-only view-change carriers + the byte-bounded `RepairBatch` keep every peer message
    // at/below `MAX_FRAME_LEN` regardless of body size, so the modelled send-path drop must NEVER fire
    // for the protocol's own traffic — even while large client bodies build a deep uncheckpointed band.
    // A drop here is a REAL bug (a carrier overflowed the frame, or a bound is incomplete), located
    // by seed + tick. (Loosening the cap to pass would mask it.)
    if c.oversized_dropped() > 0 {
      panic!(
        "vopr seed {} tick {tick}: frame-cap: a legitimate inter-replica message exceeded \
         MAX_FRAME_LEN and was oversized-dropped ({} so far) — a view-change/recovery carrier or \
         repair batch overflowed the frame (header-only carriers + windowed repair should keep every \
         peer message sub-cap regardless of body size)",
        self.seed,
        c.oversized_dropped(),
      );
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
    if let Violation(why) = applied_once.observe(c) {
      panic!("vopr seed {} tick {tick}: applied-once: {why}", self.seed);
    }
    // Staleness floor monotonicity (the committed-history high-water never regresses), observed every
    // tick across the stale-read failover — the live value of the staleness oracle in this phase (the
    // read enforcement is vacuous until a read path records reads).
    if let Violation(why) = staleness.observe(c) {
      panic!("vopr seed {} tick {tick}: staleness: {why}", self.seed);
    }
    if let Violation(why) = vm.observe(c) {
      panic!("vopr seed {} tick {tick}: view-monotonic: {why}", self.seed);
    }
    // The split-brain regression net: the durable `(epoch, view)` pair never regresses
    // lexicographically (a view drop is legitimate ONLY when the epoch rose — the per-epoch view reset
    // an epoch transition produces). Observed every tick; it watches the static `(epoch 0, view 0)`
    // lineage the foundation maintains.
    if let Violation(why) = self.epoch_view.observe(c) {
      panic!(
        "vopr seed {} tick {tick}: epoch-view-monotonic: {why}",
        self.seed
      );
    }
    // The configuration lineage fork net: the durable `config_id` history is a single non-forking
    // chain (every successor chains off the recorded current configuration). Observed every tick.
    if let Violation(why) = self.membership.observe(c) {
      panic!(
        "vopr seed {} tick {tick}: membership-monotonic: {why}",
        self.seed
      );
    }
    if let Violation(why) = bound.observe(c) {
      panic!("vopr seed {} tick {tick}: boundedness: {why}", self.seed);
    }
    // Never-primary: NO learner id (`i >= voting_count`) is ever the primary of its view. The
    // proto's `primary(view) = view % replica_count` can only name a VOTER, so a learner-as-primary
    // would be a modulus break that misroutes every client request and prepare. Checked every tick,
    // unconditionally — cheap and on every lane (a learner range is non-empty only under the axis, so
    // off-axis this loop is empty). A violation here is a REAL finding.
    for i in self.voting_count..self.node_count {
      if c.replica_is_primary(i) {
        panic!(
          "vopr seed {} tick {tick}: learner {i} is acting as PRIMARY (view {}) — a non-voting \
           learner must never be primary (primary(view) = view % voting_count names only a voter)",
          self.seed,
          c.replica_view(i).get(),
        );
      }
    }
    // No-learner-emit: a learner never SENT a counted message (PrepareOk/StartViewChange/DoViewChange),
    // observed at schedule time during the tick we just ran. A learner emitting one is a REAL finding
    // (consensus participation by a non-voter); the cluster records it structurally and we drain it here.
    if let Some(why) = c.take_learner_emission_violation() {
      panic!("vopr seed {} tick {tick}: {why}", self.seed);
    }
    self.check_structural(c, tick);
    self.check_ring_residency(c, tick);
  }

  /// Learner CONVERGENCE, asserted once after the final quiesce drain: a non-voting learner FOLLOWS
  /// the committed log the voters agreed on, applying the SAME committed ops in the same order.
  ///
  /// The check is AGREEMENT over the learner's applied prefix: every op the learner has applied equals
  /// the committed history at that position. The reference history is the longest applied `(op, body)`
  /// prefix on any replica — agreement (checked every tick) makes all replicas' applied prefixes
  /// consistent, so the longest IS the committed history — and the learner's prefix must equal it
  /// element-for-element over the learner's length. A mismatch is a learner applying a DIFFERENT
  /// committed op than the voters — a REAL finding.
  ///
  /// This deliberately does NOT require the learner to reach the frontier LENGTH. The sim drives a
  /// continuous sequential client load that does not fully drain within the run + quiesce budget, so
  /// the primary's committed head keeps advancing and a passive learner — which follows commits rather
  /// than voting on them — legitimately trails the head by the in-flight/repair window indefinitely;
  /// requiring an exact length match would assert a moving target that never settles. The LIVENESS
  /// claim that a learner actively follows and catches up is witnessed instead by the sweep's
  /// non-vacuity counters: [`VoprReport::learner_ops_applied`] (it applies committed ops by the
  /// thousand), [`VoprReport::learner_repairs_served`] (it state-syncs to catch up when it falls
  /// behind), and [`VoprReport::learner_view_changes_followed`] (it adopts new views). A no-op with no
  /// learners (the off-axis learner range is empty).
  fn check_learner_convergence(&self, c: &Cluster, ticks: u64) {
    // The committed-history frontier (for the AGREEMENT comparison): the longest applied `(op, body)`
    // prefix on any replica.
    let frontier = (0..self.node_count)
      .max_by_key(|&i| c.replica_sm(i).applied().len())
      .map(|i| c.replica_sm(i).applied().to_vec())
      .unwrap_or_default();
    for i in self.voting_count..self.node_count {
      if c.is_crashed(i) {
        continue; // a crashed learner is powered off — its convergence is asserted on a live one.
      }
      let learner = c.replica_sm(i).applied();
      for (pos, (want, got)) in frontier.iter().zip(learner.iter()).enumerate() {
        if want != got {
          panic!(
            "vopr seed {} tick {ticks} (final, post-quiesce): learner {i} diverges from the \
             committed history at applied position {pos}: learner has {got:?} but the committed \
             history has {want:?} — a learner applied a different committed op than the voters",
            self.seed,
          );
        }
      }
    }
  }

  /// The structural per-replica invariants, read directly off the sim state each tick:
  /// `op >= commit_min >= checkpoint_op` and `commit_max >= commit_min` — but NOT `op >= commit_max`,
  /// since `commit_max` is a re-learnable HINT that may EXCEED the locally-held head (`commit_max > op`
  /// is a legal tail-gap shape: the replica has heard a higher op is committed but has not yet fetched
  /// it). Plus, for the cluster's committed history, that every committed op is durably present on at
  /// least a quorum (WAL `Clean` or `<= checkpoint_op`).
  fn check_structural(&self, c: &Cluster, tick: u64) {
    for i in 0..self.node_count {
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
    let quorum = self.voting_count / 2 + 1;
    // Check the newest committed op (the one most at risk of not yet being durable on a quorum). It
    // is a sound proxy for the whole prefix: a committed op was, at commit time, durably appended on
    // a quorum, and a committed slot stays occupied thereafter — so if the newest committed op is
    // held by a quorum, every older committed op is too. Count holders among VOTERS only: the
    // commit quorum is a voter quorum, so a learner holding the op cannot stand in for a voter.
    let top = committed as u64;
    let holders = (0..self.voting_count)
      .filter(|&i| c.replica_appended_op(i, viewstamp_proto::OpNumber::with(top)))
      .count();
    // The committed-history high-water means at least one replica APPLIED op `top`, which the
    // protocol only does after a quorum durably appended it — so a quorum of occupied holders must
    // persist. A shortfall means a committed op vanished from a quorum's durable medium.
    //
    // WIPES weaken this bound HONESTLY, by exactly the wiped count: a wipe permanently forfeits one
    // replica's durable copies, so a committed op held by a bare quorum can legitimately drop to
    // `quorum - wipes` holders until repair/state-sync re-replicates it (the checker cannot cheaply
    // know when that completes, so the relaxed envelope holds for the rest of the run). The floor is
    // 1: a committed op held durably NOWHERE is an outright loss no fault budget excuses. With the
    // wipe axis off (`wipes_fired == 0` always) this is exactly the strict quorum bound — the base
    // gates are untouched. The end-of-run check (post-quiesce, full committed history applied on an
    // operational replica) stays fully strict on every lane.
    let required = quorum
      .saturating_sub(self.report.wipes_fired as usize)
      .max(1);
    if holders < required {
      panic!(
        "vopr seed {} tick {tick}: committed op {top} is durably held on only {holders} replicas \
         (< required {required} = quorum {quorum} - wipes {}) — a committed op is not retained \
         durably by the surviving quorum",
        self.seed, self.report.wipes_fired
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
  /// e.g. head=1436 over commit_min=1401 — which is repair territory, not a wrap.)
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
    for i in 0..self.node_count {
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
        if c.replica_wal_slot_not_wrapped_away(i, viewstamp_proto::OpNumber::with(op)) {
          continue; // `op` itself is still resident (`Clean`/`Faulty`) or its own append is in flight.
        }
        // `op`'s slot is `Empty`. It is a WRAP only if a strictly-later congruent op `op + m·N` (<= head)
        // is RESIDENT — that op physically occupies slot `op mod N`, having evicted the committed `op`. If
        // no later congruent op is resident, the `Empty` is one of the benign cases (async in-flight /
        // applied-from-cache / sync-pruned-deferred) the doc explains — `recover`/repair handles it.
        let mut y = op + n;
        let mut wrapped_by = None;
        while y <= head {
          if c.replica_wal_holds_op(i, viewstamp_proto::OpNumber::with(y)) {
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
    let logs: Vec<Vec<(u64, Bytes)>> = (0..self.node_count)
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
        "  replica {i}: crashed={} retired={} status={} epoch={} view={} op={} commit_min={} commit_max={} checkpoint_op={} applied_len={}",
        c.is_crashed(i),
        c.is_retired(i),
        c.replica_status_str(i),
        c.replica_durable_epoch(i).get(),
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
    let mv = (0..self.node_count)
      .map(|i| c.replica_view(i).get())
      .max()
      .unwrap_or(0);
    self.report.max_view = self.report.max_view.max(mv);
    // MISDIRECTED-read high-water (summed over replicas' persistent WAL counters). Tracked as a max so
    // a mid-run WAL rebuild (none happens in the VOPR, but defensively) cannot lower it.
    let md: u64 = (0..self.node_count)
      .map(|i| c.wal_misdirects_fired(i))
      .sum();
    self.report.misdirects_fired = self.report.misdirects_fired.max(md);
    // FORCED-sync (peer-fetch escalation) cumulative accumulation. The proto's per-replica counter
    // resets to 0 on `recover` (each restart), so we fold each POSITIVE delta into the running total
    // and always re-baseline `forced_sync_seen` — a reset's downward step then contributes nothing and
    // the next climb from 0 is counted afresh. This makes `forced_syncs` a true run-cumulative count of
    // peer-fetch escalations, robust to the per-restart reset.
    for i in 0..self.node_count {
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
    for i in 0..self.node_count {
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
      // Chunked-transfer completions, same reset-robust positive-delta accumulation (the counter
      // zeroes on `recover`; the focused large_state_sync gate is the asserting oracle — the sweep
      // only reports).
      let transfers = c.replica_sync_chunk_transfers_completed(i);
      if transfers > self.sync_chunk_transfers_seen[i] {
        self.report.sync_chunk_transfers += transfers - self.sync_chunk_transfers_seen[i];
      }
      self.sync_chunk_transfers_seen[i] = transfers;
    }
    // Non-vacuity witnesses: floored canonical unions, served `RepairBatch`es, header-only carriers.
    // All three live on the `Endpoint` and reset to 0 on `recover`, so they use the SAME reset-robust
    // positive-delta accumulation as `forced_syncs` above (a plain high-water would lose a
    // pre-restart burst). The sweeps assert their cross-seed sums are `> 0` (non-vacuity).
    for i in 0..self.node_count {
      let floored = c.replica_unions_floored(i);
      if floored > self.unions_floored_seen[i] {
        self.report.unions_floored += floored - self.unions_floored_seen[i];
      }
      self.unions_floored_seen[i] = floored;
      let served = c.replica_repair_batches_served(i);
      if served > self.repair_batches_served_seen[i] {
        self.report.repair_batches_served += served - self.repair_batches_served_seen[i];
      }
      self.repair_batches_served_seen[i] = served;
      let pbatches = c.replica_prepare_batches_sent(i);
      if pbatches > self.prepare_batches_sent_seen[i] {
        self.report.prepare_batches_sent += pbatches - self.prepare_batches_sent_seen[i];
      }
      self.prepare_batches_sent_seen[i] = pbatches;
      let carriers = c.replica_header_only_carriers_emitted(i);
      if carriers > self.header_only_carriers_seen[i] {
        self.report.header_only_carriers_emitted += carriers - self.header_only_carriers_seen[i];
      }
      self.header_only_carriers_seen[i] = carriers;
      // Session-cap evictions (the churn lane's non-vacuity witness), same reset-robust
      // positive-delta accumulation (the counter zeroes on `recover`).
      let evicted = c.replica_sessions_evicted(i);
      if evicted > self.sessions_evicted_seen[i] {
        self.report.sessions_evicted += evicted - self.sessions_evicted_seen[i];
      }
      self.sessions_evicted_seen[i] = evicted;
    }
    // LEARNER non-vacuity witnesses (the learner lane), accumulated over the learner ids only — a
    // voter slot stays 0. All three use the SAME reset-robust positive-delta accumulation as
    // `forced_syncs`: a `recover` rebuilds the `Endpoint` (resetting the applied log, the view to the
    // durable view, and the state-sync counter), so a plain high-water would miss a pre-restart climb;
    // re-baselining each tick and folding positive deltas counts each climb-from-its-base. Off-axis the
    // learner range is empty, so every counter stays 0 — the default report digest is unperturbed.
    for i in self.voting_count..self.node_count {
      // Committed ops APPLIED on the learner (it follows the committed log). `applied().len()` is the
      // SM's applied-history length, which the recover re-applies from the durable checkpoint.
      let applied = c.replica_sm(i).applied().len();
      if applied > self.learner_applied_seen[i] {
        self.report.learner_ops_applied += (applied - self.learner_applied_seen[i]) as u64;
      }
      self.learner_applied_seen[i] = applied;
      // State-syncs the learner COMPLETED (it caught up from behind via the repair/state-sync path).
      let synced = c.replica_state_sync_count(i);
      if synced > self.learner_repairs_seen[i] {
        self.report.learner_repairs_served += synced - self.learner_repairs_seen[i];
      }
      self.learner_repairs_seen[i] = synced;
      // View advances the learner FOLLOWED (it adopted a higher view via `GetView`). `replica_view`
      // is monotone within an incarnation and recovers to the durable view on restart.
      let view = c.replica_view(i).get();
      if view > self.learner_view_seen[i] {
        self.report.learner_view_changes_followed += view - self.learner_view_seen[i];
      }
      self.learner_view_seen[i] = view;
    }
    // Torn-header probe witness (summed over the persistent WALs, high-water like `misdirects_fired`
    // so a storage rebuild can never lower it). Stays 0 with the axis off.
    let th: u64 = (0..self.node_count)
      .map(|i| c.wal_torn_headers_fired(i))
      .sum();
    self.report.torn_headers_fired = self.report.torn_headers_fired.max(th);
    // Genuine-WRAP witness: a BOUNDED seed whose committed history exceeded its ring size `N` has had an
    // op `K + N` physically reuse op `K`'s slot — the ring truly wrapped (not merely filled). Latches
    // once true. Trivially false on an unbounded seed (`wal_capacity` is `None`).
    if let Some(n) = self.wal_capacity
      && (self.report.max_committed as u64) > n
    {
      self.report.bounded_seed_wrapped = true;
    }
    // Frame-cap axis high-waters: how many LARGE bodies the clients have minted (non-vacuity — the cap
    // must be exercised), and how many inter-replica messages the network has oversized-dropped (which
    // must stay 0 for legitimate traffic — the per-tick check in `run_vopr` already asserts this; the
    // report carries the cumulative count for the sweep summary). Both are monotone, so `max` is exact.
    let large: u64 = (0..c.client_count())
      .map(|i| c.client(i).large_bodies_sent())
      .sum();
    self.report.large_bodies_sent = self.report.large_bodies_sent.max(large);
    self.report.oversized_dropped = self.report.oversized_dropped.max(c.oversized_dropped());
    // Hold-axis witness: how many messages the network has HELD so far. Monotone on the cluster (the
    // cluster struct persists across replica crash/restart and nothing resets it), so `max` is exact.
    // Stays 0 with the axis disabled; the hold sweep asserts the cross-seed sum is `> 0`.
    self.report.holds_fired = self.report.holds_fired.max(c.holds_fired());
    // Asym/slow-axis deep witnesses: the cluster's monotone one-way-drop and slow-delay counters
    // (same discipline as `holds_fired` — nothing resets them, so `max` is exact). Both stay 0 with
    // their axes disabled; the asym/slow sweeps assert their cross-seed sums are `> 0`, proving an
    // episode genuinely intersected live traffic rather than merely being installed.
    self.report.one_way_dropped = self.report.one_way_dropped.max(c.one_way_dropped());
    self.report.slow_delays = self.report.slow_delays.max(c.slow_delays_applied());
    // Stale-read witness: the cluster's monotone primary-deposition counter (nothing resets it, so
    // `max` is exact). 0 with the axis off; the stale-read sweep asserts the cross-seed sum is `> 0`.
    self.report.stale_read_probes_fired = self
      .report
      .stale_read_probes_fired
      .max(c.stale_read_probes_fired());
    // Batching-axis witnesses: each batching client's counters are monotone over the run (client
    // models persist across replica crash/restart and nothing resets them — the `holds_fired`
    // discipline), so the cross-client sums are monotone too and `max` folds them exactly. All 0
    // with the axis off (plain clients report zeros).
    let (mut multi, mut groups, mut max_units) = (0u64, 0u64, 0u64);
    for i in 0..c.client_count() {
      multi += c.client(i).bodies_with_multiple_units();
      groups += c.client(i).groups_submitted();
      max_units = max_units.max(c.client(i).max_units_per_body());
    }
    self.report.bodies_with_multiple_units = self.report.bodies_with_multiple_units.max(multi);
    self.report.groups_submitted = self.report.groups_submitted.max(groups);
    self.report.max_units_per_body = self.report.max_units_per_body.max(max_units);
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

#[cfg(test)]
mod tests {
  use super::Vopr;

  // The causal stale-read witness fires ONLY on an observed probe-induced failover, never on a bare
  // cut and never after a heal-before-failover — so the lane's non-vacuity cannot be satisfied
  // without exercising a completed deposed-primary failover window.
  #[test]
  fn resolve_stale_probe_distinguishes_failover_from_heal() {
    // No probe in flight: nothing to resolve.
    assert_eq!(Vopr::resolve_stale_probe(None, false, None), (None, false));

    // A DIFFERENT serving primary in a strictly higher view while the target is still cut: the
    // probe-induced failover — the witness fires and the probe resolves.
    assert_eq!(
      Vopr::resolve_stale_probe(Some((0, 0)), true, Some((1, 1))),
      (None, true),
      "a higher-view serving primary while the target is cut is the failover witness"
    );

    // The regression: a heal BEFORE any failover (target no longer cut, no higher-view primary yet)
    // abandons the probe WITHOUT a witness — a cut undone before it forced a view change must not
    // count.
    assert_eq!(
      Vopr::resolve_stale_probe(Some((0, 0)), false, None),
      (None, false),
      "a heal before any failover abandons the probe with no witness"
    );

    // Still pending: the target is cut, but no higher-view serving primary has emerged yet (election
    // ongoing, or only the same/lower view present).
    assert_eq!(
      Vopr::resolve_stale_probe(Some((0, 0)), true, None),
      (Some((0, 0)), false),
      "an election window leaves the probe pending"
    );
    assert_eq!(
      Vopr::resolve_stale_probe(Some((0, 5)), true, Some((1, 5))),
      (Some((0, 5)), false),
      "a same-view primary is not the awaited higher-view failover"
    );

    // A target HEALED before the failover never counts, even if a higher-view serving primary now
    // exists — the cut was undone before it could cause the view change, so attributing the
    // failover to the probe would be non-causal (the calm-window-heal path the witness must
    // exclude).
    assert_eq!(
      Vopr::resolve_stale_probe(Some((0, 0)), false, Some((1, 2))),
      (None, false),
      "a higher-view primary after the cut was healed is not a probe-caused failover"
    );
  }
}

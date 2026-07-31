//! Safety / agreement checks over a cluster run.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use bytes::Bytes;
use smol_str::SmolStr;
use viewstamp_proto::{Instant, MembershipChanged, OpNumber};

use crate::cluster::{AppliedEvent, Cluster};

/// Outcome of checking a cluster's invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
  /// All checked invariants hold.
  Ok,
  /// An invariant was violated, with a human-readable reason.
  Violation(SmolStr),
}

impl CheckResult {
  /// Constructs a [`Self::Violation`] from any string-ish reason (`&str` / `String` / `SmolStr`).
  #[inline]
  pub fn violation(reason: impl Into<SmolStr>) -> Self {
    Self::Violation(reason.into())
  }

  /// True iff all invariants held.
  pub const fn is_ok(&self) -> bool {
    matches!(self, Self::Ok)
  }

  /// True iff an invariant was violated.
  pub const fn is_violation(&self) -> bool {
    matches!(self, Self::Violation(_))
  }
}

/// Checks the M1 safety invariants:
/// 1. **Contiguity/uniqueness** — each replica's applied ops are the `1,2,3,…` op-number sequence
///    with the committed `Reconfigure` op numbers REMOVED (a `Reconfigure` op is committed + assigned
///    an op number but is consensus-layer, never applied to the state machine, so its op number is
///    legitimately absent from `applied()` — every replica skips the SAME numbers, so the applied
///    sequence stays a gap-free walk of the non-reconfigure op numbers, with no duplicate).
/// 2. **Agreement** — every replica's applied `(op, body)` sequence is a prefix of the LONGEST one
///    (full content comparison, not just op numbers). Reconfigure ops are uniformly absent on every
///    replica, so the applied sequences still agree element-for-element.
/// 3. **Client safety** — each client's replies are for strictly increasing request numbers `1..=n`.
/// 4. **Medium integrity** — delegated to [`check_medium_integrity`]: every replica's durable root
///    names a checkpoint envelope its own store holds. Folded in here so every lane that asks the
///    per-tick safety question asks the medium one too.
pub fn check_safety(cluster: &Cluster) -> CheckResult {
  // The committed `Reconfigure` op numbers — absent from every replica's applied stream, so the
  // expected applied op number at each position SKIPS them. Empty on a run that never reconfigures, so
  // the contiguity check below reduces to the plain `op == position + 1`.
  let reconfigure_ops = cluster.committed_reconfigure_ops();
  let mut logs: Vec<Vec<(u64, Bytes)>> = Vec::new();
  for i in 0..cluster.replica_count() {
    let applied: Vec<(u64, Bytes)> = cluster.replica_sm(i).applied().to_vec();
    // Walk the expected op-number sequence, skipping committed reconfigure op numbers: position `idx`
    // must carry the `(idx+1)`-th op number that is not a reconfigure op.
    let mut expected = 0u64;
    for (idx, (op, _)) in applied.iter().enumerate() {
      expected += 1;
      while reconfigure_ops.contains(&expected) {
        expected += 1;
      }
      if *op != expected {
        return CheckResult::violation(format!(
          "replica {i}: applied op {op} at position {idx} (expected {expected}, skipping committed \
           reconfigure ops {reconfigure_ops:?})"
        ));
      }
    }
    logs.push(applied);
  }
  if let v @ CheckResult::Violation(_) = check_agreement(&logs) {
    return v;
  }
  for i in 0..cluster.client_count() {
    for (idx, (rn, _)) in cluster.client(i).replies().iter().enumerate() {
      if *rn != (idx as u64) + 1 {
        return CheckResult::violation(format!(
          "client {i}: reply for request {rn} at position {idx} (expected {})",
          idx + 1
        ));
      }
    }
  }
  check_medium_integrity(cluster)
}

/// Checks **medium integrity**: every replica's durable root names a checkpoint envelope its own
/// store actually holds — the stored generation at the root's `checkpoint_op` exists and its bytes
/// hash to the root's `checkpoint_id` (vacuously true while no checkpoint is rooted). A
/// `Violation` is the self-poisoned medium: with no injected fault anywhere, recovery's placement
/// and content-address verification cannot succeed from local disk, so a solo replica cannot
/// recover and a cluster escalates to a needless peer fetch.
///
/// This predicate asks about the IDENTITY of what the store retains; the boundedness checker's
/// generation arm asks about the SIZE of what it retains. The two are independent: a collector
/// that keeps the wrong generations can delete the one the next monotone root names while the
/// retained count stays constant — green on the count bound, poisoned on this one. Folded into
/// [`check_safety`] so every per-tick lane asks both; pure reads over the medium, so observing it
/// perturbs no schedule.
pub fn check_medium_integrity(cluster: &Cluster) -> CheckResult {
  for i in 0..cluster.replica_count() {
    if !cluster.sb_root_names_stored_checkpoint(i) {
      return CheckResult::violation(format!(
        "replica {i}: the durable root's (checkpoint_op, checkpoint_id) pair names no checkpoint \
         envelope its own store holds — the medium self-poisoned: local recovery would reject its \
         own checkpoint and force a peer fetch with no fault injected anywhere"
      ));
    }
  }
  CheckResult::Ok
}

/// The cross-replica AGREEMENT comparison: every applied `(op, body)` log must be a content prefix of
/// the LONGEST one. Pure over its inputs so the comparison is unit-testable without a live `Cluster`.
///
/// The canonical log is the LONGEST, not replica 0's. Comparing every log against replica 0 truncates
/// each comparison to replica 0's length, so a divergence between two OTHER replicas past that length
/// is invisible: with applied logs `[A]`, `[A,B]`, `[A,C]` both comparisons run over one element,
/// both pass, and the `B` vs `C` divergence at position 1 goes unseen. The longest log covers every
/// position any replica has applied, so a prefix comparison against it can hide no divergence.
fn check_agreement(logs: &[Vec<(u64, Bytes)>]) -> CheckResult {
  let Some((canonical, longest)) = logs.iter().enumerate().max_by_key(|(_, log)| log.len()) else {
    return CheckResult::Ok;
  };
  for (i, log) in logs.iter().enumerate() {
    if i == canonical {
      continue;
    }
    let n = log.len().min(longest.len());
    if log[..n] != longest[..n] {
      // Pinpoint the first diverging position for the audit: which op, and the two bodies.
      let pos = (0..n).find(|&p| log[p] != longest[p]).unwrap_or(0);
      let (op, body) = &log[pos];
      let (cop, cbody) = &longest[pos];
      return CheckResult::violation(format!(
        "replica {i} diverges from the longest applied log (replica {canonical}) at applied position \
         {pos}: replica {i} has ({op},{body:?}) but replica {canonical} has ({cop},{cbody:?})"
      ));
    }
  }
  CheckResult::Ok
}

/// Stateful **durability** checker: every committed op survives crash + storage-fault + restart.
///
/// `check_safety` proves agreement *at one instant*; this checker proves it *across time*, including
/// a crash + restart window. It maintains the cluster's **committed history** — the longest applied
/// `(op, body)` prefix ever observed on any replica (monotonically extended) — and on each
/// [`observe`](Self::observe) enforces, for every replica:
///
/// 1. **No committed op is ever rewritten** — a replica's applied log must agree (content) with the
///    committed history on their common prefix. (The across-time strengthening of `check_safety`: a
///    recovery that re-applied a *different* body for a committed op trips here.)
/// 2. **`checkpoint_op` is monotone non-decreasing** per replica (a durable checkpoint never goes
///    backwards — it is a committed+applied watermark).
///
/// [`check`](Self::check) then enforces the no-loss property: the committed history must still be
/// **fully present on at least one operational, non-crashed replica** — i.e. recovery never lost a
/// committed op cluster-wide. (A lagging or still-catching-up recovered replica is allowed to be
/// *behind* the committed history, as long as some replica still holds it — what matters is that the
/// op survived *somewhere*, which is exactly the durability guarantee a quorum provides.)
#[derive(Debug)]
pub struct DurabilityChecker {
  /// The longest applied `(op, body)` prefix ever observed (the committed history high-water).
  committed: Vec<(u64, Bytes)>,
  /// Per-replica high-water of `checkpoint_op` (monotonicity guard).
  checkpoint_hw: Vec<u64>,
  /// Slots a reconfiguration REMOVED from the membership (recovered `Retired` and parked). A removed
  /// slot drops from the survivor scan in [`check`](Self::check): it is no longer a member, so its
  /// frozen applied log must NOT be required to still retain the committed history (that obligation
  /// rests on the SURVIVING members). The committed history itself is kept as-is across the straddle —
  /// `observe` still folds the removed slot's frozen log into the no-rewrite check (a removed node may
  /// never read back a DIFFERENT body for a committed op it held), so removal weakens only the
  /// "who must still hold it" obligation, never the "it was never rewritten" one.
  removed: HashSet<usize>,
}

impl DurabilityChecker {
  /// A durability checker for a cluster of `replica_count` replicas.
  pub fn new(replica_count: usize) -> Self {
    Self {
      committed: Vec::new(),
      checkpoint_hw: vec![0; replica_count],
      removed: HashSet::new(),
    }
  }

  /// Folds one set of per-replica applied logs + checkpoint-ops into the committed history, returning
  /// a violation on a rewritten committed op or a regressed checkpoint. Pure over its inputs so the
  /// monotonicity logic is unit-testable without a live `Cluster`.
  fn fold(&mut self, applied: &[Vec<(u64, Bytes)>], checkpoint_ops: &[u64]) -> CheckResult {
    for (i, a) in applied.iter().enumerate() {
      // (1) No committed op rewritten: agree with the committed history on the common prefix.
      let n = a.len().min(self.committed.len());
      if a[..n] != self.committed[..n] {
        // Pinpoint the first diverging op for the audit: which committed op, and the two bodies.
        let pos = (0..n).find(|&p| a[p] != self.committed[p]).unwrap_or(0);
        let (cop, cbody) = &self.committed[pos];
        let (aop, abody) = &a[pos];
        return CheckResult::violation(format!(
          "replica {i}: applied prefix diverges from the committed history at op {cop} (a committed \
           op was rewritten/lost across time): committed=({cop},{cbody:?}) replica=({aop},{abody:?})"
        ));
      }
      // Extend the committed history if this replica is strictly ahead (and agrees on the prefix).
      if a.len() > self.committed.len() {
        self.committed = a.clone();
      }
    }
    for (i, &cp) in checkpoint_ops.iter().enumerate() {
      if cp < self.checkpoint_hw[i] {
        return CheckResult::violation(format!(
          "replica {i}: checkpoint_op regressed to {cp} (was {})",
          self.checkpoint_hw[i]
        ));
      }
      self.checkpoint_hw[i] = cp;
    }
    CheckResult::Ok
  }

  /// Record that replica `i`'s durable storage was WIPED ([`Cluster::wipe_and_restart`]): its
  /// per-replica `checkpoint_op` monotonicity baseline is forfeit with the disk (the replica
  /// legitimately restarts at checkpoint 0 — its OWN pre-wipe durable state is gone, which is not by
  /// itself a violation under the `<= f` lost-state budget). The CLUSTER-level guarantees are
  /// deliberately NOT relaxed: the committed history is kept as-is, so the wiped replica's re-applied
  /// prefix must still agree with it (a divergent re-application — the amnesia hazard breaking quorum
  /// intersection — still trips [`observe`](Self::observe)), and [`check`](Self::check) still demands
  /// the full history survive on an operational replica.
  pub fn note_wipe(&mut self, i: usize) {
    self.checkpoint_hw[i] = 0;
  }

  /// Record that slot `i` was REMOVED by an offline reconfiguration (it recovered `Retired` and is
  /// parked, no longer a member). A removed slot is dropped from the survivor scan in
  /// [`check`](Self::check) — the committed history must survive on the SURVIVING members, never on a
  /// node the configuration retired (whose applied log is frozen at its pre-removal prefix). The
  /// committed history is NOT relaxed: the removed slot's frozen log is still folded by `observe`
  /// (a removed node may not read back a different body for a committed op), so the no-rewrite and
  /// cluster-wide-survival invariants both hold across the straddle — only the removed node itself is
  /// excused from being a required holder.
  pub fn note_removed(&mut self, i: usize) {
    self.removed.insert(i);
  }

  /// Sample the cluster: update the committed history and return a violation if any replica rewrote a
  /// committed op or regressed its `checkpoint_op`. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let applied: Vec<Vec<(u64, Bytes)>> = (0..cluster.replica_count())
      .map(|i| cluster.replica_sm(i).applied().to_vec())
      .collect();
    let checkpoint_ops: Vec<u64> = (0..cluster.replica_count())
      .map(|i| cluster.replica_checkpoint_op(i).get())
      .collect();
    self.fold(&applied, &checkpoint_ops)
  }

  /// Final durability assertion: the full committed history must still be present on at least one
  /// operational, non-crashed replica — proving no committed op was lost across crash + storage-fault
  /// + restart. (Returns `Ok` vacuously if nothing was ever committed.)
  pub fn check(&self, cluster: &Cluster) -> CheckResult {
    if self.committed.is_empty() {
      return CheckResult::Ok;
    }
    let survived = (0..cluster.replica_count()).any(|i| {
      // A reconfiguration-removed slot is no longer a member — its frozen pre-removal log cannot
      // stand in for a survivor (and must not be REQUIRED to retain the full history). Survival rests
      // on the configuration's surviving members.
      !self.removed.contains(&i)
        && !cluster.is_crashed(i)
        && cluster.replica_status_is_operational(i)
        && cluster.replica_sm(i).applied().len() >= self.committed.len()
        && cluster.replica_sm(i).applied()[..self.committed.len()] == self.committed[..]
    });
    if survived {
      CheckResult::Ok
    } else {
      CheckResult::violation(format!(
        "no operational replica retains the committed history of {} ops — a committed op was lost \
         across crash + storage-fault + restart",
        self.committed.len()
      ))
    }
  }
}

/// One replica's DURABLE evidence for the durable-quorum fold: the configuration it is running under
/// and the reach of its own durable storage.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableEvidence {
  /// The replica's durable (superblock) configuration epoch.
  epoch: u64,
  /// The replica indices occupying that configuration's VOTING slots. Read off the durable membership
  /// itself, so ONE observation names the WHOLE voting set: a set accumulated replica-by-replica would
  /// understate the voters an op may be held by while the cluster is mid-transition (a voter that has
  /// not yet installed the successor is still one of its voters), and an understated voter set
  /// under-counts holders. Empty on a root that carries no membership.
  voters: Vec<usize>,
  /// How many VOTING slots that configuration has — the quorum denominator. It is the configuration's
  /// own `replica_count`, not the number of `voters` resolved above, so a voting slot held by a member
  /// id that names no simulated node still counts toward the quorum it is owed.
  voter_count: usize,
  /// The replica's durable checkpoint op: every committed op at or below it is folded into its
  /// snapshot, so the snapshot — not a WAL slot — retains it.
  checkpoint_op: u64,
}

/// One configuration in the durable-quorum checker's own epoch ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigView {
  /// The replica indices occupying the configuration's VOTING slots.
  voters: Vec<usize>,
  /// The number of voting slots — the quorum denominator.
  voter_count: usize,
}

impl ConfigView {
  /// The configuration's commit quorum: a strict majority of its voting slots.
  const fn quorum(&self) -> usize {
    self.voter_count / 2 + 1
  }
}

/// Stateful **durable-quorum** checker: EVERY committed op — not merely the newest — stays durably
/// held by a quorum of the configuration that owes it, every tick.
///
/// Where [`DurabilityChecker`] proves no committed op is rewritten or lost cluster-wide, this checker
/// proves the stronger retention property VSR's recovery rests on: a committed op is never absent from
/// a QUORUM's durable medium. It is built from three ledgers, each folded on every
/// [`observe`](Self::observe):
///
/// 1. **The committed ledger** — the real committed op NUMBERS, from the applied `(op, body)` streams
///    (which carry the true op number) UNIONED with [`Cluster::committed_reconfigure_ops`]. A
///    `Reconfigure` op is a consensus-layer op: committed and assigned an op number but never applied
///    to the state machine, so its number is absent from every applied stream while it occupies a WAL
///    slot under the same retention obligation. The applied LENGTH is therefore not an op number once
///    a reconfiguration has committed — it is strictly below the committed frontier — so the ledger
///    tracks numbers, never lengths. It is monotone: an op number admitted as committed is never
///    retracted, only DISCHARGED (below).
/// 2. **The configuration ledger** — `epoch -> voting set`, recorded from what each replica's DURABLE
///    membership says. The quorum an op is owed is the LIVE configuration's, never the static genesis
///    voter count, which a promotion or a demotion makes wrong in both directions. A configuration
///    counts as INSTALLED once a quorum of its own voters hold it durably; that latches, and the
///    highest installed epoch is the tip.
/// 3. **The discharge floor** — the only thing that ends an op's WAL-residency obligation is QUORUM
///    CHECKPOINT SUBSUMPTION: once a quorum of the owed configuration's voters have `checkpoint_op >=
///    op`, the op lives in their durable snapshots and is permanently satisfied. Checkpoints subsume
///    prefixes, so this is a monotone floor, and dropping everything at or below it is what keeps the
///    per-tick work proportional to the un-checkpointed window rather than to the whole run.
///
/// An op is HELD by a replica iff its WAL slot is occupied (`Clean` or `Faulty` — a committed slot is
/// never dropped by prune/truncate, and bit-rot does not un-occupy it) or it is folded into that
/// replica's durable checkpoint. Both clauses are read off the MEDIUM, so a replica whose disk was
/// wiped holds nothing until it genuinely re-establishes durable state. Holders are counted among
/// VOTERS only: the commit quorum is a voter quorum, so a learner holding the op cannot stand in for
/// a voter.
#[derive(Debug)]
pub struct DurableQuorumChecker {
  /// The committed ops still under active obligation. Ops at or below [`Self::discharged`] are absent
  /// — permanently satisfied, not retracted.
  tracked: BTreeSet<u64>,
  /// Every committed op at or below this is permanently satisfied by quorum checkpoint subsumption.
  discharged: u64,
  /// The highest APPLIED op number folded so far — the cursor that keeps admission proportional to the
  /// newly applied tail instead of re-scanning the whole applied history each tick.
  applied_frontier: u64,
  /// The configuration ledger: `epoch -> the configuration that epoch installed`.
  configs: BTreeMap<u64, ConfigView>,
  /// The highest epoch observed installed on a quorum of its OWN voters. Latched: an op's obligation
  /// moves to the successor the moment the successor reaches a quorum, and never moves back.
  installed: u64,
  /// What each durable-storage WIPE forfeited: `replica -> the ops its durable medium held at the
  /// instant the disk was emptied`. Keyed by replica, so repeated wipes of one node union into one
  /// entry — a single disk can only ever cost a single holder.
  wipes: BTreeMap<usize, BTreeSet<u64>>,
}

impl DurableQuorumChecker {
  /// A durable-quorum checker for a cluster that starts in its genesis configuration (epoch 0).
  pub fn new() -> Self {
    Self {
      tracked: BTreeSet::new(),
      discharged: 0,
      applied_frontier: 0,
      configs: BTreeMap::new(),
      installed: 0,
      wipes: BTreeMap::new(),
    }
  }

  /// Record that replica `i`'s durable storage was WIPED ([`Cluster::wipe_and_restart`]), capturing
  /// WHAT the disk was holding as it went: `held(op)` reports whether replica `i`'s durable medium
  /// retains `op`, and `reach` bounds the op numbers worth asking about (no medium holds anything
  /// above the cluster's highest assigned op).
  ///
  /// It must be called BEFORE the disk is replaced. The evidence exists only while the medium does,
  /// and it is the whole basis of the concession: a wipe forfeits the copies that were on THAT disk at
  /// THAT instant, so those are exactly the copies the retention envelope relaxes for — never one the
  /// wipe could not have taken.
  ///
  /// Recording the ops themselves rather than a moment in time is what makes the concession honest in
  /// both directions. A durable append PRECEDES the commit that rests on it, by however long the
  /// acknowledgement takes to arrive, so an op can reach its durable quorum before a wipe and be
  /// declared committed well after it — timing the concession by the commit would deny a copy the disk
  /// demonstrably held. Equally, an op that never reached this disk earns nothing from its loss, no
  /// matter when it committed.
  ///
  /// The concession is scoped two further ways, and a wipe that meets none of the three concedes
  /// nothing at all:
  ///
  /// - by IDENTITY and MEMBERSHIP — only a wipe of a replica that VOTES in the configuration an op is
  ///   owed removed a holder that op's obligation was counting. Holders are counted among that
  ///   configuration's voters, so an emptied learner, an emptied non-member, and an emptied node the
  ///   owed configuration retired all cost the count nothing;
  /// - by the FLOOR — the relaxed requirement never falls below one holder. A committed op held
  ///   durably NOWHERE is an outright loss no fault budget excuses.
  ///
  /// That bound is the ONLY concession a wipe earns. The wiped replica itself is not counted as a
  /// holder and does not raise the discharge floor: [`Cluster::replica_checkpoint_op`] and
  /// [`Cluster::replica_appended_op`] report an emptied disk as holding nothing, so the evidence side
  /// stays honest. Conceding the same physical fact twice — once by lowering the bound and again by
  /// crediting a phantom holder — would cost the oracle a second replica the wipe never took.
  pub fn note_wipe(&mut self, i: usize, reach: u64, held: &dyn Fn(u64) -> bool) {
    self
      .wipes
      .entry(i)
      .or_default()
      .extend((1..=reach).filter(|&op| held(op)));
  }

  /// Fold one tick of durable evidence into the three ledgers and assert the retention obligation for
  /// every tracked committed op. Pure over its inputs so the ledger + quorum logic is unit-testable
  /// without a live `Cluster`: `evidence[i]` is replica `i`'s durable configuration + checkpoint,
  /// `committed` names committed op numbers observed this tick (any order, repeats harmless), and
  /// `held(i, op)` reports whether replica `i`'s WAL slot for `op` is occupied.
  fn fold(
    &mut self,
    evidence: &[DurableEvidence],
    committed: &[u64],
    held: &dyn Fn(usize, u64) -> bool,
  ) -> CheckResult {
    // (1) The configuration ledger. Each observation names a whole voting set, so a configuration is
    // complete the first time ANY replica is seen holding it; a root carrying no membership names no
    // configuration. Per-epoch uniqueness (no two configurations at one epoch) is the
    // `MembershipMonotonicChecker`'s / `ConfigLineageChecker`'s invariant, so this only records.
    for e in evidence {
      if e.voter_count == 0 {
        continue;
      }
      self.configs.entry(e.epoch).or_insert_with(|| ConfigView {
        voters: e.voters.clone(),
        voter_count: e.voter_count,
      });
    }
    // (2) The installed tip: a configuration is installed once a quorum of its OWN voters hold it
    // durably. The durable epoch is monotone, so a replica at or beyond epoch `E` installed `E` on its
    // way — hence `epoch >= E` rather than `== E`, which would need the sample to land inside the
    // window where a quorum sits exactly at `E`.
    let mut tip = self.installed;
    for (&epoch, cfg) in self.configs.range((self.installed + 1)..) {
      let installed_on = cfg
        .voters
        .iter()
        .filter(|&&i| evidence.get(i).is_some_and(|e| e.epoch >= epoch))
        .count();
      if installed_on >= cfg.quorum() {
        tip = tip.max(epoch);
      }
    }
    self.installed = tip;
    // (3) Admit newly observed committed ops. An op at or below the discharged floor is already
    // permanently satisfied, so it is not re-admitted (the ledger drops nothing it has not
    // discharged).
    for &op in committed {
      if op > self.discharged {
        self.tracked.insert(op);
      }
    }
    // (4) Discharge by quorum checkpoint subsumption: once a quorum of the owed configuration's voters
    // have folded an op into their durable checkpoints, its retention no longer rests on any WAL slot.
    // A checkpoint subsumes its whole prefix, so the discharge is a monotone FLOOR — the quorum-th
    // largest checkpoint — and everything at or below it leaves active tracking.
    if let Some(cfg) = self.configs.get(&self.installed) {
      let quorum = cfg.quorum();
      let mut checkpoints: Vec<u64> = cfg
        .voters
        .iter()
        .filter_map(|&i| evidence.get(i).map(|e| e.checkpoint_op))
        .collect();
      if checkpoints.len() >= quorum {
        checkpoints.sort_unstable_by(|a, b| b.cmp(a));
        self.discharged = self.discharged.max(checkpoints[quorum - 1]);
        self.tracked = self.tracked.split_off(&(self.discharged + 1));
      }
    }
    // (5) The retention obligation, for EVERY tracked committed op — not merely the newest. The
    // newest-op-only form rests on "a committed op was durably appended on a quorum at commit time and
    // a committed slot stays occupied", which makes older ops a corollary of the newest one; that
    // corollary is exactly what a lost interior op breaks, so it is asserted per op instead.
    //
    // Every tracked op is owed the INSTALLED TIP's quorum — one configuration for the whole tracked
    // window, not a per-op attribution. That IS the rule "an op committed under configuration E is
    // owed E's quorum until the successor is installed on a quorum, and the successor's from then on":
    // the tip is E for exactly as long as no successor has reached a quorum, and it is the successor
    // from the moment one has. The rule mirrors the protocol's own durability witness — a shrink
    // commits only once the op is held by a quorum of the predecessor AND a quorum of the retained
    // successor — so the oracle demands neither more than the protocol guarantees nor less.
    let Some((_, cfg)) = self.configs.range(..=self.installed).next_back() else {
      return CheckResult::Ok;
    };
    let quorum = cfg.quorum();
    // WIPES weaken this bound HONESTLY, and only for the copies they actually took. The deduction for
    // an op counts the replicas that BOTH vote in the configuration this op is owed AND were holding
    // this very op when their disk was emptied. A wipe failing either test concedes NOTHING: a
    // non-voter's copy was never counted among the holders below, so its loss removes none, and an op
    // that never reached the emptied medium lost nothing to it. A blanket per-replica discount instead
    // relaxes the requirement for ops no wipe could have touched — which is the very failure this
    // obligation exists to catch.
    //
    // Reading the forfeited ops off the medium is also what keeps the concession from being denied
    // where it is due. A durable append PRECEDES the commit resting on it by the flight time of the
    // acknowledgement, so an op can reach its durable quorum before a wipe and be declared committed
    // after it; timing the deduction by the commit would refuse a copy the disk demonstrably held.
    //
    // The concession then holds for the rest of the run: the checker cannot cheaply know when
    // repair/state-sync re-replicates what the disk took. The floor is 1 — a committed op held durably
    // NOWHERE is an outright loss no fault budget excuses. With the wipe axis off (no wipes at all)
    // this is exactly the strict quorum bound, so the base gates are untouched. The end-of-run check
    // (post-quiesce, full committed history applied on an operational replica) stays fully strict on
    // every lane.
    //
    // The wipe is conceded HERE and only here. On the evidence side a wiped replica reports an empty
    // disk — no occupied slot, no subsuming checkpoint — so it is counted in neither the holders
    // below nor the discharge floor above. Relaxing the bound AND crediting the wiped replica as a
    // holder would spend the same fault twice, leaving the obligation a full replica weaker than the
    // wipe budget actually buys.
    for &op in &self.tracked {
      let conceded = self
        .wipes
        .iter()
        .filter(|(replica, forfeited)| cfg.voters.contains(replica) && forfeited.contains(&op))
        .count();
      let required = quorum.saturating_sub(conceded).max(1);
      let holders = cfg
        .voters
        .iter()
        .filter(|&&i| held(i, op) || evidence.get(i).is_some_and(|e| e.checkpoint_op >= op))
        .count();
      if holders < required {
        return CheckResult::violation(format!(
          "committed op {op} (owed epoch {}'s quorum) is durably held on only {holders} voters (< \
           required {required} = quorum {quorum} - {conceded} of its voters wiped while holding op \
           {op}) — a committed op is not retained durably by the surviving quorum",
          self.installed
        ));
      }
    }
    CheckResult::Ok
  }

  /// Sample the cluster: fold this tick's durable evidence and newly committed ops, returning a
  /// violation if any tracked committed op has fallen below its configuration's quorum of durable
  /// holders. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let n = cluster.replica_count();
    let evidence: Vec<DurableEvidence> = (0..n)
      .map(|i| DurableEvidence {
        epoch: cluster.replica_durable_epoch(i).get(),
        voters: Self::voting_slots(cluster, i, n),
        voter_count: cluster.replica_voter_count(i).map_or(0, usize::from),
        checkpoint_op: cluster.replica_checkpoint_op(i).get(),
      })
      .collect();
    // The committed `Reconfigure` ops (numbered + committed, never applied) plus the applied tail above
    // the frontier cursor. The applied streams carry the true op number, and agreement makes the
    // longest of them the committed history, so its tail is exactly the newly committed applied ops.
    let mut committed: Vec<u64> = cluster.committed_reconfigure_ops().into_iter().collect();
    let longest = (0..n)
      .map(|i| cluster.replica_sm(i).applied())
      .max_by_key(|applied| applied.len())
      .unwrap_or(&[]);
    for (op, _) in longest.iter().rev() {
      if *op <= self.applied_frontier {
        break;
      }
      committed.push(*op);
    }
    if let Some((op, _)) = longest.last() {
      self.applied_frontier = self.applied_frontier.max(*op);
    }
    self.fold(&evidence, &committed, &|i, op| {
      cluster.replica_appended_op(i, OpNumber::with(op))
    })
  }

  /// The replica indices occupying replica `i`'s DURABLE voting slots. Members are keyed by their
  /// stable `MemberId`, which the simulation assigns as the replica index, so a member id outside
  /// the replica range names no simulated node (the live-reconfiguration axis adds such a sentinel as
  /// a LEARNER) and holds no durable copy to count.
  fn voting_slots(cluster: &Cluster, i: usize, replica_count: usize) -> Vec<usize> {
    let voter_count = cluster.replica_voter_count(i).unwrap_or(0);
    (0..voter_count)
      .filter_map(|slot| cluster.replica_member_at(i, slot))
      .map(|member| member.get())
      .filter(|id| *id < replica_count as u128)
      .map(|id| id as usize)
      .collect()
  }
}

impl Default for DurableQuorumChecker {
  fn default() -> Self {
    Self::new()
  }
}

/// Stateful **applied-once** checker: every client-acked request is applied **exactly once** across
/// commits, view changes, repair, state-sync, and restarts.
///
/// It folds each replica's recorded apply stream ([`Cluster::replica_applied_events`] — one
/// `Committed` per state-machine apply, in apply order, tagged with the replica's incarnation and
/// rebased at state-sync points) into two layers of invariant, checked on every
/// [`observe`](Self::observe):
///
/// 1. **Per replica, per incarnation** — the stream is structurally an apply log: op numbers never
///    regress, and consecutive distinct ops differ by exactly 1 unless a completed state-sync rebased
///    the stream in between (the snapshot bulk-restores the skipped band, so those ops are never
///    individually re-emitted). An incarnation may START at any op — recovery re-applies only
///    `(checkpoint_op .. commit_max]`, never the snapshot-restored prefix. No `(client, request)`
///    pair is applied twice within one incarnation (a duplicate request must be deduplicated by the
///    session table, never re-applied).
/// 2. **Globally, across the whole run** — every stream folds into ONE injective map
///    `(client, request) → (op, reply)`: the same request applied at two different ops (a request
///    committed twice), two different requests at the same op (an op number reused — the
///    committed-op-loss + re-mint class), or two different replies for the same request (divergent
///    applies) are all violations.
///
/// [`check`](Self::check) then enforces the headline no-loss property (post-quiesce): every
/// client-acked reply is present in the map with a matching reply body — acked-but-never-applied is
/// a lost committed op — and the map is non-empty whenever the cluster committed anything (the
/// capture itself is non-vacuous).
#[derive(Debug)]
pub struct AppliedOnceChecker {
  /// Per-replica count of stream entries already folded (the streams are append-only).
  cursor: Vec<usize>,
  /// Per-replica incarnation of the segment currently being folded.
  incarnation: Vec<u64>,
  /// Per-replica applied frontier within the current incarnation: the last committed op folded, or
  /// the latest state-sync rebase point — `None` until the incarnation's first entry (it may start
  /// at any op).
  last_op: Vec<Option<u64>>,
  /// Per-replica `(client, request)` pairs applied within the current incarnation.
  seen: Vec<HashSet<(u128, u64)>>,
  /// The global injective map: `(client, request) → (op, reply)` across every replica and
  /// incarnation. Agreement makes re-emissions (recovery, wipes, backups) converge on identical
  /// values; any disagreement is a double-apply/divergence violation.
  by_key: HashMap<(u128, u64), (u64, Bytes)>,
  /// The reverse direction of injectivity: `op → (client, request)` — one request per op number,
  /// ever.
  by_op: HashMap<u64, (u128, u64)>,
}

impl AppliedOnceChecker {
  /// An applied-once checker for a cluster of `replica_count` replicas.
  pub fn new(replica_count: usize) -> Self {
    Self {
      cursor: vec![0; replica_count],
      incarnation: vec![0; replica_count],
      last_op: vec![None; replica_count],
      seen: vec![HashSet::new(); replica_count],
      by_key: HashMap::new(),
      by_op: HashMap::new(),
    }
  }

  /// Folds each replica's not-yet-seen apply-stream suffix into the per-incarnation and global
  /// invariants, returning the first violation. Pure over its inputs so the invariant logic is
  /// unit-testable without a live `Cluster`; each `streams[i]` must be an append-only extension of
  /// the slice passed previously.
  fn fold(
    &mut self,
    streams: &[&[(u64, AppliedEvent)]],
    reconfigure_ops: &HashSet<u64>,
  ) -> CheckResult {
    for (i, stream) in streams.iter().enumerate() {
      while self.cursor[i] < stream.len() {
        let (incarnation, entry) = &stream[self.cursor[i]];
        self.cursor[i] += 1;
        if *incarnation != self.incarnation[i] {
          // A restart/wipe rebuilt the endpoint: its apply stream re-emits from its durable
          // checkpoint, so the segment state (frontier + per-incarnation pairs) starts afresh.
          self.incarnation[i] = *incarnation;
          self.last_op[i] = None;
          self.seen[i].clear();
        }
        match entry {
          AppliedEvent::SyncPoint(op) => {
            // A completed state-sync REBASED the state machine onto the checkpoint at `op`: commits
            // resume at `op + 1`. Forward-only (`max`): the recovery peer-fetch path installs the
            // snapshot eagerly and reports the sync only once its root is durable, so the marker can
            // trail commits already folded above the synced point — it must never regress the
            // frontier.
            let target = op.get();
            self.last_op[i] = Some(self.last_op[i].map_or(target, |last| last.max(target)));
          }
          AppliedEvent::Committed(c) => {
            let op = c.op().get();
            let client = c.client().get();
            let request = c.request().get();
            if let Some(last) = self.last_op[i] {
              if op < last {
                return CheckResult::violation(format!(
                  "replica {i}: committed op regressed within an incarnation ({last} -> {op}) — \
                   the apply stream re-applied below its frontier"
                ));
              }
              // A gap is legitimate ONLY if EVERY op number strictly between `last` and `op` is a
              // committed `Reconfigure` op — consensus-layer ops that are committed + assigned an op
              // number but never applied to the state machine, so they never appear in the apply
              // stream. Any non-reconfigure number in the gap is a genuinely skipped applied op.
              if op > last + 1 {
                let unexplained = ((last + 1)..op).any(|o| !reconfigure_ops.contains(&o));
                if unexplained {
                  return CheckResult::violation(format!(
                    "replica {i}: committed-op gap within an incarnation ({last} -> {op}) with no \
                     completed state-sync or committed reconfiguration between them — an applied op \
                     was skipped"
                  ));
                }
              }
            }
            self.last_op[i] = Some(op);
            if !self.seen[i].insert((client, request)) {
              return CheckResult::violation(format!(
                "replica {i}: client {client} request {request} applied twice within one \
                 incarnation (second apply at op {op})"
              ));
            }
            if let Some(&(c2, r2)) = self.by_op.get(&op)
              && (c2, r2) != (client, request)
            {
              return CheckResult::violation(format!(
                "op {op} carries two different requests: client {c2} request {r2} vs client \
                 {client} request {request} — an op number was reused for a second request"
              ));
            }
            self.by_op.insert(op, (client, request));
            let reply = c.reply_bytes();
            match self.by_key.get(&(client, request)) {
              Some((op2, reply2)) => {
                if *op2 != op {
                  return CheckResult::violation(format!(
                    "client {client} request {request} applied at two different ops ({op2} and \
                     {op}) — a request committed twice"
                  ));
                }
                if *reply2 != reply {
                  return CheckResult::violation(format!(
                    "client {client} request {request} (op {op}): applied replies diverge \
                     ({reply2:?} vs {reply:?})"
                  ));
                }
              }
              None => {
                self.by_key.insert((client, request), (op, reply));
              }
            }
          }
        }
      }
    }
    CheckResult::Ok
  }

  /// Sample the cluster: fold every replica's newly recorded apply-stream entries (the streams are
  /// append-only) and return a violation on any double-apply, op reuse, divergent reply, or broken
  /// stream structure. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let streams: Vec<&[(u64, AppliedEvent)]> = (0..cluster.replica_count())
      .map(|i| cluster.replica_applied_events(i))
      .collect();
    let reconfigure_ops: HashSet<u64> = cluster.committed_reconfigure_ops().into_iter().collect();
    self.fold(&streams, &reconfigure_ops)
  }

  /// Final applied-once assertion (run post-quiesce): folds any not-yet-observed stream entries,
  /// then enforces that the map is non-empty whenever the cluster committed anything, and that
  /// every client-acked reply is present in the map with a matching reply body. An
  /// acked-but-never-applied request is a lost committed op — the headline invariant.
  pub fn check(&mut self, cluster: &Cluster) -> CheckResult {
    if let v @ CheckResult::Violation(_) = self.observe(cluster) {
      return v;
    }
    let committed_any =
      (0..cluster.replica_count()).any(|i| !cluster.replica_sm(i).applied().is_empty());
    let mut acked = Vec::new();
    for i in 0..cluster.client_count() {
      let client = cluster.client(i).id().get();
      for (request, body) in cluster.client(i).replies() {
        acked.push((client, *request, body.clone()));
      }
    }
    self.check_acked(&acked, committed_any)
  }

  /// The final-check core over the collected acked replies (`(client, request, reply)` triples) and
  /// whether the cluster committed anything. Pure over its inputs so the no-loss logic is
  /// unit-testable without a live `Cluster`.
  fn check_acked(&self, acked: &[(u128, u64, Bytes)], committed_any: bool) -> CheckResult {
    if committed_any && self.by_key.is_empty() {
      return CheckResult::violation(
        "the cluster committed ops but the applied-once map is empty — the apply-stream capture \
         recorded nothing",
      );
    }
    for (client, request, reply) in acked {
      match self.by_key.get(&(*client, *request)) {
        None => {
          return CheckResult::violation(format!(
            "client {client}: acked request {request} was never applied on any replica — a \
             client-acked committed op was lost"
          ));
        }
        Some((op, applied)) if applied != reply => {
          return CheckResult::violation(format!(
            "client {client}: acked request {request} disagrees with the applied reply at op {op} \
             ({reply:?} acked vs {applied:?} applied)"
          ));
        }
        Some(_) => {}
      }
    }
    CheckResult::Ok
  }
}

/// One client's ack-time record entry as the staleness fold consumes it: `(request, reply_body,
/// ack_instant)` — the shape [`Cluster::client_replies_at`] yields per client.
type AckRecord = (u64, Bytes, Instant);

/// Stateful **linearizable-read staleness** oracle: the cluster's write-reply staleness floor over
/// time, and the enforcement a linearizable-read path must satisfy the moment one exists.
///
/// A linearizable read returning at real time `T` must reflect every write that was ACKED to a client
/// before `T`. This checker maintains the two quantities that obligation rests on and joins them:
///
/// 1. **The staleness floor** — the cluster's **committed history** high-water: the longest applied
///    `(op, body)` prefix ever observed on any replica (the same quantity [`DurabilityChecker`]
///    tracks), monotonically extended. Its length is monotone non-decreasing **by construction** (a
///    fold only ever extends it), and each [`observe`](Self::observe) re-asserts that the prefix is
///    not REWRITTEN — a newly observed applied log that disagrees with the committed history on their
///    common prefix is a floor regression and trips. This is a deliberate defense-in-depth cross-check
///    of the same no-rewrite invariant [`DurabilityChecker`] enforces: the staleness floor can never
///    silently move backwards.
/// 2. **The acked set** — every client-acked write paired with the instant it was acked. Each ack is
///    `(client, request, ack_instant)` (drained from [`Cluster::client_replies_at`]); the op it
///    committed at is resolved by folding the replicas' apply streams into a `(client, request) -> op`
///    map (the apply stream is the authority on which op a request committed at). The resolved acked
///    set is therefore `(op, ack_instant)` pairs — exactly the writes a later read must not be stale
///    against.
///
/// A read is recorded via [`record_read`](Self::record_read) as `(issue_instant, returned_index,
/// returned_body)`. [`check`](Self::check) (post-quiesce) enforces the staleness obligation: every
/// recorded read at instant `T` returning applied index `R` must satisfy `R >= N`, where `N` is the
/// highest committed op whose ack_instant is strictly before `T` (the highest write acked before the
/// read issued). It also enforces **non-vacuity**: the resolved acked set is non-empty whenever the
/// cluster committed anything (the capture itself recorded something).
///
/// In the behavior-preserving phase there is no read path, so no read is ever recorded and the
/// staleness enforcement is vacuously satisfied — which is correct and intended. The live value now is
/// the floor monotonicity (every tick) plus the non-vacuity witness; the checker is STRUCTURALLY READY
/// to enforce reads the moment a linearizable-read path records them.
#[derive(Debug)]
pub struct StalenessChecker {
  /// The committed history high-water (the staleness floor): the longest applied `(op, body)` prefix
  /// ever observed on any replica, monotonically extended. Its length is the floor's numeric value.
  committed: Vec<(u64, Bytes)>,
  /// Per-replica count of apply-stream entries already folded (the streams are append-only), to learn
  /// the `(client, request) -> op` map without re-scanning.
  cursor: Vec<usize>,
  /// Per-replica incarnation of the segment currently being folded (an incarnation boundary is where
  /// a replica's apply stream legitimately re-emits from its durable checkpoint — agreement makes the
  /// re-emissions converge on the same op for a `(client, request)`).
  incarnation: Vec<u64>,
  /// The `(client, request) -> op` map learned from the apply streams — the authority on which op a
  /// request committed at, used to resolve each ack to its committed op.
  op_of: HashMap<(u128, u64), u64>,
  /// Per-client count of acked replies already drained from [`Cluster::client_replies_at`] (the
  /// per-client ack record is append-only).
  ack_cursor: Vec<usize>,
  /// The acked set: `(client, request, ack_instant)` per client-acked write, in ack order. Resolved
  /// to `(op, ack_instant)` against [`Self::op_of`] at check time (the apply stream is fully folded by
  /// then, so every acked request's op is known).
  acked: Vec<(u128, u64, Instant)>,
  /// Recorded linearizable-read observations: `(issue_instant, returned_index, returned_body)`. Empty
  /// until a read path exists; the staleness enforcement folds these against the acked set.
  reads: Vec<(Instant, u64, Bytes)>,
}

impl StalenessChecker {
  /// A staleness checker for a cluster of `replica_count` replicas and `client_count` clients.
  pub fn new(replica_count: usize, client_count: usize) -> Self {
    Self {
      committed: Vec::new(),
      cursor: vec![0; replica_count],
      incarnation: vec![0; replica_count],
      op_of: HashMap::new(),
      ack_cursor: vec![0; client_count],
      acked: Vec::new(),
      reads: Vec::new(),
    }
  }

  /// Fold one tick of cluster state into the floor + the op map + the acked set, returning the first
  /// violation. Pure over its inputs so the floor + acked-set logic is unit-testable without a live
  /// `Cluster`: `streams[i]` is replica `i`'s full apply stream (an append-only extension of the slice
  /// passed previously), `applied[i]` is replica `i`'s current applied `(op, body)` log, and each
  /// `acks[c]` is `(client_id, record)` with `record` client `c`'s full `(request, reply,
  /// ack_instant)` ack history (also append-only). The client id is threaded explicitly so an ack
  /// resolves to its op via the `(client, request) -> op` map without relying on an index convention.
  fn fold(
    &mut self,
    streams: &[&[(u64, AppliedEvent)]],
    applied: &[Vec<(u64, Bytes)>],
    acks: &[(u128, &[AckRecord])],
  ) -> CheckResult {
    // (1) The staleness floor: extend the committed history, firing on a rewritten committed op (a
    // floor regression). Identical in spirit to `DurabilityChecker::fold`'s no-rewrite check — a
    // deliberate independent cross-check that the floor never moves backwards.
    for (i, a) in applied.iter().enumerate() {
      let n = a.len().min(self.committed.len());
      if a[..n] != self.committed[..n] {
        let pos = (0..n).find(|&p| a[p] != self.committed[p]).unwrap_or(0);
        let (cop, cbody) = &self.committed[pos];
        let (aop, abody) = &a[pos];
        return CheckResult::violation(format!(
          "replica {i}: applied prefix diverges from the committed history at op {cop} — the \
           staleness floor regressed (a committed op was rewritten): committed=({cop},{cbody:?}) \
           replica=({aop},{abody:?})"
        ));
      }
      if a.len() > self.committed.len() {
        self.committed = a.clone();
      }
    }
    // (2) Learn `(client, request) -> op` from the apply streams (the op authority). Re-emissions
    // across incarnations agree, so a later identical insertion is a no-op; a DISAGREEMENT would be a
    // double-apply the `AppliedOnceChecker` owns, so this map just keeps the first-seen op.
    for (i, stream) in streams.iter().enumerate() {
      while self.cursor[i] < stream.len() {
        let (incarnation, entry) = &stream[self.cursor[i]];
        self.cursor[i] += 1;
        if *incarnation != self.incarnation[i] {
          self.incarnation[i] = *incarnation;
        }
        if let AppliedEvent::Committed(c) = entry {
          self
            .op_of
            .entry((c.client().get(), c.request().get()))
            .or_insert_with(|| c.op().get());
        }
      }
    }
    // (3) Drain new acks into the acked set (append-only per client), tagged with the client id so an
    // ack later resolves to its committed op via the `(client, request) -> op` map.
    for (c, (client_id, record)) in acks.iter().enumerate() {
      while self.ack_cursor[c] < record.len() {
        let (request, _reply, ack_instant) = &record[self.ack_cursor[c]];
        self.ack_cursor[c] += 1;
        self.acked.push((*client_id, *request, *ack_instant));
      }
    }
    CheckResult::Ok
  }

  /// Record a linearizable-read observation: a read issued at `issue_instant` returned applied index
  /// `returned_index` carrying `returned_body`. Stored for the staleness enforcement in
  /// [`check`](Self::check). No read path exists in the behavior-preserving phase, so this is unused
  /// today — it is the seam a future linearizable-read path reports through.
  pub fn record_read(&mut self, issue_instant: Instant, returned_index: u64, returned_body: Bytes) {
    self
      .reads
      .push((issue_instant, returned_index, returned_body));
  }

  /// Sample the cluster: fold the floor, the op map, and the acked set for this tick, returning a
  /// violation on a floor regression. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let streams: Vec<&[(u64, AppliedEvent)]> = (0..cluster.replica_count())
      .map(|i| cluster.replica_applied_events(i))
      .collect();
    let applied: Vec<Vec<(u64, Bytes)>> = (0..cluster.replica_count())
      .map(|i| cluster.replica_sm(i).applied().to_vec())
      .collect();
    let acks: Vec<(u128, &[AckRecord])> = (0..cluster.client_count())
      .map(|i| (cluster.client(i).id().get(), cluster.client_replies_at(i)))
      .collect();
    // The client-spawn churn lane can grow the client set mid-run; keep the ack cursor in step so a
    // spawned client's acks are folded rather than panicking on a missing cursor.
    while self.ack_cursor.len() < acks.len() {
      self.ack_cursor.push(0);
    }
    self.fold(&streams, &applied, &acks)
  }

  /// Final staleness assertion (run post-quiesce): folds any not-yet-observed state, then enforces
  /// that every recorded read is not stale against the writes acked before it issued, and that the
  /// acked set is non-empty whenever the cluster committed anything (the capture is non-vacuous).
  pub fn check(&mut self, cluster: &Cluster) -> CheckResult {
    if let v @ CheckResult::Violation(_) = self.observe(cluster) {
      return v;
    }
    let committed_any = !self.committed.is_empty();
    // Resolve every ack to its committed op via the apply-stream map (now fully folded). FAIL
    // CLOSED on a miss: an acked request was answered with a `Reply`, so its op committed and
    // applied, so it MUST appear in some replica's apply stream. Silently skipping an unresolved
    // ack would DROP it from the floor — masking a higher acked op behind a lower resolved one and
    // letting a stale read pass — the exact way an oracle weakens itself into vacuity.
    let resolved = match Self::resolve_acks(&self.acked, &self.op_of) {
      Ok(resolved) => resolved,
      Err((client, request)) => {
        return CheckResult::violation(format!(
          "client {client} request {request} was acked but appears in no apply stream — the \
           staleness oracle cannot resolve its committed op (failing closed: a dropped ack would \
           silently lower the floor and pass a stale read)"
        ));
      }
    };
    Self::check_reads(&resolved, &self.reads, committed_any)
  }

  /// Resolve each acked `(client, request, ack_instant)` to `(op, ack_instant)` via the
  /// apply-stream op map. Pure so the fail-closed resolution is unit-testable without a live
  /// `Cluster`. `Err((client, request))` if any acked request is absent from the map — the caller
  /// turns that into a violation rather than dropping the ack from the floor.
  fn resolve_acks(
    acked: &[(u128, u64, Instant)],
    op_of: &HashMap<(u128, u64), u64>,
  ) -> Result<Vec<(u64, Instant)>, (u128, u64)> {
    let mut resolved = Vec::with_capacity(acked.len());
    for (client, request, ack_instant) in acked {
      match op_of.get(&(*client, *request)) {
        Some(&op) => resolved.push((op, *ack_instant)),
        None => return Err((*client, *request)),
      }
    }
    Ok(resolved)
  }

  /// The final-check core over the resolved acked set (`(op, ack_instant)` pairs) and the recorded
  /// reads. Pure over its inputs so the staleness logic is unit-testable without a live `Cluster`:
  ///
  /// - **non-vacuity**: if the cluster committed anything but the acked set is empty, the capture
  ///   recorded nothing — the oracle would otherwise pass vacuously forever.
  /// - **staleness**: every read at instant `T` returning index `R` must satisfy `R >= N`, where `N`
  ///   is the highest committed op acked strictly before `T`. A read returning below a write that
  ///   completed before it issued is a stale (non-linearizable) read.
  fn check_reads(
    acked: &[(u64, Instant)],
    reads: &[(Instant, u64, Bytes)],
    committed_any: bool,
  ) -> CheckResult {
    if committed_any && acked.is_empty() {
      return CheckResult::violation(
        "the cluster committed ops but the staleness acked set is empty — the ack-time capture \
         recorded nothing",
      );
    }
    for (issued_at, returned_index, _body) in reads {
      // The staleness floor for this read: the highest op acked strictly before it issued.
      let floor = acked
        .iter()
        .filter(|(_, ack_at)| ack_at < issued_at)
        .map(|(op, _)| *op)
        .max();
      if let Some(n) = floor
        && *returned_index < n
      {
        return CheckResult::violation(format!(
          "linearizable read issued at {} returned applied index {returned_index}, below the \
           staleness floor {n} (a write committed at op {n} was acked before the read issued) — a \
           stale read",
          issued_at.as_nanos(),
        ));
      }
    }
    CheckResult::Ok
  }
}

/// Stateful checker: each replica's **DURABLE (superblock) view** must never decrease across
/// observations.
///
/// The quantity tracked is the durable view ([`Cluster::replica_durable_view`]), **not** the volatile
/// in-memory `view`. The in-memory view is NOT monotone across a crash + restart, and correctly so: a
/// self-driven view change advances `self.view` to the new view *before* the matching superblock
/// durable-view write lands, and the proto defers EVERY binding participation in a view (PrepareOk /
/// DoViewChange / StartView / Prepare / Commit) until that write completes (durable-view-before-
/// participate). So a replica that bumped its in-memory view, did not yet persist it, and crashed has
/// **acted in no higher view than its durable view** — on restart `recover()` legitimately restores
/// the durable view, regressing the in-memory view, and the replica is self-correcting (the next
/// higher-view message re-catches it up). Asserting monotonicity on the in-memory view would flag this
/// safe, expected behaviour (a replica enters a view change for view 1, crashes before the view-1
/// root is durable, and recovers to view 0 — having sent NOTHING in view 1). The DURABLE view is
/// the right invariant: it only advances when a view-change/adoption root
/// write lands, so it is monotone AND it is exactly "the highest view the replica could have acted in".
/// A regression THERE would be a real durable-state safety violation.
#[derive(Debug)]
pub struct ViewMonotonicChecker {
  max_view: Vec<u64>,
}

impl ViewMonotonicChecker {
  /// A checker for a cluster of `replica_count` replicas (all start at durable view 0).
  pub fn new(replica_count: usize) -> Self {
    Self {
      max_view: vec![0; replica_count],
    }
  }

  /// Record that replica `i`'s durable storage was WIPED ([`Cluster::wipe_and_restart`]): its
  /// durable-view monotonicity baseline is forfeit with the disk — the fresh superblock honestly
  /// reads view 0, and that REGRESSION IS the amnesia hazard, not a checker artifact (the replica may
  /// have voted in views its new disk has no memory of). Whether that ever lets it double-participate
  /// and break agreement is judged by the safety/durability checkers, which are NOT relaxed.
  pub fn note_wipe(&mut self, i: usize) {
    self.max_view[i] = 0;
  }

  /// Sample the cluster: returns a violation if any replica's DURABLE view dropped below a prior
  /// maximum (a real durable-view regression — never legitimate). Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      let v = cluster.replica_durable_view(i).get();
      if v < self.max_view[i] {
        return CheckResult::violation(format!(
          "replica {i}: durable view regressed to {v} (was {})",
          self.max_view[i]
        ));
      }
      self.max_view[i] = v;
    }
    CheckResult::Ok
  }
}

/// Stateful checker: each replica's durable `(Epoch, View)` must never regress LEXICOGRAPHICALLY —
/// the split-brain regression net across an epoch transition.
///
/// [`ViewMonotonicChecker`] proves the durable VIEW never regresses WITHIN an epoch; an offline-restart
/// reconfiguration legitimately RESETS the view per epoch (the successor root carries `cur`'s view,
/// but the epoch is the high-order coordinate — a later epoch always dominates an earlier one
/// regardless of view). So the right cross-epoch invariant is on the PAIR `(epoch, view)` ordered
/// lexicographically (epoch high-order): it must be monotone non-decreasing per replica. A view DROP
/// is allowed ONLY when the epoch strictly ROSE (the per-epoch view reset); a view drop AT THE SAME
/// epoch, or ANY epoch regression, is a real durable split-brain hazard — a replica acting in a
/// `(epoch, view)` it could be rolled back out of, the exact state two configurations diverging would
/// produce. The quantity is the DURABLE `(epoch, view)` (read off the superblock the proto recovers
/// from), monotone by the same durable-before-participate argument [`ViewMonotonicChecker`] documents,
/// now lifted to the epoch-prefixed pair.
#[derive(Debug)]
pub struct EpochViewMonotonicChecker {
  /// Per-replica high-water of the durable `(epoch, view)` pair (lexicographic, epoch high-order).
  high_water: Vec<(u64, u64)>,
}

impl EpochViewMonotonicChecker {
  /// A checker for a cluster of `replica_count` replicas (all start at `(epoch 0, view 0)`).
  pub fn new(replica_count: usize) -> Self {
    Self {
      high_water: vec![(0, 0); replica_count],
    }
  }

  /// Fold one durable `(epoch, view)` observation for replica `i` into its high-water, returning a
  /// violation on a LEXICOGRAPHIC regression. Pure over its inputs so the ordering logic is
  /// unit-testable without a live `Cluster`: a strictly-lower epoch, or the same epoch with a strictly
  /// lower view, is a regression; a lower view at a HIGHER epoch is the legitimate per-epoch reset.
  fn note(&mut self, i: usize, epoch: u64, view: u64) -> CheckResult {
    let (max_epoch, max_view) = self.high_water[i];
    if (epoch, view) < (max_epoch, max_view) {
      // Name which monotonicity broke: an epoch regression, or a view drop within an epoch.
      let reason = if epoch < max_epoch {
        "epoch regressed"
      } else {
        "view regressed within an epoch (a view drop is allowed only when the epoch rose)"
      };
      return CheckResult::violation(format!(
        "replica {i}: durable (epoch, view) regressed to ({epoch}, {view}) from ({max_epoch}, \
         {max_view}) — {reason}"
      ));
    }
    self.high_water[i] = (epoch, view);
    CheckResult::Ok
  }

  /// Record that slot `i`'s durable storage was WIPED (the amnesia axis): its `(epoch, view)`
  /// high-water is forfeit with the disk — the fresh superblock honestly reads `(epoch 0, view 0)`,
  /// and that regression IS the amnesia hazard, judged by the safety/durability checkers (NOT relaxed).
  pub fn note_wipe(&mut self, i: usize) {
    self.high_water[i] = (0, 0);
  }

  /// Sample the cluster: returns a violation if any replica's durable `(epoch, view)` regressed
  /// lexicographically. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      let epoch = cluster.replica_durable_epoch(i).get();
      let view = cluster.replica_durable_view(i).get();
      if let v @ CheckResult::Violation(_) = self.note(i, epoch, view) {
        return v;
      }
    }
    CheckResult::Ok
  }
}

/// Stateful checker: the durable `config_id` lineage forms a single non-forking CHAIN — every
/// successor configuration chains from the configuration currently recorded, never from a fork.
///
/// A reconfiguration mints a successor `config_id` that hashes the new membership together with its
/// PREDECESSOR's `config_id` (the lineage backward link, durably anchored by `prev_epoch`). For the
/// configuration history to be a safe single line — not two configurations that each believe they
/// succeeded the same parent (the split-brain reconfiguration hazard) — each newly observed
/// `(config_id, prev_epoch)` must chain off the lineage already recorded: its `prev_epoch` names the
/// CURRENT configuration's epoch, and a given epoch maps to exactly ONE `config_id` (a second,
/// different `config_id` at an epoch already seen is a fork). The checker records the lineage as an
/// `epoch -> config_id` map and the current epoch's high-water; a non-chained successor (its
/// `prev_epoch` is not the recorded current epoch) or a conflicting `config_id` at a known epoch
/// fires. Kept simple for PR1 (the chain is short — the offline axis bumps one epoch at a time).
#[derive(Debug)]
pub struct MembershipMonotonicChecker {
  /// The lineage observed so far: `epoch -> config_id`. One `config_id` per epoch, ever — a second
  /// distinct id at a known epoch is a fork.
  lineage: HashMap<u64, u128>,
  /// The current (highest) epoch whose configuration is recorded — the one a successor must chain off.
  current_epoch: u64,
}

impl Default for MembershipMonotonicChecker {
  fn default() -> Self {
    Self::new()
  }
}

impl MembershipMonotonicChecker {
  /// A fresh lineage checker: nothing recorded until the first observation seeds epoch 0's config.
  pub fn new() -> Self {
    Self {
      lineage: HashMap::new(),
      current_epoch: 0,
    }
  }

  /// Fold one durable configuration observation `(epoch, config_id, prev_epoch)` into the lineage,
  /// returning a violation on a FORK. Pure over its inputs so the chaining logic is unit-testable
  /// without a live `Cluster`. The rules:
  ///
  /// - A `config_id` re-observed at a known epoch must MATCH the recorded one (the same durable
  ///   configuration seen again — every node carries it). A DIFFERENT id at a known epoch is a fork.
  /// - A NEW epoch (above the current) is a successor: its `prev_epoch` must name the recorded current
  ///   epoch (it chains off the lineage tip), and the new epoch becomes current. A successor whose
  ///   `prev_epoch` is some OTHER epoch forked off a stale parent.
  ///
  /// The genesis observation (`epoch == 0`, nothing recorded yet) seeds the lineage.
  fn note(&mut self, epoch: u64, config_id: u128, prev_epoch: u64) -> CheckResult {
    if let Some(&known) = self.lineage.get(&epoch) {
      if known != config_id {
        return CheckResult::violation(format!(
          "configuration fork: epoch {epoch} carries two different config_ids ({known:#x} vs \
           {config_id:#x}) — two configurations claim the same epoch"
        ));
      }
      return CheckResult::Ok;
    }
    // A NEW epoch. Genesis (the first observation) seeds the lineage with no predecessor to chain.
    if !self.lineage.is_empty() {
      if epoch <= self.current_epoch {
        // A new (never-recorded) config_id at or below the current epoch is a fork off a stale tip:
        // the lineage already advanced past `epoch`, so a fresh configuration cannot legitimately
        // appear there.
        return CheckResult::violation(format!(
          "configuration fork: a new config_id {config_id:#x} appeared at epoch {epoch} at or below \
           the current lineage epoch {} — a successor must extend the tip, not branch below it",
          self.current_epoch
        ));
      }
      if prev_epoch != self.current_epoch {
        return CheckResult::violation(format!(
          "configuration fork: epoch {epoch}'s config chains from prev_epoch {prev_epoch}, not the \
           current lineage epoch {} — a non-chained successor (a fork off a stale parent)",
          self.current_epoch
        ));
      }
    }
    self.lineage.insert(epoch, config_id);
    self.current_epoch = self.current_epoch.max(epoch);
    CheckResult::Ok
  }

  /// Sample the cluster: fold every operational replica's durable `(epoch, config_id, prev_epoch)`
  /// into the lineage, returning a violation on a fork. A crashed replica is skipped (its durable
  /// root is read only on its next recover); a removed (`Retired`) slot still carries a valid
  /// historical configuration, so it is folded like any other — agreement makes every node that holds
  /// epoch K carry the SAME config_id, so the per-epoch uniqueness check is exactly the fork net.
  /// Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      if cluster.is_crashed(i) {
        continue;
      }
      let epoch = cluster.replica_durable_epoch(i).get();
      let config_id = cluster.replica_durable_config_id(i);
      let prev_epoch = cluster.replica_durable_prev_epoch(i).get();
      if let v @ CheckResult::Violation(_) = self.note(epoch, config_id, prev_epoch) {
        return v;
      }
    }
    CheckResult::Ok
  }
}

/// Asserts the per-op in-memory maps (`log` cache, `inflight` pipeline) and each replica's durable
/// WAL stay **bounded** over a run — the guarantee that post-checkpoint GC bounds the structures
/// that previously grew without bound in op count.
///
/// Without GC these grow with the total committed-op count (one `log`/WAL entry per op forever); with
/// GC they plateau near the un-checkpointed tail (a few `checkpoint_ops` intervals) plus pipeline
/// headroom. The bounds are generous constants chosen so a real leak (no GC) trips while normal
/// fluctuation does not. The `clients` table is bounded separately by the active client set (one
/// session per client), so it is checked against a client-count-derived bound, not the per-op bound.
/// The session's durable-root queue is checked against the CONSTANT bound of three (the submitted
/// front plus the live endpoint's two awaited roots) — independent of ops, views, time, AND the
/// incarnation count, since a rebuild collapses the dead incarnations' parked roots at endpoint
/// construction — so a root backlog accumulating under a slow superblock (one superseded root per
/// view-change or rebuild window) trips within one window. The session's checkpoint-envelope lane
/// is checked against the CONSTANT bound of one (the envelope fence's guarantee), so an
/// orphaned-envelope backlog accumulating under a backend slow on envelope writes trips at its
/// second concurrent write. The medium's RETAINED snapshot generations are checked against the
/// CONSTANT bound of three (live + staged-root-named + latest completed), so a completed orphan
/// accumulating behind overtaking view roots trips even while every in-flight count stays at one.
/// This arm bounds the retained set's SIZE only; whether the durable root's generation still
/// EXISTS in the store is a different property, asked per tick by [`check_medium_integrity`] —
/// a collector can hold the count constant while deleting the one generation the root names.
/// The block lane's total depth is checked against the serve cap plus constant headroom, so a
/// quota that stopped releasing (or an obligation that re-issues without consuming) trips within a
/// few cycles.
#[derive(Debug)]
pub struct BoundednessChecker {
  /// Max allowed entries in any per-op map (`log`, `inflight`) and any WAL.
  max_per_op: usize,
  /// Max allowed client-session entries on any replica.
  max_clients: usize,
}

impl BoundednessChecker {
  /// A checker bounding each per-op map + WAL to `max_per_op` entries and each session table to
  /// `max_clients` entries.
  pub const fn new(max_per_op: usize, max_clients: usize) -> Self {
    Self {
      max_per_op,
      max_clients,
    }
  }

  /// Sample the cluster; a violation if any per-op map, WAL, or session table exceeds its bound.
  /// Call every tick — a single over-bound observation anywhere in the run fails the gate.
  pub fn observe(&self, cluster: &Cluster) -> CheckResult {
    for i in 0..cluster.replica_count() {
      let log = cluster.replica_log_len(i);
      if log > self.max_per_op {
        return CheckResult::violation(format!(
          "replica {i}: log cache {log} exceeds bound {} (GC not bounding the per-op cache)",
          self.max_per_op
        ));
      }
      let inflight = cluster.replica_inflight_len(i);
      if inflight > self.max_per_op {
        return CheckResult::violation(format!(
          "replica {i}: inflight {inflight} exceeds bound {}",
          self.max_per_op
        ));
      }
      let wal = cluster.wal_len(i);
      if wal > self.max_per_op {
        return CheckResult::violation(format!(
          "replica {i}: WAL {wal} exceeds bound {} (prune not freeing slots below the checkpoint)",
          self.max_per_op
        ));
      }
      let clients = cluster.replica_clients_len(i);
      if clients > self.max_clients {
        return CheckResult::violation(format!(
          "replica {i}: client sessions {clients} exceeds bound {}",
          self.max_clients
        ));
      }
      // The durable-root queue: CONSTANT three — one submitted front (possibly a dead
      // predecessor's, owed to the medium) + the live endpoint's two awaited roots (its
      // durable-view write and its checkpoint root). NO per-incarnation concession: an in-place
      // rebuild collapses the dead incarnations' parked roots at endpoint construction and a
      // crash restart rebuilds the session, so the restart count buys nothing — a bound that
      // scaled with it would bless exactly the lifetime growth it exists to refuse (a driver
      // rebuilding endpoints faster than the backend lands roots would grow the queue without
      // limit, one parked header-bearing state per rebuild/view cycle, and the checker would
      // never fail). An unbounded backlog under a slow superblock now trips within one window.
      let roots = cluster.replica_roots_in_flight(i);
      let roots_bound = 3;
      if roots > roots_bound {
        return CheckResult::violation(format!(
          "replica {i}: durable-root queue {roots} exceeds bound {roots_bound} \
           (the submission gate / forfeiture / rebuild collapse is not bounding the root timeline)"
        ));
      }
      // The checkpoint-envelope lane: CONSTANT one, with no per-incarnation concession — the
      // session's envelope fence refuses a second submission while one write is outstanding, and
      // the fence reads the session ledger, which survives endpoint rebuilds and catch-up
      // postures. An envelope is never parked and an orphan cannot be forfeited (it is with the
      // medium), so admission is the lane's only bound; a second concurrent envelope anywhere is
      // the fence regressed, and under a backend that is merely slow on envelope writes the count
      // would then grow by one per view-change window with a completed sync handshake.
      let envelopes = cluster.replica_checkpoints_in_flight(i);
      if envelopes > 1 {
        return CheckResult::violation(format!(
          "replica {i}: {envelopes} checkpoint-envelope writes in flight \
           (the session's envelope fence admits one)"
        ));
      }
      // The RETAINED snapshot generations on the medium itself: CONSTANT three — the live
      // generation, a staged root's, and the latest-completed one. This is the store the
      // in-flight ledgers cannot see: with one envelope outstanding and one root with the
      // backend, a view root overtaking an orphaned envelope still deposits that envelope's
      // bytes, and without collection at the envelope landing each view/checkpoint cycle retains
      // one more completed orphan forever while every in-flight count stays green. SIZE only:
      // that the durable root's generation still EXISTS is `check_medium_integrity`'s question.
      let generations = cluster.replica_retained_snapshot_generations(i);
      if generations > 3 {
        return CheckResult::violation(format!(
          "replica {i}: {generations} checkpoint snapshot generations retained \
           (the superblock collect keeps live + staged-root-named + latest-completed)"
        ));
      }
      // The block lane's total depth: the serve cap (128 in the proto) plus headroom for the
      // quota'd kinds (one image capture, one walk) and the single-slot-obligation kinds
      // (flush/sweep/reconstruct, each serialized by the obligation that issues it and by the
      // lane's own drain). A leak in ANY kind — a quota that stopped releasing, an obligation
      // that re-issues without consuming — grows past this within a few cycles, where before
      // only the per-kind quotas were asserted and the unquota'd kinds were bounded by argument
      // alone.
      let jobs = cluster.replica_block_jobs_in_flight(i);
      if jobs > 144 {
        return CheckResult::violation(format!(
          "replica {i}: {jobs} block jobs in flight \
           (the lane's admission quotas cap the depth at the serve cap plus headroom)"
        ));
      }
    }
    CheckResult::Ok
  }
}

/// Stateful **reconfigure-applied-once** checker: every committed `Reconfigure` op swaps the epoch
/// **exactly once per replica incarnation** — no double-swap, no skipped swap, and every replica that
/// swaps a given op converges on the SAME successor `(epoch, config_id)`.
///
/// It folds each replica's recorded membership-swap stream
/// ([`Cluster::replica_membership_swaps`] — one [`MembershipChanged`] per committed `Reconfigure` op
/// whose durable `SwapEpoch` root landed, tagged with the replica's incarnation at the swap) into two
/// layers, checked on every [`observe`](Self::observe):
///
/// 1. **Per replica, per incarnation** — a `(op, incarnation)` key swaps AT MOST ONCE: a replica
///    never installs the same committed reconfiguration twice within one incarnation (a double-swap
///    would double-bump the epoch / re-fire the abdication). Keying by incarnation is load-bearing:
///    a replica that committed a `Reconfigure` op but crashed BEFORE its `SwapEpoch` root went
///    durable re-commits + re-installs that op in a LATER incarnation (the durable root was still at
///    the OLD epoch), which is a legitimate retry, not a double-application.
/// 2. **Globally, across replicas** — a committed op number swaps to exactly ONE successor: every
///    replica that installs op `o` records the SAME `(epoch, config_id)`. Divergent successors for
///    one committed op (two configurations from one reconfiguration) is a split-brain swap. The
///    installed epoch is also monotone in the op number — a later committed `Reconfigure` op installs
///    a strictly higher epoch — so the swaps form an increasing ladder.
///
/// [`check`](Self::check) folds any not-yet-observed tail. The checker is silent (vacuously `Ok`)
/// until a live reconfiguration is driven, so every run that never reconfigures passes trivially.
#[derive(Debug)]
pub struct ReconfigureAppliedOnceChecker {
  /// Per-replica count of swap-stream entries already folded (the streams are append-only).
  cursor: Vec<usize>,
  /// Per-replica `(op, incarnation)` swaps already seen — the per-replica, per-incarnation
  /// once-only key. A second occurrence of a key is a double-swap.
  seen: Vec<HashSet<(u64, u64)>>,
  /// The global map `op -> (epoch, config_id)`: the single successor every replica that swaps op `o`
  /// must agree on. A disagreement is a divergent (forked) swap of one committed reconfiguration.
  successor_of: HashMap<u64, (u64, u128)>,
}

impl ReconfigureAppliedOnceChecker {
  /// A reconfigure-applied-once checker for a cluster of `replica_count` replicas.
  pub fn new(replica_count: usize) -> Self {
    Self {
      cursor: vec![0; replica_count],
      seen: vec![HashSet::new(); replica_count],
      successor_of: HashMap::new(),
    }
  }

  /// Folds each replica's not-yet-seen swap-stream suffix into the per-incarnation once-only key + the
  /// global successor map, returning the first violation. Pure over its inputs so the invariant logic
  /// is unit-testable without a live `Cluster`; each `streams[i]` must be an append-only extension of
  /// the slice passed previously.
  fn fold(&mut self, streams: &[&[(u64, MembershipChanged)]]) -> CheckResult {
    for (i, stream) in streams.iter().enumerate() {
      while self.cursor[i] < stream.len() {
        let (incarnation, mc) = &stream[self.cursor[i]];
        self.cursor[i] += 1;
        let op = mc.op().get();
        let epoch = mc.epoch().get();
        let config_id = mc.config_id();
        // (1) Per replica, per incarnation: this committed reconfiguration installs AT MOST once.
        if !self.seen[i].insert((op, *incarnation)) {
          return CheckResult::violation(format!(
            "replica {i}: committed Reconfigure op {op} swapped TWICE within incarnation \
             {incarnation} (epoch {epoch}) — a membership swap was applied more than once"
          ));
        }
        // (2) Globally: one committed op swaps to exactly one successor `(epoch, config_id)`.
        match self.successor_of.get(&op) {
          Some(&(e2, c2)) if (e2, c2) != (epoch, config_id) => {
            return CheckResult::violation(format!(
              "committed Reconfigure op {op} installed two different successors: (epoch {e2}, \
               config_id {c2:#x}) vs (epoch {epoch}, config_id {config_id:#x}) — a divergent \
               (forked) membership swap of one committed reconfiguration"
            ));
          }
          Some(_) => {}
          None => {
            self.successor_of.insert(op, (epoch, config_id));
          }
        }
      }
    }
    CheckResult::Ok
  }

  /// Sample the cluster: fold every replica's newly recorded membership-swap entries (the streams are
  /// append-only) and return a violation on a double-swap or a divergent successor. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let streams: Vec<&[(u64, MembershipChanged)]> = (0..cluster.replica_count())
      .map(|i| cluster.replica_membership_swaps(i))
      .collect();
    self.fold(&streams)
  }

  /// Final assertion (post-quiesce): folds any not-yet-observed swap entries and re-checks the
  /// invariants. No additional post-quiesce obligation beyond the per-tick ones — the swap-once
  /// property is purely structural over the streams.
  pub fn check(&mut self, cluster: &Cluster) -> CheckResult {
    self.observe(cluster)
  }
}

/// Stateful **config-lineage** checker: the committed `config_id` chain installed by live membership
/// swaps is a single UNBROKEN line cluster-wide — every committed successor's `config_id` chains from
/// its committed predecessor, and no two configurations claim the same epoch.
///
/// Where [`MembershipMonotonicChecker`] folds the DURABLE-root `(epoch, config_id, prev_epoch)` every
/// tick, this checker folds the committed-SWAP EVENTS ([`Cluster::replica_membership_swaps`] — the
/// op-keyed view of which configuration each committed `Reconfigure` op installed). The two are
/// independent witnesses of the same single-chain property from different vantage points: the durable
/// root (what is persisted) and the committed swap (what consensus agreed to install). It maintains an
/// `epoch -> config_id` map and the highest epoch installed so far, and on each
/// [`observe`](Self::observe) enforces:
///
/// - **No fork** — a `config_id` re-observed at a known epoch must MATCH the recorded one (every
///   replica that installs epoch E carries the same `config_id`, by agreement). A DIFFERENT
///   `config_id` at a known epoch is two configurations claiming one epoch — a split-brain
///   reconfiguration.
/// - **Unbroken chain** — a single voter delta bumps the epoch by exactly one, so a newly installed
///   epoch must be exactly `current + 1` (it extends the lineage tip). An epoch that skips ahead, or
///   re-appears at or below the tip with a fresh `config_id`, did not chain off the committed
///   predecessor.
///
/// Vacuously `Ok` until a live reconfiguration installs a swap, so every non-reconfiguring run passes.
#[derive(Debug)]
pub struct ConfigLineageChecker {
  /// Per-replica count of swap-stream entries already folded (append-only).
  cursor: Vec<usize>,
  /// The committed lineage observed so far: `epoch -> config_id`. One `config_id` per epoch, ever — a
  /// second distinct id at a known epoch is a fork.
  lineage: HashMap<u64, u128>,
  /// The highest epoch a swap has installed so far — the lineage tip a successor must extend by one.
  /// `None` until the first swap (the genesis epoch is never a swap; the first swap installs epoch 1).
  tip: Option<u64>,
}

impl ConfigLineageChecker {
  /// A fresh config-lineage checker for a cluster of `replica_count` replicas.
  pub fn new(replica_count: usize) -> Self {
    Self {
      cursor: vec![0; replica_count],
      lineage: HashMap::new(),
      tip: None,
    }
  }

  /// Fold one committed-swap observation `(epoch, config_id)` into the lineage, returning a violation
  /// on a FORK or a broken chain. Pure over its inputs so the chaining logic is unit-testable without
  /// a live `Cluster`.
  fn note(&mut self, epoch: u64, config_id: u128) -> CheckResult {
    if let Some(&known) = self.lineage.get(&epoch) {
      if known != config_id {
        return CheckResult::violation(format!(
          "committed configuration fork: epoch {epoch} installed two different config_ids \
           ({known:#x} vs {config_id:#x}) — two configurations claim the same epoch from one \
           reconfiguration lineage"
        ));
      }
      return CheckResult::Ok;
    }
    // A NEW epoch installed by a swap. The genesis epoch (0) is never installed by a swap, so the
    // first swap must be epoch 1 chaining off genesis; thereafter each swap extends the tip by one.
    let expected = self.tip.map_or(1, |t| t + 1);
    if epoch != expected {
      return CheckResult::violation(format!(
        "committed configuration chain broken: a swap installed epoch {epoch} but the lineage tip is \
         {:?} (a single-voter change bumps the epoch by exactly one, so the next committed epoch must \
         be {expected}) — the successor did not chain off its committed predecessor",
        self.tip
      ));
    }
    self.lineage.insert(epoch, config_id);
    self.tip = Some(epoch);
    CheckResult::Ok
  }

  /// Fold each replica's not-yet-seen swap-stream suffix into the lineage. Pure over its inputs so the
  /// chaining logic is unit-testable; each `streams[i]` must be an append-only extension of the slice
  /// passed previously. Swaps are folded in stream order across replicas — agreement makes every
  /// replica installing epoch E carry the same `config_id`, so the per-epoch uniqueness check is the
  /// fork net regardless of the interleaving.
  fn fold(&mut self, streams: &[&[(u64, MembershipChanged)]]) -> CheckResult {
    for (i, stream) in streams.iter().enumerate() {
      while self.cursor[i] < stream.len() {
        let (_incarnation, mc) = &stream[self.cursor[i]];
        self.cursor[i] += 1;
        if let v @ CheckResult::Violation(_) = self.note(mc.epoch().get(), mc.config_id()) {
          return v;
        }
      }
    }
    CheckResult::Ok
  }

  /// Sample the cluster: fold every replica's newly recorded swap entries into the committed lineage,
  /// returning a violation on a fork or a broken chain. Call every tick.
  pub fn observe(&mut self, cluster: &Cluster) -> CheckResult {
    let streams: Vec<&[(u64, MembershipChanged)]> = (0..cluster.replica_count())
      .map(|i| cluster.replica_membership_swaps(i))
      .collect();
    self.fold(&streams)
  }

  /// Final assertion (post-quiesce): folds any not-yet-observed swap entries and re-checks the chain.
  pub fn check(&mut self, cluster: &Cluster) -> CheckResult {
    self.observe(cluster)
  }
}

#[cfg(test)]
mod tests;

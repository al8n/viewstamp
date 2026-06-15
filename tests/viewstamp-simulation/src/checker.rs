//! Safety / agreement checks over a cluster run.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use smol_str::SmolStr;
use viewstamp_proto::Instant;

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
/// 1. **Contiguity/uniqueness** — each replica's applied ops are `1,2,3,…` (no gap, no duplicate).
/// 2. **Agreement** — across replicas, the shorter applied `(op, body)` sequence is a prefix of
///    the longer (full content comparison, not just op numbers).
/// 3. **Client safety** — each client's replies are for strictly increasing request numbers `1..=n`.
pub fn check_safety(cluster: &Cluster) -> CheckResult {
  let mut logs: Vec<Vec<(u64, Bytes)>> = Vec::new();
  for i in 0..cluster.replica_count() {
    let applied: Vec<(u64, Bytes)> = cluster.replica_sm(i).applied().to_vec();
    for (idx, (op, _)) in applied.iter().enumerate() {
      if *op != idx as u64 + 1 {
        return CheckResult::violation(format!(
          "replica {i}: applied op {op} at position {idx} (expected {})",
          idx + 1
        ));
      }
    }
    logs.push(applied);
  }
  for i in 1..logs.len() {
    let n = logs[0].len().min(logs[i].len());
    if logs[0][..n] != logs[i][..n] {
      return CheckResult::violation(format!(
        "replica {i} diverges from replica 0 (content mismatch in applied prefix)"
      ));
    }
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
  fn fold(&mut self, streams: &[&[(u64, AppliedEvent)]]) -> CheckResult {
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
              if op > last + 1 {
                return CheckResult::violation(format!(
                  "replica {i}: committed-op gap within an incarnation ({last} -> {op}) with no \
                   completed state-sync between them — an applied op was skipped"
                ));
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
    self.fold(&streams)
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
/// [`ViewMonotonicChecker`] proves the durable VIEW never regresses WITHIN an epoch; a Tier C
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
    }
    CheckResult::Ok
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Cluster;

  #[test]
  fn clean_run_is_ok() {
    let mut c = Cluster::new(3, 2, 3, 1);
    for _ in 0..2000 {
      c.tick();
      if c.is_quiescent() {
        break;
      }
    }
    assert_eq!(check_safety(&c), CheckResult::Ok);
  }

  #[test]
  fn durability_checker_flags_a_regressed_committed_prefix() {
    // A committed op that is rewritten (or vanishes) across observations is a durability violation.
    let mut dur = DurabilityChecker::new(2);
    // Observation 1: both replicas agree on [1,2,3] → committed history is 3 ops.
    let o1 = vec![
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
    ];
    assert!(dur.fold(&o1, &[0, 0]).is_ok());
    // Observation 2: replica 1's op 2 now reads back a DIFFERENT body → a committed op was rewritten.
    let o2 = vec![
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"X")),
        (3, Bytes::from_static(b"c")),
      ],
    ];
    assert!(
      dur.fold(&o2, &[0, 0]).is_violation(),
      "a rewritten committed op must be flagged"
    );
  }

  #[test]
  fn durability_checker_flags_a_regressed_checkpoint() {
    let mut dur = DurabilityChecker::new(1);
    assert!(dur.fold(&[vec![]], &[5]).is_ok());
    assert!(
      dur.fold(&[vec![]], &[4]).is_violation(),
      "a checkpoint_op that goes backwards must be flagged"
    );
  }

  #[test]
  fn durability_checker_allows_a_lagging_recovered_replica() {
    // A replica that is BEHIND the committed history (e.g. just recovered, still catching up) is NOT
    // a violation — only a rewrite or cluster-wide loss is. observe must stay Ok.
    let mut dur = DurabilityChecker::new(2);
    let ahead = vec![
      vec![
        (1, Bytes::from_static(b"a")),
        (2, Bytes::from_static(b"b")),
        (3, Bytes::from_static(b"c")),
      ],
      vec![(1, Bytes::from_static(b"a"))], // replica 1 is behind, agrees on its (short) prefix
    ];
    assert!(
      dur.fold(&ahead, &[0, 0]).is_ok(),
      "a replica behind the committed history is fine as long as it agrees on its prefix"
    );
  }

  #[test]
  fn durability_checker_clean_run_passes() {
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut dur = DurabilityChecker::new(c.replica_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    assert!(
      dur.check(&c).is_ok(),
      "a clean run loses no committed op and keeps checkpoints monotone"
    );
  }

  #[test]
  fn durability_checker_final_assertion_stays_strict_when_no_operational_replica_retains_the_history()
   {
    // The end-of-run durability assertion (which the VOPR driver's final QUIESCE phase runs AFTER
    // draining) must stay STRICT: if NO operational replica retains the committed history, it is a
    // Violation. This is the "a committed op held by no operational holder still FAILS" direction — it
    // pins that the quiesce fix (drain THEN assert) did not weaken the no-loss guarantee.
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut dur = DurabilityChecker::new(c.replica_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    // Sanity: a real committed history was recorded and (healthy) it passes.
    assert!(c.replica_commit(0).get() >= 1, "the cluster committed ops");
    assert!(
      dur.check(&c).is_ok(),
      "healthy: the history survives operational"
    );
    // Now crash EVERY replica: none is operational, so no replica retains the committed history in an
    // operational state → the strict no-loss assertion must fire (it is NOT silently satisfied).
    for i in 0..c.replica_count() {
      c.crash(i);
    }
    assert!(
      dur.check(&c).is_violation(),
      "with no operational replica retaining the committed history the final assertion must FAIL — \
       the quiesce fix drains before this check but never relaxes its strictness"
    );
  }

  /// One fabricated apply-stream entry: incarnation `inc` applied op `op` for `(client, request)`
  /// producing `reply`.
  fn applied(
    inc: u64,
    op: u64,
    client: u128,
    request: u64,
    reply: &'static [u8],
  ) -> (u64, AppliedEvent) {
    use viewstamp_proto::{ClientId, Committed, OpNumber, RequestNumber};
    (
      inc,
      AppliedEvent::Committed(Committed::new(
        OpNumber::with(op),
        ClientId::new(client),
        RequestNumber::with(request),
        Bytes::from_static(reply),
      )),
    )
  }

  #[test]
  fn applied_once_clean_run_passes() {
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut once = AppliedOnceChecker::new(c.replica_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(once.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    assert!(
      once.check(&c).is_ok(),
      "a clean run applies every acked request exactly once"
    );
  }

  #[test]
  fn applied_once_checker_flags_a_double_applied_request() {
    // The same (client, request) applied at two ops within one incarnation: the session dedup
    // failed and the request committed twice — a double-apply.
    let mut once = AppliedOnceChecker::new(1);
    let s0 = vec![
      applied(0, 1, 7, 1, b"a"),
      applied(0, 2, 7, 2, b"b"),
      applied(0, 3, 7, 1, b"c"),
    ];
    assert!(
      once.fold(&[&s0]).is_violation(),
      "a request applied at two ops must be flagged"
    );
  }

  #[test]
  fn applied_once_checker_flags_a_request_committed_twice_across_replicas() {
    // The injective-map direction: replica 1's stream carries the same (client, request) at a
    // DIFFERENT op than replica 0 recorded — the request committed twice cluster-wide.
    let mut once = AppliedOnceChecker::new(2);
    let s0 = vec![applied(0, 1, 7, 1, b"a")];
    let s1 = vec![applied(0, 2, 7, 1, b"a")];
    assert!(
      once.fold(&[&s0, &s1]).is_violation(),
      "one request at two different ops across replicas must be flagged"
    );
  }

  #[test]
  fn applied_once_checker_flags_a_reused_op_number() {
    // The same op number carrying two DIFFERENT requests on two replicas: a committed op was lost
    // and its number re-minted for another request — the loss + re-mint divergence class.
    let mut once = AppliedOnceChecker::new(2);
    let s0 = vec![applied(0, 5, 1, 1, b"a")];
    let s1 = vec![applied(0, 5, 2, 1, b"a")];
    assert!(
      once.fold(&[&s0, &s1]).is_violation(),
      "an op number reused for a second request must be flagged"
    );
  }

  #[test]
  fn applied_once_checker_flags_a_divergent_reply() {
    // The same (client, request) at the same op but with two different replies: the applies
    // diverged (non-deterministic apply or a corrupted body slipped through).
    let mut once = AppliedOnceChecker::new(2);
    let s0 = vec![applied(0, 5, 1, 1, b"a")];
    let s1 = vec![applied(0, 5, 1, 1, b"X")];
    assert!(
      once.fold(&[&s0, &s1]).is_violation(),
      "divergent replies for one request must be flagged"
    );
  }

  #[test]
  fn applied_once_checker_flags_a_lost_acked_reply() {
    // A client holds an acked reply for a request NO replica's apply stream ever carried — a
    // client-acked committed op was lost. The matching acked reply passes; a divergent one trips.
    let mut once = AppliedOnceChecker::new(1);
    let s0 = vec![applied(0, 1, 7, 1, b"a")];
    assert!(once.fold(&[&s0]).is_ok());
    assert!(
      once
        .check_acked(&[(7, 2, Bytes::from_static(b"b"))], true)
        .is_violation(),
      "an acked-but-never-applied request must be flagged"
    );
    assert!(
      once
        .check_acked(&[(7, 1, Bytes::from_static(b"a"))], true)
        .is_ok(),
      "an acked reply matching the applied reply passes"
    );
    assert!(
      once
        .check_acked(&[(7, 1, Bytes::from_static(b"X"))], true)
        .is_violation(),
      "an acked reply disagreeing with the applied reply must be flagged"
    );
  }

  #[test]
  fn applied_once_checker_final_check_is_non_vacuous() {
    // An empty map while the cluster committed ops means the capture recorded nothing — the oracle
    // would otherwise pass vacuously forever.
    let once = AppliedOnceChecker::new(1);
    assert!(
      once.check_acked(&[], true).is_violation(),
      "committed ops with an empty applied map must be flagged"
    );
    assert!(
      once.check_acked(&[], false).is_ok(),
      "nothing committed, nothing required"
    );
  }

  #[test]
  fn applied_once_checker_allows_recovery_re_emission_in_a_new_incarnation() {
    // A restarted replica re-applies its recovered band: the same (client, request) pairs re-emit
    // at the SAME ops with the SAME replies — a new incarnation, not a double-apply. The new
    // incarnation may also start above op 1 (recovery never re-emits below its checkpoint).
    let mut once = AppliedOnceChecker::new(1);
    let s0 = vec![
      applied(0, 1, 7, 1, b"a"),
      applied(0, 2, 7, 2, b"b"),
      applied(1, 2, 7, 2, b"b"),
      applied(1, 3, 7, 3, b"c"),
    ];
    assert!(
      once.fold(&[&s0]).is_ok(),
      "re-emission across incarnations is recovery, not double-apply"
    );
  }

  #[test]
  fn applied_once_checker_allows_a_state_sync_rebase_but_flags_a_bare_gap() {
    use viewstamp_proto::OpNumber;
    // A completed state-sync bulk-restores the skipped band: the marker justifies the jump and
    // commits resume contiguously above the synced point.
    let mut once = AppliedOnceChecker::new(1);
    let synced = vec![
      applied(0, 1, 7, 1, b"a"),
      applied(0, 2, 7, 2, b"b"),
      (0, AppliedEvent::SyncPoint(OpNumber::with(10))),
      applied(0, 11, 7, 11, b"k"),
      applied(0, 12, 7, 12, b"l"),
    ];
    assert!(
      once.fold(&[&synced]).is_ok(),
      "a synced jump is a rebase, not a skipped apply"
    );
    // A LATE marker (the recovery peer-fetch path installs eagerly, reporting only once the synced
    // root is durable) sits below the already-folded frontier: forward-only, it must not regress
    // the frontier and flag the next contiguous op.
    let mut once = AppliedOnceChecker::new(1);
    let late = vec![
      applied(0, 41, 7, 41, b"a"),
      applied(0, 42, 7, 42, b"b"),
      (0, AppliedEvent::SyncPoint(OpNumber::with(40))),
      applied(0, 43, 7, 43, b"c"),
    ];
    assert!(
      once.fold(&[&late]).is_ok(),
      "a late sync marker never regresses the frontier"
    );
    // The same jump WITHOUT a sync between is a skipped apply.
    let mut once = AppliedOnceChecker::new(1);
    let gap = vec![
      applied(0, 1, 7, 1, b"a"),
      applied(0, 2, 7, 2, b"b"),
      applied(0, 11, 7, 11, b"k"),
    ];
    assert!(
      once.fold(&[&gap]).is_violation(),
      "an op gap with no state-sync between must be flagged"
    );
  }

  #[test]
  fn applied_once_checker_flags_a_regressed_op() {
    // An op below the incarnation's applied frontier is a re-apply (the recovered-band re-emission
    // lives in its own incarnation, never inline).
    let mut once = AppliedOnceChecker::new(1);
    let s0 = vec![applied(0, 5, 7, 5, b"a"), applied(0, 4, 7, 4, b"b")];
    assert!(
      once.fold(&[&s0]).is_violation(),
      "an op regression within an incarnation must be flagged"
    );
  }

  #[test]
  fn staleness_checker_clean_run_passes() {
    // A clean run records no reads (there is no read path), so the staleness enforcement is
    // vacuously satisfied; the floor stays monotone and the acked set is non-empty (clients are
    // acked), so the non-vacuity guard passes.
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut stale = StalenessChecker::new(c.replica_count(), c.client_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(stale.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    assert!(
      stale.check(&c).is_ok(),
      "a clean run keeps the floor monotone and records no stale read"
    );
  }

  #[test]
  fn staleness_checker_flags_a_read_below_a_write_acked_before_it() {
    // A read issued at T=100 returns applied index 4, but a write committed at op 5 was acked at
    // T=50 (before the read issued) — the read is stale (it failed to reflect a completed write).
    let acked = [(5u64, Instant::from_nanos(50))];
    let reads = [(Instant::from_nanos(100), 4u64, Bytes::from_static(b"r"))];
    assert!(
      StalenessChecker::check_reads(&acked, &reads, true).is_violation(),
      "a read returning below a write acked before it issued must be flagged"
    );
  }

  #[test]
  fn staleness_checker_passes_a_fresh_read() {
    // A read at or above every write acked before it issued is fresh. Op 5 acked at T=50; a read at
    // T=100 returning index 5 (== floor) and one returning 7 (> floor) both pass.
    let acked = [(5u64, Instant::from_nanos(50))];
    assert!(
      StalenessChecker::check_reads(
        &acked,
        &[(Instant::from_nanos(100), 5u64, Bytes::from_static(b"r"))],
        true,
      )
      .is_ok(),
      "a read returning exactly the floor is fresh"
    );
    assert!(
      StalenessChecker::check_reads(
        &acked,
        &[(Instant::from_nanos(100), 7u64, Bytes::from_static(b"r"))],
        true,
      )
      .is_ok(),
      "a read returning above the floor is fresh"
    );
    // A read that issued BEFORE the write was acked owes nothing to that write — only writes acked
    // strictly before the read constrain it. A read at T=40 (before the op-5 ack at T=50) returning
    // index 0 is fine.
    assert!(
      StalenessChecker::check_reads(
        &acked,
        &[(Instant::from_nanos(40), 0u64, Bytes::from_static(b"r"))],
        true,
      )
      .is_ok(),
      "a read that issued before a write was acked is not stale against it"
    );
  }

  #[test]
  fn staleness_checker_flags_a_regressed_floor() {
    // The staleness floor is the committed history high-water; a committed op that reads back with a
    // DIFFERENT body across observations is a floor regression (a committed op was rewritten).
    let mut stale = StalenessChecker::new(2, 0);
    let o1: Vec<Vec<(u64, Bytes)>> = vec![
      vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"b"))],
      vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"b"))],
    ];
    assert!(stale.fold(&[&[], &[]], &o1, &[]).is_ok());
    let o2: Vec<Vec<(u64, Bytes)>> = vec![
      vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"b"))],
      vec![(1, Bytes::from_static(b"a")), (2, Bytes::from_static(b"X"))],
    ];
    assert!(
      stale.fold(&[&[], &[]], &o2, &[]).is_violation(),
      "a rewritten committed op (floor regression) must be flagged"
    );
  }

  #[test]
  fn staleness_checker_fails_closed_on_an_unresolved_ack() {
    // An ack whose op the apply streams never recorded must FAIL the resolution — never be dropped.
    // Dropping it would lower the floor: here client 7's request 2 (the higher op, acked later) is
    // missing from the map while request 1 (op 5) resolves; silently skipping request 2 would let a
    // later read returning index 5 pass even though a higher write was acked before it.
    let mut op_of = HashMap::new();
    op_of.insert((7u128, 1u64), 5u64);
    let acked = [
      (7u128, 1u64, Instant::from_nanos(50)),
      (7u128, 2u64, Instant::from_nanos(60)),
    ];
    assert_eq!(
      StalenessChecker::resolve_acks(&acked, &op_of),
      Err((7u128, 2u64)),
      "an acked request absent from the apply-stream map fails closed, not silently dropped"
    );
    // With the full map both resolve.
    op_of.insert((7u128, 2u64), 6u64);
    assert!(
      StalenessChecker::resolve_acks(&acked, &op_of).is_ok(),
      "a fully-mapped acked set resolves"
    );
  }

  #[test]
  fn staleness_checker_final_check_is_non_vacuous() {
    // The cluster committed ops but no client was acked — the ack-time capture recorded nothing, so
    // the staleness oracle would otherwise pass vacuously.
    assert!(
      StalenessChecker::check_reads(&[], &[], true).is_violation(),
      "committed ops with an empty acked set must be flagged"
    );
    assert!(
      StalenessChecker::check_reads(&[], &[], false).is_ok(),
      "nothing committed, nothing required"
    );
  }

  #[test]
  fn staleness_checker_resolves_acked_ops_from_the_apply_stream() {
    // End-to-end through the live `fold`: an apply stream records client 7's request 1 at op 5 and
    // request 2 at op 6; the client's ack record carries both with ack instants. After folding, a
    // read at T just after the op-6 ack that returns index 5 is stale (op 6 was acked before it).
    let mut stale = StalenessChecker::new(1, 1);
    let stream = vec![applied(0, 5, 7, 1, b"a"), applied(0, 6, 7, 2, b"b")];
    let applied_log: Vec<Vec<(u64, Bytes)>> = vec![vec![
      (5, Bytes::from_static(b"a")),
      (6, Bytes::from_static(b"b")),
    ]];
    let acks: &[(u64, Bytes, Instant)] = &[
      (1, Bytes::from_static(b"a"), Instant::from_nanos(50)),
      (2, Bytes::from_static(b"b"), Instant::from_nanos(60)),
    ];
    assert!(
      stale
        .fold(&[&stream], &applied_log, &[(7u128, acks)])
        .is_ok()
    );
    // Resolve the acked set the way `check` does, then drive a stale read against it.
    stale.record_read(Instant::from_nanos(70), 5, Bytes::from_static(b"stale"));
    let mut resolved: Vec<(u64, Instant)> = Vec::new();
    for (client, request, ack_instant) in &stale.acked {
      if let Some(&op) = stale.op_of.get(&(*client, *request)) {
        resolved.push((op, *ack_instant));
      }
    }
    assert!(
      StalenessChecker::check_reads(&resolved, &stale.reads, true).is_violation(),
      "a read returning op 5 after op 6 was acked is stale once acks resolve to their committed ops"
    );
  }

  #[test]
  fn views_are_monotonic_across_a_crash() {
    let mut c = Cluster::new(3, 1, 2, 5);
    let mut vm = ViewMonotonicChecker::new(c.replica_count());
    for _ in 0..2000 {
      c.tick();
      assert!(vm.observe(&c).is_ok(), "no view regression");
      if c.is_quiescent() {
        break;
      }
    }
    c.crash(0);
    for _ in 0..200_000 {
      c.tick();
      assert!(vm.observe(&c).is_ok(), "no view regression after failover");
      if c.client(0).is_done() {
        break;
      }
    }
  }

  #[test]
  fn view_checker_tracks_the_durable_view_across_an_undurable_catch_up_regression() {
    // A replica that caught its IN-MEMORY view up to a higher view via the higher-view rule
    // (`catch_up_to_view` — a non-binding GetView probe, NO durable write, NO participation), then
    // crashed and recovered to its (lower) DURABLE view, legitimately regresses its in-memory view.
    // That is SAFE (it acted in no higher view than it persisted), so the view-monotonic checker —
    // which tracks the DURABLE view — must stay Ok, even though a naive in-memory-view checker WOULD
    // have fired.
    //
    // Construction: a 5-node cluster, crash the primary (r0) so the survivors fail over to view 1. A
    // lagging backup catches its in-memory view up to 1 BEFORE persisting it (the un-durable window:
    // `replica_view > replica_durable_view`). We crash that backup IN that window and restart it — it
    // recovers to durable view 0, regressing its in-memory view. The durable-view checker stays Ok
    // throughout; we also assert the in-memory view actually regressed (non-vacuity: the bug this fixes
    // would have tripped here).
    use crate::Faults;
    use core::time::Duration;

    let mut c = Cluster::new(5, 2, 200, 151);
    // Lossy network: drops keep a behind backup in the `catch_up_to_view` GetView-probe state (its
    // in-memory view bumped via the higher-view rule, the StartView that would persist it delayed), so
    // the un-durable window `replica_view > replica_durable_view` stays open long enough to observe.
    c.set_faults(Faults {
      latency: Duration::from_millis(1),
      jitter: Duration::from_millis(2),
      drop_per_mille: 200,
      duplicate_per_mille: 0,
      hold_per_mille: 0,
    });
    let mut vm = ViewMonotonicChecker::new(c.replica_count());
    // Warm up.
    for _ in 0..5_000 {
      c.tick();
      assert!(vm.observe(&c).is_ok());
      if c.replica_commit(0).get() >= 3 {
        break;
      }
    }
    // Crash the view-0 primary; the survivors fail over toward higher views. Search (re-crashing the
    // rotating primary to force fresh catch-ups) for a replica in the un-durable catch-up window.
    c.crash(0);
    let mut victim = None;
    for step in 0..200_000usize {
      c.tick();
      assert!(
        vm.observe(&c).is_ok(),
        "durable view never regresses (pre-crash)"
      );
      if let Some(i) = (0..c.replica_count())
        .find(|&i| !c.is_crashed(i) && c.replica_view(i).get() > c.replica_durable_view(i).get())
      {
        victim = Some(i);
        break;
      }
      // Periodically crash whichever replica currently leads (the live primary) and restart a crashed
      // one, to churn views and repeatedly drive lagging backups through the catch-up probe.
      if step % 4_000 == 3_999 {
        let leader = (0..c.replica_count())
          .filter(|&i| !c.is_crashed(i))
          .max_by_key(|&i| c.replica_view(i).get());
        if let Some(l) = leader {
          let live = (0..c.replica_count()).filter(|&i| !c.is_crashed(i)).count();
          // Keep a quorum up (5 replicas → never knock the live set below 3).
          if live > 3 {
            c.crash(l);
          }
        }
        for i in 0..c.replica_count() {
          if c.is_crashed(i) {
            c.restart(i);
            break;
          }
        }
      }
    }
    let v =
      victim.expect("a replica entered the un-durable catch-up window (in-memory view > durable)");
    let inmem_before = c.replica_view(v).get();
    let durable_before = c.replica_durable_view(v).get();
    assert!(
      inmem_before > durable_before,
      "the victim's in-memory view {inmem_before} leads its durable view {durable_before}"
    );
    // Crash + restart the victim: it recovers to its DURABLE view, regressing the in-memory view.
    c.crash(v);
    c.restart(v);
    let inmem_after = c.replica_view(v).get();
    assert!(
      inmem_after <= durable_before,
      "after recovery the in-memory view ({inmem_after}) is back at the durable view (<= {durable_before})"
    );
    assert!(
      inmem_after < inmem_before,
      "non-vacuity: the in-memory view genuinely REGRESSED ({inmem_before} -> {inmem_after}) — a naive \
       in-memory-view checker would have fired here"
    );
    // The durable-view checker stays Ok across the regression and the subsequent re-convergence.
    assert!(
      vm.observe(&c).is_ok(),
      "the durable-view checker tolerates the in-memory regression (the higher view was never durable)"
    );
    // Heal + run on: the durable view must stay monotone as the recovered replica re-catches up.
    c.set_faults(Faults::none());
    for i in 0..c.replica_count() {
      if c.is_crashed(i) {
        c.restart(i);
      }
    }
    for _ in 0..50_000 {
      c.tick();
      assert!(
        vm.observe(&c).is_ok(),
        "durable view stays monotone as the recovered replica re-catches up"
      );
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
  }

  #[test]
  fn epoch_view_checker_allows_a_per_epoch_view_reset_but_flags_a_same_epoch_view_drop() {
    let mut ev = EpochViewMonotonicChecker::new(1);
    // View climbs within epoch 0.
    assert!(ev.note(0, 0, 0).is_ok());
    assert!(ev.note(0, 0, 5).is_ok());
    // A view DROP at the SAME epoch is a split-brain regression.
    assert!(
      ev.note(0, 0, 4).is_violation(),
      "a view drop within an epoch must be flagged"
    );
    // A view drop is allowed when the EPOCH rose (the per-epoch view reset): epoch 1, view 0.
    let mut ev = EpochViewMonotonicChecker::new(1);
    assert!(ev.note(0, 0, 5).is_ok());
    assert!(
      ev.note(0, 1, 0).is_ok(),
      "a view reset to 0 at a higher epoch is the legitimate per-epoch reset"
    );
    // The pair is lexicographic: at the higher epoch the view climbs again.
    assert!(ev.note(0, 1, 3).is_ok());
    assert!(
      ev.note(0, 1, 2).is_violation(),
      "a view drop within the new epoch is still a regression"
    );
  }

  #[test]
  fn epoch_view_checker_flags_an_epoch_regression() {
    let mut ev = EpochViewMonotonicChecker::new(1);
    assert!(ev.note(0, 2, 1).is_ok());
    // ANY epoch regression is a split-brain hazard, even with a higher view.
    assert!(
      ev.note(0, 1, 99).is_violation(),
      "an epoch regression (even to a higher view) must be flagged"
    );
  }

  #[test]
  fn membership_checker_chains_a_lineage_and_flags_a_fork() {
    // Genesis seeds the lineage; a chained successor (prev_epoch == current) extends it.
    let mut m = MembershipMonotonicChecker::new();
    assert!(m.note(0, 0xAAAA, 0).is_ok()); // epoch 0, config A (genesis)
    assert!(m.note(0, 0xAAAA, 0).is_ok()); // the same config re-observed (another node) — fine
    assert!(
      m.note(1, 0xBBBB, 0).is_ok(),
      "epoch 1 chaining from prev_epoch 0 (the current tip) extends the lineage"
    );
    assert!(m.note(2, 0xCCCC, 1).is_ok(), "epoch 2 chains from epoch 1");
    // A FORK: a different config_id re-observed at a KNOWN epoch (two configs claim epoch 1).
    assert!(
      m.note(1, 0x9999, 0).is_violation(),
      "two different config_ids at the same epoch is a fork"
    );
  }

  #[test]
  fn membership_checker_flags_a_non_chained_successor() {
    // A successor whose prev_epoch is NOT the current tip is a fork off a stale parent.
    let mut m = MembershipMonotonicChecker::new();
    assert!(m.note(0, 0xAAAA, 0).is_ok());
    assert!(m.note(1, 0xBBBB, 0).is_ok()); // current tip is now epoch 1
    assert!(
      m.note(2, 0xCCCC, 0).is_violation(),
      "epoch 2 chaining from prev_epoch 0 (not the current tip 1) is a non-chained successor"
    );
  }

  #[test]
  fn durability_checker_excuses_a_removed_slot_from_the_survivor_scan() {
    // Two replicas agree on a 3-op committed history; then a reconfiguration REMOVES replica 1. With
    // replica 1 crashed (parked) and excused via `note_removed`, the final check must still pass
    // because the SURVIVOR (replica 0) retains the history — the removed node is no longer a required
    // holder. Without the excusal, a removed-then-crashed node could spuriously fail the check.
    use crate::Cluster;
    let mut c = Cluster::new(3, 2, 3, 9);
    let mut dur = DurabilityChecker::new(c.replica_count());
    for _ in 0..50_000 {
      c.tick();
      assert!(dur.observe(&c).is_ok());
      if (0..c.client_count()).all(|i| c.client(i).is_done()) {
        break;
      }
    }
    assert!(c.replica_commit(0).get() >= 1, "the cluster committed ops");
    // Model a removal: replica 2 is crashed (parked) AND excused. The survivors 0,1 still hold the
    // history, so the check passes — the removed node was correctly dropped from the required set.
    c.crash(2);
    dur.note_removed(2);
    assert!(
      dur.check(&c).is_ok(),
      "a removed (excused) crashed node does not break the no-loss check while survivors retain the \
       history"
    );
    // Crash a SURVIVOR too: now only replica 0 is operational and not removed — still holds the full
    // history, so the check passes (the removal did not relax the survivors' obligation).
    c.crash(1);
    assert!(
      dur.check(&c).is_ok(),
      "the surviving operational replica still retains the committed history"
    );
    // Crash the last survivor: NO operational non-removed replica retains the history → the check must
    // FAIL (removal excuses only the removed node, never the headline no-loss guarantee).
    c.crash(0);
    assert!(
      dur.check(&c).is_violation(),
      "with no operational non-removed replica retaining the history the no-loss check must fail"
    );
  }
}

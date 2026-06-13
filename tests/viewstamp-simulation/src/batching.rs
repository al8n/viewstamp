//! The deterministic batching lane: a synchronous model of the driver aggregator's PACKING + DEMUX
//! logic for sim clients, plus the per-unit exactly-once oracle.
//!
//! A batching client generates UNITS (and occasionally atomic GROUPS) on a seeded cadence; the
//! model queues them, and whenever the client has no request in flight it packs the queue FIFO into
//! ONE request body through the real [`BatchBuilder`] under the aggregator's dual-budget rule
//! (request bytes against [`SIM_REQUEST_BODY_BUDGET`]; ceiling-priced worst-case replies against
//! [`SIM_REPLY_BODY_BUDGET`] — groups pack whole or defer whole, never split). The packed body
//! rides the existing one-in-flight closed-loop client; the ack is demultiplexed with the real
//! [`ReplyView`] and every unit's reply is checked against the [`BatchSm`](crate::sm::BatchSm)
//! per-unit reply shape at ack time. Per-unit bookkeeping (every submitted unit's
//! `(request, unit_index, unit_bytes)` and its acked reply) feeds [`check_batching`], the oracle
//! extending request-level exactly-once down to units.
//!
//! Emission draws come from the client's OWN derived PRNG — never the cluster's or the VOPR
//! driver's action stream — so enabling batching on a client perturbs no other schedule, and a
//! lane with the axis OFF takes no draw at all (byte-identical default schedules).

use std::collections::{HashMap, VecDeque};

use bytes::Bytes;
use viewstamp_proto::{BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchBuilder, Prng, ReplyView};

use crate::{
  checker::CheckResult,
  cluster::{AppliedEvent, Cluster},
  sm::{SIM_REPLY_BODY_BUDGET, SIM_UNIT_REPLY_CEILING},
};

/// The request-body budget the model packs each body against — the first axis of the dual-budget
/// rule, standing in for the driver's `submit_byte_limit`. Kept SMALL (far under the 16 MiB frame)
/// so the byte budget genuinely binds within a run: the point of the lane is batching semantics
/// under chaos, not size stress.
pub const SIM_REQUEST_BODY_BUDGET: usize = 1024;

/// The largest unit count one body may carry — the reply-side axis of the dual-budget rule,
/// mirroring the aggregator's `max_units_per_body`: admit units only while the CEILING-priced reply
/// (`BATCH_COUNT_OVERHEAD + units * (BATCH_UNIT_OVERHEAD + SIM_UNIT_REPLY_CEILING)`) still fits the
/// reply budget.
pub const fn sim_max_units_per_body() -> usize {
  (SIM_REPLY_BODY_BUDGET - BATCH_COUNT_OVERHEAD) / (BATCH_UNIT_OVERHEAD + SIM_UNIT_REPLY_CEILING)
}

/// Domain separator for a batching client's emission PRNG, so its unit stream is independent of
/// every other seeded stream derived from the same base seed.
const BATCH_EMIT_SEED_MAGIC: u64 = 0xBA7C_4E11_7E55_EE0D;

/// Configuration of one batching client's seeded emission. All draws come from a PRNG derived from
/// `(base seed, client id)`, so the unit stream is a pure function of the seed that never touches
/// the cluster's or the VOPR driver's action PRNG.
#[derive(Debug, Clone, Copy)]
pub struct BatchingConfig {
  /// The cluster base seed (mixed with the client id into the emission PRNG seed).
  pub seed: u64,
  /// The client id (the same value as `ClientModel::id`), the per-client mix.
  pub client: u128,
  /// Per tick the client emits `0..=max_rate` units; a rate that can exceed one is what queues an
  /// excess while a body is in flight — the excess is what forms multi-unit bodies.
  pub max_rate: u64,
  /// One in `group_denom` emissions is an atomic GROUP of 2..=4 units instead of a single unit.
  pub group_denom: u32,
  /// Unit payload sizes are drawn in `0..=max_unit_len` (zero-length units are codec-legitimate).
  pub max_unit_len: usize,
  /// Total units this client emits over the run (the closed-loop work budget); `0` makes the
  /// client purely script-driven (`enqueue_unit` / `enqueue_group`).
  pub auto_units: u64,
}

/// One queued submission: a single unit, or a whole atomic group that must ride ONE body.
#[derive(Debug)]
struct QueuedEntry {
  units: Vec<Bytes>,
  /// `Some(id)` for a group (all units share it in the bookkeeping); `None` for a lone unit.
  group: Option<u64>,
}

/// One unit of a packed body, as the model recorded it at pack time and resolved it at ack time.
#[derive(Debug)]
pub struct SubmittedUnit {
  bytes: Bytes,
  group: Option<u64>,
  reply: Option<Bytes>,
}

impl SubmittedUnit {
  /// The unit payload submitted (and packed) for this position.
  pub fn bytes(&self) -> &Bytes {
    &self.bytes
  }

  /// The group this unit belongs to, if any.
  pub fn group(&self) -> Option<u64> {
    self.group
  }

  /// The acked per-unit reply, once the body's reply was demultiplexed.
  pub fn reply(&self) -> Option<&Bytes> {
    self.reply.as_ref()
  }
}

/// One packed body: the request number it rode and its units in pack order (the vector position IS
/// the wire `unit_index`).
#[derive(Debug)]
pub struct SubmittedBody {
  request: u64,
  units: Vec<SubmittedUnit>,
  acked: bool,
}

impl SubmittedBody {
  /// The request number the body rode.
  pub fn request(&self) -> u64 {
    self.request
  }

  /// The packed units in wire order.
  pub fn units(&self) -> &[SubmittedUnit] {
    &self.units
  }

  /// Whether the body's reply has been received and demultiplexed.
  pub fn acked(&self) -> bool {
    self.acked
  }
}

/// The synchronous aggregator model one batching client runs: seeded unit emission, a FIFO queue,
/// dual-budget packing through the real [`BatchBuilder`], ack-time [`ReplyView`] demux, and the
/// per-unit bookkeeping the oracle consumes.
#[derive(Debug)]
pub struct BatchingClient {
  cfg: BatchingConfig,
  prng: Prng,
  queue: VecDeque<QueuedEntry>,
  auto_emitted: u64,
  next_group: u64,
  bodies: Vec<SubmittedBody>,
  bodies_with_multiple_units: u64,
  max_units_per_body: u64,
  groups_submitted: u64,
  units_acked: u64,
}

impl BatchingClient {
  /// A model with the given emission config. The emission PRNG is derived from
  /// `(seed, client, BATCH_EMIT_SEED_MAGIC)` so distinct clients on one seed draw independent unit
  /// streams.
  pub fn new(cfg: BatchingConfig) -> Self {
    let seed = cfg
      .seed
      .wrapping_mul(0x100_0000_01b3)
      .wrapping_add(cfg.client as u64)
      .wrapping_add((cfg.client >> 64) as u64)
      ^ BATCH_EMIT_SEED_MAGIC;
    Self {
      cfg,
      prng: Prng::new(seed),
      queue: VecDeque::new(),
      auto_emitted: 0,
      next_group: 0,
      bodies: Vec::new(),
      bodies_with_multiple_units: 0,
      max_units_per_body: 0,
      groups_submitted: 0,
      units_acked: 0,
    }
  }

  /// How many bodies packed MORE than one unit (the lane's headline non-vacuity witness: batching
  /// genuinely engaged). Monotone over the client's lifetime.
  pub fn bodies_with_multiple_units(&self) -> u64 {
    self.bodies_with_multiple_units
  }

  /// The largest unit count any single body carried. Monotone.
  pub fn max_units_per_body(&self) -> u64 {
    self.max_units_per_body
  }

  /// How many atomic groups were enqueued. Monotone.
  pub fn groups_submitted(&self) -> u64 {
    self.groups_submitted
  }

  /// How many units have been acked (reply demultiplexed and recorded). Monotone.
  pub fn units_acked(&self) -> u64 {
    self.units_acked
  }

  /// The packed bodies in submission order (the oracle's bookkeeping).
  pub fn bodies(&self) -> &[SubmittedBody] {
    &self.bodies
  }

  /// True once the client's work is drained: the auto-emission budget is exhausted, nothing is
  /// queued, and (the caller checks) nothing is in flight.
  pub fn is_drained(&self) -> bool {
    self.auto_emitted >= self.cfg.auto_units && self.queue.is_empty()
  }

  /// Permanently stop emitting and drop queued work (the churn-retire shape): pending units never
  /// reach consensus, which is exactly a departed client abandoning its queue.
  pub fn retire(&mut self) {
    self.auto_emitted = self.cfg.auto_units;
    self.queue.clear();
  }

  /// Asserts `units` fits an EMPTY body under both budgets — every queued entry must be packable,
  /// or the pack loop could wedge on an unpackable head. Emission sizes guarantee it; a scripted
  /// gate violating it is a test bug surfaced loudly.
  fn assert_admissible(units: &[Bytes]) {
    assert!(
      !units.is_empty(),
      "an empty entry has no encoding (the codec requires count >= 1)"
    );
    assert!(
      units.len() <= sim_max_units_per_body(),
      "entry of {} units exceeds the reply-budget unit cap {}",
      units.len(),
      sim_max_units_per_body()
    );
    let needed = BATCH_COUNT_OVERHEAD
      + units
        .iter()
        .map(|u| BATCH_UNIT_OVERHEAD + u.len())
        .sum::<usize>();
    assert!(
      needed <= SIM_REQUEST_BODY_BUDGET,
      "entry of {needed} encoded bytes exceeds the request budget {SIM_REQUEST_BODY_BUDGET}"
    );
  }

  /// Queue ONE unit.
  pub fn enqueue_unit(&mut self, unit: Bytes) {
    Self::assert_admissible(std::slice::from_ref(&unit));
    self.queue.push_back(QueuedEntry {
      units: vec![unit],
      group: None,
    });
  }

  /// Queue an atomic GROUP: all units ride one body, adjacent and in order, or defer whole.
  pub fn enqueue_group(&mut self, units: Vec<Bytes>) {
    assert!(units.len() >= 2, "a group is two or more units");
    Self::assert_admissible(&units);
    let id = self.next_group;
    self.next_group += 1;
    self.groups_submitted += 1;
    self.queue.push_back(QueuedEntry {
      units,
      group: Some(id),
    });
  }

  /// One seeded emission step (call once per tick): draw `0..=max_rate` emissions, each a single
  /// unit or — one in `group_denom` — an atomic group of 2..=4 units, until the auto budget is
  /// spent. All draws come from the client's own PRNG.
  pub fn step_emission(&mut self) {
    if self.auto_emitted >= self.cfg.auto_units {
      return;
    }
    let emissions = self.prng.below(self.cfg.max_rate + 1);
    for _ in 0..emissions {
      let remaining = self.cfg.auto_units - self.auto_emitted;
      if remaining == 0 {
        return;
      }
      let group_len = if self.prng.chance(1, self.cfg.group_denom) {
        (2 + self.prng.below(3)).min(remaining)
      } else {
        1
      };
      if group_len >= 2 {
        let units: Vec<Bytes> = (0..group_len).map(|_| self.draw_unit()).collect();
        self.auto_emitted += group_len;
        self.enqueue_group(units);
      } else {
        let unit = self.draw_unit();
        self.auto_emitted += 1;
        self.enqueue_unit(unit);
      }
    }
  }

  /// One seeded unit payload: a length in `0..=max_unit_len`, filled with PRNG bytes.
  fn draw_unit(&mut self) -> Bytes {
    let len = self.prng.below(self.cfg.max_unit_len as u64 + 1) as usize;
    let bytes: Vec<u8> = (0..len).map(|_| self.prng.next_u64() as u8).collect();
    Bytes::from(bytes)
  }

  /// True iff `entry` also fits the OPEN body alongside what is already packed — the aggregator's
  /// pack-time admission, atomic over the whole entry (a group packs whole or defers whole).
  fn fits_open_body(builder: &BatchBuilder, packed_units: usize, entry: &QueuedEntry) -> bool {
    let extra: usize = entry
      .units
      .iter()
      .map(|u| BATCH_UNIT_OVERHEAD + u.len())
      .sum();
    packed_units + entry.units.len() <= sim_max_units_per_body()
      && builder.bytes_used() + extra <= builder.budget()
  }

  /// Packs queued entries FIFO into one request body for `request`, up to the first entry that no
  /// longer fits (which stays queued and leads the next body). Returns `None` when nothing is
  /// queued. Records the body's units in the bookkeeping; the caller mints the sim `Request`.
  pub fn pack(&mut self, request: u64) -> Option<Bytes> {
    self.queue.front()?;
    let mut builder = BatchBuilder::new(SIM_REQUEST_BODY_BUDGET);
    let mut units = Vec::new();
    while let Some(entry) = self.queue.front() {
      if !Self::fits_open_body(&builder, units.len(), entry) {
        assert!(
          !builder.is_empty(),
          "enqueue admission lets every queued entry fit an empty body"
        );
        break;
      }
      let entry = self.queue.pop_front().expect("front exists");
      for unit in entry.units {
        builder
          .push(&unit)
          .expect("fits_open_body admitted the whole entry");
        units.push(SubmittedUnit {
          bytes: unit,
          group: entry.group,
          reply: None,
        });
      }
    }
    let body = builder
      .finish()
      .expect("a non-empty queue packs at least the head entry");
    if units.len() > 1 {
      self.bodies_with_multiple_units += 1;
    }
    self.max_units_per_body = self.max_units_per_body.max(units.len() as u64);
    self.bodies.push(SubmittedBody {
      request,
      units,
      acked: false,
    });
    Some(body)
  }

  /// Demultiplex the committed reply for `request`: parse with the real [`ReplyView`], assert the
  /// count matches the packed units, assert each unit's reply has the BatchSm per-unit shape
  /// (8 bytes, and consecutive units of one body carry CONSECUTIVE global unit counts — the units
  /// of a body apply back-to-back), and record each reply for the oracle. Panics on any mismatch:
  /// the sim only acks bodies the BatchSm applied, so a malformed or miscounted reply is a bug.
  pub fn on_ack(&mut self, request: u64, reply_body: &Bytes) {
    let body = self
      .bodies
      .iter_mut()
      .rev()
      .find(|b| b.request == request)
      .expect("an acked request was packed by this model");
    assert!(
      !body.acked,
      "one ack per request (the client model dedupes)"
    );
    let view = match ReplyView::parse(reply_body) {
      Ok(view) => view,
      Err(err) => panic!(
        "malformed reply body for request {request} ({} bytes): {err} — BatchSm only seals \
         codec-built replies, so this is a sim bug",
        reply_body.len()
      ),
    };
    assert_eq!(
      view.len(),
      body.units.len(),
      "request {request}: reply unit count diverges from the packed unit count"
    );
    let mut prev: Option<u64> = None;
    for (idx, (unit, reply)) in body.units.iter_mut().zip(view.units()).enumerate() {
      let count = u64::from_be_bytes(
        reply
          .try_into()
          .unwrap_or_else(|_| panic!("request {request} unit {idx}: reply is not 8 bytes")),
      );
      if let Some(prev) = prev {
        assert_eq!(
          count,
          prev + 1,
          "request {request} unit {idx}: units of one body apply back-to-back, so their unit \
           counts are consecutive"
        );
      }
      prev = Some(count);
      unit.reply = Some(Bytes::copy_from_slice(reply));
      self.units_acked += 1;
    }
    body.acked = true;
  }
}

/// The per-unit exactly-once oracle, extending the request-level `AppliedOnceChecker` down to
/// units. Run it post-quiesce (the VOPR lane runs it after the final quiesce; deterministic gates
/// run it at their own quiet points). For every ACKED unit of every batching client it asserts:
///
/// 1. the unit's request committed at exactly one op (read off the recorded apply streams — an
///    acked request absent from every stream is a lost committed op);
/// 2. on EVERY replica that applied that op, the recorded unit history holds exactly one entry at
///    `(op, unit_index)`, with bytes equal to the submitted bytes — the codec round-trip and the
///    one-apply-per-unit fact, judged per replica;
/// 3. the acked reply equals the SM's deterministic per-unit reply — `(position in the replica's
///    unit history + 1)` as 8 big-endian bytes — on every replica that applied it (divergent
///    positions across replicas would already be op-level divergence, but the unit level is judged
///    directly here);
/// 4. GROUP INTEGRITY: a group's units ride one body (one op) and occupy ADJACENT unit indices in
///    submission order.
///
/// At least one replica must have applied every acked unit's op. Returns the first violation.
pub fn check_batching(c: &Cluster) -> CheckResult {
  if (0..c.client_count()).all(|i| c.client(i).batched_bodies().is_empty()) {
    return CheckResult::Ok;
  }
  let events: Vec<&[(u64, AppliedEvent)]> = (0..c.replica_count())
    .map(|i| c.replica_applied_events(i))
    .collect();
  let histories: Vec<&[(u64, u32, Bytes)]> = (0..c.replica_count())
    .map(|i| c.replica_unit_history(i))
    .collect();
  let clients: Vec<(u128, &[SubmittedBody])> = (0..c.client_count())
    .map(|i| (c.client(i).id().get(), c.client(i).batched_bodies()))
    .collect();
  check_units(&events, &histories, &clients)
}

/// The oracle core behind [`check_batching`], pure over its inputs — each replica's apply stream,
/// each replica's recorded unit history, and each client's `(id, packed bodies)` — so every
/// violation arm is unit-testable without a live `Cluster` (the checker `fold` pattern).
fn check_units(
  events: &[&[(u64, AppliedEvent)]],
  histories: &[&[(u64, u32, Bytes)]],
  clients: &[(u128, &[SubmittedBody])],
) -> CheckResult {
  // (client, request) -> op, folded over every replica's apply stream (all incarnations: re-applies
  // converge on the same op or the request-level checker already flagged them; build defensively).
  let mut op_of: HashMap<(u128, u64), u64> = HashMap::new();
  for stream in events {
    for (_, ev) in *stream {
      if let AppliedEvent::Committed(commit) = ev {
        let key = (commit.client().get(), commit.request().get());
        let op = commit.op().get();
        if let Some(&prev) = op_of.get(&key) {
          if prev != op {
            return CheckResult::violation(format!(
              "client {} request {} applied at two ops ({prev} and {op}) — a request committed \
               twice (unit-level oracle)",
              key.0, key.1
            ));
          }
        } else {
          op_of.insert(key, op);
        }
      }
    }
  }

  // Per replica: (op, unit_index) -> (global unit position, bytes). A collision is impossible by
  // construction (each op applies once per state machine) — flagged defensively.
  type UnitIndex<'a> = HashMap<(u64, u32), (usize, &'a Bytes)>;
  let mut unit_maps: Vec<UnitIndex<'_>> = Vec::new();
  for (i, history) in histories.iter().enumerate() {
    let mut map = HashMap::new();
    for (k, (op, idx, bytes)) in history.iter().enumerate() {
      if map.insert((*op, *idx), (k, bytes)).is_some() {
        return CheckResult::violation(format!(
          "replica {i}: unit (op {op}, index {idx}) appears twice in the recorded unit history — \
           a unit was applied twice"
        ));
      }
    }
    unit_maps.push(map);
  }

  for &(client, bodies) in clients {
    // Group integrity, packing-level (judged on EVERY packed body, acked or not): a group's units
    // ride ONE body and occupy one contiguous run of indices within it, in submission order.
    let mut group_body: HashMap<u64, u64> = HashMap::new();
    for body in bodies {
      let request = body.request();
      let mut last_group: Option<u64> = None;
      let mut closed: Vec<u64> = Vec::new();
      for unit in body.units() {
        match (unit.group(), last_group) {
          (Some(g), Some(open)) if g == open => {}
          (Some(g), _) => {
            if closed.contains(&g) {
              return CheckResult::violation(format!(
                "client {client} request {request}: group {g} occupies non-adjacent unit indices \
                 — a group was split within its body"
              ));
            }
            match group_body.get(&g) {
              Some(&other) if other != request => {
                return CheckResult::violation(format!(
                  "client {client}: group {g} rides two bodies (requests {other} and {request}) \
                   — a group was split across bodies"
                ));
              }
              _ => {
                group_body.insert(g, request);
              }
            }
            if let Some(open) = last_group {
              closed.push(open);
            }
            last_group = Some(g);
          }
          (None, _) => {
            if let Some(open) = last_group.take() {
              closed.push(open);
            }
          }
        }
      }
    }
    for body in bodies {
      if !body.acked() {
        continue;
      }
      let request = body.request();
      let Some(&op) = op_of.get(&(client, request)) else {
        return CheckResult::violation(format!(
          "client {client}: acked batched request {request} was never applied on any replica — a \
           client-acked committed op was lost (unit-level oracle)"
        ));
      };
      let mut applied_somewhere = false;
      for (ri, map) in unit_maps.iter().enumerate() {
        // A replica that applied this op holds its unit 0 (every batch carries >= 1 unit).
        if !map.contains_key(&(op, 0)) {
          continue;
        }
        applied_somewhere = true;
        for (idx, unit) in body.units().iter().enumerate() {
          let Some(&(k, recorded)) = map.get(&(op, idx as u32)) else {
            return CheckResult::violation(format!(
              "replica {ri}: acked unit (client {client}, request {request}, index {idx}) is \
               missing from the unit history at op {op}"
            ));
          };
          if recorded != unit.bytes() {
            return CheckResult::violation(format!(
              "replica {ri}: unit (client {client}, request {request}, index {idx}) at op {op} \
               recorded different bytes than were submitted ({} vs {} bytes)",
              recorded.len(),
              unit.bytes().len()
            ));
          }
          let expect = Bytes::copy_from_slice(&((k as u64 + 1).to_be_bytes()));
          match unit.reply() {
            Some(reply) if *reply == expect => {}
            Some(reply) => {
              return CheckResult::violation(format!(
                "replica {ri}: unit (client {client}, request {request}, index {idx}) at op {op} \
                 acked reply {reply:?} diverges from the SM's deterministic per-unit reply \
                 {expect:?}"
              ));
            }
            None => {
              return CheckResult::violation(format!(
                "client {client} request {request} unit {idx}: the body is acked but the unit has \
                 no recorded reply — the demux bookkeeping is broken"
              ));
            }
          }
        }
        // Count equality SM-side: the op's recorded units end exactly at the body's unit count.
        if map.contains_key(&(op, body.units().len() as u32)) {
          return CheckResult::violation(format!(
            "replica {ri}: op {op} recorded more units than client {client} request {request} \
             submitted ({} submitted)",
            body.units().len()
          ));
        }
      }
      if !applied_somewhere {
        return CheckResult::violation(format!(
          "client {client}: acked batched request {request} (op {op}) is in no replica's unit \
           history — the batch body was acked but its units were never recorded"
        ));
      }
    }
  }
  CheckResult::Ok
}

#[cfg(test)]
mod tests {
  use super::*;

  fn cfg(auto_units: u64) -> BatchingConfig {
    BatchingConfig {
      seed: 7,
      client: 1,
      max_rate: 2,
      group_denom: 5,
      max_unit_len: 16,
      auto_units,
    }
  }

  #[test]
  fn packing_is_fifo_and_respects_the_byte_budget() {
    let mut b = BatchingClient::new(cfg(0));
    // Three units whose encoded sizes force a byte-budget split: each costs 4 + 400, the body
    // budget is 1024, so two fit (4 + 808 = 812) and the third (1216) defers.
    for tag in [1u8, 2, 3] {
      b.enqueue_unit(Bytes::from(vec![tag; 400]));
    }
    let body1 = b.pack(1).expect("queued units pack");
    let view = viewstamp_proto::BatchView::parse(&body1).expect("codec-built");
    assert_eq!(
      view.len(),
      2,
      "two 400-byte units fill the 1024-byte budget"
    );
    assert_eq!(view.unit(0).map(|u| u[0]), Some(1), "FIFO order");
    assert_eq!(view.unit(1).map(|u| u[0]), Some(2));
    let body2 = b.pack(2).expect("the deferred unit leads the next body");
    let view = viewstamp_proto::BatchView::parse(&body2).expect("codec-built");
    assert_eq!(view.len(), 1);
    assert_eq!(view.unit(0).map(|u| u[0]), Some(3));
    assert!(b.pack(3).is_none(), "an empty queue packs nothing");
    assert_eq!(b.bodies_with_multiple_units(), 1);
    assert_eq!(b.max_units_per_body(), 2);
  }

  #[test]
  fn packing_respects_the_reply_side_unit_cap() {
    let mut b = BatchingClient::new(cfg(0));
    // Tiny units: the byte budget would admit ~200, but the reply-side cap binds first.
    for _ in 0..sim_max_units_per_body() + 3 {
      b.enqueue_unit(Bytes::from_static(b"u"));
    }
    let body = b.pack(1).expect("packs");
    let view = viewstamp_proto::BatchView::parse(&body).expect("codec-built");
    assert_eq!(
      view.len(),
      sim_max_units_per_body(),
      "the ceiling-priced reply budget caps the unit count"
    );
    let rest = b.pack(2).expect("the excess leads the next body");
    assert_eq!(
      viewstamp_proto::BatchView::parse(&rest)
        .expect("codec-built")
        .len(),
      3
    );
  }

  #[test]
  fn a_group_packs_whole_or_defers_whole() {
    let mut b = BatchingClient::new(cfg(0));
    b.enqueue_unit(Bytes::from(vec![1u8; 700]));
    // The group needs 2 * (4 + 200) = 408 more bytes; 4 + 704 + 408 > 1024, so it defers whole.
    b.enqueue_group(vec![
      Bytes::from(vec![2u8; 200]),
      Bytes::from(vec![3u8; 200]),
    ]);
    let body1 = b.pack(1).expect("packs the lone unit");
    assert_eq!(
      viewstamp_proto::BatchView::parse(&body1)
        .expect("codec-built")
        .len(),
      1,
      "the body ships without the group"
    );
    let body2 = b.pack(2).expect("the group leads the next body");
    let view = viewstamp_proto::BatchView::parse(&body2).expect("codec-built");
    assert_eq!(view.len(), 2, "the group rides one body, whole");
    assert_eq!(b.groups_submitted(), 1);
    let groups: Vec<Option<u64>> = b.bodies()[1].units().iter().map(|u| u.group()).collect();
    assert_eq!(groups, vec![Some(0), Some(0)], "adjacent group bookkeeping");
  }

  #[test]
  fn on_ack_demuxes_and_records_per_unit_replies() {
    let mut b = BatchingClient::new(cfg(0));
    b.enqueue_unit(Bytes::from_static(b"a"));
    b.enqueue_unit(Bytes::from_static(b"bb"));
    let body = b.pack(1).expect("packs");
    // Apply through the real BatchSm to produce the genuine reply body.
    let mut sm = crate::sm::BatchSm::default();
    let reply =
      viewstamp_proto::StateMachine::apply(&mut sm, viewstamp_proto::OpNumber::with(1), &body);
    b.on_ack(1, &reply);
    assert_eq!(b.units_acked(), 2);
    let units = b.bodies()[0].units();
    assert_eq!(
      units[0].reply().map(|r| r.as_ref()),
      Some(&1u64.to_be_bytes()[..])
    );
    assert_eq!(
      units[1].reply().map(|r| r.as_ref()),
      Some(&2u64.to_be_bytes()[..])
    );
    assert!(b.bodies()[0].acked());
  }

  #[test]
  #[should_panic(expected = "reply unit count diverges")]
  fn on_ack_panics_on_a_count_mismatch() {
    let mut b = BatchingClient::new(cfg(0));
    b.enqueue_unit(Bytes::from_static(b"a"));
    b.enqueue_unit(Bytes::from_static(b"bb"));
    b.pack(1).expect("packs");
    // A one-unit reply for a two-unit body.
    let mut reply = BatchBuilder::new(64);
    reply.push(&1u64.to_be_bytes()).expect("fits");
    b.on_ack(1, &reply.finish().expect("non-empty"));
  }

  #[test]
  fn seeded_emission_is_deterministic_and_spends_the_budget() {
    let run = || {
      let mut b = BatchingClient::new(cfg(40));
      for _ in 0..200 {
        b.step_emission();
      }
      let mut shipped: Vec<Vec<u8>> = Vec::new();
      let mut request = 1;
      while let Some(body) = b.pack(request) {
        shipped.push(body.to_vec());
        request += 1;
      }
      (shipped, b.groups_submitted())
    };
    let (a, ga) = run();
    let (b, gb) = run();
    assert_eq!(a, b, "emission + packing is a pure function of the config");
    assert_eq!(ga, gb);
    assert!(!a.is_empty(), "the budget genuinely emitted units");
  }

  /// One fabricated apply-stream entry: op `op` committed `(client, request)`.
  fn committed(op: u64, client: u128, request: u64) -> (u64, AppliedEvent) {
    use viewstamp_proto::{ClientId, Committed, OpNumber, RequestNumber};
    (
      0,
      AppliedEvent::Committed(Committed::new(
        OpNumber::with(op),
        ClientId::new(client),
        RequestNumber::with(request),
        Bytes::new(),
      )),
    )
  }

  /// One fabricated acked unit with the deterministic reply for global position `count`.
  fn acked_unit(bytes: &'static [u8], group: Option<u64>, count: u64) -> SubmittedUnit {
    SubmittedUnit {
      bytes: Bytes::from_static(bytes),
      group,
      reply: Some(Bytes::copy_from_slice(&count.to_be_bytes())),
    }
  }

  /// One fabricated packed body.
  fn body(request: u64, acked: bool, units: Vec<SubmittedUnit>) -> SubmittedBody {
    SubmittedBody {
      request,
      units,
      acked,
    }
  }

  #[test]
  fn oracle_passes_a_consistent_fabrication() {
    let events = vec![committed(1, 7, 1)];
    let history: Vec<(u64, u32, Bytes)> = vec![
      (1, 0, Bytes::from_static(b"a")),
      (1, 1, Bytes::from_static(b"bb")),
    ];
    let bodies = vec![body(
      1,
      true,
      vec![acked_unit(b"a", None, 1), acked_unit(b"bb", None, 2)],
    )];
    assert!(check_units(&[&events], &[&history], &[(7, &bodies)]).is_ok());
  }

  #[test]
  fn oracle_flags_an_acked_body_never_applied() {
    // No replica's apply stream carries (client 7, request 1): the ack references a lost op.
    let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
    assert!(
      check_units(&[&[]], &[&[]], &[(7, &bodies)]).is_violation(),
      "an acked-but-never-applied batched request must be flagged"
    );
  }

  #[test]
  fn oracle_flags_an_op_with_no_unit_history() {
    // The request committed but no replica's unit history holds its op: the units vanished.
    let events = vec![committed(1, 7, 1)];
    let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
    assert!(
      check_units(&[&events], &[&[]], &[(7, &bodies)]).is_violation(),
      "an acked op missing from every unit history must be flagged"
    );
  }

  #[test]
  fn oracle_flags_rewritten_unit_bytes() {
    let events = vec![committed(1, 7, 1)];
    let history: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"X"))];
    let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
    assert!(
      check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
      "recorded unit bytes diverging from the submitted bytes must be flagged"
    );
  }

  #[test]
  fn oracle_flags_a_divergent_per_unit_reply() {
    let events = vec![committed(1, 7, 1)];
    let history: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"a"))];
    // The history position is 0, so the deterministic reply is 1 — an acked 5 diverges.
    let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 5)])];
    assert!(
      check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
      "an acked reply diverging from the SM's deterministic per-unit reply must be flagged"
    );
  }

  #[test]
  fn oracle_flags_a_missing_or_extra_unit_at_the_op() {
    let events = vec![committed(1, 7, 1)];
    // Missing: the body acked two units but the op's history holds one.
    let short: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"a"))];
    let two = vec![body(
      1,
      true,
      vec![acked_unit(b"a", None, 1), acked_unit(b"bb", None, 2)],
    )];
    assert!(
      check_units(&[&events], &[&short], &[(7, &two)]).is_violation(),
      "a unit missing from the op's history must be flagged"
    );
    // Extra: the op's history holds three units but the body submitted two.
    let long: Vec<(u64, u32, Bytes)> = vec![
      (1, 0, Bytes::from_static(b"a")),
      (1, 1, Bytes::from_static(b"bb")),
      (1, 2, Bytes::from_static(b"ghost")),
    ];
    assert!(
      check_units(&[&events], &[&long], &[(7, &two)]).is_violation(),
      "an op recording more units than were submitted must be flagged"
    );
  }

  #[test]
  fn oracle_flags_a_request_committed_at_two_ops() {
    let events = vec![committed(1, 7, 1), committed(2, 7, 1)];
    let history: Vec<(u64, u32, Bytes)> = vec![(1, 0, Bytes::from_static(b"a"))];
    let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
    assert!(
      check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
      "a request applied at two ops must be flagged"
    );
  }

  #[test]
  fn oracle_flags_a_duplicated_unit_in_a_history() {
    let events = vec![committed(1, 7, 1)];
    let history: Vec<(u64, u32, Bytes)> = vec![
      (1, 0, Bytes::from_static(b"a")),
      (1, 0, Bytes::from_static(b"a")),
    ];
    let bodies = vec![body(1, true, vec![acked_unit(b"a", None, 1)])];
    assert!(
      check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
      "a unit applied twice within one history must be flagged"
    );
  }

  #[test]
  fn oracle_flags_a_group_split_within_a_body() {
    // Group 0's units sit at indices 0 and 2 with a lone unit between them: non-adjacent.
    let events = vec![committed(1, 7, 1)];
    let history: Vec<(u64, u32, Bytes)> = vec![
      (1, 0, Bytes::from_static(b"g")),
      (1, 1, Bytes::from_static(b"x")),
      (1, 2, Bytes::from_static(b"g")),
    ];
    let bodies = vec![body(
      1,
      true,
      vec![
        acked_unit(b"g", Some(0), 1),
        acked_unit(b"x", None, 2),
        acked_unit(b"g", Some(0), 3),
      ],
    )];
    assert!(
      check_units(&[&events], &[&history], &[(7, &bodies)]).is_violation(),
      "a group on non-adjacent indices must be flagged"
    );
  }

  #[test]
  fn oracle_flags_a_group_split_across_bodies() {
    // Group 0 has one unit in request 1 and another in request 2: the atomic group was split.
    // Packing-level integrity is judged on unacked bodies too, so no events/history are needed.
    let bodies = vec![
      body(1, false, vec![acked_unit(b"g1", Some(0), 1)]),
      body(2, false, vec![acked_unit(b"g2", Some(0), 2)]),
    ];
    assert!(
      check_units(&[&[]], &[&[]], &[(7, &bodies)]).is_violation(),
      "a group riding two bodies must be flagged"
    );
  }
}

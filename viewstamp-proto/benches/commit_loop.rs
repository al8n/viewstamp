//! End-to-end committed-ops/sec through a single-process, in-memory 3-endpoint
//! cluster: a stream of small closed-loop client requests driven through
//! accept → prepare → ack → commit → apply → reply, with NO sockets and NO
//! threads — the Sans-I/O [`Endpoint`]s are driven directly, the way the proto's
//! own loopback fixtures drive them, over synchronous in-bench `Wal`/`Superblock`
//! impls (the crate's test fixtures are `#[cfg(test)]`-only, so the bench carries
//! its own minimal impls of the public traits). Messages deliver instantly and in
//! order; storage completes synchronously on poll — so the measurement is the
//! protocol's own per-op work (ingress, WAL submit/complete bookkeeping, quorum
//! counting, apply, reply, plus a checkpoint every `DEFAULT_CHECKPOINT_OPS` = 32
//! ops), not I/O.
//!
//! Each criterion iteration runs 4 closed-loop clients × 64 requests = 256
//! committed ops on a fresh 3-replica cluster; throughput is reported in
//! ELEMENTS (committed ops) per second.
//!
//! The `commit_loop_units_per_body` group measures edge-batching amortization through
//! the SAME loop: each request body carries 1 / 4 / 16 / 64 user units packed with
//! [`BatchBuilder`], and the state machine decodes the committed body with [`BatchView`],
//! applies each unit, and seals one result per unit into the reply with a
//! [`ReplyBuilder`]. Every variant commits the same 256 op bodies, so reporting
//! throughput in ELEMENTS (committed USER UNITS) per second makes the curve read the
//! amortization directly: per-unit cost is the roughly-constant per-op cost divided by
//! units-per-body, until per-unit decode/apply/reply work starts to bind.
//!
//! # Baseline — MACHINE-SPECIFIC, for trend comparison on the same box only
//!
//! Recorded from one local `cargo bench` run (Apple M1 Max, macOS,
//! rustc 1.98.0-nightly) as the initial reference point:
//!
//! | benchmark                        | time per 256 ops | throughput    |
//! |----------------------------------|------------------|---------------|
//! | `commit_loop/3_replicas_256_ops` | ~554 µs          | ~462 Kelem/s  |
//!
//! The amortization curve, from the same run shape (every row commits 256 bodies; the
//! elements are user units):
//!
//! | benchmark                       | time per 256 bodies | throughput     |
//! |---------------------------------|---------------------|----------------|
//! | `commit_loop_units_per_body/1`  | ~707 µs             | ~362 Kelem/s   |
//! | `commit_loop_units_per_body/4`  | ~901 µs             | ~1.14 Melem/s  |
//! | `commit_loop_units_per_body/16` | ~1.44 ms            | ~2.84 Melem/s  |
//! | `commit_loop_units_per_body/64` | ~3.62 ms            | ~4.53 Melem/s  |

use std::{
  collections::{BTreeMap, VecDeque},
  hint::black_box,
  time::Duration,
};

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use viewstamp_proto::{
  BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchBuilder, BatchView, BlockAddress, BlockStore,
  CheckpointRead, ClientId, Config, Endpoint, Header, Instant, MemberId, Membership, Message,
  OpNumber, Peer, ReadId, Recipient, ReplicaId, ReplyBuilder, Request, RequestNumber, SlotStatus,
  StateMachine, Superblock, SuperblockDone, VsrState, Wal, WalDone, WriteId, block_address,
  max_reply_body_len,
};

const REPLICAS: usize = 3;
const CLIENTS: u64 = 4;
const OPS_PER_CLIENT: u64 = 64;
const TOTAL_OPS: u64 = CLIENTS * OPS_PER_CLIENT;
/// The units-per-body axis of the amortization curve; every point commits the same
/// `TOTAL_OPS` bodies.
const UNITS_PER_BODY: [u64; 4] = [1, 4, 16, 64];
/// Every user unit is 8 small bytes — the same payload size the unbatched loop's whole
/// request body carries, so the curve varies ONLY the packing factor.
const UNIT_LEN: usize = 8;

/// A minimal synchronous in-memory WAL over the public [`Wal`] trait: appends/reads
/// complete immediately into the completion queue (drained by the endpoint's
/// `handle_storage`), honoring the only-durable visibility contract trivially
/// because completion is synchronous with submission.
#[derive(Default)]
struct BenchWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  done: VecDeque<WalDone>,
}

impl Wal for BenchWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }
  fn header(&self, op: OpNumber) -> Option<Header> {
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }
  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else {
      SlotStatus::Empty
    }
  }
  fn submit_append(&mut self, id: WriteId, op: OpNumber, header: Header, body: Bytes) {
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: ReadId, op: OpNumber) {
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(viewstamp_proto::ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) -> std::vec::Vec<WriteId> {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
    std::vec::Vec::new()
  }
  fn prune(&mut self, below: OpNumber) -> std::vec::Vec<WriteId> {
    self.entries.retain(|&op, _| op >= below.get());
    std::vec::Vec::new()
  }
  fn poll(&mut self) -> Option<WalDone> {
    self.done.pop_front()
  }
}

/// A minimal synchronous in-memory superblock over the public [`Superblock`]
/// trait: root/checkpoint writes land immediately (in submission order, per the
/// trait's serialized-writer contract) and complete on the next poll.
#[derive(Default)]
struct BenchSb {
  state: VsrState,
  checkpoint: Option<(OpNumber, Bytes)>,
  done: VecDeque<SuperblockDone>,
}

impl Superblock for BenchSb {
  fn state(&self) -> VsrState {
    self.state.clone()
  }
  fn submit_write(&mut self, id: WriteId, state: VsrState) {
    self.state = state;
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_write_checkpoint(&mut self, id: WriteId, op: OpNumber, snapshot: Bytes) {
    self.checkpoint = Some((op, snapshot));
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_read_checkpoint(&mut self, id: ReadId) {
    self.done.push_back(match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
      }
      None => SuperblockDone::Fault(id),
    });
  }
  fn poll(&mut self) -> Option<SuperblockDone> {
    self.done.pop_front()
  }
}

/// A deterministic counter state machine: `apply` is O(1) and `snapshot` is 8
/// bytes, so checkpoints stay cheap and the measurement isolates the protocol
/// (not a toy state machine's snapshot cost).
#[derive(Default)]
struct CounterSm {
  applied: u64,
}

impl CounterSm {
  fn snapshot(&self) -> Bytes {
    Bytes::copy_from_slice(&self.applied.to_be_bytes())
  }
}

impl StateMachine for CounterSm {
  type Image = Bytes;

  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    self.applied += 1;
    Bytes::new()
  }
  fn checkpoint_image(&self) -> Self::Image {
    self.snapshot()
  }
  fn materialize(image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    store.put(image.clone())
  }
  fn restore_seed(&self) -> Self {
    CounterSm::default()
  }
  fn restore(
    &mut self,
    root: BlockAddress,
    store: &viewstamp_proto::VerifiedView<'_>,
  ) -> Result<(), viewstamp_proto::RestoreError> {
    let block = store
      .read_block(root)
      .ok_or(viewstamp_proto::RestoreError::new(root))?;
    self.applied = u64::from_be_bytes(block[..].try_into().expect("an 8-byte counter snapshot"));
    Ok(())
  }
}

/// The batch-aware counterpart of [`CounterSm`]: every committed body is a batch, decoded
/// with [`BatchView`]; each unit is applied as the same O(1) counter bump, and one 8-byte
/// result per unit is sealed into the reply with a [`ReplyBuilder`] — the decode →
/// apply-per-unit → reply-per-unit shape a batch-aware embedder state machine runs, so
/// the measurement includes the real per-unit codec work.
#[derive(Default)]
struct BatchCounterSm {
  applied_units: u64,
}

impl StateMachine for BatchCounterSm {
  type Image = Bytes;

  fn apply(&mut self, _op: OpNumber, body: &[u8]) -> Bytes {
    let view = BatchView::parse(body).expect("the bench clients mint codec-built batch bodies");
    let mut reply = ReplyBuilder::new(max_reply_body_len(), UNIT_LEN);
    for _unit in view.units() {
      self.applied_units += 1;
      reply
        .push(&self.applied_units.to_be_bytes())
        .expect("8-byte unit replies of a small bench batch fit the reply budget");
    }
    reply
      .finish()
      .expect("a parsed batch carries at least one unit")
  }
  fn checkpoint_image(&self) -> Self::Image {
    self.snapshot()
  }
  fn materialize(image: &Self::Image, store: &mut dyn BlockStore) -> BlockAddress {
    store.put(image.clone())
  }
  fn restore_seed(&self) -> Self {
    BatchCounterSm::default()
  }
  fn restore(
    &mut self,
    root: BlockAddress,
    store: &viewstamp_proto::VerifiedView<'_>,
  ) -> Result<(), viewstamp_proto::RestoreError> {
    let block = store
      .read_block(root)
      .ok_or(viewstamp_proto::RestoreError::new(root))?;
    self.applied_units =
      u64::from_be_bytes(block[..].try_into().expect("an 8-byte counter snapshot"));
    Ok(())
  }
}

impl BatchCounterSm {
  fn snapshot(&self) -> Bytes {
    Bytes::copy_from_slice(&self.applied_units.to_be_bytes())
  }
}

/// A synchronous in-memory [`BlockStore`] for the bench: checkpoints write content-addressed blocks
/// into a `BTreeMap` and reads return them, so the SM's `checkpoint`/`restore` path runs without any
/// storage cost contaminating the protocol measurement.
#[derive(Default)]
struct BenchBlocks {
  blocks: BTreeMap<BlockAddress, Bytes>,
}
impl BlockStore for BenchBlocks {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.blocks.get(&addr).cloned()
  }
  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = block_address(&block);
    self.blocks.insert(addr, block);
    addr
  }
  fn flush(&mut self) -> Result<(), viewstamp_proto::BlockStoreError> {
    Ok(())
  }
  fn has_block(&self, addr: BlockAddress) -> bool {
    self.blocks.contains_key(&addr)
  }
}

struct Replica<S: StateMachine> {
  ep: Endpoint<S>,
  wal: BenchWal,
  sb: BenchSb,
  blocks: BenchBlocks,
  /// The execution-order witness of this replica's inline storage lane.
  block_lane: viewstamp_proto::BlockJobCursor,
}

/// One closed-loop client: at most one request in flight; the next is minted as
/// soon as the matching reply lands.
struct Client {
  id: ClientId,
  next: u64,
  inflight: Option<u64>,
}

/// Drive `TOTAL_OPS` requests — each carrying `body(request_number)` — to commitment on
/// a fresh 3-replica cluster of `S` state machines and return the reply count (asserted
/// complete). Fault-free and instant-delivery, so the run stays in view 0 with replica 0
/// as primary; timers are still fired every virtual millisecond, exactly like a driver
/// would, so heartbeats and checkpoint cadence run their normal course.
fn run_commit_loop<S, B>(body: B) -> u64
where
  S: StateMachine + Default,
  B: Fn(u64) -> Bytes,
{
  let mut reps: Vec<Replica<S>> = (0..REPLICAS)
    .map(|i| {
      let wal = BenchWal::default();
      let mut sb = BenchSb::default();
      // Genesis: format the fresh store (writes the durable genesis root) and take the runnable endpoint.
      let ep = Endpoint::new(
        Config::try_new(1, MemberId::new(i as u128)).expect("a valid 3-node config"),
        Membership::genesis(
          REPLICAS as u8,
          0,
          (0..REPLICAS as u128).map(MemberId::new).collect(),
        )
        .expect("a valid 3-node genesis membership"),
        0xBE7C_0FFE ^ (i as u64).wrapping_mul(0x1234_5678),
        S::default(),
        u64::MAX,
      )
      .commit(&wal, &mut sb)
      .expect("genesis commit formats the fresh bench store");
      Replica {
        ep,
        wal,
        sb,
        blocks: BenchBlocks::default(),
        block_lane: viewstamp_proto::BlockJobCursor::new(),
      }
    })
    .collect();
  let mut clients: Vec<Client> = (1..=CLIENTS)
    .map(|id| Client {
      id: ClientId::new(id as u128),
      next: 1,
      inflight: None,
    })
    .collect();

  let mut now = Instant::ZERO;
  let mut inbox: VecDeque<(usize, Peer, Message)> = VecDeque::new();
  let mut replies = 0u64;
  let mut rounds = 0u64;

  while replies < TOTAL_OPS {
    rounds += 1;
    assert!(
      rounds < 100_000,
      "commit loop wedged: {replies}/{TOTAL_OPS} replies after {rounds} rounds"
    );
    now = now + Duration::from_millis(1);

    // Closed-loop ingress: every idle client submits its next request to the
    // view-0 primary (replica 0), with the body the variant under measurement mints.
    for cl in &mut clients {
      if cl.inflight.is_none() && cl.next <= OPS_PER_CLIENT {
        let req = Request::new(cl.id, RequestNumber::with(cl.next), body(cl.next));
        cl.inflight = Some(cl.next);
        cl.next += 1;
        let r = &mut reps[0];
        r.ep.handle_message(
          now,
          &mut r.wal,
          &mut r.sb,
          Peer::Client(cl.id),
          Message::Request(req),
        );
      }
    }

    // Drain the cluster to quiescence at this instant: route every outgoing
    // message (instant, in-order delivery), pump storage completions, drain
    // events; repeat until a full pass moves nothing.
    loop {
      let mut moved = false;
      for (i, r) in reps.iter_mut().enumerate() {
        let from = Peer::Replica(ReplicaId::new(i as u16));
        while let Some(out) = r.ep.poll_message() {
          moved = true;
          let (to, msg) = (out.to(), out.into_msg());
          match to {
            Recipient::To(Peer::Replica(t)) => inbox.push_back((t.get() as usize, from, msg)),
            Recipient::To(Peer::Client(cid)) => {
              if let Message::Reply(rep) = msg {
                let cl = clients
                  .iter_mut()
                  .find(|c| c.id == cid)
                  .expect("a reply routes to a known client");
                if cl.inflight == Some(rep.request().get()) {
                  cl.inflight = None;
                  replies += 1;
                }
              }
            }
            Recipient::To(Peer::Member(_)) => {
              unreachable!(
                "the endpoint routes by Replica slot; Member is a transport-layer identity"
              )
            }
            Recipient::Backups => {
              for t in 0..REPLICAS {
                if t != i {
                  inbox.push_back((t, from, msg.clone()));
                }
              }
            }
            Recipient::AllReplicas => {
              for t in 0..REPLICAS {
                inbox.push_back((t, from, msg.clone()));
              }
            }
          }
        }
      }
      while let Some((to, from, msg)) = inbox.pop_front() {
        moved = true;
        let r = &mut reps[to];
        r.ep.handle_message(now, &mut r.wal, &mut r.sb, from, msg);
      }
      for r in &mut reps {
        // The bench's inline storage lane: drain the WAL/superblock completions, then execute one
        // queued block job and feed its completion back, until neither side produces work.
        loop {
          r.ep.handle_storage(now, &mut r.wal, &mut r.sb);
          let Some(job) = r.ep.poll_block_job() else {
            break;
          };
          let done = viewstamp_proto::execute_block_job(&mut r.block_lane, job, &mut r.blocks);
          r.ep.on_block_done(now, &mut r.wal, &mut r.sb, done);
        }
        while r.ep.poll_event().is_some() {}
      }
      if !moved {
        break;
      }
    }

    // Fire timers at the advanced instant (heartbeat / retransmit cadence), as a
    // real driver would each tick.
    for r in &mut reps {
      r.ep.handle_timeout(now, &mut r.wal, &mut r.sb);
    }
  }

  assert_eq!(replies, TOTAL_OPS, "every request commits and replies");
  replies
}

/// One request body of `units` user units for request number `next`, packed with the
/// production [`BatchBuilder`] against an exactly-sized budget; each unit is a distinct
/// 8-byte payload.
fn batch_body(units: u64, next: u64) -> Bytes {
  let mut builder =
    BatchBuilder::new(BATCH_COUNT_OVERHEAD + units as usize * (BATCH_UNIT_OVERHEAD + UNIT_LEN));
  for k in 0..units {
    builder
      .push(&(next * units + k).to_be_bytes())
      .expect("the budget is sized for exactly `units` units");
  }
  builder.finish().expect("at least one unit was pushed")
}

fn bench_commit_loop(c: &mut Criterion) {
  let mut g = c.benchmark_group("commit_loop");
  g.throughput(Throughput::Elements(TOTAL_OPS));
  g.bench_function("3_replicas_256_ops", |b| {
    b.iter(|| {
      black_box(run_commit_loop::<CounterSm, _>(|next| {
        Bytes::copy_from_slice(&next.to_be_bytes())
      }))
    })
  });
  g.finish();
}

fn bench_commit_loop_units_per_body(c: &mut Criterion) {
  let mut g = c.benchmark_group("commit_loop_units_per_body");
  for units in UNITS_PER_BODY {
    // Every point commits the same TOTAL_OPS bodies; the elements are USER UNITS, so
    // the per-point throughput reads the amortization factor off the report directly.
    g.throughput(Throughput::Elements(TOTAL_OPS * units));
    g.bench_with_input(BenchmarkId::from_parameter(units), &units, |b, &units| {
      b.iter(|| {
        black_box(run_commit_loop::<BatchCounterSm, _>(|next| {
          batch_body(units, next)
        }))
      })
    });
  }
  g.finish();
}

criterion_group!(benches, bench_commit_loop, bench_commit_loop_units_per_body);
criterion_main!(benches);

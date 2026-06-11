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
//! # Baseline — MACHINE-SPECIFIC, for trend comparison on the same box only
//!
//! Recorded from one local `cargo bench` run (Apple M1 Max, macOS,
//! rustc 1.98.0-nightly) as the initial reference point:
//!
//! | benchmark                        | time per 256 ops | throughput    |
//! |----------------------------------|------------------|---------------|
//! | `commit_loop/3_replicas_256_ops` | ~554 µs          | ~462 Kelem/s  |

use std::collections::{BTreeMap, VecDeque};
use std::hint::black_box;
use std::time::Duration;

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use viewstamp_proto::{
  CheckpointRead, ClientId, Config, Endpoint, Header, Instant, Message, OpId, OpNumber, Peer,
  Recipient, ReplicaId, Request, RequestNumber, SlotStatus, StateMachine, Superblock,
  SuperblockDone, VsrState, Wal, WalDone,
};

const REPLICAS: usize = 3;
const CLIENTS: u64 = 4;
const OPS_PER_CLIENT: u64 = 64;
const TOTAL_OPS: u64 = CLIENTS * OPS_PER_CLIENT;

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
  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    self.entries.insert(op.get(), (header, body));
    self.head = self.head.max(op.get());
    self.done.push_back(WalDone::Appended(id));
  }
  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    self.done.push_back(match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(viewstamp_proto::ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    });
  }
  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    self.head = self.head.min(above.get());
  }
  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
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
  fn submit_write(&mut self, id: OpId, state: VsrState) {
    self.state = state;
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    self.checkpoint = Some((op, snapshot));
    self.done.push_back(SuperblockDone::Wrote(id));
  }
  fn submit_read_checkpoint(&mut self, id: OpId) {
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

impl StateMachine for CounterSm {
  fn apply(&mut self, _op: OpNumber, _body: &[u8]) -> Bytes {
    self.applied += 1;
    Bytes::new()
  }
  fn snapshot(&self) -> Bytes {
    Bytes::copy_from_slice(&self.applied.to_be_bytes())
  }
  fn restore(&mut self, snapshot: &[u8]) {
    self.applied = u64::from_be_bytes(snapshot.try_into().expect("an 8-byte counter snapshot"));
  }
}

struct Replica {
  ep: Endpoint<CounterSm>,
  wal: BenchWal,
  sb: BenchSb,
}

/// One closed-loop client: at most one request in flight; the next is minted as
/// soon as the matching reply lands.
struct Client {
  id: ClientId,
  next: u64,
  inflight: Option<u64>,
}

/// Drive `TOTAL_OPS` small requests to commitment on a fresh 3-replica cluster and
/// return the reply count (asserted complete). Fault-free and instant-delivery, so
/// the run stays in view 0 with replica 0 as primary; timers are still fired every
/// virtual millisecond, exactly like a driver would, so heartbeats and checkpoint
/// cadence run their normal course.
fn run_commit_loop() -> u64 {
  let mut reps: Vec<Replica> = (0..REPLICAS)
    .map(|i| Replica {
      ep: Endpoint::new(
        Config::try_new(1, ReplicaId::new(i as u8), REPLICAS as u8).expect("a valid 3-node config"),
        0xBE7C_0FFE ^ (i as u64).wrapping_mul(0x1234_5678),
        CounterSm::default(),
      ),
      wal: BenchWal::default(),
      sb: BenchSb::default(),
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
    // view-0 primary (replica 0); the body is 8 small bytes.
    for cl in &mut clients {
      if cl.inflight.is_none() && cl.next <= OPS_PER_CLIENT {
        let req = Request::new(
          cl.id,
          RequestNumber::with(cl.next),
          Bytes::copy_from_slice(&cl.next.to_be_bytes()),
        );
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
      for i in 0..REPLICAS {
        let from = Peer::Replica(ReplicaId::new(i as u8));
        while let Some(out) = reps[i].ep.poll_message() {
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
        r.ep.handle_storage(now, &mut r.wal, &mut r.sb);
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

fn bench_commit_loop(c: &mut Criterion) {
  let mut g = c.benchmark_group("commit_loop");
  g.throughput(Throughput::Elements(TOTAL_OPS));
  g.bench_function("3_replicas_256_ops", |b| {
    b.iter(|| black_box(run_commit_loop()))
  });
  g.finish();
}

criterion_group!(benches, bench_commit_loop);
criterion_main!(benches);

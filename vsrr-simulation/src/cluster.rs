use core::time::Duration;

use vsrr_proto::{
  Config, DEFAULT_CHECKPOINT_OPS, Endpoint, Instant, Message, Outgoing, Peer, Prng, Recipient,
  ReplicaId,
};

use crate::client::ClientModel;
use crate::clock::Clock;
use crate::network::{Faults, InFlight, Network, Target};
use crate::sm::LogSm;
use crate::storage::{InMemorySuperblock, InMemoryWal, StorageFaults};

/// Mixed into the per-replica storage-fault seed so a replica's WAL/SB fault PRNG is independent of
/// its protocol PRNG (which uses a different mixer in `with_checkpoint_ops`).
const STORAGE_SEED_MAGIC: u64 = 0x5151_DEAD_BEEF_0F0F;

/// A deterministic single-thread cluster of `Endpoint<LogSm>` replicas + clients.
pub struct Cluster {
  replicas: Vec<Endpoint<LogSm>>,
  /// Per-replica write-ahead logs (persist across crashes; see `crash`).
  wals: Vec<InMemoryWal>,
  /// Per-replica superblocks (persist across crashes; see `crash`).
  sbs: Vec<InMemorySuperblock>,
  clients: Vec<ClientModel>,
  net: Network,
  clock: Clock,
  prng: Prng,
  /// The base seed, retained to re-derive a replica's per-replica seed on `restart`.
  seed: u64,
  faults: Faults,
  /// Seeded storage-fault plan applied to every replica's WAL + superblock (per-replica seed). The
  /// WAL/SB structs persist across crash/restart, so permanent verdicts (torn / bit-rot) and the
  /// fault PRNG survive a restart unchanged — recovery faces the same durable medium it crashed on.
  storage_faults: StorageFaults,
  replica_count: u8,
  /// The checkpoint interval, retained so `restart` rebuilds a replica with the same config.
  checkpoint_ops: u64,
  crashed: Vec<bool>,
  /// Partition group id per replica. Replica↔replica messages between different groups are
  /// dropped. All replicas start in group 0 (no partition).
  groups: Vec<u8>,
}

impl Cluster {
  /// Creates a cluster of `replicas` replicas and `clients` clients, each client
  /// issuing `requests_per_client` requests. No faults by default.
  pub fn new(replicas: u8, clients: u32, requests_per_client: u64, seed: u64) -> Self {
    Self::with_checkpoint_ops(
      replicas,
      clients,
      requests_per_client,
      seed,
      DEFAULT_CHECKPOINT_OPS,
    )
  }

  /// Like [`Cluster::new`] but with an explicit checkpoint interval, so short runs can exercise
  /// checkpoints + checkpoint-based recovery.
  pub fn with_checkpoint_ops(
    replicas: u8,
    clients: u32,
    requests_per_client: u64,
    seed: u64,
    checkpoint_ops: u64,
  ) -> Self {
    let replica_set: Vec<Endpoint<LogSm>> = (0..replicas)
      .map(|i| {
        let cfg = Config::with_checkpoint_ops(1, ReplicaId::new(i), replicas, checkpoint_ops)
          .expect("valid cluster config");
        Endpoint::new(
          cfg,
          seed ^ (i as u64).wrapping_mul(0x1234_5678),
          LogSm::default(),
        )
      })
      .collect();
    let client_set: Vec<ClientModel> = (0..clients)
      .map(|i| ClientModel::new((i as u128) + 1, requests_per_client))
      .collect();
    let n = replicas as usize;
    let storage_faults = StorageFaults::none();
    let (wals, sbs) = Self::seed_storage(replicas, seed, storage_faults);
    Self {
      replicas: replica_set,
      wals,
      sbs,
      clients: client_set,
      net: Network::new(),
      clock: Clock::new(),
      prng: Prng::new(seed),
      seed,
      faults: Faults::none(),
      storage_faults,
      replica_count: replicas,
      checkpoint_ops,
      crashed: vec![false; n],
      groups: vec![0; n],
    }
  }

  /// Builds the per-replica seeded WAL + superblock vectors. Each replica's storage gets a distinct
  /// seed derived from the base `seed`, its index, and [`STORAGE_SEED_MAGIC`], so fault decisions are
  /// reproducible per (seed, replica) yet independent across replicas.
  fn seed_storage(
    replicas: u8,
    seed: u64,
    faults: StorageFaults,
  ) -> (Vec<InMemoryWal>, Vec<InMemorySuperblock>) {
    let wals = (0..replicas)
      .map(|i| InMemoryWal::with_faults(faults, Self::storage_seed(seed, i)))
      .collect();
    let sbs = (0..replicas)
      .map(|i| InMemorySuperblock::with_faults(faults, Self::storage_seed(seed, i)))
      .collect();
    (wals, sbs)
  }

  /// The per-replica storage-fault seed.
  fn storage_seed(seed: u64, replica: u8) -> u64 {
    seed ^ (replica as u64).wrapping_mul(STORAGE_SEED_MAGIC) ^ STORAGE_SEED_MAGIC
  }

  /// Replaces the network fault model (call before running).
  pub fn set_faults(&mut self, faults: Faults) {
    self.faults = faults;
  }

  /// Replaces the storage fault model (call before running). Re-seeds every replica's (empty) WAL +
  /// superblock with the new plan, mirroring [`Cluster::set_faults`] for the network. Permanent
  /// verdicts (torn / bit-rot) and the fault PRNG then live in the durable structs and survive a
  /// `crash` + `restart` unchanged — a restarted replica recovers from the same faulty medium.
  pub fn set_storage_faults(&mut self, faults: StorageFaults) {
    self.storage_faults = faults;
    let (wals, sbs) = Self::seed_storage(self.replica_count, self.seed, faults);
    self.wals = wals;
    self.sbs = sbs;
  }

  /// The current virtual instant.
  pub fn now(&self) -> Instant {
    self.clock.now()
  }

  /// Read access to replica `i`'s state machine (for invariant checking).
  pub fn replica_sm(&self, i: usize) -> &LogSm {
    self.replicas[i].state_machine()
  }

  /// Replica `i`'s current view (for invariant checking).
  pub fn replica_view(&self, i: usize) -> vsrr_proto::View {
    self.replicas[i].view()
  }

  /// Replica `i`'s current checkpoint op (for invariant checking / boundedness gates).
  pub fn replica_checkpoint_op(&self, i: usize) -> vsrr_proto::OpNumber {
    self.replicas[i].checkpoint_op()
  }

  /// True iff replica `i` is participating in consensus (`Normal` or `ViewChange`) — i.e. it is NOT
  /// still recovering (`Recovering`/`RecoveringHead`). Used by the disk-fault gate to confirm a
  /// restarted replica drove its `Recovering` loop to a participating state.
  pub fn replica_status_is_operational(&self, i: usize) -> bool {
    let s = self.replicas[i].status();
    s.is_normal() || s.is_view_change()
  }

  /// Read access to client `i` (for invariant checking).
  pub fn client(&self, i: usize) -> &ClientModel {
    &self.clients[i]
  }

  /// Number of replicas (for invariant checking).
  pub fn replica_count(&self) -> usize {
    self.replicas.len()
  }

  /// Number of clients.
  pub fn client_count(&self) -> usize {
    self.clients.len()
  }

  /// True once all clients are done and nothing is in flight.
  pub fn is_quiescent(&self) -> bool {
    self.net.is_empty() && self.clients.iter().all(ClientModel::is_done)
  }

  /// Crash-stop replica `i`: it stops being ticked and its messages are dropped. Its durable
  /// `wals[i]`/`sbs[i]` are left intact so a later `restart` can recover from them.
  pub fn crash(&mut self, i: usize) {
    self.crashed[i] = true;
  }

  /// Restart a previously-crashed replica: rebuild it from its durable WAL + superblock via
  /// `Endpoint::recover`. Re-derives the same per-replica config + seed used in `new`, so the
  /// recovered replica keeps its identity. Its in-memory state (log cache, SM) is reconstructed
  /// from storage; everything not yet durable is lost (as a real crash would lose it).
  ///
  /// `recover` is now a metadata-only constructor that returns in `Status::Recovering` and drives
  /// its WAL-tail (+ checkpoint) reads via `handle_storage` (retrying any fault). We pump
  /// `handle_storage` here in a bounded loop so the replica reaches `Normal`/`RecoveringHead` before
  /// the next `tick` — keeping the existing "assert state right after restart" gates stable. (The
  /// main `tick` loop also pumps `handle_storage` every tick, so an un-pumped restart would still
  /// recover; this pump is purely for test-assertion timing.)
  pub fn restart(&mut self, i: usize) {
    let cfg = Config::with_checkpoint_ops(
      1,
      ReplicaId::new(i as u8),
      self.replica_count,
      self.checkpoint_ops,
    )
    .expect("valid cluster config");
    let seed = self.seed ^ (i as u64).wrapping_mul(0x1234_5678);
    let now = self.clock.now();
    self.replicas[i] = Endpoint::recover(
      cfg,
      seed,
      LogSm::default(),
      &mut self.wals[i],
      &mut self.sbs[i],
    );
    // Drain the Recovering read loop to completion. Bounded by the WAL-tail length × the per-slot
    // retry budget plus a margin; a fault that never clears within this leaves the replica
    // Recovering/RecoveringHead and the per-tick `handle_storage` keeps trying.
    for _ in 0..4_096 {
      if !self.replicas[i].status().is_recovering() {
        break;
      }
      self.replicas[i].handle_timeout(now, &mut self.wals[i], &mut self.sbs[i]);
      self.replicas[i].handle_storage(now, &mut self.wals[i], &mut self.sbs[i]);
    }
    self.crashed[i] = false;
  }

  /// Whether replica `i` is crashed.
  pub fn is_crashed(&self, i: usize) -> bool {
    self.crashed[i]
  }

  #[doc(hidden)]
  pub fn wal_head_for_test(&self, i: usize) -> u64 {
    use vsrr_proto::Wal;
    self.wals[i].op_head().get()
  }

  /// Test-only: how many of replica `i`'s WAL slots in `1..=op` are PERMANENTLY corrupt (bit-rot or
  /// torn) — i.e. would read back faulty. The M3.3b permanent-fault gate uses this to assert recovery
  /// is non-vacuous (the crashed replica genuinely must peer-repair some rotted committed slot).
  #[doc(hidden)]
  pub fn wal_corrupt_slots_at_or_below_for_test(&self, i: usize, op: u64) -> usize {
    self.wals[i].corrupt_slots_at_or_below_for_test(op)
  }

  /// Partition the replicas into groups: `groups[i]` is replica `i`'s group id. Replica↔replica
  /// messages between different groups are dropped until `heal`. (Client↔replica traffic is unaffected.)
  pub fn partition(&mut self, groups: Vec<u8>) {
    assert_eq!(
      groups.len(),
      self.replicas.len(),
      "one group id per replica"
    );
    self.groups = groups;
  }

  /// Heal all partitions (a single group).
  pub fn heal(&mut self) {
    self.groups = vec![0; self.replicas.len()];
  }

  /// Whether replica↔replica traffic between replicas `a` and `b` is currently partitioned.
  pub fn partitioned(&self, a: u8, b: u8) -> bool {
    self.groups[a as usize] != self.groups[b as usize]
  }

  /// One simulation step.
  pub fn tick(&mut self) {
    let now = self.clock.now();

    for ci in 0..self.clients.len() {
      if let Some(req) = self.clients[ci].pending(now) {
        let from = Peer::Client(self.clients[ci].id());
        for ri in 0..self.replicas.len() {
          if !self.crashed[ri] {
            self.schedule(
              now,
              from,
              Target::Replica(ri as u8),
              Message::Request(req.clone()),
            );
          }
        }
      }
    }

    // Collect outgoing messages from each replica first, then route — avoids a
    // simultaneous &mut self.replicas[ri] + &mut self borrow conflict in route().
    let mut outgoing: Vec<(ReplicaId, Outgoing)> = Vec::new();
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      while let Some(out) = self.replicas[ri].poll_message() {
        outgoing.push((ReplicaId::new(ri as u8), out));
      }
    }
    for (from, out) in outgoing {
      self.route(now, from, out);
    }

    // Deliver due network messages. handle_message indexes self.replicas/wals/sbs
    // directly — those are disjoint from self.net, self.clients, self.crashed.
    for m in self.net.take_due(now) {
      match m.target {
        Target::Replica(idx) => {
          let ri = idx as usize;
          if !self.crashed[ri] {
            self.replicas[ri].handle_message(
              now,
              &mut self.wals[ri],
              &mut self.sbs[ri],
              m.from,
              m.msg,
            );
          }
        }
        Target::Client(id) => {
          if let Some(c) = self.clients.iter_mut().find(|c| c.id().get() == id) {
            c.handle(m.msg);
          }
        }
      }
    }

    // Pump storage completions: drives append-before-ack (on_wal_done) + durable-view (on_sb_done).
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      self.replicas[ri].handle_storage(now, &mut self.wals[ri], &mut self.sbs[ri]);
    }

    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      while self.replicas[ri].poll_event().is_some() {}
    }

    let next = [
      self.net.next_deadline(),
      self
        .replicas
        .iter()
        .enumerate()
        .filter(|(ri, _)| !self.crashed[*ri])
        .filter_map(|(_, ep)| ep.poll_timeout())
        .min(),
    ]
    .into_iter()
    .flatten()
    .min();
    let target = match next {
      Some(t) if t > now => t,
      _ => now + Duration::from_millis(1),
    };
    self.clock.advance_to(target);

    let now = self.clock.now();
    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      self.replicas[ri].handle_timeout(now, &mut self.wals[ri], &mut self.sbs[ri]);
      // Pump storage after timeout: drives append-before-ack (on_wal_done) + durable-view (on_sb_done).
      self.replicas[ri].handle_storage(now, &mut self.wals[ri], &mut self.sbs[ri]);
    }
  }

  /// Expands a `Recipient` into concrete `Target`s and schedules each.
  fn route(&mut self, now: Instant, from: ReplicaId, out: Outgoing) {
    // Belt-and-suspenders: a crashed replica should never be polled, but
    // drop any outgoing it might emit just in case.
    if self.crashed[from.get() as usize] {
      return;
    }
    let (to, msg) = (out.to(), out.into_msg());
    match to {
      Recipient::To(Peer::Replica(r)) => {
        self.schedule(now, Peer::Replica(from), Target::Replica(r.get()), msg);
      }
      Recipient::To(Peer::Client(c)) => {
        self.schedule(now, Peer::Replica(from), Target::Client(c.get()), msg);
      }
      Recipient::Backups => {
        for idx in 0..self.replica_count {
          if idx != from.get() {
            self.schedule(now, Peer::Replica(from), Target::Replica(idx), msg.clone());
          }
        }
      }
      Recipient::AllReplicas => {
        for idx in 0..self.replica_count {
          self.schedule(now, Peer::Replica(from), Target::Replica(idx), msg.clone());
        }
      }
    }
  }

  /// Applies the fault model and (unless dropped) enqueues a message.
  fn schedule(&mut self, now: Instant, from: Peer, target: Target, msg: Message) {
    if let (Peer::Replica(from_r), Target::Replica(to_r)) = (from, target) {
      if self.partitioned(from_r.get(), to_r) {
        return;
      }
    }
    if self.faults.drop_per_mille > 0 && self.prng.chance(self.faults.drop_per_mille, 1000) {
      return;
    }
    let jitter_ns = if self.faults.jitter.is_zero() {
      0
    } else {
      self.prng.below(self.faults.jitter.as_nanos() as u64)
    };
    let deliver_at = now + self.faults.latency + Duration::from_nanos(jitter_ns);
    self.net.enqueue(InFlight {
      deliver_at,
      from,
      target,
      msg,
      seq: 0,
    });
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::storage::StorageFaults;

  #[test]
  fn one_node_cluster_ticks() {
    let mut cluster = Cluster::new(1, 1, 1, /*seed*/ 7);
    let t0 = cluster.now();
    for _ in 0..50 {
      cluster.tick();
    }
    assert!(cluster.now() > t0, "virtual clock must advance");
  }

  #[test]
  fn restart_recovers_through_the_recovering_loop_under_faults() {
    let mut c = Cluster::new(3, 1, 3, 5);
    // TRANSIENT read faults on every replica's WAL (no permanent corruption); the recover loop must
    // retry through them and reach Normal.
    c.set_storage_faults(StorageFaults {
      read_fault_per_mille: 100,
      ..StorageFaults::none()
    });
    let mut warm = false;
    for _ in 0..40_000 {
      c.tick();
      if !c.replica_sm(1).applied().is_empty() {
        warm = true;
        break;
      }
    }
    assert!(warm, "replica 1 commits >= 1 op before the crash");
    c.crash(1);
    for _ in 0..500 {
      c.tick();
    }
    c.restart(1); // metadata-only recover + bounded handle_storage pump (retries the faulted reads)
    // After restart the replica is operational (Normal or ViewChange) — never stranded in Recovering,
    // because the faults are transient and clear within the proto's retry budget.
    assert!(
      c.replica_status_is_operational(1),
      "restart drives the Recovering loop to Normal under transient faults"
    );
  }

  #[test]
  fn crashed_replica_stops_and_is_skipped() {
    let mut c = Cluster::new(3, 1, 1, 7);
    c.crash(0);
    assert!(c.is_crashed(0));
    // ticking must not panic and must not deliver to/from the crashed replica.
    for _ in 0..20 {
      c.tick();
    }
    // a crashed primary means no commits; the (single) client cannot finish without view change,
    // but the loop must run cleanly.
    assert!(c.now().as_nanos() > 0);
  }

  #[test]
  fn partition_groups_block_cross_group_traffic() {
    let mut c = Cluster::new(5, 1, 1, 3);
    assert!(!c.partitioned(0, 3), "no partition by default");
    c.partition(vec![0, 0, 0, 1, 1]); // {0,1,2} | {3,4}
    assert!(c.partitioned(0, 3), "cross-group is blocked");
    assert!(!c.partitioned(0, 1), "same-group is not blocked");
    assert!(!c.partitioned(3, 4), "same-group is not blocked");
    c.heal();
    assert!(!c.partitioned(0, 3), "heal removes all partitions");
  }
}

use core::time::Duration;

use vsrr_proto::{Config, Endpoint, Instant, Message, Outgoing, Peer, Prng, Recipient, ReplicaId};

use crate::client::ClientModel;
use crate::clock::Clock;
use crate::network::{Faults, InFlight, Network, Target};
use crate::sm::LogSm;

/// A deterministic single-thread cluster of `Endpoint<LogSm>` replicas + clients.
pub struct Cluster {
  replicas: Vec<Endpoint<LogSm>>,
  clients: Vec<ClientModel>,
  net: Network,
  clock: Clock,
  prng: Prng,
  faults: Faults,
  replica_count: u8,
  crashed: Vec<bool>,
  /// Partition group id per replica. Replica↔replica messages between different groups are
  /// dropped. All replicas start in group 0 (no partition).
  groups: Vec<u8>,
}

impl Cluster {
  /// Creates a cluster of `replicas` replicas and `clients` clients, each client
  /// issuing `requests_per_client` requests. No faults by default.
  pub fn new(replicas: u8, clients: u32, requests_per_client: u64, seed: u64) -> Self {
    let replica_set: Vec<Endpoint<LogSm>> = (0..replicas)
      .map(|i| {
        let cfg = Config::try_new(1, ReplicaId::new(i), replicas).expect("valid cluster config");
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
    Self {
      replicas: replica_set,
      clients: client_set,
      net: Network::new(),
      clock: Clock::new(),
      prng: Prng::new(seed),
      faults: Faults::none(),
      replica_count: replicas,
      crashed: vec![false; n],
      groups: vec![0; n],
    }
  }

  /// Replaces the fault model (call before running).
  pub fn set_faults(&mut self, faults: Faults) {
    self.faults = faults;
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

  /// Crash-stop replica `i`: it stops being ticked and its messages are dropped.
  pub fn crash(&mut self, i: usize) {
    self.crashed[i] = true;
  }

  /// Whether replica `i` is crashed.
  pub fn is_crashed(&self, i: usize) -> bool {
    self.crashed[i]
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

    for ri in 0..self.replicas.len() {
      if self.crashed[ri] {
        continue;
      }
      while let Some(out) = self.replicas[ri].poll_message() {
        self.route(now, ReplicaId::new(ri as u8), out);
      }
    }

    for m in self.net.take_due(now) {
      match m.target {
        Target::Replica(idx) => {
          if !self.crashed[idx as usize] {
            self.replicas[idx as usize].handle_message(now, m.from, m.msg);
          }
        }
        Target::Client(id) => {
          if let Some(c) = self.clients.iter_mut().find(|c| c.id().get() == id) {
            c.handle(m.msg);
          }
        }
      }
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
      self.replicas[ri].handle_timeout(now);
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

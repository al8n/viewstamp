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
}

impl Cluster {
  /// Creates a cluster of `replicas` replicas and `clients` clients, each client
  /// issuing `requests_per_client` requests. No faults by default.
  pub fn new(replicas: u8, clients: u32, requests_per_client: u64, seed: u64) -> Self {
    let replica_set: Vec<Endpoint<LogSm>> = (0..replicas)
      .map(|i| {
        let cfg = Config::new(1, ReplicaId::new(i), replicas);
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
    Self {
      replicas: replica_set,
      clients: client_set,
      net: Network::new(),
      clock: Clock::new(),
      prng: Prng::new(seed),
      faults: Faults::none(),
      replica_count: replicas,
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

  /// Read access to client `i` (for invariant checking).
  pub fn client(&self, i: usize) -> &ClientModel {
    &self.clients[i]
  }

  /// Number of clients.
  pub fn client_count(&self) -> usize {
    self.clients.len()
  }

  /// True once all clients are done and nothing is in flight.
  pub fn is_quiescent(&self) -> bool {
    self.net.is_empty() && self.clients.iter().all(ClientModel::is_done)
  }

  /// The current primary index (M1: always view 0 -> replica 0).
  fn primary_index(&self) -> u8 {
    0
  }

  /// One simulation step.
  pub fn tick(&mut self) {
    let now = self.clock.now();

    let primary = self.primary_index();
    for ci in 0..self.clients.len() {
      if let Some(req) = self.clients[ci].pending() {
        let from = Peer::Client(self.clients[ci].id());
        self.schedule(now, from, Target::Replica(primary), Message::Request(req));
      }
    }

    for ri in 0..self.replicas.len() {
      while let Some(out) = self.replicas[ri].poll_message() {
        self.route(now, ReplicaId::new(ri as u8), out);
      }
    }

    for m in self.net.take_due(now) {
      match m.target {
        Target::Replica(idx) => {
          self.replicas[idx as usize].handle_message(now, m.from, m.msg);
        }
        Target::Client(id) => {
          if let Some(c) = self.clients.iter_mut().find(|c| c.id().get() == id) {
            c.handle(m.msg);
          }
        }
      }
    }

    for ri in 0..self.replicas.len() {
      while self.replicas[ri].poll_event().is_some() {}
    }

    let next = [
      self.net.next_deadline(),
      self
        .replicas
        .iter()
        .filter_map(Endpoint::poll_timeout)
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
      self.replicas[ri].handle_timeout(now);
    }
  }

  /// Expands a `Recipient` into concrete `Target`s and schedules each.
  fn route(&mut self, now: Instant, from: ReplicaId, out: Outgoing) {
    let Outgoing { to, msg } = out;
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
}

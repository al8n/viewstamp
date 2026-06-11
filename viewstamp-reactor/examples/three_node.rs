//! Three-node viewstamp cluster over real loopback TCP.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p viewstamp-reactor --example three_node --features tokio
//! ```
//!
//! The `tokio` feature pulls in the concrete `agnostic` runtime this example runs on (hence the
//! example's `required-features` gate); the drivers themselves are generic over any
//! `agnostic::Runtime`, so the same embedding runs on smol by swapping the runtime parameter and
//! feature.
//!
//! Three replicas run in one process, each on its own driver task, speaking the `Labeled`
//! cleartext handshake over plain TCP (`Labeled<Passthrough>`). A few operations are submitted
//! through a BACKUP replica — which relays them to the primary — and the committed replies are
//! printed. Plaintext keeps the example focused on the embedder's obligations; a production
//! cluster wraps each link in TLS (`Labeled<TlsRecords>`, see `tests/stream_loopback.rs`) or uses
//! the QUIC driver, whose cluster-private mTLS is mandatory (see `tests/loopback.rs`).
//!
//! What the embedder supplies, narrated inline below:
//! - **Durable storage** — a [`Wal`] (the operation log) and a [`Superblock`] (the durable root +
//!   checkpoints) per replica. This example uses the simulation crate's in-memory fixtures;
//!   replace them with your durable implementation. The contracts a real backend must honor
//!   (completion-means-durable, writes never fault, header durability independent of bodies,
//!   serialized crash-atomic root writes) are consolidated in `viewstamp_proto::storage`'s
//!   module docs — read them before writing a disk backend.
//! - **A storage-ready notifier** — the driver parks between events; the storage side signals the
//!   notifier when completions are ready to poll.
//! - **A durable client session** — a `ClientId` + the last-used request number, so a restarted
//!   process never re-mints a request number the cluster already served.
//! - **A state machine** — deterministic `apply`/`snapshot`/`restore` (here: the simulation
//!   crate's `LogSm`, which replies with the post-apply op count).

use std::{net::SocketAddr, sync::Arc};

use agnostic::tokio::TokioRuntime;
use bytes::Bytes;
use viewstamp_proto::{
  ClientId, Config, Conn, LabelOptions, Labeled, Passthrough, Peer, ReplicaId, Superblock, Wal,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal, sm::LogSm};

/// The cluster id every node (and the `Labeled` handshake) must agree on. Pick one per cluster;
/// a node presenting a different id is rejected at the handshake.
const CLUSTER: u128 = 0xD0C5;

/// Wraps a storage impl and signals the driver's storage-ready notifier on every submit.
///
/// THE NOTIFIER CONTRACT: the driver's event loop parks waiting on I/O, commands, timers, and
/// this notifier; it polls `Wal::poll`/`Superblock::poll` only when woken. A REAL asynchronous
/// backend (io_uring, a thread pool) signals the notifier when a completion lands. The in-memory
/// fixtures used here are synchronous — every submit completes immediately — so the wrapper
/// signals right at submit. Without a signal the driver would never wake to drain the completion
/// and the cluster would stall.
struct Notifying<T> {
  inner: T,
  ready: flume::Sender<()>,
}

impl<T> Notifying<T> {
  fn new(inner: T, ready: flume::Sender<()>) -> Self {
    Self { inner, ready }
  }

  fn signal(&self) {
    let _ = self.ready.try_send(());
  }
}

/// Pure delegation plus the submit-time signal. A real embedder implements `Wal` directly over
/// its durable log; this delegating shape exists only to bolt the notifier onto the in-memory
/// fixture.
impl<T: Wal> Wal for Notifying<T> {
  fn op_head(&self) -> viewstamp_proto::OpNumber {
    self.inner.op_head()
  }
  fn header(&self, op: viewstamp_proto::OpNumber) -> Option<viewstamp_proto::Header> {
    self.inner.header(op)
  }
  fn status(&self, op: viewstamp_proto::OpNumber) -> viewstamp_proto::SlotStatus {
    self.inner.status(op)
  }
  fn capacity(&self) -> u64 {
    self.inner.capacity()
  }
  fn submit_append(
    &mut self,
    id: viewstamp_proto::OpId,
    op: viewstamp_proto::OpNumber,
    header: viewstamp_proto::Header,
    body: Bytes,
  ) {
    self.inner.submit_append(id, op, header, body);
    self.signal();
  }
  fn submit_read(&mut self, id: viewstamp_proto::OpId, op: viewstamp_proto::OpNumber) {
    self.inner.submit_read(id, op);
    self.signal();
  }
  fn truncate(&mut self, above: viewstamp_proto::OpNumber) {
    self.inner.truncate(above);
  }
  fn prune(&mut self, below: viewstamp_proto::OpNumber) {
    self.inner.prune(below);
  }
  fn poll(&mut self) -> Option<viewstamp_proto::WalDone> {
    self.inner.poll()
  }
}

impl<T: Superblock> Superblock for Notifying<T> {
  fn state(&self) -> viewstamp_proto::VsrState {
    self.inner.state()
  }
  fn submit_write(&mut self, id: viewstamp_proto::OpId, state: viewstamp_proto::VsrState) {
    self.inner.submit_write(id, state);
    self.signal();
  }
  fn submit_write_checkpoint(
    &mut self,
    id: viewstamp_proto::OpId,
    op: viewstamp_proto::OpNumber,
    snapshot: Bytes,
  ) {
    self.inner.submit_write_checkpoint(id, op, snapshot);
    self.signal();
  }
  fn submit_read_checkpoint(&mut self, id: viewstamp_proto::OpId) {
    self.inner.submit_read_checkpoint(id);
    self.signal();
  }
  fn poll(&mut self) -> Option<viewstamp_proto::SuperblockDone> {
    self.inner.poll()
  }
}

#[tokio::main]
async fn main() {
  // Fixed loopback addresses, one per replica. Every node knows the full address map up front:
  // viewstamp clusters have a static membership (no discovery protocol).
  let addrs: Vec<SocketAddr> = (0..3)
    .map(|i| format!("127.0.0.1:{}", 47200 + i).parse().unwrap())
    .collect();

  let mut handles = Vec::new();
  for id in 0u8..3 {
    // The peer map: everyone but me.
    let peers: Vec<(ReplicaId, SocketAddr)> = (0u8..3)
      .filter(|&p| p != id)
      .map(|p| (ReplicaId::new(p), addrs[p as usize]))
      .collect();

    // The cluster config: (cluster id, my replica id, cluster size). Replica ids are the dense
    // indices 0..n; view 0's primary is replica 0.
    let config = Config::try_new(CLUSTER, ReplicaId::new(id), 3).unwrap();

    // EMBEDDER OBLIGATION — storage. A fresh in-memory Wal + Superblock per replica, wrapped with
    // the storage-ready notifier. Replace `InMemoryWal`/`InMemorySuperblock` with your durable
    // implementations (see the `viewstamp_proto::storage` module docs for the contracts). The
    // driver inspects the store at build time: genesis state boots fresh, any durable state takes
    // the recover path — restart-over-the-same-store is how a crashed node rejoins.
    let (ready_tx, ready_rx) = flume::unbounded();
    let wal = Notifying::new(InMemoryWal::new(), ready_tx.clone());
    let sb = Notifying::new(InMemorySuperblock::new(), ready_tx);

    // EMBEDDER OBLIGATION — the record layer. The dialer/acceptor factories hand the driver a
    // `Conn` per peer link. `Labeled` runs the cluster-id + peer-identity handshake; wrapping
    // `Passthrough` keeps the bytes cleartext. Swap in `TlsRecords` for TLS without touching
    // anything else. The factories are `Arc<dyn .. + Send + Sync>` so the driver holding them
    // stays `Send` — its `run()` future must be spawnable on a multi-threaded runtime.
    let mk_dialer: Arc<dyn Fn(Peer) -> Conn<Labeled<Passthrough>> + Send + Sync> = {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(id)));
      Arc::new(move |_peer| Conn::from_parts(Labeled::dialer(Passthrough::new(), &opts)))
    };
    let mk_acceptor: Arc<dyn Fn() -> Conn<Labeled<Passthrough>> + Send + Sync> = {
      let opts = LabelOptions::new(CLUSTER, Peer::Replica(ReplicaId::new(id)));
      Arc::new(move || Conn::from_parts(Labeled::acceptor(Passthrough::new(), &opts)))
    };

    // EMBEDDER OBLIGATION — the client session. `ClientId` names this node's local submit session
    // and must be unique across the cluster; the cluster deduplicates requests per client, so a
    // restarted process must either persist its last request number (passing it as
    // `first_request`) or use a fresh `ClientId` — this example starts fresh at 0.
    let session = ClientId::new(u128::from(id) + 1);

    // The runtime parameter (`TokioRuntime`) is the only type the constructor cannot infer; the
    // construction binds the listener, so it must run inside the runtime that will poll it.
    let (driver, handle) = viewstamp_reactor::ReactorStreamDriver::<TokioRuntime, _, _, _, _>::new(
      config,
      LogSm::default(), // EMBEDDER OBLIGATION — the deterministic state machine.
      wal,
      sb,
      session,
      0, // first_request: fresh session, so the first minted request is 1.
      addrs[id as usize],
      peers,
      mk_dialer,
      mk_acceptor,
      ready_rx,
    )
    .await
    .expect("driver builds and binds its listener");

    // One driver task per replica; the returned `Handle` is the application's way in. The dropped
    // `JoinHandle` DETACHES the task (a tokio drop never cancels), so each run loop keeps driving
    // on its own.
    drop(tokio::spawn(driver.run()));
    handles.push(handle);
  }

  // Submit through replica 1 — a BACKUP in view 0. The coordinator relays the request to the
  // primary over the replica mesh, so the application can talk to any node. `submit` resolves
  // once the op is COMMITTED (replicated to a quorum) and applied locally.
  for n in 1u64..=3 {
    let body = format!("op-{n}");
    let reply = handles[1]
      .submit(Bytes::from(body.clone()))
      .await
      .expect("the cluster commits the request");
    // `LogSm::apply` replies with the post-apply op count as 8 big-endian bytes.
    let count = u64::from_be_bytes(reply[..].try_into().expect("LogSm replies with 8 bytes"));
    println!("committed {body:?}; state machine has applied {count} op(s)");
  }

  // Graceful shutdown: each handle tells its driver to stop; dropping the last handle would too.
  for h in &handles {
    let _ = h.shutdown().await;
  }
  println!("cluster shut down cleanly");
}

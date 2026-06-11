# UNRELEASED

Nothing has been released yet; everything below is the current state of the tree.

- **Consensus core (`viewstamp-proto`)** — the Sans-I/O Viewstamped Replication state
  machine: normal operation, view change, crash recovery, checkpoints + post-checkpoint
  GC, state-sync (with chunked transfer for over-frame checkpoints), peer repair
  (including a windowed bulk-repair channel for header-only view-change carriers),
  durable committed-band headers, append-before-ack and
  durable-view-before-participate gating, a physical bounded-WAL ring with
  stall-before-wrap, and pluggable `Wal`/`Superblock`/`StateMachine` contracts.
- **Deterministic simulation + VOPR (`viewstamp-simulation`)** — a seeded
  single-threaded cluster simulator with per-tick safety/durability/liveness checkers,
  adversarial fault axes (crash + fsync loss, network reorder/drop/duplicate/delay/hold,
  one-way partitions, slow-replica delays, storage torn/bit-rot/misdirected-read
  faults, wipe-and-restart, client churn), a committed sweep gate with pinned
  regression seeds, and nightly wide-seed CI lanes.
- **TCP + TLS transport (`viewstamp-proto`, features `tcp`/`tls`)** — Sans-I/O stream
  transport: length-prefixed framing with a bounded incremental decoder, a typed
  per-connection lifecycle, the `Labeled` cluster/identity handshake, an optional rustls
  record layer, peer routing with single-source outbound caps, and a
  `StreamCoordinator` composing it all over the endpoint.
- **QUIC transport (`viewstamp-proto`, feature `quic`)** — quinn-proto-based transport
  with mandatory cluster-private mTLS, certificate-based peer identity (`CertOid` /
  `Hello`), configurable stream layout, and a `QuicCoordinator` mirroring the stream
  coordinator.
- **compio drivers (`viewstamp-compio`)** — real-I/O drivers on the compio proactor
  runtime: a QUIC driver and a TCP/TLS stream driver, both generic over storage and
  state machine, with durable-state boot/recovery, client-session submit/reply handles,
  bounded in-flight budgets, and reconnect/redial management.

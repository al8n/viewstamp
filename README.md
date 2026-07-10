<div align="center">
<h1>viewstamp</h1>
</div>
<div align="center">

Pure-Rust Viewstamped Replication: a Sans-I/O consensus state machine, QUIC and TCP+TLS transports, real-I/O drivers, and a deterministic adversarial simulator.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/viewstamp-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Fviewstamp" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/viewstamp/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/viewstamp?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076" height="22">

</div>

## Introduction

`viewstamp` is a [Viewstamped Replication] consensus library in pure Rust. The protocol
logic lives in a single Sans-I/O "super state machine" — modeled on `quinn-proto`: it
takes events as inputs (`handle_*`) and emits actions as outputs (`poll_*`), owning no
I/O, no clock, and no randomness source. [TigerBeetle]'s `src/vsr/replica.zig` is the
correctness reference for the protocol logic, including its storage-fault model: WAL
corruption (torn writes, bit-rot, misdirected reads) is part of the fault model, not an
afterthought, and faults surface as data the protocol repairs from peers — never as
panics.

## Threat model — non-Byzantine, crash-fault-tolerant

viewstamp is **crash-fault-tolerant** for a **trusted** cluster, exactly like
TigerBeetle — explicitly **not** Byzantine-fault-tolerant. It tolerates crash-stop
failures, storage faults, and network partitions, assuming honest, authenticated
participants. Authenticating a message's sender is the **driver's** job (the QUIC
transport mandates cluster-private mTLS; the proto keeps a cheap sender-binding ingress
backstop against a buggy or misrouting driver). Cryptographic message authentication
against a genuinely malicious replica — signatures, BFT voting — is out of scope.

## Workspace

| Crate | What it is |
|---|---|
| [`viewstamp-proto`](viewstamp-proto) | The Sans-I/O consensus core (`no_std` + `alloc` capable), plus feature-gated Sans-I/O transports: `tcp` (length-prefixed framing + connection lifecycle + peer routing), `tls` (rustls record layer), `quic` (quinn-proto with mandatory cluster-private mTLS). |
| [`viewstamp-driver`](viewstamp-driver) | The runtime-agnostic driver core shared by both driver crates: the embedder `Handle`/`Command` surface, in-flight submit budgets, the `DriverConfig` tuning surface, the `Clock`, and `DriverError`. |
| [`viewstamp-compio`](viewstamp-compio) | Real-I/O drivers on the [compio] proactor runtime: a QUIC driver and a TCP/TLS stream driver. Generic over storage, state machine, and identity — they bundle no backend. |
| [`viewstamp-simulation`](viewstamp-simulation) | The deterministic simulation harness + the VOPR adversarial sweep (see below). Also home of the in-memory `Wal`/`Superblock` fixtures. |
| [`viewstamp-reactor`](viewstamp-reactor) | Reactor-I/O drivers on tokio or smol via the [agnostic] runtime abstraction: a QUIC driver and a TCP/TLS stream driver. Generic over storage, state machine, and identity — they bundle no backend. |

## Quickstart

A runnable three-node cluster over real loopback TCP lives in
[`viewstamp-compio/examples/three_node.rs`](viewstamp-compio/examples/three_node.rs):

```sh
cargo run -p viewstamp-compio --example three_node
```

The same embedding over the reactor drivers (on tokio) lives in
[`viewstamp-reactor/examples/three_node.rs`](viewstamp-reactor/examples/three_node.rs):

```sh
cargo run -p viewstamp-reactor --example three_node --features tokio
```

Each boots three in-process replicas, submits a few operations through a backup (which
relays to the primary), prints the committed replies, and shuts down. The comments
narrate each embedder obligation — storage, client identity, the driver handle — and the
examples use the simulation crate's in-memory storage, which you replace with your
durable implementation in production.

## The embedder contract

The proto owns no log and no disk: you supply a `Wal` (the operation log) and a
`Superblock` (the durable root + checkpoints), and the consensus core orchestrates over
them. The contracts those implementations must honor — completion-means-durable,
writes-never-fault, header durability independent of bodies, crash-atomic serialized
root writes, drain-in-flight-before-recover — are consolidated in the
[`storage` module documentation](viewstamp-proto/src/storage/mod.rs). Read that before
writing a backend; each clause is load-bearing for committed-op survival.

The state machine side is three methods (`apply` / `snapshot` / `restore`), required to
be deterministic across replicas.

### Edge batching

Many small operations can share one consensus op: callers hand individual units (or
atomic groups) to a batching aggregator, which consumes a driver `Handle`, packs
everything queued into the next request body while one is in flight, and demultiplexes
each committed reply back to its callers. Your `apply` then decodes each committed body
with the shared codec — `BatchView` in, one result per unit out through a
`ReplyBuilder`:

```rust,ignore
let (batch, pump) = aggregator(handle, BatchConfig::new(max_unit_reply_len));
// spawn pump.run() exactly like the driver's own run(); then, from any task:
let reply = batch.submit(unit).await?;
```

A body applies atomically (it is one op) and a group is never split across bodies, but
batches are not transactions — units stay independent operations that share an op. The
codec layout, the request/reply budget contracts, and the aggregator's retry-contract
error taxonomy are documented in the
[`batch` module](viewstamp-proto/src/batch.rs) and the
[`aggregate` module](viewstamp-driver/src/aggregate.rs).

## Validation: the VOPR

The flagship test rig is a [VOPR-style] deterministic simulator
(`viewstamp-simulation`): N endpoints + client models in one thread over a virtual
network with a virtual clock and one seeded PRNG, so **a whole cluster run is a pure
function of its seed** — any failure replays exactly.

Each seed builds a fresh cluster (size 2–6) and explores a randomized adversarial
schedule within the crash-stop fault model (a quorum always survives):

- **Process faults** — crash + restart, with in-flight (un-fsynced) WAL appends
  discarded at the crash boundary; a wipe lane where a crashed replica rejoins with an
  empty disk.
- **Network faults** — reorder, drop, duplicate, delay; a hold lane where messages are
  held arbitrarily long and released late; a one-way (asymmetric) partition lane and a
  slow-replica (gray-failure) lane.
- **Storage faults** — read faults, torn writes, bit-rot, misdirected reads (a read
  returning a wrong-but-valid sibling slot), recover-time fault injection.
- **Structural axes** — async WAL + async superblock completion windows, small and
  large checkpoint intervals, a physical bounded-WAL ring on a third of seeds
  (stall-before-wrap, recovery off a wrapped ring), and a client-churn lane driving
  the session-cap eviction.

Safety, durability, view-monotonicity, boundedness, append-before-ack, and
ring-residency invariants are checked every tick; liveness is judged over calm windows
on virtual time. The committed CI gate sweeps seeds `0..64` plus a pinned list of every
seed that ever caught a real bug; a nightly release-mode workflow sweeps `0..1024` (plus
the hold lane) and is verified clean out to `0..2048`. To replay one seed:

```sh
VOPR_SEED=<seed> cargo test -p viewstamp-simulation --test vopr replay_single_seed -- --ignored --nocapture
```

Byte-decode surfaces (`Message`, the superblock root, the WAL header codec, the stream
transport ingress) are additionally fuzzed under `cargo fuzz` (see [`fuzz/`](https://github.com/al8n/viewstamp/tree/main/fuzz)).

## Status

Pre-0.1 and unpublished. The wire format and the on-disk formats are **unstable**:
versions are checked and mismatches rejected, but there is no cross-version
compatibility story yet — upgrades are flag-day. APIs will move.

### Versioning and upgrades

The wire protocol and the durable formats version **independently**, so a
message-format change can never invalidate data already on disk:

- **Messages** ride a protobuf envelope, normatively defined by the schema
  ([`proto/viewstamp/v1/messages.proto`](viewstamp-proto/proto/viewstamp/v1/messages.proto));
  [`viewstamp-proto/WIRE.md`](viewstamp-proto/WIRE.md) pins the byte-level semantics.
  There is no per-message version field — the `Labeled` hello's `HELLO_VERSION` is
  the single wire-version fence instead, and mixed-version peers reject each other
  at the handshake before any consensus frame is trusted. An additive protobuf
  field needs no bump; a semantic break to the wire bumps `HELLO_VERSION`.
- **Durable formats** carry their own versions
  ([`viewstamp-proto/src/storage/mod.rs`](viewstamp-proto/src/storage/mod.rs)): the
  superblock root leads with `SUPERBLOCK_VERSION` and decodes by
  **compatibility range** — the whole layout-compatible range
  `1..=SUPERBLOCK_VERSION` is accepted, so a wire-only bump never strands a
  persisted root — and each WAL slot header leads with its own `HEADER_VERSION`.

Pre-1.0 the cluster upgrade story is **flag-day**: stop all replicas, upgrade all
of them, restart — mixed-version clusters are rejected at connect time by the
handshake fence above. Rolling upgrades require wire-version negotiation (accept
a range, speak the lowest common version), which is future work.

#### License

`viewstamp` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2021 Al Liu.

[Github-url]: https://github.com/al8n/viewstamp/
[CI-url]: https://github.com/al8n/viewstamp/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/viewstamp/
[Viewstamped Replication]: https://pmg.csail.mit.edu/papers/vr-revisited.pdf
[TigerBeetle]: https://github.com/tigerbeetle/tigerbeetle
[VOPR-style]: https://docs.tigerbeetle.com/concepts/safety/
[compio]: https://github.com/compio-rs/compio
[agnostic]: https://github.com/al8n/agnostic

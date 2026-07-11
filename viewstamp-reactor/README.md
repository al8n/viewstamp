<div align="center">
<h1>viewstamp-reactor</h1>
</div>
<div align="center">

Reactor-I/O (readiness) QUIC and TCP/TLS drivers for `viewstamp-proto`.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/viewstamp-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/viewstamp/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/viewstamp?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076" height="22">

</div>

One task owns a [`viewstamp_proto::QuicCoordinator`] ([`ReactorQuicDriver`]) or a
[`viewstamp_proto::StreamCoordinator`] ([`ReactorStreamDriver`]) plus the embedder's
[`viewstamp_proto::Wal`]/[`viewstamp_proto::Superblock`] and its socket, and drives
consensus over real sockets on any runtime implementing [`agnostic::Runtime`] — tokio or smol,
pulled in by this crate's `tokio`/`smol` features (the drivers themselves are generic over the
runtime parameter and compile against the abstraction alone). The drivers are generic over the
state machine, storage, and (for QUIC) identity source — they bundle no backend, and all
TLS/framing lives in-process in the proto coordinators; the drivers only move raw bytes.

## Scaling across cores

One consensus group is one serial state machine: a single driver owns its endpoint, storage,
and socket, and `run()` drives them as ONE task — the QUIC driver spawns nothing, and the
stream driver spawns only per-connection read/write bridge tasks (plus dial tasks) whose
handles it owns abort-on-drop, so they die with their connection. There is no parallelism
inside a group, and none would help: consensus applies committed operations in log order, so
one group's throughput ceiling is one core by design.

Unlike the compio drivers, whose `!Send` tasks are pinned to the thread that spawned them, the
`run()` future is `Send` (given `Send` state-machine/storage/identity types): a work-stealing
multi-threaded runtime schedules or migrates it like any other task, and the group stays
serial because it is one task, not because of any thread pinning. Scale-out is N INDEPENDENT
groups as N driver tasks on one shared runtime — each driver binds its own socket/port, owns
its own WAL/superblock store, and forms its own replica mesh, so groups share nothing and the
runtime spreads them across cores. For explicit core pinning, run N single-thread runtimes
(e.g. tokio's `current_thread` flavor, one per pinned core) with one driver task each; the
caveat is that a socket must be polled by the runtime that registered it, and construction
binds the sockets, so construct AND `run()` a driver inside the runtime that owns it — never
build it on one runtime and ship it to another.

[`Handle`]s are the cross-thread surface: a `Handle` is `Send + Sync` and O(1) to clone, so
any thread may `submit` to any group and await the committed reply — the bounded command
channel and the per-submit reply channel do the crossing.

[Github-url]: https://github.com/al8n/viewstamp/
[CI-url]: https://github.com/al8n/viewstamp/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/viewstamp/

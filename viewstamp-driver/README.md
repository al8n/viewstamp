<div align="center">
<h1>viewstamp-driver</h1>
</div>
<div align="center">

Runtime-agnostic driver core shared by the viewstamp driver crates.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/viewstamp-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/viewstamp/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/viewstamp?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076" height="22">

</div>

A driver binds `viewstamp-proto`'s Sans-I/O consensus endpoint to a real runtime; this crate is
the runtime-independent half of that job, shared by every driver: the embedder-facing
[`Handle`] and its [`Command`] protocol, the in-flight submit budget the handle reserves
against, the [`DriverConfig`] tuning surface, the [`Clock`] anchoring the proto's monotonic
instants to std time, the session run-loop helpers (endpoint construction, pending-submit
bookkeeping, retransmission, committed-event delivery), the [`DriverError`] type drivers
surface to the application, and the edge-batching [`aggregator`] coalescing many caller units
into one consensus op per submit.

See the [workspace README](https://github.com/al8n/viewstamp) for the full project overview,
and [`viewstamp-compio`] / [`viewstamp-reactor`] for the concrete real-I/O drivers built on
this core.

[Github-url]: https://github.com/al8n/viewstamp/
[CI-url]: https://github.com/al8n/viewstamp/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/viewstamp/
[`viewstamp-compio`]: https://github.com/al8n/viewstamp/tree/main/viewstamp-compio
[`viewstamp-reactor`]: https://github.com/al8n/viewstamp/tree/main/viewstamp-reactor

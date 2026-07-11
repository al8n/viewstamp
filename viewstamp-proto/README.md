<div align="center">
<h1>viewstamp-proto</h1>
</div>
<div align="center">

Sans-I/O state machine for the Viewstamped Replication protocol.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/viewstamp-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/viewstamp/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/viewstamp?style=for-the-badge&token=6R3QFWRWHL&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge&fontColor=white&logoColor=f5c076" height="22">

</div>

Modeled on `quinn-proto`: a pure state machine that takes events as inputs
(`handle_*`) and emits actions as outputs (`poll_*`), owning no I/O, no clock,
and no randomness source. TigerBeetle's `src/vsr/replica.zig` is the
correctness reference for the protocol logic.

## Threat model (non-Byzantine, crash-fault-tolerant)

viewstamp is a **crash-fault-tolerant** Viewstamped Replication implementation for a **TRUSTED**
cluster — exactly like TigerBeetle, and explicitly **NOT** a Byzantine-fault-tolerant /
blockchain system. Authenticating a replica message's sender is the **DRIVER's** responsibility:
the driver sets the `from: Peer` it passes to [`Endpoint::handle_message`] to the AUTHENTICATED
transport peer (mirroring TigerBeetle's `message_bus.zig` `set_and_verify_peer`), and the proto
TRUSTS that `from`. As a cheap **defense-in-depth** backstop, `handle_message`'s ingress binds each
message's own self-claimed sender to `from` and drops any mismatch, so a BUGGY or misrouting driver
(or a trivially-mislabeled message) cannot let a forged/misrouted message spoof a quorum vote — the
ingress analogue of the single egress emission chokepoint. Full message authentication against a
genuinely MALICIOUS sender (cryptographic signatures, Byzantine fault tolerance) is **OUT OF
SCOPE** — a BFT/blockchain concern, not a crash-fault-tolerant one.

See the [workspace README](https://github.com/al8n/viewstamp) for the full project overview,
capabilities, and the VOPR simulator.

[Github-url]: https://github.com/al8n/viewstamp/
[CI-url]: https://github.com/al8n/viewstamp/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/viewstamp/

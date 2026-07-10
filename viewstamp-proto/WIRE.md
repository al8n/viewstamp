# viewstamp wire format (normative)

This document pins the byte-level encoding of everything `viewstamp-proto` puts on a wire or a
disk: the consensus envelope, the stream/QUIC frame, and the `Labeled` hello. **Any wire-affecting
change below MUST bump `HELLO_VERSION`** (`src/transport/labeled/mod.rs`) so mixed-version nodes
reject each other at the handshake instead of mis-decoding consensus traffic. The golden byte
vectors in `src/wire/tests.rs` (`golden_byte_vectors`) pin one encoded exemplar of every `Message`
variant; a deliberate wire-format change updates this document, the schema, the vectors, and
`HELLO_VERSION` in the same commit.

## 1. The consensus envelope (`Message`, `PreparedEntry`, `ReconfigurePayload`)

The envelope is **protobuf (proto3)**, defined normatively by
[`proto/viewstamp/v1/messages.proto`](proto/viewstamp/v1/messages.proto) and generated into the
crate at build time (via `buffa`). One transport frame (§2) carries exactly one
`viewstamp.v1.Message`; a membership-change log entry's `PreparedEntry.body_state` oneof carries
one `viewstamp.v1.ReconfigurePayload`. The schema file is the field reference — this section pins
the SEMANTICS.

**Envelope semantics (protobuf, accepted as-is):**

- Absent scalar fields decode as zero/empty — identical in meaning to an explicit zero (proto3's
  default-value rule); this equivalence applies to SCALARS. For the exactly-16-byte id/checksum
  `bytes` fields (below), an absent field decodes as EMPTY bytes and is REJECTED by the length
  check, so absence is NOT equivalent to an explicit all-zero 16-byte id (which decodes to `0`
  and is accepted).
- Duplicate fields follow protobuf merge semantics precisely: duplicate singular SCALAR fields are
  last-wins; duplicate singular EMBEDDED-MESSAGE fields MERGE their field sets; a `oneof`
  re-occurrence of the SAME message-typed variant (e.g. two `PreparedEntry.reconfigure` arms in
  sequence) MERGES like any embedded message, while a DIFFERENT variant (e.g. `present` then
  `repairing_checksum`) REPLACES the body wholesale; repeated fields (a `log`,
  `ReconfigurePayload.members`) concatenate. An independent implementation must reproduce these
  rules exactly — a decoder that merges where this crate replaces (or vice versa) accepts a
  different set of byte strings than this crate does.
- Unknown fields are skipped, bounded at `MAX_UNKNOWN_FIELDS` (16 — `src/wire/mod.rs`) per
  envelope — FORWARD COMPATIBILITY: a newer node may add fields without breaking an older decoder.
  Past the bound, decode rejects rather than materialize unbounded transient state from a
  field-flood. A new field whose MEANING an old node must not silently ignore still requires a
  `HELLO_VERSION` bump (§3) — the unknown-field allowance is tolerance for genuinely-optional
  additions, not a general escape from versioning.
- Overlong varints reject (protobuf's 10-byte varint cap); nested messages are
  recursion-depth-limited; every declared length (a `bytes`/`string`/sub-message size) is
  bounds-checked against the remaining input BEFORE any allocation. These are enforced by the
  generated codec (`buffa`); `map_decode_err` (`src/wire/mod.rs`) collapses every such structural
  failure to `CodecError::Malformed` — the caller-visible behavior (reject the frame) is identical
  whichever rule tripped, so viewstamp does not distinguish them further.
- Field order on the wire is unconstrained: a decoder accepts fields in any order, so one peer's
  chosen encode order never binds what another peer's decoder accepts.

**viewstamp's validation (enforced at the wire→domain conversion: `src/wire/convert.rs`,
`src/wire/messages_a.rs`, `src/wire/messages_b.rs`):**

- Every id/checksum/address-shaped `bytes` field decodes to a `u128` and MUST be **exactly 16
  bytes** (big-endian): `client` (`PreparedEntry`, `Request`, `Prepare`, `Reply`), `config_id`
  (every message carrying the epoch-policy pair — `Commit`, `DoViewChange`, `GetView`,
  `LearnerProof`, `LearnerStatus`, `Nack`, `Prepare`, `PrepareBatch`, `PrepareOk`, `Recovery`,
  `RecoveryResponse`, `RepairBatch`, `RequestLearnerProof`, `RequestPrepare`,
  `RequestPrepareRange`, `RequestSync`, `StartView`, `StartViewChange`, `SyncCheckpoint`),
  `prepare_checksum` (`PrepareOk`), `checkpoint_id` (`SyncCheckpoint`), `repairing_checksum` (the
  `PreparedEntry.body_state` oneof arm), `prev_config_id` and each `members` element
  (`ReconfigurePayload`), and `addr` (`RequestBlock`, `BlockResponse`). Any other length rejects.
- Every `replica`-shaped `uint32` field (and `RequestLearnerProof.from`, the soliciting replica's
  own slot) must be `<= u16::MAX`: `DoViewChange`, `GetView`, `LearnerProof`, `LearnerStatus`,
  `Nack`, `PrepareOk`, `Recovery`, `RecoveryResponse`, `RequestLearnerProof`, `RequestPrepare`,
  `RequestPrepareRange`, `RequestSync`, `StartView`, `StartViewChange`, `SyncCheckpoint`.
- `ReconfigurePayload.replica_count` must be `<= u8::MAX` (255) and `.learner_count` must be
  `<= u16::MAX` (65535) — the wire's `uint32` widening of the domain's narrower voting/learner
  counts narrows back down at conversion.
- `Message.body` must be present: an envelope with no oneof arm set is the wire's "no known
  message" case (parity with the retired codec's unknown-tag reject).
- `PreparedEntry.body_state` must be present: every log entry carries exactly one of `present` /
  `repairing_checksum` / `reconfigure` on the wire.
- Each of the checks above rejects as `CodecError::Malformed { what }` naming the offending
  field (e.g. `"Prepare.config_id"`); structural failures surface as described earlier. An
  envelope that ends before it can be fully read surfaces as `CodecError::Truncated`. A
  rejected message never panics and is never partially applied — `decode_message` returns `Err`
  for the WHOLE envelope. The transport's reaction to that `Err` is transport-specific: the
  byte-stream transport closes the connection on it (`Conn::poll_decoded`) rather than attempt to
  resynchronize mid-stream, while the QUIC coordinator instead drops just the failed frame and
  keeps draining the rest of the batch (`src/transport/quic/mod.rs`'s `drain_bridge`) —
  consensus retransmission recovers the dropped message.

**Determinism vs. acceptance:** `encode_message`'s output is deterministic — fields in ascending
field-number order, a proto3-default scalar OMITTED rather than written as zero (pinned by
`golden_byte_vectors`) — but `decode_message`'s acceptance is WIDER: a non-canonical encoding
(fields out of order, an explicit zero where proto3 would omit it, a duplicate scalar later
overwritten) still decodes, provided it resolves to a valid domain value. Two distinct byte strings
can therefore decode to the identical `Message` — decoding is not injective, so
`(encode_message, decode_message)` is a canonicalizing retraction (re-encoding a decoded value
always reproduces the same canonical bytes), never a byte-level bijection.

## 2. The frame layer

The stream transport's `[u32 length][payload]` framing and the QUIC transport's per-stream framing
(`src/transport/frame/mod.rs`) are UNCHANGED by the protobuf envelope cutover, and so is
`MAX_FRAME_LEN` (16 MiB): the cutover replaced what rides INSIDE a frame's payload (the hand-rolled
codec → the protobuf envelope), never the framing around it. Both transports share the identical
frame shape:

```text
[ u32 payload length, BIG-endian ][ payload = one encoded viewstamp.v1.Message ]
```

A receiver rejects an over-`MAX_FRAME_LEN` declared length as soon as the 4-byte prefix completes,
before any of that frame's body is retained; a sender refuses to emit a frame that would exceed it.

The per-message-type frame-BUDGET constants (`REQUEST_ENCODE_OVERHEAD`, `PREPARE_ENCODE_OVERHEAD`,
`REPLY_ENCODE_OVERHEAD`, the log-entry and batch-carrier overheads, `MAX_REQUEST_BODY_OVERHEAD`,
`max_request_body_len`, `max_reply_body_len`, `MAX_HEADER_ONLY_BAND_DEPTH` — `src/message/mod.rs`
and `src/transport/frame/mod.rs`) ARE new: they charge each scalar its worst-case protobuf encoding
(a tag byte plus a varint at its widest) and each length-delimited field its worst-case framing,
rather than the retired fixed-width codec's exact per-field byte count, so a body admitted against
a modeled budget can never encode past `MAX_FRAME_LEN`. Their derivation is documented at the const
definitions themselves — `src/message/mod.rs`'s module-level comment explains the
worst-case-charging methodology and each const's arithmetic. This file is not that arithmetic's
source of truth and does not restate the numbers.

## 3. The hello + versioning

`HELLO_VERSION` (`src/transport/labeled/mod.rs`, currently `3`) is THE wire-version fence for every
transport: the stream `Labeled` hello (the dialer sends eagerly; the acceptor answers only after
validating the dialer's) and the QUIC control-stream preface written by the `Hello` identity source
(`src/transport/quic/identity/mod.rs`), which encodes and parses through the IDENTICAL
`labeled::encode_hello` / `classify_hello` codec the stream transport uses — one format, one
parser, one version byte, shared by both. (A cluster configured with the alternative `CertOid`
identity source carries no hello frame at all on QUIC — its identity rides the mTLS certificate
extension instead, so `HELLO_VERSION` does not fence it; mixing identity sources within one
cluster is not a supported configuration.)

Rule: an ADDITIVE protobuf field — a new field number an old decoder tolerates as unknown within
`MAX_UNKNOWN_FIELDS` — needs NO `HELLO_VERSION` bump. Any OTHER wire-affecting change — a new field
whose meaning an old peer must not silently ignore, a semantic change to an existing field, or a
change to `MAX_UNKNOWN_FIELDS`/a frame budget that would admit input an old peer rejects (or vice
versa) — bumps `HELLO_VERSION`, so mixed-version peers refuse the connection at the handshake
rather than let either side mis-decode consensus traffic.

The envelope itself carries NO per-message version: `decode_message` has no version field to
dispatch on. Versioning happens exactly once, at the hello, before any consensus frame is trusted.

## 4. Durable state

The WAL `Header` (`HEADER_VERSION`) and the durable superblock root `VsrState`
(`SUPERBLOCK_VERSION`, currently `7`) are hand-rolled, fixed-width / length-prefixed big-endian
encodings — UNCHANGED by the protobuf envelope cutover, and NOT protobuf. Their layout, per-version
decode dispatch, and rejection surface (`CodecError::UnknownVersion` / `LengthOverflow` /
`TrailingBytes` / …) are documented at their definitions in `src/storage/mod.rs`, which is
normative for the on-disk format; this document does not restate it.

The wire envelope (§1) is never itself written to disk. A `Reconfigure` op's `body_checksum`
domain is its payload's CANONICAL flat encoding (`ReconfigurePayload::encode_body` — a hand-rolled
`u8`/`u16`/`u32`-count/`u128`-member layout), not the wire envelope's protobuf encoding of the same
payload (`PreparedEntry.body_state`'s `reconfigure` arm). This is deliberate: the wire envelope is
a structural transport concern (how a `Message` crosses the network), while the checksum identity
is the durable content-addressing concern (what a `Reconfigure` op IS) — the two encodings of the
"same" logical payload differ on purpose, and only `encode_body`'s bytes are ever hashed
(`Header::body_checksum`) or written to the WAL.

A log or superblock written before the protobuf envelope cutover does not replay against this
version (pre-release; no migration path is provided).

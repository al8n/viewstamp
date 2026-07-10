//! Wire-codec micro-benchmarks: one encode and one decode benchmark per hot
//! [`Message`] kind, each in its own criterion group with BYTES throughput (the
//! encoded length), so regressions in the per-message serialization cost show up
//! as a drop in MB/s. The representative shapes:
//!
//! - `prepare_1kib` — a [`Prepare`] carrying a 1 KiB client body (the normal-path
//!   replication hop; the dominant per-op wire cost).
//! - `prepare_ok` — a [`PrepareOk`] (the fixed-size commit-quorum vote).
//! - `commit` — a [`Commit`] (the fixed-size heartbeat / commit-advance).
//! - `dvc_64_header_only` — a [`DoViewChange`] carrying a 64-entry HEADER-ONLY
//!   (`Body::Repairing`) log slice (the view-change carrier shape: entries ship no
//!   bodies, so the cost is pure per-entry framing × 64 elements).
//! - `repair_batch_4x1kib` — a [`RepairBatch`] serving 4 entries of 1 KiB bodies
//!   (the windowed bulk-repair answer; body-bearing multi-entry framing).
//!
//! # Baseline — MACHINE-SPECIFIC, for trend comparison on the same box only
//!
//! Recorded from one local `cargo bench` run (Apple M1 Max, macOS,
//! rustc 1.98.0-nightly) as the initial reference point. Predates the protobuf wire envelope
//! (`encode_message`/`decode_message`); re-baseline after that cutover before trusting a delta
//! against these numbers.
//!
//! | benchmark                          | time     | throughput  |
//! |------------------------------------|----------|-------------|
//! | `codec/prepare_1kib/encode`        | ~54 ns   | ~19 GiB/s   |
//! | `codec/prepare_1kib/decode`        | ~60 ns   | ~17 GiB/s   |
//! | `codec/prepare_ok/encode`          | ~28 ns   | ~1.5 GiB/s  |
//! | `codec/prepare_ok/decode`          | ~7.3 ns  | ~5.6 GiB/s  |
//! | `codec/commit/encode`              | ~25 ns   | ~1.0 GiB/s  |
//! | `codec/commit/decode`              | ~6.2 ns  | ~4.1 GiB/s  |
//! | `codec/dvc_64_header_only/encode`  | ~200 ns  | ~15 GiB/s   |
//! | `codec/dvc_64_header_only/decode`  | ~269 ns  | ~11 GiB/s   |
//! | `codec/repair_batch_4x1kib/encode` | ~119 ns  | ~34 GiB/s   |
//! | `codec/repair_batch_4x1kib/decode` | ~256 ns  | ~16 GiB/s   |

use std::hint::black_box;

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use viewstamp_proto::{
  ClientId, Commit, DoViewChange, Message, OpNumber, Prepare, PrepareOk, PreparedEntry,
  RepairBatch, ReplicaId, RequestNumber, View, decode_message, encode_message,
};

const KIB: usize = 1024;

fn body(len: usize) -> Bytes {
  Bytes::from(vec![0xA5u8; len])
}

/// The normal-path replication hop: a `Prepare` with a 1 KiB client body.
fn prepare_1kib() -> Message {
  Message::Prepare(Prepare::new(
    View::with(3),
    OpNumber::with(1_000),
    OpNumber::with(998),
    OpNumber::with(992),
    viewstamp_proto::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(40),
    body(KIB),
  ))
}

/// The fixed-size content-addressed commit-quorum vote.
fn prepare_ok() -> Message {
  Message::PrepareOk(PrepareOk::new(
    View::with(3),
    OpNumber::with(1_000),
    ReplicaId::new(2),
    OpNumber::with(992),
    0x1234_5678_9ABC_DEF0_1122_3344_5566_7788,
    viewstamp_proto::Epoch::new(0),
    0,
  ))
}

/// The fixed-size heartbeat / commit-advance.
fn commit() -> Message {
  Message::Commit(Commit::new(
    View::with(3),
    OpNumber::with(1_000),
    OpNumber::with(992),
    viewstamp_proto::Epoch::new(0),
    0,
  ))
}

/// The view-change carrier shape: a 64-entry header-only (`Body::Repairing`) log slice —
/// no bodies, pure per-entry framing.
fn dvc_64_header_only() -> Message {
  let log: Vec<PreparedEntry> = (937..=1_000)
    .map(|op| {
      PreparedEntry::repairing(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        0x5EED_0000_0000_0000_0000_0000_0000_0000 | op as u128,
      )
    })
    .collect();
  Message::DoViewChange(DoViewChange::new(
    View::with(4),
    View::with(3),
    OpNumber::with(1_000),
    OpNumber::with(998),
    viewstamp_proto::Epoch::new(0),
    0,
    ReplicaId::new(1),
    log,
  ))
}

/// The windowed bulk-repair answer: 4 served entries of 1 KiB bodies each.
fn repair_batch_4x1kib() -> Message {
  let log: Vec<PreparedEntry> = (997..=1_000)
    .map(|op| {
      PreparedEntry::new(
        OpNumber::with(op),
        ClientId::new(7),
        RequestNumber::with(op),
        body(KIB),
      )
    })
    .collect();
  Message::RepairBatch(RepairBatch::new(
    View::with(3),
    OpNumber::with(1_000),
    OpNumber::with(992),
    0,
    log,
  ))
}

fn bench_codec(c: &mut Criterion) {
  let kinds: [(&str, Message); 5] = [
    ("prepare_1kib", prepare_1kib()),
    ("prepare_ok", prepare_ok()),
    ("commit", commit()),
    ("dvc_64_header_only", dvc_64_header_only()),
    ("repair_batch_4x1kib", repair_batch_4x1kib()),
  ];
  for (name, msg) in kinds {
    let encoded = encode_message(&msg);
    assert_eq!(
      decode_message(encoded.clone()).expect("the fixture round-trips"),
      msg,
      "fixture sanity: encode → decode is the identity"
    );
    let mut g = c.benchmark_group(format!("codec/{name}"));
    g.throughput(Throughput::Bytes(encoded.len() as u64));
    g.bench_function("encode", |b| b.iter(|| encode_message(black_box(&msg))));
    g.bench_function("decode", |b| {
      b.iter(|| decode_message(black_box(encoded.clone())).expect("a round-tripped buffer decodes"))
    });
    g.finish();
  }
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);

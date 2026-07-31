//! The FOREIGN-CONFIG ingress-injection lane of the reconfiguration foundation oracle.
//!
//! A node admits a STRICT message (a vote / lead / commit driver — one that contributes to the
//! append / vote / view accumulators) ONLY on an exact `(epoch, config_id)` match. This lane is the
//! BYTE-IDENTITY witness of that authority gate: it runs a healthy backup through an identical
//! workload TWICE — once clean, once with an extra foreign-stamped strict message interleaved — and
//! asserts the two runs leave the backup's observable consensus state (`op` / `commit` / `view`, plus
//! the durable view) BYTE-IDENTICAL. The foreign message changed nothing: it was dropped for
//! authority, never reaching the accumulators. Two witnesses:
//!
//! - the SPLIT-BRAIN witness — a FOREIGN-EPOCH strict message (a different configuration's voter);
//! - the DIVERGENT-ROLLOUT witness — a SAME-EPOCH but FOREIGN-`config_id` strict message (two
//!   memberships at the same epoch number, e.g. a partially-applied rollout).
//!
//! These are deliberate DETERMINISTIC tests (not a per-tick checker): the cleanest way to assert
//! "this message had ZERO effect" is to diff two otherwise-identical runs, which a focused fixture
//! expresses directly. The proto's own `epoch_ingress.rs` unit tests prove the gate per message type;
//! this lane proves the END-TO-END byte-identity at the sim's public API, which the reconfiguration
//! oracle rests on.

use bytes::Bytes;
use viewstamp_proto::Storage;
use viewstamp_proto::{
  ClientId, Commit, Config, Endpoint, Epoch, Instant, MemberId, Membership, Message, OpNumber,
  Peer, Prepare, PrepareOk, ReplicaId, RequestNumber, StartViewChange, Superblock, View,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal, MemBlockStore};

/// A `config_id` NOT in the fixture lineage (the fixtures carry `config_id = 0`).
const FOREIGN_CONFIG_ID: u128 = 0xDEAD_BEEF;
/// An epoch NOT the fixture epoch (the fixtures carry `Epoch::new(0)`).
const FOREIGN_EPOCH: u64 = 9;

/// A genesis membership of `n` voters (slot `i` is `MemberId::new(i)`), `config_id = 0` so a
/// hand-built same-config message (carrying 0) passes the strict gate.
fn genesis(n: u8) -> Membership {
  Membership::from_durable_parts(
    Epoch::new(0),
    n,
    0,
    (0..n as u128).map(MemberId::new).collect(),
    0,
  )
  .expect("valid genesis membership")
}

/// A fresh backup (replica 1 of 3) with its own WAL + superblock — the receiver under test.
fn backup() -> (
  Endpoint<viewstamp_simulation::sm::LogSm>,
  Storage<InMemoryWal, InMemorySuperblock, viewstamp_simulation::sm::LogSm>,
) {
  // The sim's `SimSm` is private; build the plain `LogSm` the cluster wraps. (Re-exported below.)
  let cfg = Config::try_new(1, MemberId::new(1)).expect("valid config");
  let wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  // Genesis: commit over this backup's own store (formats it), yielding the runnable endpoint.
  let e = Endpoint::new(
    cfg,
    genesis(3),
    0,
    viewstamp_simulation::sm::LogSm::default(),
    u64::MAX,
  )
  .commit(&wal, &mut sb)
  .expect("genesis commit formats the store");
  (e, Storage::new(wal, sb))
}

/// The observable consensus state used for the byte-identity comparison: the head, the applied +
/// known-committed frontiers, the in-memory view, and the DURABLE (superblock) view. A foreign-stamped
/// strict message that was correctly dropped leaves every one of these unchanged.
#[derive(Debug, PartialEq, Eq)]
struct Accumulators {
  op: u64,
  commit_min: u64,
  commit_max: u64,
  view: u64,
  durable_view: u64,
}

fn snapshot(
  e: &Endpoint<viewstamp_simulation::sm::LogSm>,
  storage: &Storage<InMemoryWal, InMemorySuperblock, viewstamp_simulation::sm::LogSm>,
) -> Accumulators {
  Accumulators {
    op: e.op().get(),
    commit_min: e.commit().get(),
    commit_max: e.commit_max().get(),
    view: e.view().get(),
    durable_view: storage.sb().state().view().get(),
  }
}

/// A same-config (epoch 0, config_id 0) `Prepare(op)` from the primary — the legitimate workload that
/// advances the head and (with a matching commit) the commit frontier.
fn prepare(op: u64, commit: u64) -> Message {
  Message::Prepare(Prepare::new(
    View::new(),
    OpNumber::with(op),
    OpNumber::with(commit),
    OpNumber::new(),
    Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(op),
    Bytes::copy_from_slice(&[op as u8]),
  ))
}

/// Drive the legitimate workload (the SAME on both runs): the primary prepares ops 1..=3, the backup
/// appends + acks each, and a same-config Commit advances the commit. Pumps storage after each so the
/// WAL appends complete and the accumulators settle.
fn drive_workload(
  e: &mut Endpoint<viewstamp_simulation::sm::LogSm>,
  storage: &mut Storage<InMemoryWal, InMemorySuperblock, viewstamp_simulation::sm::LogSm>,
  _blocks: &mut MemBlockStore,
) {
  let now = Instant::ZERO;
  let primary = Peer::Replica(ReplicaId::new(0));
  for op in 1..=3u64 {
    e.handle_message(now, storage, primary, prepare(op, op.saturating_sub(1)));
    e.handle_storage(now, storage);
  }
  // Commit up to 3 (same config) — advances commit_max and applies the held prefix.
  e.handle_message(
    now,
    storage,
    primary,
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  e.handle_storage(now, storage);
  while e.poll_message().is_some() {} // drain emitted acks (observation-only)
}

#[test]
fn foreign_epoch_strict_message_has_zero_effect_on_the_accumulators() {
  // CONTROL: the clean workload.
  let (mut control, mut cstorage) = backup();
  let mut cb = MemBlockStore::new();
  drive_workload(&mut control, &mut cstorage, &mut cb);
  let clean = snapshot(&control, &cstorage);

  // WITNESS: the same workload, but with a FOREIGN-EPOCH strict message interleaved at every step —
  // a PrepareOk (a commit-quorum vote) and a head-advancing Prepare, both stamped epoch 9. The strict
  // authority gate drops each for authority, so the accumulators must end BYTE-IDENTICAL to the clean
  // run (the foreign configuration's voter contributed nothing).
  let (mut witness, mut wstorage) = backup();
  let now = Instant::ZERO;
  let primary = Peer::Replica(ReplicaId::new(0));
  for op in 1..=3u64 {
    witness.handle_message(
      now,
      &mut wstorage,
      primary,
      prepare(op, op.saturating_sub(1)),
    );
    witness.handle_storage(now, &mut wstorage);
    // Foreign-epoch head-advancing Prepare (would advance `op` if admitted) from the claimed primary.
    witness.handle_message(
      now,
      &mut wstorage,
      primary,
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(op + 100), // a head far above — would jump `op` if the strict gate let it in
        OpNumber::with(op + 100),
        OpNumber::new(),
        Epoch::new(FOREIGN_EPOCH),
        0,
        ClientId::new(7),
        RequestNumber::with(op + 100),
        Bytes::copy_from_slice(&[1u8]),
      )),
    );
    // Foreign-epoch PrepareOk (a vote) from a peer — would feed the vote map if admitted.
    witness.handle_message(
      now,
      &mut wstorage,
      Peer::Replica(ReplicaId::new(2)),
      Message::PrepareOk(PrepareOk::new(
        View::new(),
        OpNumber::with(op),
        ReplicaId::new(2),
        OpNumber::new(),
        0,
        Epoch::new(FOREIGN_EPOCH),
        0,
      )),
    );
    witness.handle_storage(now, &mut wstorage);
  }
  witness.handle_message(
    now,
    &mut wstorage,
    primary,
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  witness.handle_storage(now, &mut wstorage);
  while witness.poll_message().is_some() {}
  let witnessed = snapshot(&witness, &wstorage);

  assert_eq!(
    clean, witnessed,
    "a foreign-EPOCH strict message must leave the backup's consensus accumulators byte-identical — \
     it was dropped for authority (the split-brain ingress witness)"
  );
  // Non-vacuity: the workload genuinely moved the accumulators (so "unchanged by the foreign message"
  // is meaningful, not a comparison of two empty states).
  assert!(
    clean.op >= 3 && clean.commit_max >= 3,
    "the legitimate workload advanced the head + commit (op={}, commit_max={})",
    clean.op,
    clean.commit_max
  );
}

#[test]
fn same_epoch_foreign_config_id_strict_message_has_zero_effect() {
  // The DIVERGENT-ROLLOUT witness: a strict message at the SAME epoch (0) but a FOREIGN `config_id`
  // (two memberships claiming epoch 0 — a partially-applied rollout) is ALSO dropped for authority, so
  // it cannot advance the commit or the head.
  let (mut control, mut cstorage) = backup();
  let mut cb = MemBlockStore::new();
  drive_workload(&mut control, &mut cstorage, &mut cb);
  let clean = snapshot(&control, &cstorage);

  let (mut witness, mut wstorage) = backup();
  let now = Instant::ZERO;
  let primary = Peer::Replica(ReplicaId::new(0));
  for op in 1..=3u64 {
    witness.handle_message(
      now,
      &mut wstorage,
      primary,
      prepare(op, op.saturating_sub(1)),
    );
    witness.handle_storage(now, &mut wstorage);
    // Same-epoch, FOREIGN-config_id head-advancing Prepare + a foreign-config Commit (would advance
    // the commit if admitted). Both dropped by the lineage gate.
    witness.handle_message(
      now,
      &mut wstorage,
      primary,
      Message::Prepare(Prepare::new(
        View::new(),
        OpNumber::with(op + 100),
        OpNumber::with(op + 100),
        OpNumber::new(),
        Epoch::new(0),
        FOREIGN_CONFIG_ID,
        ClientId::new(7),
        RequestNumber::with(op + 100),
        Bytes::copy_from_slice(&[1u8]),
      )),
    );
    witness.handle_message(
      now,
      &mut wstorage,
      primary,
      Message::Commit(Commit::new(
        View::new(),
        OpNumber::with(op + 100),
        OpNumber::new(),
        Epoch::new(0),
        FOREIGN_CONFIG_ID,
      )),
    );
    witness.handle_storage(now, &mut wstorage);
  }
  witness.handle_message(
    now,
    &mut wstorage,
    primary,
    Message::Commit(Commit::new(
      View::new(),
      OpNumber::with(3),
      OpNumber::new(),
      Epoch::new(0),
      0,
    )),
  );
  witness.handle_storage(now, &mut wstorage);
  while witness.poll_message().is_some() {}
  let witnessed = snapshot(&witness, &wstorage);

  assert_eq!(
    clean, witnessed,
    "a SAME-epoch FOREIGN-config_id strict message must leave the accumulators byte-identical — it \
     was dropped for authority (the divergent-rollout ingress witness)"
  );
}

#[test]
fn foreign_epoch_start_view_change_does_not_perturb_the_view() {
  // A foreign-epoch view-change DRIVER (a `StartViewChange`) must not move the backup's view: a
  // different configuration's view-change campaign cannot recruit this node. The control never sees
  // it; the witness sees one per step. Views (in-memory + durable) end byte-identical.
  let (control, cstorage) = backup();
  let clean = snapshot(&control, &cstorage);

  let (mut witness, mut wstorage) = backup();
  let now = Instant::ZERO;
  for v in 1..=3u64 {
    witness.handle_message(
      now,
      &mut wstorage,
      Peer::Replica(ReplicaId::new(2)),
      Message::StartViewChange(StartViewChange::new(
        View::with(v),
        ReplicaId::new(2),
        Epoch::new(FOREIGN_EPOCH),
        0,
      )),
    );
    witness.handle_storage(now, &mut wstorage);
  }
  while witness.poll_message().is_some() {}
  let witnessed = snapshot(&witness, &wstorage);
  assert_eq!(
    clean.view, witnessed.view,
    "a foreign-epoch StartViewChange must not advance the in-memory view"
  );
  assert_eq!(
    clean.durable_view, witnessed.durable_view,
    "a foreign-epoch StartViewChange must not advance the durable view"
  );
}

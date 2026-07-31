use super::*;
use viewstamp_proto::{
  ClientId, Header, OpNumber, ReadId, RequestNumber, Superblock, View, VsrState, Wal, WalDone,
  WriteId,
};

/// Correlation ids for these fixture tests: the incarnation is immaterial here — the fixture
/// only echoes the id back — so every id in this module shares one. Writes and reads draw from the
/// same sequence space, exactly as the endpoint's single counter does.
const TEST_INCARNATION: u64 = 1;
fn write_id(seq: u64) -> WriteId {
  WriteId::new(TEST_INCARNATION, seq)
}
fn read_id(seq: u64) -> ReadId {
  ReadId::new(TEST_INCARNATION, seq)
}

#[test]
fn append_then_read_round_trips() {
  let mut w = InMemoryWal::new();
  let h = Header::new(
    OpNumber::with(1),
    View::new(),
    ClientId::new(7),
    RequestNumber::with(1),
    b"x",
  );
  w.submit_append(
    write_id(1),
    OpNumber::with(1),
    h,
    bytes::Bytes::from_static(b"x"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(write_id(1))));
  assert_eq!(w.op_head(), OpNumber::with(1));
  assert_eq!(w.header(OpNumber::with(1)), Some(h));
  w.submit_read(read_id(2), OpNumber::with(1));
  match w.poll() {
    Some(WalDone::ReadOk(r)) => {
      assert_eq!(r.op(), OpNumber::with(1));
      assert_eq!(r.body(), b"x");
    }
    other => panic!("expected ReadOk, got {other:?}"),
  }
  w.submit_read(read_id(3), OpNumber::with(9));
  assert_eq!(w.poll(), Some(WalDone::Absent(read_id(3))));
}

#[test]
fn truncate_and_prune() {
  let mut w = InMemoryWal::new();
  for op in 1..=5u64 {
    let h = Header::new(
      OpNumber::with(op),
      View::new(),
      ClientId::new(1),
      RequestNumber::with(op),
      b"x",
    );
    w.submit_append(
      write_id(op),
      OpNumber::with(op),
      h,
      bytes::Bytes::from_static(b"x"),
    );
    let _ = w.poll();
  }
  w.truncate(OpNumber::with(3));
  assert_eq!(w.op_head(), OpNumber::with(3));
  assert!(w.header(OpNumber::with(4)).is_none());
  w.prune(OpNumber::with(2));
  assert!(w.header(OpNumber::with(1)).is_none());
  assert!(w.header(OpNumber::with(2)).is_some());
}

#[test]
fn superblock_write_reflects_in_state() {
  let mut sb = InMemorySuperblock::new();
  assert_eq!(sb.state(), VsrState::new());
  // Include canonical committed-band headers (ops 1..=3) so the vsr_headers round-trip through
  // submit_write/state() too (the superblock stores VsrState by value).
  let headers: std::vec::Vec<Header> = (1..=3)
    .map(|op| {
      Header::new(
        OpNumber::with(op),
        View::with(2),
        ClientId::new(1),
        RequestNumber::with(op),
        &[op as u8],
      )
    })
    .collect();
  let next = VsrState::try_new(
    View::with(2),
    View::with(2),
    OpNumber::with(3),
    OpNumber::with(0),
    0,
    headers,
  )
  .unwrap();
  sb.submit_write(write_id(1), next.clone());
  assert!(sb.poll().is_some());
  assert_eq!(sb.state(), next);
  assert_eq!(sb.state().committed_headers_slice().len(), 3);
}

/// Appends one entry `body` at `op` and drains the `Appended` completion.
fn append(w: &mut InMemoryWal, op: u64, body: &'static [u8]) {
  let h = Header::new(
    OpNumber::with(op),
    View::new(),
    ClientId::new(1),
    RequestNumber::with(op),
    body,
  );
  w.submit_append(
    write_id(op),
    OpNumber::with(op),
    h,
    Bytes::from_static(body),
  );
  let _ = w.poll();
}

#[test]
fn seeded_read_fault_is_deterministic_and_transient() {
  let mk = || {
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        read_fault_per_mille: 500,
        ..StorageFaults::none()
      },
      7,
    );
    append(&mut w, 1, b"x");
    w
  };
  let (mut a, mut b) = (mk(), mk());
  // Same seed ⇒ identical fault verdicts across two independent WALs; and a faulted read is
  // TRANSIENT (a later read of the same slot can succeed — verified by seeing both outcomes).
  let mut saw_fault = false;
  let mut saw_ok = false;
  for i in 0..40u64 {
    a.submit_read(read_id(i), OpNumber::with(1));
    b.submit_read(read_id(i), OpNumber::with(1));
    let fa = a.poll().unwrap().is_fault();
    let fb = b.poll().unwrap().is_fault();
    assert_eq!(fa, fb, "deterministic per seed");
    saw_fault |= fa;
    saw_ok |= !fa;
  }
  assert!(saw_fault, "read_fault_per_mille=500 must fault some reads");
  assert!(
    saw_ok,
    "a transient fault clears: some reads of the same slot succeed"
  );
}

#[test]
fn read_faults_clear_within_the_proto_retry_budget() {
  // The load-bearing property for the transient-fault gate: a TRANSIENT read fault must clear within the
  // proto's RECOVER_READ_RETRIES (8) immediate retries — otherwise a recovering replica strands.
  // We model that exact budget (9 attempts per round) and assert a clean read is almost certain.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      read_fault_per_mille: 80,
      ..StorageFaults::none()
    },
    1234,
  );
  append(&mut w, 1, b"payload");
  let mut stranded_rounds = 0;
  for round in 0..1000u64 {
    let mut cleared = false;
    for attempt in 0..9u64 {
      w.submit_read(read_id(round * 9 + attempt), OpNumber::with(1));
      if !w.poll().unwrap().is_fault() {
        cleared = true;
        break;
      }
    }
    if !cleared {
      stranded_rounds += 1;
    }
  }
  assert_eq!(
    stranded_rounds, 0,
    "a transient read fault (8%) must clear within the 9-attempt retry budget every round"
  );
}

#[test]
fn bit_rot_makes_a_slot_permanently_body_faulty() {
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
    1,
  );
  append(&mut w, 1, b"x");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Faulty,
    "bit-rotted slot is Faulty"
  );
  // The header is durable even when the body is permanently corrupt — the append wrote the
  // header successfully before the rot verdict fired.
  let stored_header = w
    .header(OpNumber::with(1))
    .expect("bit-rotted slot still has a durable header");
  assert_eq!(
    stored_header.op(),
    OpNumber::with(1),
    "the durable header carries the correct op"
  );
  // Every read of a bit-rotted slot yields BodyFaulty carrying the durable header, not a bare
  // Fault — the op is identified, only the body is unrecoverable from this replica.
  for i in 0..5u64 {
    w.submit_read(read_id(i), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::BodyFaulty(bf)) => {
        assert_eq!(
          bf.header(),
          stored_header,
          "BodyFaulty carries the durable header"
        );
      }
      other => panic!("permanent bit-rot must yield BodyFaulty, got {other:?}"),
    }
  }
}

#[test]
fn torn_write_yields_body_faulty_on_read() {
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      torn_write_per_mille: 1000,
      ..StorageFaults::none()
    },
    1,
  );
  append(&mut w, 1, b"intact");
  // A torn slot keeps its ORIGINAL header (the tear is latent — only the stored body bytes are
  // corrupt) and reports Clean. The header is fully durable and readable.
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
  let stored_header = w
    .header(OpNumber::with(1))
    .expect("torn slot still has its original durable header");
  assert_eq!(stored_header.op(), OpNumber::with(1));
  // A read of a torn slot yields BodyFaulty (header durable, body unverifiable) — not a bare
  // ReadOk with a corrupt body that the caller must re-check, and not a bare Fault that
  // discards the known-durable header.
  w.submit_read(read_id(2), OpNumber::with(1));
  match w.poll() {
    Some(WalDone::BodyFaulty(bf)) => {
      assert_eq!(
        bf.header(),
        stored_header,
        "BodyFaulty carries the durable original header"
      );
    }
    other => panic!("torn write must yield BodyFaulty, got {other:?}"),
  }
}

#[test]
fn misdirected_read_returns_a_wrong_op_but_valid_entry() {
  // A misdirected read for op X returns a DIFFERENT present, valid slot's entry: the body
  // checksum-VERIFIES (it is a real op's body), so only the PLACEMENT check (`header.op() == X`)
  // catches it. We use a 1000-per-mille rate so it always fires, and several distinct durable slots
  // so a sibling exists.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      misdirect_read_per_mille: 1000,
      ..StorageFaults::none()
    },
    7,
  );
  for op in 1..=4u64 {
    append(&mut w, op, b"body");
  }
  // Read op 2: every read is misdirected, so it returns SOME other op's (valid) entry, never op 2's.
  let mut saw_misdirect = false;
  for i in 0..20u64 {
    w.submit_read(read_id(100 + i), OpNumber::with(2));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => {
        assert!(
          r.header().verify(r.body()),
          "a misdirected read still returns a CHECKSUM-CORRECT entry (only the op is wrong)"
        );
        assert_ne!(
          r.header().op(),
          OpNumber::with(2),
          "the misdirected entry is for a DIFFERENT op — the placement check (header.op() == op) \
           is exactly what must reject it"
        );
        saw_misdirect = true;
      }
      other => panic!("expected a (misdirected) ReadOk, got {other:?}"),
    }
  }
  assert!(
    saw_misdirect,
    "misdirect_read_per_mille=1000 must misdirect"
  );
}

#[test]
fn misdirected_read_falls_through_when_no_sibling_exists() {
  // With only ONE durable slot there is no valid sibling to misdirect to, so the read is HONEST even
  // at a 1000-per-mille misdirect rate (a misdirect never fabricates an entry — it can only return a
  // real, different present slot, and there is none).
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      misdirect_read_per_mille: 1000,
      ..StorageFaults::none()
    },
    7,
  );
  append(&mut w, 1, b"only");
  for i in 0..10u64 {
    w.submit_read(read_id(i), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => {
        assert_eq!(
          r.header().op(),
          OpNumber::with(1),
          "honest read of the sole slot"
        );
        assert_eq!(r.body(), b"only");
      }
      other => panic!("expected the honest ReadOk, got {other:?}"),
    }
  }
}

#[test]
fn misdirected_read_is_deterministic_per_seed() {
  // Same seed + same plan ⇒ identical misdirect targets (the sibling pick uses the seeded PRNG).
  let run = || {
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        misdirect_read_per_mille: 500,
        ..StorageFaults::none()
      },
      1234,
    );
    for op in 1..=4u64 {
      append(&mut w, op, b"b");
    }
    let mut out = std::vec::Vec::new();
    for i in 0..30u64 {
      w.submit_read(read_id(i), OpNumber::with(2));
      match w.poll() {
        Some(WalDone::ReadOk(r)) => out.push(r.header().op().get()),
        Some(WalDone::Absent(_)) => out.push(0),
        other => panic!("unexpected {other:?}"),
      }
    }
    out
  };
  assert_eq!(
    run(),
    run(),
    "misdirected reads are a pure function of the seed"
  );
}

#[test]
fn permanent_verdicts_survive_a_restart_via_the_persisted_struct() {
  // A bit-rotted slot stays rotted across a crash/restart because the WAL struct persists in the
  // Cluster (the `rotted` set lives in the struct). This is what makes the permanent-fault
  // gate meaningful; here we assert the struct-level persistence directly.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
    9,
  );
  append(&mut w, 1, b"x");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Faulty);
  // No "restart" resets the struct — the Cluster reuses the same `InMemoryWal`. Re-reading still
  // yields BodyFaulty (the rot verdict is permanent), proving the verdict is stable for the
  // lifetime of the durable medium.
  for i in 0..3u64 {
    w.submit_read(read_id(i), OpNumber::with(1));
    assert!(
      w.poll().unwrap().is_body_faulty(),
      "a permanently bit-rotted slot always yields BodyFaulty"
    );
  }
}

// ── Task-2 durable-header tests ──

#[test]
fn rotted_op_header_survives_and_read_yields_body_faulty() {
  // An appended-then-rotted op must keep its durable header (the header tuple in `entries` is
  // intact; only the body is unrecoverable from this replica). A read must yield BodyFaulty
  // carrying that header, not a bare Fault.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
    42,
  );
  append(&mut w, 3, b"payload");
  // header() returns Some even for a rotted slot.
  let stored = w
    .header(OpNumber::with(3))
    .expect("rotted slot still has a durable header");
  assert_eq!(stored.op(), OpNumber::with(3));
  // A read yields BodyFaulty carrying the durable header.
  w.submit_read(read_id(1), OpNumber::with(3));
  match w.poll() {
    Some(WalDone::BodyFaulty(bf)) => {
      assert_eq!(bf.id(), read_id(1));
      assert_eq!(bf.header(), stored, "carries the durable header");
    }
    other => panic!("rotted slot must yield BodyFaulty, got {other:?}"),
  }
}

#[test]
fn torn_op_header_survives_and_read_yields_body_faulty() {
  // An appended-then-torn op must keep its durable header (the tear only flips a body byte;
  // the stored header tuple in `entries` is the original intact header). A read must yield
  // BodyFaulty carrying that header.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      torn_write_per_mille: 1000,
      ..StorageFaults::none()
    },
    42,
  );
  append(&mut w, 7, b"content");
  // header() returns Some for a torn slot (the tear is latent — only the body is corrupt).
  let stored = w
    .header(OpNumber::with(7))
    .expect("torn slot still has its original durable header");
  assert_eq!(stored.op(), OpNumber::with(7));
  // A read yields BodyFaulty carrying the durable header.
  w.submit_read(read_id(1), OpNumber::with(7));
  match w.poll() {
    Some(WalDone::BodyFaulty(bf)) => {
      assert_eq!(bf.id(), read_id(1));
      assert_eq!(bf.header(), stored, "carries the original durable header");
    }
    other => panic!("torn slot must yield BodyFaulty, got {other:?}"),
  }
}

#[test]
fn torn_header_slot_vanishes_entirely() {
  // The torn-header contract-violation probe: a completed append whose verdict fired retains NO
  // recoverable header — `header()` is None, `status()` is Empty, a read is Absent — exactly the
  // shape the `Wal` header-durability contract forbids a real backend from producing. The append
  // COMPLETED normally (`Appended` fired), so the proto acked it believing it durable.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      torn_header_per_mille: 1000,
      ..StorageFaults::none()
    },
    42,
  );
  append(&mut w, 5, b"gone");
  assert_eq!(w.torn_headers_fired(), 1, "the verdict fired");
  assert!(
    w.header(OpNumber::with(5)).is_none(),
    "a torn-header slot has NO recoverable header"
  );
  assert_eq!(
    w.status(OpNumber::with(5)),
    SlotStatus::Empty,
    "a torn-header slot reports Empty — as if never written"
  );
  w.submit_read(read_id(1), OpNumber::with(5));
  assert_eq!(
    w.poll(),
    Some(WalDone::Absent(read_id(1))),
    "a read of a torn-header slot is Absent"
  );
  // Truncating the slot away clears the verdict with it (no ghost entry under a gone op).
  w.truncate(OpNumber::with(0));
  assert_eq!(w.status(OpNumber::with(5)), SlotStatus::Empty);
  assert_eq!(
    w.torn_headers_fired(),
    1,
    "the witness counter is cumulative"
  );
}

#[test]
fn never_appended_op_yields_absent() {
  // An op that was never durably appended (not in `entries`) must yield Absent on a read —
  // not BodyFaulty (there is no durable header to carry) and not Fault.
  let mut w = InMemoryWal::new();
  // Append op 1 to keep the WAL non-empty; op 99 was never appended.
  append(&mut w, 1, b"x");
  assert!(
    w.header(OpNumber::with(99)).is_none(),
    "a never-appended op has no durable header"
  );
  w.submit_read(read_id(5), OpNumber::with(99));
  assert_eq!(
    w.poll(),
    Some(WalDone::Absent(read_id(5))),
    "a never-appended op yields Absent, not BodyFaulty"
  );
}

/// A durable VSR root naming `checkpoint_op` (with a matching `commit >= checkpoint_op` and no
/// committed-band headers) — the proto's step-2 root that makes a just-written snapshot the live
/// checkpoint. Used by the two-slot superblock tests to ROOT a snapshot the way `recover` expects.
fn root_naming_checkpoint(checkpoint_op: u64) -> VsrState {
  VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(checkpoint_op),
    OpNumber::with(checkpoint_op),
    // A non-zero checkpoint id; the exact value is irrelevant to these storage-level tests (the
    // proto's id cross-check lives above this layer).
    0x1234,
    std::vec::Vec::new(),
  )
  .expect("commit == checkpoint_op and log_view <= view")
}

/// Pump an async-mode superblock until its staged writes have all become durable and all `Wrote`
/// completions are consumed (bounded). Used by the supersession test to land each staged root/
/// snapshot in FIFO order.
fn drain(sb: &mut InMemorySuperblock) {
  for _ in 0..256 {
    let had = sb.poll().is_some();
    if !had && sb.staged_len() == 0 {
      return;
    }
  }
  panic!("superblock did not drain within the bound");
}

/// Sync-mode: write a checkpoint snapshot at `op` AND its durable root, so the snapshot becomes the
/// live/readable checkpoint (the full proto two-step sequence). Drains both `Wrote` completions.
fn write_rooted_checkpoint(sb: &mut InMemorySuperblock, op: u64, snap: &'static [u8]) {
  sb.submit_write_checkpoint(
    write_id(900 + op),
    OpNumber::with(op),
    Bytes::from_static(snap),
  );
  let _ = sb.poll();
  sb.submit_write(write_id(800 + op), root_naming_checkpoint(op));
  let _ = sb.poll();
}

#[test]
fn superblock_checkpoint_read_fault_is_transient() {
  use viewstamp_proto::SuperblockDone;
  let mut sb = InMemorySuperblock::with_faults(
    StorageFaults {
      read_fault_per_mille: 500,
      ..StorageFaults::none()
    },
    3,
  );
  // Write AND root a checkpoint (the proto two-step sequence) so reads have a live, readable
  // checkpoint to (transiently) fault on.
  write_rooted_checkpoint(&mut sb, 4, b"snap");
  let mut saw_fault = false;
  let mut saw_read = false;
  for i in 1..40u64 {
    sb.submit_read_checkpoint(read_id(i));
    match sb.poll().unwrap() {
      SuperblockDone::Fault(_) => saw_fault = true,
      SuperblockDone::CheckpointRead(cr) => {
        assert_eq!(cr.op(), OpNumber::with(4));
        saw_read = true;
      }
      other => panic!("unexpected superblock completion: {other:?}"),
    }
  }
  assert!(saw_fault, "checkpoint reads must transiently fault");
  assert!(
    saw_read,
    "a transient checkpoint fault clears: some reads succeed"
  );
}

#[test]
fn superblock_corrupt_checkpoint_read_returns_parseable_but_altered_bytes() {
  use viewstamp_proto::SuperblockDone;
  // the corrupt-checkpoint-read fault returns a `CheckpointRead` for the RIGHT op whose
  // bytes are the live snapshot with one trailing byte flipped — still a `CheckpointRead` (parseable),
  // but NOT byte-identical to the written snapshot, so it hashes to a different checkpoint id. Proven
  // TRANSIENT: across many reads some return the GENUINE bytes (a re-read serves the clean snapshot).
  let mut sb = InMemorySuperblock::with_faults(
    StorageFaults {
      corrupt_checkpoint_read_per_mille: 500,
      ..StorageFaults::none()
    },
    3,
  );
  let genuine: &[u8] = b"a-genuine-checkpoint-snapshot";
  write_rooted_checkpoint(&mut sb, 4, b"a-genuine-checkpoint-snapshot");
  let mut saw_corrupt = false;
  let mut saw_genuine = false;
  for i in 1..64u64 {
    sb.submit_read_checkpoint(read_id(i));
    match sb.poll().unwrap() {
      SuperblockDone::CheckpointRead(cr) => {
        assert_eq!(
          cr.op(),
          OpNumber::with(4),
          "the corrupt read keeps its bound op"
        );
        assert_eq!(
          cr.snapshot().len(),
          genuine.len(),
          "the fault flips a byte in place, never changes the length",
        );
        if cr.snapshot() == genuine {
          saw_genuine = true;
        } else {
          // Differs from the written bytes ⇒ a different content hash, but still a CheckpointRead.
          assert_ne!(
            viewstamp_proto::checkpoint_id(cr.snapshot()),
            viewstamp_proto::checkpoint_id(genuine),
            "corrupt bytes hash to a DIFFERENT id than the genuine snapshot",
          );
          saw_corrupt = true;
        }
      }
      other => panic!("unexpected superblock completion: {other:?}"),
    }
  }
  assert!(saw_corrupt, "the corrupt-checkpoint-read fault must fire");
  assert!(
    saw_genuine,
    "the fault is transient: some reads return the genuine snapshot"
  );
}

/// Reads the live checkpoint synchronously (no faults), asserting it is a `CheckpointRead` and
/// returning its `(op, body)`; panics on a `Fault`/unexpected completion.
fn read_live_checkpoint(sb: &mut InMemorySuperblock) -> (u64, Vec<u8>) {
  use viewstamp_proto::SuperblockDone;
  sb.submit_read_checkpoint(read_id(7777));
  match sb.poll() {
    Some(SuperblockDone::CheckpointRead(cr)) => (cr.op().get(), cr.snapshot().to_vec()),
    other => panic!("expected a live CheckpointRead, got {other:?}"),
  }
}

#[test]
fn checkpoint_unreadable_until_a_root_names_it() {
  use viewstamp_proto::SuperblockDone;
  // A written-but-unrooted snapshot is NOT yet the live checkpoint (redundant-copy model, finding B):
  // the durable root is the authority for which generation is readable.
  let mut sb = InMemorySuperblock::new();
  // No checkpoint at all → read faults (the no-checkpoint case).
  sb.submit_read_checkpoint(read_id(1));
  assert!(matches!(sb.poll(), Some(SuperblockDone::Fault(_))));
  // Write a snapshot at op 4 but do NOT root it → still no live checkpoint.
  sb.submit_write_checkpoint(write_id(2), OpNumber::with(4), Bytes::from_static(b"snap4"));
  let _ = sb.poll();
  sb.submit_read_checkpoint(read_id(3));
  assert!(
    matches!(sb.poll(), Some(SuperblockDone::Fault(_))),
    "an unrooted snapshot is not yet readable"
  );
  // Now write the durable root naming op 4 → the snapshot becomes the live, readable checkpoint.
  sb.submit_write(write_id(4), root_naming_checkpoint(4));
  let _ = sb.poll();
  assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
}

#[test]
fn orphaned_checkpoint_restores_the_last_rooted_snapshot() {
  // THE finding-B case. Root a checkpoint at op 4; then write a NEWER snapshot at op 8 whose ROOT
  // never lands (orphaned — e.g. the checkpoint was abandoned, or a crash interrupted its root). A
  // faithful redundant-copy backend must still serve the last-ROOTED snapshot (op 4) — NOT the
  // orphaned op-8 bytes — so recover restores from its own disk (`cr.op() == state.checkpoint_op()`)
  // instead of escalating to a spurious peer fetch.
  let mut sb = InMemorySuperblock::new();
  write_rooted_checkpoint(&mut sb, 4, b"snap4");
  assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
  // A newer snapshot lands but its root never does.
  sb.submit_write_checkpoint(
    write_id(50),
    OpNumber::with(8),
    Bytes::from_static(b"snap8"),
  );
  let _ = sb.poll();
  // The live checkpoint is STILL the rooted op-4 snapshot (the durable root still names op 4), and
  // crucially its op MATCHES what `state().checkpoint_op()` reports — so recover's placement check
  // (`cr.op() == state.checkpoint_op()`) passes and it restores locally.
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
}

#[test]
fn crash_discards_a_staged_but_unrooted_snapshot_keeping_the_rooted_one() {
  // A crash (`discard_inflight`) drops a staged-but-unrooted snapshot, keeping the last-rooted one
  // readable — the redundant-copy crash semantics (finding B).
  let mut sb = InMemorySuperblock::new();
  write_rooted_checkpoint(&mut sb, 4, b"snap4");
  // A newer snapshot lands (root not yet written).
  sb.submit_write_checkpoint(
    write_id(50),
    OpNumber::with(8),
    Bytes::from_static(b"snap8"),
  );
  let _ = sb.poll();
  // Crash: the unrooted op-8 snapshot is lost; the rooted op-4 one survives, readable and matching
  // the durable root.
  sb.discard_inflight();
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
  // A subsequent root that DOES name op 8 cannot resurrect the discarded snapshot — it was lost.
  sb.submit_write(write_id(60), root_naming_checkpoint(8));
  let _ = sb.poll();
  use viewstamp_proto::SuperblockDone;
  sb.submit_read_checkpoint(read_id(61));
  assert!(
    matches!(sb.poll(), Some(SuperblockDone::Fault(_))),
    "the discarded op-8 snapshot is gone; naming it leaves no readable snapshot"
  );
}

#[test]
fn supersession_keeps_the_older_rooted_snapshot_readable() {
  // The serialized-root-ordering supersession (the proto's `submit_durable_view` comment): a
  // checkpoint's step-2 root (naming the NEW op) is left in flight when a view change issues a
  // durable-view root naming the OLD checkpoint; FIFO completes the new-op root FIRST but the later
  // old-op root supersedes it. The live checkpoint must end up the OLD one, and its snapshot must
  // still be readable (not GC'd by the transient new-op-rooted window). Async mode to stage both.
  let mut sb = InMemorySuperblock::with_async_writes_and_faults(StorageFaults::none(), 1, 1);
  // Establish a rooted checkpoint at op 4 first (drain fully).
  sb.submit_write_checkpoint(write_id(1), OpNumber::with(4), Bytes::from_static(b"snap4"));
  drain(&mut sb);
  sb.submit_write(write_id(2), root_naming_checkpoint(4));
  drain(&mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  // A new checkpoint at op 8: snapshot written + its step-2 root staged...
  sb.submit_write_checkpoint(write_id(3), OpNumber::with(8), Bytes::from_static(b"snap8"));
  drain(&mut sb); // snapshot durable; op-8 root not yet submitted
  sb.submit_write(write_id(4), root_naming_checkpoint(8)); // step-2 root for op 8 (staged)
  // ...then a view change supersedes it with a durable-view root naming the OLD op 4 (staged AFTER).
  sb.submit_write(write_id(5), root_naming_checkpoint(4));
  drain(&mut sb);
  // The FINAL durable root names op 4 (supersession), and the op-4 snapshot is STILL readable.
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
}

#[test]
fn no_faults_is_byte_for_byte_reliable() {
  // StorageFaults::none() must reproduce the old reliable behaviour exactly.
  let mut w = InMemoryWal::with_faults(StorageFaults::none(), 42);
  append(&mut w, 1, b"intact");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
  for i in 0..10u64 {
    w.submit_read(read_id(i), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => assert!(r.header().verify(r.body())),
      other => panic!("no-faults WAL must always ReadOk a present slot, got {other:?}"),
    }
  }
}

/// Submits (does NOT poll) an append at `op`, returning its `WriteId` — for async-mode tests that
/// must observe the staged (in-flight) state before completion.
fn submit(w: &mut InMemoryWal, id: u64, op: u64, body: &'static [u8]) -> WriteId {
  let h = Header::new(
    OpNumber::with(op),
    View::new(),
    ClientId::new(1),
    RequestNumber::with(op),
    body,
  );
  let oid = write_id(id);
  w.submit_append(oid, OpNumber::with(op), h, Bytes::from_static(body));
  oid
}

#[test]
fn async_append_stays_dirty_until_the_delay_elapses_then_becomes_durable() {
  // The core async-mode primitive: a submitted append is NOT durable for `delay`
  // polls — `status` is Dirty (never Clean), `op_head` does not count it, a read returns Absent, and
  // `poll` yields no Appended — then exactly at the delay it becomes durable and `poll` yields it.
  let mut w = InMemoryWal::with_async_appends(3);
  let id = submit(&mut w, 1, 1, b"x");
  assert_eq!(w.staged_len(), 1, "the append is staged, not yet durable");

  // While in flight, the non-ticking inspectors (status/op_head/header) all report not-durable, and
  // a read returns Absent. Verify the read FIRST (one poll for it — which also ticks 3→2).
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Dirty,
    "in-flight: Dirty"
  );
  assert_eq!(
    w.op_head(),
    OpNumber::with(0),
    "op_head ignores an in-flight slot"
  );
  assert!(
    w.header(OpNumber::with(1)).is_none(),
    "no readable header in flight"
  );
  w.submit_read(read_id(100), OpNumber::with(1));
  assert!(
    matches!(w.poll(), Some(WalDone::Absent(_))),
    "a read of a staged slot returns Absent"
  );
  // `delay` was 3; one poll above ticked it to 2. Two more polls reach 0 WITHOUT releasing.
  assert_eq!(
    w.poll(),
    None,
    "still in flight (remaining 2→1): no Appended"
  );
  assert_eq!(
    w.poll(),
    None,
    "still in flight (remaining 1→0): no Appended"
  );
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Dirty,
    "still Dirty at the boundary"
  );
  assert_eq!(w.staged_len(), 1, "still staged until the release poll");
  // The next poll (remaining == 0) releases the append: it becomes durable and yields its Appended.
  assert_eq!(
    w.poll(),
    Some(WalDone::Appended(id)),
    "the staged append becomes durable and yields its Appended"
  );
  assert_eq!(w.staged_len(), 0, "the staging queue drained");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Clean,
    "now durable"
  );
  assert_eq!(w.op_head(), OpNumber::with(1));
  w.submit_read(read_id(200), OpNumber::with(1));
  match w.poll() {
    Some(WalDone::ReadOk(r)) => {
      assert_eq!(r.op(), OpNumber::with(1));
      assert!(r.header().verify(r.body()));
    }
    other => panic!("a durable slot reads back ReadOk, got {other:?}"),
  }
}

#[test]
fn async_delay_zero_still_defers_to_the_next_poll_never_inline() {
  // `delay == 0` must NOT complete inline in `submit_append` (that would be the synchronous path):
  // the in-flight window must exist for at least the gap until the next poll.
  let mut w = InMemoryWal::with_async_appends(0);
  let id = submit(&mut w, 1, 1, b"x");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Dirty,
    "delay=0 is still staged at submit time (not inline-durable)"
  );
  assert_eq!(
    w.poll(),
    Some(WalDone::Appended(id)),
    "released on next poll"
  );
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
}

#[test]
fn async_appends_complete_in_submission_order() {
  // A serial WAL writer: staged appends become durable FIFO. With delay=1, op1 releases, then op2.
  let mut w = InMemoryWal::with_async_appends(1);
  let id1 = submit(&mut w, 1, 1, b"a");
  let id2 = submit(&mut w, 2, 2, b"b");
  assert_eq!(w.staged_len(), 2);
  assert_eq!(
    w.poll(),
    None,
    "tick 1: op1 counts down from 1, nothing ready yet"
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(id1)), "op1 durable first");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
  assert_eq!(
    w.status(OpNumber::with(2)),
    SlotStatus::Dirty,
    "op2 still in flight while op1's window closed"
  );
  assert_eq!(w.poll(), None, "op2 counts down from 1");
  assert_eq!(w.poll(), Some(WalDone::Appended(id2)), "op2 durable second");
  assert_eq!(w.op_head(), OpNumber::with(2));
}

#[test]
fn async_mode_composes_with_a_torn_write() {
  // The torn-write verdict is taken at SUBMIT and applied on COMPLETION: while staged the slot is
  // Dirty; once durable it carries the original header but a corrupt body (fails proto verify).
  let mut w = InMemoryWal::with_async_appends_and_faults(
    StorageFaults {
      torn_write_per_mille: 1000,
      ..StorageFaults::none()
    },
    1,
    2,
  );
  submit(&mut w, 1, 1, b"intact");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Dirty,
    "staged: Dirty regardless of the (already-decided) torn verdict"
  );
  // Tick past the delay (delay=2 → 2 countdown polls, then release).
  assert_eq!(w.poll(), None);
  assert_eq!(w.poll(), None);
  assert_eq!(w.poll(), Some(WalDone::Appended(write_id(1))));
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Clean,
    "a torn slot is Clean (latent tear) once durable"
  );
  w.submit_read(read_id(9), OpNumber::with(1));
  match w.poll() {
    Some(WalDone::BodyFaulty(bf)) => {
      assert_eq!(
        bf.header().op(),
        OpNumber::with(1),
        "BodyFaulty carries the durable header for the async torn write"
      );
    }
    other => panic!("expected BodyFaulty for a durable torn slot, got {other:?}"),
  }
}

#[test]
fn sync_mode_is_the_default_and_unchanged() {
  // The default constructors must NOT stage: an append is durable inline (existing-gate behaviour).
  for mut w in [
    InMemoryWal::new(),
    InMemoryWal::with_faults(StorageFaults::none(), 7),
  ] {
    let id = submit(&mut w, 1, 1, b"x");
    assert_eq!(w.staged_len(), 0, "default mode never stages");
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Clean,
      "default append is durable inline"
    );
    assert_eq!(w.op_head(), OpNumber::with(1));
    assert_eq!(w.poll(), Some(WalDone::Appended(id)));
  }
}

#[test]
fn discard_inflight_drops_staged_appends_but_keeps_durable_entries() {
  // The faithful fsync-loss-on-crash model: a crash drops every STAGED (not-yet-durable) append
  // WITHOUT ever letting it become durable, while the already-durable log survives untouched.
  let mut w = InMemoryWal::with_async_appends(3);
  // op1 is appended and fully released → durable; op2 is submitted but still in flight.
  let id1 = submit(&mut w, 1, 1, b"a");
  // Release op1 (delay 3 → tick 3,2,1,0 then the release poll yields Appended).
  for _ in 0..3 {
    assert_eq!(w.poll(), None);
  }
  assert_eq!(
    w.poll(),
    Some(WalDone::Appended(id1)),
    "op1 becomes durable"
  );
  assert_eq!(w.op_head(), OpNumber::with(1));
  let _id2 = submit(&mut w, 2, 2, b"b");
  assert_eq!(w.staged_len(), 1, "op2 is staged, in flight");
  assert_eq!(w.status(OpNumber::with(2)), SlotStatus::Dirty);

  // Crash: discard the in-flight op2. The durable op1 stays; op2 is GONE and never resurfaces.
  w.discard_inflight();
  assert_eq!(w.staged_len(), 0, "the in-flight append was discarded");
  assert_eq!(
    w.op_head(),
    OpNumber::with(1),
    "head sits at the last DURABLE op — the lost in-flight write never advanced it"
  );
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Clean,
    "the durable op survives the crash"
  );
  assert_eq!(
    w.status(OpNumber::with(2)),
    SlotStatus::Empty,
    "the lost in-flight op leaves no slot behind"
  );
  // A post-crash poll never resurrects op2 as durable (no stale `Appended` after recovery).
  for _ in 0..8 {
    assert_eq!(w.poll(), None, "no staged append resurfaces post-discard");
  }
  assert_eq!(w.op_head(), OpNumber::with(1));
  // op1 still reads back intact.
  w.submit_read(read_id(99), OpNumber::with(1));
  assert!(matches!(w.poll(), Some(WalDone::ReadOk(_))));
}

#[test]
fn discard_inflight_is_a_noop_in_sync_mode() {
  // Synchronous mode never stages, so a crash-time discard is a harmless no-op (durable log intact).
  let mut w = InMemoryWal::new();
  let id = submit(&mut w, 1, 1, b"x");
  assert_eq!(w.poll(), Some(WalDone::Appended(id)));
  w.discard_inflight();
  assert_eq!(w.op_head(), OpNumber::with(1), "sync durable op untouched");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
}

#[test]
fn bounded_capacity_reports_the_ring_size() {
  // The unbounded default reports u64::MAX (the proto's stall never engages); a bounded ring reports
  // its slot count n (the stall engages against it).
  assert_eq!(InMemoryWal::new().capacity(), u64::MAX);
  assert_eq!(InMemoryWal::with_capacity(3).capacity(), 3);
  assert_eq!(InMemoryWal::with_capacity(12).capacity(), 12);
}

#[test]
fn bounded_ring_append_wraps_and_a_wrapped_over_op_reads_absent() {
  // The core ring semantics: op K lands in slot K mod n, so an append at K physically OVERWRITES the
  // op that last held that slot (op K-n). A read of the wrapped-over op then returns Absent (its
  // bytes are gone — a clean wrap), while the op currently resident in the slot reads back.
  let mut w = InMemoryWal::with_capacity(3); // slots {0,1,2}
  for op in 1..=3u64 {
    append(&mut w, op, b"v");
  }
  // All three residents are present; the head is the highest op.
  assert_eq!(w.op_head(), OpNumber::with(3));
  for op in 1..=3u64 {
    assert_eq!(w.status(OpNumber::with(op)), SlotStatus::Clean);
    assert!(w.header(OpNumber::with(op)).is_some());
  }
  // Append op 4 → slot 4 mod 3 == 1 == op 1's slot: op 1 is physically overwritten by op 4.
  append(&mut w, 4, b"v");
  assert_eq!(w.op_head(), OpNumber::with(4));
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Empty,
    "op 1 was wrapped over by op 4 (same ring slot) — its slot no longer holds it"
  );
  assert!(
    w.header(OpNumber::with(1)).is_none(),
    "a wrapped-over op has no resident header"
  );
  w.submit_read(read_id(100), OpNumber::with(1));
  assert!(
    matches!(w.poll(), Some(WalDone::Absent(_))),
    "a read of the wrapped-over op is Absent (a clean wrap; its bytes are gone)"
  );
  // op 4 (the new occupant of slot 1) and the untouched residents (ops 2, 3) read back intact.
  for op in [2u64, 3, 4] {
    assert_eq!(w.status(OpNumber::with(op)), SlotStatus::Clean);
    w.submit_read(read_id(200 + op), OpNumber::with(op));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => assert_eq!(r.op(), OpNumber::with(op)),
      other => panic!("op {op} should read back ReadOk, got {other:?}"),
    }
  }
}

#[test]
fn bounded_ring_eviction_clears_a_wrapped_bit_rot_verdict() {
  // Overwriting a bit-rotted ring slot physically rewrites the media, so the OLD op's permanent rot
  // verdict is cleared from the WAL (it leaves `rotted`): op 1 is rotted, then op 4 (same slot in an
  // n=3 ring) wraps over it. op 1 must read `Empty`, NOT `Faulty` — proving the eviction dropped its
  // rot entry rather than leaving a ghost verdict under a wrapped-away op number.
  let mut w = InMemoryWal::with_capacity_faults(
    3,
    StorageFaults {
      bit_rot_per_mille: 1000, // every append here rots its slot (we only need op 1's, for the wrap)
      ..StorageFaults::none()
    },
    1,
  );
  append(&mut w, 1, b"x");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Faulty,
    "op 1 rotted"
  );
  // Append ops 2, 3 (distinct slots), then op 4 wraps over op 1's slot (4 mod 3 == 1).
  append(&mut w, 2, b"x");
  append(&mut w, 3, b"x");
  append(&mut w, 4, b"x");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Empty,
    "op 1 (rotted) was physically overwritten by op 4 → no longer resident, and its rot verdict cleared"
  );
  // op 4 is the new resident of the slot (its OWN append-time verdict applies, not op 1's stale one).
  assert_ne!(
    w.status(OpNumber::with(4)),
    SlotStatus::Empty,
    "op 4 is the new resident of the slot"
  );
}

#[test]
fn bounded_ring_prune_and_truncate_work_on_the_resident_set() {
  // GC/view-change ops operate on the currently-resident ring ops exactly as in unbounded mode.
  let mut w = InMemoryWal::with_capacity(8);
  for op in 1..=5u64 {
    append(&mut w, op, b"v");
  }
  w.truncate(OpNumber::with(3));
  assert_eq!(w.op_head(), OpNumber::with(3));
  assert!(w.header(OpNumber::with(4)).is_none());
  w.prune(OpNumber::with(2));
  assert!(w.header(OpNumber::with(1)).is_none());
  assert!(w.header(OpNumber::with(2)).is_some());
  assert!(w.header(OpNumber::with(3)).is_some());
}

#[test]
fn bounded_ring_composes_with_async_appends() {
  // A bounded ring in async-append mode: the physical write (and thus the wrap-eviction) happens on
  // RELEASE, not at submit. An n=2 ring; op 1 then op 3 share slot 1. Stage + release op 1, then op 3
  // overwrites it on release. `set_capacity` makes an EMPTY async WAL bounded (exercising the setter).
  let mut w = InMemoryWal::with_async_appends(0);
  w.set_capacity(Some(2));
  let id1 = submit(&mut w, 1, 1, b"a");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Dirty, "staged");
  assert_eq!(w.poll(), Some(WalDone::Appended(id1)), "op 1 durable");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
  // op 3 shares op 1's slot (3 mod 2 == 1). Stage + release it → it overwrites op 1 on release.
  let id3 = submit(&mut w, 3, 3, b"c");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Clean,
    "op 1 still resident while op 3 is only STAGED (physical write deferred to release)"
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(id3)), "op 3 durable");
  assert_eq!(
    w.status(OpNumber::with(1)),
    SlotStatus::Empty,
    "op 3's release physically overwrote op 1's slot"
  );
  assert_eq!(w.status(OpNumber::with(3)), SlotStatus::Clean);
  assert_eq!(w.op_head(), OpNumber::with(3));
}

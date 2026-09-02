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
  // A torn slot keeps its ORIGINAL header (only the stored body bytes are corrupt) and reports the
  // body-level damage as Faulty. The header is fully durable and readable.
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Faulty);
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
fn a_damaged_body_gets_the_same_verdict_from_status_and_from_a_read() {
  // The `Wal` header-durability contract admits ONE verdict per slot: a body-level fault surfaces as
  // `SlotStatus::Faulty` from `status()` AND as `WalDone::BodyFaulty` from a read, keeping the
  // durable header readable either way. Both permanent body-fault classes are checked because they
  // reach the slot by different routes — bit-rot marks the slot, a torn write corrupts the stored
  // bytes — and a fixture that answered `Clean` for one of them would tell a caller the durable copy
  // is good while its own read says it is not.
  for faults in [
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
    StorageFaults {
      torn_write_per_mille: 1000,
      ..StorageFaults::none()
    },
  ] {
    let mut w = InMemoryWal::with_faults(faults, 3);
    append(&mut w, 1, b"body");
    let by_status = w.status(OpNumber::with(1));
    w.submit_read(read_id(1), OpNumber::with(1));
    let by_read = w.poll();
    assert_eq!(
      by_status,
      SlotStatus::Faulty,
      "status must report the damage the read reports ({by_read:?})"
    );
    assert!(
      matches!(by_read, Some(WalDone::BodyFaulty(_))),
      "a damaged body reads back BodyFaulty, got {by_read:?}"
    );
    assert!(
      w.header(OpNumber::with(1)).is_some(),
      "the header survives a body-level fault"
    );
  }
}

/// `replicas` WALs sharing ONE permanent-fault budget of `tolerance`, each with its own seed and the
/// given (certain, in these tests) fault plan — the cluster shape the budget exists to bound.
fn budgeted_wals(
  replicas: u16,
  tolerance: usize,
  faults: StorageFaults,
) -> (PermanentLossBudget, Vec<InMemoryWal>) {
  let budget = PermanentLossBudget::new(tolerance);
  let wals = (0..replicas)
    .map(|i| {
      let mut w = InMemoryWal::with_faults(faults, u64::from(i));
      w.set_loss_budget(budget.clone(), i);
      w
    })
    .collect();
  (budget, wals)
}

#[test]
fn a_unanimous_quorum_admits_no_permanent_body_fault() {
  // Two replicas: the quorum is 2, so `f` is 0 and destroying even ONE durable copy of a committed op
  // leaves it recoverable from nowhere. Both replicas roll a certain bit-rot; both must be refused
  // and both durable copies must still read back.
  let (budget, mut wals) = budgeted_wals(
    2,
    0,
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
  );
  for w in &mut wals {
    append(w, 1, b"committed");
  }
  assert_eq!(budget.refused(), 2, "one refusal per replica");
  for (i, w) in wals.iter_mut().enumerate() {
    assert_eq!(
      w.status(OpNumber::with(1)),
      SlotStatus::Clean,
      "replica {i}'s durable copy must survive"
    );
    w.submit_read(read_id(1), OpNumber::with(1));
    assert!(
      matches!(w.poll(), Some(WalDone::ReadOk(_))),
      "replica {i} must still read its copy back"
    );
  }
}

#[test]
fn a_permanent_body_fault_stops_at_the_last_readable_copies() {
  // Three replicas: the quorum is 2, so `f` is 1 — exactly one may permanently lose op 1. The
  // torn-write roll is certain everywhere, so the budget alone decides which copies survive.
  let (budget, mut wals) = budgeted_wals(
    3,
    1,
    StorageFaults {
      torn_write_per_mille: 1000,
      ..StorageFaults::none()
    },
  );
  for w in &mut wals {
    append(w, 1, b"committed");
  }
  assert_eq!(budget.refused(), 2, "two of three rolls refused");
  let destroyed = wals
    .iter()
    .filter(|w| w.status(OpNumber::with(1)) == SlotStatus::Faulty)
    .count();
  assert_eq!(destroyed, 1, "exactly f copies destroyed, never more");
}

#[test]
fn a_trimmed_slot_returns_its_seat_to_the_budget() {
  // A seat describes a destroyed copy that still EXISTS. Trimming the slot away destroys nothing that
  // is still there, so the seat must come back — otherwise one early fault would forbid faults at
  // that op number for the rest of the run, long after the op was re-minted over it.
  let (_budget, mut wals) = budgeted_wals(
    2,
    1,
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
  );
  append(&mut wals[0], 1, b"first");
  assert_eq!(wals[0].status(OpNumber::with(1)), SlotStatus::Faulty);
  append(&mut wals[1], 1, b"first");
  assert_eq!(
    wals[1].status(OpNumber::with(1)),
    SlotStatus::Clean,
    "the only seat is taken, so the second copy survives"
  );
  wals[0].truncate(OpNumber::with(0));
  append(&mut wals[1], 1, b"second");
  assert_eq!(
    wals[1].status(OpNumber::with(1)),
    SlotStatus::Faulty,
    "the released seat is available to another replica"
  );
}

#[test]
fn an_unbudgeted_wal_keeps_its_permanent_verdicts() {
  // A standalone fixture has no cluster to stay durable for, so it applies its verdicts unbudgeted —
  // the behaviour every targeted single-WAL gate relies on.
  let mut w = InMemoryWal::with_faults(
    StorageFaults {
      bit_rot_per_mille: 1000,
      ..StorageFaults::none()
    },
    1,
  );
  append(&mut w, 1, b"x");
  assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Faulty);
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

/// A durable VSR root whose `(checkpoint_op, checkpoint_id)` pair BOTH come from the given envelope
/// bytes — the step-2 root exactly as the proto mints it (the id is the envelope's content hash).
/// For tests that assert the root-names-stored-checkpoint integrity predicate, where
/// [`root_naming_checkpoint`]'s placeholder id would trip the id half of the check on its own.
fn root_naming_envelope(checkpoint_op: u64, snap: &[u8]) -> VsrState {
  VsrState::try_new(
    View::new(),
    View::new(),
    OpNumber::with(checkpoint_op),
    OpNumber::with(checkpoint_op),
    viewstamp_proto::checkpoint_id(snap),
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
  // A written-but-unrooted snapshot is NOT yet the live checkpoint under the redundant-copy model:
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
  // readable — the redundant-copy crash semantics.
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
fn a_staged_root_defers_the_live_checkpoint_handoff_until_it_lands() {
  // The retention window the serialized root writer still opens: a checkpoint's step-2 root is
  // STAGED (in flight, not yet durable), and until it lands the OLD checkpoint is the live one —
  // its snapshot must stay readable, and the newer written-but-unrooted generation must be
  // retained without being served. (The supersession arm — a LATER root naming an OLDER
  // checkpoint completing behind a newer-op root — is unreachable and so untested: the proto
  // session refuses a checkpoint-pointer rewind at its submission choke and hands the backend one
  // root write at a time, which the submit_write assert above enforces.)
  let mut sb = InMemorySuperblock::with_async_writes_and_faults(StorageFaults::none(), 1, 1);
  // Establish a rooted checkpoint at op 4 first (drain fully).
  sb.submit_write_checkpoint(write_id(1), OpNumber::with(4), Bytes::from_static(b"snap4"));
  drain(&mut sb);
  sb.submit_write(write_id(2), root_naming_checkpoint(4));
  drain(&mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  // A new checkpoint at op 8: snapshot written and durable, its step-2 root STAGED but unlanded.
  sb.submit_write_checkpoint(write_id(3), OpNumber::with(8), Bytes::from_static(b"snap8"));
  drain(&mut sb); // snapshot durable; op-8 root not yet submitted
  sb.submit_write(write_id(4), root_naming_checkpoint(8)); // step-2 root for op 8 (staged)
  // While the root is in flight the OLD checkpoint is still the live, servable one.
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));
  assert_eq!(read_live_checkpoint(&mut sb), (4, b"snap4".to_vec()));
  // The landing promotes op 8: the new generation is served, and only then is op 4 collectable.
  drain(&mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(8));
  assert_eq!(read_live_checkpoint(&mut sb), (8, b"snap8".to_vec()));
}

#[test]
fn envelope_lag_completes_a_later_root_around_the_lagging_envelope() {
  // The per-kind release the trait contract permits: an envelope write draws an extra seeded delay,
  // and a ROOT submitted after it completes FIRST — the cross-kind overtake under which an orphaned
  // envelope outlives the durable-view roots submitted after it. Both writes still complete exactly
  // once, and the durable state ends at the last-submitted root.
  use viewstamp_proto::SuperblockDone;
  let mut sb = InMemorySuperblock::with_async_writes_and_faults(StorageFaults::none(), 1, 1);
  sb.set_envelope_lag(Some(9));
  // The orphan shape: an envelope whose correlation a view transition dropped, then the
  // transition's durable-view root (carrying the old checkpoint pair) submitted after it.
  sb.submit_write_checkpoint(write_id(1), OpNumber::with(4), Bytes::from_static(b"snap4"));
  sb.submit_write(write_id(2), root_naming_checkpoint(0));
  let mut landed = Vec::new();
  for _ in 0..64 {
    if let Some(SuperblockDone::Wrote(id)) = sb.poll() {
      landed.push(id);
    }
    if sb.staged_len() == 0 && landed.len() == 2 {
      break;
    }
  }
  assert_eq!(
    landed,
    std::vec![write_id(2), write_id(1)],
    "the later root completed AROUND the lagging envelope, then the envelope landed"
  );
  assert_eq!(
    sb.envelope_overtakes_fired(),
    1,
    "the cross-kind overtake was counted (the reorder sweep's non-vacuity witness)"
  );
  assert_eq!(
    sb.state(),
    root_naming_checkpoint(0),
    "the durable state is the last-submitted root"
  );
  assert!(sb.poll().is_none(), "every write completed exactly once");
}

#[test]
fn repeated_root_over_envelope_overtakes_retain_a_constant_generation_count() {
  // The relocated backlog the in-flight ledgers cannot see: each cycle stages one envelope (the
  // fence's one outstanding write), a later view root overtakes it (the lag mode's cross-kind
  // release) naming the OLD live checkpoint, and the envelope then completes into the store with
  // no correlation left to root it. In-flight counts stay at one root / one envelope throughout —
  // yet without collection at the envelope landing the store retained every such completed
  // orphan, one distinct generation per view/checkpoint cycle, indefinitely. The collect holds
  // the retained set to live + staged-root-named + latest completed: at most three, every cycle.
  // This test pins the retained COUNT under orphan churn; which generations the collect must
  // KEEP — identity over numeric order — is pinned by
  // `a_completion_below_an_orphaned_generation_is_retained_until_rooted`.
  use viewstamp_proto::SuperblockDone;
  let mut sb = InMemorySuperblock::with_async_writes_and_faults(StorageFaults::none(), 1, 1);
  sb.set_envelope_lag(Some(9));
  // A rooted live checkpoint at op 4, never advanced by the orphaned cycles below.
  sb.submit_write_checkpoint(write_id(1), OpNumber::with(4), Bytes::from_static(b"live4"));
  drain(&mut sb);
  sb.submit_write(write_id(2), root_naming_checkpoint(4));
  drain(&mut sb);
  assert_eq!(sb.state().checkpoint_op(), OpNumber::with(4));

  let overtakes_before = sb.envelope_overtakes_fired();
  for cycle in 0..16u64 {
    // The cycle's checkpoint attempt writes its envelope at a fresh op...
    let op = 8 + 4 * cycle;
    sb.submit_write_checkpoint(
      write_id(100 + 2 * cycle),
      OpNumber::with(op),
      Bytes::from_static(b"orphan"),
    );
    // ...and a view transition drops the correlation and submits a durable-view root that still
    // names the OLD live checkpoint. Under the lag mode the root completes AROUND the staged
    // envelope; the envelope then lands with nothing left to root it.
    sb.submit_write(write_id(101 + 2 * cycle), root_naming_checkpoint(4));
    let mut landed = 0;
    for _ in 0..64 {
      if let Some(SuperblockDone::Wrote(_)) = sb.poll() {
        landed += 1;
      }
      if landed == 2 && sb.staged_len() == 0 {
        break;
      }
    }
    assert_eq!(landed, 2, "cycle {cycle}: both writes completed");
    assert!(
      sb.retained_snapshot_generations() <= 3,
      "cycle {cycle}: {} generations retained — the completed orphans are accumulating \
       outside every in-flight bound",
      sb.retained_snapshot_generations(),
    );
    // The live checkpoint stays served, untouched by the collection.
    assert_eq!(read_live_checkpoint(&mut sb), (4, b"live4".to_vec()));
  }
  // Non-vacuity: the cross-kind overtake genuinely fired (the axis was exercised, not staged
  // FIFO), so the constant count above was held UNDER overtakes, not in their absence.
  assert!(
    sb.envelope_overtakes_fired() > overtakes_before,
    "no root ever overtook a staged envelope — the schedule under test never occurred"
  );
}

#[test]
fn a_completion_below_an_orphaned_generation_is_retained_until_rooted() {
  // A cancelled pre-root install can leave a completed orphan generation ABOVE the local frontier:
  // with checkpoint 4 live, a state-sync envelope for op 12 lands after a view transition dropped
  // its install (no root for 12 will ever come), and the next local checkpoint then writes its
  // envelope at the still-valid frontier 8 — numerically BELOW the dead orphan. The generation a
  // live correlation can still root is identified by the LATEST COMPLETION (the session's envelope
  // lane admits one write at a time, and a fresh correlation rewrites its envelope before rooting,
  // so a new envelope submission is itself the witness that every older unrooted generation's
  // correlation is dead) — NOT by numeric order: selecting the numeric maximum deletes generation
  // 8 at its own landing and keeps dead 12, so the monotone step-2 root for 8 then names a
  // generation the store no longer holds. The retained COUNT stays within its bound throughout —
  // only the integrity predicate sees the self-poisoning: live-checkpoint reads fault on a medium
  // with no injected fault anywhere, so a solo replica cannot recover from its own disk and a
  // cluster escalates to a needless peer fetch.
  let mut sb = InMemorySuperblock::new();
  sb.submit_write_checkpoint(write_id(1), OpNumber::with(4), Bytes::from_static(b"snap4"));
  let _ = sb.poll();
  sb.submit_write(write_id(2), root_naming_envelope(4, b"snap4"));
  let _ = sb.poll();
  assert!(sb.root_names_stored_checkpoint_for_test());
  // The cancelled install's orphan: its envelope completes; no root for it ever comes.
  sb.submit_write_checkpoint(
    write_id(3),
    OpNumber::with(12),
    Bytes::from_static(b"snap12"),
  );
  let _ = sb.poll();
  // The valid local-frontier envelope lands BELOW the orphan...
  sb.submit_write_checkpoint(write_id(4), OpNumber::with(8), Bytes::from_static(b"snap8"));
  let _ = sb.poll();
  // ...and its step-2 root (submitted only after that envelope completed) makes it live.
  sb.submit_write(write_id(5), root_naming_envelope(8, b"snap8"));
  let _ = sb.poll();
  assert!(
    sb.root_names_stored_checkpoint_for_test(),
    "the durable root names checkpoint 8 but its generation is gone — collected at its own \
     landing while the dead orphan 12 was retained as the numeric maximum"
  );
  assert_eq!(read_live_checkpoint(&mut sb), (8, b"snap8".to_vec()));
  // The dead orphan was superseded by the newer completion; only the live generation remains.
  assert_eq!(sb.retained_snapshot_generations(), 1);
}

#[test]
#[should_panic(expected = "a second checkpoint-envelope write was submitted")]
fn a_second_staged_envelope_trips_the_backend_assert() {
  // The envelope-fence oracle: the proto session admits ONE outstanding envelope write, so a second
  // concurrent submission reaching the backend is a fence regression — refused fail-stop in every
  // profile, mirroring the one-root assert in `submit_write`.
  let mut sb = InMemorySuperblock::with_async_writes_and_faults(StorageFaults::none(), 1, 2);
  sb.submit_write_checkpoint(write_id(1), OpNumber::with(4), Bytes::from_static(b"a"));
  sb.submit_write_checkpoint(write_id(2), OpNumber::with(8), Bytes::from_static(b"b"));
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
    SlotStatus::Faulty,
    "a torn slot is Faulty once durable — its body no longer verifies"
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

/// A header for the stale-landing tests: identity varies with `client` so an eviction's description
/// names distinguishable content.
fn landing_header(op: u64, client: u128) -> Header {
  Header::new(
    OpNumber::with(op),
    View::new(),
    ClientId::new(client),
    RequestNumber::with(1),
    b"x",
  )
}

#[test]
fn an_older_incarnations_landing_over_a_newer_ones_is_a_stale_landing() {
  // Async mode with zero delay: each staged append lands on the next poll, so the LANDING ORDER is
  // the submission order — letting this test choose who lands over whom.
  let mut w = InMemoryWal::with_async_appends(0);
  // Incarnation 7 (the successor) lands op 1 first.
  w.submit_append(
    WriteId::new(7, 1),
    OpNumber::with(1),
    landing_header(1, 9),
    bytes::Bytes::from_static(b"new"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(WriteId::new(7, 1))));
  assert_eq!(w.stale_landings_fired(), 0, "a first landing has no holder");
  // Incarnation 5 (the dead predecessor, its write retained across a rebuild) lands the same op
  // afterwards: an older writer's bytes over a newer writer's landed slot.
  w.submit_append(
    WriteId::new(5, 1),
    OpNumber::with(1),
    landing_header(1, 7),
    bytes::Bytes::from_static(b"old"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(WriteId::new(5, 1))));
  assert_eq!(w.stale_landings_fired(), 1, "the stale landing is counted");
  let (op, why) = w
    .take_stale_landing()
    .expect("the stale landing is recorded");
  assert_eq!(op, 1);
  assert!(
    why.contains("incarnation 5") && why.contains("incarnation 7"),
    "the description names both writers: {why}"
  );
  assert!(w.take_stale_landing().is_none(), "drained");
}

#[test]
fn a_newer_incarnations_landing_over_an_older_ones_is_ordinary() {
  // The legitimate direction — recovery repairs, adoption re-appends — must stay silent.
  let mut w = InMemoryWal::with_async_appends(0);
  w.submit_append(
    WriteId::new(5, 1),
    OpNumber::with(1),
    landing_header(1, 7),
    bytes::Bytes::from_static(b"old"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(WriteId::new(5, 1))));
  w.submit_append(
    WriteId::new(7, 1),
    OpNumber::with(1),
    landing_header(1, 9),
    bytes::Bytes::from_static(b"new"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(WriteId::new(7, 1))));
  assert_eq!(w.stale_landings_fired(), 0);
  assert!(w.take_stale_landing().is_none());
}

#[test]
fn a_truncated_slot_has_no_holder_for_a_late_landing_to_be_stale_against() {
  // Truncation empties the slot: whatever lands into the trimmed region afterwards is landing into
  // ownerless space (the tolerated resurrection), not evicting anyone.
  let mut w = InMemoryWal::with_async_appends(0);
  w.submit_append(
    WriteId::new(7, 1),
    OpNumber::with(1),
    landing_header(1, 9),
    bytes::Bytes::from_static(b"new"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(WriteId::new(7, 1))));
  w.truncate(OpNumber::with(0));
  w.submit_append(
    WriteId::new(5, 1),
    OpNumber::with(1),
    landing_header(1, 7),
    bytes::Bytes::from_static(b"old"),
  );
  assert_eq!(w.poll(), Some(WalDone::Appended(WriteId::new(5, 1))));
  assert_eq!(w.stale_landings_fired(), 0);
  assert!(w.take_stale_landing().is_none());
}

/// The read-delay seed used by the fixtures below. Any seed works — they drive the device clock
/// directly and assert on the BAND each verdict lands in, not on a particular draw.
const READ_DELAY_SEED: u64 = 0xD0DE_1A17_5EED_0001;

/// The first op whose slot is DEGRADED under [`READ_DELAY_SEED`], and the first that is not. Read off
/// the same pure verdict the WAL uses, so the fixtures name real slots of the seeded medium rather
/// than hard-coding numbers that a mixer change would silently invalidate.
fn degraded_and_healthy_ops(seed: u64) -> (u64, u64) {
  let degraded = (1..10_000)
    .find(|&op| InMemoryWal::slot_degraded(seed, op))
    .expect("some slot in the first ten thousand is degraded");
  let healthy = (1..10_000)
    .find(|&op| !InMemoryWal::slot_degraded(seed, op))
    .expect("some slot in the first ten thousand is healthy");
  (degraded, healthy)
}

/// A virtual clock cursor in milliseconds, carried across the reads of one fixture: the device clock
/// is monotone, so each read's latency must be measured from where the previous one left it.
struct DeviceClock(u64);

impl DeviceClock {
  /// Advance the medium's clock to this cursor.
  fn feed(&self, w: &mut InMemoryWal) {
    w.advance_device_clock(Instant::from_nanos(self.0 * 1_000_000));
  }
}

/// Append `op` durably, submit a read of it, and return how long the completion took — driving the
/// device clock forward one millisecond at a time from where `clock` stands, so the measured latency
/// is the drawn one to within a millisecond.
fn read_latency(w: &mut InMemoryWal, clock: &mut DeviceClock, op: u64, seq: u64) -> Duration {
  clock.feed(w);
  submit(w, seq, op, b"body");
  while w.poll().is_some() {}
  w.submit_read(read_id(seq + 1_000), OpNumber::with(op));
  let submitted_at = clock.0;
  for _ in 0..10_000u64 {
    clock.0 += 1;
    clock.feed(w);
    if w.poll().is_some() {
      return Duration::from_millis(clock.0 - submitted_at);
    }
  }
  panic!("the read of op {op} never completed within ten virtual seconds");
}

#[test]
fn reads_resolve_inline_with_no_read_delay_plan() {
  // The default: a read's completion is queued in the call that submitted it, so it is available to
  // the very next poll with no clock ever advancing. This is the property every existing gate rests
  // on, and the reason an off-axis schedule cannot move.
  let mut w = InMemoryWal::new();
  submit(&mut w, 1, 1, b"x");
  assert_eq!(w.poll(), Some(WalDone::Appended(write_id(1))));
  w.submit_read(read_id(2), OpNumber::with(1));
  assert!(
    matches!(w.poll(), Some(WalDone::ReadOk(_))),
    "a read resolves inline without the axis"
  );
  assert_eq!(w.reads_delayed(), 0);
  assert_eq!(w.reads_past_budget(), 0);
  assert_eq!(w.late_bodies_delivered(), 0);
}

#[test]
fn a_degraded_slot_answers_past_the_recovery_read_budget_and_a_healthy_one_well_inside_it() {
  // The band the whole axis rests on: a degraded slot cannot answer inside the proto's recovery read
  // budget, so every additive retransmission of its op is outstanding when the op resolves from its
  // durable header — while a healthy slot always answers inside it, keeping the ordinary in-budget
  // read path exercised alongside.
  let (degraded, healthy) = degraded_and_healthy_ops(READ_DELAY_SEED);
  let mut w = InMemoryWal::new();
  w.set_read_delay(Some(READ_DELAY_SEED));
  let mut clock = DeviceClock(0);
  let slow = read_latency(&mut w, &mut clock, degraded, 1);
  assert!(
    slow > RECOVERY_READ_BUDGET,
    "a degraded slot answered in {slow:?}, inside the {RECOVERY_READ_BUDGET:?} recovery read budget"
  );
  assert!(
    slow < READ_STALL_FLOOR + READ_STALL_SPAN,
    "a degraded slot answered in {slow:?}, past the top of its band — a stall that outlives the \
     convergence drain would wedge an armed seed rather than make it late"
  );
  let fast = read_latency(&mut w, &mut clock, healthy, 2);
  assert!(
    fast < RECOVERY_READ_BUDGET,
    "a healthy slot answered in {fast:?}, outside the {RECOVERY_READ_BUDGET:?} recovery read budget"
  );
  assert_eq!(
    w.reads_past_budget(),
    1,
    "exactly the degraded read was late"
  );
  assert_eq!(w.late_bodies_delivered(), 1, "and it delivered bytes");
}

#[test]
fn every_read_of_a_degraded_slot_is_late_however_often_it_is_retried() {
  // The additive retransmissions share the op, so an op whose degradation was re-rolled per attempt
  // would be resolved by the first attempt that drew a healthy latency and could never reach its
  // budget with a live correlation. The verdict is a pure function of (seed, op) precisely so that
  // cannot happen.
  let (degraded, _) = degraded_and_healthy_ops(READ_DELAY_SEED);
  let mut w = InMemoryWal::new();
  w.set_read_delay(Some(READ_DELAY_SEED));
  let mut clock = DeviceClock(0);
  for attempt in 0..9 {
    let latency = read_latency(&mut w, &mut clock, degraded, attempt);
    assert!(
      latency > RECOVERY_READ_BUDGET,
      "retransmission {attempt} of a degraded slot answered in {latency:?}, inside the budget"
    );
  }
  assert_eq!(w.reads_past_budget(), 9);
}

#[test]
fn a_held_read_resolves_exactly_once_even_over_a_truncated_slot() {
  // A delay is a latency model, never a drop: the trait owes every submitted read exactly one
  // completion, and `truncate`/`prune` report cancelled WRITES only. So a read still in flight when
  // its slot is trimmed away still delivers the bytes it captured — which is precisely the
  // "captured before a later write mutated the slot" case an endpoint's carried-body durability
  // witness exists to judge — and delivers them once.
  let (degraded, _) = degraded_and_healthy_ops(READ_DELAY_SEED);
  let mut w = InMemoryWal::new();
  w.set_read_delay(Some(READ_DELAY_SEED));
  submit(&mut w, 1, degraded, b"body");
  while w.poll().is_some() {}
  w.submit_read(read_id(2), OpNumber::with(degraded));
  assert!(w.poll().is_none(), "the read is held, not resolved inline");
  assert!(
    w.truncate(OpNumber::with(degraded - 1)).is_empty(),
    "a truncate cancels writes, and there is none in flight"
  );
  let mut delivered = 0;
  for ms in 0..10_000u64 {
    w.advance_device_clock(Instant::from_nanos(ms * 1_000_000));
    while let Some(done) = w.poll() {
      assert!(
        matches!(done, WalDone::ReadOk(_)),
        "the trimmed slot's read still delivers the bytes it captured, got {done:?}"
      );
      delivered += 1;
    }
  }
  assert_eq!(delivered, 1, "exactly one completion, however long it took");
}

#[test]
fn a_crash_discards_the_reads_in_flight() {
  // In-flight reads are device work the process death takes with it, and the session that submitted
  // them dies too — a crash opens a fresh one over the surviving media, so nothing is owed those
  // completions any more. The durable log is untouched, and a later read of the same slot is served.
  let (degraded, _) = degraded_and_healthy_ops(READ_DELAY_SEED);
  let mut w = InMemoryWal::new();
  w.set_read_delay(Some(READ_DELAY_SEED));
  submit(&mut w, 1, degraded, b"body");
  while w.poll().is_some() {}
  w.submit_read(read_id(2), OpNumber::with(degraded));
  w.discard_inflight();
  let mut clock = DeviceClock(0);
  for _ in 0..10_000u64 {
    clock.0 += 1;
    clock.feed(&mut w);
    assert!(w.poll().is_none(), "a discarded read never resurfaces");
  }
  assert_eq!(w.status(OpNumber::with(degraded)), SlotStatus::Clean);
  assert!(read_latency(&mut w, &mut clock, degraded, 3) > RECOVERY_READ_BUDGET);
}

#[test]
fn a_held_read_stays_held_while_the_device_clock_stands_still() {
  // The due instants are stated against the device's own clock, so a medium nobody advances holds
  // its reads indefinitely — the requirement `set_read_delay` states on its harness.
  let (_, healthy) = degraded_and_healthy_ops(READ_DELAY_SEED);
  let mut w = InMemoryWal::new();
  w.set_read_delay(Some(READ_DELAY_SEED));
  submit(&mut w, 1, healthy, b"body");
  while w.poll().is_some() {}
  w.submit_read(read_id(2), OpNumber::with(healthy));
  for _ in 0..1_000 {
    assert!(w.poll().is_none(), "a held read waits on the device clock");
  }
  w.advance_device_clock(Instant::from_nanos(RECOVERY_READ_BUDGET.as_nanos() as u64));
  assert!(matches!(w.poll(), Some(WalDone::ReadOk(_))));
}

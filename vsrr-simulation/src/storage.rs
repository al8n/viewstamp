//! Deterministic in-memory `Wal`/`Superblock` impls for the DST harness.
//!
//! M3.0/M3.1: reliable + synchronous (each submit completes immediately into the
//! completion queue). M3.3a adds **seeded** fault injection ([`StorageFaults`]): TRANSIENT WAL read
//! faults (each read independently rolls — a retry may succeed, exercising the proto's
//! `Status::Recovering` retry loop), permanent torn writes (a flipped body byte ⇒ `Header::verify`
//! fails on read-back), and permanent bit-rot (every read of the slot faults). All faults surface as
//! data (`WalDone::Fault`/`Absent`, `SlotStatus::Faulty`) — the WAL never silently fixes a corrupt
//! body, so the proto's checksum chokepoint always sees it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bytes::Bytes;
use vsrr_proto::{
  CheckpointRead, Header, OpId, OpNumber, Prng, ReadOk, SlotStatus, Superblock, SuperblockDone,
  VsrState, Wal, WalDone,
};

/// Seeded storage-fault plan for one replica's WAL + superblock. Deterministic per (seed, replica):
/// the same seed reproduces the same fault decisions, and permanent verdicts (torn / bit-rot) live
/// in the durable struct so they survive a crash + restart unchanged.
///
/// All probabilities are out of 1000 (per mille), mirroring [`crate::Faults`] for the network. Like
/// `Faults`, this is a plain sim-harness config value with public fields — the "no public fields"
/// golden rule is enforced on `vsrr-proto` (the library), not on the simulation test harness, which
/// already uses pub-field config structs for ergonomic test setup.
///
/// # The transient-vs-permanent distinction (load-bearing for the M3.3a gate)
///
/// - **`read_fault_per_mille`** — TRANSIENT. Each `submit_read` rolls independently, so a faulted
///   read may succeed on retry; the proto's recover loop (budget `RECOVER_READ_RETRIES`) clears it.
///   The M3.3a "committed ops survive crash + storage-fault + restart" gate uses ONLY this, so a
///   restarted replica always recovers from its OWN disk and reaches `Normal` — no peer needed.
/// - **`torn_write_per_mille` / `bit_rot_per_mille`** — PERMANENT (a slot is gone until rewritten /
///   for good on this replica). Recovering such a committed slot needs a PEER: a permanently-faulty
///   HEAD slot ⇒ `RecoveringHead` + `StartView`/`RecoveryResponse` adoption (B1); a permanently-faulty
///   NON-head committed slot ⇒ peer fault-repair via `RequestPrepare` → `Prepare`, with the commit
///   HELD below the hole until the op arrives (B4). M3.3a gates set these to `0` because peer-repair
///   did not yet exist (a permanent committed-op fault would have tripped the old "committed op
///   present in log" expectation); the M3.3b permanent-fault gate turns them on and proves no
///   committed op is lost across crash + permanent fault + restart.
#[derive(Debug, Clone, Copy)]
pub struct StorageFaults {
  /// Per-read probability (out of 1000) that a WAL read returns `Fault` instead of the entry.
  /// TRANSIENT: re-rolled on every read, so a retry can succeed (the recover loop relies on this).
  pub read_fault_per_mille: u32,
  /// Per-append probability (out of 1000) that the durable body is written TORN (one flipped byte
  /// with the ORIGINAL header ⇒ `Header::verify` fails on read-back). Permanent until rewritten.
  pub torn_write_per_mille: u32,
  /// Per-append probability (out of 1000) that the slot is PERMANENTLY corrupt (bit-rot): every read
  /// of it faults, modelling unrecoverable media damage. (Used by M3.3b; `0` in M3.3a gates.)
  pub bit_rot_per_mille: u32,
}

impl StorageFaults {
  /// No faults: every read succeeds, no torn writes, no bit-rot.
  pub const fn none() -> Self {
    Self {
      read_fault_per_mille: 0,
      torn_write_per_mille: 0,
      bit_rot_per_mille: 0,
    }
  }
}

impl Default for StorageFaults {
  fn default() -> Self {
    Self::none()
  }
}

/// A seeded in-memory write-ahead log. With [`StorageFaults::none`] it is reliable + synchronous
/// (M3.0/M3.1 behaviour); with faults it injects transient read faults + permanent torn/bit-rot.
#[derive(Debug)]
pub struct InMemoryWal {
  entries: BTreeMap<u64, (Header, Bytes)>,
  head: u64,
  completions: VecDeque<WalDone>,
  faults: StorageFaults,
  /// Drives the TRANSIENT `read_fault_per_mille` decision. Re-rolled per read (independent attempts),
  /// so a faulted read clears on retry. Persists across restart in the struct (transient verdicts
  /// need not be stable; only permanent ones do, and those live in `entries`/`rotted`).
  prng: Prng,
  /// Slots marked PERMANENTLY corrupt (bit-rot) at append time: every read faults, `status` reports
  /// `Faulty`, `header` reports `None`. Persists across restart (the struct survives crash/restart).
  rotted: BTreeSet<u64>,
}

impl Default for InMemoryWal {
  fn default() -> Self {
    Self::new()
  }
}

impl InMemoryWal {
  /// Creates an empty, reliable WAL (no faults).
  pub fn new() -> Self {
    Self::with_faults(StorageFaults::none(), 0)
  }

  /// Creates an empty WAL with a seeded fault plan. `seed` drives the transient read-fault rolls and
  /// the per-append torn/bit-rot decisions deterministically.
  pub fn with_faults(faults: StorageFaults, seed: u64) -> Self {
    Self {
      entries: BTreeMap::new(),
      head: 0,
      completions: VecDeque::new(),
      faults,
      prng: Prng::new(seed),
      rotted: BTreeSet::new(),
    }
  }

  /// Test-only: the number of PERMANENTLY-corrupt slots in `1..=op` — bit-rotted (every read faults)
  /// or torn (the stored body fails its header's `verify`). Used by the M3.3b permanent-fault gate to
  /// assert the crashed replica's recovery is non-vacuous (it really does read back faulty committed
  /// slots that must be peer-repaired).
  #[doc(hidden)]
  pub fn corrupt_slots_at_or_below_for_test(&self, op: u64) -> usize {
    (1..=op)
      .filter(|&o| {
        self.rotted.contains(&o) || self.entries.get(&o).is_some_and(|(h, b)| !h.verify(b))
      })
      .count()
  }
}

/// Flips one byte of a body so `Header::verify` fails on read-back (a torn write). An empty body
/// grows by one junk byte (so it no longer matches a header computed over `b""`).
fn tear(body: &Bytes) -> Bytes {
  let mut v = body.to_vec();
  match v.first_mut() {
    Some(b) => *b ^= 0xFF,
    None => v.push(0xFF),
  }
  Bytes::from(v)
}

impl Wal for InMemoryWal {
  fn op_head(&self) -> OpNumber {
    OpNumber::with(self.head)
  }

  fn header(&self, op: OpNumber) -> Option<Header> {
    // A known-permanently-faulty (bit-rotted) slot reports no header, per the trait contract
    // ("None = absent OR known-faulty"). A torn slot still has its original header (the tear is
    // latent — only the body fails verify on read), so it reports its header as usual.
    if self.rotted.contains(&op.get()) {
      return None;
    }
    self.entries.get(&op.get()).map(|(h, _)| *h)
  }

  fn status(&self, op: OpNumber) -> SlotStatus {
    if self.rotted.contains(&op.get()) {
      SlotStatus::Faulty
    } else if self.entries.contains_key(&op.get()) {
      SlotStatus::Clean
    } else {
      SlotStatus::Empty
    }
  }

  fn submit_append(&mut self, id: OpId, op: OpNumber, header: Header, body: Bytes) {
    // PERMANENT bit-rot: mark the slot so every future read faults (and status/header report it).
    if self.faults.bit_rot_per_mille > 0 && self.prng.chance(self.faults.bit_rot_per_mille, 1000) {
      self.rotted.insert(op.get());
    }
    // PERMANENT torn write: persist the ORIGINAL header with a corrupted body so `Header::verify`
    // fails on read-back. Never silently fix it — the proto's checksum chokepoint must detect it.
    let stored = if self.faults.torn_write_per_mille > 0
      && self.prng.chance(self.faults.torn_write_per_mille, 1000)
    {
      tear(&body)
    } else {
      body
    };
    self.entries.insert(op.get(), (header, stored));
    self.head = self.head.max(op.get());
    self.completions.push_back(WalDone::Appended(id));
  }

  fn submit_read(&mut self, id: OpId, op: OpNumber) {
    // PERMANENT bit-rot: this slot always faults.
    if self.rotted.contains(&op.get()) {
      self.completions.push_back(WalDone::Fault(id));
      return;
    }
    // TRANSIENT read fault: rolled independently per read, so a retry may succeed — this is what the
    // proto's recover retry loop relies on to clear a transient fault from its OWN disk.
    if self.faults.read_fault_per_mille > 0
      && self.prng.chance(self.faults.read_fault_per_mille, 1000)
    {
      self.completions.push_back(WalDone::Fault(id));
      return;
    }
    // Otherwise return the stored entry. A torn body is returned AS-IS (it fails the proto's
    // `Header::verify`), never repaired.
    let done = match self.entries.get(&op.get()) {
      Some((h, b)) => WalDone::ReadOk(ReadOk::new(id, *h, b.clone())),
      None => WalDone::Absent(id),
    };
    self.completions.push_back(done);
  }

  fn truncate(&mut self, above: OpNumber) {
    self.entries.retain(|&op, _| op <= above.get());
    // A truncated-away slot is no longer corrupt (it will be rewritten by a later append).
    self.rotted.retain(|&op| op <= above.get());
    self.head = self.head.min(above.get());
  }

  fn prune(&mut self, below: OpNumber) {
    self.entries.retain(|&op, _| op >= below.get());
    self.rotted.retain(|&op| op >= below.get());
  }

  fn poll(&mut self) -> Option<WalDone> {
    self.completions.pop_front()
  }
}

/// A seeded in-memory superblock + checkpoint store. The only fault it injects is a TRANSIENT
/// checkpoint-read fault (`read_fault_per_mille`): the recover loop retries it within budget. It
/// NEVER permanently corrupts a checkpoint the durable root names (preserving the M3.2a invariant
/// that the root only ever names a fully-written snapshot), so the M3.3a recover always eventually
/// restores. Torn/bit-rot are WAL-only.
#[derive(Debug)]
pub struct InMemorySuperblock {
  state: VsrState,
  checkpoint: Option<(OpNumber, Bytes)>,
  completions: VecDeque<SuperblockDone>,
  faults: StorageFaults,
  prng: Prng,
}

impl Default for InMemorySuperblock {
  fn default() -> Self {
    Self::new()
  }
}

impl InMemorySuperblock {
  /// Creates a fresh-cluster superblock (`VsrState::initial`, no checkpoint, no faults).
  pub fn new() -> Self {
    Self::with_faults(StorageFaults::none(), 0)
  }

  /// Creates a fresh-cluster superblock with a seeded fault plan. Only `read_fault_per_mille` (a
  /// transient checkpoint-read fault) is honoured; torn/bit-rot do not apply to the superblock.
  pub fn with_faults(faults: StorageFaults, seed: u64) -> Self {
    Self {
      state: VsrState::initial(),
      checkpoint: None,
      completions: VecDeque::new(),
      faults,
      prng: Prng::new(seed),
    }
  }
}

impl Superblock for InMemorySuperblock {
  fn state(&self) -> VsrState {
    self.state
  }

  fn submit_write(&mut self, id: OpId, state: VsrState) {
    self.state = state;
    self.completions.push_back(SuperblockDone::Wrote(id));
  }

  fn submit_write_checkpoint(&mut self, id: OpId, op: OpNumber, snapshot: Bytes) {
    self.checkpoint = Some((op, snapshot));
    self.completions.push_back(SuperblockDone::Wrote(id));
  }

  fn submit_read_checkpoint(&mut self, id: OpId) {
    // TRANSIENT checkpoint-read fault: rolled independently per read, so the proto's recover loop
    // clears it within budget. NEVER permanent — the root always names a fully-written snapshot, so
    // a real `None` (no checkpoint) is the only non-transient `Fault`, returned unconditionally.
    if self.checkpoint.is_some()
      && self.faults.read_fault_per_mille > 0
      && self.prng.chance(self.faults.read_fault_per_mille, 1000)
    {
      self.completions.push_back(SuperblockDone::Fault(id));
      return;
    }
    let done = match &self.checkpoint {
      Some((op, snap)) => {
        SuperblockDone::CheckpointRead(CheckpointRead::new(id, *op, snap.clone()))
      }
      None => SuperblockDone::Fault(id),
    };
    self.completions.push_back(done);
  }

  fn poll(&mut self) -> Option<SuperblockDone> {
    self.completions.pop_front()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use vsrr_proto::{
    ClientId, Header, OpId, OpNumber, RequestNumber, Superblock, View, VsrState, Wal, WalDone,
  };

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
      OpId::new(1),
      OpNumber::with(1),
      h,
      bytes::Bytes::from_static(b"x"),
    );
    assert_eq!(w.poll(), Some(WalDone::Appended(OpId::new(1))));
    assert_eq!(w.op_head(), OpNumber::with(1));
    assert_eq!(w.header(OpNumber::with(1)), Some(h));
    w.submit_read(OpId::new(2), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => {
        assert_eq!(r.op(), OpNumber::with(1));
        assert_eq!(r.body(), b"x");
      }
      other => panic!("expected ReadOk, got {other:?}"),
    }
    w.submit_read(OpId::new(3), OpNumber::with(9));
    assert_eq!(w.poll(), Some(WalDone::Absent(OpId::new(3))));
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
        OpId::new(op),
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
    assert_eq!(sb.state(), VsrState::initial());
    let next = VsrState::try_new(
      View::with(2),
      View::with(2),
      OpNumber::with(3),
      OpNumber::with(0),
      0,
    )
    .unwrap();
    sb.submit_write(OpId::new(1), next);
    assert!(sb.poll().is_some());
    assert_eq!(sb.state(), next);
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
      OpId::new(op),
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
      a.submit_read(OpId::new(i), OpNumber::with(1));
      b.submit_read(OpId::new(i), OpNumber::with(1));
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
    // The load-bearing property for the M3.3a gate: a TRANSIENT read fault must clear within the
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
        w.submit_read(OpId::new(round * 9 + attempt), OpNumber::with(1));
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
  fn bit_rot_makes_a_slot_permanently_faulty() {
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
    assert!(
      w.header(OpNumber::with(1)).is_none(),
      "a known-faulty slot reports no header"
    );
    for i in 0..5u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      assert!(
        w.poll().unwrap().is_fault(),
        "permanent: every read of a bit-rotted slot faults"
      );
    }
  }

  #[test]
  fn torn_write_fails_proto_verify_on_read() {
    let mut w = InMemoryWal::with_faults(
      StorageFaults {
        torn_write_per_mille: 1000,
        ..StorageFaults::none()
      },
      1,
    );
    append(&mut w, 1, b"intact");
    // A torn slot keeps its ORIGINAL header (the tear is latent) and reports Clean — only the body
    // fails verify on read, exactly the corruption a dumb backend cannot hide from the proto.
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    assert!(w.header(OpNumber::with(1)).is_some());
    w.submit_read(OpId::new(2), OpNumber::with(1));
    match w.poll() {
      Some(WalDone::ReadOk(r)) => assert!(
        !r.header().verify(r.body()),
        "a torn body fails the proto's Header::verify"
      ),
      other => panic!("torn write should still yield a (corrupt) ReadOk, got {other:?}"),
    }
  }

  #[test]
  fn permanent_verdicts_survive_a_restart_via_the_persisted_struct() {
    // A bit-rotted slot stays rotted across a crash/restart because the WAL struct persists in the
    // Cluster (the `rotted` set lives in the struct). This is what makes the M3.3b permanent-fault
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
    // faults, proving the verdict is stable for the lifetime of the durable medium.
    for i in 0..3u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      assert!(w.poll().unwrap().is_fault());
    }
  }

  #[test]
  fn superblock_checkpoint_read_fault_is_transient() {
    use vsrr_proto::SuperblockDone;
    let mut sb = InMemorySuperblock::with_faults(
      StorageFaults {
        read_fault_per_mille: 500,
        ..StorageFaults::none()
      },
      3,
    );
    // Stage a checkpoint so reads have something to (transiently) fault on.
    sb.submit_write_checkpoint(OpId::new(1), OpNumber::with(4), Bytes::from_static(b"snap"));
    let _ = sb.poll();
    let mut saw_fault = false;
    let mut saw_read = false;
    for i in 1..40u64 {
      sb.submit_read_checkpoint(OpId::new(i));
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
  fn no_faults_is_byte_for_byte_reliable() {
    // StorageFaults::none() must reproduce the old reliable behaviour exactly.
    let mut w = InMemoryWal::with_faults(StorageFaults::none(), 42);
    append(&mut w, 1, b"intact");
    assert_eq!(w.status(OpNumber::with(1)), SlotStatus::Clean);
    for i in 0..10u64 {
      w.submit_read(OpId::new(i), OpNumber::with(1));
      match w.poll() {
        Some(WalDone::ReadOk(r)) => assert!(r.header().verify(r.body())),
        other => panic!("no-faults WAL must always ReadOk a present slot, got {other:?}"),
      }
    }
  }
}

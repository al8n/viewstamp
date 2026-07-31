use std::{collections::HashMap, time::Duration};

use bytes::Bytes;
use viewstamp_proto::{
  BlockAddress, BlockJob, BlockJobDone, BlockStore, BlockStoreError, ClientId, Config, Endpoint,
  Epoch, Instant, MemberId, Membership, Message, Peer, Request, RequestNumber, SingleChange,
};
use viewstamp_simulation::{InMemorySuperblock, InMemoryWal, sm::LogSm};

use super::BlockLane;

const CLUSTER: u128 = 0x51a1;

/// How long a test waits for a spawned lane's worker to answer before calling it wedged. Orders of
/// magnitude above the microseconds an in-memory store needs, so a loaded machine cannot fail it.
const LANE_ANSWER_DEADLINE: Duration = Duration::from_secs(5);

/// A volatile block store, the minimum a lane needs to execute a real checkpoint materialize.
#[derive(Default)]
struct MemBlocks {
  blocks: HashMap<BlockAddress, Bytes>,
}

impl BlockStore for MemBlocks {
  fn read_block(&self, addr: BlockAddress) -> Option<Bytes> {
    self.blocks.get(&addr).cloned()
  }
  fn put(&mut self, block: Bytes) -> BlockAddress {
    let addr = viewstamp_proto::block_address(&block);
    self.blocks.insert(addr, block);
    addr
  }
  fn flush(&mut self) -> Result<(), BlockStoreError> {
    Ok(())
  }
  fn has_block(&self, addr: BlockAddress) -> bool {
    self.blocks.contains_key(&addr)
  }
}

/// The genesis membership for an `n`-voter cluster, `MemberId::new(i)` in slot `i`.
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

/// A formatted single-voter store and the endpoint over it, at `checkpoint_ops = 1` so the first
/// committed op immediately owes a checkpoint — the cheapest way to make an endpoint issue a real
/// block job.
///
/// A sole voter is its own quorum, so its own durable append commits the op with no peer traffic.
fn single_voter() -> (
  Endpoint<LogSm, SingleChange>,
  InMemoryWal,
  InMemorySuperblock,
) {
  let config = Config::with_checkpoint_ops(CLUSTER, MemberId::new(0_u128), 1)
    .expect("a valid single-voter config");
  let mut wal = InMemoryWal::new();
  let mut sb = InMemorySuperblock::new();
  crate::format(config, &genesis(1), &wal, &mut sb).expect("format the genesis store");
  let endpoint = crate::build_endpoint(config, genesis(1), LogSm::default(), &mut wal, &mut sb)
    .expect("the formatted store builds an endpoint");
  (endpoint, wal, sb)
}

/// Commit one client op and return the first block job the endpoint queues for it.
fn first_job(
  endpoint: &mut Endpoint<LogSm, SingleChange>,
  wal: &mut InMemoryWal,
  sb: &mut InMemorySuperblock,
) -> BlockJob<LogSm> {
  let now = Instant::ZERO;
  endpoint.handle_message(
    now,
    wal,
    sb,
    Peer::Client(ClientId::new(7)),
    Message::Request(Request::new(
      ClientId::new(7),
      RequestNumber::with(1),
      Bytes::from_static(b"x"),
    )),
  );
  for _ in 0..64 {
    endpoint.handle_storage(now, wal, sb);
    if let Some(job) = endpoint.poll_block_job() {
      return job;
    }
  }
  panic!("a committed op at checkpoint_ops = 1 owes a checkpoint materialize");
}

/// A SPAWNED lane carries a checkpoint through to its durable root: the endpoint issues jobs, the
/// lane executes them on its own thread, and feeding the completions back publishes the checkpoint.
///
/// The recorded ids assert the end-to-end order — every job answered, in the order it was issued —
/// which is also enforced from the other side: the endpoint fail-stops on any other order, so a
/// green run is the ordering assertion twice over.
#[test]
fn a_spawned_lane_carries_a_checkpoint_to_its_durable_root() {
  let (mut endpoint, mut wal, mut sb) = single_voter();
  let lane: BlockLane<LogSm> = BlockLane::spawn(MemBlocks::default());
  let now = Instant::ZERO;

  let first = first_job(&mut endpoint, &mut wal, &mut sb);
  let mut issued = vec![first.id()];
  let mut answered = Vec::new();
  lane.submit(first);

  // Drive to quiescence: a completion can release the next job (the materialize's durable root is
  // what lets the sweep run), so the loop alternates until the endpoint owes no storage at all.
  let deadline = std::time::Instant::now() + LANE_ANSWER_DEADLINE;
  while endpoint.has_inflight_storage() {
    assert!(
      std::time::Instant::now() < deadline,
      "the spawned lane left the endpoint owing storage after {LANE_ANSWER_DEADLINE:?}",
    );
    endpoint.handle_storage(now, &mut wal, &mut sb);
    while let Some(job) = endpoint.poll_block_job() {
      issued.push(job.id());
      lane.submit(job);
    }
    while let Some(done) = lane.try_recv() {
      answered.push(done.id());
      endpoint.on_block_done(now, &mut wal, &mut sb, done);
    }
    std::thread::yield_now();
  }

  assert_eq!(
    answered, issued,
    "every issued job is answered, in the order it was issued"
  );
  assert_eq!(
    viewstamp_proto::Superblock::state(&sb)
      .checkpoint_op()
      .get(),
    1,
    "the materialize the lane executed published a durable checkpoint at the committed op"
  );
}

/// An INLINE lane resolves a job WITHIN the submit — the property a deterministic harness needs, so
/// a test can step a driver without waiting on a thread.
#[test]
fn an_inline_lane_answers_within_the_submit() {
  let (mut endpoint, mut wal, mut sb) = single_voter();
  let lane: BlockLane<LogSm> = BlockLane::inline(MemBlocks::default());

  let job = first_job(&mut endpoint, &mut wal, &mut sb);
  let id = job.id();
  lane.submit(job);

  let done: BlockJobDone<LogSm> = lane
    .try_recv()
    .expect("an inline lane has executed the job by the time `submit` returns");
  assert_eq!(done.id(), id, "the completion answers the submitted job");
}

/// THE CURSOR'S CROSS-INCARNATION CHECK, and why the lane must own it.
///
/// Two endpoints sharing one storage lane model a rebuild in place: incarnations come from one
/// process-wide monotone counter, so the endpoint built SECOND carries the larger one. Executing the
/// dead endpoint's still-queued job AFTER its successor's — the interleaving an asynchronous lane
/// makes reachable — is exactly what the lane's cursor exists to stop, and it fail-stops here.
#[test]
#[should_panic(expected = "block job executed out of issue order")]
fn one_lane_stops_a_dead_endpoints_job_running_after_its_successors() {
  let (mut dead, mut dead_wal, mut dead_sb) = single_voter();
  let dead_job = first_job(&mut dead, &mut dead_wal, &mut dead_sb);
  let (mut live, mut live_wal, mut live_sb) = single_voter();
  let live_job = first_job(&mut live, &mut live_wal, &mut live_sb);
  assert!(
    live_job.id().incarnation() > dead_job.id().incarnation(),
    "the endpoint built second holds the later incarnation",
  );

  let lane: BlockLane<LogSm> = BlockLane::inline(MemBlocks::default());
  lane.submit(live_job);
  lane.submit(dead_job);
}

/// The counterpart, and the reason the cursor must OUTLIVE a rebuild: a FRESH lane has nothing for
/// its first admission to follow, so the very job the shared lane above stopped is admitted here
/// without a word. A driver that minted a new lane when it rebuilt an endpoint over the same store
/// would forfeit the guarantee silently — this is what that forfeit looks like.
#[test]
fn a_fresh_lanes_first_admission_is_unchecked() {
  let (mut dead, mut dead_wal, mut dead_sb) = single_voter();
  let dead_job = first_job(&mut dead, &mut dead_wal, &mut dead_sb);
  let (mut live, mut live_wal, mut live_sb) = single_voter();
  let live_job = first_job(&mut live, &mut live_wal, &mut live_sb);

  let successors_lane: BlockLane<LogSm> = BlockLane::inline(MemBlocks::default());
  successors_lane.submit(live_job);
  let rebuilt_lane: BlockLane<LogSm> = BlockLane::inline(MemBlocks::default());
  rebuilt_lane.submit(dead_job);

  assert!(
    rebuilt_lane.try_recv().is_some(),
    "a fresh cursor admits the dead endpoint's job unchecked — the guarantee the shared lane keeps"
  );
}

/// A CLONE is the same lane: same store, same cursor. This is how a lane survives the driver that
/// held it, so a rebuilt driver executes against a cursor that already remembers what the dead
/// driver's lane ran.
#[test]
fn a_clone_carries_the_lanes_cursor_past_the_driver_that_held_it() {
  let (mut dead, mut dead_wal, mut dead_sb) = single_voter();
  let dead_job = first_job(&mut dead, &mut dead_wal, &mut dead_sb);
  let (mut live, mut live_wal, mut live_sb) = single_voter();
  let live_job = first_job(&mut live, &mut live_wal, &mut live_sb);

  let lane: BlockLane<LogSm> = BlockLane::inline(MemBlocks::default());
  let carried = lane.clone();
  drop(lane); // the driver that held the original is gone; the embedder kept this handle
  carried.submit(live_job);

  let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    carried.submit(dead_job);
  }));
  assert!(
    stopped.is_err(),
    "the carried clone still holds the cursor that stops the dead endpoint's job"
  );
}

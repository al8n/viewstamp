use core::time::Duration;

use bytes::Bytes;
use viewstamp_proto::{
  BATCH_COUNT_OVERHEAD, BATCH_UNIT_OVERHEAD, BatchBuilder, ClientId, Instant, Message, Prng,
  ReplyOutcome, ReplyTooLarge, Request, RequestNumber, max_request_body_len,
};

use crate::batching::{BatchingClient, BatchingConfig, SubmittedBody};

const REQUEST_TIMEOUT: Duration = Duration::from_millis(200);

/// One in `LARGE_BODY_DENOM` requests (seeded, per client+request) carries a LARGE body instead of
/// the default 8 bytes — the rest stay small. Kept rare so most requests stay cheap: the
/// large ones are what build a large-bodied uncheckpointed band that rides the (header-only)
/// view-change carriers + the byte-bounded `RepairBatch` repair serve.
const LARGE_BODY_DENOM: u32 = 12;

/// The maximum LARGE-body size, as a fraction of [`max_request_body_len`] (the largest body that fits
/// every single-message carrier — `Request`/`Prepare`/single-entry `RepairBatch` — by construction).
/// A large request draws a size in `[1, max_request_body_len() / LARGE_BODY_DIVISOR]` ≈ `[1, 64 KiB]`.
/// Well under the per-message bound, so any single `Prepare`/`Request` stays far below the frame cap (a
/// legitimate single-message carrier is NEVER oversized-dropped), while a DEEP band of such ops,
/// carried full-bodied, would sum past the frame: the overflow header-only carriers exist to avoid,
/// and what makes `oversized_dropped == 0` a real oracle as large
/// bodies flow through view-change/recovery. ~64 KiB (not the multi-MiB `max`) is the sweet spot: still
/// ~8000× the 8-byte default — genuinely large, building a non-trivial band — yet small enough that the
/// MiB-scale clone/encode churn (broadcast × duplicate × thousands of ticks × up to 6 replicas) does
/// NOT blow the VOPR's wall-clock. The frame-overflow CONVERSE (a full-bodied band would be dropped) is
/// proven separately with near-`max` bodies in the focused proto + `cluster.rs` unit tests, so the
/// sweep does not need maximal bodies for the cap to stay a real oracle.
const LARGE_BODY_DIVISOR: usize = 256;

/// The minimum LARGE-body size (bytes). A "large" request is floored here so it is ALWAYS strictly
/// above the 8-byte default — making the `> 8` large-body count exact — and is a genuinely substantial
/// body (1 KiB, ~128× the default) even at the low end of the draw.
const LARGE_BODY_FLOOR: usize = 1024;

/// Domain separator mixed into the per-(client, request) large-body PRNG seed so it is independent of
/// every other seeded stream (the network/storage PRNGs, the bounded-WAL draw). Drawing the body-size
/// decision from THIS derived seed — never from the cluster's action PRNG — keeps the fault schedule
/// (drops/crashes/partitions) byte-identical to the small-body sweep; only the body sizes change.
const LARGE_BODY_SEED_MAGIC: u64 = 0x1A6E_B0D7_51DE_0B0D;

/// A simple closed-loop client: one request in flight; on reply, record it and
/// issue the next, until `total` requests have committed.
#[derive(Debug)]
pub struct ClientModel {
  id: ClientId,
  total: u64,
  next_request: u64,
  replies: Vec<(u64, Bytes)>,
  /// Parallel to [`Self::replies`], one entry per recorded reply in the SAME order, each carrying the
  /// virtual instant the matching `Reply` was delivered to the client — i.e. when the request was
  /// ACKED at real (sim) time. The staleness oracle folds these to learn each acked op's
  /// ack-instant; the plain [`Self::replies`] record is kept untouched so the other checkers and the
  /// digest harness read it unchanged.
  replies_at: Vec<(u64, Bytes, Instant)>,
  /// Requests answered with the terminal REFUSAL outcome instead of a body: `(request, refusal)` in
  /// ack order. A refused request is ANSWERED — the client advances exactly as it does on a body,
  /// and it counts toward [`Self::is_done`] — but the result is an ERROR, so it is never appended to
  /// [`Self::replies`] where a checker or the digest would read it as a payload. Empty on every run
  /// whose state machine keeps its replies within the bound.
  refused: Vec<(u64, ReplyTooLarge)>,
  inflight: Option<Request>,
  /// Last instant at which the inflight request was transmitted; `None` means
  /// "not yet sent this cycle" so the next `pending` call must transmit.
  last_sent: Option<Instant>,
  /// The cluster base seed, mixed with the client id + request number to make the per-request
  /// large-body decision a deterministic function of the seed (no draw from the action PRNG).
  seed: u64,
  /// How many LARGE-bodied requests this client has minted (observability: the VOPR asserts the
  /// large-body axis genuinely fired — `> 0` across the sweep — so the frame cap is tested non-vacuously).
  large_bodies_sent: u64,
  /// `None` (default) ⇒ the seeded small/large body mix above. `Some(len)` ⇒ EVERY request carries
  /// exactly `len` body bytes (first 8 still the request number, big-endian). The large-snapshot
  /// state-sync gate sets this so a short run accumulates a checkpoint envelope past the one-frame
  /// threshold without thousands of requests.
  fixed_body_len: Option<usize>,
  /// `Some` ⇒ this client is a BATCHING client: bodies are packed from the model's unit queue
  /// instead of [`Self::body_for`], replies are demultiplexed per unit, and the model keeps the
  /// per-unit bookkeeping the unit oracle consumes. `None` (default) ⇒ the plain client path,
  /// whose per-seed schedules stay byte-identical (no batching draw is consumed).
  batching: Option<BatchingClient>,
  /// `true` ⇒ every plain body is wrapped as a ONE-unit batch through the real codec, so a
  /// batching-mode cluster (whose `BatchSm` parses every committed body) can carry this client's
  /// traffic. Plain clients in a batching lane set this; the default `false` leaves bodies
  /// untouched (pinned-seed schedules stay byte-identical).
  wrap_single_unit: bool,
}

impl ClientModel {
  /// Creates a client that will issue `total` requests, numbered 1..=total. `seed` is the cluster base
  /// seed, used to derive the deterministic per-request large-body decision.
  pub fn new(id: u128, total: u64, seed: u64) -> Self {
    Self {
      id: ClientId::new(id),
      total,
      next_request: 1,
      replies: Vec::new(),
      replies_at: Vec::new(),
      refused: Vec::new(),
      inflight: None,
      last_sent: None,
      seed,
      large_bodies_sent: 0,
      fixed_body_len: None,
      batching: None,
      wrap_single_unit: false,
    }
  }

  /// Turn this client into a BATCHING client driving the aggregator model (call before the run
  /// starts): units are emitted on `cfg`'s seeded cadence, queued, packed FIFO into one-in-flight
  /// request bodies, and demultiplexed per unit on ack. Replaces the plain body generation
  /// entirely; the request numbering, one-in-flight discipline, and retransmit cadence are the
  /// existing client model's.
  pub fn enable_batching(&mut self, cfg: BatchingConfig) {
    self.batching = Some(BatchingClient::new(cfg));
  }

  /// Make every plain body a ONE-unit batch (call before the run starts): the codec wrap that lets
  /// a batching-mode cluster parse this client's traffic. A no-op for a batching client.
  pub fn wrap_bodies_as_single_unit_batches(&mut self) {
    self.wrap_single_unit = true;
  }

  /// The batching model's mutable half, for scripted gates (`enqueue_unit` / `enqueue_group`).
  /// `None` for a plain client.
  pub fn batching_mut(&mut self) -> Option<&mut BatchingClient> {
    self.batching.as_mut()
  }

  /// The packed-body bookkeeping the unit oracle consumes (empty for a plain client).
  pub fn batched_bodies(&self) -> &[SubmittedBody] {
    self.batching.as_ref().map_or(&[], |b| b.bodies())
  }

  /// How many bodies packed more than one unit (0 for a plain client). Monotone.
  pub fn bodies_with_multiple_units(&self) -> u64 {
    self
      .batching
      .as_ref()
      .map_or(0, BatchingClient::bodies_with_multiple_units)
  }

  /// The largest unit count any single body carried (0 for a plain client). Monotone.
  pub fn max_units_per_body(&self) -> u64 {
    self
      .batching
      .as_ref()
      .map_or(0, BatchingClient::max_units_per_body)
  }

  /// How many atomic groups were enqueued (0 for a plain client). Monotone.
  pub fn groups_submitted(&self) -> u64 {
    self
      .batching
      .as_ref()
      .map_or(0, BatchingClient::groups_submitted)
  }

  /// How many units have been acked (0 for a plain client). Monotone.
  pub fn units_acked(&self) -> u64 {
    self
      .batching
      .as_ref()
      .map_or(0, BatchingClient::units_acked)
  }

  /// Make EVERY request from this client carry exactly `len` body bytes (replacing the seeded
  /// small/large mix). Call before the run starts. The large-snapshot state-sync gate uses this to
  /// drive the cluster's checkpoint envelope past the one-frame threshold in a short run.
  pub fn set_fixed_body_len(&mut self, len: usize) {
    self.fixed_body_len = Some(len);
  }

  /// The client id.
  pub fn id(&self) -> ClientId {
    self.id
  }

  /// The replies received so far, bodies only — a refused request is in [`Self::refused`].
  pub fn replies(&self) -> &[(u64, Bytes)] {
    &self.replies
  }

  /// The requests answered with the over-bound-reply REFUSAL, in ack order.
  pub fn refused(&self) -> &[(u64, ReplyTooLarge)] {
    &self.refused
  }

  /// The replies received so far, each STAMPED with the virtual instant it was acked (the `Reply`
  /// delivery instant) — `(request, reply_body, ack_instant)`, in the same order as [`Self::replies`].
  /// The staleness oracle reads this to learn when each committed op was acked to a client.
  pub fn replies_at(&self) -> &[(u64, Bytes, Instant)] {
    &self.replies_at
  }

  /// How many LARGE-bodied requests this client has minted (the non-vacuity witness for the frame-cap
  /// axis: across the sweep this must climb `> 0`, proving large bodies really flowed).
  pub fn large_bodies_sent(&self) -> u64 {
    self.large_bodies_sent
  }

  /// True once every request has received its reply. A batching client is done when its emission
  /// budget is spent, its queue is drained, and nothing is in flight (every packed body acked).
  pub fn is_done(&self) -> bool {
    match &self.batching {
      Some(b) => b.is_drained() && self.inflight.is_none(),
      None => self.answered() == self.total,
    }
  }

  /// How many of this client's requests have reached a TERMINAL outcome — a body or a refusal.
  /// Both end the request: the op committed either way, so the client never retries it.
  fn answered(&self) -> u64 {
    (self.replies.len() + self.refused.len()) as u64
  }

  /// RETIRE this client: it permanently stops issuing/retransmitting (any in-flight request is
  /// abandoned) and counts as done for the liveness checks. The churn lane uses this to model a
  /// client leaving the system — its session row on the replicas goes idle and ages toward the
  /// deterministic cap eviction, while a freshly-spawned client takes over the load.
  pub fn retire(&mut self) {
    self.total = self.answered();
    self.inflight = None;
    self.last_sent = None;
    if let Some(b) = self.batching.as_mut() {
      b.retire();
    }
  }

  /// The body for request number `req`: the default 8 bytes, or — for a seeded ~1/[`LARGE_BODY_DENOM`]
  /// fraction of requests — a LARGE body sized in `[LARGE_BODY_FLOOR,
  /// max_request_body_len()/LARGE_BODY_DIVISOR]`. The decision + size are a pure function of `(seed,
  /// client, req)`, so the run stays deterministic without perturbing the cluster's action PRNG. The
  /// first 8 bytes always carry `req` big-endian (a large body is `req`'s bytes padded), so the body
  /// still encodes the request number.
  fn body_for(&self, req: u64) -> Bytes {
    let small = req.to_be_bytes();
    // The fixed-size override (the large-snapshot gate): every body exactly `len` bytes, the first
    // 8 still carrying `req` big-endian so the reply checkers keep working.
    if let Some(len) = self.fixed_body_len {
      let mut body = std::vec![0u8; len.max(small.len())];
      body[..small.len()].copy_from_slice(&small);
      return Bytes::from(body);
    }
    let mut prng = Prng::new(
      self
        .seed
        .wrapping_mul(0x100_0000_01b3)
        .wrapping_add(self.id.get() as u64)
        .wrapping_add(req.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        ^ LARGE_BODY_SEED_MAGIC,
    );
    if !prng.chance(1, LARGE_BODY_DENOM) {
      return Bytes::from(small.to_vec());
    }
    // A genuinely-large body: floored at `LARGE_BODY_FLOOR` (so the "large" branch is always > the
    // 8-byte default — the `> 8` count in `pending` is then exact) and capped at
    // `max_request_body_len() / LARGE_BODY_DIVISOR`. The first 8 bytes carry `req` big-endian.
    let ceil = (max_request_body_len() / LARGE_BODY_DIVISOR).max(LARGE_BODY_FLOOR + 1);
    let span = (ceil - LARGE_BODY_FLOOR) as u64;
    let len = LARGE_BODY_FLOOR + prng.below(span) as usize;
    let mut body = std::vec![0u8; len];
    body[..small.len()].copy_from_slice(&small);
    Bytes::from(body)
  }

  /// Returns the request to (re)send this instant, if any: mints the next request
  /// when idle, and (re)transmits the in-flight request when first sent or when
  /// `REQUEST_TIMEOUT` has elapsed since the last send. Returns `None` otherwise.
  ///
  /// A BATCHING client mints its next request by stepping the model's seeded emission once (this
  /// is the per-tick call) and, when idle, packing the queue FIFO into one body; the one-in-flight
  /// and retransmit discipline below is shared verbatim with the plain path.
  pub fn pending(&mut self, now: Instant) -> Option<Request> {
    if let Some(b) = self.batching.as_mut() {
      b.step_emission();
      if self.inflight.is_none()
        && let Some(body) = b.pack(self.next_request)
      {
        self.inflight = Some(Request::new(
          self.id,
          RequestNumber::with(self.next_request),
          body,
        ));
        self.last_sent = None;
      }
    } else if self.inflight.is_none() && self.next_request <= self.total {
      let body = self.body_for(self.next_request);
      if body.len() > 8 {
        self.large_bodies_sent += 1;
      }
      // The single-unit wrap (batching-mode clusters only): the SAME plain body, riding the codec
      // layout so the BatchSm can parse it. Applied after the large-body accounting so that
      // witness keeps counting the inner payload.
      let body = if self.wrap_single_unit {
        let mut wrap = BatchBuilder::new(body.len() + BATCH_COUNT_OVERHEAD + BATCH_UNIT_OVERHEAD);
        wrap.push(&body).expect("the wrap budget is exact");
        wrap.finish().expect("one unit pushed")
      } else {
        body
      };
      self.inflight = Some(Request::new(
        self.id,
        RequestNumber::with(self.next_request),
        body,
      ));
      self.last_sent = None;
    }
    let due = match self.last_sent {
      None => true,
      Some(t) => now.saturating_duration_since(t) >= REQUEST_TIMEOUT,
    };
    if self.inflight.is_some() && due {
      self.last_sent = Some(now);
      self.inflight.clone()
    } else {
      None
    }
  }

  /// Handles a reply delivered at virtual instant `now`: if it matches the in-flight request, record
  /// its outcome and advance. A body is recorded as before (stamping the parallel ack-instant
  /// record at `now`), and a batching client first demultiplexes it per unit (count + per-unit reply
  /// assertions, and the oracle's bookkeeping) through the model.
  ///
  /// A REFUSAL is equally terminal: the op committed, its result is an error, and the client moves
  /// on to its next request. It is recorded as an error outcome — never appended to the reply
  /// history, where the reply and staleness oracles would read it as a payload the state machine
  /// produced — and the batching demux is skipped, there being no reply batch to split.
  pub fn handle(&mut self, now: Instant, msg: Message) {
    if let Message::Reply(r) = msg
      && let Some(req) = &self.inflight
      && req.request() == r.request()
    {
      let request = r.request().get();
      match r.into_outcome() {
        ReplyOutcome::Ok(body) => {
          let body = body.into_bytes();
          if let Some(b) = self.batching.as_mut() {
            b.on_ack(request, &body);
          }
          self.replies.push((request, body.clone()));
          self.replies_at.push((request, body, now));
        }
        ReplyOutcome::TooLarge(err) => self.refused.push((request, err)),
      }
      self.inflight = None;
      self.last_sent = None;
      self.next_request += 1;
    }
  }
}

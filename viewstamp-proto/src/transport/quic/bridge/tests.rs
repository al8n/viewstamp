use super::*;
use bytes::Bytes;

use crate::{
  Commit, OpNumber, ReplicaId, View, decode_message, encode_message,
  transport::{
    CloseCause,
    frame::LEN_PREFIX,
    quic::{
      crypto::{
        MAX_BIDI_STREAMS, MAX_STREAM_RECEIVE_WINDOW, MIN_FILLED_STREAM_FRAME_PAYLOAD,
        QUINN_REASSEMBLY_MAX_SPANS,
      },
      testutil::{PacketPipe, addr},
    },
  },
};
use core::time::Duration;
use quinn_proto::{Dir, StreamId};

/// `transmit_segments` reproduces quinn's GSO segment layout exactly: full `segment_size` chunks
/// with one possibly-shorter tail, a single chunk when `segment_size >= len`, no chunks for empty
/// contents, and no panic on a (never-emitted) zero segment size.
#[test]
fn transmit_segments_splits_per_quinn_gso_layout() {
  let contents: Vec<u8> = (0u8..=9).collect();
  // Even split: 10 bytes at segment 5 → two full datagrams.
  let segs: Vec<&[u8]> = transmit_segments(&contents, 5).collect();
  assert_eq!(segs, vec![&contents[..5], &contents[5..]]);
  // Short tail: 10 bytes at segment 4 → 4, 4, 2.
  let segs: Vec<&[u8]> = transmit_segments(&contents, 4).collect();
  assert_eq!(segs, vec![&contents[..4], &contents[4..8], &contents[8..]]);
  // Segment at/above the whole length → exactly one datagram.
  assert_eq!(
    transmit_segments(&contents, contents.len()).count(),
    1,
    "a segment size equal to the contents is one datagram"
  );
  assert_eq!(transmit_segments(&contents, 1024).count(), 1);
  // Empty contents → nothing to send.
  assert_eq!(transmit_segments(&[], 5).count(), 0);
  // A zero segment size cannot come out of quinn; the clamp keeps it panic-free regardless.
  assert_eq!(transmit_segments(&contents, 0).count(), contents.len());
}

impl Bridge {
  /// Whether any connection has finished the QUIC handshake (`Authenticating` or `Validated`).
  /// These bridge-only tests have no coordinator to run the identity step, so a handshake
  /// completing leaves the connection in `Authenticating`; the stream-mechanics helpers below
  /// drive raw streams on it directly.
  fn any_handshook(&mut self) -> bool {
    self
      .table
      .iter_mut()
      .any(|(_, e)| e.phase == Phase::Authenticating || e.phase == Phase::Validated)
  }

  /// The first handshook (`Authenticating`/`Validated`) connection's handle, if any.
  fn first_handshook(&mut self) -> Option<ConnectionHandle> {
    self
      .table
      .iter_mut()
      .find(|(_, e)| e.phase == Phase::Authenticating || e.phase == Phase::Validated)
      .map(|(h, _)| *h)
  }

  /// How many LIVE (non-`Closed`) connections are bound to `peer` — the per-peer connection bound's
  /// observable. The reconnect-churn regression asserts this stays at `PER_PEER_CONN_LIMIT` however
  /// many same-peer connections the peer establishes.
  fn live_conns_for_peer(&mut self, peer: Peer) -> usize {
    self
      .table
      .iter_mut()
      .filter(|(_, e)| e.peer == Some(peer) && !e.phase.is_closed())
      .count()
  }

  /// Force EVERY `Authenticating` connection's auth deadline to `now`, and return how many were set.
  /// The mass-auth-reap test uses this to make all N connections expire together deterministically —
  /// without it the connections' last-handshake-anchored idle timers (1 s) would always trip before
  /// the 5 s auth deadline. Re-stamping the deadline (the quantity under test) to `now` lets the next
  /// `handle_timeout(now)` reap them all while their idle timers are still in the future.
  fn force_auth_deadlines_now(&mut self, now: Instant) -> usize {
    let mut n = 0;
    for (_, e) in self.table.iter_mut() {
      if e.phase == Phase::Authenticating {
        e.auth_deadline = Some(now);
        n += 1;
      }
    }
    n
  }

  /// Open a bidi SEND stream on the first handshook connection and write `data`,
  /// recording the stream id on the Control class. Panics if no connection is
  /// handshook or the stream cannot be opened (test-only).
  fn test_open_write_first_stream(&mut self, data: &[u8]) -> StreamId {
    let h = self.first_handshook().expect("a handshook connection");
    let e = self.table.entry(h).expect("entry for validated handle");
    let sid = e
      .conn
      .streams()
      .open(Dir::Bi)
      .expect("a bidi stream slot is available");
    e.class_mut(StreamClass::Control).send = Some(sid);
    let n = e
      .conn
      .send_stream(sid)
      .write(data)
      .expect("write to fresh stream");
    assert_eq!(n, data.len(), "the whole payload fits in the send window");
    e.conn
      .send_stream(sid)
      .finish()
      .expect("finish the send half");
    sid
  }

  /// Like [`Self::test_open_write_first_stream`] but leaves the send half OPEN (no `finish`), the way a
  /// real long-lived Control stream stays open for the connection's life. Finishing instead would FIN
  /// the stream, and once the reader drains the data + FIN quinn drops the recv entry so the next
  /// `read` returns `ClosedStream` — which `ingest_recv` treats as a reset and resets the decoder,
  /// discarding any buffered partial (an artifact a never-FIN'd consensus stream does not have).
  fn test_open_write_first_stream_kept_open(&mut self, data: &[u8]) -> StreamId {
    let h = self.first_handshook().expect("a handshook connection");
    let e = self.table.entry(h).expect("entry for validated handle");
    let sid = e
      .conn
      .streams()
      .open(Dir::Bi)
      .expect("a bidi stream slot is available");
    e.class_mut(StreamClass::Control).send = Some(sid);
    let n = e
      .conn
      .send_stream(sid)
      .write(data)
      .expect("write to fresh stream");
    assert_eq!(n, data.len(), "the whole payload fits in the send window");
    sid
  }

  /// Attempt to open a UNIDIRECTIONAL stream on the first handshook connection, returning the
  /// result. With the transport advertising `max_concurrent_uni_streams = 0`, quinn refuses the
  /// local open against the peer's 0 limit, so this is `None` — the uni surface is closed by
  /// construction even on a fully validated connection (test-only).
  fn test_try_open_uni_first(&mut self) -> Option<StreamId> {
    let h = self.first_handshook().expect("a handshook connection");
    let e = self.table.entry(h).expect("entry for validated handle");
    e.conn.streams().open(Dir::Uni)
  }

  /// Attempt to send a QUIC DATAGRAM on the first handshook connection, returning the result. The
  /// transport sets `datagram_receive_buffer_size(None)`, so on a peer running this transport the
  /// send is rejected — `Disabled` (the sender's own receive is off, checked first) when both ends
  /// are this transport, or `UnsupportedByPeer` (no `max_datagram_size` advertised) if the sender's
  /// receive were enabled. The datagram surface is closed either way (test-only).
  fn test_try_send_datagram_first(&mut self) -> Result<(), quinn_proto::SendDatagramError> {
    let h = self.first_handshook().expect("a handshook connection");
    let e = self.table.entry(h).expect("entry for validated handle");
    e.conn
      .datagrams()
      .send(bytes::Bytes::from_static(b"probe"), /*drop=*/ true)
  }

  /// Open raw bidi SEND streams on connection `h` until `streams().open(Dir::Bi)` returns `None`
  /// (the peer's advertised concurrent-bidi-stream limit is exhausted), returning how many this call
  /// opened. Used to drive `flush_outbound`'s reopen into the no-progress path: with every bidi slot
  /// consumed, the post-reset `open` cannot mint a fresh Bulk send stream (test-only).
  fn test_exhaust_bidi_stream_slots(&mut self, h: ConnectionHandle) -> usize {
    let e = self.table.entry(h).expect("entry for the connection");
    let mut opened = 0;
    while e.conn.streams().open(Dir::Bi).is_some() {
      opened += 1;
    }
    opened
  }

  /// Open a raw extra bidi SEND stream on connection `h` and write `data` WITHOUT finishing it and
  /// WITHOUT recording the id on any class. The peer adopts it as a fresh peer-opened stream; opened
  /// after the class send streams it lands at a higher [`StreamId`] index, so the peer's
  /// `class_of_index` maps it to Bulk. Left open (not finished) so the peer's recv stream for it stays
  /// in the RECEIVING state. Returns the new stream id (test-only).
  fn test_open_extra_bidi_stream(&mut self, h: ConnectionHandle, data: &[u8]) -> StreamId {
    let e = self.table.entry(h).expect("entry for the connection");
    let sid = e
      .conn
      .streams()
      .open(Dir::Bi)
      .expect("a bidi stream slot is available");
    let n = e
      .conn
      .send_stream(sid)
      .write(data)
      .expect("write to the fresh extra stream");
    assert_eq!(n, data.len(), "the whole payload fits in the send window");
    sid
  }

  /// The count of complete-but-undrained frames currently queued on connection `h`'s `class`
  /// decoder (test observable for the bounded-read regression).
  fn test_ready_len(&mut self, h: ConnectionHandle, class: StreamClass) -> usize {
    self
      .table
      .entry(h)
      .map(|e| e.class_mut(class).decoder.ready_len())
      .unwrap_or(0)
  }

  /// The bytes of an incomplete frame currently retained on connection `h`'s `class` decoder (test
  /// observable for the Bulk reopen reset: a frame left mid-transfer on a reset recv stream must not
  /// survive the stream boundary into the reopened stream's decode).
  fn test_partial_len(&mut self, h: ConnectionHandle, class: StreamClass) -> usize {
    self
      .table
      .entry(h)
      .map(|e| e.class_mut(class).decoder.partial_len())
      .unwrap_or(0)
  }

  /// The peer-opened recv `StreamId` currently adopted for connection `h`'s `class`, if any (test
  /// observable for the Bulk reopen: the reopened stream lands at a HIGHER index than the original).
  fn test_recv_id(&mut self, h: ConnectionHandle, class: StreamClass) -> Option<StreamId> {
    self.table.entry(h).and_then(|e| e.class_mut(class).recv)
  }

  /// How many of `ids` still hold a LIVE, NOT-YET-STOPPED local recv entry in quinn on connection `h`
  /// — the observable for the opener's recv-half-leak regression. quinn does not expose its `recv` map
  /// size, so probe each id: `recv_stream(id).read(ordered)` returns `Ok` only while the `Recv` entry is
  /// present AND not stopped (quinn `Chunks::new` errors with `ClosedStream` for a vacant OR stopped
  /// recv), and `Chunks::Drop` reinserts the entry while reading nothing — so the probe is side-effect
  /// free here (these ids are LOCALLY-opened recv halves the bridge never reads in production, and the
  /// probe consumes no bytes, so `read = 0` issues no flow-control credit). With the
  /// [`retire_local_send`] fix a retired stream's recv half is `stop`ped → `ClosedStream` → not counted;
  /// the NEUTERED bridge (no recv-half `stop`) leaves it open + unstopped → `Ok` → counted, so the count
  /// GROWS one per churn cycle.
  fn test_live_unstopped_local_recv_count(
    &mut self,
    h: ConnectionHandle,
    ids: &[StreamId],
  ) -> usize {
    let Some(e) = self.table.entry(h) else {
      return 0;
    };
    ids
      .iter()
      .filter(|&&sid| e.conn.recv_stream(sid).read(/*ordered=*/ true).is_ok())
      .count()
  }

  /// The number of connections currently deferred on `deferred_ready` (test observable for the
  /// leftover-read reschedule: a read that stops on its budget with bytes still readable defers the
  /// connection HERE for the next pump, not onto `stream_ready`).
  fn test_deferred_ready_len(&self) -> usize {
    self.deferred_ready.len()
  }

  /// Stage raw already-framed bytes directly into connection `h`'s `class` outbound buffer, as a
  /// prior partial/blocked write would have left them. Used to enqueue a large burst of tiny frames
  /// without routing each through `write_framed` (test-only).
  fn test_stage_outbound(&mut self, h: ConnectionHandle, class: StreamClass, bytes: &[u8]) {
    let e = self.table.entry(h).expect("entry for staged outbound");
    e.class_mut(class).outbound.extend(bytes.iter().copied());
  }

  /// Accept the first peer-opened bidi stream on the first handshook
  /// connection and read all available bytes. Returns `None` if no stream is
  /// pending yet (test-only).
  fn test_read_first_stream(&mut self) -> Option<Vec<u8>> {
    let h = self.first_handshook()?;
    let e = self.table.entry(h)?;
    let sid = e.conn.streams().accept(Dir::Bi)?;
    e.class_mut(StreamClass::Control).recv = Some(sid);
    let mut out = Vec::new();
    let mut recv = e.conn.recv_stream(sid);
    let mut chunks = recv.read(/*ordered=*/ true).ok()?;
    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
      out.extend_from_slice(&chunk.bytes);
    }
    let _ = chunks.finalize();
    Some(out)
  }
}

/// Build two bridges and ferry datagrams between them until both report
/// `Connected`, then exchange a stream payload. Returns once the budget is
/// exhausted; the caller asserts on the resulting state.
///
/// `crippled` sets the negative-control flag on BOTH bridges (skips the
/// endpoint-event drain) so the same harness exercises the failure path.
fn drive_handshake(crippled: bool) -> (Bridge, Bridge, bool, Option<Vec<u8>>) {
  let opts = QuicOptions::accept_any_for_test();
  let mut a = Bridge::new(&opts, Some([0x11; 32]));
  let mut b = Bridge::new(&opts, Some([0x22; 32]));
  if crippled {
    a.skip_endpoint_drain = true;
    b.skip_endpoint_drain = true;
  }
  let a_addr = addr(1);
  let b_addr = addr(2);

  let base = Instant::now();
  a.connect(
    base,
    b_addr,
    "viewstamp.local",
    Peer::Replica(ReplicaId::new(1)),
  )
  .expect("dial on a fresh endpoint succeeds");

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut delivered: Option<Vec<u8>> = None;
  let mut wrote_ping = false;

  for k in 0..200u64 {
    let now = base + Duration::from_millis(k * 5);

    // Drain A's transmits → queued toward B; B's transmits → queued toward A.
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr, "A only talks to B in this test");
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr, "B only talks to A in this test");
      pipe_to_a.push(b_addr, bytes);
    }

    // Deliver every queued datagram to the OTHER bridge.
    while let Some((from, bytes)) = pipe_to_b.pop() {
      b.handle_datagram(now, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(now, from, None, &bytes);
    }

    a.handle_timeout(now);
    b.handle_timeout(now);

    // Drain the coordinator-facing connected queues (also exercises them).
    while a.connected.pop_front().is_some() {}
    while b.connected.pop_front().is_some() {}

    // Once both have finished the QUIC handshake, do the one-shot stream exchange.
    if !wrote_ping && a.any_handshook() && b.any_handshook() {
      a.test_open_write_first_stream(b"ping");
      wrote_ping = true;
      // Flush A's stream bytes out immediately so they reach B this loop.
      a.handle_timeout(now);
    }
    if wrote_ping
      && delivered.is_none()
      && let Some(got) = b.test_read_first_stream()
      && !got.is_empty()
    {
      delivered = Some(got);
    }
    if delivered.is_some() {
      break;
    }
  }

  let both_handshook = a.any_handshook() && b.any_handshook();
  (a, b, both_handshook, delivered)
}

#[test]
fn two_bridges_complete_handshake_and_exchange_bytes() {
  let (a, b, both_handshook, delivered) = drive_handshake(/*crippled=*/ false);
  assert!(
    both_handshook,
    "both bridges must finish the QUIC handshake"
  );
  assert_eq!(
    delivered.as_deref(),
    Some(b"ping".as_slice()),
    "B must read the bytes A wrote over the bidi stream"
  );
  assert!(
    a.endpoint_events_processed() > 0,
    "the dialer's service pump must feed endpoint events back through \
     Endpoint::handle_event during the handshake"
  );
  assert!(
    b.endpoint_events_processed() > 0,
    "the acceptor's service pump must do the same"
  );
}

/// A fully validated peer cannot pin connection-level credit/state on the protocol surfaces this
/// transport does not use: incoming UNIDIRECTIONAL streams and DATAGRAM receive are disabled at the
/// `TransportConfig` level (`build_transport`), so even after the QUIC handshake completes a peer
/// (a) cannot open a uni stream — `streams().open(Dir::Uni)` is refused by construction against the
/// peer's advertised 0 uni-stream limit — and (b) cannot send a DATAGRAM. The datagram send is
/// rejected with `Disabled` here (both bridges run this transport, so the SENDER's own
/// `datagram_receive_buffer_size(None)` short-circuits before the peer is consulted); a sender whose
/// own receive were enabled would instead see `UnsupportedByPeer` against our missing
/// `max_datagram_size` advertisement. Either variant proves the datagram surface is closed and
/// nothing is buffered. A bidi open still works (the in-use surface), proving the connection is
/// genuinely usable and only the unused surfaces are closed.
#[test]
fn validated_peer_cannot_open_uni_stream_or_send_datagram() {
  use quinn_proto::SendDatagramError;
  let (mut a, mut b, both_handshook, _) = drive_handshake(/*crippled=*/ false);
  assert!(
    both_handshook,
    "both bridges must finish the QUIC handshake"
  );

  for bridge in [&mut a, &mut b] {
    assert!(
      bridge.test_try_open_uni_first().is_none(),
      "a uni stream must be refused by construction (peer advertises a 0 uni-stream limit)"
    );
    assert!(
      matches!(
        bridge.test_try_send_datagram_first(),
        Err(SendDatagramError::Disabled | SendDatagramError::UnsupportedByPeer)
      ),
      "a DATAGRAM send must be rejected (datagram receive disabled on this transport)"
    );
  }
}

/// Negative control for the `poll_endpoint_events` drain (step 2 of the
/// service pump), mirroring memberlist's
/// `service_quinn_drains_poll_endpoint_events`.
///
/// The load-bearing observable is `endpoint_events_processed`: a real
/// handshake emits `NeedIdentifiers` (and friends) on BOTH connections, and a
/// correct pump must drain them from `Connection::poll_endpoint_events` and
/// feed each non-`Drained` event back through `Endpoint::handle_event` — which
/// is what mints the connection IDs and registers reset tokens that keep the
/// connection making progress under CID rotation / migration / longer
/// lifetimes. This test asserts the contrast across the SAME harness:
///
/// - healthy run: the counter advances past zero on both peers (the drain
///   runs on the live handshake path); and
/// - crippled run (`skip_endpoint_drain`): the counter is exactly zero on
///   both peers (the flag genuinely disables step 2).
///
/// NOTE on scope: a *minimal* two-party loopback handshake plus a single
/// stream exchange completes in quinn-proto 0.11.x even with the drain
/// skipped — the initial connection IDs suffice for that short exchange, so a
/// "handshake fails to complete" assertion would NOT hold here. The drain
/// becomes strictly required only once CID rotation / migration / exhaustion
/// forces a fresh CID. The counter contrast is therefore the faithful,
/// deterministic proof that the drain is wired and that the flag controls it —
/// exactly the property memberlist's mirror test asserts.
#[test]
fn service_drains_endpoint_events() {
  // Healthy: the drain runs, so endpoint events are fed back on both peers.
  let (a, b, healthy_handshook, _) = drive_handshake(/*crippled=*/ false);
  assert!(healthy_handshook, "the healthy handshake must complete");
  assert!(
    a.endpoint_events_processed() > 0 && b.endpoint_events_processed() > 0,
    "a correct service pump must drain Connection::poll_endpoint_events() and \
     feed each non-Drained event to Endpoint::handle_event; both peers emit \
     NeedIdentifiers during the handshake"
  );

  // Crippled: step 2 is skipped, so the counter never leaves zero — the flag
  // genuinely gates the (otherwise load-bearing) drain.
  let (ca, cb, _, _) = drive_handshake(/*crippled=*/ true);
  assert_eq!(
    ca.endpoint_events_processed(),
    0,
    "with the drain skipped, NO endpoint event is ever fed back on the dialer"
  );
  assert_eq!(
    cb.endpoint_events_processed(),
    0,
    "same on the acceptor — proving the skip is what suppresses the drain"
  );
}

/// Two connected bridges plus the bookkeeping a follow-on stream test needs: the bridges, their
/// addresses, each side's connection handle, and the `Instant` the handshake last serviced at (so
/// the caller threads the SAME monotonic clock forward — a clock jump past `max_idle_timeout`
/// (1 s) would silently close the connections).
struct Linked {
  a: Bridge,
  b: Bridge,
  a_addr: SocketAddr,
  b_addr: SocketAddr,
  ha: ConnectionHandle,
  hb: ConnectionHandle,
  now: Instant,
}

/// Drive two fresh bridges (A dials B) through the handshake by ferrying datagrams until both
/// finish the QUIC handshake. Unlike `drive_handshake` this exposes the handles (and the current
/// clock) so a test can drive the real `open_send_and_preface` / `bind_validated` / `write_framed`
/// / `ingest_recv` paths. `layout` selects `Single` or `ControlBulk` on both bridges.
fn connect_two_bridges(layout: StreamLayout) -> Linked {
  let opts = QuicOptions::accept_any_with_layout(layout);
  let mut a = Bridge::new(&opts, Some([0x33; 32]));
  let mut b = Bridge::new(&opts, Some([0x44; 32]));
  let a_addr = addr(11);
  let b_addr = addr(12);

  let base = Instant::now();
  a.connect(
    base,
    b_addr,
    "viewstamp.local",
    Peer::Replica(ReplicaId::new(1)),
  )
  .expect("dial on a fresh endpoint succeeds");

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut now = base;
  for k in 0..200u64 {
    now = base + Duration::from_millis(k * 5);
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr);
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    while let Some((from, bytes)) = pipe_to_b.pop() {
      b.handle_datagram(now, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(now, from, None, &bytes);
    }
    a.handle_timeout(now);
    b.handle_timeout(now);
    while a.connected.pop_front().is_some() {}
    while b.connected.pop_front().is_some() {}
    if a.any_handshook() && b.any_handshook() {
      break;
    }
  }
  assert!(
    a.any_handshook() && b.any_handshook(),
    "both bridges must finish the QUIC handshake"
  );
  let ha = a.first_handshook().expect("A has a handshook connection");
  let hb = b.first_handshook().expect("B has a handshook connection");
  Linked {
    a,
    b,
    a_addr,
    b_addr,
    ha,
    hb,
    now,
  }
}

/// Regression for the FIFO frame-ordering invariant in `write_framed` / `flush_outbound`.
///
/// The bug it guards: when bytes are already STAGED (a prior `Blocked` left an earlier frame in
/// `outbound`), a fresh `write_framed` must queue BEHIND them, never jump ahead. The old code
/// prepended the unwritten remainder in front of `outbound` and wrote a fresh frame directly
/// without first checking `outbound`, so a second frame could overtake a staged first one and the
/// on-wire order inverted. The fix appends to the back and front-drains, making `outbound` a
/// strict FIFO.
///
/// The test stages frame-1's bytes directly (standing in for a prior `Blocked`), then
/// `write_framed`s frame-2, flushes, ferries the datagrams to B, and asserts B decodes the two
/// frames IN ORDER [frame-1, frame-2]. Under the old prepend logic frame-2 would arrive first.
#[test]
fn staged_then_new_frame_preserves_on_wire_order() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));

  // Two distinguishable messages; frame-1 must arrive before frame-2.
  let frame1 = Message::Commit(Commit::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
  ));
  let frame2 = Message::Commit(Commit::new(
    View::with(1),
    OpNumber::with(2),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
  ));

  // Continue the SAME monotonic clock the handshake left off at (a jump past the 1 s idle timeout
  // would close the link before any frame moved).
  let now = start + Duration::from_millis(5);

  // Open A's SEND stream with an empty preface, then bind B as its peer + validate it (the
  // coordinator does the open-preface on `Connected` and the bind+validate after `authenticate`).
  // `write_framed` flushes only on `Validated`, so the binding must precede the staged writes.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);

  // Pre-stage frame-1 directly into A's outbound, as a prior `Blocked` write would have left it —
  // WITHOUT writing it to the stream. The send stream is already open, so the only thing keeping
  // ordering honest now is that `write_framed(frame-2)` appends behind this staged frame-1.
  {
    let e = a.table.entry(ha).expect("A's entry");
    let mut staged1 = Vec::new();
    encode_frame(&encode_message(&frame1), &mut staged1);
    e.class_mut(StreamClass::Control).outbound.extend(staged1);
  }

  // A fresh frame-2 must queue BEHIND the staged frame-1, then the front-drain writes both in
  // order. (Old bug: frame-2 would be written to the stream immediately, ahead of frame-1.)
  a.write_framed(now, ha, StreamClass::Control, &frame2);

  // B must be able to surface frames: bind its peer + validate so `ingest_recv` doesn't early-out.
  b.bind_validated(now, hb, peer_a);

  // Ferry A's STREAM datagrams to B until B has decoded both frames (bounded loop, clock threaded).
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut got: Vec<Message> = Vec::new();
  for k in 1..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr);
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    while let Some((from, bytes)) = pipe_to_b.pop() {
      b.handle_datagram(tick, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(tick, from, None, &bytes);
    }
    a.handle_timeout(tick);
    b.handle_timeout(tick);

    b.ingest_recv(tick, hb);
    while let Some(frame) = b.next_frame(hb, StreamClass::Control) {
      if let Ok(msg) = decode_message(Bytes::from(frame)) {
        got.push(msg);
      }
    }
    if got.len() >= 2 {
      break;
    }
  }

  assert_eq!(
    got,
    vec![frame1, frame2],
    "B must decode the staged frame BEFORE the later-written frame (strict-FIFO on-wire order)"
  );
}

/// A distinct `Commit` carrying `op` in its op-number, so tests can tell frames apart by class.
fn commit(op: u64) -> Message {
  Message::Commit(Commit::new(
    View::with(1),
    OpNumber::with(op),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
  ))
}

/// A keepalive frame that fits the PRE-AUTH Control cap (`MAX_HELLO_LEN`). The pre-auth Control reader
/// (`extend_first`) admits only a single hello-sized first frame; since the epoch-policy matrix pushed
/// every CONSENSUS carrier (even an empty `Commit`) past `MAX_HELLO_LEN`, a consensus keepalive sent
/// before validation would be rejected as an oversized first frame and reap the connection. An
/// empty-body `Request` (NEITHER in the matrix, so unchanged at 31 bytes) is the smallest message and
/// stays under the cap, so it keeps an `Authenticating` connection alive without tripping the
/// oversized-first-frame guard. `n` varies the client id so successive keepalives differ.
fn pre_auth_keepalive(n: u64) -> Message {
  use crate::{ClientId, RequestNumber, message::Request};
  Message::Request(Request::new(
    ClientId::new(n as u128),
    RequestNumber::with(0),
    bytes::Bytes::new(),
  ))
}

/// Ferry datagrams between two linked bridges for one tick at `tick`, draining both transmit
/// queues into the peer and firing both timers. The caller threads the monotonic clock forward.
fn ferry_once(
  a: &mut Bridge,
  b: &mut Bridge,
  a_addr: SocketAddr,
  b_addr: SocketAddr,
  pipe_to_a: &mut PacketPipe,
  pipe_to_b: &mut PacketPipe,
  tick: Instant,
) {
  while let Some((dst, bytes)) = a.poll_transmit() {
    assert_eq!(dst, b_addr);
    pipe_to_b.push(a_addr, bytes);
  }
  while let Some((dst, bytes)) = b.poll_transmit() {
    assert_eq!(dst, a_addr);
    pipe_to_a.push(b_addr, bytes);
  }
  while let Some((from, bytes)) = pipe_to_b.pop() {
    b.handle_datagram(tick, from, None, &bytes);
  }
  while let Some((from, bytes)) = pipe_to_a.pop() {
    a.handle_datagram(tick, from, None, &bytes);
  }
  a.handle_timeout(tick);
  b.handle_timeout(tick);
}

/// Per-class routing: under `ControlBulk`, a frame written on the Control class must arrive on the
/// peer's Control recv and a frame written on the Bulk class on the peer's Bulk recv — proving the
/// StreamId-INDEX class assignment (Control opened first = index 0, Bulk second = index 1) routes
/// each accepted peer stream to the correct class regardless of accept order.
#[test]
fn control_and_bulk_frames_route_to_their_class_recv() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // A opens BOTH classes (empty preface) and validates B; B validates A so its `ingest_recv` runs.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // Distinct frames per class. The Bulk message is forced large enough to be unmistakably a bulk
  // payload, but routing here is by the caller-passed class, not by size.
  let ctrl_msg = commit(0x11);
  let bulk_msg = commit(0x22);
  a.write_framed(now, ha, StreamClass::Control, &ctrl_msg);
  a.write_framed(now, ha, StreamClass::Bulk, &bulk_msg);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut got_ctrl: Option<Message> = None;
  let mut got_bulk: Option<Message> = None;
  for k in 1..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    b.ingest_recv(tick, hb);
    if got_ctrl.is_none()
      && let Some(f) = b.next_frame(hb, StreamClass::Control)
    {
      got_ctrl = decode_message(Bytes::from(f)).ok();
    }
    if got_bulk.is_none()
      && let Some(f) = b.next_frame(hb, StreamClass::Bulk)
    {
      got_bulk = decode_message(Bytes::from(f)).ok();
    }
    if got_ctrl.is_some() && got_bulk.is_some() {
      break;
    }
  }

  assert_eq!(
    got_ctrl.as_ref(),
    Some(&ctrl_msg),
    "the Control-class frame must decode from the peer's Control recv (StreamId index 0)"
  );
  assert_eq!(
    got_bulk.as_ref(),
    Some(&bulk_msg),
    "the Bulk-class frame must decode from the peer's Bulk recv (StreamId index 1)"
  );
  // Cross-check the classes did not bleed: no Bulk frame arrived on Control and vice versa.
  assert!(
    b.next_frame(hb, StreamClass::Control).is_none(),
    "no extra frame should remain on the Control recv"
  );
  assert!(
    b.next_frame(hb, StreamClass::Bulk).is_none(),
    "no extra frame should remain on the Bulk recv"
  );
}

/// A burst of many tiny frames packed into one receive window must NOT let `ingest_recv` queue an
/// unbounded number of complete frames before they are drained. The read is bounded to `STAGE_CHUNK`
/// bytes per pass, so the decoder's ready queue holds at most one budget's worth of frames at a time
/// (≤ `STAGE_CHUNK / 4` zero-body frames), and the connection defers onto `deferred_ready` (for the
/// NEXT pump) while bytes remain so the rest still drains across passes — with every frame delivered.
///
/// NEUTER CHECK: revert the per-pass read to `chunks.next(usize::MAX)` (no budget) and the
/// `ready_len` bound below fails — a single pass queues all `BURST` frames at once (queue depth
/// ≈ the total frame count), which is exactly the unbounded-allocation path this guards.
#[test]
fn a_tiny_frame_burst_in_one_window_is_drained_in_bounded_passes() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // Many zero-body frames (4 bytes each: just the length prefix) — the smallest possible frame, so
  // the queue-depth blowup an unbounded read would cause is maximal. BURST spans several STAGE_CHUNK
  // passes and fits inside the 1 MiB stream_receive_window, so B can buffer the whole burst
  // before it reads a byte (the realistic exhaustion setup).
  const BURST: usize = 8 * STAGE_CHUNK / LEN_PREFIX; // = 8 budgets' worth of minimal frames
  let mut blob = Vec::new();
  for _ in 0..BURST {
    encode_frame(&[], &mut blob);
  }
  assert!(
    blob.len() > 4 * STAGE_CHUNK,
    "the burst must exceed several read budgets"
  );
  a.test_stage_outbound(ha, StreamClass::Control, &blob);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Phase 1: push the whole burst to B WITHOUT B reading, so its recv buffer fills past one budget.
  // B's stream window (1 MiB) exceeds the burst, so A drains all of it even though B never reads.
  // Ferry until A has emptied its staged outbound, then a few extra ticks to land the last in-flight
  // datagrams in B's recv buffer (A pacing means the tail arrives a tick or two after the last write).
  let mut settle = 0u64;
  let mut last_tick = now;
  for k in 1..600u64 {
    let tick = now + Duration::from_millis(k);
    last_tick = tick;
    a.flush_stream(tick, ha); // keep draining A's staged outbound as the window allows
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    let a_done = {
      let e = a.table.entry(ha).expect("A entry");
      e.class_mut(StreamClass::Control).outbound.is_empty()
    };
    if a_done {
      settle += 1;
      if settle >= 32 {
        break;
      }
    }
  }

  // The measured pass: B reads ONCE. The read is budget-bounded, so the decoder's ready queue holds
  // at most STAGE_CHUNK/LEN_PREFIX frames — NOT the whole burst — and leftover data re-enqueues the
  // connection onto stream_ready (work-due-now for has_pending_work / poll_timeout).
  let read_tick = last_tick + Duration::from_millis(1);
  let framing_failed = b.ingest_recv(read_tick, hb);
  assert!(!framing_failed, "valid frames must not trigger a teardown");

  let depth = b.test_ready_len(hb, StreamClass::Control);
  assert!(
    depth <= STAGE_CHUNK / LEN_PREFIX,
    "one pass must queue at most a budget's worth of frames, got {depth} (bound {})",
    STAGE_CHUNK / LEN_PREFIX
  );
  assert!(
    depth < BURST / 4,
    "the queued depth ({depth}) must be far below the total burst ({BURST}) — \
     window-size-independent, not proportional to the frame count"
  );
  assert!(
    b.test_deferred_ready_len() >= 1,
    "leftover readable data must defer the connection (for the NEXT pump) so the driver re-pumps"
  );

  // Correctness: every frame is eventually delivered across bounded passes. Drain the queue this
  // pass produced, then keep reading+draining (each ingest_recv reads the next budget) until the
  // count reaches the whole burst. Each pass makes forward progress, so this terminates.
  let mut delivered = 0usize;
  let mut guard = 0u64;
  loop {
    while b.next_frame(hb, StreamClass::Control).is_some() {
      delivered += 1;
    }
    if delivered >= BURST {
      break;
    }
    let tick = read_tick + Duration::from_millis(guard + 1);
    let failed = b.ingest_recv(tick, hb);
    assert!(!failed, "valid frames must never tear the connection down");
    guard += 1;
    assert!(
      guard < BURST as u64,
      "draining must make forward progress every pass (no stall)"
    );
  }
  assert_eq!(
    delivered, BURST,
    "every frame in the burst is delivered across the bounded passes — no loss"
  );
}

/// Consuming inbound reads emits flow-control credit FROM `ingest_recv` itself — the same pump,
/// without any unrelated traffic servicing the connection. This is the decisive proof for the
/// dropped-`ShouldTransmit` fix.
///
/// quinn only queues `MAX_STREAM_DATA` once the application has consumed at least
/// `stream_receive_window / 8` (128 KiB of the 1 MiB window) past the last advertised limit, so a
/// single 64 KiB budget read does not cross it; the receiver must read several budgets first. The
/// test fills B's whole stream window with one large frame (between the 1 MiB window and the 16 MiB
/// frame cap), so the sender A blocks behind flow control, then reads budgets on B with NO inbound
/// datagram and NO `handle_timeout` between reads — the ONLY thing that can push a datagram onto B's
/// outbound is `ingest_recv` servicing the connection after a read that freed the window. It asserts
/// such a credit datagram IS emitted.
///
/// NEUTER CHECK: drop the `should_transmit`-driven `self.service(now)` after the reads (the old
/// `let _ = chunks.finalize()` with no post-read service) and B's outbound stays empty through every
/// read — no credit is emitted this pump, so a `poll_timeout`-driven sender, blocked behind the
/// window with nothing to send, would never be unblocked until an unrelated timer fired.
#[test]
fn a_budget_read_emits_flow_control_credit_this_pump() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // One frame larger than B's 1 MiB stream_receive_window but under the 16 MiB frame cap. A can only
  // push a window's worth onto the wire before B blocks it; the rest stays staged in A's outbound.
  const FRAME_BODY: usize = 12 * 1024 * 1024;
  let mut framed = Vec::new();
  encode_frame(&vec![0xC3u8; FRAME_BODY], &mut framed);
  let total_len = framed.len();
  a.test_stage_outbound(ha, StreamClass::Control, &framed);

  // Ferry until A has filled B's window and can push no more (A's outbound stops shrinking). The
  // ferry fires B's timers, so any ACKs it produces are flushed here, BEFORE the measured reads.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut last_a_left = usize::MAX;
  let mut stable = 0u64;
  let mut tick = now;
  for k in 1..4000u64 {
    tick = now + Duration::from_millis(k);
    a.flush_stream(tick, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    let a_left = {
      let e = a.table.entry(ha).expect("A entry");
      e.class_mut(StreamClass::Control).outbound.len()
    };
    // A is flow-control blocked once its staged tail stops draining (window full at the receiver).
    if a_left == last_a_left && a_left > 0 {
      stable += 1;
      if stable >= 16 {
        break;
      }
    } else {
      stable = 0;
      last_a_left = a_left;
    }
  }
  let a_blocked = {
    let e = a.table.entry(ha).expect("A entry");
    e.class_mut(StreamClass::Control).outbound.len()
  };
  assert!(
    a_blocked > 0,
    "A must be flow-control blocked with a staged tail (frame {total_len} B exceeds B's 1 MiB \
     stream window), so the transfer depends on B's credit"
  );

  // Drain any datagrams the ferry left in B's outbound, so the ONLY source of a fresh datagram below
  // is a `ingest_recv` that freed the window. Do NOT touch B's timers after this.
  while b.poll_transmit().is_some() {}

  // Read budgets on B with no inbound and no timer between calls. After enough budgets cross the
  // 1 MiB (window/8) threshold, an `ingest_recv` queues MAX_STREAM_DATA AND services the connection,
  // putting the credit datagram on B's outbound THIS pump. Assert that happens.
  let mut emitted_credit = false;
  let max_reads = (12 * 1024 * 1024 / STAGE_CHUNK) as u64 + 8;
  for r in 0..max_reads {
    let rtick = tick + Duration::from_millis(r + 1);
    let failed = b.ingest_recv(rtick, hb);
    assert!(
      !failed,
      "a large valid frame must not tear the connection down"
    );
    if b.poll_transmit().is_some() {
      // A datagram appeared with no inbound and no timer fired — it can only be the flow-control
      // credit this read produced via `ingest_recv`'s post-read service.
      emitted_credit = true;
      break;
    }
  }
  assert!(
    emitted_credit,
    "reading inbound budgets that freed the stream window must make `ingest_recv` emit the \
     flow-control credit datagram THIS pump (the dropped-ShouldTransmit fix), without any unrelated \
     traffic servicing the connection"
  );

  // End-to-end: with credit flowing, the WHOLE over-window frame is delivered. Resume the ferry (B now
  // emits credit each time it frees window, so A drains its staged tail) until B decodes the frame.
  let mut got: Option<Vec<u8>> = None;
  for k in 0..8000u64 {
    let t = tick + Duration::from_millis(k + 100);
    a.flush_stream(t, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      t,
    );
    b.ingest_recv(t, hb);
    if let Some(f) = b.next_frame(hb, StreamClass::Control) {
      got = Some(f);
      break;
    }
  }
  assert_eq!(
    got.map(|f| f.len()),
    Some(FRAME_BODY),
    "the full over-window frame must be delivered once flow-control credit flows after each budget \
     read"
  );
}

/// The unread backlog a full stream receive window admits must stay inside the span count quinn's
/// stream reassembler will hold — the derivation
/// [`MAX_STREAM_RECEIVE_WINDOW`](crate::transport::quic::crypto::MAX_STREAM_RECEIVE_WINDOW) states,
/// measured against real packetization rather than assumed.
///
/// quinn buffers each received STREAM frame as its own span and rejects an insert once the count
/// passes `QUINN_REASSEMBLY_MAX_SPANS` — closing the whole CONNECTION, not throttling the peer. The
/// compaction it tries first merges only poorly utilized spans, so full packets from a sender with a
/// backlog stay separate and a deep backlog cannot be compacted back under the ceiling. The window
/// is what bounds that backlog, so it has to be small enough that a window's worth of full packets
/// is fewer spans than the ceiling.
///
/// This test drives the worst case directly: a frame several windows long, ferried to B with B
/// reading NOTHING, so B's reassembler holds a whole window unread. Each datagram carries at most
/// one STREAM frame per stream, so the datagrams B absorbs unread bound the spans it holds. Then B
/// drains and the frame must arrive in FULL — a stream quinn had errored would deliver nothing.
///
/// It fails in both directions the end-to-end tests only fail indirectly: raising the window (or
/// shrinking the packets a window holds) drives the span count over the ceiling, and a quinn release
/// that lowers its own bound errors this stream while the count assertion still passes.
///
/// Scope: this is the FILLED-PACKET case the sizing covers — the shape a bulk transfer produces.
/// A sender whose segmentation is not packet-filling reaches the ceiling on far fewer bytes, and no
/// window prevents that;
/// `a_sub_packet_flood_makes_the_bridge_emit_the_lost_event_for_the_refused_stream` covers that
/// shape, and `quic::loopback::a_stalled_receiver_refused_by_the_reassembler_recovers_and_completes_its_operation`
/// the recovery it gets.
#[test]
fn a_full_stream_window_of_unread_packets_stays_within_the_reassembly_bound() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // Several windows' worth on the Bulk class, so A fills B's whole window and stays blocked behind
  // it with a staged tail — the deepest unread backlog flow control permits.
  const BODY: usize = 4 * MAX_STREAM_RECEIVE_WINDOW as usize;
  let mut framed = Vec::new();
  encode_frame(&vec![0x2Bu8; BODY], &mut framed);
  let total = framed.len();
  a.test_stage_outbound(ha, StreamClass::Bulk, &framed);

  // Ferry with NO `ingest_recv` on B, counting every datagram B absorbs, until A can push nothing
  // more onto the wire (B's window is full and A still holds a staged tail).
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut unread_datagrams = 0usize;
  let mut unread_bytes = 0usize;
  let mut idle = 0u64;
  let mut tick = now;
  for k in 1..4000u64 {
    tick = now + Duration::from_millis(k);
    a.flush_stream(tick, ha);
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr);
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    let before = unread_datagrams;
    while let Some((from, bytes)) = pipe_to_b.pop() {
      unread_datagrams += 1;
      unread_bytes += bytes.len();
      b.handle_datagram(tick, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(tick, from, None, &bytes);
    }
    a.handle_timeout(tick);
    b.handle_timeout(tick);
    // A is done filling once nothing more reaches B for a stretch of ticks while a staged tail
    // remains: only B's window can be holding it back, since B never reads.
    let a_left = {
      let e = a.table.entry(ha).expect("A entry");
      e.class_mut(StreamClass::Bulk).outbound.len()
    };
    if unread_datagrams == before && a_left > 0 {
      idle += 1;
      if idle >= 64 {
        break;
      }
    } else {
      idle = 0;
    }
  }
  let a_left = {
    let e = a.table.entry(ha).expect("A entry");
    e.class_mut(StreamClass::Bulk).outbound.len()
  };
  assert!(
    a_left > 0,
    "A must still hold a staged tail: the frame ({total} B) is several windows long, so B's window \
     is the only thing that can have stopped it"
  );
  // The pin: a full window of real packets is fewer spans than quinn's reassembler will hold. The
  // count includes B's control-stream and pure-ACK datagrams, so it over-counts the Bulk spans.
  assert!(
    unread_datagrams as u64 <= QUINN_REASSEMBLY_MAX_SPANS,
    "a window's worth of unread datagrams ({unread_datagrams}) must stay within the \
     {QUINN_REASSEMBLY_MAX_SPANS}-span reassembly ceiling — the window is sized as \
     {MAX_STREAM_RECEIVE_WINDOW} B / {MIN_FILLED_STREAM_FRAME_PAYLOAD} B per full packet"
  );

  // ...and the count is a full window's worth rather than an early-ended fill: a stream quinn has
  // already errored stops ACKing, which ends the fill too, so this is checked after the pin.
  assert!(
    unread_bytes >= MAX_STREAM_RECEIVE_WINDOW as usize,
    "a full window ({MAX_STREAM_RECEIVE_WINDOW} B) must have reached B unread before flow control \
     stopped A, got {unread_bytes} B"
  );

  // B now drains. The frame arrives in full only if quinn kept every span it buffered: a stream it
  // had errored delivers nothing, however much credit B goes on to grant.
  let mut got: Option<Vec<u8>> = None;
  for k in 0..8000u64 {
    let t = tick + Duration::from_millis(k + 1);
    a.flush_stream(t, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      t,
    );
    assert!(
      !b.ingest_recv(t, hb),
      "a legitimate over-window transfer must never reap the connection"
    );
    if let Some(f) = b.next_frame(hb, StreamClass::Bulk) {
      got = Some(f);
      break;
    }
  }
  assert_eq!(
    got.map(|f| f.len()),
    Some(BODY),
    "the whole {BODY}-byte frame must arrive after a full window sat unread in the reassembler"
  );
}

/// UNIT PIN, sender side: a sub-packet write flood makes the bridge emit the LOST event for the
/// stream quinn refused, classified and unbound.
///
/// Scope is deliberately this one step. The receive window bounds an unread backlog's BYTES, not the
/// number of spans quinn buffers them as, and quinn refuses a stream more spans than its reassembler
/// holds. A sender that hands quinn a few hundred bytes per pump gives it less than a packet's worth
/// each time, so every packet carries a sub-packet span well-utilized enough that compaction will not
/// merge it — no loss and no reordering needed, and roughly [`QUINN_REASSEMBLY_MAX_SPANS`] * 2 such
/// writes cross the ceiling on well under a megabyte, which is the point: the bytes never approach
/// the window, so no window setting prevents this.
///
/// What the bridge owes at that moment is asserted here and nothing more: the loss is queued for the
/// coordinator to reap, classified as the QUIC layer rejecting the connection, and the peer's routing
/// is unbound so nothing is written into a dead connection. Whether the cluster then RECOVERS — both
/// ends reaping, the link re-established, the in-flight operation completing — is a property of the
/// coordinator, the consensus layer and the driver's link reconcile, and is proved end to end over
/// real mTLS by `quic::loopback::a_stalled_receiver_refused_by_the_reassembler_recovers_and_completes_its_operation`.
/// Asserting it here would mean building that state by hand instead of reaching it.
///
/// The flood stages already-framed bytes and flushes them through the production `flush_outbound`
/// write path, which is where the coalescing that shapes the spans lives.
#[test]
fn a_sub_packet_flood_makes_the_bridge_emit_the_lost_event_for_the_refused_stream() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);
  assert_eq!(
    b.handle_for(peer_a),
    Some(hb),
    "B routes to A before the flood"
  );

  // One small frame per pump: too little for quinn to fill a packet with, so each pump puts one
  // sub-packet STREAM frame on the wire. B never reads, so they all stay buffered as separate spans.
  const TRICKLE_BODY: usize = 396;
  let mut framed = Vec::new();
  encode_frame(&vec![0x77u8; TRICKLE_BODY], &mut framed);
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut writes = 0u64;
  let mut lost = None;
  for k in 1..(QUINN_REASSEMBLY_MAX_SPANS * 6) {
    // Micro-second ticks keep the whole flood inside one PTO and far inside the idle timeout, so the
    // loss under test is the reassembler's refusal and not a timer.
    let tick = now + Duration::from_micros(k * 20);
    if a.table.entry(ha).is_none() {
      // A's own side of the connection drained away first: stop feeding it and let the assertions
      // below report what B did — or failed to do — with the loss.
      break;
    }
    a.test_stage_outbound(ha, StreamClass::Bulk, &framed);
    writes += 1;
    a.flush_stream(tick, ha);
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr);
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    while let Some((from, bytes)) = pipe_to_b.pop() {
      b.handle_datagram(tick, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(tick, from, None, &bytes);
    }
    a.handle_timeout(tick);
    b.handle_timeout(tick);
    if let Some(h) = b.take_lost() {
      lost = Some(h);
      break;
    }
  }

  // The promised classification and teardown, in the order the recovery depends on.
  assert_eq!(
    lost,
    Some(hb),
    "the reassembler's refusal must surface as a LOST connection queued for reaping, not a silent \
     stall — after {writes} sub-packet writes"
  );
  assert_eq!(
    b.conn_close_count(CloseCause::RecordRejected),
    1,
    "and be classified as the QUIC layer rejecting the connection, not an idle-out or a peer close"
  );
  assert_eq!(
    b.handle_for(peer_a),
    None,
    "routing to the peer must be unbound the instant the connection is lost, so nothing is sent \
     into a dead connection"
  );
  // Non-vacuity, and the finding this pins: it was the SPAN count that closed it, not the window.
  // The flood crossed the span ceiling while the bytes stayed far under a window's worth.
  assert!(
    writes > QUINN_REASSEMBLY_MAX_SPANS,
    "the flood must actually cross the span ceiling ({QUINN_REASSEMBLY_MAX_SPANS}), took {writes} \
     writes"
  );
  let flooded = writes * framed.len() as u64;
  assert!(
    flooded < MAX_STREAM_RECEIVE_WINDOW,
    "and it must do so on less than a window ({MAX_STREAM_RECEIVE_WINDOW} B) of stream bytes — \
     {flooded} B — since a window that admitted this would have to be smaller than any usable one"
  );
}

/// The `Single` layout still round-trips one frame on the Control class (the only class it opens).
#[test]
fn single_layout_round_trips_one_frame() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::Single);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  let msg = commit(0x33);
  a.write_framed(now, ha, StreamClass::Control, &msg);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut got: Option<Message> = None;
  for k in 1..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    b.ingest_recv(tick, hb);
    if let Some(f) = b.next_frame(hb, StreamClass::Control) {
      got = decode_message(Bytes::from(f)).ok();
      break;
    }
  }
  assert_eq!(
    got.as_ref(),
    Some(&msg),
    "the Single layout must round-trip its frame on the Control class"
  );
}

/// `Single` is a Control-only RECEIVE fence: a version-skew / buggy valid-cert peer that opens a
/// second (Bulk-index) bidi stream to a `Single` receiver must NOT have that stream adopted or its
/// frame delivered as consensus — the offending stream is refused (stopped) while the Control class
/// keeps delivering normally.
///
/// The peer `a` is run as a `ControlBulk` opener (so it legitimately opens Control at index 0 AND
/// Bulk at index 1 and writes a real frame on each), while the receiver `b`'s connection layout is
/// forced to `Single` — exactly the version-skew shape: a `ControlBulk` peer dialing a `Single`
/// node. The Control frame must arrive on `b`'s Control recv; the Bulk frame must NEVER appear on
/// `b`'s Bulk recv (the index-1 stream is refused at the accept loop, never read, never decoded).
///
/// NEUTER CHECK: drop the `e.layout.is_single() && class.is_bulk()` refuse-arm in `ingest_recv`'s
/// accept loop and `b` adopts + reads the Bulk stream, so the Bulk frame IS delivered — the
/// unconfigured-surface delivery this fence forbids.
#[test]
fn single_layout_refuses_a_peer_opened_bulk_stream() {
  // Both sides handshake as ControlBulk so `a` actually opens its Bulk (index-1) send stream.
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Force the RECEIVER onto the `Single` layout: it now expects a Control-only surface, while `a`
  // still opens + writes Bulk. This is the version-skew mismatch the fence must contain.
  b.table.entry(hb).expect("B's entry").layout = StreamLayout::Single;

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // A distinct frame on each class. Under the fence the Bulk frame must be refused at B.
  let ctrl_msg = commit(0x55);
  let bulk_msg = commit(0x66);
  a.write_framed(now, ha, StreamClass::Control, &ctrl_msg);
  a.write_framed(now, ha, StreamClass::Bulk, &bulk_msg);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut got_ctrl: Option<Message> = None;
  let mut bulk_delivered = false;
  for k in 1..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    b.ingest_recv(tick, hb);
    if got_ctrl.is_none()
      && let Some(f) = b.next_frame(hb, StreamClass::Control)
    {
      got_ctrl = decode_message(Bytes::from(f)).ok();
    }
    // The Bulk decoder must stay empty for the whole run: the refused stream is never read into it.
    if b.next_frame(hb, StreamClass::Bulk).is_some() {
      bulk_delivered = true;
      break;
    }
  }

  assert_eq!(
    got_ctrl.as_ref(),
    Some(&ctrl_msg),
    "the Single layout must still deliver its Control-class consensus frame"
  );
  assert!(
    !bulk_delivered,
    "a peer-opened Bulk (index ≥ 1) stream must NOT be delivered as consensus to a Single receiver"
  );
  // The refused Bulk stream is not adopted as a recv on B's Bulk slot.
  assert!(
    b.table
      .entry(hb)
      .expect("B's entry")
      .class_mut(StreamClass::Bulk)
      .recv
      .is_none(),
    "the refused Bulk stream must not be adopted as B's Bulk recv under Single"
  );
}

/// Per-STREAM reset backpressure: overflowing one class's outbound buffer RESETS just that class's
/// send stream (its id dropped, buffer cleared) while the OTHER class's send stream and the
/// connection itself stay alive (the bridge is not closed/lost). Drives the overflow by staging >
/// the cap directly into the Bulk buffer, then a `write_framed` on Bulk that crosses the cap.
#[test]
fn per_class_overflow_resets_only_that_stream() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);

  // Open both classes and validate so writes flush. Record the original per-class send ids.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  let (ctrl_send_before, bulk_send_before) = {
    let e = a.table.entry(ha).expect("A's entry");
    (
      e.class_mut(StreamClass::Control).send,
      e.class_mut(StreamClass::Bulk).send,
    )
  };
  assert!(
    ctrl_send_before.is_some() && bulk_send_before.is_some(),
    "ControlBulk opens both send streams on Connected"
  );

  // Stage just over the cap directly into the Bulk buffer (standing in for a peer that stopped
  // reading Bulk), WITHOUT touching Control.
  {
    let e = a.table.entry(ha).expect("A's entry");
    e.class_mut(StreamClass::Bulk)
      .outbound
      .resize(PER_CLASS_OUTBOUND_CAP + 1, 0u8);
  }

  // A write on Bulk now crosses the cap → the Bulk send stream is reset (id dropped, buffer
  // cleared, reopened by the flush onto a fresh id). Control is untouched.
  a.write_framed(now, ha, StreamClass::Bulk, &commit(0x44));

  let e = a.table.entry(ha).expect("A's entry still present");
  assert!(
    !e.phase.is_closed(),
    "a per-stream reset must NOT close the connection"
  );
  assert_eq!(
    e.class_mut(StreamClass::Control).send,
    ctrl_send_before,
    "the Control send stream is untouched by a Bulk overflow"
  );
  // The Bulk buffer was cleared by the reset; the single post-reset frame (the `commit` above)
  // either still sits staged or was already flushed — in both cases it is far under the cap.
  assert!(
    e.class_mut(StreamClass::Bulk).outbound.len() <= PER_CLASS_OUTBOUND_CAP,
    "the over-cap Bulk buffer was cleared by the reset"
  );
  // The connection is still in the table and routable (not on the lost queue's reap path).
  assert!(
    a.is_validated(ha),
    "the connection stays Validated after a single-stream reset"
  );
}

/// A Bulk-overflow reset whose FOLLOW-ON reopen makes NO write progress must STILL drain its
/// `RESET_STREAM` into `out` THIS pump — the gap a progress-gated service trigger leaves open.
///
/// `write_framed`'s Bulk-overflow path resets the Bulk send stream (queuing a `RESET_STREAM` in
/// quinn) and then flushes the re-staged frame onto a fresh stream. The reset frame reaches the wire
/// ONLY via a `poll_transmit`, which only `service` runs. A service trigger gated on the follow-on
/// `flush_outbound` reporting WRITE progress misses this case — the reopen can make none: here every
/// bidi stream slot is exhausted, so the post-reset `open` returns `None` and `flush_outbound`
/// reports `false`. Under such a gate the `RESET_STREAM` would sit stranded in quinn (in neither
/// `out` nor `has_pending_work`) until unrelated traffic woke a `poll_timeout`-driven driver.
/// `write_framed` therefore arms the trigger UNCONDITIONALLY after the flush: it sets the deferred
/// `needs_service` flag regardless of flush progress, and the pump-end `service` that consumes it
/// (stood in for here by `service_if_deferred`) collects the reset this same pump.
///
/// The construction is deterministic and uses NO peer/ferry: A opens its class streams, then opens
/// raw bidi streams until the concurrency limit is exhausted (so the post-reset reopen necessarily
/// fails), drains its outbound so the ONLY thing a later `poll_transmit` can carry is the reset, and
/// `write_framed`s a Bulk frame that crosses the per-class cap. The test asserts a datagram IS
/// emitted; with the Bulk stream's id dropped and reopen blocked, that datagram is the `RESET_STREAM`.
///
/// NEUTER CHECK: gate the deferral on flush progress (`if self.flush_outbound(now, h, class) {
/// self.needs_service = true; }` in `write_framed`'s tail) and `service_if_deferred` runs nothing —
/// this `poll_transmit` returns `None`, the reset stranded, exactly the wakeup gap this closes.
#[test]
fn a_bulk_overflow_reset_with_a_blocked_reopen_drains_its_reset_this_pump() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);

  // Open both class send streams (Control idx 0, Bulk idx 1) and validate so `write_framed` flushes.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);

  // Exhaust every remaining bidi stream slot so the post-reset reopen in `flush_outbound` cannot mint
  // a fresh Bulk send stream (`open` returns `None`) — forcing the no-write-progress path. A reset
  // stream does not free its slot until the peer ACKs the RESET_STREAM, so right after the reset the
  // reopen is still at the cap.
  let opened = a.test_exhaust_bidi_stream_slots(ha);
  assert!(
    opened > 0,
    "there must be spare bidi slots to exhaust beyond the two class streams"
  );
  {
    let e = a.table.entry(ha).expect("A's entry");
    assert!(
      e.conn.streams().open(Dir::Bi).is_none(),
      "the bidi stream concurrency limit must be exhausted so the post-reset reopen fails"
    );
  }

  // Stage just over the cap directly into the Bulk buffer (a peer that stopped reading Bulk), then
  // drain A's outbound so the ONLY datagram a later `poll_transmit` can carry is the reset itself.
  {
    let e = a.table.entry(ha).expect("A's entry");
    e.class_mut(StreamClass::Bulk)
      .outbound
      .resize(PER_CLASS_OUTBOUND_CAP + 1, 0u8);
  }
  while a.poll_transmit().is_some() {}

  // The over-cap Bulk write resets the Bulk stream (queuing a RESET_STREAM) and then fails to reopen
  // (slots exhausted) — the follow-on flush makes NO progress. `write_framed` must still arm the
  // deferred-service flag UNCONDITIONALLY, so the pump-end pass (`service_if_deferred` here) collects
  // the RESET_STREAM into `out` THIS pump.
  a.write_framed(now, ha, StreamClass::Bulk, &commit(0x44));
  a.service_if_deferred(now);

  assert!(
    a.poll_transmit().is_some(),
    "a Bulk-overflow reset whose reopen made no progress must still drain its RESET_STREAM into `out` \
     THIS pump (the unconditionally-armed deferred service) — with A's outbound drained first and no \
     peer traffic, the emitted datagram is that reset; a progress-gated trigger strands it"
  );
  // The connection survives the per-stream reset (a Bulk overflow never tears down the connection).
  assert!(
    a.is_validated(ha),
    "a Bulk-stream reset must not close the connection"
  );
}

/// A Bulk frame staged behind a stream-slot-EXHAUSTED reopen must flush once the peer frees a bidi
/// slot (`MAX_STREAMS` → `StreamEvent::Available { dir: Dir::Bi }`) — WITHOUT any new `write_framed`
/// to that peer. This is the liveness hole the dropped `Available` left: a Bulk send stream is RESET
/// (a `PER_CLASS_OUTBOUND_CAP` overflow or a peer STOP), its frame re-stages with NO send id, but
/// every bidi slot is consumed so `flush_outbound`'s reopen `open(Dir::Bi)` returns `None` and the
/// frame sits staged. The credit that unblocks it is the peer raising its concurrent-bidi-stream
/// limit, which quinn surfaces as `Available { dir: Dir::Bi }`. The fix enqueues the handle on
/// `stream_ready` (exactly like `Writable`), so the next pump's `flush_stream` reopens the Bulk
/// stream and drains the staged frame to the peer.
///
/// This is the CONSUMER half of the credit-return loop — that A REACTS to an arriving `MAX_STREAMS`.
/// The PRODUCER half — that B's accept-loop retirement actually EMITS that `MAX_STREAMS` through
/// production paths alone — is owned by
/// [`sustained_bulk_reopen_churn_replenishes_bidi_credit_via_peer_max_streams`]. So this test forces
/// the credit to arrive by RESETTING B's accepted send halves directly (targeted scaffolding, not a
/// production model): a bidi stream retires only once BOTH halves close, and adopting a replacement
/// frees only the recv half of the one stream it replaces — so the raw extra streams here, all mapped
/// to Bulk by index, are retired by the explicit per-tick B-side reset, which is what re-advertises
/// the larger `MAX_STREAMS`. The OTHER test proves the bridge does that retirement itself.
///
/// Construction (real two-bridge ferry, so the `MAX_STREAMS` credit is genuinely on the wire): A
/// opens its class streams and both sides validate. A then opens raw extra bidi streams until its
/// limit is exhausted (`open(Dir::Bi)` → `None`) — these arrive at B, whose `ingest_recv` accept
/// loop adopts each as a higher-index Bulk recv. A's outbound is drained and a fresh Bulk frame is
/// STAGED directly (not via `write_framed`) while the Bulk send stream is reset, so the frame is
/// staged with no send id and no slot to reopen on. Each ferry tick resets B's send half of every
/// extra stream (A already reset their A→B halves), fully retiring them on B so it re-advertises a
/// larger `MAX_STREAMS`; that delivers to A as `Available { dir: Dir::Bi }`; the pump drains A's
/// `stream_ready` (where the `Available` handle now sits) into `flush_stream`, the Bulk send reopens,
/// and the staged frame reaches B's Bulk recv. The test asserts B decodes that exact frame though A
/// issued NO `write_framed` after staging.
///
/// NEUTER CHECK: revert the `Available { dir: Dir::Bi }` arm in `on_app_event` to the dropped
/// `_ => {}`. The credit still arrives and raises A's stream limit, but nothing enqueues A onto
/// `stream_ready`, so the pump's `flush_stream` is never re-driven for it (the staged `outbound` is
/// excluded from `has_pending_work`): the Bulk send stream is never reopened, the frame stays staged,
/// and B never decodes it — `got` is `None` and the assertion fails. (Confirmed: the staged frame is
/// stranded exactly until an unrelated `write_framed` to this peer happens to run `flush_outbound`.)
#[test]
fn a_staged_bulk_frame_flushes_when_a_bidi_slot_frees_via_max_streams() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let mut now = start + Duration::from_millis(5);

  // A opens both class send streams (Control idx 0, Bulk idx 1); both sides validate so B's
  // `ingest_recv` runs and A's later staged Bulk frame would flush once a stream exists.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Exhaust every remaining bidi slot on A by opening raw extra streams, capturing their ids. Each
  // carries a byte so B definitely adopts a recv half for it (so the later reset frees a real recv,
  // not a never-instantiated one). After this, A's `open(Dir::Bi)` returns `None` — a Bulk reopen
  // cannot mint a fresh send stream, the precondition for the strand. A's bidi `next` is now at the
  // peer's advertised `max`, so only the peer RAISING that limit (a `MAX_STREAMS` frame, surfaced as
  // `Available { Bi }`) lets A open again; that credit is what the test drives below by resetting these
  // extra streams so B retires them.
  let mut extra_ids = Vec::new();
  loop {
    let opened = {
      let e = a.table.entry(ha).expect("A's entry");
      match e.conn.streams().open(Dir::Bi) {
        Some(sid) => {
          let _ = e.conn.send_stream(sid).write(&[0xCD]);
          Some(sid)
        }
        None => None,
      }
    };
    match opened {
      Some(sid) => extra_ids.push(sid),
      None => break,
    }
  }
  assert!(
    !extra_ids.is_empty(),
    "there must be spare bidi slots beyond the two class streams to exhaust"
  );
  {
    let e = a.table.entry(ha).expect("A's entry");
    assert!(
      e.conn.streams().open(Dir::Bi).is_none(),
      "A's bidi stream limit must be exhausted so the staged Bulk frame cannot reopen its stream"
    );
  }

  // RESET A's Bulk send stream (drop its id) and STAGE one fresh Bulk frame directly into the now
  // send-id-less Bulk buffer — i.e. a frame staged behind an exhausted reopen, NOT written via
  // `write_framed`. This is the frame whose delivery the whole test turns on.
  a.reset_send_class(ha, StreamClass::Bulk);
  let staged = commit(0x71);
  {
    let mut framed = Vec::new();
    encode_frame(&encode_message(&staged), &mut framed);
    a.test_stage_outbound(ha, StreamClass::Bulk, &framed);
  }

  // RESET the extra streams too. A reset retires the stream once the peer frees its recv half: B's
  // `ingest_recv` reads the reset, frees that recv (B holds NO send half for these — it never wrote
  // their B→A direction), so the bidi stream is fully retired on B, which then re-advertises a larger
  // `MAX_STREAMS`. That returning credit is the `Available { Bi }` event A must act on. (This models a
  // peer that frees stream concurrency after the local side's reset churn pushed `next` to the limit.)
  {
    let e = a.table.entry(ha).expect("A's entry");
    for sid in &extra_ids {
      let _ = e
        .conn
        .send_stream(*sid)
        .reset(VarInt::from_u32(STREAM_RESET_CODE));
    }
  }
  {
    let e = a.table.entry(ha).expect("A's entry");
    assert!(
      e.class_mut(StreamClass::Bulk).send.is_none(),
      "the staged Bulk frame must have NO send stream (reset), so only a freed slot can flush it"
    );
    assert!(
      !e.class_mut(StreamClass::Bulk).outbound.is_empty(),
      "the Bulk frame must be staged in `outbound`"
    );
  }

  // Sanity: with every bidi slot still exhausted, a flush attempt now CANNOT reopen the Bulk stream,
  // so the staged frame stays put. (This is the pre-credit state the `Available` signal must rescue.)
  a.flush_stream(now, ha);
  {
    let e = a.table.entry(ha).expect("A's entry");
    assert!(
      e.class_mut(StreamClass::Bulk).send.is_none()
        && !e.class_mut(StreamClass::Bulk).outbound.is_empty(),
      "before the credit arrives the staged Bulk frame cannot reopen a stream and stays staged"
    );
  }

  // Ferry the resets so B fully RETIRES the extra streams, which makes it re-advertise `MAX_STREAMS`
  // → A's `Available { dir: Dir::Bi }`. A bidi stream is only retired once BOTH halves close, so each
  // tick also resets B's SEND half (the B→A direction) of every extra stream B has accepted — A
  // already reset the A→B half above. With both halves reset the stream is fully retired on B, freeing
  // a remote-stream slot; B then grants the credit. Each tick mirrors the coordinator pump: ferry
  // datagrams, retire on B, drain A's `stream_ready` (where the fix enqueues the `Available` handle)
  // into `flush_stream`, then `ingest_recv` on B. NO `write_framed` is issued anywhere here, so the
  // ONLY thing that can flush the staged Bulk frame is the freed-slot reopen the `Available` signal
  // drives. Stop as soon as B decodes the staged frame.
  let mut got: Option<Message> = None;
  for k in 1..200u64 {
    now = start + Duration::from_millis(5 + k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    // Close B's send half of each extra stream so the bidi stream fully retires on B (A already reset
    // the other half). `reset` is a no-op once the stream is gone, so re-running it each tick is safe.
    if let Some(e) = b.table.entry(hb) {
      for sid in &extra_ids {
        let _ = e
          .conn
          .send_stream(*sid)
          .reset(VarInt::from_u32(STREAM_RESET_CODE));
      }
    }
    // Drain A's stream-ready signals (Readable / Writable / Opened / Available) into the send-side
    // retry, exactly as the coordinator's `drain_bridge` does — this is the production consumer of the
    // `Available`-queued handle.
    let ready = a.take_ready_unique();
    for h in ready {
      a.flush_stream(now, h);
    }
    let _ = b.ingest_recv(now, hb);
    if let Some(f) = b.next_frame(hb, StreamClass::Bulk) {
      got = decode_message(Bytes::from(f)).ok();
      break;
    }
  }

  assert_eq!(
    got,
    Some(staged),
    "the Bulk frame staged behind an exhausted reopen must flush once the peer frees a bidi slot \
     (MAX_STREAMS → Available {{ Bi }}) and reach B's Bulk recv — with NO new write_framed; dropping \
     the Available signal strands it (the neuter)"
  );
  {
    let e = a.table.entry(ha).expect("A's entry");
    assert!(
      e.class_mut(StreamClass::Bulk).outbound.is_empty(),
      "A's Bulk outbound must be fully drained once the staged frame flushed"
    );
  }
  // The reopened Bulk stream rides a live connection; the per-stream reset never tore it down.
  assert!(
    a.is_validated(ha),
    "the connection stays Validated throughout"
  );
}

/// PRODUCTION-PATH proof that retiring a peer-opened bidi stream replenishes the opener's bidi-stream
/// credit: a sustained Bulk reset→reopen churn — driven ONLY through `write_framed` + the production
/// `reset_send_class`, with NO manual `send_stream(...).reset()` on B's accepted streams — must let A
/// open FAR MORE than `MAX_BIDI_STREAMS` distinct Bulk streams (so credit is genuinely returning) and
/// a final staged Bulk frame must DELIVER.
///
/// Mechanism: each `reset_send_class(Bulk)` drops A's Bulk send id; the next `write_framed` reopens
/// Bulk at the next monotonic index — consuming one of A's bidi slots (B's `max_concurrent_bidi`
/// remote budget). A's initial budget is `MAX_BIDI_STREAMS` (8: 1 Control + 1 Bulk + 6 spare), so
/// without credit return A's reopens would dry up after a handful and the staged frame would strand.
/// With the fix, B's `ingest_recv` accept loop RETIRES the old Bulk stream when it adopts the reopened
/// higher-index one — closing BOTH halves (the `stop` on its recv half AND `finish` on its unused send
/// half) — so the accepted stream leaves quinn's remote-stream accounting and B re-advertises a larger
/// `MAX_STREAMS`. That credit arrives at A as `Available { Bi }`, A keeps reopening, and the churn runs
/// indefinitely.
///
/// The test ferries each cycle (so the reopened stream genuinely reaches B and B's MAX_STREAMS
/// genuinely returns over the wire), drains A's `stream_ready` into `flush_stream` exactly as the
/// coordinator pump does, and counts the DISTINCT Bulk send indices A opens. Driving 24 cycles (3×
/// the limit) and demanding > `MAX_BIDI_STREAMS` distinct indices proves the credit replenished; the
/// final frame's delivery proves the reopened stream still carries data end-to-end.
///
/// NEUTER CHECK: drop the `finish()` on the unused send half in `retire_peer_recv` (leave only the
/// recv `stop`). B then never fully retires the accepted Bulk streams, `allocated_remote_count` never
/// decrements, no `MAX_STREAMS` is re-advertised, and A's bidi credit is never replenished: after its
/// initial budget is spent A's `write_framed` cannot reopen Bulk, the distinct-index count plateaus at
/// `MAX_BIDI_STREAMS`, and the final staged frame never reaches B (`delivered` stays `None`). Both
/// assertions then fail — the strand the fix prevents.
#[test]
fn sustained_bulk_reopen_churn_replenishes_bidi_credit_via_peer_max_streams() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let mut now = start + Duration::from_millis(5);

  // A opens both class send streams (Control idx 0, Bulk idx 1); both sides validate so B's
  // `ingest_recv` accept loop runs and A's Bulk frames can flush.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Settle the handshake's first Bulk open at B before the churn (so the very first reopen below is a
  // genuine boundary at B, not a fresh adopt).
  for k in 1..6u64 {
    now = start + Duration::from_millis(5 + k * 5);
    a.write_framed(now, ha, StreamClass::Bulk, &commit(0x40));
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    let _ = b.ingest_recv(now, hb);
  }

  // Drive MANY MORE Bulk reset→reopen cycles than `MAX_BIDI_STREAMS` (8), all via production paths.
  // Record each DISTINCT Bulk send index A manages to open: a fresh higher index each cycle is only
  // possible while A still has bidi credit, which past the 8th open can ONLY come from B's returned
  // `MAX_STREAMS`. No `send_stream(...).reset()` is ever issued against B's accepted streams — B's own
  // accept-loop retirement (the fix) is the sole thing freeing those slots.
  let mut distinct_bulk_indices: Vec<u64> = Vec::new();
  let cycles = 24u64;
  for k in 0..cycles {
    // Production Bulk reset (the same routine `flush_outbound`/the `Stopped` arm call): drop A's Bulk
    // send id so the next write reopens a fresh stream at the next index.
    a.reset_send_class(ha, StreamClass::Bulk);
    // Production reopen + write: stages a Bulk frame and opens a fresh Bulk send stream if credit
    // allows. If A is out of bidi credit this opens nothing and the frame just stays staged.
    a.write_framed(now, ha, StreamClass::Bulk, &commit(0x50 + k));
    if let Some(e) = a.table.entry(ha)
      && let Some(sid) = e.class_mut(StreamClass::Bulk).send
    {
      let idx = sid.index();
      if !distinct_bulk_indices.contains(&idx) {
        distinct_bulk_indices.push(idx);
      }
    }
    // Ferry both ways so the reopened stream reaches B (its accept loop retires the prior one and
    // re-grants MAX_STREAMS) and B's returned credit reaches A as `Available { Bi }`.
    now = start + Duration::from_millis(35 + k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    // Drain A's stream-ready signals (the `Available { Bi }` handle the credit-return enqueues) into
    // the send-side retry, exactly as the coordinator's `drain_bridge` does.
    let ready = a.take_ready_unique();
    for h in ready {
      a.flush_stream(now, h);
    }
    let _ = b.ingest_recv(now, hb);
  }

  assert!(
    distinct_bulk_indices.len() as u64 > u64::from(MAX_BIDI_STREAMS),
    "A must open MORE than MAX_BIDI_STREAMS ({}) distinct Bulk streams across the churn — only \
     possible if B keeps returning bidi credit via MAX_STREAMS as it retires the old streams; got {}",
    MAX_BIDI_STREAMS,
    distinct_bulk_indices.len(),
  );

  // Credit demonstrably keeps flowing: stage ONE final Bulk frame on a freshly reset (send-id-less)
  // Bulk class and prove it reopens + DELIVERS to B through the same production drain. This is the
  // staged-frame-strands case the leak caused; with credit replenished it flushes.
  a.reset_send_class(ha, StreamClass::Bulk);
  let final_frame = commit(0x7E);
  a.write_framed(now, ha, StreamClass::Bulk, &final_frame);
  let mut delivered: Option<Message> = None;
  for k in 0..60u64 {
    now = start + Duration::from_millis(35 + (cycles + k) * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    let ready = a.take_ready_unique();
    for h in ready {
      a.flush_stream(now, h);
    }
    let _ = b.ingest_recv(now, hb);
    if let Some(f) = b.next_frame(hb, StreamClass::Bulk)
      && decode_message(Bytes::from(f)).ok() == Some(final_frame.clone())
    {
      delivered = Some(final_frame.clone());
      break;
    }
  }
  assert_eq!(
    delivered,
    Some(final_frame),
    "the final Bulk frame must reopen and DELIVER — proving the peer's retirement of the churned \
     streams replenished A's bidi-stream credit; dropping the unused-send-half `finish` strands it"
  );
  assert!(
    a.is_validated(ha),
    "the connection stays Validated throughout the churn"
  );
}

/// Sustained Bulk reset/reopen churn must reclaim the OPENER's LOCAL stream state — not merely the
/// peer's bidi credit. This transport opens BIDI streams but uses each ONE-WAY: A (the opener) writes
/// only the send half of each Bulk stream; A's UNUSED recv half of that same locally-opened stream is
/// never read by the bridge. Because B (the acceptor) `finish`es its own unused send half when it
/// retires the stream, a FIN arrives on A's unused recv half — but `ingest_recv` only reads PEER-opened
/// recv ids, so absent an explicit `stop` that FIN is never consumed and A's local `Recv` entry lingers
/// FOREVER. Across many reset/reopen cycles that is ONE leaked `Recv` per retired stream: unbounded
/// local stream-state growth (distinct from the bidi-credit return the prior test covers — the credit
/// DOES come back via A's `RESET_STREAM`, so the leak is invisible to that observable).
///
/// The fix routes every local-send-abandon through [`retire_local_send`], which `stop`s the unused recv
/// half so quinn frees its `Recv` entry on B's FIN. The test churns far more than `MAX_BIDI_STREAMS`
/// Bulk reset→reopen cycles through PRODUCTION paths (`reset_send_class` + `write_framed`), records every
/// distinct local Bulk send id A mints, ferries BOTH ways each cycle (so B retires + `finish`es and the
/// FIN reaches A), and then probes how many of those retired ids still hold a LIVE, UNSTOPPED local recv
/// entry on A. With the fix that count is 0 — every retired stream's recv half was stopped and freed.
///
/// NEUTER CHECK: delete the `recv_stream(sid).stop(..)` line in [`retire_local_send`] and each retired
/// stream's recv half stays open + unstopped, so the probe counts them and the count GROWS one per
/// cycle (≈ `cycles` live entries) — the `assert_eq!(leaked, 0)` then fails, surfacing the leak.
#[test]
fn sustained_bulk_churn_reclaims_the_openers_local_recv_state() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let mut now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Settle the handshake's first Bulk stream at B before the churn so the first reopen is a genuine
  // boundary at B (its accept loop retires + `finish`es the prior stream), not a fresh adopt.
  for k in 1..6u64 {
    now = start + Duration::from_millis(5 + k * 5);
    a.write_framed(now, ha, StreamClass::Bulk, &commit(0x40));
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    let _ = b.ingest_recv(now, hb);
  }

  // Record every DISTINCT Bulk send id A mints across the churn — these are A's locally-opened streams
  // whose UNUSED recv halves are the leak surface. Drive MANY more cycles than MAX_BIDI_STREAMS (8) via
  // production paths; ferry both ways each cycle so B retires + `finish`es each prior stream and that
  // FIN reaches A (the only thing that lets A's stopped recv half actually free).
  let mut churned_send_ids: Vec<StreamId> = Vec::new();
  let cycles = 24u64;
  for k in 0..cycles {
    a.reset_send_class(ha, StreamClass::Bulk);
    a.write_framed(now, ha, StreamClass::Bulk, &commit(0x50 + k));
    if let Some(e) = a.table.entry(ha)
      && let Some(sid) = e.class_mut(StreamClass::Bulk).send
      && !churned_send_ids.contains(&sid)
    {
      churned_send_ids.push(sid);
    }
    now = start + Duration::from_millis(35 + k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    let ready = a.take_ready_unique();
    for h in ready {
      a.flush_stream(now, h);
    }
    let _ = b.ingest_recv(now, hb);
  }

  // A must have churned through many distinct Bulk streams (only possible if B keeps returning bidi
  // credit as it retires the old ones — the credit half of the retirement), so the leak surface is real
  // and large.
  assert!(
    churned_send_ids.len() as u64 > u64::from(MAX_BIDI_STREAMS),
    "A must mint MORE than MAX_BIDI_STREAMS ({}) distinct Bulk streams across the churn; got {}",
    MAX_BIDI_STREAMS,
    churned_send_ids.len(),
  );

  // A few extra ferries so the LAST cycles' FINs from B are delivered to A and free A's stopped recv
  // halves (the stop is issued at retire time; the free lands when B's FIN arrives).
  for k in 0..12u64 {
    now = start + Duration::from_millis(35 + (cycles + k) * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    let _ = b.ingest_recv(now, hb);
  }

  // The current (live) Bulk send id is legitimately still open — exclude it; the leak is about the
  // RETIRED streams, all of which must have had their unused recv half stopped + freed.
  let current_bulk = a
    .table
    .entry(ha)
    .and_then(|e| e.class_mut(StreamClass::Bulk).send);
  let retired: Vec<StreamId> = churned_send_ids
    .iter()
    .copied()
    .filter(|sid| Some(*sid) != current_bulk)
    .collect();
  assert!(
    retired.len() as u64 >= u64::from(MAX_BIDI_STREAMS),
    "the churn must have retired many Bulk streams (got {})",
    retired.len()
  );

  let leaked = a.test_live_unstopped_local_recv_count(ha, &retired);
  assert_eq!(
    leaked, 0,
    "every RETIRED local Bulk stream's UNUSED recv half must be stopped + freed on A — a live, \
     unstopped local Recv entry per retired stream is the opener-side leak `retire_local_send` closes \
     (neuter: drop its `recv_stream(sid).stop(..)` and this count grows ~one per churn cycle)"
  );
  assert!(
    a.is_validated(ha),
    "the connection stays Validated throughout the churn"
  );
}

/// A Bulk SEND stream that resets and reopens at a HIGHER StreamId index must NOT carry a stale
/// partial frame across the boundary on the RECV side. The peer's `ingest_recv` accept loop adopts
/// the reopened (higher-index) Bulk recv id, REPLACING the old one; if it does not also RESET that
/// class's decoder, a frame left mid-transfer on the old (now-reset) stream stays in the decoder and
/// is prepended to the reopened stream's first bytes — misframing it (here: the leftover declares a
/// large length, so the reopened frame is swallowed into the never-completing partial and never
/// decodes; a different leftover could instead trip a spurious `FrameTooLong` teardown). The read-side
/// `Reset` arm (which DOES reset the decoder) never runs for this, because the accept loop already
/// replaced the recv id before the per-class read loop is reached.
///
/// Setup: A stages a Bulk frame whose 4-byte prefix declares a large body but sends only a few body
/// bytes (an incomplete frame), and ferries until B's Bulk decoder holds that partial. Then A resets
/// its Bulk send stream and writes a fresh COMPLETE Bulk frame, which quinn reopens at a higher index.
/// B then ingests: the accept loop adopts the new id; with the fix it stops the old stream and resets
/// the decoder, so the partial is gone and the fresh frame decodes cleanly.
///
/// NEUTER CHECK: drop the `st.decoder = FrameDecoder::new(MAX_FRAME_LEN)` (and the old-stream `stop`)
/// from the accept-loop boundary in `ingest_recv` and the stale partial survives — the reopened
/// frame is absorbed into the leftover's still-unmet declared length and `next_frame(Bulk)` never
/// yields it, so the `got_bulk` assertion fails.
#[test]
fn bulk_reset_reopen_resets_recv_decoder_and_frees_the_old_stream() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Stage an INCOMPLETE Bulk frame directly into A's Bulk outbound: a 4-byte prefix declaring 4096
  // body bytes, but only 8 body bytes follow. B will read these and buffer a partial that needs 4088
  // more bytes — which never arrive on this stream (A resets it below).
  let mut partial = Vec::new();
  partial.extend_from_slice(&4096u32.to_be_bytes());
  partial.extend_from_slice(&[0xABu8; 8]);
  a.test_stage_outbound(ha, StreamClass::Bulk, &partial);

  // Ferry until B's Bulk decoder holds the partial (8 body bytes buffered, no complete frame).
  let mut saw_partial = false;
  for k in 1..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    a.flush_stream(tick, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    b.ingest_recv(tick, hb);
    if b.test_partial_len(hb, StreamClass::Bulk) > 0 {
      saw_partial = true;
      break;
    }
  }
  assert!(
    saw_partial,
    "B's Bulk decoder must buffer the incomplete frame's partial before the reset"
  );
  assert!(
    b.next_frame(hb, StreamClass::Bulk).is_none(),
    "the incomplete frame must NOT have produced a complete frame"
  );
  let old_recv = b
    .test_recv_id(hb, StreamClass::Bulk)
    .expect("B adopted a Bulk recv id");

  // A resets its Bulk send stream (drops the old send id) and writes a fresh COMPLETE Bulk frame; the
  // reset+reopen mints a NEW Bulk send id at a higher index, so B will accept a new Bulk recv id.
  a.reset_send_class(ha, StreamClass::Bulk);
  let reopened = commit(0x5A);
  a.write_framed(now, ha, StreamClass::Bulk, &reopened);

  // Ferry until B decodes a Bulk frame on the reopened stream (or the budget runs out).
  let mut got_bulk: Option<Message> = None;
  let mut new_recv: Option<StreamId> = None;
  for k in 200..500u64 {
    let tick = now + Duration::from_millis(k * 5);
    a.flush_stream(tick, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    let framing_failed = b.ingest_recv(tick, hb);
    assert!(
      !framing_failed,
      "a clean reopened-stream frame must NOT trip a framing-error teardown (no stale partial \
       prepended)"
    );
    new_recv = b.test_recv_id(hb, StreamClass::Bulk);
    if let Some(f) = b.next_frame(hb, StreamClass::Bulk) {
      got_bulk = decode_message(Bytes::from(f)).ok();
      break;
    }
  }

  assert!(
    new_recv.is_some_and(|n| n.index() > old_recv.index()),
    "the reopened Bulk recv stream must land at a HIGHER StreamId index than the reset one \
     (old {:?}, new {:?})",
    old_recv,
    new_recv,
  );
  assert_eq!(
    got_bulk.as_ref(),
    Some(&reopened),
    "the reopened Bulk stream's frame must decode cleanly — the stale partial from the reset stream \
     must NOT survive the recv-id boundary (it is dropped + the decoder reset)"
  );
  // The boundary also cleared the leftover partial: after decoding the reopened frame, no partial
  // from the dead stream lingers.
  assert_eq!(
    b.test_partial_len(hb, StreamClass::Bulk),
    0,
    "no stale partial may remain on the reopened Bulk decoder"
  );
}

/// A `StreamEvent::Stopped` must act on its EXACT StreamId, never reset "the current Bulk stream" by
/// class index. quinn's `Stopped { id }` is per-exact-id (`received_stop_sending` keys on `id`), and
/// under normal UDP reordering a STALE stop can arrive for an ALREADY-RETIRED Bulk id AFTER the class
/// has reopened: the peer's acceptor can receive our reopened Bulk STREAM before our old `RESET_STREAM`,
/// retire the old recv, and emit `STOP_SENDING` for the OLD id — which reaches us when `classes[Bulk].send`
/// is the NEW stream (here carrying a staged frame). The OLD code classified the id by `class_of_index`
/// and reset the WHOLE current Bulk class, dropping LIVE Bulk traffic for a stop that targeted a dead
/// stream. The fix compares `id` against the class's current send id and ignores a non-matching (stale)
/// stop, while still resetting a genuine stop for the CURRENT id.
///
/// This drives `on_app_event` directly with synthesized `Stopped` events (the decisive, deterministic
/// probe — a sim reorder is non-deterministic): first a STALE stop for the OLD id (must be ignored — the
/// new send id and its staged frame survive), then a genuine stop for the CURRENT id (must reset the
/// class).
///
/// NEUTER CHECK: revert the arm to the index-only `match class_of_index(id) { Bulk => reset_send_class }`
/// and the STALE stop resets the live class — the new send id is dropped and the staged frame cleared,
/// so the "current id unchanged" / "staged frame survives" assertions fail.
#[test]
fn a_stale_stop_for_a_retired_bulk_id_does_not_reset_the_live_stream() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);

  // Open both class send streams and validate so `write_framed` stages onto Bulk. Record the OLD Bulk
  // send id (index 1).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  let old_bulk = a
    .table
    .entry(ha)
    .and_then(|e| e.class_mut(StreamClass::Bulk).send)
    .expect("ControlBulk opened a Bulk send stream");

  // Reset + reopen Bulk so the CURRENT Bulk send id is a NEW (higher-index) stream, and stage a frame on
  // it (a `write_framed` while the reopen is blocked leaves the frame staged; here the reopen succeeds, so
  // some/all may flush — either way the send id is the NEW one). Record the new id and the staged length.
  a.reset_send_class(ha, StreamClass::Bulk);
  let live_frame = commit(0x6C);
  a.write_framed(now, ha, StreamClass::Bulk, &live_frame);
  let new_bulk = a
    .table
    .entry(ha)
    .and_then(|e| e.class_mut(StreamClass::Bulk).send)
    .expect("the Bulk class reopened a fresh send stream");
  assert!(
    new_bulk.index() > old_bulk.index(),
    "the reopened Bulk send stream must land at a HIGHER index (old {old_bulk:?}, new {new_bulk:?})"
  );
  // Stage an extra raw frame directly so there is DEFINITELY live staged Bulk data to protect (whatever
  // the `write_framed` flushed, this guarantees a non-empty outbound to observe).
  let mut staged = Vec::new();
  encode_frame(&[0x9Au8; 24], &mut staged);
  a.test_stage_outbound(ha, StreamClass::Bulk, &staged);
  let staged_before = a
    .table
    .entry(ha)
    .map(|e| e.class_mut(StreamClass::Bulk).outbound.len())
    .unwrap_or(0);
  assert!(
    staged_before > 0,
    "there must be live staged Bulk data to protect"
  );

  // STALE stop: the peer STOP_SENDINGs the OLD (already-retired) Bulk id. It must be IGNORED — the live
  // Bulk send id and its staged frame survive, and the connection stays Validated.
  a.on_app_event(
    now,
    ha,
    Event::Stream(StreamEvent::Stopped {
      id: old_bulk,
      error_code: VarInt::from_u32(STREAM_RESET_CODE),
    }),
  );
  assert_eq!(
    a.table
      .entry(ha)
      .and_then(|e| e.class_mut(StreamClass::Bulk).send),
    Some(new_bulk),
    "a STALE stop for the retired OLD Bulk id must NOT reset the live class — the NEW send id survives"
  );
  assert_eq!(
    a.table
      .entry(ha)
      .map(|e| e.class_mut(StreamClass::Bulk).outbound.len())
      .unwrap_or(0),
    staged_before,
    "the live staged Bulk frame must NOT be dropped by a stale stop for a retired id"
  );
  assert!(
    a.is_validated(ha),
    "a stale Bulk stop must not tear down the connection"
  );

  // GENUINE stop: the peer STOP_SENDINGs the CURRENT Bulk id. This DOES reset the class — the send id is
  // dropped (reopen-on-next-write) and its buffer cleared; Control and the connection survive.
  a.on_app_event(
    now,
    ha,
    Event::Stream(StreamEvent::Stopped {
      id: new_bulk,
      error_code: VarInt::from_u32(STREAM_RESET_CODE),
    }),
  );
  assert_eq!(
    a.table
      .entry(ha)
      .and_then(|e| e.class_mut(StreamClass::Bulk).send),
    None,
    "a genuine stop for the CURRENT Bulk id must reset the class (send id dropped to reopen on next write)"
  );
  assert_eq!(
    a.table
      .entry(ha)
      .map(|e| e.class_mut(StreamClass::Bulk).outbound.len())
      .unwrap_or(usize::MAX),
    0,
    "the reset clears the Bulk buffer"
  );
  assert!(
    a.is_validated(ha),
    "a Bulk reset (even for the current id) keeps the connection Validated"
  );
}

/// Stopping a REPLACED Bulk recv stream must drain its queued STOP_SENDING (+ recovered credit) into
/// `out` THIS pump — not strand it in quinn until unrelated activity. When the peer resets+reopens its
/// Bulk send stream at a higher index, the accept loop in [`Self::ingest_recv`] adopts the new recv id
/// and `stop`s the old one; `stop` queues a `STOP_SENDING` (the old stream is still receiving) plus the
/// connection-level flow-control credit for its unread data. Those frames reach the wire only via a
/// `poll_transmit`, which only `service` runs — so the `stop` must set the same `should_service` flag a
/// window-freeing read does, and `ingest_recv` must `service(now)` after the borrow is released.
///
/// The construction is deterministic and small (so flow control / congestion never interfere): A opens
/// its Control + Bulk class streams normally and sends ONE small valid frame on the Bulk stream that B
/// adopts as its Bulk recv; A leaves that stream OPEN (never finished, never reset). A then opens a
/// SECOND raw bidi stream (a higher [`StreamId`] index → Bulk on B) carrying another small valid frame.
/// B's accept loop adopts the second Bulk stream while the FIRST is still in the RECEIVING state, so
/// `stop`ping the first queues a `STOP_SENDING` (its `is_receiving()` holds). B's outbound is drained to
/// empty IMMEDIATELY before the measured `ingest_recv`, which runs with no new inbound and no timer — so
/// the accept-loop `stop` is the ONLY thing that can put a datagram on B's outbound. The test asserts one
/// IS emitted. (Never resetting the first stream is what makes the STOP_SENDING deterministic — a reset
/// would make it non-receiving before the stop.)
///
/// NEUTER CHECK: drop the `should_service = true` on the accept-loop `stop` and the measured `ingest_recv`
/// emits NOTHING — no read here frees a window, so absent the stop-service B's outbound stays empty and
/// the STOP_SENDING sits in quinn until unrelated traffic; `emitted_at_stop` fails.
#[test]
fn stopping_a_replaced_recv_stream_drains_its_frames_this_pump() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // A sends ONE small valid frame on its Bulk CLASS stream. B adopts that stream as its Bulk recv. A
  // leaves it OPEN (the bridge never finishes a class send stream), so it stays in the RECEIVING state —
  // which is what makes the later `stop` of it queue a STOP_SENDING. Small so nothing flow-control or
  // congestion blocks; ferry until B has adopted the first Bulk recv id.
  a.write_framed(now, ha, StreamClass::Bulk, &commit(0x11));

  let mut first_recv = None;
  for k in 1..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    a.flush_stream(tick, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    b.ingest_recv(tick, hb);
    first_recv = b.test_recv_id(hb, StreamClass::Bulk);
    if first_recv.is_some() {
      break;
    }
  }
  let first_recv = first_recv.expect("B adopted the first Bulk recv id");

  // A opens a SECOND raw bidi stream (a HIGHER StreamId index → Bulk on B) carrying another small VALID
  // framed payload, WITHOUT resetting or finishing the FIRST. (Valid so B's read of the new stream does
  // not trip a framing-error teardown; small so it is never congestion-blocked.) The first stream stays
  // RECEIVING, so when B's accept loop adopts the second Bulk stream and `stop`s the first, the `stop`
  // queues a STOP_SENDING.
  let mut extra_frame = Vec::new();
  encode_frame(&[0xCDu8; 16], &mut extra_frame);
  a.test_open_extra_bidi_stream(ha, &extra_frame);

  // Drive the second stream to B. Each iteration: ferry A↔B, then forward B's post-ferry transmits ON to
  // A so B's outbound is EMPTY going into the measured `ingest_recv` (which runs with no further inbound
  // and no timer). The accept loop in that `ingest_recv` is then the only thing that can put a packet on
  // B's now-empty outbound — via the `stop` of the replaced first stream (the fix's `should_service` →
  // post-loop `service(now)`). Detect the adoption by the Bulk recv id LEAVING `first_recv` (to the new
  // id), and capture whether THAT ingest emitted a packet.
  let mut emitted_at_stop = false;
  let mut stop_ran = false;
  for k in 200..1200u64 {
    let tick = now + Duration::from_millis(k * 5);
    a.flush_stream(tick, ha);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    // Forward B's post-ferry transmits ON to A so B's outbound is empty at the measurement point.
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(tick, from, None, &bytes);
    }

    let recv_before = b.test_recv_id(hb, StreamClass::Bulk);
    let framing_failed = b.ingest_recv(tick, hb);
    assert!(
      !framing_failed,
      "the second Bulk stream's adoption must not trip a framing-error teardown"
    );
    let recv_after = b.test_recv_id(hb, StreamClass::Bulk);
    // The accept-loop `stop` fires exactly when the Bulk recv id is replaced away from `first_recv` to
    // the new (higher-index) id. Capture whether THIS `ingest_recv` emitted a packet.
    if recv_before == Some(first_recv) && recv_after.is_some_and(|n| n.index() > first_recv.index())
    {
      stop_ran = true;
      emitted_at_stop = b.poll_transmit().is_some();
      break;
    }
  }

  assert!(
    stop_ran,
    "B's accept loop must adopt the second Bulk stream and `stop` the first (the recv id must leave \
     first_recv={first_recv:?} for a higher index)"
  );
  assert!(
    emitted_at_stop,
    "stopping the replaced Bulk recv stream must drain its STOP_SENDING/credit into `out` THIS pump \
     (the `should_service`-on-stop fix) — with B's outbound drained immediately before and no timer \
     fired, the accept-loop `stop` is the only possible source of the emitted packet"
  );
}

/// Control-class overflow REAPS the whole connection, not just the stream. A Control overflow
/// means the peer is not consuming consensus traffic; reopening Control at a higher StreamId index
/// would mis-map it to Bulk on the peer (`class_of_index` is index-0-fixed), silently
/// black-holing consensus. The correct response is a full connection teardown: phase → `Closed`,
/// handle pushed onto `lost`. The connection must NOT be left `Validated` with a reopened Control
/// stream at a fresh index.
#[test]
fn control_class_overflow_reaps_connection() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);

  // Open both classes and validate so writes flush.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);

  // Verify the connection is Validated before the overflow.
  assert!(
    a.is_validated(ha),
    "connection must be Validated before the Control overflow test"
  );

  // Stage just over the cap directly into the Control buffer (peer is not reading consensus
  // traffic). This simulates what a `write_framed` overflow check will see.
  {
    let e = a.table.entry(ha).expect("A's entry");
    e.class_mut(StreamClass::Control)
      .outbound
      .resize(PER_CLASS_OUTBOUND_CAP + 1, 0u8);
  }

  // A write on Control now crosses the cap → the whole connection must be reaped (phase = Closed,
  // handle on `lost`). It must NOT reset-in-place and leave a reopened Control stream at a
  // higher index.
  a.write_framed(now, ha, StreamClass::Control, &commit(0x55));

  // The connection must be Closed (not Validated with a reopened Control stream).
  let is_closed = a
    .table
    .entry(ha)
    .map(|e| e.phase.is_closed())
    .unwrap_or(true);
  assert!(
    is_closed,
    "a Control-class overflow must reap the connection (phase = Closed), not reset the stream in place"
  );

  // The handle must be on the `lost` queue for the coordinator to reap.
  assert!(
    a.lost.contains(&ha),
    "a Control-class overflow must push the handle onto `lost` so the coordinator reaps it"
  );

  // The connection must NOT still be Validated (i.e., not left live-but-wedged with a reopened
  // Control stream at a fresh index).
  assert!(
    !a.is_validated(ha),
    "the connection must not remain Validated after a Control-class overflow"
  );
}

/// Reconnect churn must not leak quinn endpoint state. Repeatedly: dial A→B, complete the
/// handshake, then close A's connection and ferry until the connection fully drains. Each cycle's
/// `EndpointEvent::Drained` must be forwarded to `Endpoint::handle_event` so the endpoint frees its
/// slab slot + CID/reset-token indexes — not merely reaped from the local table. The observable is
/// `endpoint_open_connections()`: it must return to zero after every drained cycle and never grow
/// with the cycle count. Before the fix (Drained dropped at the drain site) the endpoint slab grew
/// by one per cycle even though the table was reaped.
#[test]
fn drained_connections_do_not_leak_endpoint_slab_state() {
  let opts = QuicOptions::accept_any_for_test();
  let mut a = Bridge::new(&opts, Some([0x55; 32]));
  let mut b = Bridge::new(&opts, Some([0x66; 32]));
  let a_addr = addr(21);
  let b_addr = addr(22);

  let base = Instant::now();
  let mut now = base;
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // One continuous monotonic clock across all cycles (a >1 s gap would trip the idle timeout, but
  // the per-cycle drain completes well inside that). 5 ms steps as elsewhere.
  let mut step = |a: &mut Bridge, b: &mut Bridge, now: &mut Instant| {
    *now += Duration::from_millis(5);
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr);
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    while let Some((from, bytes)) = pipe_to_b.pop() {
      b.handle_datagram(*now, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(*now, from, None, &bytes);
    }
    a.handle_timeout(*now);
    b.handle_timeout(*now);
    while a.connected.pop_front().is_some() {}
    while b.connected.pop_front().is_some() {}
    while a.stream_ready.pop_front().is_some() {}
    while b.stream_ready.pop_front().is_some() {}
  };

  const CYCLES: usize = 6;
  for cycle in 0..CYCLES {
    // Dial a fresh connection A→B and drive the handshake to completion on A.
    let ha = a
      .connect(
        now,
        b_addr,
        "viewstamp.local",
        Peer::Replica(ReplicaId::new(1)),
      )
      .expect("dial on a fresh endpoint succeeds");
    for _ in 0..200 {
      step(&mut a, &mut b, &mut now);
      if a.any_handshook() {
        break;
      }
    }
    assert!(
      a.any_handshook(),
      "cycle {cycle}: A's connection must finish the QUIC handshake"
    );

    // Close A's connection and ferry until it fully drains: the table entry is reaped AND the
    // endpoint slab slot is freed (Drained forwarded). Reap the `lost` queue each tick the way the
    // coordinator would, so the close path is exercised end to end.
    a.close_local(now, ha, CloseCause::PeerClosed);
    let mut drained = false;
    for _ in 0..600 {
      step(&mut a, &mut b, &mut now);
      while let Some(h) = a.take_lost() {
        a.reap(h);
      }
      while let Some(h) = b.take_lost() {
        b.reap(h);
      }
      if a.endpoint_open_connections() == 0 && a.table_len() == 0 {
        drained = true;
        break;
      }
    }
    assert!(
      drained,
      "cycle {cycle}: A's closed connection must drain — endpoint slab AND table back to zero \
       (open_connections={}, table_len={})",
      a.endpoint_open_connections(),
      a.table_len(),
    );
  }

  // The decisive leak check: after CYCLES open/close cycles the endpoint tracks NO leftover
  // connection. A leak (Drained dropped) would leave one slab entry per cycle here.
  assert_eq!(
    a.endpoint_open_connections(),
    0,
    "the endpoint slab must not retain drained connections across reconnect churn"
  );
  assert_eq!(
    a.table_len(),
    0,
    "the local table must be empty after all cycles drained"
  );
}

/// A LOCALLY-fatal inbound framing error must tear the connection down so it DRAINS and frees the
/// endpoint slab — not merely unbind routing. A peer (A) writes a frame whose declared length
/// exceeds `MAX_FRAME_LEN`; B's `ingest_recv` rejects it and routes the teardown through the shared
/// `close_local` choke-point, which issues the quinn `close`. With the close issued, B's connection
/// drains to `Drained` and the endpoint frees its slab slot + B's table entry empties.
///
/// The invariant this pins: a local-fatal teardown that sets `Phase::Closed` + pushes `lost` WITHOUT
/// a quinn `close` never drains the connection (the peer keeps it alive), so `Drained` never fires
/// and the slab slot + connection-cap slot are pinned indefinitely. Every local-fatal teardown must
/// close-then-drain via `close_local`.
#[test]
fn an_inbound_framing_error_closes_and_drains_freeing_the_endpoint_slab() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::Single);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Bind both sides so B's `ingest_recv` runs (it early-outs while Handshaking).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // Before the fault, B holds exactly its one live connection in both the table and the slab.
  assert_eq!(b.table_len(), 1, "B holds the live connection");
  assert!(
    b.endpoint_open_connections() >= 1,
    "the endpoint tracks B's live connection"
  );

  // A writes ONLY a 4-byte length prefix declaring a frame larger than `MAX_FRAME_LEN`. The decoder
  // rejects on the prefix alone — no body is needed — so this is the minimal over-cap frame.
  let over_cap = (MAX_FRAME_LEN + 1).to_be_bytes();
  a.test_open_write_first_stream(&over_cap);

  // Ferry until B's connection fully drains: ingest the over-cap prefix (which triggers the close),
  // then reap `lost` the way the coordinator would, and let the service pump drive `Drained`.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut closed_and_drained = false;
  for k in 1..600u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    // B ingests: the over-cap prefix trips the framing error and routes through `close_local`.
    b.ingest_recv(tick, hb);
    while let Some(h) = a.take_lost() {
      a.reap(h);
    }
    while let Some(h) = b.take_lost() {
      b.reap(h);
    }
    if b.endpoint_open_connections() == 0 && b.table_len() == 0 {
      closed_and_drained = true;
      break;
    }
  }

  assert!(
    closed_and_drained,
    "the over-cap inbound frame must close B's connection and drain it — endpoint slab AND table \
     back to zero (open_connections={}, table_len={})",
    b.endpoint_open_connections(),
    b.table_len(),
  );
}

/// While `Authenticating`, the Control recv decoder is capped at `MAX_HELLO_LEN` — so a peer cannot
/// pin a LARGE first Control frame before its identity validates. A (the dialer) is held
/// `Authenticating`; B opens a Control stream and writes a frame whose DECLARED length exceeds
/// `MAX_HELLO_LEN` but is far under `MAX_FRAME_LEN`. Under the pre-auth cap A's decoder rejects it on
/// the length prefix alone (a `FrameTooLong` from `ingest_recv`, before retaining the body) and tears
/// the connection down through the shared `close_local`. A never buffers the oversized frame's body.
///
/// The discriminating signal is `ingest_recv` returning `true` — the FRAMING-error teardown — which is
/// distinct from an idle/auth-deadline reap (those never run through `ingest_recv`). It must fire
/// PROMPTLY, on the first ingest that sees the prefix, far inside the 1 s idle timeout and the 5 s
/// auth deadline — so the teardown is unambiguously the cap, not a timeout.
///
/// NEUTER: raise the `Authenticating` Control cap back to `MAX_FRAME_LEN` (drop the phase split in
/// `decoder_max`) and the 36-declared frame is BUFFERED (its body just never arrives over the FIN'd
/// stream) — `ingest_recv` never returns `true`, A stays `Authenticating`, and this test fails. (A
/// would only later idle out, which this test deliberately does NOT accept as the teardown.)
#[test]
fn an_oversized_pre_auth_control_frame_is_rejected_not_buffered() {
  use crate::transport::labeled::MAX_HELLO_LEN;

  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb: _hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  // A's connection to B is `Authenticating` (the handshake completed; A never validated B), so A's
  // Control recv decoder is held at the small pre-auth cap.
  assert!(
    a.is_authenticating(ha),
    "A's connection starts Authenticating (pre-auth Control cap in force)"
  );

  // B writes a raw Control frame (its first stream → index 0 → Control on A) whose declared length is
  // one byte over `MAX_HELLO_LEN`. The decoder rejects on the 4-byte prefix alone — no body needed —
  // so a length prefix is the minimal trigger. Well under `MAX_FRAME_LEN`, so ONLY the pre-auth cap
  // rejects it.
  let over_hello = ((MAX_HELLO_LEN + 1) as u32).to_be_bytes();
  let _ = b.test_open_write_first_stream(&over_hello);

  // A small budget, far inside the 1 s idle timeout (≈200 ticks) and 5 s auth deadline: the only thing
  // that can tear A down this fast is the pre-auth cap rejecting the frame as it is read.
  const PROMPT_TICKS: u64 = 40;
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut framing_teardown = false;
  for k in 1..PROMPT_TICKS {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    // A ingests B's oversized pre-auth Control frame: the pre-auth cap trips a `FrameTooLong`, routed
    // through `close_local`. `ingest_recv` returning `true` IS that framing-error teardown — the signal
    // this test keys on (an idle/auth reap would not run through `ingest_recv`).
    let framed_error = a.ingest_recv(tick, ha);
    // The decoder must NEVER buffer the oversized frame's BODY — the over-cap declared length is
    // rejected on the 4-byte prefix, so at most the bounded length prefix is ever transiently held.
    assert!(
      a.test_partial_len(ha, StreamClass::Control) <= LEN_PREFIX,
      "the oversized pre-auth Control frame's body is never buffered (rejected on the prefix), k={k}"
    );
    if framed_error {
      framing_teardown = true;
      break;
    }
    // Until the rejection, A is still a healthy `Authenticating` connection (it did NOT idle/auth out
    // first — the teardown below is the cap, not a timeout).
    assert!(
      a.is_authenticating(ha),
      "A stays Authenticating until the cap rejects the frame (no idle/auth teardown first), k={k}"
    );
  }
  assert!(
    framing_teardown,
    "the oversized pre-auth Control frame must trip a prompt FRAMING-error teardown (ingest_recv \
     == true) — the pre-auth cap rejecting it, not a later idle/auth reap"
  );

  // After the close, drive the connection to a full drain (close + `Drained`) exactly as the
  // coordinator would, freeing the endpoint slab + cap slot.
  let mut torn_down = false;
  for k in PROMPT_TICKS..600u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while let Some(h) = a.take_lost() {
      a.reap(h);
    }
    while let Some(h) = b.take_lost() {
      b.reap(h);
    }
    if a.endpoint_open_connections() == 0 && a.table_len() == 0 {
      torn_down = true;
      break;
    }
  }
  assert!(
    torn_down,
    "the rejected connection must close + drain — endpoint slab AND table back to zero: \
     open_connections={}, table_len={}",
    a.endpoint_open_connections(),
    a.table_len(),
  );
  // Per-cause close observability: the over-cap declared length is a peer PROTOCOL VIOLATION and
  // must be attributed to FrameTooLong — not collapsed into TruncatedFrame (a torn FIN), which
  // would make an oversized-frame peer indistinguishable from a mid-frame disconnect in the
  // counters an operator diagnoses from.
  assert_eq!(
    a.conn_close_count(CloseCause::FrameTooLong),
    1,
    "the over-cap inbound frame is counted as FrameTooLong"
  );
  assert_eq!(
    a.conn_close_count(CloseCause::TruncatedFrame),
    0,
    "an over-cap rejection is NOT a truncation — the two fatal framing causes stay distinguishable"
  );
}

/// After validation the Control cap is RAISED to `MAX_FRAME_LEN`, so a LARGE post-auth Control
/// consensus frame (well over `MAX_HELLO_LEN`) is accepted — the small pre-auth cap must not survive
/// into the consensus phase or it would wrongly reject legitimate Control traffic. A validates B (so
/// A's Control decoder is lifted); B then sends a ~1 KiB consensus `Prepare` on Control, which A must
/// decode.
///
/// NEUTER: skip the `set_max` raise in `bind_validated` (leave Control at `MAX_HELLO_LEN`) and A
/// rejects this frame as `FrameTooLong`, tearing the connection down — so the message never arrives
/// and this test fails.
#[test]
fn a_large_post_validation_control_frame_is_accepted_after_the_cap_is_raised() {
  use crate::{ClientId, Prepare, RequestNumber, transport::labeled::MAX_HELLO_LEN};

  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Validate BOTH sides: A's Control decoder is raised to `MAX_FRAME_LEN` here, and B is validated so
  // it can open its Control send stream and stage the consensus frame.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // A ~1 KiB Prepare body forces an encoded Control frame far larger than `MAX_HELLO_LEN` yet under
  // `MAX_FRAME_LEN`. Written explicitly to Control (bypassing `partition`), so the class under test is
  // the raised one.
  let body = bytes::Bytes::from(vec![0x5Au8; 1024]);
  let big = Message::Prepare(Prepare::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(7),
    RequestNumber::with(1),
    body,
  ));
  assert!(
    big.encoded_len() > MAX_HELLO_LEN,
    "the test frame must exceed the pre-auth cap to exercise the raise"
  );
  b.write_framed(now, hb, StreamClass::Control, &big);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut got: Option<Message> = None;
  for k in 1..400u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    if a.ingest_recv(tick, ha) {
      break; // a teardown (the neuter) — leave `got` None so the assert fails informatively
    }
    while let Some(payload) = a.next_frame(ha, StreamClass::Control) {
      if let Ok(msg) = decode_message(Bytes::from(payload)) {
        got = Some(msg);
      }
    }
    if got.is_some() {
      break;
    }
  }
  assert_eq!(
    got,
    Some(big),
    "a large post-validation Control consensus frame must be accepted once the cap is raised"
  );
  assert!(
    a.is_validated(ha),
    "A stays Validated — the large Control frame is accepted, not a teardown"
  );
}

/// A peer that already validated US pipelines a legitimate consensus Control frame (larger than the
/// pre-auth `MAX_HELLO_LEN` cap — a `Prepare`/`PrepareOk`) directly behind its hello in ONE read pass
/// while we are still `Authenticating`. The pre-auth Control decode must consume ONLY the first
/// (hello) frame under the small cap and leave the larger frame BUFFERED, NOT reject it: rejecting it
/// would tear down a VALID connection (the coordinator authenticates only AFTER `ingest_recv`
/// returns, so the cap raise has not happened yet). Once validated, the cap is raised and the buffered
/// tail is delivered — nothing is lost.
///
/// Here B writes `[small frame ≤ MAX_HELLO_LEN][~1 KiB frame > MAX_HELLO_LEN]` in one stream write (so
/// A reads both in one pass). A is held `Authenticating`; its `ingest_recv` must NOT tear down, must
/// surface the small leading frame, and must keep the larger frame buffered. The test then validates A
/// (raising the cap + scheduling the re-read, as the coordinator does after `authenticate`); the larger
/// frame is then delivered on the next pump.
///
/// NEUTER: feed the WHOLE read buffer to the pre-auth-capped `extend` (drop the `extend_first` branch
/// in `ingest_recv`). `extend` decodes the small frame, then hits the larger frame's over-cap length
/// prefix and returns `FrameTooLong`, so `ingest_recv` returns `true` and `close_local`s A — this test
/// then fails at the no-teardown assert (and the larger frame never arrives). The companion
/// `an_oversized_pre_auth_control_frame_is_rejected_not_buffered` shows a FIRST over-cap frame is still
/// rejected, so the fix does not weaken the oversized-hello pin defense.
#[test]
fn a_control_frame_pipelined_after_the_hello_is_buffered_then_delivered_post_validation() {
  use crate::{ClientId, Prepare, RequestNumber, transport::labeled::MAX_HELLO_LEN};

  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb: _hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  assert!(
    a.is_authenticating(ha),
    "A starts Authenticating (the pre-auth Control cap is in force)"
  );

  // The leading frame stands in for the hello — opaque to the bridge (which does not classify it; the
  // coordinator's `authenticate` does), but sized within the pre-auth cap so `extend_first` admits it.
  let hello_stub = [0xA1u8; 6];
  // A legitimate consensus Control frame whose ENCODED length is far over `MAX_HELLO_LEN` yet under
  // `MAX_FRAME_LEN`: a peer that already validated us flushes this queued behind its hello.
  let big = Message::Prepare(Prepare::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(9),
    RequestNumber::with(1),
    bytes::Bytes::from(vec![0x6Cu8; 1024]),
  ));
  let big_payload = encode_message(&big);
  assert!(
    big_payload.len() > MAX_HELLO_LEN,
    "the pipelined frame must exceed the pre-auth cap to exercise the fix"
  );
  // `[hello][big]` written as ONE buffer on B's first stream (index 0 → Control on A), so both frames
  // arrive in A's single pre-auth read pass. The stream is kept OPEN (never FIN'd) like a real
  // long-lived Control stream — a FIN would make A's drained read return `ClosedStream`, which
  // `ingest_recv` treats as a reset and discards the buffered tail (a test artifact, not the surface
  // under test).
  let mut pipelined = Vec::new();
  encode_frame(&hello_stub, &mut pipelined);
  encode_frame(&big_payload, &mut pipelined);
  let _ = b.test_open_write_first_stream_kept_open(&pipelined);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Pump until A has read B's Control bytes (the leading hello frame surfaces). `ingest_recv` must
  // NEVER return `true` here — that would be the (neutered) framing-error teardown on the pipelined
  // larger frame.
  let mut hello_seen: Option<Vec<u8>> = None;
  for k in 1..200u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    assert!(
      !a.ingest_recv(tick, ha),
      "the pipelined larger frame must NOT tear A down pre-auth (k={k})"
    );
    assert!(
      a.is_authenticating(ha),
      "A stays Authenticating until it is validated below (k={k})"
    );
    if let Some(frame) = a.next_frame(ha, StreamClass::Control) {
      hello_seen = Some(frame);
      break;
    }
  }
  assert_eq!(
    hello_seen.as_deref(),
    Some(hello_stub.as_slice()),
    "the leading hello frame is delivered pre-auth"
  );
  // The larger frame is NOT surfaced yet — it is buffered un-decoded under the pre-auth cap.
  assert!(
    a.next_frame(ha, StreamClass::Control).is_none(),
    "the pipelined larger frame stays buffered while Authenticating (not yet decoded)"
  );
  assert!(
    a.test_partial_len(ha, StreamClass::Control) > MAX_HELLO_LEN,
    "the whole larger frame is retained un-decoded in the decoder's partial buffer"
  );

  // Validate A exactly as the coordinator does after `authenticate` succeeds on the hello: this raises
  // the Control cap to `MAX_FRAME_LEN` and schedules the post-validation re-read.
  let now = start + Duration::from_millis(200 * 5);
  a.bind_validated(now, ha, peer_b);

  // The buffered tail decodes under the raised cap on the next pump (no new Control bytes needed).
  let mut got: Option<Message> = None;
  for k in 201..400u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    assert!(
      !a.ingest_recv(tick, ha),
      "the buffered larger frame decodes cleanly post-validation, no teardown (k={k})"
    );
    while let Some(payload) = a.next_frame(ha, StreamClass::Control) {
      if let Ok(msg) = decode_message(Bytes::from(payload)) {
        got = Some(msg);
      }
    }
    if got.is_some() {
      break;
    }
  }
  assert_eq!(
    got,
    Some(big),
    "the Control frame pipelined behind the hello is delivered intact after validation"
  );
  assert!(
    a.is_validated(ha),
    "A stays Validated — the pipelined frame was buffered then delivered, never a teardown"
  );
}

/// Inbound accepts are bounded by the connection cap. A single server bridge with a LOW cap is
/// dialed by more distinct client bridges than the cap allows; the server must REFUSE the overflow
/// (its table never exceeds the cap) while the connections it did accept keep their handshake. This
/// is the untrusted-network backstop: without the cap each Initial would allocate a `Connection`.
#[test]
fn inbound_accepts_are_bounded_by_the_connection_cap() {
  const CAP: usize = 2;
  const DIALERS: usize = 5;

  let server_opts = QuicOptions::accept_any_for_test().with_max_connections(CAP);
  let mut server = Bridge::new(&server_opts, Some([0x77; 32]));
  let server_addr = addr(30);

  // Each dialer is its OWN bridge (so each presents a distinct connection to the server), with a
  // unique source address so the server keys them apart.
  let client_opts = QuicOptions::accept_any_for_test();
  let mut clients: Vec<(Bridge, SocketAddr)> = (0..DIALERS)
    .map(|i| {
      let mut c = Bridge::new(&client_opts, Some([0x80 + i as u8; 32]));
      let caddr = addr(40 + i as u16);
      c.connect(
        Instant::now(),
        server_addr,
        "viewstamp.local",
        Peer::Replica(ReplicaId::new(0)),
      )
      .expect("dial on a fresh endpoint succeeds");
      (c, caddr)
    })
    .collect();

  let base = Instant::now();
  let mut now = base;
  // Per-direction pipes: to the server (tagged with each client's addr) and back to each client.
  let mut to_server = PacketPipe::default();
  let mut to_client: Vec<PacketPipe> = (0..DIALERS).map(|_| PacketPipe::default()).collect();
  let mut max_server_table = 0usize;
  let mut max_server_slab = 0usize;

  for _ in 0..400u64 {
    now += Duration::from_millis(5);

    // Clients → server (each datagram tagged with the originating client's address).
    for (c, caddr) in clients.iter_mut() {
      while let Some((dst, bytes)) = c.poll_transmit() {
        assert_eq!(dst, server_addr);
        to_server.push(*caddr, bytes);
      }
    }
    // Server → clients: route each datagram back to the client that owns the destination address.
    while let Some((dst, bytes)) = server.poll_transmit() {
      if let Some(idx) = clients.iter().position(|(_, caddr)| *caddr == dst) {
        to_client[idx].push(server_addr, bytes);
      }
    }
    // Deliver to the server, then to each client.
    while let Some((from, bytes)) = to_server.pop() {
      server.handle_datagram(now, from, None, &bytes);
    }
    for (idx, (c, _)) in clients.iter_mut().enumerate() {
      while let Some((from, bytes)) = to_client[idx].pop() {
        c.handle_datagram(now, from, None, &bytes);
      }
    }
    server.handle_timeout(now);
    for (c, _) in clients.iter_mut() {
      c.handle_timeout(now);
    }
    while server.connected.pop_front().is_some() {}
    while server.stream_ready.pop_front().is_some() {}

    max_server_table = max_server_table.max(server.table_len());
    max_server_slab = max_server_slab.max(server.endpoint_open_connections());
    // The cap is the hard invariant at every observation point — both the local table and the
    // quinn endpoint slab. A refused inbound attempt allocates NEITHER.
    assert!(
      server.table_len() <= CAP,
      "the server table must never exceed the connection cap ({CAP}), saw {}",
      server.table_len()
    );
    assert!(
      server.endpoint_open_connections() <= CAP,
      "the endpoint slab must never exceed the connection cap ({CAP}), saw {}",
      server.endpoint_open_connections()
    );
  }

  // The cap actually BIT: with more dialers than the cap, the server admitted up to the cap and
  // refused the rest. The PEAK table size is the observable — it reached exactly the cap and never
  // exceeded it (the final count is not asserted: idle connections legitimately drain away after the
  // 1 s idle timeout, and a drained connection is now removed, so the table may shrink back).
  assert_eq!(
    max_server_table, CAP,
    "with {DIALERS} dialers and a cap of {CAP}, the server must admit exactly the cap and refuse \
     the rest (peak table size was {max_server_table})"
  );
  // The endpoint slab peak also stayed within the cap — refused attempts never allocated a slot.
  assert!(
    max_server_slab <= CAP,
    "the endpoint slab must stay within the cap ({CAP}); peak was {max_server_slab}"
  );
  // Per-cause close observability: the refusals are COUNTED even though a refused attempt never
  // allocates a `ConnEntry` (the refusal branch counts directly — the shared Closed-transition
  // counting can never see a pre-entry refusal). Excess dialers retry their Initials, so the count
  // is at least the surplus beyond the cap, and every refusal is attributed to AcceptCapacity.
  assert!(
    server.conn_close_count(CloseCause::AcceptCapacity) >= (DIALERS - CAP) as u64,
    "at-cap inbound refusals are counted (got {}, expected at least {})",
    server.conn_close_count(CloseCause::AcceptCapacity),
    DIALERS - CAP
  );
}

/// Outbound DIALS are bounded by the same connection cap as inbound accepts. With a cap of 1, the
/// first `connect` succeeds and the second is refused with [`DialError::AtCapacity`] WITHOUT
/// allocating — neither the local table nor the quinn endpoint slab gains a second entry.
///
/// The invariant this pins: the cap must bound DIALED and accepted connections alike. With only the
/// accept path checking it, `connect` could push the live count past `max_connections` under retry /
/// reconnect churn — so both the dial and the accept route through the single `at_capacity` gate.
#[test]
fn outbound_dials_are_bounded_by_the_connection_cap() {
  let opts = QuicOptions::accept_any_for_test().with_max_connections(1);
  let mut a = Bridge::new(&opts, Some([0x99; 32]));

  // First dial fits under the cap of 1: it allocates one connection in both the table and the slab.
  let first = a.connect(
    Instant::now(),
    addr(51),
    "viewstamp.local",
    Peer::Replica(ReplicaId::new(1)),
  );
  assert!(first.is_ok(), "the first dial fits under the cap of 1");
  assert_eq!(a.table_len(), 1, "the first dial inserts one table entry");
  assert_eq!(
    a.endpoint_open_connections(),
    1,
    "the first dial allocates one endpoint slab slot"
  );

  // Second dial is at the cap: it must be refused WITHOUT allocating a second connection.
  let second = a.connect(
    Instant::now(),
    addr(52),
    "viewstamp.local",
    Peer::Replica(ReplicaId::new(2)),
  );
  assert_eq!(
    second,
    Err(DialError::AtCapacity { cap: 1 }),
    "a dial at the cap is refused with AtCapacity, not allowed through"
  );
  assert_eq!(
    a.table_len(),
    1,
    "the refused dial must NOT add a second table entry"
  );
  assert_eq!(
    a.endpoint_open_connections(),
    1,
    "the refused dial must NOT allocate a second endpoint slab slot"
  );
}

/// An outbound message whose encoded frame would exceed [`MAX_FRAME_LEN`] is DROPPED by
/// `write_framed`'s `wire_size_bound()` ADMISSION gate — never even built as a pb view, let alone
/// encoded, framed, or emitted as a datagram — and the connection is NOT reaped. The receive side
/// fatals on an over-cap declared length, so emitting such a frame could only make the peer close;
/// consensus retransmission cannot help (the message can never fit a frame), so dropping is the
/// correct behaviour. Mirrors the byte-stream router's
/// `an_oversized_outbound_frame_is_dropped_and_the_conn_stays_open`.
#[test]
fn an_oversized_message_is_dropped_before_encoding_and_not_transmitted() {
  use crate::SyncCheckpoint;

  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);

  // Open A's send streams and validate B so `write_framed` would otherwise flush to the wire.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);

  // Drain any datagrams the open/bind produced so the post-write transmit check sees only what the
  // oversized write would add (which must be NOTHING).
  while a.poll_transmit().is_some() {}

  // A `SyncCheckpoint` whose snapshot alone is `MAX_FRAME_LEN` bytes — the surrounding header pushes
  // the encoded length strictly over the cap. Only ONE such message is allocated, and the preflight
  // is asserted via the cheap `wire_size_bound()` — the ADMISSION gate `write_framed` actually
  // checks, BEFORE building the pb view or encoding — so no second 16 MiB copy is paid.
  let snapshot = bytes::Bytes::from(vec![0u8; MAX_FRAME_LEN as usize]);
  let huge = Message::SyncCheckpoint(SyncCheckpoint::new(
    View::with(1),
    OpNumber::with(1),
    0,
    crate::Epoch::new(0),
    0,
    ReplicaId::new(0),
    0,
    snapshot,
    bytes::Bytes::new(),
  ));
  assert!(
    huge.wire_size_bound() > MAX_FRAME_LEN as usize,
    "the crafted message's wire_size_bound() exceeds the frame cap (checked without encoding)"
  );
  assert!(
    huge.encoded_len() > MAX_FRAME_LEN as usize,
    "the crafted message's encoded length also exceeds the frame cap (sanity check)"
  );
  assert_eq!(a.oversized_dropped(), 0, "no oversize recorded yet");

  // Record the Control class's staged-outbound length before the write, to prove no framed bytes
  // were appended (the message was never encoded).
  let control_outbound_before = a
    .table
    .entry(ha)
    .map(|e| e.class_mut(StreamClass::Control).outbound.len())
    .expect("A's entry");

  a.write_framed(now, ha, StreamClass::Control, &huge);

  assert_eq!(
    a.oversized_dropped(),
    1,
    "the oversized message is surfaced via the oversized-dropped counter"
  );
  // Nothing was staged for transmission: the frame was never built.
  assert_eq!(
    a.table
      .entry(ha)
      .map(|e| e.class_mut(StreamClass::Control).outbound.len()),
    Some(control_outbound_before),
    "no framed bytes are staged for a message that failed the size preflight"
  );
  // No datagram carrying the (un-built) frame was emitted.
  assert!(
    a.poll_transmit().is_none(),
    "an oversized message must not produce any outbound datagram"
  );
  // The connection stays alive — an oversized LOCAL message is a dropped send, not a teardown, and
  // the peer never sees an over-cap frame to fatal on.
  assert!(
    a.is_validated(ha),
    "the connection stays Validated: an oversized local message is dropped, not reaped"
  );
  assert!(
    !a.lost.contains(&ha),
    "an oversized local message must not push the connection onto `lost`"
  );

  // A normal-sized frame still routes on the same connection afterwards and does not bump the
  // oversized counter.
  a.write_framed(now, ha, StreamClass::Control, &commit(0x01));
  assert_eq!(
    a.oversized_dropped(),
    1,
    "a normal-sized message does not increment the oversized counter"
  );
}

/// The classify-then-admit regression for a `PrepareBatch`: `layout::partition`'s `PrepareBatch` arm
/// sizes the batch with `wire_size_bound()` — a saturating, allocation-free structural bound — rather
/// than `encoded_len()`, which would build the `pb` view (allocating) BEFORE `write_framed`'s own
/// admission gate ever runs. This drives BOTH calls in their true production order — `partition` (the
/// classifier `write_to_peer` calls first), then `write_framed` (the admission gate at
/// bridge/mod.rs's `wire_size_bound() > MAX_FRAME_LEN` check) — over a REAL validated connection, and
/// proves the oversized batch is refused at admission on whichever class it was classified onto,
/// with no frame ever built or observed by the peer on either stream class.
///
/// NEUTER CHECK: reverting `partition`'s `PrepareBatch` arm to `msg.encoded_len()` still passes this
/// test (both measures agree well below the `u32`-wrap regime this crafted 16 MiB+1 batch exercises),
/// but it is exactly the call `layout::tests::control_and_bulk_classify_as_expected` pins as unsound
/// pre-admission — this test's job is only to prove the PRODUCTION ROUTE refuses the batch, not to
/// re-litigate which sizing call classification uses.
#[test]
fn an_oversized_prepare_batch_is_refused_before_classification_builds_a_view() {
  use crate::{ClientId, PreparedEntry, RequestNumber, message::PrepareBatch};

  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Open A's send streams and validate BOTH sides so `write_framed` would otherwise flush to the
  // wire and B's `ingest_recv` actually runs (rather than early-outing pre-validation).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // Drain any datagrams the open/bind produced so the post-write checks below see only what the
  // oversized route would add (which must be NOTHING).
  while a.poll_transmit().is_some() {}

  // A `PrepareBatch` carrying one entry whose body alone is one byte over `MAX_FRAME_LEN`; the
  // carrier + per-entry framing pushes `wire_size_bound()` further past the cap. Only ONE such
  // message is allocated.
  let body = Bytes::from(vec![0u8; MAX_FRAME_LEN as usize + 1]);
  let huge = Message::PrepareBatch(PrepareBatch::new(
    View::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    vec![PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(1),
      RequestNumber::with(1),
      body,
    )],
  ));
  assert!(
    huge.wire_size_bound() > MAX_FRAME_LEN as usize,
    "the crafted batch's wire_size_bound() exceeds the frame cap (checked without building the pb view)"
  );

  // Classify through the REAL production function, in the REAL order `write_to_peer` calls it —
  // BEFORE `write_framed`'s admission gate — proving classification alone does not choke on (or
  // misclassify) an oversized batch.
  let class = crate::transport::quic::layout::partition(&huge, StreamLayout::ControlBulk);
  assert!(
    class.is_bulk(),
    "an over-threshold batch classifies onto Bulk, the conservative direction"
  );

  assert_eq!(a.oversized_dropped(), 0, "no oversize recorded yet");
  let control_outbound_before = a
    .table
    .entry(ha)
    .map(|e| e.class_mut(StreamClass::Control).outbound.len())
    .expect("A's entry");
  let bulk_outbound_before = a
    .table
    .entry(ha)
    .map(|e| e.class_mut(StreamClass::Bulk).outbound.len())
    .expect("A's entry");

  // Admit through the production choke-point with the class `partition` picked.
  a.write_framed(now, ha, class, &huge);

  assert_eq!(
    a.oversized_dropped(),
    1,
    "the oversized PrepareBatch is refused at write_framed's admission gate and counted"
  );
  assert_eq!(
    a.table
      .entry(ha)
      .map(|e| e.class_mut(StreamClass::Control).outbound.len()),
    Some(control_outbound_before),
    "no framed bytes are staged on Control for a batch that failed the size preflight"
  );
  assert_eq!(
    a.table
      .entry(ha)
      .map(|e| e.class_mut(StreamClass::Bulk).outbound.len()),
    Some(bulk_outbound_before),
    "no framed bytes are staged on Bulk either — the class partition picked still refuses"
  );
  assert!(
    a.poll_transmit().is_none(),
    "an oversized PrepareBatch must not produce any outbound datagram"
  );

  // Ferry forward: the peer must never observe a frame on either class, since none was ever built.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  for k in 1..20u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    b.ingest_recv(tick, hb);
  }
  assert_eq!(
    b.test_ready_len(hb, StreamClass::Control),
    0,
    "no frame is ready on the peer's Control class"
  );
  assert_eq!(
    b.test_ready_len(hb, StreamClass::Bulk),
    0,
    "no frame is ready on the peer's Bulk class"
  );
  assert!(
    b.next_frame(hb, StreamClass::Control).is_none(),
    "no frame was ever queued on Control"
  );
  assert!(
    b.next_frame(hb, StreamClass::Bulk).is_none(),
    "no frame was ever queued on Bulk"
  );

  // A normal-sized frame still routes on the same connection afterwards and does not bump the
  // oversized counter.
  a.write_framed(now, ha, StreamClass::Control, &commit(0x01));
  assert_eq!(
    a.oversized_dropped(),
    1,
    "a normal-sized message does not increment the oversized counter"
  );
}

/// `frame_checked`'s `len` parameter is a caller-supplied estimate computed BEFORE `payload` runs
/// (`Message::encoded_len()` for a consensus send, via the pb view `write_framed` builds). A
/// message whose true size nears 4 GiB could wrap that estimate below the cap via buffa's
/// unchecked `u32` accumulation while the real encoding is not — unreproducible here with an
/// actual message, so this drives `frame_checked` directly with a `len` that UNDERSTATES the
/// payload (as a wrapped estimate would), pinning that the backstop re-checks the bytes `payload`
/// actually produces and refuses (counting it) regardless of what `len` claimed.
#[test]
fn frame_checked_backstop_refuses_bytes_over_the_cap_even_when_len_understates_them() {
  let opts = QuicOptions::accept_any_for_test();
  let mut a = Bridge::new(&opts, Some([0x11; 32]));
  assert_eq!(a.oversized_dropped(), 0, "no oversize recorded yet");

  // `len = 0` lies that the payload is empty; only the backstop (which re-checks the bytes the
  // closure actually returns) can catch this one.
  let oversized = vec![0u8; MAX_FRAME_LEN as usize + 1];
  let framed = a.frame_checked(0, || oversized);

  assert!(
    framed.is_none(),
    "the backstop refuses a produced payload over the cap even though `len` said 0"
  );
  assert_eq!(
    a.oversized_dropped(),
    1,
    "the backstop counts its refusal through the same oversized-dropped counter as the preflight"
  );
}

/// An oversized control PREFACE is size-checked through the same `frame_checked` choke-point as a
/// consensus message: it is NOT framed or staged, it bumps the oversized counter, and the connection
/// is torn down (an over-cap preface is local API-misuse of the custom-identity hatch — the peer
/// would fatally reject its declared length, so closing is the safe response, never a panic).
///
/// The invariant this pins: EVERY encode-and-send path must size-check against `MAX_FRAME_LEN`. The
/// preface encode in `open_send_and_preface` had no size check, so an embedder-supplied over-cap
/// preface allocated and staged a frame the peer's decoder rejects, with no oversized-drop
/// accounting — the preface routes through `frame_checked` like every other encode-and-send.
#[test]
fn an_oversized_control_preface_is_not_framed_and_tears_down_the_connection() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let now = start + Duration::from_millis(5);

  // The connection is pre-preface (Authenticating, preface_done = false), and nothing is staged on
  // Control yet.
  assert_eq!(a.oversized_dropped(), 0, "no oversize recorded yet");
  assert_eq!(
    a.table
      .entry(ha)
      .map(|e| e.class_mut(StreamClass::Control).outbound.len()),
    Some(0),
    "Control outbound is empty before the preface"
  );

  // A preface one byte over the frame cap — only reachable via a misbehaving custom IdentitySource.
  let over_cap_preface = vec![0u8; MAX_FRAME_LEN as usize + 1];
  a.open_send_and_preface(now, ha, &over_cap_preface);

  // It was counted, never framed/staged…
  assert_eq!(
    a.oversized_dropped(),
    1,
    "the oversized preface bumps the oversized-dropped counter"
  );
  // …and the connection is torn down: phase Closed and queued onto `lost` (the same `close_local`
  // path every local-fatal decision uses). The over-cap preface bytes never reach the Control buffer
  // (the entry may already be Closed, but it must NOT hold a staged preface frame).
  let staged = a
    .table
    .entry(ha)
    .map_or(0, |e| e.class_mut(StreamClass::Control).outbound.len());
  assert_eq!(
    staged, 0,
    "no preface frame is staged for an over-cap preface"
  );
  assert!(
    a.lost.contains(&ha),
    "an over-cap preface tears the connection down (queued onto `lost`)"
  );
  assert!(
    !a.is_validated(ha),
    "the connection is not Validated after an over-cap preface"
  );
}

/// A within-cap preface still frames and stages normally through `frame_checked` — the Hello scheme's
/// preface rides out as the first Control frame and the connection is not torn down.
#[test]
fn a_normal_control_preface_is_framed_and_staged() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let now = start + Duration::from_millis(5);

  // A small, valid preface (stands in for a Hello).
  let preface = b"hello-preface";
  a.open_send_and_preface(now, ha, preface);

  assert_eq!(
    a.oversized_dropped(),
    0,
    "a within-cap preface does not bump the oversized counter"
  );
  assert!(
    !a.lost.contains(&ha),
    "a within-cap preface does not tear the connection down"
  );
  // The preface was framed and marked done (it may have already flushed to the stream, so assert the
  // done flag rather than a non-empty buffer).
  assert_eq!(
    a.table.entry(ha).map(|e| e.preface_done),
    Some(true),
    "a within-cap preface opens the streams and marks the preface done"
  );
}

/// A deferred `Drained` is processed in step 1 of the service pump: it frees quinn's slab slot,
/// reaps the local table entry, and PURGES any residual queued events for the same handle.
///
/// quinn's per-connection endpoint-event FIFO can place a non-terminal event (`NeedIdentifiers` /
/// `ResetToken` / `RetireConnectionId`) BEFORE the terminal `Drained`. Handling `Drained` INLINE at
/// the step-2 drain site (the earlier behaviour) would free the slab while an earlier same-handle
/// event is still deferred, so the next pass replays that event against the freed/reused handle. The
/// fix routes `Drained` through the SAME one-tick deferral as every other event, so step 1 drains
/// the queue in FIFO order — any earlier event is applied while the handle is still live, then
/// `Drained` frees the slot. The end-to-end FIFO path (real handshake feedback before a real
/// `Drained`) is exercised by `drained_connections_do_not_leak_endpoint_slab_state`; this test pins
/// the step-1 mechanics the deferral relies on, using the only externally-constructible
/// `EndpointEvent` (`drained()` — the inner non-terminal variants are `pub(crate)`).
///
/// It seeds A's `pending_endpoint_events` with a `Drained` for a LIVE handle followed by a SECOND
/// `Drained` for the same handle (standing in for a residual queued event), runs the pump, and
/// asserts: no panic; the slab slot is freed and the table entry reaped (the no-leak guarantee — the
/// old step 1 had no `Drained` arm, so it would never reap the entry here); exactly ONE `Drained` is
/// accounted (the residual second one is purged by the `retain`, not re-fed against the freed
/// handle); and the deferral queue is left empty.
#[test]
fn deferred_drained_frees_the_slab_reaps_the_entry_and_purges_residual_events() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::Single);
  let now = start + Duration::from_millis(5);

  // The connection is live in both the local table and quinn's slab before the drain.
  assert!(a.table.entry(ha).is_some(), "A holds the live connection");
  let slab_before = a.endpoint_open_connections();
  assert!(slab_before >= 1, "the endpoint tracks the live connection");

  let processed_before = a.endpoint_events_processed();

  // Seed the deferral queue: a terminal `Drained` for the live handle, then a SECOND `Drained` for
  // the SAME handle standing in for a residual queued event the purge must drop (quinn emits nothing
  // after `Drained`, but step 1 must be robust to it rather than re-feed a freed handle).
  a.pending_endpoint_events
    .push_back((ha, EndpointEvent::drained()));
  a.pending_endpoint_events
    .push_back((ha, EndpointEvent::drained()));

  // Step 1 drains the queue: it must NOT panic, frees the slab + reaps the entry on the first
  // `Drained`, and purges the trailing same-handle entry.
  a.service(now);

  // Exactly ONE `Drained` was fed back; the purged trailing one was NOT processed (it would have
  // over-counted by one). The service pass itself feeds back NO further endpoint events: the
  // connection is gone, so step 2 polls nothing for it.
  assert_eq!(
    a.endpoint_events_processed(),
    processed_before + 1,
    "exactly one Drained is processed; the residual same-handle event is purged"
  );
  // The queue is fully drained (the trailing event was purged, not left pending).
  assert!(
    a.pending_endpoint_events.is_empty(),
    "no endpoint event remains queued for the drained handle"
  );
  // The table entry is reaped — under the pre-fix step 1 (no `Drained` arm) it would have remained,
  // stranded with a freed slab slot.
  assert!(
    a.table.entry(ha).is_none(),
    "the drained connection's table entry is reaped"
  );
  // The slab slot is freed — the no-leak guarantee still holds.
  assert_eq!(
    a.endpoint_open_connections(),
    slab_before - 1,
    "the endpoint frees the drained connection's slab slot"
  );
}

/// A `poll_timeout`-DRIVEN driver drains a closed connection without any unrelated traffic forcing
/// the pass. This is the test the tight-loop churn tests cannot be: it never pumps continuously and
/// it feeds the bridge NO inbound datagrams — it only ever advances the clock to the deadline the
/// bridge itself reports and fires `handle_timeout`, exactly as a real sleep-until-`poll_timeout`
/// driver would.
///
/// The gap it pins: `service` defers every endpoint event (the terminal `Drained` included) to the
/// NEXT service pass via `pending_endpoint_events`. If `poll_timeout` reported only connection timers,
/// a driver sleeping on it would stop ONE pass before the deferred `Drained` is applied — so
/// `Endpoint::handle_event` would never free quinn's slab and `table.remove` would never free the
/// cap slot until some unrelated event happened to wake it. The fix: `poll_timeout` returns an
/// IMMEDIATE deadline whenever there is deferred immediate work (`has_pending_work` — the endpoint-
/// event feedback AND the coordinator-facing `connected` / `stream_ready` / `lost` queues), so the
/// deferred work is observable as work-due-now and the driver re-pumps at once.
///
/// A connection dialed to a black-hole peer (nothing ever answers) is `close_local`'d; the quinn
/// `close` arms the drain timer AND queues the handle onto `lost`. A faithful sleep-until-
/// `poll_timeout` driver drains the coordinator queues (here: reaps `lost`, what the real
/// `drain_bridge` does) on every wake — which is exactly what clears the immediate-work signal so the
/// clock can advance to the real drain timer. Following ONLY `poll_timeout` + that drain carries the
/// connection through `Drained` so both the endpoint slab and the local table return to zero. The
/// loop also asserts the no-busy-loop invariant directly: every deadline the bridge reports while the
/// connection is live is `Some` (a real timer or the immediate deferred-work signal — never `None`
/// that would strand a sleeping driver), and once every queue is empty and the connection is gone the
/// deadline goes to `None`.
#[test]
fn a_poll_timeout_driven_driver_drains_a_closed_connection() {
  let opts = QuicOptions::accept_any_for_test();
  let mut a = Bridge::new(&opts, Some([0xA1; 32]));
  let b_addr = addr(60);

  let base = Instant::now();
  let ha = a
    .connect(
      base,
      b_addr,
      "viewstamp.local",
      Peer::Replica(ReplicaId::new(1)),
    )
    .expect("dial on a fresh endpoint succeeds");
  assert_eq!(a.table_len(), 1, "the dial inserts the connection");
  assert!(
    a.endpoint_open_connections() >= 1,
    "the endpoint tracks the dialed connection"
  );

  // Close locally: the quinn `close` arms the drain timer. From here the ONLY thing that advances
  // the connection is the `poll_timeout`-driven loop below — no inbound datagram is ever delivered.
  a.close_local(base, ha, CloseCause::PeerClosed);

  // Sleep-until-`poll_timeout` driver: drain transmits AND the coordinator queues (the real
  // `drain_bridge` reaps `lost`), then jump the clock straight to the reported deadline and fire
  // timers. Crucially we never sleep PAST deferred work: while `pending_endpoint_events` or a
  // coordinator queue is non-empty `poll_timeout` reports `now`, so the loop re-pumps immediately;
  // draining `lost` is what then clears that immediate signal so the clock can advance to the real
  // drain timer. A hard step budget bounds the loop; a never-waking driver (the bug) would exhaust it
  // with the slab still held.
  let mut now = base;
  let mut drained = false;
  for _ in 0..10_000 {
    // The driver drains its outbound queue before sleeping (matches the real loop); the bytes go
    // to the black-hole peer and are discarded — they are NOT fed back into `a`.
    while a.poll_transmit().is_some() {}
    // Reap the `lost` queue the way `drain_bridge` would: `close_local` queued the handle there, and
    // it is now a `poll_timeout` wake signal, so a faithful driver drains it each pass.
    while let Some(h) = a.take_lost() {
      a.reap(h);
    }

    let Some(deadline) = a.poll_timeout() else {
      // No timer and no deferred work: the connection must already be fully gone for this to be
      // correct (otherwise a live connection was stranded with no wakeup).
      drained = a.endpoint_open_connections() == 0 && a.table_len() == 0;
      break;
    };
    // Never rewind the monotonic clock; an immediate (deferred-work) deadline may be at-or-before
    // `now`, which correctly means "re-pump without sleeping".
    now = now.max(deadline);
    a.handle_timeout(now);

    if a.endpoint_open_connections() == 0 && a.table_len() == 0 {
      drained = true;
      break;
    }
  }

  assert!(
    drained,
    "a poll_timeout-driven driver must drain the closed connection — slab and table back to zero \
     (open_connections={}, table_len={}) — without any unrelated traffic forcing the pass",
    a.endpoint_open_connections(),
    a.table_len(),
  );
  // The deferral queue is empty and no timer remains: a quiescent bridge reports `None`, so the
  // driver sleeps indefinitely rather than busy-looping.
  assert!(
    a.pending_endpoint_events.is_empty(),
    "no deferred endpoint event remains after the drain"
  );
  assert!(
    a.poll_timeout().is_none(),
    "a fully-drained bridge reports no deadline (no busy-loop in steady state)"
  );
}

/// `poll_timeout` reports work-due-now for EVERY coordinator-facing queue, not only the endpoint-
/// event feedback — so a `poll_timeout`-driven driver is woken to drain a `connected` /
/// `stream_ready` / `lost` event that a `service` pass enqueued AFTER this pass's `drain_bridge`
/// already ran, with NO inbound datagram forcing the pass.
///
/// The gap it pins: `has_pending_work` originally consulted ONLY `pending_endpoint_events`. But a
/// successful `write_framed` (and `open_send_and_preface` / `bind_validated` / `flush_stream`) re-
/// enters `service`, whose `on_app_event` can push a fresh `Connected` / `Stream(_)` /
/// `ConnectionLost` onto these coordinator queues — and `pump` runs `service` AFTER `drain_bridge`,
/// so that event lands once `drain_bridge`'s drain loops have already passed this pump. A driver that
/// then slept until `poll_timeout` would sleep on the connection idle timer (~1 s out) while
/// connection auth/read/reap work sat queued, until some unrelated datagram or later timer woke it.
///
/// This drives a LIVE connection (so a real far-future idle timer is armed — the observable the bug
/// would sleep on), seeds a coordinator queue the way a post-`drain_bridge` `service` pass would, and
/// follows ONLY `poll_timeout`: it advances the clock to the reported deadline and re-pumps, never
/// feeding an inbound datagram. The decisive assertion is that with the queue non-empty the reported
/// deadline is IMMEDIATE (at-or-before `now`) rather than the ~1 s idle timer, so the driver re-pumps
/// at once and drains the queued handle.
///
/// NEUTER CHECK (inline): the same seeded state is fed to a predicate that mimics the pre-fix
/// `pending_endpoint_events`-only `has_pending_work`; it is asserted to report the FAR idle timer
/// (≥ 100 ms out), i.e. it would strand the queued work — exactly the failure the full predicate
/// fixes. The live `poll_timeout` reports an at-or-before-`now` deadline for the same state.
#[test]
fn poll_timeout_wakes_the_driver_for_a_coordinator_queue_enqueued_after_drain() {
  // A genuinely connected bridge whose connection has an armed timer — the deadline a buggy
  // `poll_timeout` would sleep on while a coordinator event sat queued.
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);

  // Quiesce the connection so its NEXT timer is strictly in the future: advance the clock in small
  // steps, draining transmits and firing timers (NO inbound datagram), until nothing is staged and
  // `min_conn_timeout` is strictly after `now`. (Right after a handshake quinn may have a due
  // loss-detection / ACK timer; this settles to the longer idle-style timer so "immediate vs the
  // real timer" is an unambiguous contrast below.)
  let mut now = start;
  for _ in 0..64 {
    now += Duration::from_millis(5);
    while a.poll_transmit().is_some() {}
    a.handle_timeout(now);
    // Keep the coordinator queues clear while quiescing, so only the seeded event below populates one.
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    while a.take_lost().is_some() {}
    let quiescent = a.poll_transmit().is_none()
      && a.pending_endpoint_events.is_empty()
      && a.table.min_conn_timeout().is_some_and(|t| t > now);
    if quiescent {
      break;
    }
  }
  let bare_timer = a
    .table
    .min_conn_timeout()
    .expect("a live connection arms a timer");
  assert!(
    bare_timer > now,
    "the quiesced connection's next timer is strictly in the future (the deadline a sleeping driver \
     would wait on): {bare_timer:?} vs now {now:?}"
  );
  assert!(
    a.pending_endpoint_events.is_empty(),
    "no endpoint-event feedback is pending in this scenario"
  );

  // Stand in for `on_app_event` having pushed a coordinator event onto `stream_ready` from a
  // `service` pass that ran AFTER this pump's `drain_bridge` drain loops. (The end-to-end enqueue is
  // exercised by the loopback/sim; this pins the wake mechanics the deferral relies on, mirroring how
  // `deferred_drained_...` seeds `pending_endpoint_events` directly.)
  a.stream_ready.push_back(ha);

  // NEUTER: the pre-fix predicate consulted ONLY `pending_endpoint_events`, which is empty here, so
  // it would report the bare connection timer (strictly future) and strand the queued `stream_ready`
  // handle until an unrelated event woke the driver.
  let pre_fix_pending = !a.pending_endpoint_events.is_empty();
  let pre_fix_deadline = if pre_fix_pending {
    Some(now)
  } else {
    a.table.min_conn_timeout()
  };
  assert_eq!(
    pre_fix_deadline,
    Some(bare_timer),
    "with the pre-fix (endpoint-events-only) predicate the driver would sleep on the future \
     connection timer, stranding the queued coordinator event"
  );
  assert!(
    pre_fix_deadline.is_some_and(|d| d > now),
    "the pre-fix predicate's deadline is in the future — a sleeping driver would NOT re-pump now"
  );

  // The FULL predicate makes the coordinator queue work-due-now: `poll_timeout` reports an immediate
  // (at-or-before-`now`) deadline, so a sleep-until-`poll_timeout` driver re-pumps at once.
  let deadline = a.poll_timeout().expect("an immediate deadline is reported");
  assert!(
    deadline <= now,
    "a queued coordinator event must make poll_timeout report work-due-now (<= now), not the future \
     connection timer ({deadline:?} vs now {now:?})"
  );

  // Follow ONLY `poll_timeout`: advance to the reported deadline and drain the coordinator queue the
  // way `drain_bridge` would, feeding NO inbound datagram. The driver is woken and processes the
  // queued handle; once drained the predicate goes false and `poll_timeout` falls back to the real
  // connection timer (so this never busy-loops).
  let mut clock = now;
  let mut processed = false;
  for _ in 0..16 {
    let Some(d) = a.poll_timeout() else { break };
    clock = clock.max(d);
    // The coordinator's `drain_bridge` drains this queue here; draining it is the woken-up work.
    while let Some(h) = a.take_stream_ready() {
      assert_eq!(h, ha, "only the seeded handle is queued");
      processed = true;
    }
    if a.stream_ready.is_empty() && a.pending_endpoint_events.is_empty() {
      break;
    }
  }
  assert!(
    processed,
    "the poll_timeout-driven driver must be woken to drain the queued coordinator event without any \
     inbound datagram"
  );

  // No busy-loop: with the coordinator queues drained and no endpoint-event feedback pending, the
  // predicate is false again and `poll_timeout` reports the real (future) connection timer, not a
  // perpetual immediate wake.
  assert!(
    a.stream_ready.is_empty() && a.pending_endpoint_events.is_empty(),
    "the queued coordinator event was drained"
  );
  let after = a
    .poll_timeout()
    .expect("the live connection still arms its timer");
  assert!(
    after > clock,
    "once the queues are drained poll_timeout falls back to the future connection timer, not an \
     immediate wake (no busy-loop)"
  );
}

/// A send-path close unbinds routing ATOMICALLY: the instant a Control-class overflow tears the
/// connection down (mid-pump, via `close_local`), the peer is no longer routable to that handle, so
/// subsequent queued frames for that peer do NOT grow the closed connection's outbound buffers.
///
/// The gap it pins: `close_local` used to leave the `by_peer` binding intact until the coordinator's
/// later `reap`. A local close from the SEND path after `drain_bridge`'s lost-loop already ran this
/// pump would then still resolve the peer via `handle_for` / `bound_replica_peers`, so the rest of the
/// same pump could stage more framed bytes onto the just-closed entry — stale routing + avoidable
/// outbound growth. The fix unbinds inside `close_local`; `write_framed` also refuses to stage onto a
/// non-`Validated` entry (defense in depth). This test asserts BOTH: routing is gone immediately, and
/// a direct re-write onto the closed handle stages nothing.
#[test]
fn a_send_path_close_unbinds_routing_atomically_so_later_frames_do_not_grow_the_buffer() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);

  // Routing is live before the close: the peer resolves to this handle and appears in the fan-out.
  assert_eq!(
    a.handle_for(peer_b),
    Some(ha),
    "the validated peer routes to its handle before the close"
  );
  assert!(
    a.bound_replica_peers(None).contains(&peer_b),
    "the validated peer is in the routing fan-out before the close"
  );

  // Force a Control-class overflow on the SEND path: stage just over the cap, then a `write_framed`
  // on Control crosses it and routes through `close_local` — the send-path teardown this pins.
  {
    let e = a.table.entry(ha).expect("A's entry");
    e.class_mut(StreamClass::Control)
      .outbound
      .resize(PER_CLASS_OUTBOUND_CAP + 1, 0u8);
  }
  a.write_framed(now, ha, StreamClass::Control, &commit(0x01));

  // The connection is closed AND its routing is unbound ATOMICALLY — not deferred to a later reap.
  assert!(
    a.handle_for(peer_b).is_none(),
    "a send-path close must unbind routing at once: the peer no longer resolves to the handle"
  );
  assert!(
    !a.bound_replica_peers(None).contains(&peer_b),
    "the closed connection's peer must be gone from the routing fan-out immediately"
  );

  // The overflow path cleared+grew the Control buffer to the over-cap close marker; capture it, then
  // prove a SUBSEQUENT direct write to the same (now-closed) handle stages NOTHING — the binding is
  // gone and `write_framed` refuses a non-`Validated` entry, so the doomed buffer does not grow.
  let control_after_close = a
    .table
    .entry(ha)
    .map_or(0, |e| e.class_mut(StreamClass::Control).outbound.len());
  a.write_framed(now, ha, StreamClass::Control, &commit(0x02));
  a.write_framed(now, ha, StreamClass::Bulk, &commit(0x03));
  let control_after_extra = a
    .table
    .entry(ha)
    .map_or(0, |e| e.class_mut(StreamClass::Control).outbound.len());
  assert_eq!(
    control_after_extra, control_after_close,
    "frames queued for a closed connection must not grow its outbound buffer (routing skips it, \
     and write_framed refuses a non-Validated entry)"
  );
  assert!(
    !a.is_validated(ha),
    "the connection is no longer Validated after the send-path close"
  );
}

/// A frame too large to leave the sender in one flow-control window must still drain in FULL across
/// pumps WITHOUT a follow-on application write to that peer — the staged tail is carried by the
/// `Writable`-driven retry alone, never stranded until the next `write_framed` coincidentally
/// re-flushes it. This is the behavioral guard for [`Self::flush_outbound`]'s staged-tail handling:
/// one `flush_outbound` primes the first window, and from then on the ONLY thing that touches the
/// stream is a flush gated on a `Writable` (surfaced via `stream_ready`) — there is deliberately NO
/// unconditional `flush_stream` and NO second `write_framed`. If the tail were dropped, or the flush
/// path stopped retrying, the frame would never fully arrive.
///
/// The frame is sized OVER the 1 MiB `stream_receive_window`, so its first write is necessarily
/// partial (the peer's per-stream flow-control budget caps it) and the remainder must be pushed only
/// as the peer reads and reopens its window. Draining the staged tail therefore depends entirely on
/// the connection making progress under flow control between pumps, with no application traffic to
/// piggyback on.
///
/// NOTE on scope: under this transport's flow-control parameters the per-stream window (1 MiB) is the
/// binding limit on every partial write, never the connection-level send window (~9.5 MiB) — so the
/// `Writable` that retries the tail always originates from the peer freeing its STREAM window
/// (`MAX_STREAM_DATA`) as it reads, a signal independent of whether `flush_outbound` writes once or
/// loops. This test thus guards the end-to-end staged-tail drain, not the loop's extra iteration in
/// isolation; the connection-window-blocked path the loop additionally covers is unreachable here
/// because any progress on the tail requires the peer to read (which itself reopens the stream
/// window), so a single large frame cannot be stranded on connection-level flow control alone.
#[test]
fn a_large_frame_partial_write_drains_its_tail_across_pumps_without_a_follow_on_write() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // A opens both classes + validates B; B validates A so its `ingest_recv` surfaces frames.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.bind_validated(now, hb, peer_a);

  // A Bulk frame larger than B's 1 MiB stream_receive_window: the first write can only be partial,
  // so the tail MUST be carried out across later pumps as B reads and reopens its window.
  const BODY: usize = 12 * 1024 * 1024;
  let mut framed = Vec::new();
  encode_frame(&vec![0xD7u8; BODY], &mut framed);
  let total = framed.len();
  a.test_stage_outbound(ha, StreamClass::Bulk, &framed);

  // ONE flush to prime the first window's worth onto the stream. After this the test NEVER flushes
  // unconditionally and NEVER writes another frame to this peer.
  a.flush_outbound(now, ha, StreamClass::Bulk);
  let staged_after_first = a
    .table
    .entry(ha)
    .map_or(0, |e| e.class_mut(StreamClass::Bulk).outbound.len());
  assert!(
    staged_after_first > 0,
    "the frame ({total} B) must exceed one flow-control window so a tail stays staged after the \
     first flush (staged {staged_after_first})"
  );

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut got: Option<usize> = None;
  for k in 1..40_000u64 {
    let tick = now + Duration::from_millis(k);
    // Drive ONLY datagram movement + timers: A's transmits to B, B's (ACK/credit) back to A.
    while let Some((dst, bytes)) = a.poll_transmit() {
      assert_eq!(dst, b_addr);
      pipe_to_b.push(a_addr, bytes);
    }
    while let Some((dst, bytes)) = b.poll_transmit() {
      assert_eq!(dst, a_addr);
      pipe_to_a.push(b_addr, bytes);
    }
    while let Some((from, bytes)) = pipe_to_b.pop() {
      b.handle_datagram(tick, from, None, &bytes);
    }
    while let Some((from, bytes)) = pipe_to_a.pop() {
      a.handle_datagram(tick, from, None, &bytes);
    }
    a.handle_timeout(tick);
    b.handle_timeout(tick);

    // The ONLY flush of the staged tail: gated on A surfacing the Bulk stream as writable again. No
    // unconditional flush, no second `write_framed` — the retry is driven purely by flow control.
    let mut writable = false;
    while let Some(h) = a.take_stream_ready() {
      if h == ha {
        writable = true;
      }
    }
    if writable {
      a.flush_outbound(tick, ha, StreamClass::Bulk);
    }

    // B reads; once it decodes the whole frame the tail has fully drained.
    b.ingest_recv(tick, hb);
    if let Some(f) = b.next_frame(hb, StreamClass::Bulk) {
      got = Some(f.len());
      break;
    }
  }

  assert_eq!(
    got,
    Some(BODY),
    "the whole {BODY}-byte frame must drain across pumps from the staged tail alone, with no \
     unconditional flush and no follow-on application write to this peer"
  );
  // The send buffer is fully drained — nothing of the frame is left stranded.
  let staged_at_end = a
    .table
    .entry(ha)
    .map_or(0, |e| e.class_mut(StreamClass::Bulk).outbound.len());
  assert_eq!(
    staged_at_end, 0,
    "no staged tail may remain once the frame has been delivered"
  );
}

/// A connection that finishes the QUIC/mTLS handshake but never validates (no valid `Hello`, the
/// coordinator never binds it) must NOT pin its slot forever: the bridge stamps an
/// [`AUTH_DEADLINE`] when the connection enters [`Phase::Authenticating`], folds it into
/// [`Self::poll_timeout`] as a connection timer, and `close_local`s any still-`Authenticating`
/// connection once the clock passes that deadline — freeing its table entry AND its quinn endpoint
/// slab slot (the connection-cap slot). Without this a silent valid-cert peer holds its slot for the
/// connection's whole keepalive-extended lifetime (quinn's 1 s idle timeout is refreshed by the
/// peer's traffic, so it never trips), and N such peers exhaust `max_connections`.
///
/// The harness: A dials B and reaches `Authenticating` (these bridge-level tests have no coordinator
/// to run the identity step, so a completed handshake leaves A there). B is validated so it can drive
/// periodic Control traffic to A — whose datagrams (and A's ACKs) keep A's quinn idle timer fresh,
/// standing in for the real misbehaving peer's keepalives — proving A does NOT simply idle out at 1 s.
/// A is held `Authenticating` well past the 1 s idle timeout, then the test verifies:
///
/// 1. With A quiesced (its near quinn timers drained, its last activity pushing the idle timer out
///    PAST the auth deadline), `poll_timeout` reports the auth deadline — strictly EARLIER than A's
///    own `min_conn_timeout` — so a sleep-until-`poll_timeout` driver wakes exactly to reap it. This
///    is the decisive fold-in evidence: the reported deadline is the auth deadline, not quinn's timer.
/// 2. The drain is driven by `poll_timeout` + `handle_timeout` ALONE — no fixed-step ferry, no peer
///    traffic — exactly as a `poll_timeout`-scheduled driver would run it: each iteration advances the
///    clock to the reported deadline (`now.max(deadline)`) and fires `handle_timeout`. Once A is reaped
///    out of `Authenticating`, the reported deadline must ADVANCE past the (now-stale) auth deadline to
///    quinn's close/drain timer — it must NOT stick at the past auth deadline — and A's table entry AND
///    endpoint slab slot must reach zero. This is the load-bearing observable for phase-scoping the
///    deadline: a stale auth deadline that survived the reap would keep being reported as the next
///    wakeup, and `now.max(past)` never advances the clock, so quinn's future drain timer is never
///    reached — the `poll_timeout`-driven drive would STALL with the slab + cap slot leaked. (The
///    earlier fixed-step-ferry drain MASKED this: the ferry advanced the clock independently of
///    `poll_timeout`, so the stuck deadline was never the thing moving the clock.)
/// 3. The VALIDATED connection (B) carries NO auth deadline (`earliest_auth_deadline` is `None` on B,
///    and B's entry's `auth_deadline` is cleared), so a connection that validated before its deadline
///    is structurally excluded from the reap — only `Authenticating` connections are candidates.
///
/// NEUTER CHECK (deadline scope): drop the `is_authenticating()` filter from
/// [`ConnTable::earliest_auth_deadline`](super::table::ConnTable) AND the `auth_deadline = None` clear
/// in [`Self::close_local`], and the `poll_timeout`-driven drain STALLS: after the reap, `poll_timeout`
/// keeps returning the past auth deadline, `now.max(past)` never advances the clock to quinn's drain
/// timer, and A's table entry + slab slot never reach zero (`drained` stays false) — the leak this
/// guards.
/// NEUTER CHECK (the reap itself): skip the `close_local` on auth-deadline expiry in [`Self::service`]
/// (or never stamp the deadline) and A stays pinned in `Authenticating` past 5 s — its entry + slab
/// slot do NOT drop.
#[test]
fn an_authenticating_connection_past_its_deadline_is_reaped_freeing_its_slot() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_a = Peer::Replica(ReplicaId::new(0));

  // A reached `Authenticating` (no coordinator validated it) and carries a stamped auth deadline.
  assert!(
    a.is_authenticating(ha),
    "A's handshook-but-unbound connection sits in Authenticating"
  );
  let auth_deadline = a
    .table
    .entry(ha)
    .and_then(|e| e.auth_deadline)
    .expect("entering Authenticating stamps an auth deadline");
  // Stamped `connected_tick + AUTH_DEADLINE`, where the `Connected` event fired a handshake tick or
  // two before the returned clock `start` — so the deadline is at-or-just-before `start + AUTH_DEADLINE`.
  assert!(
    auth_deadline <= start + AUTH_DEADLINE
      && auth_deadline + Duration::from_millis(50) >= start + AUTH_DEADLINE,
    "the auth deadline is stamped at ~(handshake completion + AUTH_DEADLINE): {auth_deadline:?} vs \
     start+AUTH_DEADLINE {:?}",
    start + AUTH_DEADLINE
  );

  // Validate B so it can drive periodic Control traffic to A (keeping A's quinn idle timer fresh).
  // (3) A VALIDATED connection carries NO auth deadline, so it is never a reap candidate.
  b.open_send_and_preface(start, hb, &[]);
  b.bind_validated(start, hb, peer_a);
  assert!(b.is_validated(hb), "B is validated");
  assert!(
    b.table.entry(hb).and_then(|e| e.auth_deadline).is_none(),
    "a validated connection's auth deadline is cleared (it is not a reap candidate)"
  );
  assert!(
    b.table.earliest_auth_deadline().is_none(),
    "a validated-only bridge reports no auth deadline to reap"
  );

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Keep A alive WELL past the 1 s idle timeout via B's periodic Control traffic, up to ~4.6 s — still
  // short of the 5 s auth deadline. A staying `Authenticating` here is the proof it does NOT idle out:
  // its idle timer is refreshed by the traffic, so only the auth deadline can reap it.
  let mut nonce = 0u64;
  for k in 1..4600u64 {
    let tick = start + Duration::from_millis(k);
    if k % 100 == 0 {
      b.write_framed(tick, hb, StreamClass::Control, &pre_auth_keepalive(nonce));
      nonce += 1;
    }
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
  }
  assert!(
    a.is_authenticating(ha),
    "A is kept alive past the 1 s idle timeout by the peer's traffic and is STILL Authenticating \
     (so only the auth deadline — not the idle timeout — can reap it)"
  );
  // B is still validated and still carries no auth deadline — a validated connection is never reaped.
  assert!(
    b.is_validated(hb),
    "B remains validated across the keepalive window"
  );
  assert!(
    b.table.earliest_auth_deadline().is_none(),
    "B (validated) never becomes a reap candidate even as the clock runs past 1 s"
  );

  // SETTLE A: stop B's traffic and advance A alone WITHOUT new inbound data so its near quinn timers
  // (ACK/loss) drain, leaving only the idle timer — which, anchored at the ~4.6 s last activity, now
  // sits PAST the auth deadline. Drain A's coordinator queues so `has_pending_work` is false and
  // `poll_timeout` falls through to the connection-timer fold-in rather than reporting work-due-now.
  for k in 4601..4750u64 {
    let tick = start + Duration::from_millis(k);
    while a.poll_transmit().is_some() {}
    a.handle_timeout(tick);
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    while a.take_lost().is_some() {}
  }
  assert!(
    !a.has_pending_work(),
    "A is quiesced: no deferred immediate work, so poll_timeout reports a connection timer"
  );
  assert!(
    a.is_authenticating(ha),
    "A is still Authenticating at the settle point (before the deadline)"
  );

  // (1) The auth deadline is folded into poll_timeout AS a connection timer: it is reported, and it is
  // strictly EARLIER than quinn's own next timer for this connection (whose idle timer was pushed past
  // the deadline by the keepalive traffic). So a sleeping driver wakes exactly at the auth deadline.
  let quinn_timer = a
    .table
    .min_conn_timeout()
    .expect("a live connection arms a quinn timer");
  let reported = a.poll_timeout().expect("poll_timeout reports a deadline");
  assert_eq!(
    reported, auth_deadline,
    "poll_timeout must report the auth deadline (folded in as a connection timer)"
  );
  assert!(
    auth_deadline < quinn_timer,
    "the auth deadline ({auth_deadline:?}) must be strictly earlier than quinn's own next timer \
     ({quinn_timer:?}) — proving the fold-in is what the sleeping driver wakes on, not quinn's timer"
  );

  // Before the reap A still holds its table entry + endpoint slab slot.
  assert_eq!(a.table_len(), 1, "A's connection is live before the reap");
  assert!(
    a.endpoint_open_connections() >= 1,
    "the endpoint still tracks A's connection before the reap"
  );

  // (2) Drive the reap-and-drain with `poll_timeout` + `handle_timeout` ALONE — NO ferry, NO peer
  // traffic — the way a `poll_timeout`-scheduled driver would. Each iteration sleeps until the
  // reported deadline (advancing the clock via `now.max(deadline)`, never backwards), fires
  // `handle_timeout`, and reaps A's `lost` queue. This is the drive that a stale auth deadline would
  // STALL: if the past deadline kept being reported after the reap, `now.max(past)` would never reach
  // quinn's future drain timer. With the deadline phase-scoped + cleared on close, the reported
  // deadline advances PAST the auth deadline to quinn's close/drain timer, and the connection drains.
  //
  // B is left untouched: it never ACKs A's CONNECTION_CLOSE, so A's drain is driven purely by its own
  // close/drain timers (which `poll_timeout` must surface) — exactly the path the fold-in must keep
  // advancing. No datagram ever crosses, so `pipe_to_a` / `pipe_to_b` stay empty; the drain depends
  // entirely on the timer the bridge reports.
  // Start the clock at the first reported deadline (the auth deadline, asserted above).
  let mut now = a
    .poll_timeout()
    .expect("a live connection reports a poll_timeout deadline");
  let mut reaped_out = false;
  let mut deadline_advanced_past_auth = false;
  let mut drained = false;
  for _ in 0..4000u64 {
    a.handle_timeout(now);
    while let Some(h) = a.take_lost() {
      a.reap(h);
    }
    // The reap fires once the clock passes the auth deadline: A leaves `Authenticating`.
    if !reaped_out && !a.is_authenticating(ha) {
      reaped_out = true;
    }
    if a.table_len() == 0 && a.endpoint_open_connections() == 0 {
      drained = true;
      break;
    }
    // Sleep until the NEXT reported deadline. Once A is reaped (Closed), its auth deadline is cleared
    // AND filtered out, so `poll_timeout` reports quinn's close/drain timer — strictly AFTER the auth
    // deadline. Advance the clock to it MONOTONICALLY via `max`: this is the anti-stall pivot. A stale
    // past auth deadline reported here would make `now.max(past) == now`, the clock would never reach
    // quinn's drain timer, and this loop would spin in place until the iteration cap — leaving `drained`
    // false (the failure mode the neuter check reproduces).
    let next = a
      .poll_timeout()
      .expect("a draining connection still reports a poll_timeout deadline");
    if reaped_out && next > auth_deadline {
      deadline_advanced_past_auth = true;
    }
    now = now.max(next);
  }
  assert!(
    reaped_out,
    "past its auth deadline A is reaped out of Authenticating (close_local set it Closed)"
  );
  assert!(
    deadline_advanced_past_auth,
    "after the reap, poll_timeout must ADVANCE the reported deadline past the (now-stale) auth \
     deadline to quinn's drain timer — it must not stick at the past auth deadline (the stall this \
     guards against)"
  );
  assert!(
    drained,
    "the reaped Authenticating connection must drain fully under a poll_timeout-driven drive — table \
     entry AND endpoint slab slot back to zero (table_len={}, slab={})",
    a.table_len(),
    a.endpoint_open_connections(),
  );
  // Per-cause close observability: the reap counted EXACTLY ONE AuthDeadline close — and stayed at
  // one through the whole drain, even though quinn's own `ConnectionLost { LocallyClosed }` event
  // for the locally-issued close runs the same teardown tail again (the Closed-transition guard is
  // what makes the count once-per-connection, whichever notification arrives second).
  assert_eq!(
    a.conn_close_count(CloseCause::AuthDeadline),
    1,
    "the auth-deadline reap is counted exactly once for the connection"
  );
  for cause in [
    CloseCause::PeerClosed,
    CloseCause::IdleTimeout,
    CloseCause::Superseded,
    CloseCause::IdentityRejected,
    CloseCause::TruncatedFrame,
  ] {
    assert_eq!(
      a.conn_close_count(cause),
      0,
      "no close is attributed to {cause} in the auth-deadline reap scenario"
    );
  }
}

/// MANY connections that all sit in `Authenticating` and expire TOGETHER are reaped by a SINGLE
/// `handle_timeout` with NO recursive `service` re-entry — the non-recursive `close_local` makes a
/// mass simultaneous auth-deadline expiry do at most one service pass, and they all drain to zero.
///
/// The gap it pins: `close_local` used to call `self.service(now)` inline. The auth-reap loop runs
/// INSIDE `service`, so reaping N expired connections re-entered `service` once per close, each
/// re-entry rescanning the whole table — a stack-overflow / latency hazard under mass expiry, and a
/// contradiction of the no-reentrancy claim. The fix makes `close_local` a non-recursive state
/// mutation; the systematic service-after-every-pump (here the bridge's own entry-point `service`, in
/// production the coordinator's pump-end `service`) collects the CONNECTION_CLOSE. The `service_depth`
/// guard (asserted at the top of EVERY `service`) is the direct proof: it trips the instant a
/// `close_local` re-enters `service`.
///
/// Determinism: a connection's idle timer (1 s, anchored at handshake completion) always trips before
/// its 5 s auth deadline if nothing refreshes it, so to make the AUTH-reap (not the idle timeout) the
/// thing that fires, the test re-stamps every `Authenticating` connection's auth deadline to `now`
/// AFTER the handshakes — the deadline is the quantity under test — then fires ONE `handle_timeout(now)`
/// while the idle timers are still in the future. All N expire on that single pass.
///
/// NEUTER CHECK: restore `self.service(now)` at the tail of `close_local`, and this test PANICS in the
/// reaping `handle_timeout` — the auth-reap's first `close_local` re-enters `service`, tripping the
/// `service_depth` re-entrancy assertion (the recursion this fix removes). (The single-connection
/// `an_authenticating_connection_past_its_deadline_is_reaped...` test trips it too — the guard catches
/// the recursion on any auth-reap path; this test pins the N-at-once case the finding names.)
#[test]
fn a_mass_auth_deadline_expiry_reaps_all_with_no_service_reentrancy() {
  const N: usize = 8;
  let opts = QuicOptions::accept_any_with_layout(StreamLayout::Single).with_max_connections(N);
  let mut a = Bridge::new(&opts, Some([0x3A; 32]));
  let mut b = Bridge::new(&opts, Some([0x3B; 32]));
  let a_addr = addr(81);
  let b_addr = addr(82);

  let base = Instant::now();
  // Dial N connections A→B; each is a distinct connection (distinct handle) accepted on B.
  let mut handles = Vec::new();
  for _ in 0..N {
    let h = a
      .connect(
        base,
        b_addr,
        "viewstamp.local",
        Peer::Replica(ReplicaId::new(1)),
      )
      .expect("each dial is under the cap");
    handles.push(h);
  }
  assert_eq!(a.table_len(), N, "all N dials are live");

  // Ferry until every A-side connection has finished the QUIC handshake and sits in `Authenticating`
  // (A has no coordinator to validate them). Stay well inside the 1 s idle timeout while handshaking.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut now = base;
  for k in 0..200u64 {
    now = base + Duration::from_millis(k);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    while a.take_connected().is_some() {}
    while b.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    while b.take_stream_ready().is_some() {}
    if handles.iter().all(|&h| a.is_authenticating(h)) {
      break;
    }
  }
  assert!(
    handles.iter().all(|&h| a.is_authenticating(h)),
    "all N connections must reach Authenticating with a stamped auth deadline"
  );

  // Quiesce A's near quinn timers so the only timer in the PAST after the deadline re-stamp is the auth
  // deadline (not a stale ACK/loss timer), and drain A's coordinator queues. The clock stays well under
  // the 1 s idle timeout, so the connections remain `Authenticating`.
  for _ in 0..10 {
    now += Duration::from_millis(1);
    while a.poll_transmit().is_some() {}
    a.handle_timeout(now);
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    while a.take_lost().is_some() {}
  }
  assert!(
    handles.iter().all(|&h| a.is_authenticating(h)),
    "the connections are still Authenticating (well inside the 1 s idle timeout)"
  );

  // Re-stamp EVERY Authenticating connection's auth deadline to `now` so they all expire together on
  // the next timeout — deterministic, with the idle timers still in the future.
  let forced = a.force_auth_deadlines_now(now);
  assert_eq!(
    forced, N,
    "all N Authenticating connections get the expiry deadline"
  );

  // Fire ONE `handle_timeout` at the (now-past) deadline. Its single `service` runs the auth-reap, which
  // `close_local`s ALL N expired connections. With `close_local` non-recursive this is ONE service pass
  // and no re-entry — the `service_depth` guard inside `service` panics on any re-entrant call.
  let past = now + Duration::from_millis(1);
  a.handle_timeout(past);

  // Every connection was reaped out of `Authenticating` in that one pass (phase → Closed, queued lost).
  assert!(
    handles.iter().all(|&h| !a.is_authenticating(h)),
    "one handle_timeout must reap ALL expired Authenticating connections (no per-close recursion \
     needed to make progress)"
  );
  assert!(
    a.table.earliest_auth_deadline().is_none(),
    "no auth deadline remains pending — all N were reaped out of Authenticating"
  );

  // Drive the drain to zero the way a poll_timeout-driven driver would: ferry (so B acks the closes),
  // reap `lost`, advance to the reported deadline, fire timers. All N must free their table entries AND
  // endpoint slab slots — proving the non-recursive close still drains every connection.
  now = past;
  let mut drained = false;
  for _ in 0..10_000 {
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      now,
    );
    while let Some(h) = a.take_lost() {
      a.reap(h);
    }
    while let Some(h) = b.take_lost() {
      b.reap(h);
    }
    if a.table_len() == 0 && a.endpoint_open_connections() == 0 {
      drained = true;
      break;
    }
    let next = a.poll_timeout().unwrap_or(now + Duration::from_millis(5));
    now = now.max(next);
  }
  assert!(
    drained,
    "all N reaped connections must drain — table AND endpoint slab back to zero (table_len={}, \
     slab={})",
    a.table_len(),
    a.endpoint_open_connections(),
  );
}

/// One flapping but VALID-cert member that keeps reconnecting cannot exhaust the global connection
/// cap with same-peer connections: the bridge bounds the LIVE connection count per peer to
/// [`PER_PEER_CONN_LIMIT`], reaping the OLDEST same-peer excess on each validation. So a DIFFERENT
/// legitimate peer always still has room to connect — the connection-table-exhaustion DoS this bound
/// closes (a `Validated` connection is NOT reaped by the [`AUTH_DEADLINE`], so without a per-peer
/// bound a member that re-validates fresh connections — each kept alive by its keepalives — would
/// accumulate unbounded same-peer slots and starve the rest of the mesh).
///
/// Harness: bridge A (cap deliberately small) is repeatedly reconnected by `Replica(1)` — each wave
/// dials ONE fresh A→B connection, drives it handshook, and validates it as `Replica(1)` (the reap
/// fires here), then drains whatever was reaped. The live `Replica(1)` count must NEVER exceed the
/// bound across MANY more waves than the cap, every wave's dial must still fit (slots are freed), and
/// a final `Replica(2)` connection must still bind and survive. The mutual-dial pair is implicitly
/// preserved: the bound keeps the THREE newest, which always include the just-validated connection.
///
/// NEUTER CHECK: drop the `excess_peer_conns` reap loop in [`Self::bind_validated`] and the live
/// `Replica(1)` count climbs unbounded — within `cap` waves the table hits the cap, the next same-peer
/// dial fails `AtCapacity`, and the `Replica(2)` dial can never get a slot (the starvation this guards).
#[test]
fn one_peer_reconnect_churn_is_bounded_and_a_different_peer_still_connects() {
  // Cap deliberately small: smaller than the number of reconnect waves, so WITHOUT the per-peer reap
  // the churn would exhaust it. It is still > PER_PEER_CONN_LIMIT + a little drain headroom + 1 (for
  // the different peer), so WITH the reap every dial fits.
  const CAP: usize = 6;
  const WAVES: usize = 10;
  let opts = QuicOptions::accept_any_with_layout(StreamLayout::Single).with_max_connections(CAP);
  let mut a = Bridge::new(&opts, Some([0x5A; 32]));
  let mut b = Bridge::new(&opts, Some([0x5B; 32]));
  let a_addr = addr(91);
  let b_addr = addr(92);
  let flapping = Peer::Replica(ReplicaId::new(1));
  let other = Peer::Replica(ReplicaId::new(2));

  let base = Instant::now();
  let mut now = base;
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // Dial ONE fresh A→B connection (expecting `expected`), ferry until A's NEWEST handshook handle is
  // ready, and return it. The newest handshook handle is the one just dialed (older ones are already
  // Validated, not Authenticating). Bounded; threads the shared clock forward in 1 ms steps.
  let dial_handshook = |a: &mut Bridge,
                        b: &mut Bridge,
                        now: &mut Instant,
                        pa: &mut PacketPipe,
                        pb: &mut PacketPipe,
                        expected: Peer|
   -> ConnectionHandle {
    let h = a
      .connect(*now, b_addr, "viewstamp.local", expected)
      .expect("a reconnect dial must fit under the cap once stale excess is reaped");
    for _ in 0..400u64 {
      *now += Duration::from_millis(1);
      ferry_once(a, b, a_addr, b_addr, pa, pb, *now);
      while a.take_connected().is_some() {}
      while b.take_connected().is_some() {}
      while a.take_stream_ready().is_some() {}
      while b.take_stream_ready().is_some() {}
      while b.take_lost().is_some() {
        // B reaps its own side of any connection A closed, so B's slab does not fill across waves.
      }
      if a.is_authenticating(h) || a.is_validated(h) {
        break;
      }
    }
    assert!(
      a.is_authenticating(h) || a.is_validated(h),
      "the freshly dialed reconnect must finish its handshake"
    );
    h
  };

  // Reconnect churn: each wave is a fresh same-peer connection that VALIDATES (past the auth deadline),
  // exactly the case the auth-deadline reap does NOT cover.
  for wave in 0..WAVES {
    let h = dial_handshook(
      &mut a,
      &mut b,
      &mut now,
      &mut pipe_to_a,
      &mut pipe_to_b,
      flapping,
    );
    a.open_send_and_preface(now, h, &[]);
    a.bind_validated(now, h, flapping);

    // Drain whatever the reap closed so its table + slab slots free before the next wave's dial.
    for _ in 0..2_000u64 {
      if a.table.iter_mut().all(|(_, e)| !e.phase.is_closed()) {
        break;
      }
      now += Duration::from_millis(1);
      ferry_once(
        &mut a,
        &mut b,
        a_addr,
        b_addr,
        &mut pipe_to_a,
        &mut pipe_to_b,
        now,
      );
      while let Some(lh) = a.take_lost() {
        a.reap(lh);
      }
      while let Some(lh) = b.take_lost() {
        b.reap(lh);
      }
    }

    // THE BOUND: however many waves have run, the live same-peer count never exceeds the per-peer limit.
    assert!(
      a.live_conns_for_peer(flapping) <= PER_PEER_CONN_LIMIT,
      "wave {wave}: live Replica(1) connections ({}) must stay within PER_PEER_CONN_LIMIT ({}) — \
       reconnect churn must not accumulate same-peer connections",
      a.live_conns_for_peer(flapping),
      PER_PEER_CONN_LIMIT
    );
  }

  // After all the churn the live same-peer count is exactly the bound (steady state holds the newest
  // PER_PEER_CONN_LIMIT), and the table is bounded — NOT WAVES-deep.
  assert_eq!(
    a.live_conns_for_peer(flapping),
    PER_PEER_CONN_LIMIT,
    "the flapping peer settles at exactly PER_PEER_CONN_LIMIT live connections, not {WAVES}"
  );
  assert!(
    a.table_len() <= CAP,
    "the table is bounded by the cap throughout the churn (len={}, cap={CAP})",
    a.table_len()
  );

  // THE PAYOFF: a DIFFERENT legitimate peer still gets a slot — the one peer's churn did not exhaust the
  // global cap. Without the per-peer reap the table would be pinned at the cap by Replica(1) and this
  // dial would fail `AtCapacity`.
  let other_h = dial_handshook(
    &mut a,
    &mut b,
    &mut now,
    &mut pipe_to_a,
    &mut pipe_to_b,
    other,
  );
  a.open_send_and_preface(now, other_h, &[]);
  a.bind_validated(now, other_h, other);
  assert!(
    a.is_validated(other_h),
    "a different peer must still be able to connect and validate despite the one peer's churn"
  );
  assert_eq!(
    a.live_conns_for_peer(other),
    1,
    "the different peer holds its own live connection, untouched by Replica(1)'s per-peer reap"
  );
  assert_eq!(
    a.live_conns_for_peer(flapping),
    PER_PEER_CONN_LIMIT,
    "binding the different peer never reaps the flapping peer's kept connections (per-peer isolation)"
  );
  assert_eq!(
    a.handle_for(other),
    Some(other_h),
    "the different peer is routable (its routing slot points at the live connection)"
  );
}

/// A connection that validates LATE — the OLDEST same-peer connection by creation `seq`, but the most
/// recently bound — must NOT be reaped by its own per-peer bound, and its routing must survive. Under
/// mutual dial + reconnect churn a connection inserted EARLY can validate LATE (a slow/split Hello
/// arriving just before the auth deadline while newer reconnects already validated), so insertion
/// recency does not track validation recency. `bind_validated` binds the routing slot at the just-bound
/// handle BEFORE reaping; if the reap did not EXCLUDE that handle it would (being the oldest by `seq`)
/// land in the excess set, `close_local` it, and — because the slot points at it — drop the peer's
/// outbound routing while OTHER live same-peer connections remain (a peer with live connections but no
/// routing entry). The fix excludes the just-bound handle from the reap and, defensively, promotes the
/// newest remaining live same-peer connection if the slot is ever left unbound.
///
/// Harness: dial FOUR same-peer connections (h0 oldest … h3 newest by `seq`). The newest THREE are made
/// `Validated` + bound directly (they validated earlier, so the slot ends pointing at h3). Then the
/// OLDEST (h0) validates via `bind_validated` — the delayed validation. After it:
/// - h0 is NOT reaped (it is `Validated`, the just-bound canonical handle);
/// - the routing slot points at a LIVE same-peer connection (h0 itself), never `None`-with-live;
/// - the live same-peer count is exactly `PER_PEER_CONN_LIMIT` (one of the four was reaped — the oldest
///   OTHER, h1 — not h0).
///
/// NEUTER CHECK (don't exclude h): pass a dummy/never-matching handle to `excess_peer_conns` (or drop
/// the `keep` exclusion), and with limit 3 over four connections the OLDEST (h0 — the just-bound) is
/// returned, `close_local`d, and the routing slot it was just bound to is cleared → `handle_for(peer)`
/// is `None` while h2/h3 are still live (the dropped-routing bug this guards).
#[test]
fn delayed_validation_of_the_oldest_same_peer_connection_keeps_routing_live() {
  let opts = QuicOptions::accept_any_with_layout(StreamLayout::Single).with_max_connections(8);
  let mut a = Bridge::new(&opts, Some([0x6A; 32]));
  let b_addr = addr(73);
  let peer = Peer::Replica(ReplicaId::new(1));
  let now = Instant::now();

  // Dial four same-peer connections; each `connect` inserts an entry stamped with the next monotonic
  // `seq`, so h0 is the oldest and h3 the newest. No handshake is needed: `bind_validated` operates on
  // the table entry (bind + phase + reap), independent of the QUIC handshake state.
  let mut h = Vec::new();
  for _ in 0..4 {
    h.push(
      a.connect(now, b_addr, "viewstamp.local", peer)
        .expect("dial fits under the cap"),
    );
  }

  // The NEWEST three validated EARLIER: set them `Validated` + bound directly (not via `bind_validated`,
  // so no reap fires here). `bind_peer` is last-established-wins, so the slot ends at h3.
  for &hi in &h[1..4] {
    a.table.entry(hi).expect("entry").phase = Phase::Validated;
    a.table.bind_peer(hi, peer);
  }
  assert_eq!(
    a.handle_for(peer),
    Some(h[3]),
    "before the delayed validation the slot points at the newest bound handle (h3)"
  );

  // The OLDEST (h0) validates LATE. This binds the slot at h0, then reaps the per-peer excess.
  a.bind_validated(now, h[0], peer);

  // h0 — the just-bound, oldest-by-seq handle — must survive the reap.
  assert!(
    a.is_validated(h[0]),
    "the just-bound oldest-by-seq connection is never reaped by its own per-peer bound"
  );
  // Routing must point at a LIVE same-peer connection — here h0, the canonical just-bound handle —
  // never `None` while live same-peer connections remain.
  let routed = a.handle_for(peer);
  assert_eq!(
    routed,
    Some(h[0]),
    "the just-validated canonical handle (h0) holds the routing slot after the reap"
  );
  assert!(
    routed.is_some_and(|r| a.is_validated(r)),
    "the routing slot points at a LIVE (Validated) connection, never a reaped/closed one"
  );
  // Exactly one of the four was reaped (the oldest OTHER, h1) — the bound settles at the limit.
  assert_eq!(
    a.live_conns_for_peer(peer),
    PER_PEER_CONN_LIMIT,
    "the per-peer bound settles at PER_PEER_CONN_LIMIT live connections (one excess reaped)"
  );
  assert!(
    !a.is_validated(h[1]) || a.table.entry(h[1]).is_some_and(|e| e.phase.is_closed()),
    "the reaped connection is the OLDEST OTHER (h1), now closing — not the just-bound h0"
  );
  // h2 and h3 (the newest others) are kept alongside h0.
  assert!(
    a.live_conns_for_peer(peer) == PER_PEER_CONN_LIMIT
      && [h[0], h[2], h[3]].iter().all(|&hi| {
        a.table
          .entry(hi)
          .is_some_and(|e| !e.phase.is_closed() && e.peer == Some(peer))
      }),
    "the kept set is h0 (just-bound) plus the two NEWEST others (h2, h3)"
  );
}

/// Losing the connection a peer routes OUTBOUND on must RECOVER routing to its live mutual-dial sibling,
/// not leave the peer unrouteable until a future re-dial validates. Under the mutual-dial design a peer
/// pair holds TWO validated connections; if `by_peer[p]` points at one and that one is lost/closed,
/// `mark_closed_unbind_push`'s `unbind` clears the slot — but its routing-recovery promote then re-points
/// `by_peer[p]` at the still-live sibling (the just-closed handle is `Closed`, so `promote` skips it).
/// This exercises BOTH teardown paths that share that tail: a PEER-initiated `Event::ConnectionLost`
/// (driven through `on_app_event`) and a LOCAL `close_local`. A single-connection peer whose only
/// connection is lost has no sibling, so routing correctly CLEARS (and `routing_is_live` holds
/// vacuously). And a loss of a connection that is NOT the routing target leaves the slot untouched.
///
/// NEUTER CHECK (remove the recovery): drop the `promote_routing_if_unbound(p)` call from
/// `mark_closed_unbind_push`. Then losing the routed handle clears `by_peer[p]` and leaves it empty
/// WHILE the live sibling remains — `handle_for(peer)` returns `None` (the peer is unrouteable for
/// outbound) and the `routing_is_live` debug-assert in the tail trips. This is the I2 gap the recovery
/// closes.
#[test]
fn losing_a_routed_connection_recovers_routing_to_a_live_sibling() {
  let opts = QuicOptions::accept_any_with_layout(StreamLayout::Single).with_max_connections(8);
  let mut a = Bridge::new(&opts, Some([0x6B; 32]));
  let b_addr = addr(74);
  let peer = Peer::Replica(ReplicaId::new(1));
  let now = Instant::now();

  // The mutual-dial pair: two same-peer validated connections. `h_routed` is dialed first (older `seq`),
  // `h_sibling` second (newer). Both are bound + Validated directly on the table (no handshake needed —
  // routing recovery operates on the table entry's phase + peer). `bind_peer` is last-established-wins,
  // so binding `h_sibling` LAST then `h_routed` LAST leaves the slot at `h_routed` — the connection
  // selected for OUTBOUND, which the loss below tears down.
  let h_routed = a
    .connect(now, b_addr, "viewstamp.local", peer)
    .expect("dial fits under the cap");
  let h_sibling = a
    .connect(now, b_addr, "viewstamp.local", peer)
    .expect("dial fits under the cap");
  for &hi in &[h_sibling, h_routed] {
    a.table.entry(hi).expect("entry").phase = Phase::Validated;
    a.table.bind_peer(hi, peer);
  }
  assert_eq!(
    a.handle_for(peer),
    Some(h_routed),
    "the peer's outbound route is the routed handle before the loss"
  );

  // PEER-INITIATED LOSS of the routed handle: quinn emits `ConnectionLost`. The shared teardown tail
  // marks `h_routed` Closed + unbinds it, then RECOVERS routing to the live sibling.
  a.on_app_event(
    now,
    h_routed,
    Event::ConnectionLost {
      reason: quinn_proto::ConnectionError::Reset,
    },
  );
  assert!(
    a.table.entry(h_routed).is_some_and(|e| e.phase.is_closed()),
    "the lost routed connection is marked Closed (kept for the drain)"
  );
  assert_eq!(
    a.handle_for(peer),
    Some(h_sibling),
    "routing PROMOTES to the live sibling — the peer still has an outbound route across the loss \
     (not cleared until a re-dial)"
  );
  assert!(
    a.is_validated(h_sibling),
    "the promoted routing target is the LIVE (Validated) sibling, never the Closed handle"
  );

  // LOCAL `close_local` of the now-routed sibling — the OTHER teardown path through the same tail. With
  // no live same-peer connection left (the first handle is Closed), routing correctly CLEARS: a
  // single-connection-worth-of-live peer losing its only live connection is unrouteable, and that is the
  // consistent state (`routing_is_live` holds vacuously — no live entry, empty slot).
  a.close_local(now, h_sibling, CloseCause::PeerClosed);
  assert_eq!(
    a.handle_for(peer),
    None,
    "with no live sibling remaining, losing the last live connection clears routing"
  );
  assert!(
    a.table.routing_is_live(peer),
    "an unbound slot with no live same-peer entry is the consistent routing state (I2, vacuous)"
  );

  // A loss of a connection that is NOT the peer's routing target leaves the slot UNTOUCHED. Fresh pair:
  // bind `h_routed2` as the canonical route, `h_extra` as a non-routed live sibling, then lose `h_extra`.
  let h_routed2 = a
    .connect(now, b_addr, "viewstamp.local", peer)
    .expect("dial fits under the cap");
  let h_extra = a
    .connect(now, b_addr, "viewstamp.local", peer)
    .expect("dial fits under the cap");
  for &hi in &[h_extra, h_routed2] {
    a.table.entry(hi).expect("entry").phase = Phase::Validated;
    a.table.bind_peer(hi, peer);
  }
  assert_eq!(
    a.handle_for(peer),
    Some(h_routed2),
    "routed2 holds the slot"
  );
  a.close_local(now, h_extra, CloseCause::PeerClosed);
  assert_eq!(
    a.handle_for(peer),
    Some(h_routed2),
    "losing a NON-routed connection leaves the routing target untouched (unbind no-op, promote no-op)"
  );

  // A `Handshaking` connection torn down before it ever bound a peer has `peer == None` — the recovery
  // is skipped entirely (nothing to promote), and the unrelated peer's routing is unaffected.
  let h_handshaking = a
    .connect(now, b_addr, "viewstamp.local", peer)
    .expect("dial fits under the cap");
  a.table.entry(h_handshaking).expect("entry").peer = None;
  a.close_local(now, h_handshaking, CloseCause::PeerClosed);
  assert_eq!(
    a.handle_for(peer),
    Some(h_routed2),
    "tearing down a peerless Handshaking connection promotes nothing and leaves routing intact"
  );
}

/// A peer that STREAMS Bulk-class data BEFORE its identity validates cannot pin memory on the in-use
/// bidi surface: while a connection is `Authenticating`, `ingest_recv` reads ONLY the Control class
/// (which carries the identity preface), NOT Bulk. So the Bulk decoder does not grow and no Bulk
/// flow-control credit is regranted — quinn's per-stream window backpressures the withholding peer.
/// Once the connection validates, the SAME Bulk bytes (buffered in quinn, never dropped) flow normally.
///
/// Harness: A dials B; both sit `Authenticating`. B is then `Validated` on ITS side (so it can open its
/// Bulk send stream and stage a Bulk frame) and streams a Bulk frame toward A. A is held `Authenticating`
/// (the withholding-peer's victim has not validated B yet); B drives periodic Control keepalive frames
/// so A's connection stays alive in `Authenticating` (an `Authenticating` connection otherwise idle-times
/// out without traffic). Each tick A's `ingest_recv` runs and the test asserts, WHILE A is
/// `Authenticating`:
/// - A's Bulk decoder stays empty (`ready_len + partial_len == 0`) — Bulk is NOT read or extended;
/// - A's Control decoder DID receive frames — Control reading is unchanged, the Hello path still flows.
///
/// Then A validates and reads again: the Bulk frame B sent pre-validation is delivered intact (the bytes
/// were backpressured in quinn, not lost).
///
/// NEUTER CHECK (read Bulk pre-auth): change `ingest_recv`'s `read_classes` to always read both classes
/// (drop the `is_validated` gate), and A's Bulk decoder GROWS while `Authenticating` (the frame is read
/// and its credit regranted) — the peer-controllable pre-auth memory pin this guards.
#[test]
fn bulk_is_not_read_or_credited_before_the_peer_identity_validates() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));

  // A is the receiver whose connection to B is still `Authenticating` (it has not validated B). B is
  // validated on ITS side so it can open its Bulk send stream and stream frames toward A.
  assert!(
    a.is_authenticating(ha),
    "A's connection to B starts Authenticating"
  );
  b.open_send_and_preface(start, hb, &[]);
  b.bind_validated(start, hb, peer_a);

  // B streams a Bulk frame toward A while A is still Authenticating — the withholding peer pushing Bulk
  // ahead of A binding it. A distinguishable payload so the post-validation delivery is unambiguous.
  let bulk_msg = commit(0x44);
  b.write_framed(start, hb, StreamClass::Bulk, &bulk_msg);

  // Drive the authenticating phase with `ferry_once` (which fires `handle_timeout` on both, keeping the
  // timers fresh) and B sending a periodic Control frame so A's `Authenticating` connection stays alive
  // (mirrors the auth-deadline test's keepalive). A's `ingest_recv` runs each tick. Throughout, A's Bulk
  // decoder must never hold a byte (Bulk is not read pre-validation), while Control IS read.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut control_seen_while_auth = false;
  let mut nonce = 0u64;
  for k in 1..120u64 {
    let tick = start + Duration::from_millis(k * 5);
    // Periodic Control traffic from the validated side keeps A's connection from idling out.
    if k % 6 == 0 {
      b.write_framed(tick, hb, StreamClass::Control, &pre_auth_keepalive(nonce));
      nonce += 1;
    }
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    while a.take_lost().is_some() {}
    a.ingest_recv(tick, ha);

    // A must stay Authenticating across the whole phase (it never validates B here).
    assert!(
      a.is_authenticating(ha),
      "A remains Authenticating throughout the pre-validation phase (k={k})"
    );
    // INVARIANT (the fix): while Authenticating, A's Bulk decoder never holds a single byte — neither a
    // complete frame nor a partial one. The Bulk bytes are backpressured in quinn, unread + uncredited.
    assert_eq!(
      a.test_ready_len(ha, StreamClass::Bulk) + a.test_partial_len(ha, StreamClass::Bulk),
      0,
      "no Bulk byte may enter A's decoder while Authenticating (Bulk is not read → not credited), k={k}"
    );
    // Drain A's Control frames so its decoder does not just fill with the keepalive backlog; note we saw
    // Control flow (the Hello path is unchanged — only Bulk is withheld pre-validation).
    while a.next_frame(ha, StreamClass::Control).is_some() {
      control_seen_while_auth = true;
    }
  }
  assert!(
    control_seen_while_auth,
    "the Control class must still be read while Authenticating (the Hello must flow)"
  );
  // The Bulk recv stream WAS adopted (id tracked, so the stream is not lost) even though unread — the
  // data backpressure, not non-adoption, is what the skip provides.
  assert!(
    a.test_recv_id(ha, StreamClass::Bulk).is_some(),
    "A adopts B's Bulk recv stream (id tracked) but leaves its bytes unread until Validated"
  );

  // NOW A validates B. The previously-withheld Bulk frame must flow with nothing lost — the bytes were
  // buffered in quinn under backpressure, and the post-`Validated` read drains them.
  let mut now = start + Duration::from_millis(120 * 5);
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  assert!(a.is_validated(ha), "A has validated B");

  let mut bulk_msg_received: Option<Message> = None;
  for k in 0..200u64 {
    let tick = now + Duration::from_millis(k * 5);
    now = tick;
    // Keep B driving a little Control traffic so the link stays warm while the buffered Bulk drains.
    if k % 6 == 0 {
      b.write_framed(tick, hb, StreamClass::Control, &pre_auth_keepalive(nonce));
      nonce += 1;
    }
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    // Skip the Control keepalive frames; find the one Bulk frame B sent pre-validation.
    while a.next_frame(ha, StreamClass::Control).is_some() {}
    if let Some(payload) = a.next_frame(ha, StreamClass::Bulk) {
      bulk_msg_received =
        Some(decode_message(Bytes::from(payload)).expect("a valid framed Bulk message"));
      break;
    }
  }
  assert_eq!(
    bulk_msg_received,
    Some(bulk_msg),
    "after validation the withheld Bulk frame flows intact (backpressured pre-auth, never dropped)"
  );
}

/// Pre-auth Bulk that was buffered (adopted-but-unread) while a connection was `Authenticating` MUST
/// be read the instant the connection validates, WITHOUT any further external traffic. Because the
/// `Authenticating` skip leaves Bulk bytes unread + backpressured in quinn and `Readable` fires only
/// per-received-STREAM-frame, if the peer's Hello and its Bulk arrived in the SAME readiness edge that
/// edge is already consumed — nothing would re-drive a Bulk read. `bind_validated` therefore SCHEDULES
/// one: it enqueues the handle on `stream_ready`, which `has_pending_work` counts (so `poll_timeout`
/// returns the immediate deadline and a `poll_timeout`-driven driver re-pumps at once), and the next
/// pump's `ingest_recv` reads the now-allowed Bulk class — delivering the buffered bytes.
///
/// Harness: A is held `Authenticating`; B (validated on its side) streams ONE Bulk frame, ferried to A
/// so the bytes buffer in quinn while A's `ingest_recv` reads only Control (Bulk decoder stays empty).
/// Then ALL ferrying STOPS and A validates B. The test asserts the scheduling fired (`stream_ready`
/// holds `ha`, `poll_timeout` is immediate) and that draining `stream_ready` → `ingest_recv` (with NO
/// new datagrams) delivers the buffered Bulk frame.
///
/// NEUTER CHECK (don't schedule the post-validation read): drop the `stream_ready.push_back(h)` at the
/// tail of `bind_validated`, and after validation `stream_ready` is empty + `ingest_recv` is never
/// re-driven for `ha`, so the buffered Bulk frame is STRANDED (never delivered without unrelated later
/// traffic) — the liveness bug this guards.
#[test]
fn pre_auth_bulk_is_read_immediately_after_validation_without_new_traffic() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));

  assert!(a.is_authenticating(ha), "A starts Authenticating");
  // B validates on its side so it can open its Bulk send stream and stage a Bulk frame.
  b.open_send_and_preface(start, hb, &[]);
  b.bind_validated(start, hb, peer_a);
  let bulk_msg = commit(0x77);
  b.write_framed(start, hb, StreamClass::Bulk, &bulk_msg);

  // Ferry until the Bulk bytes have buffered in quinn for A (A still Authenticating, Bulk unread). B
  // drives periodic Control keepalive so A's Authenticating connection does not idle out while we wait.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut nonce = 0u64;
  let mut last = start;
  for k in 1..120u64 {
    let tick = start + Duration::from_millis(k * 5);
    last = tick;
    if k % 6 == 0 {
      b.write_framed(tick, hb, StreamClass::Control, &pre_auth_keepalive(nonce));
      nonce += 1;
    }
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_connected().is_some() {}
    while a.take_stream_ready().is_some() {}
    while a.take_lost().is_some() {}
    a.ingest_recv(tick, ha);
    // The Bulk recv id is adopted but its bytes stay unread (the pre-auth skip).
    if a.test_recv_id(ha, StreamClass::Bulk).is_some() {
      // Give a few more ticks for the Bulk STREAM frame to actually arrive + buffer, then stop.
      if k >= 20 {
        break;
      }
    }
    assert!(
      a.is_authenticating(ha),
      "A stays Authenticating while buffering (k={k})"
    );
  }
  assert!(
    a.test_recv_id(ha, StreamClass::Bulk).is_some(),
    "A adopted B's Bulk recv stream while Authenticating"
  );
  assert_eq!(
    a.test_ready_len(ha, StreamClass::Bulk) + a.test_partial_len(ha, StreamClass::Bulk),
    0,
    "the Bulk bytes are buffered in quinn (backpressured), NOT in A's decoder, pre-validation"
  );

  // STOP all ferrying. From here NO new datagram reaches A — the only thing that may drive a Bulk read
  // is the post-validation schedule `bind_validated` installs.
  let now = last + Duration::from_millis(5);
  // Drain any stale coordinator-facing signals so `stream_ready` starts empty for the assertion.
  while a.take_stream_ready().is_some() {}
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  assert!(a.is_validated(ha), "A validated B");

  // THE SCHEDULE: `bind_validated` enqueued `ha` on `stream_ready`, so `poll_timeout` reports the
  // immediate deadline (has_pending_work) — a `poll_timeout`-driven driver re-pumps at once.
  assert!(
    a.stream_ready.iter().any(|&h| h == ha),
    "bind_validated schedules a post-validation read of ha on stream_ready"
  );
  let immediate = a.poll_timeout();
  assert!(
    immediate.is_some_and(|t| t <= Instant::now()),
    "the scheduled read makes poll_timeout immediate (has_pending_work covers it)"
  );

  // Drive ONLY the stream_ready drain (what a re-pump does) — NO datagrams ferried. The buffered Bulk
  // must be read and surfaced now.
  let mut delivered: Option<Message> = None;
  while let Some(h) = a.take_stream_ready() {
    a.ingest_recv(now, h);
  }
  while a.next_frame(ha, StreamClass::Control).is_some() {}
  if let Some(payload) = a.next_frame(ha, StreamClass::Bulk) {
    delivered = decode_message(Bytes::from(payload)).ok();
  }
  assert_eq!(
    delivered,
    Some(bulk_msg),
    "the buffered pre-auth Bulk frame is delivered immediately after validation with NO new traffic"
  );
}

/// Two Bulk-class peer-opened streams ADOPTED while `Authenticating` (the peer reset its Bulk send and
/// reopened it at a higher index before this side validated) must RETIRE-on-replace exactly like the
/// post-auth path: the OLD recv id is closed via `retire_peer_recv` (its recv half `stop`ped, its
/// unused send half `finish`ed) BEFORE the new id overwrites it. Without the retire the old recv stream
/// is orphaned — unreachable, its per-stream window pinned, and never leaving quinn's remote-stream
/// accounting (so the peer never re-grants `MAX_STREAMS`) — a leak that compounds per pre-auth Bulk
/// replacement. Only the new id's BYTES stay unread (the pre-auth skip); the dead old id is reclaimed.
///
/// Harness: A is Authenticating. B opens a first extra bidi stream (adopted by A as Bulk recv id #1),
/// A ingests; B RESETS it and opens a second extra bidi stream at a higher index (adopted as Bulk recv
/// id #2), A ingests again. The recv id must have advanced to #2, and probing id #1 must show it is no
/// longer a live unstopped recv (it was retired, not orphaned).
///
/// NEUTER CHECK (don't retire pre-auth): restore the `if authenticating && class.is_bulk()` early
/// `continue` that only tracks the newest id, and id #1 stays a LIVE unstopped local-recv (orphaned) —
/// the leak this guards.
#[test]
fn pre_auth_replaced_bulk_recv_stream_is_retired_not_orphaned() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);

  assert!(a.is_authenticating(ha), "A stays Authenticating throughout");
  // B opens its real class send streams (Control index 0, Bulk index 1) so the EXTRA streams below land
  // at higher indices that A's `class_of_index` maps to Bulk.
  b.open_send_and_preface(start, hb, &[]);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();

  // B opens the FIRST extra bidi stream; ferry + ingest so A adopts it as a Bulk recv id.
  b.test_open_extra_bidi_stream(hb, b"bulk-1");
  let mut first_id = None;
  for k in 1..60u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    if let Some(id) = a.test_recv_id(ha, StreamClass::Bulk) {
      first_id = Some(id);
      break;
    }
  }
  let first_id = first_id.expect("A adopts B's first extra bidi stream as a Bulk recv id");

  // B RESETS the first extra stream and opens a SECOND at a higher index; ferry + ingest so A adopts the
  // replacement. The accept loop must retire `first_id` on replace.
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e.conn.send_stream(first_id).reset(VarInt::from_u32(7));
  }
  b.test_open_extra_bidi_stream(hb, b"bulk-2");
  let mut second_id = None;
  for k in 60..160u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    if let Some(id) = a.test_recv_id(ha, StreamClass::Bulk)
      && id != first_id
    {
      second_id = Some(id);
      break;
    }
  }
  let second_id = second_id.expect("A adopts B's second extra bidi stream, replacing the first");
  assert_ne!(
    first_id, second_id,
    "the Bulk recv id advanced to the reopened (higher-index) stream"
  );
  // THE FIX: the replaced first recv id was RETIRED (its recv half stopped), not orphaned — probing it
  // shows it is no longer a live unstopped local recv. (Neutered: it would still be live → count 1.)
  assert_eq!(
    a.test_live_unstopped_local_recv_count(ha, &[first_id]),
    0,
    "the replaced pre-auth Bulk recv stream is retired (stopped), not left orphaned"
  );
  assert!(
    a.is_authenticating(ha),
    "A never validated — the retire-on-replace ran purely in the Authenticating phase"
  );
}

/// A peer-side reset of OUR Control RECV stream must REAP the whole connection (the I9 mirror of the
/// Control SEND fatals), NOT per-class-reset it. Control is index-0-fixed, so a per-class reset would
/// retire the recv and wait for a re-`Opened` Control stream — but the peer can only reopen at a HIGHER
/// index, which `class_of_index` maps to Bulk, so the Control recv could NEVER be re-established and the
/// connection would wedge: still `Validated`/routed but unable to deliver any future Control (consensus)
/// frame. The fix routes a Control recv-RESET through `close_local`: the connection goes `Closed`, is
/// queued on `lost`, and its `by_peer` routing is cleared — recovered to a sibling if one exists, else
/// emptied — so a redial reopens Control at index 0.
///
/// Driven over the real datagram path: A and B validate; B writes a Control frame so A ADOPTS B's
/// Control send as its Control recv id; B then RESETS that stream; A `ingest_recv`s the RESET. Asserted
/// for BOTH layouts. Under `Single` Control is the only stream, so the reap is the only correct outcome.
///
/// NEUTER CHECK: drop the `class == Control` branch in `ingest_recv`'s reset arm (revert to the generic
/// per-class reset for Control too) and A stays `Validated` with `handle_for(peer_b) == Some(ha)` but a
/// `None` Control recv id — the bound-but-Control-dead wedge this guards.
fn peer_control_recv_reset_reaps_the_connection(layout: StreamLayout) {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Both validate so consensus frames flow and `ingest_recv` runs the read path (not the pre-auth skip).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);
  assert_eq!(
    a.handle_for(peer_b),
    Some(ha),
    "A routes peer B to this connection while it is Validated"
  );

  // B writes a Control frame so A ADOPTS B's Control send stream (index 0) as its Control recv id — the
  // reset below must land on an ADOPTED Control recv, the wedge scenario. Ferry until A has the recv id
  // AND decoded the frame.
  b.write_framed(now, hb, StreamClass::Control, &commit(0x55));
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut adopted = false;
  for k in 1..120u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    while a.next_frame(ha, StreamClass::Control).is_some() {}
    if a.test_recv_id(ha, StreamClass::Control).is_some() {
      adopted = true;
      break;
    }
  }
  assert!(
    adopted,
    "A must adopt B's Control send stream as its Control recv id before the reset"
  );

  // B RESETS its Control send stream (= A's Control recv). Find B's Control send id and reset it.
  let b_control_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Control).send)
    .expect("B opened a Control send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e
      .conn
      .send_stream(b_control_send)
      .reset(VarInt::from_u32(7));
  }

  // Ferry + A.ingest_recv: A reads the Control RESET and must REAP the connection.
  let mut reaped = false;
  for k in 120..260u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    if a.table.entry(ha).is_some_and(|e| e.phase.is_closed()) {
      reaped = true;
      break;
    }
  }
  assert!(
    reaped,
    "a peer-side Control RECV reset must REAP the connection (close_local → Closed), not leave it \
     Validated with a dead Control recv"
  );
  // Routing is cleared (single connection, no sibling to recover to) — the wedge's tell-tale
  // `handle_for(peer_b) == Some(ha)` must be gone.
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted (its by_peer slot cleared on close_local)"
  );
  // The reaped handle was queued on `lost` for the coordinator's redial pass.
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(
    saw_lost,
    "the reaped connection is queued on `lost` so the coordinator redials"
  );
}

#[test]
fn peer_control_recv_reset_reaps_the_connection_control_bulk() {
  peer_control_recv_reset_reaps_the_connection(StreamLayout::ControlBulk);
}

#[test]
fn peer_control_recv_reset_reaps_the_connection_single() {
  peer_control_recv_reset_reaps_the_connection(StreamLayout::Single);
}

/// The Bulk counterpart of the Control recv-RESET reap: a peer-side reset of OUR Bulk RECV stream must
/// NOT reap the connection — it resets just that class in place (recv id dropped, decoder reset), and the
/// connection stays `Validated`/routed with Control intact. This is the OTHER half of the I9 class
/// split: Control reaps, Bulk resets. (`ControlBulk` only — `Single` has no Bulk class.)
#[test]
fn peer_bulk_recv_reset_resets_in_place_not_reaped() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // B writes a Bulk frame so A adopts B's Bulk send (index 1) as its Bulk recv id.
  b.write_framed(now, hb, StreamClass::Bulk, &commit(0x66));
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut bulk_recv = None;
  for k in 1..120u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    while a.next_frame(ha, StreamClass::Bulk).is_some() {}
    if let Some(id) = a.test_recv_id(ha, StreamClass::Bulk) {
      bulk_recv = Some(id);
      break;
    }
  }
  assert!(
    bulk_recv.is_some(),
    "A adopts B's Bulk send as its Bulk recv"
  );

  // B RESETS its Bulk send stream (= A's Bulk recv).
  let b_bulk_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Bulk).send)
    .expect("B opened a Bulk send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e.conn.send_stream(b_bulk_send).reset(VarInt::from_u32(7));
  }

  // Ferry + A.ingest_recv: A reads the Bulk RESET. The connection must STAY alive (Bulk resets in place).
  for k in 120..220u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
  }
  assert!(
    a.is_validated(ha),
    "a peer-side Bulk RECV reset must NOT close the connection (Bulk resets in place)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    Some(ha),
    "the connection stays routed after a Bulk recv reset"
  );
}

/// The FIN twin of the Control recv-RESET reap: a peer that GRACEFULLY FINISHES its Control send half
/// (an ordinary `finish()`/FIN, not a reset) must REAP the connection, NOT be consumed as a plain EOF.
/// quinn surfaces a consumed final offset as `Chunks::next() == Ok(None)`, distinct from
/// `Err(Blocked)` (would-block). Before the consolidation that `Ok(None)` `break`ed like a would-block,
/// leaving the connection `Validated`/routed with `recv = Some(..)` but a Control recv that can never
/// re-deliver — the same wedge as the reset, reached via FIN. Now FIN flows the SAME class-split as
/// RESET: Control reaps. Asserted for BOTH layouts (under `Single` Control is the only stream, so the
/// reap is the sole correct outcome).
///
/// Here B's frame is consumed BEFORE the FIN, so `scratch` is empty when the FIN is read — this isolates
/// the reap itself (its delivery-of-pre-FIN-frames twin is
/// `peer_control_recv_fin_delivers_frames_before_reaping`). The reap is DEFERRED: a graceful FIN returns
/// `false` from `ingest_recv` and queues the close on `pending_fin_close`, which the coordinator drains
/// AFTER the frame drain. The test replays that order and keys the reap on the deferred
/// `finish_fin_close`, inside a window far shorter than the 1 s idle timeout — NOT on a bare
/// `is_closed()`, which a later idle reap would also satisfy. Until the FIN is read, A must stay
/// `Validated`/routed (no idle teardown got there first).
///
/// NEUTER CHECK: revert the read loop's `Ok(None) => { fault = RecvFault::Graceful; break; }` to
/// `Ok(None) => break` (treat a consumed FIN as a would-block again) and the FIN never queues a deferred
/// close, so within the prompt window A stays `Validated` with `handle_for(peer_b) == Some(ha)` and a
/// still-`Some` Control recv id — the bound-but-Control-dead wedge this guards.
fn peer_control_recv_fin_reaps_the_connection(layout: StreamLayout) {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Both validate so consensus frames flow and `ingest_recv` runs the read path (not the pre-auth skip).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);
  assert_eq!(
    a.handle_for(peer_b),
    Some(ha),
    "A routes peer B to this connection while it is Validated"
  );

  // B writes a Control frame so A ADOPTS B's Control send stream (index 0) as its Control recv id — the
  // FIN below must land on an ADOPTED Control recv, the wedge scenario. Ferry until A has the recv id
  // AND decoded the frame.
  b.write_framed(now, hb, StreamClass::Control, &commit(0x55));
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut adopted = false;
  for k in 1..120u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    while a.next_frame(ha, StreamClass::Control).is_some() {}
    if a.test_recv_id(ha, StreamClass::Control).is_some() {
      adopted = true;
      break;
    }
  }
  assert!(
    adopted,
    "A must adopt B's Control send stream as its Control recv id before the FIN"
  );

  // B gracefully FINISHES its Control send stream (= A's Control recv): an empty-FIN, NOT a reset. Find
  // B's Control send id and `finish` it.
  let b_control_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Control).send)
    .expect("B opened a Control send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e.conn.send_stream(b_control_send).finish();
  }

  // Ferry, then drive `ingest_recv` ONLY for a handle quinn actually signaled readable — exactly as
  // the coordinator's `drain_bridge` does via `take_ready_unique`. The FIN arrives as ONE STREAM frame
  // (one `Readable`); a build that treats a consumed FIN as a plain would-block reads it on that single
  // ingest, frees the recv, and is NEVER re-signaled (a finished stream raises no further `Readable`) —
  // leaving the connection `Validated` with a dead Control recv. The window is far inside the 1 s idle
  // timeout (≈200 ticks), so an idle reap cannot be the cause either.
  //
  // The reap is DEFERRED: a graceful Control FIN decodes any pre-FIN bytes + DELIVERS them first, so
  // `ingest_recv` returns `false` and queues the close on `pending_fin_close`; the coordinator then
  // drains that queue (after the frame drain) to reap. Here `scratch` is empty (B's frame was consumed
  // before the FIN), so this asserts the FIN STILL reaps — via the deferred queue, not the `ingest_recv`
  // return. Replaying `drain_bridge`'s order: ingest, drain frames, `finish_fin_close`.
  const PROMPT_TICKS: u64 = 40;
  let mut reaped = false;
  for k in 120..120 + PROMPT_TICKS {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    for h in a.take_ready_unique() {
      // A graceful FIN no longer reaps INLINE; it returns false and defers the close.
      assert!(
        !a.ingest_recv(tick, h),
        "a graceful Control FIN defers its reap (ingest_recv returns false), it does not reap inline"
      );
      while a.next_frame(h, StreamClass::Control).is_some() {}
      while let Some((hh, cls, disp)) = a.take_pending_fin_close() {
        a.finish_fin_close(tick, hh, cls, disp);
        if hh == ha {
          reaped = true;
        }
      }
    }
    if reaped {
      break;
    }
    // Before the FIN is read, A is a healthy routed `Validated` connection — no idle/auth teardown beat
    // the FIN to it (that is what makes the reap below attributable to the FIN, not a timeout).
    assert!(
      a.is_validated(ha) && a.handle_for(peer_b) == Some(ha),
      "A stays Validated and routed until it reads the Control FIN (no idle teardown first), k={k}"
    );
  }
  assert!(
    reaped,
    "a peer-side Control RECV FIN must PROMPTLY REAP the connection (via the deferred \
     pending_fin_close → close_local), not be consumed as a plain EOF that leaves it Validated with a \
     dead Control recv"
  );
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "the FIN reap put the connection in Closed"
  );
  // Routing is cleared (single connection, no sibling to recover to) — the wedge's tell-tale
  // `handle_for(peer_b) == Some(ha)` must be gone.
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted (its by_peer slot cleared on close_local)"
  );
  // The reaped handle was queued on `lost` for the coordinator's redial pass.
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(
    saw_lost,
    "the reaped connection is queued on `lost` so the coordinator redials"
  );
}

#[test]
fn peer_control_recv_fin_reaps_the_connection_control_bulk() {
  peer_control_recv_fin_reaps_the_connection(StreamLayout::ControlBulk);
}

#[test]
fn peer_control_recv_fin_reaps_the_connection_single() {
  peer_control_recv_fin_reaps_the_connection(StreamLayout::Single);
}

/// The Bulk counterpart of the Control recv-FIN reap (and the FIN twin of the Bulk recv-RESET case): a
/// peer that gracefully FINISHES its Bulk send half must NOT reap the connection — Bulk retires in
/// place (recv id dropped, decoder reset) and the connection stays `Validated`/routed with Control
/// intact. The OTHER half of the consolidated I9 class split: Control reaps, Bulk retires — for EVERY
/// fatal recv variant alike. (`ControlBulk` only — `Single` has no Bulk class.)
#[test]
fn peer_bulk_recv_fin_resets_in_place_not_reaped() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // B writes a Bulk frame so A adopts B's Bulk send (index 1) as its Bulk recv id.
  b.write_framed(now, hb, StreamClass::Bulk, &commit(0x66));
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut bulk_recv = None;
  for k in 1..120u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
    while a.next_frame(ha, StreamClass::Bulk).is_some() {}
    if let Some(id) = a.test_recv_id(ha, StreamClass::Bulk) {
      bulk_recv = Some(id);
      break;
    }
  }
  assert!(
    bulk_recv.is_some(),
    "A adopts B's Bulk send as its Bulk recv"
  );

  // B gracefully FINISHES its Bulk send stream (= A's Bulk recv): an empty-FIN, NOT a reset.
  let b_bulk_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Bulk).send)
    .expect("B opened a Bulk send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e.conn.send_stream(b_bulk_send).finish();
  }

  // Ferry + A.ingest_recv: A reads the Bulk FIN. The connection must STAY alive (Bulk retires in place).
  for k in 120..220u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    while a.take_stream_ready().is_some() {}
    a.ingest_recv(tick, ha);
  }
  assert!(
    a.is_validated(ha),
    "a peer-side Bulk RECV FIN must NOT close the connection (Bulk retires in place)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    Some(ha),
    "the connection stays routed after a Bulk recv FIN"
  );
  // The Bulk recv id is dropped (the finished stream is retired); a fresh Bulk stream reopens at a
  // higher index on the peer's next write.
  assert_eq!(
    a.test_recv_id(ha, StreamClass::Bulk),
    None,
    "the finished Bulk recv is retired in place, its recv id cleared"
  );
}

/// The auth-deadline biconditional (I7) holds after EVERY lifecycle transition: `auth_deadline` is
/// `Some` exactly while a connection is `Authenticating`. This drives a connection through each
/// transition and checks the biconditional from the outside, complementing the in-line
/// `debug_assert!`s at the mutation sites — so a regression that desynced the field from the phase is
/// caught even in a release-style assertion-free build of this test's logic.
#[test]
fn auth_deadline_is_present_exactly_while_authenticating() {
  // Reads the biconditional for handle `h` on bridge `x`: deadline-present IFF Authenticating.
  fn biconditional_holds(x: &mut Bridge, h: ConnectionHandle) -> bool {
    x.table
      .entry(h)
      .is_some_and(|e| e.auth_deadline.is_some() == e.is_authenticating())
  }

  let Linked {
    mut a,
    mut b,
    ha,
    hb,
    now,
    ..
  } = connect_two_bridges(StreamLayout::Single);
  let peer_b = Peer::Replica(ReplicaId::new(1));

  // ENTER Authenticating: the handshake left both sides `Authenticating`, so the deadline is present.
  assert!(
    a.is_authenticating(ha) && a.table.entry(ha).and_then(|e| e.auth_deadline).is_some(),
    "after the handshake the connection is Authenticating WITH a deadline"
  );
  assert!(
    biconditional_holds(&mut a, ha),
    "I7 after entering Authenticating"
  );
  assert!(
    biconditional_holds(&mut b, hb),
    "I7 after entering Authenticating (B)"
  );

  // EXIT to Validated: validating clears the deadline.
  a.bind_validated(now, ha, peer_b);
  assert!(
    a.is_validated(ha) && a.table.entry(ha).and_then(|e| e.auth_deadline).is_none(),
    "a Validated connection carries no deadline"
  );
  assert!(
    biconditional_holds(&mut a, ha),
    "I7 after exiting to Validated"
  );

  // EXIT to Closed (local fatal): closing B's still-Authenticating connection clears its deadline.
  b.close_local(now, hb, CloseCause::PeerClosed);
  assert!(
    b.table.entry(hb).is_some_and(|e| e.phase.is_closed())
      && b.table.entry(hb).and_then(|e| e.auth_deadline).is_none(),
    "a Closed connection carries no deadline"
  );
  assert!(
    biconditional_holds(&mut b, hb),
    "I7 after exiting to Closed"
  );
}

/// A complete Control frame that arrives in the SAME readable event as a graceful FIN — `[frame][FIN]`
/// — MUST be delivered to the consensus (`next_frame`) layer BEFORE the FIN reaps the connection. The
/// hazard: treating the FIN like a RESET — discarding `scratch` before reaping — drops a vote/commit the
/// peer wrote immediately before finishing its send half. A graceful FIN instead DECODES `scratch` and
/// DEFERS the reap (via `pending_fin_close`) so the queued frame is popped first; only an ABANDONED close
/// (RESET / closed) discards (the peer threw those bytes away).
///
/// The test faithfully replays what the coordinator's `drain_bridge` does in order: `ingest_recv`,
/// then drain `next_frame`, then `take_pending_fin_close` + `finish_fin_close`. The NEUTER is in-test: a
/// FIN-as-RESET discard would leave the decoder EMPTY after `ingest_recv` (asserted: the frame is
/// present) and would have reaped INLINE (asserted: `ingest_recv` returned `false` and the reap is
/// DEFERRED).
fn peer_control_recv_fin_delivers_frames_before_reaping(layout: StreamLayout) {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Both validate so consensus frames flow and `ingest_recv` runs the read path (not the pre-auth skip).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // B writes ONE Control frame, then IMMEDIATELY finishes its Control send half — WITHOUT letting A
  // read in between. So the frame bytes AND the FIN are both in flight before A's first read: A's
  // single `ingest_recv` adopts the stream (accept loop) and reads `[frame][FIN]` in ONE cursor — the
  // exact scenario the finding describes. (Contrast `peer_control_recv_fin_reaps_the_connection`, which
  // ferries the frame to A FIRST so it is consumed in a SEPARATE read before the FIN.)
  let frame = commit(0xA1);
  b.write_framed(now, hb, StreamClass::Control, &frame);
  let b_control_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Control).send)
    .expect("B opened a Control send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e.conn.send_stream(b_control_send).finish();
  }

  // Ferry datagrams WITHOUT A reading its Control stream, so BOTH the frame bytes and the FIN buffer in
  // A's quinn state before the single read. Draining `stream_ready` each tick keeps the queue bounded;
  // the stream bytes persist in quinn regardless. A is signaled readable on the FIRST STREAM frame, so
  // ferry well past that (the FIN follows the tiny frame within a tick or two) — 60 ticks is far inside
  // the 1 s idle timeout (≈200 ticks). The read happens AFTER this flush, reading `[frame][FIN]` at once.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(
    signaled,
    "A must be signaled readable for the FIN'd Control stream before the read"
  );

  // THE single ingest that reads `[frame][FIN]`: the accept loop adopts the recv id, then the read loop
  // accumulates the frame into `scratch`, sees the FIN (`Ok(None)` → `Graceful`), DECODES `scratch`
  // (frame now queued `ready`), and DEFERS the reap. A graceful FIN returns `false` (NOT `true`) so
  // `drain_bridge` does not skip the frame drain.
  let read_tick = now + Duration::from_millis(60 * 5);
  let returned_true = a.ingest_recv(read_tick, ha);
  // The connection is NOT yet reaped — the reap is deferred until after delivery.
  assert!(
    a.is_validated(ha),
    "the connection stays Validated through the FIN ingest (reap is deferred until after delivery)"
  );
  // Deliver the queued frame, exactly as `drain_bridge`'s `next_frame` drain does.
  let delivered = a
    .next_frame(ha, StreamClass::Control)
    .and_then(|payload| decode_message(Bytes::from(payload)).ok());
  // The deferred teardown is queued; running it (as `drain_bridge` does after the frame drain) reaps.
  let mut deferred_close = false;
  if let Some((hh, cls, disp)) = a.take_pending_fin_close() {
    assert_eq!(hh, ha, "the FIN'd handle is queued for the deferred reap");
    assert_eq!(
      cls,
      StreamClass::Control,
      "the FIN was on the Control class"
    );
    assert_eq!(
      disp,
      FinDisposition::Clean,
      "a `[complete frame][FIN]` close framed cleanly (partial_len == 0) — the Clean class-split"
    );
    a.finish_fin_close(read_tick, hh, cls, disp);
    deferred_close = true;
  }

  // DELIVERY-BEFORE-TEARDOWN: the complete Control frame written before the FIN reached the consensus
  // layer (a FIN-as-RESET discard loses it — under the neuter `delivered` is `None`).
  assert_eq!(
    delivered.as_ref(),
    Some(&frame),
    "the Control frame that arrived in the same read as the FIN MUST be delivered before the reap"
  );
  // The reap was DEFERRED, not inline: `ingest_recv` returned `false` (so `drain_bridge` ran the frame
  // drain) and the close came from the `pending_fin_close` queue.
  assert!(
    !returned_true,
    "a graceful Control FIN returns false (deferred reap), so drain_bridge does NOT skip the frame drain"
  );
  assert!(
    deferred_close,
    "the Control FIN reap is driven by the post-delivery pending_fin_close queue"
  );
  // AND THEN the connection is reaped (Control: the dead index-0 recv is unrecoverable in place).
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "after its frames are delivered, the Control-FIN connection is reaped (Closed)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted (its by_peer slot cleared on close_local)"
  );
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(
    saw_lost,
    "the reaped connection is queued on `lost` so the coordinator redials"
  );
}

#[test]
fn peer_control_recv_fin_delivers_frames_before_reaping_control_bulk() {
  peer_control_recv_fin_delivers_frames_before_reaping(StreamLayout::ControlBulk);
}

#[test]
fn peer_control_recv_fin_delivers_frames_before_reaping_single() {
  peer_control_recv_fin_delivers_frames_before_reaping(StreamLayout::Single);
}

/// The Bulk counterpart: a complete Bulk frame that arrives in the SAME readable event as a graceful
/// FIN — `[frame][FIN]` — MUST be delivered before the Bulk stream retires in place. Same edge as the
/// Control case, the OTHER half of the class split: Bulk delivers-then-retires (connection stays
/// `Validated`/routed), where Control delivers-then-reaps. (`ControlBulk` only — `Single` has no Bulk.)
#[test]
fn peer_bulk_recv_fin_delivers_frames_before_retiring() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // B writes ONE Bulk frame, then immediately finishes its Bulk send half — frame + FIN both in flight
  // before A reads, so A's single `ingest_recv` reads `[frame][FIN]` on the Bulk recv in one cursor.
  let frame = commit(0xB2);
  b.write_framed(now, hb, StreamClass::Bulk, &frame);
  let b_bulk_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Bulk).send)
    .expect("B opened a Bulk send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let _ = e.conn.send_stream(b_bulk_send).finish();
  }

  // Flush both the frame and the FIN into A WITHOUT reading the Bulk stream (see the Control twin), then
  // do the single read of `[frame][FIN]`.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(
    signaled,
    "A must be signaled readable for the FIN'd Bulk stream before the read"
  );

  let read_tick = now + Duration::from_millis(60 * 5);
  // A graceful Bulk FIN never reaps the connection, so `ingest_recv` returns `false` and the Bulk
  // decoder holds the pre-FIN frame.
  assert!(
    !a.ingest_recv(read_tick, ha),
    "a Bulk FIN does not reap the connection (returns false)"
  );
  assert!(
    a.is_validated(ha),
    "the connection stays Validated across a Bulk FIN (Bulk retires in place)"
  );
  let delivered = a
    .next_frame(ha, StreamClass::Bulk)
    .and_then(|payload| decode_message(Bytes::from(payload)).ok());
  let mut deferred_retire = false;
  if let Some((hh, cls, disp)) = a.take_pending_fin_close() {
    assert_eq!(
      hh, ha,
      "the FIN'd handle is queued for the deferred Bulk retire"
    );
    assert_eq!(cls, StreamClass::Bulk, "the FIN was on the Bulk class");
    assert_eq!(
      disp,
      FinDisposition::Clean,
      "a `[complete frame][FIN]` Bulk close framed cleanly — Clean retires the stream in place"
    );
    a.finish_fin_close(read_tick, hh, cls, disp);
    deferred_retire = true;
  }

  assert_eq!(
    delivered.as_ref(),
    Some(&frame),
    "the Bulk frame that arrived in the same read as the FIN MUST be delivered before the retire"
  );
  assert!(
    deferred_retire,
    "the Bulk FIN retire is driven by the post-delivery pending_fin_close queue"
  );
  // The connection stays alive and routed; only the Bulk stream retired.
  assert!(
    a.is_validated(ha),
    "a peer-side Bulk FIN must NOT close the connection (Bulk retires in place)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    Some(ha),
    "the connection stays routed after a Bulk recv FIN"
  );
  assert_eq!(
    a.test_recv_id(ha, StreamClass::Bulk),
    None,
    "the finished Bulk recv is retired in place, its recv id cleared"
  );
}

/// How much of a `[u32 len][body]` frame the peer manages to send before it FINs its send half — the
/// two mid-frame truncation shapes a graceful FIN must reject.
#[derive(Clone, Copy)]
enum Truncation {
  /// Only SOME of the 4-byte length prefix (here 2 bytes), then FIN: the decoder cannot even read the
  /// declared length — `partial_len` is a sub-prefix remainder.
  SplitPrefix,
  /// The whole length prefix plus only PART of the declared body, then FIN: the decoder read the
  /// length, copied a partial body, and is mid-frame — `partial_len` is prefix + the partial body.
  PartialBody,
}

/// A graceful FIN that arrives MID-FRAME (the peer finished its send half after writing only part of a
/// `[len][body]` frame) is a TRUNCATION, not a clean close: there is a non-zero `partial_len` left in
/// the decoder with no more bytes ever coming. It must be rejected exactly like an over-`MAX_FRAME_LEN`
/// length (the `FrameTooLong` path) — `close_local` reaps the WHOLE connection (for BOTH classes) and
/// `ingest_recv` returns `true` — NOT routed through the clean-FIN deferred disposition (Control reap /
/// Bulk retire-in-place) that would silently DROP the partial frame.
///
/// This drives the post-validation `extend` decode path (both sides `Validated`) for both truncation
/// shapes (`SplitPrefix`, `PartialBody`) on the named `class`. B opens its class send stream, writes
/// only a PREFIX of one framed message as raw bytes, then `finish`es that send half; A ferries until it
/// is signaled readable, then a single `ingest_recv` reads `[partial-frame][FIN]` in one cursor and must
/// reap.
///
/// NEUTER CHECK: drop the `partial_len != 0` truncation guard in the graceful-FIN branch (fall straight
/// through to the `pending_fin_close` deferral). The truncated partial frame is then silently DROPPED:
/// `ingest_recv` returns `false`, and — decisively for Bulk — `finish_fin_close` retires only the Bulk
/// stream, leaving the connection `Validated` and still routed (`handle_for(peer_b) == Some(ha)`) after
/// losing the final partial message. (For Control the neuter still eventually reaps via the deferred
/// queue, but as a clean close rather than a framing error — the partial frame is dropped with no
/// framing signal; the Bulk arm is the one that wrongly stays Validated, which these assertions pin.)
fn peer_recv_fin_mid_frame_reaps_as_truncation(
  layout: StreamLayout,
  class: StreamClass,
  trunc: Truncation,
) {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Both validate so `ingest_recv` runs the post-validation `extend` decode (not the pre-auth skip),
  // and a Bulk truncation can be told apart from a clean Bulk retire by whether the connection survives.
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // Frame one message, then keep only a mid-frame PREFIX of those bytes: a split length prefix (2 of 4
  // bytes) or the whole prefix plus a partial body. B writes exactly that prefix raw onto its `class`
  // send stream and FINs — so A reads `[partial-frame][FIN]` and the decoder is left mid-frame.
  let mut framed = Vec::new();
  encode_frame(&encode_message(&commit(0x7C)), &mut framed);
  let cut = match trunc {
    Truncation::SplitPrefix => 2,
    // Prefix (4) + a few body bytes, but strictly fewer than the whole frame.
    Truncation::PartialBody => LEN_PREFIX + 3,
  };
  assert!(cut < framed.len(), "the prefix must be a proper truncation");
  let partial = framed[..cut].to_vec();

  let b_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(class).send)
    .expect("B opened the class send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let n = e
      .conn
      .send_stream(b_send)
      .write(&partial)
      .expect("write the partial frame");
    assert_eq!(n, partial.len(), "the whole partial prefix is staged");
    let _ = e.conn.send_stream(b_send).finish();
  }

  // Ferry WITHOUT A reading its `class` stream so both the partial-frame bytes and the FIN buffer in A's
  // quinn state before the single read (the same setup as the deliver-before-close FIN tests). 60 ticks
  // is far inside the 1 s idle timeout, so no idle reap can be the cause.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(
    signaled,
    "A must be signaled readable for the FIN'd {class:?} stream before the read"
  );

  // THE single ingest of `[partial-frame][FIN]`: the read accumulates the partial frame, sees the FIN
  // (`Ok(None)` → `Graceful`), decodes `scratch` (leaving a non-zero `partial_len`), and the truncation
  // guard reaps the connection — returning `true` so the caller stops pulling frames, EXACTLY like a
  // `FrameTooLong`. A clean-FIN disposition would instead return `false` and (for Bulk) retire in place.
  let read_tick = now + Duration::from_millis(60 * 5);
  assert!(
    a.ingest_recv(read_tick, ha),
    "a graceful FIN mid-frame on {class:?} is a truncation: it reaps (returns true) like a framing error"
  );
  // A truncation reaps the WHOLE connection for BOTH classes — it must NOT be the Bulk retire-in-place
  // disposition (which would leave the connection Validated/routed after dropping the partial frame).
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "the truncated-frame connection is reaped (Closed), not left Validated, for {class:?}"
  );
  assert!(
    !a.is_validated(ha),
    "a {class:?} mid-frame FIN truncation tears the whole connection down (NOT a Bulk retire-in-place)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted (its by_peer slot cleared on close_local)"
  );
  // No deferred clean-FIN close was queued — the truncation took the immediate framing-error path.
  assert!(
    a.take_pending_fin_close().is_none(),
    "a truncation reaps inline via close_local, NOT through the deferred pending_fin_close queue"
  );
  // And the partial frame was DROPPED, never surfaced as a (corrupt) complete frame.
  assert!(
    a.next_frame(ha, class).is_none(),
    "the truncated frame is never delivered as a complete frame"
  );
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(
    saw_lost,
    "the reaped connection is queued on `lost` so the coordinator redials"
  );
}

#[test]
fn peer_control_recv_fin_split_prefix_reaps_as_truncation_control_bulk() {
  peer_recv_fin_mid_frame_reaps_as_truncation(
    StreamLayout::ControlBulk,
    StreamClass::Control,
    Truncation::SplitPrefix,
  );
}

#[test]
fn peer_control_recv_fin_split_prefix_reaps_as_truncation_single() {
  peer_recv_fin_mid_frame_reaps_as_truncation(
    StreamLayout::Single,
    StreamClass::Control,
    Truncation::SplitPrefix,
  );
}

#[test]
fn peer_control_recv_fin_partial_body_reaps_as_truncation_control_bulk() {
  peer_recv_fin_mid_frame_reaps_as_truncation(
    StreamLayout::ControlBulk,
    StreamClass::Control,
    Truncation::PartialBody,
  );
}

#[test]
fn peer_control_recv_fin_partial_body_reaps_as_truncation_single() {
  peer_recv_fin_mid_frame_reaps_as_truncation(
    StreamLayout::Single,
    StreamClass::Control,
    Truncation::PartialBody,
  );
}

/// Bulk truncations — the case the finding flags as worst: without the guard the connection stays
/// Validated/routed after silently dropping the final partial Bulk frame. (`ControlBulk` only — `Single`
/// has no Bulk class.)
#[test]
fn peer_bulk_recv_fin_split_prefix_reaps_as_truncation() {
  peer_recv_fin_mid_frame_reaps_as_truncation(
    StreamLayout::ControlBulk,
    StreamClass::Bulk,
    Truncation::SplitPrefix,
  );
}

#[test]
fn peer_bulk_recv_fin_partial_body_reaps_as_truncation() {
  peer_recv_fin_mid_frame_reaps_as_truncation(
    StreamLayout::ControlBulk,
    StreamClass::Bulk,
    Truncation::PartialBody,
  );
}

/// A graceful FIN arriving as `[COMPLETE frame][PARTIAL frame][FIN]` post-validation: `extend` queues
/// the complete frame onto `ready` AND leaves a non-zero `partial_len` (the torn frame). The complete
/// frame MUST be delivered to the consensus layer, the torn frame MUST be rejected, and the connection
/// MUST then reap (a truncation tears down the WHOLE connection — both classes — exactly like a framing
/// error). The hazard the one disposition closes: a fault that queued a complete prefix frame returning
/// `true` INLINE makes the coordinator's `drain_bridge` SKIP the `next_frame` drain (`if ingest_recv {
/// continue }`), dropping the complete frame the peer wrote immediately before the torn one. The fix
/// DEFERS every deliver-before-close case (whenever a complete frame is queued) through
/// `pending_fin_close`, recording the `Truncated` disposition so the deferred close reaps the whole
/// connection AFTER delivery — never a bare `return true` that strands the queued frame.
///
/// The test replays `drain_bridge`'s exact order — `ingest_recv` (must DEFER, returning `false`), drain
/// `next_frame` (delivers the complete frame), then `take_pending_fin_close` (must carry `Truncated`)
/// plus `finish_fin_close` (reaps the whole connection). It runs for Control AND Bulk; a truncation
/// reaps the connection for BOTH (the partial frame is never surfaced), so the disposition is a
/// whole-connection teardown, not the Bulk retire-in-place a clean FIN would take.
///
/// NEUTER CHECK: reap a truncation INLINE even when it has queued frames — `if truncated { close_local;
/// return true }` without the `has_ready()` defer. `ingest_recv` then returns `true`, so this test's
/// `delivered_before_close` (which the coordinator only reaches when `ingest_recv` returns `false`) is
/// never pulled and the complete frame is DROPPED — the `returned_false` assert fires first, the
/// delivery assert second.
fn peer_recv_fin_complete_then_partial_delivers_prefix_then_reaps(class: StreamClass) {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  // Both validate so `ingest_recv` runs the post-validation `extend` decode (full cap, both classes).
  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // `[complete frame][prefix of a second frame]` raw onto B's `class` send stream, then FIN — so A reads
  // one COMPLETE frame followed by a TORN frame and the FIN in a single cursor. The complete frame must
  // survive; the torn one must not.
  let complete = commit(0xC0);
  let mut bytes = Vec::new();
  encode_frame(&encode_message(&complete), &mut bytes);
  let mut second = Vec::new();
  encode_frame(&encode_message(&commit(0xD1)), &mut second);
  let torn_cut = LEN_PREFIX + 3;
  assert!(
    torn_cut < second.len(),
    "the second frame must be a proper truncation"
  );
  bytes.extend_from_slice(&second[..torn_cut]);

  let b_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(class).send)
    .expect("B opened the class send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let n = e
      .conn
      .send_stream(b_send)
      .write(&bytes)
      .expect("write the complete + torn bytes");
    assert_eq!(
      n,
      bytes.len(),
      "the whole `[complete][torn]` prefix is staged"
    );
    let _ = e.conn.send_stream(b_send).finish();
  }

  // Ferry WITHOUT A reading its `class` stream so the bytes and the FIN buffer in A's quinn state before
  // the single read. 60 ticks is far inside the 1 s idle timeout.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(
    signaled,
    "A must be signaled readable for the FIN'd {class:?} stream before the read"
  );

  // THE single ingest of `[complete][torn][FIN]`: the complete frame is queued `ready`, the torn frame
  // leaves a non-zero `partial_len`, and the FIN is seen. Because a complete frame is queued, the close
  // is DEFERRED (returns `false`) so `drain_bridge` delivers the complete frame first — NOT an inline
  // truncation reap that would drop it.
  let read_tick = now + Duration::from_millis(60 * 5);
  let returned_true = a.ingest_recv(read_tick, ha);
  assert!(
    !returned_true,
    "a {class:?} FIN behind a COMPLETE frame DEFERS (returns false) so drain_bridge delivers the frame"
  );
  assert!(
    a.is_validated(ha),
    "the connection stays Validated through the deferred-close ingest (reap follows delivery)"
  );

  // Deliver the queued frame, exactly as `drain_bridge`'s `next_frame` drain does.
  let delivered_before_close = a
    .next_frame(ha, class)
    .and_then(|payload| decode_message(Bytes::from(payload)).ok());
  assert_eq!(
    delivered_before_close.as_ref(),
    Some(&complete),
    "the COMPLETE {class:?} frame ahead of the torn one MUST be delivered before the reap (NEUTER: an \
     inline truncation reap drops it)"
  );
  // The torn frame is NOT a complete frame — never surfaced.
  assert!(
    a.next_frame(ha, class).is_none(),
    "the torn {class:?} frame is never delivered as a complete frame"
  );

  // The deferred close carries `Truncated` (a torn frame is a framing failure), so it reaps the WHOLE
  // connection for EITHER class — not the Bulk retire-in-place a clean FIN would take.
  let deferred = a.take_pending_fin_close();
  assert_eq!(
    deferred,
    Some((ha, class, FinDisposition::Truncated)),
    "a torn frame behind a complete one defers a Truncated close (whole-connection reap) for {class:?}"
  );
  if let Some((hh, cls, disp)) = deferred {
    a.finish_fin_close(read_tick, hh, cls, disp);
  }
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "after delivering the complete frame, the truncated-tail connection is reaped (Closed) for {class:?}"
  );
  assert!(
    !a.is_validated(ha),
    "a {class:?} truncation tears the whole connection down (NOT a Bulk retire-in-place)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted for {class:?}"
  );
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(
    saw_lost,
    "the reaped connection is queued on `lost` so the coordinator redials"
  );
}

#[test]
fn peer_control_recv_fin_complete_then_partial_delivers_prefix_then_reaps() {
  peer_recv_fin_complete_then_partial_delivers_prefix_then_reaps(StreamClass::Control);
}

#[test]
fn peer_bulk_recv_fin_complete_then_partial_delivers_prefix_then_reaps() {
  peer_recv_fin_complete_then_partial_delivers_prefix_then_reaps(StreamClass::Bulk);
}

/// A FRAMING ERROR (`FrameTooLong`) that lands BEHIND a complete frame: A reads `[complete frame][len
/// prefix declaring > MAX_FRAME_LEN]` in one pass (NO FIN — a pure mid-stream framing violation). `extend`
/// queues the complete frame onto `ready`, then rejects the over-cap prefix. The complete frame MUST
/// still be delivered before the connection reaps — the SAME deliver-before-close rule the graceful-FIN
/// path uses, applied to the framing-error path. The hazard the one disposition closes: the framing
/// branch returning `true` INLINE makes `drain_bridge` skip the `next_frame` drain, dropping the queued
/// frame. The fix DEFERS (`Truncated`) when `has_ready()`, delivering the prefix, then reaps the whole
/// connection.
///
/// NEUTER CHECK: restore the framing branch's bare `self.close_local(now, h, CloseCause::PeerClosed); return true;` (no
/// `has_ready()` defer). `ingest_recv` returns `true`, so the complete prefix frame is never pulled —
/// the `returned_false` assert fires, then the delivery assert.
#[test]
fn peer_control_recv_frame_too_long_behind_complete_frame_delivers_prefix_then_reaps() {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let peer_a = Peer::Replica(ReplicaId::new(0));
  let now = start + Duration::from_millis(5);

  a.open_send_and_preface(now, ha, &[]);
  a.bind_validated(now, ha, peer_b);
  b.open_send_and_preface(now, hb, &[]);
  b.bind_validated(now, hb, peer_a);

  // `[complete frame][4-byte length prefix declaring MAX_FRAME_LEN + 1]`. `extend` rejects an over-cap
  // declared length on the prefix ALONE (before any body), so no body bytes are needed — the bare
  // oversized prefix trips `FrameTooLong` after the complete frame is already queued.
  let complete = commit(0xE2);
  let mut bytes = Vec::new();
  encode_frame(&encode_message(&complete), &mut bytes);
  bytes.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());

  let b_send = b
    .table
    .entry(hb)
    .and_then(|e| e.class_mut(StreamClass::Control).send)
    .expect("B opened a Control send stream");
  {
    let e = b.table.entry(hb).expect("B entry");
    let n = e
      .conn
      .send_stream(b_send)
      .write(&bytes)
      .expect("write the complete frame + oversized prefix");
    assert_eq!(
      n,
      bytes.len(),
      "the whole `[complete][oversized prefix]` is staged"
    );
    // No `finish` — this is a mid-stream framing violation, not a graceful FIN.
  }

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = now + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(signaled, "A must be signaled readable before the read");

  // The single ingest: `extend` queues the complete frame, then errors on the oversized prefix. Because
  // a complete frame is queued, the framing-error close is DEFERRED (returns `false`) so the frame is
  // delivered first.
  let read_tick = now + Duration::from_millis(60 * 5);
  let returned_true = a.ingest_recv(read_tick, ha);
  assert!(
    !returned_true,
    "a FrameTooLong behind a COMPLETE frame DEFERS (returns false) so drain_bridge delivers the frame"
  );
  let delivered_before_close = a
    .next_frame(ha, StreamClass::Control)
    .and_then(|payload| decode_message(Bytes::from(payload)).ok());
  assert_eq!(
    delivered_before_close.as_ref(),
    Some(&complete),
    "the COMPLETE frame ahead of the oversized prefix MUST be delivered before the reap (NEUTER: an \
     inline framing-error reap drops it)"
  );

  let deferred = a.take_pending_fin_close();
  assert_eq!(
    deferred,
    Some((ha, StreamClass::Control, FinDisposition::OverCap)),
    "an over-cap declared length behind a complete frame defers an OverCap (whole-connection) reap"
  );
  if let Some((hh, cls, disp)) = deferred {
    a.finish_fin_close(read_tick, hh, cls, disp);
  }
  // The deferred over-cap reap is attributed to FrameTooLong — the protocol violation — not to
  // TruncatedFrame (a torn FIN), keeping the two fatal framing causes distinguishable in the
  // per-cause counters on the DEFERRED path exactly as on the inline one.
  assert_eq!(
    a.conn_close_count(CloseCause::FrameTooLong),
    1,
    "the deferred over-cap reap counts as FrameTooLong"
  );
  assert_eq!(
    a.conn_close_count(CloseCause::TruncatedFrame),
    0,
    "the deferred over-cap reap is not attributed to truncation"
  );
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "after delivering the complete frame, the framing-error connection is reaped (Closed)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted"
  );
}

/// The deferred-FIN queue's per-connection disposition PRECEDENCE: a whole-connection fatal
/// supersedes a queued `Clean` for the same handle, regardless of arrival order. FAIL-BEFORE
/// (FIFO application): a Control `[complete frame][FIN]` queues `Clean` first; a Bulk over-cap
/// prefix in the same pump then queues `OverCap` BEHIND it — the drain applied `Clean` first,
/// `close_fault_class` marked the connection `Closed` under `PeerClosed`, and the later fatal's
/// `close_local` was an idempotent no-op that never counted, leaving a real over-cap inbound frame
/// outside the `FrameTooLong` counter.
#[test]
fn a_deferred_fatal_disposition_supersedes_a_queued_clean_fin() {
  let Linked {
    mut a,
    b: _b,
    ha,
    now,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);

  // The cross-class same-pump order the FIFO bug needs: the Control clean FIN is recorded first,
  // the Bulk over-cap fatal second (both route through the producer choke).
  a.push_fin_close(ha, StreamClass::Control, FinDisposition::Clean);
  a.push_fin_close(ha, StreamClass::Bulk, FinDisposition::OverCap);
  // The fatal PURGED the queued Clean: exactly one disposition remains for the handle.
  let first = a.take_pending_fin_close();
  assert_eq!(
    first,
    Some((ha, StreamClass::Bulk, FinDisposition::OverCap)),
    "the fatal supersedes the earlier-queued Clean for the same connection"
  );
  assert_eq!(
    a.take_pending_fin_close(),
    None,
    "no second disposition survives for the handle"
  );
  // A Clean arriving AFTER the fatal was applied-or-queued is likewise inert: re-queue the fatal,
  // then push a late Clean — the fatal still wins.
  a.push_fin_close(ha, StreamClass::Bulk, FinDisposition::OverCap);
  a.push_fin_close(ha, StreamClass::Control, FinDisposition::Clean);
  assert_eq!(
    a.take_pending_fin_close(),
    Some((ha, StreamClass::Bulk, FinDisposition::OverCap)),
    "a Clean queued after a fatal is skipped (the fatal wins in either order)"
  );
  assert_eq!(a.take_pending_fin_close(), None);
  // A queued OverCap outranks an incoming Truncated (the over-cap rejection is the dominant fact).
  a.push_fin_close(ha, StreamClass::Control, FinDisposition::OverCap);
  a.push_fin_close(ha, StreamClass::Control, FinDisposition::Truncated);
  assert_eq!(
    a.take_pending_fin_close(),
    Some((ha, StreamClass::Control, FinDisposition::OverCap)),
    "an incoming Truncated does not demote a queued OverCap"
  );
  assert_eq!(a.take_pending_fin_close(), None);
  // Applying the surviving fatal counts FrameTooLong — never PeerClosed — closing the loop on the
  // accounting the precedence exists for.
  let (hh, cls, disp) = first.expect("asserted Some above");
  a.finish_fin_close(now, hh, cls, disp);
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "the surviving fatal reaps the whole connection"
  );
  assert_eq!(
    a.conn_close_count(CloseCause::FrameTooLong),
    1,
    "the over-cap fatal is counted as FrameTooLong despite the earlier clean FIN"
  );
  assert_eq!(
    a.conn_close_count(CloseCause::PeerClosed),
    0,
    "the superseded Clean never attributes a clean peer close"
  );
}

/// Open B's first stream (A's Control), write `payload`, and `finish` (FIN) the send half — the
/// pre-auth `[…][FIN]` setup. Returns the stream id. Modeled on
/// [`Bridge::test_open_write_first_stream`] (it `finish`es), but on connection `hb` (B's handle) so
/// the FIN lands on A's index-0 Control stream while A is still `Authenticating`.
fn b_open_write_first_stream_finished(
  b: &mut Bridge,
  hb: ConnectionHandle,
  payload: &[u8],
) -> StreamId {
  let e = b.table.entry(hb).expect("B entry");
  let sid = e
    .conn
    .streams()
    .open(Dir::Bi)
    .expect("a bidi stream slot is available");
  e.class_mut(StreamClass::Control).send = Some(sid);
  let n = e
    .conn
    .send_stream(sid)
    .write(payload)
    .expect("write to fresh stream");
  assert_eq!(
    n,
    payload.len(),
    "the whole payload fits in the send window"
  );
  e.conn
    .send_stream(sid)
    .finish()
    .expect("finish the send half");
  sid
}

/// A peer that already validated US pipelines a COMPLETE consensus Control frame directly behind its
/// hello and then gracefully FINs its Control send half, so A reads `[hello][complete pipelined
/// frame][FIN]` in ONE pre-auth read pass (the connection is still `Authenticating`, so `ingest_recv`
/// decodes via `extend_first` under the small hello cap and leaves the larger pipelined frame buffered
/// RAW). NOTHING is truncated: the pipelined frame is whole. The connection MUST validate, BOTH the
/// hello and the pipelined frame must be delivered, and ONLY THEN the graceful FIN reaps the
/// connection — never a false truncation that drops the valid frame.
///
/// The hazard: treating ANY `partial_len != 0` after a graceful FIN as a truncated frame reaps a VALID
/// connection here — pre-auth that partial is the intentionally-retained pipelined tail, not a torn
/// frame — returning `true` (skipping the coordinator's frame drain) and dropping the hello AND the
/// pipelined frame. The truncation oracle is therefore gated on the decoder being drained at its FINAL
/// cap: pre-auth, a non-zero partial with a COMPLETE first frame (the hello) is the buffered tail, so
/// the FIN is DEFERRED; `bind_validated` raises the cap and drains the tail's complete frames onto
/// `ready` for delivery before the deferred reap.
///
/// The test replays `drain_bridge`'s exact order: `ingest_recv` (must DEFER, returning `false`),
/// pull the hello, `bind_validated` (stands in for the coordinator authenticating the hello — raises
/// the cap + drains the tail), pull the now-decoded pipelined frame, then
/// `take_pending_fin_close` + `finish_fin_close` (the reap).
///
/// NEUTER: drop the final-cap gate (`let truncated = partial_len != 0;`). `ingest_recv` then returns
/// `true` and reaps on the buffered (COMPLETE) tail — the first defer assert fires (the connection is
/// already Closed and the hello + pipelined frame are gone), the dropped-valid-frame regression.
fn preauth_control_fin_with_complete_tail_validates_then_reaps(layout: StreamLayout) {
  use crate::{ClientId, Prepare, RequestNumber, transport::labeled::MAX_HELLO_LEN};

  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  assert!(
    a.is_authenticating(ha),
    "A starts Authenticating (the pre-auth Control cap is in force)"
  );

  // A stand-in hello (opaque to the bridge, sized within the pre-auth cap) followed by a COMPLETE
  // consensus Control frame well OVER the hello cap but under `MAX_FRAME_LEN` — the legitimate
  // pipeline a peer that already validated us flushes behind its hello.
  let hello_stub = [0xA1u8; 6];
  let pipelined = Message::Prepare(Prepare::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(9),
    RequestNumber::with(1),
    bytes::Bytes::from(vec![0x6Cu8; 1024]),
  ));
  let pipelined_payload = encode_message(&pipelined);
  assert!(
    pipelined_payload.len() > MAX_HELLO_LEN,
    "the pipelined frame must exceed the pre-auth cap to exercise the buffered-tail path"
  );
  let mut buf = Vec::new();
  encode_frame(&hello_stub, &mut buf);
  encode_frame(&pipelined_payload, &mut buf);
  // B writes `[hello][pipelined]` in ONE stream write and FINs — so A reads both frames AND the FIN
  // in one cursor while still Authenticating.
  b_open_write_first_stream_finished(&mut b, hb, &buf);

  // Ferry WITHOUT A reading its Control stream so the frames and the FIN buffer in A's quinn state
  // before the single read. 60 ticks is far inside the 1 s idle timeout.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(
    signaled,
    "A must be signaled readable for the FIN'd Control stream before the read"
  );

  // THE single ingest of `[hello][pipelined][FIN]` while Authenticating. The decoder yields the hello
  // (ready), buffers the pipelined frame RAW (a non-zero `partial_len`), and sees the FIN. Because the
  // FIRST frame COMPLETED, the partial is the buffered tail — NOT a truncation: `ingest_recv` DEFERS
  // (returns `false`) so `drain_bridge` does not skip the frame drain.
  let read_tick = start + Duration::from_millis(60 * 5);
  let returned_true = a.ingest_recv(read_tick, ha);
  assert!(
    !returned_true,
    "a pre-auth graceful FIN behind a COMPLETE hello defers (returns false) — NOT a false truncation reap"
  );
  assert!(
    a.is_authenticating(ha),
    "the connection is still Authenticating after the FIN ingest (the reap is deferred, the hello not yet authenticated)"
  );
  assert!(
    a.test_partial_len(ha, StreamClass::Control) > MAX_HELLO_LEN,
    "the complete pipelined frame is retained un-decoded under the pre-auth cap (not truncated, not dropped)"
  );

  // Pull the hello, exactly as `drain_bridge` does, and validate A — standing in for the coordinator
  // authenticating the hello. `bind_validated` raises the Control cap AND drains the buffered tail's
  // complete frames onto `ready`.
  let hello = a.next_frame(ha, StreamClass::Control);
  assert_eq!(
    hello.as_deref(),
    Some(hello_stub.as_slice()),
    "the hello is delivered before the reap"
  );
  a.bind_validated(read_tick, ha, peer_b);
  assert!(
    a.is_validated(ha),
    "A validates from the pre-auth hello — the connection is NOT torn down"
  );

  // The pipelined consensus frame is now decoded (by `bind_validated`'s cap-raise + tail drain) and
  // delivered — `drain_bridge`'s same-pass `next_frame` loop pops it right after validation.
  let pipelined_got = a
    .next_frame(ha, StreamClass::Control)
    .and_then(|p| decode_message(Bytes::from(p)).ok());
  assert_eq!(
    pipelined_got,
    Some(pipelined),
    "the COMPLETE pipelined frame behind the hello is delivered (never false-reaped, never dropped)"
  );
  assert!(
    a.next_frame(ha, StreamClass::Control).is_none(),
    "no further frames — the tail was exactly the hello + the one pipelined frame"
  );

  // ONLY NOW the deferred graceful-FIN reap runs (Control: the dead index-0 recv is unrecoverable).
  // The hello completed, so the buffered tail is the legitimately-retained pipeline — a `Clean` close,
  // NOT a truncation.
  let deferred = a.take_pending_fin_close();
  assert_eq!(
    deferred,
    Some((ha, StreamClass::Control, FinDisposition::Clean)),
    "the FIN'd handle is queued for the deferred Control reap (delivery-before-teardown), Clean"
  );
  if let Some((hh, cls, disp)) = deferred {
    a.finish_fin_close(read_tick, hh, cls, disp);
  }
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "after the hello AND the pipelined frame are delivered, the pre-auth-FIN connection is reaped (Closed)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted"
  );
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(
    saw_lost,
    "the reaped connection is queued on `lost` so the coordinator redials"
  );
}

#[test]
fn preauth_control_fin_with_complete_tail_validates_then_reaps_control_bulk() {
  preauth_control_fin_with_complete_tail_validates_then_reaps(StreamLayout::ControlBulk);
}

#[test]
fn preauth_control_fin_with_complete_tail_validates_then_reaps_single() {
  preauth_control_fin_with_complete_tail_validates_then_reaps(StreamLayout::Single);
}

/// A pre-auth `[complete hello][PARTIAL tail frame][FIN]`: the hello completes but the pipelined tail
/// is torn (only a prefix of its frame arrived before the FIN). Because the FIRST frame completed,
/// `ingest_recv` still DEFERS (does not truncate-reap pre-auth) — the hello is authenticated and the
/// connection validates; the partial tail, re-evaluated under the raised cap, is NOT a complete frame
/// so it is NEVER delivered (no spurious/corrupt consensus message), and the deferred FIN then reaps
/// the connection. So the disposition is: hello authenticated (the connection validates), the torn
/// tail dropped, the connection reaped — identical to the clean-tail case except no tail frame is
/// delivered. (A pre-auth FIN is always on the index-0 Control class, which reaps whether or not the
/// tail was truncated, so the truncation distinction does not change the outcome here — only that the
/// torn trailing bytes are dropped, which they are.)
fn preauth_control_fin_with_partial_tail_validates_then_reaps(layout: StreamLayout) {
  use crate::{ClientId, Prepare, RequestNumber, transport::labeled::MAX_HELLO_LEN};

  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  assert!(a.is_authenticating(ha), "A starts Authenticating");

  let hello_stub = [0xA1u8; 6];
  let pipelined = Message::Prepare(Prepare::new(
    View::with(1),
    OpNumber::with(1),
    OpNumber::with(0),
    OpNumber::with(0),
    crate::Epoch::new(0),
    0,
    ClientId::new(9),
    RequestNumber::with(1),
    bytes::Bytes::from(vec![0x6Cu8; 1024]),
  ));
  let pipelined_payload = encode_message(&pipelined);
  let mut framed_tail = Vec::new();
  encode_frame(&pipelined_payload, &mut framed_tail);
  // `[hello][PREFIX of the pipelined frame]`: keep the whole hello frame plus only part of the tail
  // frame (its length prefix + some body, strictly fewer than the whole), then FIN.
  let mut buf = Vec::new();
  encode_frame(&hello_stub, &mut buf);
  let tail_cut = LEN_PREFIX + 16;
  assert!(
    tail_cut < framed_tail.len(),
    "the tail prefix must be a proper truncation"
  );
  buf.extend_from_slice(&framed_tail[..tail_cut]);
  b_open_write_first_stream_finished(&mut b, hb, &buf);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(signaled, "A must be signaled readable before the read");

  // The hello completed, so the FIN DEFERS even though the tail is torn (pre-auth never truncate-reaps
  // once the first frame is whole — the disposition is the same Control reap).
  let read_tick = start + Duration::from_millis(60 * 5);
  assert!(
    !a.ingest_recv(read_tick, ha),
    "a pre-auth graceful FIN behind a COMPLETE hello defers, even with a torn tail (returns false)"
  );
  let hello = a.next_frame(ha, StreamClass::Control);
  assert_eq!(
    hello.as_deref(),
    Some(hello_stub.as_slice()),
    "the hello is delivered"
  );
  a.bind_validated(read_tick, ha, peer_b);
  assert!(
    a.is_validated(ha),
    "A validates from the pre-auth hello (the torn tail does not block validation)"
  );
  // The torn tail is NOT a complete frame under the raised cap — it is never delivered (its prefix
  // remains buffered, dropped at the reap), so no corrupt consensus frame surfaces.
  assert!(
    a.next_frame(ha, StreamClass::Control).is_none(),
    "the truncated tail is never delivered as a complete frame"
  );
  assert!(
    a.test_partial_len(ha, StreamClass::Control) > 0,
    "the torn tail's prefix remains buffered (undeliverable), to be dropped at the reap"
  );
  // The deferred FIN reaps the connection — attributed to the TORN tail. At ingest time the
  // pre-auth classification was ambiguous (a partial behind a complete hello is normally the
  // legitimately-retained pipelined tail), so a Clean FIN was queued; the raised-cap re-decode at
  // validation resolved the ambiguity (the tail is torn at the FINAL cap) and UPGRADED the queued
  // disposition — the peer finished mid-frame, and the per-cause counters must say so rather than
  // reporting a clean peer close.
  let deferred = a.take_pending_fin_close();
  assert_eq!(
    deferred,
    Some((ha, StreamClass::Control, FinDisposition::Truncated)),
    "the deferred FIN was upgraded to Truncated once the raised-cap re-decode proved the tail torn"
  );
  if let Some((hh, cls, disp)) = deferred {
    a.finish_fin_close(read_tick, hh, cls, disp);
  }
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "the connection reaps after delivering the hello and dropping the torn tail"
  );
  assert_eq!(
    a.conn_close_count(CloseCause::TruncatedFrame),
    1,
    "the torn-tail reap is counted as TruncatedFrame (not a clean peer close)"
  );
  assert_eq!(
    a.conn_close_count(CloseCause::PeerClosed),
    0,
    "no clean peer close is attributed for a FIN that tore a frame"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted"
  );
  let _ = MAX_HELLO_LEN;
}

#[test]
fn preauth_control_fin_with_partial_tail_validates_then_reaps_control_bulk() {
  preauth_control_fin_with_partial_tail_validates_then_reaps(StreamLayout::ControlBulk);
}

#[test]
fn preauth_control_fin_with_partial_tail_validates_then_reaps_single() {
  preauth_control_fin_with_partial_tail_validates_then_reaps(StreamLayout::Single);
}

/// A pre-auth FIN that lands MID-HELLO — `[PARTIAL hello frame][FIN]` — IS a real truncation even
/// pre-auth: the FIRST frame never completed, so `extend_first` leaves the incomplete hello in
/// `partial` with NO frame on `ready`. There is nothing to authenticate (the connection will never
/// validate) and no post-validation re-decode can recover it, so `ingest_recv` reaps INLINE (returns
/// `true`, like `FrameTooLong`) rather than deferring. This is the case the truncation oracle MUST
/// still catch pre-auth — the fix distinguishes it from a complete hello + buffered tail by the empty
/// ready queue (`!decoder.has_ready()`).
fn preauth_control_fin_mid_hello_reaps_as_truncation(layout: StreamLayout) {
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(layout);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  assert!(a.is_authenticating(ha), "A starts Authenticating");

  // Frame a hello-sized message, then keep only a MID-FRAME prefix (the whole length prefix plus a few
  // body bytes, strictly fewer than the whole frame), then FIN — so A reads `[partial hello][FIN]`.
  let mut framed = Vec::new();
  encode_frame(&[0xA1u8; 20], &mut framed);
  let cut = LEN_PREFIX + 5;
  assert!(cut < framed.len(), "the prefix must be a proper truncation");
  b_open_write_first_stream_finished(&mut b, hb, &framed[..cut]);

  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  let mut signaled = false;
  for k in 1..60u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
    if a.take_ready_unique().contains(&ha) {
      signaled = true;
    }
  }
  assert!(signaled, "A must be signaled readable before the read");

  // THE single ingest of `[partial hello][FIN]`: the hello never completes (`ready` empty,
  // `partial_len != 0`), so this IS a truncation — reap inline (return `true`), exactly like a framing
  // error, NOT the deferred clean-FIN disposition.
  let read_tick = start + Duration::from_millis(60 * 5);
  assert!(
    a.ingest_recv(read_tick, ha),
    "a pre-auth graceful FIN MID-HELLO is a truncation: it reaps (returns true) like a framing error"
  );
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "the mid-hello truncation reaps the whole connection (Closed)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted"
  );
  assert!(
    a.take_pending_fin_close().is_none(),
    "a mid-hello truncation reaps inline via close_local, NOT through the deferred queue"
  );
  assert!(
    a.next_frame(ha, StreamClass::Control).is_none(),
    "the torn hello is never delivered as a complete frame"
  );
  let mut saw_lost = false;
  while let Some(h) = a.take_lost() {
    if h == ha {
      saw_lost = true;
    }
  }
  assert!(saw_lost, "the reaped connection is queued on `lost`");
}

#[test]
fn preauth_control_fin_mid_hello_reaps_as_truncation_control_bulk() {
  preauth_control_fin_mid_hello_reaps_as_truncation(StreamLayout::ControlBulk);
}

#[test]
fn preauth_control_fin_mid_hello_reaps_as_truncation_single() {
  preauth_control_fin_mid_hello_reaps_as_truncation(StreamLayout::Single);
}

/// `bind_validated`'s buffered-tail re-decode failure path — a defensive branch — must DEFER its reap
/// (not close synchronously), so the hello already on the decoder's ready queue is delivered first.
///
/// The branch fires only when, after the cap is raised to `MAX_FRAME_LEN`, the buffered pre-auth tail
/// STILL declares a length over that cap. The live decode path cannot reach it: `extend_first`'s
/// `buffer_capped_tail` rejects an over-`MAX_FRAME_LEN` tail prefix during the pre-auth read (capping the
/// tail at the SAME constant the post-validation `extend` checks against), so any tail that survived to
/// `bind_validated` decodes cleanly at the raised cap. The branch is therefore DEFENSIVE — but its
/// teardown must still obey deliver-before-close: a synchronous `close_local` here would reap the
/// connection with the complete hello still queued on the Control decoder, dropping it.
///
/// This reconstructs the otherwise-unreachable state white-box: feed a COMPLETE framed hello through
/// `extend_first` (so the hello sits on `ready`), then seed an over-`MAX_FRAME_LEN` 4-byte length prefix
/// straight into the decoder's `partial` (bypassing the guard the live path applies). Driving
/// `bind_validated` then raises the cap, the re-decode rejects the seeded prefix (`frame_error`), and the
/// fix DEFERS a `Truncated` close. The asserts pin: the connection is NOT synchronously Closed by
/// `bind_validated` (it validated and deferred), the deferred `(ha, Control, Truncated)` is queued, the
/// hello is delivered via `next_frame`, and only `finish_fin_close` then reaps.
///
/// NEUTER CHECK: revert the fix to a synchronous `if tail_frame_error { close_local(now, h); return; }`.
/// Then right after `bind_validated` the connection is already `Closed` and NOTHING is queued on
/// `pending_fin_close` — the "still validated, not synchronously closed" assert fires first, the
/// "deferred Truncated queued" assert second: the synchronous teardown reaped before the hello drain.
#[test]
fn bind_validated_tail_decode_error_defers_truncated_close_not_synchronous() {
  let Linked {
    mut a,
    ha,
    now: start,
    ..
  } = connect_two_bridges(StreamLayout::ControlBulk);
  let peer_b = Peer::Replica(ReplicaId::new(1));
  let now = start + Duration::from_millis(5);
  assert!(
    a.is_authenticating(ha),
    "A is Authenticating after the handshake (the pre-auth Control cap is in force)"
  );

  // A COMPLETE framed hello, decoded under the pre-auth cap so it sits on the Control decoder's ready
  // queue — this is the frame deliver-before-close must surface before any reap.
  let hello_stub = [0xA7u8; 6];
  let mut framed_hello = Vec::new();
  encode_frame(&hello_stub, &mut framed_hello);
  {
    let e = a.table.entry(ha).expect("A entry");
    let decoder = &mut e.class_mut(StreamClass::Control).decoder;
    decoder
      .extend_first(&framed_hello)
      .expect("the hello frame decodes under the pre-auth cap");
    assert!(
      decoder.has_ready(),
      "the complete hello is queued on the Control decoder before validation"
    );
    // Seed an over-`MAX_FRAME_LEN` length prefix straight into `partial`, bypassing the `extend_first`
    // prefix guard that makes this state unreachable through the live read. After `set_max` raises the
    // cap, `bind_validated`'s re-decode (`extend(&[])`) reads this prefix and rejects it (`FrameTooLong`).
    decoder.seed_partial_for_test(&(MAX_FRAME_LEN + 1).to_be_bytes());
  }

  // Validate A. The cap-raise + tail re-decode hits the seeded over-cap prefix (`tail_frame_error`), and
  // the fix DEFERS a `Truncated` close rather than closing synchronously.
  a.bind_validated(now, ha, peer_b);

  // The decisive deliver-before-close assertions (both FAIL under the synchronous-close neuter): the
  // connection validated and is NOT yet torn down — the reap was deferred, not run inside `bind_validated`.
  assert!(
    a.is_validated(ha),
    "bind_validated DEFERS the tail-error reap: the connection validated and is not synchronously closed"
  );
  assert!(
    a.table.entry(ha).is_some_and(|e| !e.phase.is_closed()),
    "the connection is not Closed by bind_validated — the deferred close runs only after delivery"
  );

  // The hello queued before the fault is delivered, exactly as `drain_bridge`'s `next_frame` drain does —
  // a synchronous close would have reaped with this frame still queued (dropping it).
  let hello = a.next_frame(ha, StreamClass::Control);
  assert_eq!(
    hello.as_deref(),
    Some(hello_stub.as_slice()),
    "the complete hello is delivered before the deferred reap (NEUTER: a synchronous close drops it)"
  );

  // The deferred close carries `OverCap` (the over-cap tail is a peer protocol violation →
  // whole-connection reap attributed to FrameTooLong), queued for the post-delivery teardown —
  // empty under the synchronous-close neuter.
  let deferred = a.take_pending_fin_close();
  assert_eq!(
    deferred,
    Some((ha, StreamClass::Control, FinDisposition::OverCap)),
    "the tail framing error defers an OverCap (whole-connection) close, not a synchronous reap"
  );
  if let Some((hh, cls, disp)) = deferred {
    a.finish_fin_close(now, hh, cls, disp);
  }
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "after the hello is delivered, the deferred OverCap close reaps the whole connection (Closed)"
  );
  assert_eq!(
    a.handle_for(peer_b),
    None,
    "the reaped connection is unrouted"
  );
}

/// A short/empty FIRST Control frame must NOT leave the connection open for a LATER frame to
/// authenticate. This replays `drain_bridge`'s exact pre-auth Control loop against the real
/// [`Hello`](crate::transport::quic::Hello) source: B writes `[short-or-empty hello prefix][valid
/// hello]` as TWO complete Control frames (the delivered-first-frame attack), A reads them while
/// `Authenticating`, and the FIRST frame's `authenticate` decides the connection's fate.
///
/// On QUIC the first delivered frame is a COMPLETE popped frame, so it is the SOLE Hello
/// opportunity: a `HelloOutcome::Incomplete` prefix must be `Rejected`, closing the connection,
/// NOT `Pending`. The coordinator's `apply_outcome` then `close_local`s and the
/// `!is_validated` break stops the drain, so the buffered valid SECOND frame never authenticates —
/// the connection is `Closed` and unrouted, never bound to the peer the second frame claims.
///
/// NEUTER CHECK: revert `Hello::authenticate`'s delivered-frame arm to `Incomplete => Pending`
/// (unconditionally). The first (short/empty) frame then yields `Pending`, the connection stays
/// `Authenticating`, the loop continues to the buffered SECOND frame, the valid hello authenticates,
/// and `bind_validated` binds the peer — the assertions below (`Closed`, unrouted, not bound) all
/// fail: exactly the later-frame-authenticates hole this fix closes.
fn a_short_first_control_frame_does_not_let_a_later_frame_authenticate(short_first: &[u8]) {
  use crate::transport::quic::identity::{Hello, IdentityCtx, IdentityOutcome, IdentitySource};

  const CLUSTER: u128 = 0x5151;
  let Linked {
    mut a,
    mut b,
    a_addr,
    b_addr,
    ha,
    hb,
    now: start,
  } = connect_two_bridges(StreamLayout::ControlBulk);
  // The peer the SECOND (valid) frame claims — A must NEVER bind it via that later frame.
  let claimed = Peer::Replica(ReplicaId::new(1));
  assert!(
    a.is_authenticating(ha),
    "A starts Authenticating (the first Control frame is the sole Hello opportunity)"
  );

  // `short_first` is a malformed/short first Control frame (empty, or a valid tag+version prefix that
  // does NOT complete a hello) — `classify_hello` returns `Incomplete` for it. The SECOND frame is a
  // genuine, complete hello for `claimed`. B writes BOTH as complete Control frames in one stream
  // write so A reads them in one pre-auth pass while still Authenticating.
  assert!(
    matches!(
      crate::transport::labeled::classify_hello(short_first, CLUSTER),
      crate::transport::labeled::HelloOutcome::Incomplete
    ),
    "the first frame must be a genuinely Incomplete hello prefix (the precondition under attack)"
  );
  let mut valid_hello = Vec::new();
  crate::transport::labeled::encode_hello(
    CLUSTER,
    crate::transport::labeled::HelloId::from_peer(claimed),
    &mut valid_hello,
  );
  let mut buf = Vec::new();
  encode_frame(short_first, &mut buf);
  encode_frame(&valid_hello, &mut buf);
  b_open_write_first_stream_finished(&mut b, hb, &buf);

  // Ferry WITHOUT A reading its Control stream, so both frames buffer in A's quinn state before the
  // single pre-auth read pass. 60 ticks is far inside the 1 s idle timeout.
  let mut pipe_to_a = PacketPipe::default();
  let mut pipe_to_b = PacketPipe::default();
  for k in 1..60u64 {
    let tick = start + Duration::from_millis(k * 5);
    ferry_once(
      &mut a,
      &mut b,
      a_addr,
      b_addr,
      &mut pipe_to_a,
      &mut pipe_to_b,
      tick,
    );
  }

  // Replay `drain_bridge`'s pre-auth Control loop EXACTLY: ingest, then pull frames one at a time,
  // running `Hello::authenticate` on each while Authenticating and applying the coordinator's binding
  // decision (Rejected → close_local + break).
  let read_tick = start + Duration::from_millis(60 * 5);
  a.ingest_recv(read_tick, ha);
  let src = Hello::new(CLUSTER);
  let mut rejected_on_first = false;
  while let Some(payload) = a.next_frame(ha, StreamClass::Control) {
    if a.is_authenticating(ha) {
      match src.authenticate(&IdentityCtx::new(&[], Some(&payload), CLUSTER)) {
        // This bridge-level replay maps the attested MemberId straight to a routing slot (the
        // fixture's member id == slot); the coordinator's `apply_outcome` does this via the active
        // membership. Unreached in the passing case — the short first frame rejects below.
        IdentityOutcome::Identified(id) => {
          let slot = id.id().as_replica().map(|m| m.get() as u16).unwrap_or(0);
          a.bind_validated(read_tick, ha, Peer::Replica(ReplicaId::new(slot)));
        }
        IdentityOutcome::Pending => {}
        IdentityOutcome::Rejected => {
          rejected_on_first = true;
          a.close_local(read_tick, ha, CloseCause::PeerClosed);
        }
      }
      if !a.is_validated(ha) {
        break; // the coordinator stops pulling frames from a non-validated connection
      }
    } else {
      break;
    }
  }

  assert!(
    rejected_on_first,
    "the FIRST (short/empty) Control frame must be REJECTED at the auth boundary, not admitted as \
     Pending (NEUTER: Incomplete => Pending makes this false and the loop falls through to bind)"
  );
  assert!(
    a.table.entry(ha).is_some_and(|e| e.phase.is_closed()),
    "the connection is CLOSED by the first-frame rejection — never left open for the later frame"
  );
  assert_eq!(
    a.handle_for(claimed),
    None,
    "A must NOT have bound the peer the buffered SECOND (valid) frame claims — the later frame never \
     authenticated (NEUTER: it binds and this is Some)"
  );
}

/// Case (1) with an EMPTY first Control frame: a zero-length first frame is a delivered frame (not the
/// `Connected` no-frame probe), so it is REJECTED and the later valid hello never binds.
#[test]
fn an_empty_first_control_frame_does_not_let_a_later_frame_authenticate() {
  a_short_first_control_frame_does_not_let_a_later_frame_authenticate(&[]);
}

/// Case (1) with a SHORT first Control frame: a valid hello tag+version truncated before the peer id
/// is `Incomplete`; as the delivered first frame it is REJECTED and the later valid hello never binds.
#[test]
fn a_truncated_first_control_frame_does_not_let_a_later_frame_authenticate() {
  // A valid hello, minus its last byte → a genuine `Incomplete` prefix that does not complete.
  let mut full = Vec::new();
  crate::transport::labeled::encode_hello(
    0x5151,
    crate::transport::labeled::HelloId::from_peer(Peer::Replica(ReplicaId::new(1))),
    &mut full,
  );
  let short = &full[..full.len() - 1];
  a_short_first_control_frame_does_not_let_a_later_frame_authenticate(short);
}

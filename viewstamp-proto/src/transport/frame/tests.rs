use super::*;

#[test]
fn round_trip_single_and_multi() {
  let mut buf = Vec::new();
  encode_frame(b"abc", &mut buf);
  encode_frame(b"de", &mut buf);
  let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
  dec.extend(&buf).unwrap();
  assert_eq!(dec.next_frame(), Some(b"abc".to_vec()));
  assert_eq!(dec.next_frame(), Some(b"de".to_vec()));
  assert_eq!(dec.next_frame(), None);
  assert_eq!(dec.partial_len(), 0);
}

#[test]
fn partial_frame_accumulates() {
  let mut buf = Vec::new();
  encode_frame(b"hello", &mut buf);
  let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
  dec.extend(&buf[..3]).unwrap();
  assert_eq!(dec.next_frame(), None);
  dec.extend(&buf[3..]).unwrap();
  assert_eq!(dec.next_frame(), Some(b"hello".to_vec()));
}

#[test]
fn an_oversized_declared_length_is_rejected_before_buffering_the_body() {
  let mut dec = FrameDecoder::new(8);
  let mut packet = Vec::new();
  packet.extend_from_slice(&100u32.to_be_bytes()); // declares 100 > cap 8
  packet.extend_from_slice(&[0u8; 1000]); // a large body must never be retained
  assert_eq!(
    dec.extend(&packet),
    Err(TransportError::FrameTooLong { len: 100, max: 8 })
  );
  assert!(dec.partial_len() <= 4, "the over-cap body is not retained");
}

#[test]
fn split_prefix_then_oversized_body_is_rejected_without_retaining_the_tail() {
  let mut dec = FrameDecoder::new(8);
  dec.extend(&[0u8, 0u8, 0u8]).unwrap(); // 3 bytes of the prefix
  let mut rest = Vec::new();
  rest.push(100u8); // the 4th prefix byte completes "declares 100"
  rest.extend_from_slice(&[0u8; 1000]); // huge tail
  assert_eq!(
    dec.extend(&rest),
    Err(TransportError::FrameTooLong { len: 100, max: 8 })
  );
  assert!(dec.partial_len() <= 4, "the over-cap tail is not retained");
}

#[test]
fn header_only_reports_a_partial() {
  let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
  let mut buf = Vec::new();
  encode_frame(b"hello", &mut buf);
  dec.extend(&buf[..4]).unwrap(); // header only, no body
  assert_eq!(dec.next_frame(), None);
  assert_eq!(dec.partial_len(), 4);
}

/// `extend_first` yields ONLY the first frame under the small cap and retains a pipelined frame that
/// is OVER that cap, un-decoded; after `set_max` raises the cap, the next `extend` decodes the tail.
/// This is the pre-auth Control path: a peer that already validated us pipelines a consensus frame
/// (larger than the hello cap) directly behind its hello in one read, and it must not be rejected.
#[cfg(feature = "quic")]
#[test]
fn extend_first_yields_the_hello_and_retains_an_over_cap_pipelined_tail() {
  let hello = vec![0xAAu8; 6]; // fits the small cap
  let big = vec![0x5Au8; 64]; // over the cap, under the raised cap
  let mut buf = Vec::new();
  encode_frame(&hello, &mut buf);
  encode_frame(&big, &mut buf);

  let mut dec = FrameDecoder::new(8); // a hello-sized cap; `big` (64) exceeds it
  dec.extend_first(&buf).unwrap(); // ONE pass delivers hello + the over-cap tail
  // Only the hello surfaces; the tail is buffered RAW (its over-cap prefix is NOT yet checked).
  assert_eq!(dec.next_frame(), Some(hello));
  assert_eq!(
    dec.next_frame(),
    None,
    "the over-cap tail is NOT decoded while capped"
  );
  assert!(
    dec.partial_len() > 8,
    "the whole tail frame is buffered un-decoded"
  );

  // Validation raises the cap; the next `extend` drains the buffered tail with NO new bytes.
  dec.set_max(MAX_FRAME_LEN);
  dec.extend(&[]).unwrap();
  assert_eq!(
    dec.next_frame(),
    Some(big),
    "the tail decodes once the cap is raised"
  );
  assert_eq!(dec.next_frame(), None);
  assert_eq!(dec.partial_len(), 0);
}

/// A FIRST frame whose declared length is over the cap is STILL rejected by `extend_first` on the
/// prefix alone — the oversized-hello pin attack the pre-auth cap exists to stop, preserved.
#[cfg(feature = "quic")]
#[test]
fn extend_first_rejects_an_oversized_first_frame_on_the_prefix() {
  let mut dec = FrameDecoder::new(8);
  let mut packet = Vec::new();
  packet.extend_from_slice(&100u32.to_be_bytes()); // a FIRST frame declaring 100 > cap 8
  packet.extend_from_slice(&[0u8; 1000]); // its body must never be retained
  assert_eq!(
    dec.extend_first(&packet),
    Err(TransportError::FrameTooLong { len: 100, max: 8 })
  );
  assert!(
    dec.partial_len() <= 4,
    "the over-cap first frame's body is not retained"
  );
  assert_eq!(dec.next_frame(), None);
}

/// `extend_first` resumes a hello split across reads, then retains the pipelined over-cap tail that
/// arrived in the same final segment — no frame is yielded until the hello completes.
#[cfg(feature = "quic")]
#[test]
fn extend_first_resumes_a_split_hello_then_buffers_the_tail() {
  let hello = vec![0x11u8; 6];
  let big = vec![0x22u8; 64];
  let mut buf = Vec::new();
  encode_frame(&hello, &mut buf);
  encode_frame(&big, &mut buf);

  let mut dec = FrameDecoder::new(8);
  // First read: only part of the hello (prefix + 2 body bytes). Nothing yielded yet.
  dec.extend_first(&buf[..6]).unwrap();
  assert_eq!(dec.next_frame(), None);
  // Second read: the rest of the hello plus the whole over-cap tail, in one segment.
  dec.extend_first(&buf[6..]).unwrap();
  assert_eq!(dec.next_frame(), Some(hello));
  assert_eq!(
    dec.next_frame(),
    None,
    "the over-cap tail stays buffered while capped"
  );

  dec.set_max(MAX_FRAME_LEN);
  dec.extend(&[]).unwrap();
  assert_eq!(dec.next_frame(), Some(big));
}

/// After the cap is raised, a single `extend` drains MULTIPLE pipelined tail frames out of `partial`,
/// in order — `extend_first` may buffer more than one frame behind the hello in one read pass.
#[cfg(feature = "quic")]
#[test]
fn extend_drains_multiple_buffered_tail_frames_after_the_cap_is_raised() {
  let hello = vec![0x01u8; 4];
  let a = vec![0x0Au8; 40];
  let b = vec![0x0Bu8; 50];
  let mut buf = Vec::new();
  encode_frame(&hello, &mut buf);
  encode_frame(&a, &mut buf);
  encode_frame(&b, &mut buf);

  let mut dec = FrameDecoder::new(8);
  dec.extend_first(&buf).unwrap();
  assert_eq!(dec.next_frame(), Some(hello));
  assert_eq!(dec.next_frame(), None);

  dec.set_max(MAX_FRAME_LEN);
  dec.extend(&[]).unwrap();
  assert_eq!(dec.next_frame(), Some(a));
  assert_eq!(dec.next_frame(), Some(b));
  assert_eq!(dec.next_frame(), None);
  assert_eq!(dec.partial_len(), 0);
}

/// A pipelined tail frame declaring OVER `MAX_FRAME_LEN` must be rejected on its 4-byte length prefix
/// — BEFORE any of its body is buffered — even while the decoder is still at the small pre-auth cap.
/// The hello validated this side, so the tail is buffered for post-validation decode; without a prefix
/// guard the over-cap body would be retained up to the read budget (raising the pre-auth pin from the
/// hello cap to a whole `STAGE_CHUNK`) and only rejected later by `extend` under the raised cap. The
/// guard rejects it here against the FULL frame cap (the cap the tail would decode under), retaining no
/// tail body, so the connection is torn down on the prefix.
///
/// NEUTER CHECK: drop the prefix check in `buffer_capped_tail` (blindly `extend_from_slice` the whole
/// tail) and `extend_first` returns `Ok` here while `partial_len` grows to include the over-cap body —
/// exactly the pre-auth body retention this guard closes.
#[cfg(feature = "quic")]
#[test]
fn extend_first_rejects_an_over_cap_pipelined_tail_on_its_prefix() {
  let hello = vec![0xAAu8; 6]; // fits the small pre-auth cap
  let mut buf = Vec::new();
  encode_frame(&hello, &mut buf);
  // A tail frame whose declared length exceeds the FULL frame cap, followed by body bytes that must
  // NEVER be retained. (The prefix is hand-built so the declared length can exceed MAX_FRAME_LEN
  // without allocating a multi-megabyte body.)
  buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
  let tail_body = [0u8; 256];
  buf.extend_from_slice(&tail_body);

  let mut dec = FrameDecoder::new(8); // the hello-sized pre-auth cap
  assert_eq!(
    dec.extend_first(&buf),
    Err(TransportError::FrameTooLong {
      len: MAX_FRAME_LEN + 1,
      max: MAX_FRAME_LEN,
    }),
    "an over-`MAX_FRAME_LEN` pipelined tail is rejected even at the small pre-auth cap"
  );
  // The hello still surfaced (it was decoded before the offending tail), and NONE of the over-cap tail
  // body was retained — `partial` holds at most the hello-having-been-cleared plus the tail's 4-byte
  // prefix, never its 256-byte body.
  assert_eq!(dec.next_frame(), Some(hello));
  assert!(
    dec.partial_len() <= LEN_PREFIX,
    "no over-cap tail body is retained (partial bounded by the prefix, not the body): got {}",
    dec.partial_len()
  );
}

/// The over-cap pipelined tail is rejected on its prefix even when the over-cap frame arrives BEHIND a
/// legitimate in-cap tail frame in the same buffer: the walk steps over the in-cap frame's buffered
/// body, then rejects the next frame on its prefix — still retaining none of the over-cap body.
#[cfg(feature = "quic")]
#[test]
fn extend_first_rejects_an_over_cap_tail_behind_an_in_cap_tail() {
  let hello = vec![0x11u8; 6];
  let ok_tail = vec![0x22u8; 64]; // over the pre-auth cap, under MAX_FRAME_LEN — legitimate, buffered
  let mut buf = Vec::new();
  encode_frame(&hello, &mut buf);
  encode_frame(&ok_tail, &mut buf);
  buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes()); // then an over-cap frame's prefix
  buf.extend_from_slice(&[0u8; 128]); // its body must not be retained

  let mut dec = FrameDecoder::new(8);
  assert_eq!(
    dec.extend_first(&buf),
    Err(TransportError::FrameTooLong {
      len: MAX_FRAME_LEN + 1,
      max: MAX_FRAME_LEN,
    })
  );
  assert_eq!(dec.next_frame(), Some(hello));
  // `partial` may hold the legitimate in-cap tail (`ok_tail`, retained for post-validation decode) plus
  // the rejected frame's 4-byte prefix — but NOT the rejected frame's 128-byte body.
  assert!(
    dec.partial_len() <= LEN_PREFIX + LEN_PREFIX + ok_tail.len(),
    "only the in-cap tail (plus the rejected prefix) is retained, never the over-cap body: got {}",
    dec.partial_len()
  );
}

/// The legitimate pipelined-tail case is unchanged by the tail guard: a tail frame in
/// `MAX_HELLO_LEN < len <= MAX_FRAME_LEN` (a consensus Control frame a peer that already validated us
/// pipelines behind its hello, larger than the hello cap) is BUFFERED — not rejected — and decodes
/// once `set_max` raises the cap. This pins the boundary the guard must straddle: it checks against
/// `MAX_FRAME_LEN`, NOT the small pre-auth `MAX_HELLO_LEN`, so a real consensus frame survives.
#[cfg(feature = "quic")]
#[test]
fn extend_first_preserves_a_legitimate_over_hello_cap_tail() {
  use crate::transport::labeled::MAX_HELLO_LEN;
  let hello = vec![0x33u8; 6];
  // A tail strictly larger than the hello cap but well within the frame limit — the consensus frame
  // the pre-auth tail buffering exists to preserve.
  let big = vec![0x44u8; MAX_HELLO_LEN + 64];
  let mut buf = Vec::new();
  encode_frame(&hello, &mut buf);
  encode_frame(&big, &mut buf);

  let mut dec = FrameDecoder::new(MAX_HELLO_LEN as u32); // the real pre-auth Control cap
  dec.extend_first(&buf).unwrap(); // NOT rejected — the tail is in (hello_cap, MAX_FRAME_LEN]
  assert_eq!(dec.next_frame(), Some(hello));
  assert_eq!(
    dec.next_frame(),
    None,
    "the over-hello-cap tail stays buffered while capped (not yet decoded, not rejected)"
  );
  dec.set_max(MAX_FRAME_LEN);
  dec.extend(&[]).unwrap();
  assert_eq!(
    dec.next_frame(),
    Some(big),
    "the legitimate consensus tail decodes once the cap is raised"
  );
  assert_eq!(dec.partial_len(), 0);
}

/// A maximum-sized frame leaves exactly ONE frame-sized allocation live.
///
/// The decoder assembles a frame in `partial`, so a 16 MiB frame grows that buffer to 16 MiB. If the
/// completed frame were COPIED out and `partial` merely cleared, the copy and the retained capacity
/// would both be live — 32 MiB held for one 16 MiB frame, and retained for the connection's life.
/// Handing the buffer over instead keeps one allocation and restarts `partial` from the bounded
/// working capacity.
///
/// Fed one read budget at a time, exactly as the QUIC receive path feeds it, so the capacity the
/// assembly actually grows to is the one observed.
#[test]
fn a_max_sized_frame_retains_no_second_frame_allocation() {
  let body = vec![0xA5u8; MAX_FRAME_LEN as usize];
  let mut wire = Vec::new();
  encode_frame(&body, &mut wire);

  let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
  let mut assembling = core::ptr::null();
  for chunk in wire.chunks(STAGE_CHUNK) {
    dec.extend(chunk).unwrap();
    if dec.partial_len() > 0 {
      assembling = dec.partial.as_ptr();
    }
  }
  assert!(
    dec.partial.capacity() <= RETAINED_PARTIAL_CAP,
    "the completed frame's storage must be handed over, not copied out of a retained \
     {}-byte buffer",
    dec.partial.capacity()
  );
  assert_eq!(dec.partial_len(), 0, "nothing follows the frame");
  let frame = dec.next_frame().expect("the whole frame decodes");
  assert_eq!(frame.len(), MAX_FRAME_LEN as usize);
  assert_eq!(
    frame, body,
    "the handed-over storage carries the body intact"
  );
  assert_eq!(
    frame.as_ptr(),
    assembling,
    "the delivered frame must BE the buffer the assembly grew — a copy would allocate a second \
     frame-sized buffer alongside it, which is the peak this pins"
  );
  assert_eq!(
    frame.capacity(),
    MAX_FRAME_LEN as usize + LEN_PREFIX,
    "and that buffer must be reserved to the frame's own size, not doubled past it"
  );
  assert!(
    dec.partial.capacity() <= RETAINED_PARTIAL_CAP,
    "and nothing frame-sized is retained after the drain"
  );
}

/// The steady path keeps its buffer: a frame within the retained capacity is copied out and the
/// partial buffer REUSED, so a stream of small consensus frames does not reallocate per frame. This
/// is the half of the hand-over rule that the max-frame regression would otherwise let regress into
/// "allocate a fresh buffer for every frame".
#[test]
fn small_frames_reuse_the_retained_partial_buffer() {
  let mut dec = FrameDecoder::new(MAX_FRAME_LEN);
  let mut wire = Vec::new();
  encode_frame(&[0x11u8; 512], &mut wire);
  dec.extend(&wire).unwrap();
  assert_eq!(dec.next_frame().map(|f| f.len()), Some(512));
  let retained = dec.partial.capacity();
  assert!(
    retained >= 512 + LEN_PREFIX,
    "the small-frame path keeps its buffer for the next frame, got {retained}"
  );
  assert!(
    retained <= RETAINED_PARTIAL_CAP,
    "and never carries more than the bounded working capacity, got {retained}"
  );
  for _ in 0..64 {
    dec.extend(&wire).unwrap();
    assert_eq!(dec.next_frame().map(|f| f.len()), Some(512));
    assert_eq!(
      dec.partial.capacity(),
      retained,
      "a steady stream of small frames must not grow or replace the buffer"
    );
  }
}

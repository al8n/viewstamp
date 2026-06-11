//! Regenerates the committed seed corpus for every fuzz target, using the crate's own encoders
//! (so the seeds are guaranteed-valid inputs the fuzzer mutates from). Run from the `fuzz/`
//! directory:
//!
//! ```sh
//! cargo run --bin corpus_gen
//! ```

use std::fs;
use std::path::Path;

use bytes::Bytes;
use viewstamp_proto::{
  ClientId, Commit, GetView, Header, Message, OpNumber, ReplicaId, Request, RequestNumber,
  StartViewChange, View, VsrState,
};

fn write(target: &str, name: &str, bytes: &[u8]) {
  let dir = Path::new("corpus").join(target);
  fs::create_dir_all(&dir).expect("create corpus dir");
  let path = dir.join(name);
  fs::write(&path, bytes).expect("write corpus seed");
  println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

/// `[u32 length][payload]` — the stream transport's frame shape (the documented wire format).
fn frame(payload: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(4 + payload.len());
  out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
  out.extend_from_slice(payload);
  out
}

fn main() {
  // ── message_decode: a handful of valid encoded messages ──
  let request = Message::Request(Request::new(
    ClientId::new(7),
    RequestNumber::with(1),
    Bytes::from_static(b"seed-op"),
  ));
  let commit = Message::Commit(Commit::new(
    View::with(3),
    OpNumber::with(9),
    OpNumber::with(4),
  ));
  let svc = Message::StartViewChange(StartViewChange::new(View::with(2), ReplicaId::new(1)));
  let get_view = Message::GetView(GetView::new(View::with(1), ReplicaId::new(2), 0xDEAD));
  for (name, msg) in [
    ("request", &request),
    ("commit", &commit),
    ("start_view_change", &svc),
    ("get_view", &get_view),
  ] {
    write("message_decode", name, &msg.encode());
  }

  // ── stream_ingress: [lane byte][wire payload] (lane 1 = hello prefixed by the harness) ──
  write("stream_ingress", "framed_request_validated", &{
    let mut v = vec![1u8];
    v.extend_from_slice(&frame(&request.encode()));
    v
  });
  write("stream_ingress", "framed_commit_validated", &{
    let mut v = vec![1u8];
    v.extend_from_slice(&frame(&commit.encode()));
    v
  });
  write("stream_ingress", "framed_request_raw", &{
    let mut v = vec![0u8];
    v.extend_from_slice(&frame(&request.encode()));
    v
  });

  // ── superblock_decode: encoded durable roots + a WAL slot header ──
  write("superblock_decode", "fresh_root", &VsrState::new().encode());
  let h5 = Header::new(
    OpNumber::with(5),
    View::with(2),
    ClientId::new(7),
    RequestNumber::with(3),
    b"seed-body",
  );
  let h6 = Header::new(
    OpNumber::with(6),
    View::with(2),
    ClientId::new(8),
    RequestNumber::with(1),
    b"seed-body-2",
  );
  let root = VsrState::try_new(
    View::with(2),
    View::with(2),
    OpNumber::with(6),
    OpNumber::with(4),
    0xC0FFEE,
    vec![h5, h6],
  )
  .expect("a valid committed-band root");
  write("superblock_decode", "root_with_band", &root.encode());
  write("superblock_decode", "wal_header", &h5.encode());
}

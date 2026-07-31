//! Regenerates the committed seed corpus for every fuzz target, using the crate's own encoders
//! (so the seeds are guaranteed-valid inputs the fuzzer mutates from). Run from the `fuzz/`
//! directory:
//!
//! ```sh
//! cargo run --bin corpus_gen
//! ```

use std::{fs, path::Path};

use bytes::Bytes;
use viewstamp_proto::{
  BlockAddress, BlockResponse, ClientId, Commit, DoViewChange, Epoch, GetView, Header, MemberId,
  Message, Nack, OpNumber, Prepare, PreparedEntry, ReconfigurePayload, ReplicaId, Request,
  RequestNumber, StartViewChange, SyncCheckpoint, View, VsrState, encode_message,
};

/// A 3-entry log spanning all three `PreparedEntry` body states (`Present`, `Repairing`,
/// `Reconfigure`) — exercises the `repeated PreparedEntry` field's nested oneof and the
/// `ReconfigurePayload` sub-message in one seed.
fn mixed_log() -> Vec<PreparedEntry> {
  vec![
    PreparedEntry::new(
      OpNumber::with(1),
      ClientId::new(1),
      RequestNumber::with(1),
      Bytes::from_static(b"a"),
    ),
    PreparedEntry::repairing(
      OpNumber::with(2),
      ClientId::new(2),
      RequestNumber::with(2),
      0x1122_3344_5566_7788_99AA_BBCC_DDEE_FF00,
    ),
    PreparedEntry::reconfigure(
      OpNumber::with(3),
      ClientId::RECONFIGURATION,
      RequestNumber::with(3),
      ReconfigurePayload::new(
        2,
        0,
        vec![MemberId::new(1), MemberId::new(2)].into_boxed_slice(),
        0,
      ),
    ),
  ]
}

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
    Epoch::new(0),
    0,
  ));
  let svc = Message::StartViewChange(StartViewChange::new(
    View::with(2),
    ReplicaId::new(1),
    Epoch::new(0),
    0,
  ));
  let get_view = Message::GetView(GetView::new(
    View::with(1),
    ReplicaId::new(2),
    0xDEAD,
    Epoch::new(0),
    0,
  ));
  let prepare = Message::Prepare(Prepare::new(
    View::with(5),
    OpNumber::with(10),
    OpNumber::with(9),
    OpNumber::with(4),
    Epoch::new(0),
    0xC0FFEE,
    ClientId::new(7),
    RequestNumber::with(2),
    Bytes::from_static(b"prepare-body"),
  ));
  let do_view_change = Message::DoViewChange(
    DoViewChange::new(
      View::with(6),
      View::with(5),
      OpNumber::with(9),
      OpNumber::with(4),
      Epoch::new(0),
      0xC0FFEE,
      ReplicaId::new(1),
      mixed_log(),
    )
    .with_checkpoint_op(OpNumber::with(3)),
  );
  let sync_checkpoint = Message::SyncCheckpoint(
    SyncCheckpoint::new(
      View::with(4),
      OpNumber::with(8),
      0xBEEF,
      Epoch::new(0),
      0xC0FFEE,
      ReplicaId::new(2),
      0x1234,
      Bytes::from_static(b"snapshot-body"),
      Bytes::from_static(b"membership-body"),
    )
    // Membership-bearing, so the producing op is stamped — decode refuses the pair split apart,
    // and the corpus seeds the ACCEPTED shape (the fuzzer mutates its way to the refusals).
    .with_config_install_op(OpNumber::with(7)),
  );
  let block_response_present = Message::BlockResponse(BlockResponse::new(
    BlockAddress::from_bytes(0xAA55u128.to_be_bytes()),
    Some(Bytes::from_static(b"block-body")),
  ));
  let block_response_absent = Message::BlockResponse(BlockResponse::new(
    BlockAddress::from_bytes(0xAA55u128.to_be_bytes()),
    None,
  ));
  let nack = Message::Nack(Nack::new(
    View::with(7),
    OpNumber::with(11),
    ReplicaId::new(3),
    0xC0FFEE,
  ));
  for (name, msg) in [
    ("request", &request),
    ("commit", &commit),
    ("start_view_change", &svc),
    ("get_view", &get_view),
    ("prepare", &prepare),
    ("do_view_change", &do_view_change),
    ("sync_checkpoint", &sync_checkpoint),
    ("block_response_present", &block_response_present),
    ("block_response_absent", &block_response_absent),
    ("nack", &nack),
  ] {
    write("message_decode", name, &encode_message(msg));
  }

  // ── stream_ingress: [lane byte][wire payload] (lane 1 = hello prefixed by the harness) ──
  write("stream_ingress", "framed_request_validated", &{
    let mut v = vec![1u8];
    v.extend_from_slice(&frame(&encode_message(&request)));
    v
  });
  write("stream_ingress", "framed_commit_validated", &{
    let mut v = vec![1u8];
    v.extend_from_slice(&frame(&encode_message(&commit)));
    v
  });
  write("stream_ingress", "framed_request_raw", &{
    let mut v = vec![0u8];
    v.extend_from_slice(&frame(&encode_message(&request)));
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

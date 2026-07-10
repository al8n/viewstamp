//! `decode_message` over arbitrary bytes: must never panic, must allocate boundedly; anything it
//! accepts re-encodes to the canonical form, which decodes back equal (one-round fixpoint: the
//! canonical image is stable even though arbitrary accepted inputs need not be byte-canonical).

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use viewstamp_proto::{decode_message, encode_message};

fuzz_target!(|data: &[u8]| {
  let frame = Bytes::copy_from_slice(data);
  if let Ok(msg) = decode_message(frame) {
    let canonical = encode_message(&msg);
    assert_eq!(
      canonical.len(),
      msg.encoded_len(),
      "encoded_len disagrees with encode_message"
    );
    let again = decode_message(canonical).expect("canonical form decodes");
    assert_eq!(again, msg, "decode(encode(m)) != m");
  }
});

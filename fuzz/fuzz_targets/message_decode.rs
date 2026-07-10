//! `decode_message` over arbitrary bytes: must never panic, must allocate boundedly, and must
//! round-trip — anything it accepts re-encodes infallibly to bytes that decode back equal (the
//! codec is a bijection on its image), with `encoded_len` agreeing with the actual encoding.

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use viewstamp_proto::{decode_message, encode_message};

fuzz_target!(|data: &[u8]| {
  if let Ok(msg) = decode_message(Bytes::copy_from_slice(data)) {
    let bytes = encode_message(&msg);
    assert_eq!(
      bytes.len(),
      msg.encoded_len(),
      "encoded_len disagrees with encode_message"
    );
    let again = decode_message(bytes).expect("re-encoded message decodes");
    assert_eq!(again, msg, "decode(encode(m)) != m");
  }
});

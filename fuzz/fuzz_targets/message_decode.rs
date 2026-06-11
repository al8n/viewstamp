//! `Message::decode` over arbitrary bytes: must never panic, must allocate boundedly, and must
//! round-trip — anything it accepts re-encodes infallibly to bytes that decode back equal (the
//! codec is a bijection on its image), with `encoded_len` agreeing with the actual encoding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use viewstamp_proto::Message;

fuzz_target!(|data: &[u8]| {
  if let Ok(msg) = Message::decode(data) {
    let bytes = msg.encode();
    assert_eq!(
      bytes.len(),
      msg.encoded_len(),
      "encoded_len disagrees with encode"
    );
    let again = Message::decode(&bytes).expect("re-encoded message decodes");
    assert_eq!(again, msg, "decode(encode(m)) != m");
  }
});

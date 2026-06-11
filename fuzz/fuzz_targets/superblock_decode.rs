//! The superblock/WAL disk codec over arbitrary bytes: `VsrState::decode` (the durable root) and
//! `Header::decode` (the fixed-size WAL slot header) must never panic, must allocate boundedly
//! (the root's header-count prefix is validated against the remaining bytes before any
//! allocation), and must round-trip whatever they accept.

#![no_main]

use libfuzzer_sys::fuzz_target;
use viewstamp_proto::{Header, VsrState};

fuzz_target!(|data: &[u8]| {
  if let Ok(state) = VsrState::decode(data) {
    // `decode` re-validates through `try_new`, so anything it returns upholds the VSR root
    // invariants and re-encodes to a decodable root. (`encode` stamps the CURRENT version, so a
    // root carried under an older layout-compatible version tag round-trips by VALUE, not byte.)
    let bytes = state.encode();
    let again = VsrState::decode(&bytes).expect("re-encoded root decodes");
    assert_eq!(again, state, "VsrState::decode(encode(s)) != s");
  }
  if let Ok(header) = Header::decode(data) {
    // The stored checksum is decoded verbatim (verification is the proto's job), so the byte
    // round-trip is exact.
    let bytes = header.encode();
    let again = Header::decode(&bytes).expect("re-encoded header decodes");
    assert_eq!(again, header, "Header::decode(encode(h)) != h");
  }
});

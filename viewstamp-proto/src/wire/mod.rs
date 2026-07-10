//! The wire envelope: buffa-generated protobuf types and their conversions to and
//! from the domain structs.
//!
//! `proto/viewstamp/v1/messages.proto` is the NORMATIVE schema (WIRE.md references
//! it); `build.rs` generates the types here via buffa. The domain types never change
//! shape for the wire's sake — encoding converts INTO the generated types and
//! decoding converts OUT of them at the transport choke points.

mod generated {
  // The generated zero-copy `*View` accessors carry many single-use / elided
  // lifetime parameters that trip the workspace's `rust_2018_idioms` and
  // `single_use_lifetimes` warn-lints; both are hard errors under `-D warnings`
  // and are buffa's codegen shape, not ours to rewrite.
  #![allow(clippy::wrong_self_convention)]
  #![allow(rust_2018_idioms)]
  #![allow(single_use_lifetimes)]
  include!(concat!(env!("OUT_DIR"), "/viewstamp_wire_generated.rs"));
}
pub(crate) use generated::viewstamp::v1 as pb;

// `convert`'s functions have no production call site yet: the per-message-variant conversions
// that will call them land in later additions to this module, so only the round-trip/rejection
// tests exercise them for now, leaving them unreachable in a non-test build.
#[cfg_attr(not(test), allow(dead_code))]
mod convert;

// `messages_a`'s functions have no production call site yet: the envelope-level oneof dispatch
// that will call them lands in a later addition to this module, so only the round-trip/rejection
// tests exercise them for now, leaving them unreachable in a non-test build.
#[cfg_attr(not(test), allow(dead_code))]
mod messages_a;

#[cfg(test)]
mod tests;

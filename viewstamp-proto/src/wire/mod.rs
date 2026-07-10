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
// `pb` has no non-test consumer yet: the wire<->domain conversions land in
// later additions to this module, so only the smoke test below uses it for now.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use generated::viewstamp::v1 as pb;

#[cfg(test)]
mod tests;

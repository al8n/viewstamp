//! Build-time codegen for the wire envelope.
//!
//! Uses `buffa-build` to invoke `protoc` against `proto/viewstamp/v1/messages.proto`
//! and produce the wire types via buffa's codegen. The output lands in `OUT_DIR` and
//! is pulled in by `src/wire/mod.rs` via `include!`. The schema file is the NORMATIVE
//! wire document (WIRE.md references it).

fn main() {
  println!("cargo:rerun-if-changed=build.rs");
  println!("cargo:rerun-if-changed=proto");

  buffa_build::Config::new()
    .files(&["proto/viewstamp/v1/messages.proto"])
    .includes(&["proto"])
    .use_bytes_type()
    .include_file("viewstamp_wire_generated.rs")
    .compile()
    .expect("buffa codegen failed");
}

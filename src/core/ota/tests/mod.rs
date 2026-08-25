//! Test submodule declarations for `core::ota`.
//!
//! Golden vectors live in their own file so future host projects (sensor
//! firmware, gateway, offline signer tooling) can copy them verbatim as the
//! cross-repository conformance contract.

mod golden_vectors;
mod receiver_tests;
#[path = "sender_tests.rs"]
mod sender_tests;
mod wire_tests;
// Cross-engine proof: compiled only when BOTH halves exist. The file itself
// carries the cfg gate so this declaration stays inert otherwise.
#[path = "interop_tests.rs"]
mod interop_tests;

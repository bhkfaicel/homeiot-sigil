//! Deterministic generator for the FROZEN P-256 conformance material used
//! by the literal golden vectors in `golden_vectors.rs`.
//!
//! The keypair derives from a FIXED scalar, so re-running this test always
//! reproduces the exact bytes frozen in the golden vector. If the manifest
//! v2 layout ever changes, update `VECTOR_IMAGE_SHA` / the message assembly
//! here, re-run this generator, and refresh the literals — never hand-edit
//! signatures.

extern crate std;

use p256::SecretKey;
use p256::ecdsa::{SigningKey, signature::Signer};
use std::println;

/// SHA-256 of the canonical 300 B interop image (bytes `(i*13+5)%241`),
/// matching the receiver/interop fixtures.
const VECTOR_IMAGE_SHA: [u8; 32] = [
    0xA6, 0x8B, 0xA9, 0x09, 0x35, 0x01, 0x9C, 0x98, 0x20, 0x35, 0x2C, 0xE1, 0x4A, 0xC0, 0x52, 0xAC,
    0x24, 0xAC, 0xFA, 0x23, 0x74, 0xC9, 0x98, 0x00, 0x52, 0xCE, 0x26, 0xAA, 0x26, 0x49, 0xA6, 0x28,
];

#[test]
fn print_manifest_v2_material() {
    let secret = SecretKey::from_slice(&[0x42u8; 32]).expect("valid scalar");
    let signing = SigningKey::from(&secret);
    let pub_compressed = signing.verifying_key().to_encoded_point(true);

    // Manifest v2: product 0x0001, version 11, 300 B image, chunk_len 64.
    let mut msg = std::vec::Vec::new();
    msg.extend_from_slice(b"sigil-ota-v2");
    msg.extend_from_slice(&1u16.to_le_bytes());
    msg.extend_from_slice(&11u32.to_le_bytes());
    msg.extend_from_slice(&300u32.to_le_bytes());
    msg.push(64);
    msg.extend_from_slice(&VECTOR_IMAGE_SHA);

    let sig: p256::ecdsa::Signature = signing.sign(&msg);
    println!("PUB = {}", to_hex(pub_compressed.as_bytes()));
    println!("MSG = {}", to_hex(&msg));
    println!("SIG = {}", to_hex(&sig.to_bytes()));
}

fn to_hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| alloc::format!("{:02x}", x)).collect()
}

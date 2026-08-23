//! Host-side AEAD performance measurements (dev-only).
//!
//! Quantifies the ChaCha20-Poly1305 primitive cost of the Data encrypt /
//! decrypt hot path at representative LoRa payload sizes (`L = 0 / 16 / 64 /
//! 128 / 200`). These tests are measurement instruments, not correctness
//! gates: host wall-clock numbers are informational only and must never be
//! presented as target metrics (hardware latency is host firmware work on the
//! real `thumbv6m-none-eabi` / gateway targets). Deterministic facts that do
//! transfer to the target (wire sizes, buffer counts, per-direction payload
//! copies) are asserted and printed next to each timing so later structural
//! optimizations can be compared against this recorded baseline.
//!
//! Run: `cargo test --locked --all-features perf_measurements -- --nocapture`

// The crate is `no_std`; the unit-test harness links `std` on the host, which
// provides the monotonic clock used for the informational timings.
extern crate std;

// Pull the handful of `std` macros used by this dev-only suite into scope
// (`no_std` builds have an empty macro prelude even under `cfg(test)`).
use std::println;

use std::hint::black_box;
use std::time::Instant;

use crate::core::aead::{TAG_SIZE, decrypt_into, encrypt_append};
use crate::core::frame::{FrameType, build_header};
use crate::core::session::{NoncePrefix, SessionKey};
use heapless::Vec;

/// Fixed symmetric session key for all measured operations (test-only value).
const KEY: SessionKey = [0x42u8; 32];
/// Fixed nonce prefix; every timed operation uses counter 0, which mirrors
/// steady-state single-frame cost (counter value does not change cipher cost).
const PREFIX: NoncePrefix = [0x01u8; 4];
/// Peer identity used in the authenticated header data (AAD).
const PEER: [u8; 17] = [7u8; 17];
/// Representative Data payload lengths spanning the supported range from an
/// empty body up to `DATA_MAX` (200 bytes).
const PAYLOAD_LENGTHS: [usize; 5] = [0, 16, 64, 128, 200];
/// Fixed iteration count per timed section so numbers are reproducible in
/// shape across runs (host noise still applies to absolute values).
const ITERATIONS: u32 = 20_000;
/// Output buffer capacity matching the production `<DATA=200, MSG=256>` shape.
const CAP: usize = 256;

/// Builds a deterministic plaintext of `len` bytes (LCG pattern, no runtime
/// randomness) so repeated runs measure identical input data.
fn deterministic_plaintext(len: usize) -> Vec<u8, CAP> {
    let mut out = Vec::<u8, CAP>::new();
    let mut state = 0xA5A5_1234u32;
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // Unwrap is safe: len <= CAP by construction.
        out.push((state >> 24) as u8).unwrap();
    }
    out
}

/// Times `iterations` executions of `op` and prints nothing itself; returns
/// nanoseconds per operation (host wall clock, informational only).
fn time_ns_per_op<F: FnMut()>(iterations: u32, mut op: F) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        op();
    }
    let total = start.elapsed();
    total.as_nanos() / u128::from(iterations.max(1))
}

/// Measures the production-shaped AEAD primitives behind the Data path:
/// [`encrypt_append`] (egress: plaintext appended into the caller's single
/// output frame buffer) and [`decrypt_into`] (ingress: ciphertext copied once
/// into the caller's final destination buffer and decrypted in place).
///
/// Structural facts asserted here (target-relevant):
/// - wire overhead is exactly the 16-byte Poly1305 tag over `L` plaintext
///   bytes (the 19-byte outer header + 12-byte nonce are built by callers);
/// - exactly **one** large output buffer exists per direction and exactly one
///   full-payload copy happens per direction inside these primitives.
#[test]
fn perf_measurements_aead_encrypt_decrypt_by_length() {
    let aad = build_header(&PEER, FrameType::Data);
    println!("AEAD ChaCha20-Poly1305 baseline ({ITERATIONS} iterations per row):");
    println!("  L(pt) | ct+tag | encrypt ns/op | decrypt ns/op | buffers/direction");
    for len in PAYLOAD_LENGTHS {
        let plaintext = deterministic_plaintext(len);

        // Correctness + deterministic wire-size check before timing.
        let mut sealed = Vec::<u8, CAP>::new();
        encrypt_append(&KEY, &PREFIX, 0, &plaintext, &aad, &mut sealed).unwrap();
        assert_eq!(sealed.len(), len + TAG_SIZE);
        let mut opened = Vec::<u8, CAP>::new();
        decrypt_into(&KEY, &PREFIX, 0, &sealed, &aad, &mut opened).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());

        // Egress primitive: fresh caller-owned frame buffer per operation,
        // matching how `encrypt_data` builds one frame per transmission.
        let encrypt_ns = time_ns_per_op(ITERATIONS, || {
            let mut frame = Vec::<u8, CAP>::new();
            encrypt_append(
                black_box(&KEY),
                black_box(&PREFIX),
                black_box(0),
                black_box(plaintext.as_slice()),
                black_box(&aad),
                &mut frame,
            )
            .unwrap();
            black_box(frame.as_slice());
        });

        // Ingress primitive: decrypt into a fresh destination buffer, the
        // same single-buffer shape used by the receive pipeline.
        let decrypt_ns = time_ns_per_op(ITERATIONS, || {
            let mut out = Vec::<u8, CAP>::new();
            decrypt_into(
                black_box(&KEY),
                black_box(&PREFIX),
                black_box(0),
                black_box(sealed.as_slice()),
                black_box(&aad),
                &mut out,
            )
            .unwrap();
            black_box(out.as_slice());
        });

        println!(
            "  {len:>5} | {sealed_len:>6} | {encrypt_ns:>13} | {decrypt_ns:>13} | 1 (single output Vec)",
            sealed_len = sealed.len(),
        );
    }
}

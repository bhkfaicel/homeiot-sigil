//! Host-side usbserial performance measurements (dev-only).
//!
//! Quantifies the link-tier hot paths at representative radio payload sizes
//! (`L = 0 / 64 / 255`): the plain-profile `Msg::encode` egress and
//! `Decoder::feed`/`pop` ingress round-trip, plus the secure-profile
//! `SecureChannel::seal` egress (the head's hottest TX path: every received
//! LoRa frame is sealed before going out on USB) and its sealed
//! `feed`/`pop` round-trip. These tests are measurement instruments, not
//! correctness gates: host wall-clock numbers are informational only and
//! must never be presented as target metrics (hardware latency is host
//! firmware work on the real `thumbv6m-none-eabi` head). Deterministic
//! facts that do transfer to the target (type sizes, sealed wire lengths)
//! are printed next to the timings so later structural optimizations can
//! be compared against this recorded baseline.
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

use core::mem::size_of;

use super::{PSK_A, established_pair, frame};
use crate::usbserial::{
    Decoder, MAX_FRAME_LEN, MAX_RADIO_PAYLOAD, Msg, PSK_LEN, Payload, SECURE_MAX_FRAME_LEN,
    SecureChannel,
};

/// Representative radio payload lengths: empty, typical sensor report, and
/// the physical SX1278 maximum.
const PAYLOAD_LENGTHS: [usize; 3] = [0, 64, MAX_RADIO_PAYLOAD];
/// Fixed iteration count per timed section so numbers are reproducible in
/// shape across runs (host noise still applies to absolute values).
const ITERATIONS: u32 = 20_000;

/// Builds an RX message carrying `len` bytes of deterministic LCG payload
/// (mixed zero and non-zero bytes, no runtime randomness) so repeated runs
/// measure identical inputs and a realistic COBS byte distribution instead
/// of a degenerate constant fill.
fn deterministic_rx(len: usize) -> Msg {
    let mut payload = Payload::new();
    let mut state = 0xA5A5_1234u32;
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        // Unwrap is safe: len <= MAX_RADIO_PAYLOAD by construction.
        payload.push((state >> 24) as u8).expect("len <= capacity");
    }
    Msg::Rx {
        rssi: -55,
        snr: 9,
        payload,
    }
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

/// Measures the plain-profile (COBS + CRC-16) hot paths: `Msg::encode`
/// egress into a fresh frame buffer, and the `Decoder::feed`/`pop` ingress
/// round-trip on a decoder reused across frames (the steady receive shape:
/// one complete frame in, one message out, queue drained).
#[test]
fn perf_measurements_plain_framing_roundtrip() {
    println!("Plain framing baseline (COBS + CRC-16, {ITERATIONS} iterations per row):");
    println!(
        "  sizes (source facts): Decoder = {} B, Msg = {} B",
        size_of::<Decoder>(),
        size_of::<Msg>()
    );
    println!("  L(payload) | wire | encode ns/op | feed+pop round-trip ns/op");
    for len in PAYLOAD_LENGTHS {
        let msg = deterministic_rx(len);

        // Correctness + deterministic wire-size check before timing.
        let wire = frame(&msg);
        let mut decoder = Decoder::new();
        decoder.feed(wire.as_slice());
        assert_eq!(
            decoder.pop().as_ref(),
            Some(&msg),
            "decoded message mismatch"
        );
        assert_eq!(decoder.pop(), None, "queue must be empty afterwards");

        // Egress: encode into a fresh buffer per operation, matching how the
        // head serializes each outgoing message.
        let encode_ns = time_ns_per_op(ITERATIONS, || {
            let mut buf = [0u8; MAX_FRAME_LEN];
            let n = black_box(&msg).encode(&mut buf).expect("frame fits");
            black_box(&buf[..n]);
        });

        // Ingress: feed one pre-encoded frame and drain the queue per
        // operation on a long-lived decoder (framing is stateless between
        // complete frames).
        let feed_ns = time_ns_per_op(ITERATIONS, || {
            decoder.feed(black_box(wire.as_slice()));
            black_box(decoder.pop());
        });

        println!(
            "  {len:>10} | {wire_len:>4} | {encode_ns:>13} | {feed_ns:>26}",
            wire_len = wire.len(),
        );
    }
}

/// Measures the secure-profile hot paths on an established PSK channel:
/// `SecureChannel::seal` alone (fresh output buffer per operation, send
/// counter advancing — the exact egress path the head firmware runs) and
/// the full `seal` + `feed` + `pop` round-trip. Every sealed frame carries a
/// fresh counter, so the ingress half cannot reuse a pre-sealed frame; the
/// round-trip number therefore covers both halves end to end.
#[test]
fn perf_measurements_secure_channel_roundtrip() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    println!(
        "Secure channel baseline (PSK-{PSK_LEN}B ChaCha20-Poly1305 + COBS + CRC, \
         {ITERATIONS} iterations per row):"
    );
    println!(
        "  sizes (source facts): SecureChannel = {} B",
        size_of::<SecureChannel>()
    );
    println!("  L(payload) | sealed | seal ns/op | seal+feed+pop round-trip ns/op");
    for len in PAYLOAD_LENGTHS {
        let msg = deterministic_rx(len);
        let mut out = [0u8; SECURE_MAX_FRAME_LEN];

        // Correctness + wire check before timing (counters advance; the
        // round-trip must hold at any counter value).
        let n = host.seal(&msg, &mut out).expect("seal fits");
        head.feed(&out[..n]);
        assert_eq!(head.pop().as_ref(), Some(&msg), "sealed message mismatch");
        assert_eq!(head.pop(), None, "queue must be empty afterwards");

        // Egress: seal alone into a fresh output buffer, the head's hottest
        // TX path.
        let seal_ns = time_ns_per_op(ITERATIONS, || {
            let mut out = [0u8; SECURE_MAX_FRAME_LEN];
            let n = host.seal(black_box(&msg), &mut out).expect("seal fits");
            black_box(&out[..n]);
        });

        // End to end: seal + feed + pop, one fresh sealed frame per op.
        let roundtrip_ns = time_ns_per_op(ITERATIONS, || {
            let mut out = [0u8; SECURE_MAX_FRAME_LEN];
            let n = host.seal(black_box(&msg), &mut out).expect("seal fits");
            head.feed(black_box(&out[..n]));
            black_box(head.pop());
        });

        println!("  {len:>10} | {n:>6} | {seal_ns:>11} | {roundtrip_ns:>33}");
    }
}

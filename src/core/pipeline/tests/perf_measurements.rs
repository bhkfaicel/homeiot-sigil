//! Host-side pipeline performance measurements (dev-only).
//!
//! Two measurement areas, both tied to recorded audit findings:
//!
//! 1. **Event receive** — tracks the large payload copies on the Event
//!    receive path against a matched-size Data receive (identical AEAD
//!    plaintext size). Wall time is informational host data; the copy counts
//!    are structural source facts. Since the id strip moved in place into
//!    the single decrypt destination buffer, both paths carry exactly **1**
//!    large copy; a regression reintroducing a second buffer would show up
//!    here as Event ≈ Data + one full-payload copy at every length.
//! 2. **Handshake classification** — quantifies the clear-text per-step
//!    classification cost, which bulk-copies each classified handshake frame
//!    once into the `MSG`-sized event buffer without any decryption.
//!
//! Methodology: receive counters are strictly monotonic, so every frame can
//! be authenticated exactly once per receiver state. Each timed pass therefore
//! replays a pre-built frame pool against a **fresh** receiver and processes
//! every frame exactly once, in counter order. The best of three passes is
//! reported to damp host scheduling noise. Frame pools live on the test heap
//! (`std::vec::Vec`); this is measurement-only code and never ships.
//!
//! Run: `cargo test --locked --all-features perf_measurements -- --nocapture`

// The crate is `no_std`; the unit-test harness links `std` on the host, which
// provides the monotonic clock and test-heap containers used here.
extern crate std;

// Pull the handful of `std` macros used by this dev-only suite into scope
// (`no_std` builds have an empty macro prelude even under `cfg(test)`).
use std::{println, vec};

use std::hint::black_box;
use std::time::Instant;

use crate::core::event::{SigilAction, SigilEvent};
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET};
use crate::core::manager::SessionManager;
use crate::core::session::{DirectionalMaterial, Session, SessionRole};
use crate::core::test_support::test_manager_with_mac;
use heapless::Vec;

/// Identities reused from this test tree (sensor sender / gateway receiver).
use super::{LOCAL, REMOTE};

/// Application payload lengths delivered with each received Event; the
/// authenticated plaintext is always `8 + L` bytes (id prefix + payload).
const EVENT_PAYLOAD_LENGTHS: [usize; 3] = [8, 64, 192];
/// Frames per timed pass; large enough to smooth host noise, small enough to
/// keep pool building fast.
const POOL: usize = 2048;
/// Timed passes per scenario; the minimum sample is reported.
const PASSES: u32 = 3;
/// Fixed iteration count for the pure classification sections.
const CLASSIFY_ITERATIONS: usize = 50_000;
/// Wire capacity of every measured frame buffer (production default).
const MSG_CAP: usize = 256;
/// Decrypted capacity used on the receive side (production default).
const DATA_CAP: usize = 200;
/// Symmetric session material shared by the measurement pair (test-only).
const KEY: [u8; 32] = [0x42u8; 32];
const PREFIX: [u8; 4] = [0x01u8; 4];
/// Durable resume PSK carried by the active test sessions (test-only value).
const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

/// Builds a sensor/gateway manager pair sharing one symmetric session so the
/// sensor can emit frames the gateway authenticates. The gateway indexes its
/// session by the sender MAC (`LOCAL`), mirroring production keying.
fn measurement_pair() -> (SessionManager<4>, SessionManager<4>) {
    let mut sensor = test_manager_with_mac::<4>(LOCAL);
    let mut gateway = test_manager_with_mac::<4>(REMOTE);
    // Key lifetime respects the maximum session lifetime contract: expiry is
    // anchored at the fixture timebase (1_000) plus one day.
    const NOW: u32 = 1_000;
    const EXPIRE: u32 = NOW + 86_400;
    let material = DirectionalMaterial::symmetric_for_test(KEY, PREFIX);
    sensor
        .insert(
            Session::new_active(
                REMOTE,
                [2u8; 33],
                material.clone(),
                SessionRole::Sensor,
                RESUME_PSK,
                EXPIRE,
                NOW,
            )
            .unwrap(),
        )
        .unwrap();
    gateway
        .insert(
            Session::new_active(
                LOCAL,
                [2u8; 33],
                material,
                SessionRole::Gateway,
                RESUME_PSK,
                EXPIRE,
                NOW,
            )
            .unwrap(),
        )
        .unwrap();
    (sensor, gateway)
}

/// Times one sequential pass of `op` over the whole pool; returns nanoseconds
/// per operation (host wall clock, informational only).
fn time_pass_ns<F: FnMut(usize)>(pool_len: usize, mut op: F) -> u128 {
    let start = Instant::now();
    for index in 0..pool_len {
        op(index);
    }
    let total = start.elapsed();
    total.as_nanos() / pool_len.max(1) as u128
}

/// Extracts the decrypted payload length from a processed receive result.
/// Panics on unexpected event kinds: measurement frames are valid by design.
fn payload_len_of(event: &SigilEvent<DATA_CAP, MSG_CAP>) -> usize {
    match event {
        SigilEvent::Data { payload, .. } => payload.len(),
        SigilEvent::Event { payload, .. } => payload.len(),
        other => panic!("unexpected event kind during measurement: {other:?}"),
    }
}

/// Measures the gateway-side Event receive path at several application
/// payload sizes and compares it with a matched-size Data receive (identical
/// AEAD plaintext size). Structural copy counts are printed alongside each
/// row:
///
/// - Data receive: **1** large copy — the single decrypt destination buffer
///   is moved into the returned event untouched;
/// - Event receive: **1** large copy — the same decrypt destination buffer is
///   moved into the delivery handler and the 8-byte id is stripped in place;
///   no second `DATA`-capacity buffer is created.
///
/// The remaining Event-vs-Data delta is the durable-delivery transaction
/// bookkeeping, not copying. The Event row times `receive + delivery
/// release` because a fresh Event id cannot be accepted while a delivery
/// stays pending; the release itself is an O(1) state clear with no crypto
/// or copying.
#[test]
fn perf_measurements_event_receive_copies_and_time() {
    println!("Event vs Data receive baseline ({POOL} frames per pass, best of {PASSES}):");
    println!("  app L | pt len | data ns/op | event recv+release ns/op | large copies data/event");

    for app_len in EVENT_PAYLOAD_LENGTHS {
        // --- Build both pools up front on the test heap, each from its own
        // independent sensor instance so both pools start at TX counter 0
        // (a fresh receiver accepts counters only within the replay window
        // above its initial expectation of 0). Data plaintexts are sized
        // `8 + app_len` so decrypted sizes match the Event rows exactly.
        let (mut data_sensor, _) = measurement_pair();
        let data_payload = vec![0xABu8; 8 + app_len];
        let mut data_pool: std::vec::Vec<Vec<u8, MSG_CAP>> = std::vec::Vec::new();
        for _ in 0..POOL {
            let frame = data_sensor
                .encrypt_data::<MSG_CAP>(&REMOTE, black_box(&data_payload[..]), 1_000)
                .unwrap();
            data_pool.push(frame);
        }
        // Event sends start an ACK wait per id; cancellation does not alter
        // already-built wire bytes and frees the wait for the next distinct id.
        let (mut event_sensor, _) = measurement_pair();
        let event_payload = vec![0xCDu8; app_len];
        let mut event_pool: std::vec::Vec<Vec<u8, MSG_CAP>> = std::vec::Vec::new();
        for id in 1..=POOL as u64 {
            let action = event_sensor
                .send_event::<MSG_CAP>(&REMOTE, id, black_box(&event_payload[..]), 1_000)
                .unwrap();
            event_sensor.cancel_pending_event(&REMOTE, id).unwrap();
            let frame = match action {
                SigilAction::Transmit { payload, .. } => payload,
                _ => panic!("expected Transmit action"),
            };
            event_pool.push(frame);
        }

        // Correctness passes validate sizes and acceptance before timing;
        // they run on their own receivers so they never consume the pools'
        // single-use authentication on a timed receiver.
        {
            let (_, mut gateway) = measurement_pair();
            for frame in &data_pool {
                let (event, _) = gateway
                    .process_incoming_packet::<DATA_CAP, MSG_CAP>(frame, 1_000)
                    .unwrap();
                assert_eq!(payload_len_of(&event), 8 + app_len);
            }
        }
        {
            let (_, mut gateway) = measurement_pair();
            for (index, frame) in event_pool.iter().enumerate() {
                let (event, _) = gateway
                    .process_incoming_packet::<DATA_CAP, MSG_CAP>(frame, 1_000)
                    .unwrap();
                assert_eq!(payload_len_of(&event), app_len);
                gateway
                    .release_event_delivery(&LOCAL, index as u64 + 1)
                    .unwrap();
            }
        }

        // Timed Data passes: fresh receiver per pass, strict counter order.
        let mut data_ns = u128::MAX;
        for _ in 0..PASSES {
            let (_, mut gateway) = measurement_pair();
            let ns = time_pass_ns(POOL, |index| {
                let (event, _) = gateway
                    .process_incoming_packet::<DATA_CAP, MSG_CAP>(&data_pool[index], 1_000)
                    .unwrap();
                black_box(payload_len_of(&event));
            });
            data_ns = data_ns.min(ns);
        }

        // Timed Event passes including the mandatory delivery release.
        let mut event_ns = u128::MAX;
        for _ in 0..PASSES {
            let (_, mut gateway) = measurement_pair();
            let ns = time_pass_ns(POOL, |index| {
                let (event, _) = gateway
                    .process_incoming_packet::<DATA_CAP, MSG_CAP>(&event_pool[index], 1_000)
                    .unwrap();
                black_box(payload_len_of(&event));
                gateway
                    .release_event_delivery(&LOCAL, index as u64 + 1)
                    .unwrap();
            });
            event_ns = event_ns.min(ns);
        }

        println!(
            "  {app_len:>5} | {pt:>6} | {data_ns:>10} | {event_ns:>24} | 1 / 1",
            pt = 8 + app_len,
        );
    }
}

/// Measures the clear-text handshake classification cost through
/// `process_incoming_packet`: outer-header parse, `FrameType` routing, and
/// exactly **one** bulk full-frame copy into the `MSG` event buffer (no
/// decryption, no session lookup). Three representative wire sizes are
/// classified: a minimal 40-byte handshake frame and the two largest install
/// frames (215-byte InstallRequest, 219-byte InstallChallenge).
#[test]
fn perf_measurements_handshake_classification_copies() {
    // Bare managers are sufficient: handshake arms classify without touching
    // the session table. A gateway-role build classifies request/confirm
    // steps; under --all-features both directions compile.
    let mut manager: SessionManager<4> = crate::core::test_support::test_manager();

    // Deterministic frame corpus: correct protocol version + discriminator,
    // arbitrary body bytes (classification parses only the outer header).
    let scenarios: [(&str, FrameType, usize); 3] = [
        ("minimal-handshake", FrameType::ResumeRequest, 40),
        ("install-request", FrameType::InstallRequest, 215),
        ("install-challenge", FrameType::InstallChallenge, 219),
    ];

    println!("Handshake classification baseline ({CLASSIFY_ITERATIONS} iterations per row):");
    println!("  frame              | wire len | ns/op | large copies");
    for (name, frame_type, len) in scenarios {
        let mut packet = vec![0u8; len];
        packet[FRAME_TYPE_OFFSET] = frame_type as u8;
        packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
        packet[..17].copy_from_slice(&[3u8; 17]);

        // Correctness pass: must classify per-step without decryption.
        let (event, action) = manager
            .process_incoming_packet::<DATA_CAP, MSG_CAP>(&packet, 1_000)
            .unwrap();
        assert!(matches!(action, SigilAction::NeedsHostDispatch { .. }));
        match event {
            SigilEvent::InstallRequest { frame, .. }
            | SigilEvent::InstallChallenge { frame, .. }
            | SigilEvent::ResumeRequest { frame, .. } => assert_eq!(frame.len(), len),
            other => panic!("unexpected classification result: {other:?}"),
        }

        let ns = time_pass_ns(CLASSIFY_ITERATIONS, |_| {
            let (event, action) = manager
                .process_incoming_packet::<DATA_CAP, MSG_CAP>(black_box(&packet), 1_000)
                .unwrap();
            black_box((payload_is_handshake(&event), action));
        });

        println!("  {name:<18} | {len:>8} | {ns:>5} | 1 bulk full-frame copy");
    }
}

/// Returns true when the classified event is one of the handshake variants
/// asserted above (keeps the timed closure branch-free of formatting work).
fn payload_is_handshake(event: &SigilEvent<DATA_CAP, MSG_CAP>) -> bool {
    matches!(
        event,
        SigilEvent::InstallRequest { .. }
            | SigilEvent::InstallChallenge { .. }
            | SigilEvent::ResumeRequest { .. }
    )
}

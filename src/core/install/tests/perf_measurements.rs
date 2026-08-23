//! Host-side install-admission performance measurements (dev-only).
//!
//! Quantifies the gateway admission phase of `handle_install_request` at
//! empty / half / full cooldown-table occupancy (`K = 0 / 64 / 128` on a
//! gateway-sized manager). Two complementary sections:
//!
//! 1. **Admission phases** — times exactly the two `AdmissionStore` calls an
//!    accepted request performs, in production order: the single-scan decide
//!    phase (`admit_install`, which purges expired entries once and then
//!    applies the cooldown and capacity guards) and the post-authentication
//!    stamp (`stamp_install_request`, which never scans). The rotation
//!    re-stamps already-known peers so occupancy stays constant across
//!    iterations (inserting a fresh peer per call would grow the table and
//!    change the measured scenario mid-loop; the insert cost of a new key
//!    equals that of replacing a known key).
//! 2. **End-to-end handler** — full `handle_install_request` with mock SE:
//!    accepted requests (fresh sensors) at `K = 0 / 64`, and the saturated
//!    guard-only rejection (`AdmissionTableFull`) at `K = 128`, which is
//!    mutation-free and therefore loopable.
//!
//! Structural scan counts (source-level facts, printed for the record): the
//! decide phase purges expired entries exactly once and shares that single
//! O(K) scan across all of its decisions, so an **accepted** request
//! performs **1** full-table admission scan, and the **rate-limited** and
//! **admission-saturated** rejections also perform exactly **1** (they exit
//! inside the same decide call, before any stamp). Host wall-clock numbers
//! are informational only.
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

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::manager::SessionManager;
use crate::core::session::PeerId;
use crate::core::test_support::{MockRandom, MockSecureElement};

/// Gateway-sized capacity matching the production default.
const CAPACITY: usize = 128;
/// Cooldown-occupancy scenarios: empty, half, full.
const OCCUPANCY: [usize; 3] = [0, 64, 128];
/// Iterations per timed helper section.
const HELPER_ITERATIONS: u32 = 20_000;
/// Distinct fresh sensors per timed end-to-end accepted pass.
const ACCEPT_POOL: usize = 32;
/// Timebase (host seconds). Stamps filled at `FILL_NOW` stay inside the
/// 15-second install cooldown window during every measured call.
const FILL_NOW: u32 = 1_000;
/// Gateway local MAC used by the measured gateway managers.
const GW_MAC: [u8; 17] = [0x72u8; 17];
/// Session-key lifetime passed to the handler (seconds).
const KEY_LIFETIME_SECS: u32 = 86_400;

/// Distinct synthetic sensor identity for index `k`.
fn sensor_mac_at(k: usize) -> PeerId {
    let mut mac = [0x70u8; 17];
    mac[0] = (k & 0xFF) as u8;
    mac[1] = ((k >> 8) & 0xFF) as u8;
    mac
}

/// Times `iterations` executions of `op`; returns nanoseconds per operation
/// (host wall clock, informational only).
fn time_ns_per_op<F: FnMut()>(iterations: u32, mut op: F) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        op();
    }
    let total = start.elapsed();
    total.as_nanos() / u128::from(iterations.max(1))
}

/// Builds a valid clear-text InstallRequest frame from a fresh deterministic
/// sensor identity using the shared mock secure element.
fn build_request_frame(k: usize) -> heapless::Vec<u8, 256> {
    let mac = sensor_mac_at(k);
    let mut sensor: SessionManager<2> = crate::core::test_support::test_manager_with_mac(mac);
    let mut se_sensor = MockSecureElement::sensor((k % 251 + 1) as u8, mac);
    let mut rng_sensor = MockRandom::new();
    match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, FILL_NOW)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit an InstallRequest"),
    }
}

/// Measures the admission phases of an accepted request at empty / half /
/// full cooldown occupancy, rotating over already-stamped peers so table
/// size stays fixed. The decide phase is shape-invariant — one purge and the
/// same lookup path whether it admits, rate-limits, or saturates — so its
/// measured cost composes with the scan-free stamp into the accepted phase.
/// Prints the structural purge-scan counts next to each timing.
#[test]
fn perf_measurements_install_admission_helper_trio() {
    println!(
        "Install admission phases ({HELPER_ITERATIONS} iterations per row, stamps kept live):"
    );
    println!("  K | decide ns/op | stamp ns/op | scans/request (every shape)");

    for k in OCCUPANCY {
        let mut gateway: SessionManager<CAPACITY> =
            crate::core::test_support::test_manager_with_mac(GW_MAC);
        // Fill the cooldown table with live (unexpired) stamps.
        for k_index in 0..k {
            gateway
                .stamp_install_request(sensor_mac_at(k_index), FILL_NOW)
                .unwrap();
        }

        // Rotation cursor over stamped peers (no-op rotation at K = 0 where
        // the decision takes the fresh-peer branch instead).
        let mut rotate = 0usize;
        let decide_ns = time_ns_per_op(HELPER_ITERATIONS, || {
            let peer = if k == 0 {
                sensor_mac_at(usize::MAX)
            } else {
                sensor_mac_at(rotate % k)
            };
            rotate = rotate.wrapping_add(1);
            let decision = gateway.admit_install(black_box(&peer), FILL_NOW);
            if k == 0 {
                assert!(decision.is_ok(), "fresh peer must be admitted");
            } else {
                // Live cooldown: the rate-limited guard fires before any
                // capacity consideration, proving the documented order.
                assert_eq!(decision, Err(SigilError::RateLimited { peer }));
            }
            black_box(decision.is_ok());
        });

        let mut rotate_stamp = 0usize;
        let stamp_ns = time_ns_per_op(HELPER_ITERATIONS, || {
            let peer = if k == 0 {
                sensor_mac_at(usize::MAX)
            } else {
                sensor_mac_at(rotate_stamp % k)
            };
            rotate_stamp = rotate_stamp.wrapping_add(1);
            // Re-stamping a known peer replaces its value without growing the
            // table, keeping the measured occupancy constant.
            gateway.stamp_install_request(peer, FILL_NOW).unwrap();
        });

        assert_eq!(
            gateway.len(),
            0,
            "admission measurements create no sessions"
        );
        println!(
            "  {k:>1} | {decide_ns:>12} | {stamp_ns:>11} | 1 x O(K) retain (accepted, rate-limited, saturated)"
        );
    }
}

/// Measures the end-to-end `handle_install_request` cost: accepted installs
/// from fresh sensors at `K = 0 / 64` (mock-SE crypto dominates), and the
/// saturated guard-only rejection at `K = 128`, which returns
/// [`SigilError::AdmissionTableFull`] before any SE work and never mutates
/// state, so it can be looped.
#[test]
fn perf_measurements_install_request_end_to_end() {
    let mut se_gateway = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_gateway = MockRandom::new();

    // Accepted passes at empty and half occupancy.
    for &k in &OCCUPANCY[..2] {
        let mut gateway: SessionManager<CAPACITY> =
            crate::core::test_support::test_manager_with_mac(GW_MAC);
        for k_index in 0..k {
            gateway
                .stamp_install_request(sensor_mac_at(k_index), FILL_NOW)
                .unwrap();
        }
        // Pre-build one request per distinct fresh sensor (untimed).
        let frames: std::vec::Vec<heapless::Vec<u8, 256>> = (0..ACCEPT_POOL)
            .map(|index| build_request_frame(k * 1000 + index))
            .collect();

        let start = Instant::now();
        for frame in &frames {
            match gateway.handle_install_request::<256>(
                black_box(frame),
                &mut se_gateway,
                &mut rng_gateway,
                FILL_NOW + 1,
                KEY_LIFETIME_SECS,
            ) {
                Ok(SigilAction::Transmit { .. }) => {}
                other => panic!("expected accepted install, got {other:?}"),
            }
        }
        let elapsed = start.elapsed();
        let per_accept = elapsed.as_nanos() / ACCEPT_POOL as u128;
        assert_eq!(gateway.pending_len(), ACCEPT_POOL);
        println!(
            "accepted install @ K={k}: {per_accept} ns/request incl. mock-SE chain (occupancy drifts to K={end})",
            end = k + ACCEPT_POOL,
        );
    }

    // Saturated guard path: full table rejects before any SE work and does
    // not mutate, so repeated calls measure the pure guard phase.
    let mut gateway: SessionManager<CAPACITY> =
        crate::core::test_support::test_manager_with_mac(GW_MAC);
    for k_index in 0..CAPACITY {
        gateway
            .stamp_install_request(sensor_mac_at(k_index), FILL_NOW)
            .unwrap();
    }
    let frame = build_request_frame(u16::MAX as usize);
    let saturated_ns = time_ns_per_op(HELPER_ITERATIONS, || {
        let result = gateway.handle_install_request::<256>(
            black_box(&frame),
            &mut se_gateway,
            &mut rng_gateway,
            FILL_NOW + 1,
            KEY_LIFETIME_SECS,
        );
        assert_eq!(result.unwrap_err(), SigilError::AdmissionTableFull);
    });
    println!(
        "saturated rejection @ K=128: {saturated_ns} ns/request (guard phase only, no SE work)"
    );
}

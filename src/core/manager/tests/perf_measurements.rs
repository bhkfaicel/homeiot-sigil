//! Host-side manager performance measurements (dev-only).
//!
//! Two measurement areas, both tied to recorded audit findings:
//!
//! 1. **`tick(now)` pending occupancy** — quantifies the O(P) full-table
//!    scan (plus removals) at empty / half / full pending occupancy on a
//!    gateway-sized manager (`N = 128`). Both a scan-only tick (nothing
//!    expired) and a purging tick are measured; removed-entry counts are
//!    asserted so the deterministic part of the measurement is exact.
//! 2. **FNV-indexed session lookup** — quantifies expected-O(1)
//!    `FnvIndexMap` access cost at 1 / 64 / 128 distinct keys, the lookup
//!    shape used by every authenticated ingress and egress operation.
//!
//! Host wall-clock numbers are informational only; they must never be read
//! as target metrics. Run:
//! `cargo test --locked --all-features perf_measurements -- --nocapture`

// The crate is `no_std`; the unit-test harness links `std` on the host, which
// provides the monotonic clock used for the informational timings.
extern crate std;

// Pull the handful of `std` macros used by this dev-only suite into scope
// (`no_std` builds have an empty macro prelude even under `cfg(test)`).
use std::println;

use std::hint::black_box;
use std::time::Instant;

use crate::core::install::INSTALL_TIMEOUT_MS;
use crate::core::manager::SessionManager;
use crate::core::pending::PendingHandshake;
use crate::core::session::{DirectionalMaterial, PeerId, Session, SessionRole};

/// Gateway-sized capacity matching the production default.
const CAPACITY: usize = 128;
/// Pending-occupancy scenarios: empty, half, full.
const PENDING_OCCUPANCY: [usize; 3] = [0, 64, 128];
/// Session-table occupancies for the lookup scenario: single peer,
/// half table, full table.
const LOOKUP_OCCUPANCY: [usize; 3] = [1, 64, 128];
/// Iterations per timed scan-only section.
const TICK_ITERATIONS: u32 = 10_000;
/// Lookups per timed section for the FNV map scenario.
const LOOKUP_ITERATIONS: u32 = 200_000;
/// Timed passes per purging sample; the minimum sample is reported.
const PURGE_PASSES: u32 = 3;
/// Insertion timebase (host seconds). Deadlines land at `INSERT_NOW + 30`.
const INSERT_NOW: u32 = 1_000;
/// Symmetric session material for lookup-fixture sessions (test-only value).
const KEY: [u8; 32] = [0x42u8; 32];
const PREFIX: [u8; 4] = [0x01u8; 4];
/// Durable resume PSK carried by the active test sessions (test-only value).
const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

/// Distinct synthetic peer identity for index `k` (deterministic, unique per
/// `k < 65536` via two key bytes).
fn peer_at(k: usize) -> PeerId {
    let mut mac = [0x50u8; 17];
    mac[0] = (k & 0xFF) as u8;
    mac[1] = ((k >> 8) & 0xFF) as u8;
    mac
}

/// Builds an active symmetric session keyed by `peer` (test-only fixture).
fn active_session(peer: PeerId) -> Session {
    Session::new_active(
        peer,
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
        SessionRole::Gateway,
        &RESUME_PSK,
        INSERT_NOW + 100_000,
        INSERT_NOW,
    )
    .unwrap()
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

/// Measures [`SessionManager::tick`] at empty / half / full pending
/// occupancy. Two sections per occupancy level:
///
/// - **scan-only** — every entry is still inside its deadline window, so the
///   tick performs exactly one full O(P) iteration and removes nothing
///   (`P = K`, asserted empty result);
/// - **purge** — `now` equals the shared deadline, so the same single pass
///   collects and removes all `K` pre-commit entries (asserted count).
///
/// The purge sample rebuilds the table outside the timer for each of the
/// three passes and reports the best sample.
#[test]
fn perf_measurements_tick_pending_occupancy() {
    println!(
        "tick baseline on SessionManager<{CAPACITY}> (scan-only {TICK_ITERATIONS} iterations):"
    );
    println!("  pending K | scan-only ns/op | purge ns/entry | entries removed");

    for k in PENDING_OCCUPANCY {
        let mut manager: SessionManager<CAPACITY> = crate::core::test_support::test_manager();
        // Pre-commit install-sensor pendings with a shared deadline:
        // deadline = INSERT_NOW + ceil(INSTALL_TIMEOUT_MS / 1000) = 1_030.
        for k_index in 0..k {
            let handshake = PendingHandshake::new_install_sensor(
                peer_at(k_index),
                [(k_index & 0xFF) as u8; 16],
                INSTALL_TIMEOUT_MS,
                INSERT_NOW,
            );
            manager.insert_pending(peer_at(k_index), handshake).unwrap();
        }
        assert_eq!(manager.pending_len(), k);
        let deadline = INSERT_NOW + INSTALL_TIMEOUT_MS.div_ceil(1000);

        // Scan-only section: nothing expired, no mutation happens.
        let scan_ns = time_ns_per_op(TICK_ITERATIONS, || {
            let purged = manager.tick(INSERT_NOW);
            assert!(purged.is_empty());
            black_box(purged);
        });

        // Purge samples: fresh table per pass, one collecting tick each.
        let mut purge_ns_per_entry = u128::MAX;
        for _ in 0..PURGE_PASSES {
            let mut fresh: SessionManager<CAPACITY> = crate::core::test_support::test_manager();
            for k_index in 0..k {
                let handshake = PendingHandshake::new_install_sensor(
                    peer_at(k_index),
                    [(k_index & 0xFF) as u8; 16],
                    INSTALL_TIMEOUT_MS,
                    INSERT_NOW,
                );
                fresh.insert_pending(peer_at(k_index), handshake).unwrap();
            }
            let start = Instant::now();
            let purged = fresh.tick(deadline);
            let elapsed = start.elapsed().as_nanos();
            assert_eq!(purged.len(), k);
            assert_eq!(fresh.pending_len(), 0);
            purge_ns_per_entry =
                purge_ns_per_entry.min(if k == 0 { elapsed } else { elapsed / k as u128 });
        }

        println!("  {k:>9} | {scan_ns:>15} | {purge_ns_per_entry:>14} | {k}");
    }
}

/// Measures expected-O(1) session lookups through the public facade
/// (`SessionManager::get`) at 1 / 64 / 128 distinct keys. Keys rotate over
/// the inserted set so every measured access is a hit, mirroring the
/// authenticated ingress/egress lookup shape.
#[test]
fn perf_measurements_fnv_lookup_by_occupancy() {
    println!("FNV session-lookup baseline ({LOOKUP_ITERATIONS} iterations per row):");
    println!("  sessions M | hit ns/op");
    for m in LOOKUP_OCCUPANCY {
        let mut manager: SessionManager<CAPACITY> = crate::core::test_support::test_manager();
        let keys: heapless::Vec<PeerId, CAPACITY> = (0..m)
            .map(|k| {
                let peer = peer_at(k);
                manager.insert(active_session(peer)).unwrap();
                peer
            })
            .collect();
        assert_eq!(manager.len(), m);

        let mut rotate = 0usize;
        let ns = time_ns_per_op(LOOKUP_ITERATIONS, || {
            let key = keys[rotate % m];
            rotate = rotate.wrapping_add(1);
            let session = manager.get(black_box(&key));
            assert!(session.is_some());
            black_box(session);
        });
        println!("  {m:>10} | {ns:>8}");
    }
}

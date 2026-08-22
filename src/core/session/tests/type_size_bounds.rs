//! Library-owned type-size regression bounds for [`Session`].
//!
//! # Purpose
//! These assertions fail whenever `Session` grows beyond its approved byte
//! bound, so a silent footprint regression cannot merge unnoticed.
//!
//! # Measurement basis
//! Sizes are measured with [`size_of`] on the **host test target**. They are a
//! crate-internal regression contract only: final flash, static RAM, and stack
//! budgets remain the **host firmware's** responsibility, measured and enforced
//! on its own final linked image for the chosen target and feature set (see
//! the crate-level footprint contract in `src/lib.rs`). Latest record refresh:
//! 2026-08-22, transcribed from the crate-owner-approved measurement source
//! `docs/footprint-report.md`.
//!
//! # Measured sizes (host, bytes)
//! The size legitimately differs per feature configuration because `Session`
//! carries role-gated bookkeeping fields (sensor: pending/last TX event ids;
//! gateway: resume/time-sync request stamps and RX event ids):
//!
//! | Configuration | Measured | Approved bound |
//! |---------------|----------|----------------|
//! | `sensor` only | 216      | 224            |
//! | `gateway` only| 232      | 240            |
//! | `sensor,gateway` | 264   | 272            |
//!
//! Bound rule: the measured size rounded up to the next 16-byte boundary
//! (8-24 bytes of explicit headroom), keeping small layout shifts legal while
//! catching any field addition or widening.
//!
//! # Why the two-role build guards every configuration
//! This suite executes in the two-role configuration, where **every** role-gated
//! field is present. A mono-role build only ever removes fields, so its size is
//! strictly smaller than the two-role superset asserted here; growth in any
//! configuration is therefore caught by this bound. The per-configuration
//! constants below stay parameterized so the assertions remain correct if the
//! suite is ever compiled for a mono-role configuration.
//!
//! # Integrator guidance
//! When budgeting static RAM for a session table, use the recorded size of
//! **your** feature configuration as the per-peer cost (for example inside
//! `SessionManager<N>`), then re-measure on the final target: target layout
//! may differ from the host measurements recorded here.
//!
//! # Approval path for raising a bound
//! Raising a bound is a crate-owner decision that must be recorded in a new
//! revision-history entry of this repository's architecture plan; never raise
//! a bound silently to make a test pass.

use core::mem::size_of;

use crate::core::session::Session;

/// Approved `Session` byte bound for sensor-only builds (measured 216).
#[cfg(all(feature = "sensor", not(feature = "gateway")))]
const SESSION_MAX_BYTES: usize = 224;

/// Approved `Session` byte bound for gateway-only builds (measured 232).
#[cfg(all(feature = "gateway", not(feature = "sensor")))]
const SESSION_MAX_BYTES: usize = 240;

/// Approved `Session` byte bound for the two-role composition (measured 264).
#[cfg(all(feature = "sensor", feature = "gateway"))]
const SESSION_MAX_BYTES: usize = 272;

#[test]
fn session_size_stays_within_its_approved_bound() {
    assert!(
        size_of::<Session>() <= SESSION_MAX_BYTES,
        "Session size {} bytes exceeds the approved bound of {} bytes; \
         growth requires an explicit crate-owner decision",
        size_of::<Session>(),
        SESSION_MAX_BYTES
    );
}

//! Library-owned type-size regression bounds for [`SessionManager`].
//!
//! # Purpose
//! These assertions fail whenever `SessionManager<N>` grows beyond its approved
//! byte bounds for the two reference capacities: `N = 2` (single-peer sensor
//! default) and `N = 128` (gateway default), so a silent footprint regression
//! cannot merge unnoticed.
//!
//! # Measurement basis
//! Sizes are measured with [`size_of`] on the **host test target**. They are a
//! crate-internal regression contract only: final flash, static RAM, and stack
//! budgets remain the **host firmware's** responsibility, measured and enforced
//! on its own final linked image for the chosen target and feature set (see
//! the crate-level footprint contract in `src/lib.rs`).
//!
//! # Measured sizes (host, bytes)
//! The size legitimately differs per feature configuration because the manager
//! carries a gateway-gated per-peer install-cooldown map in addition to the
//! session and pending tables (both scale linearly with `N`):
//!
//! | Configuration   | `SessionManager<2>` | Bound | `SessionManager<128>` | Bound  |
//! |-----------------|---------------------|-------|----------------------|--------|
//! | `sensor` only   | 1336                | 1344  | 80968                | 80976  |
//! | `gateway` only  | 1432                | 1440  | 86608                | 86624  |
//! | `sensor,gateway`| 1496                | 1504  | 90704                | 90720  |
//!
//! Bound rule: the measured size rounded up to the next 16-byte boundary
//! (8-24 bytes of explicit headroom), keeping small layout shifts legal while
//! catching any field addition or map widening.
//!
//! # Why the two-role build guards every configuration
//! This suite executes in the two-role configuration, where **every** role-gated
//! field is present. A mono-role build only ever removes fields, so its size is
//! strictly smaller than the two-role superset asserted here; growth in any
//! configuration is therefore caught by these bounds. The per-configuration
//! constants below stay parameterized so the assertions remain correct if the
//! suite is ever compiled for a mono-role configuration.
//!
//! # Integrator guidance
//! When budgeting static RAM, treat the manager as the dominant fixed
//! allocation of the library: roughly 1.5 KiB for a `SessionManager<2>` sensor
//! and 80-91 KiB for a `SessionManager<128>` gateway, for the recorded feature
//! configuration. Re-measure on the final target: target layout may differ
//! from the host measurements recorded here.
//!
//! # Approval path for raising a bound
//! Raising a bound is a crate-owner decision that must be recorded in a new
//! revision-history entry of this repository's architecture plan; never raise
//! a bound silently to make a test pass.

use core::mem::size_of;

use crate::core::manager::SessionManager;

/// Approved `SessionManager<2>` byte bound for sensor-only builds (measured 1336).
#[cfg(all(feature = "sensor", not(feature = "gateway")))]
const MANAGER2_MAX_BYTES: usize = 1344;

/// Approved `SessionManager<2>` byte bound for gateway-only builds (measured 1432).
#[cfg(all(feature = "gateway", not(feature = "sensor")))]
const MANAGER2_MAX_BYTES: usize = 1440;

/// Approved `SessionManager<2>` byte bound for the two-role composition (measured 1496).
#[cfg(all(feature = "sensor", feature = "gateway"))]
const MANAGER2_MAX_BYTES: usize = 1504;

/// Approved `SessionManager<128>` byte bound for sensor-only builds (measured 80968).
#[cfg(all(feature = "sensor", not(feature = "gateway")))]
const MANAGER128_MAX_BYTES: usize = 80976;

/// Approved `SessionManager<128>` byte bound for gateway-only builds (measured 86608).
#[cfg(all(feature = "gateway", not(feature = "sensor")))]
const MANAGER128_MAX_BYTES: usize = 86624;

/// Approved `SessionManager<128>` byte bound for the two-role composition (measured 90704).
#[cfg(all(feature = "sensor", feature = "gateway"))]
const MANAGER128_MAX_BYTES: usize = 90720;

#[test]
fn manager_capacity_two_stays_within_its_approved_bound() {
    assert!(
        size_of::<SessionManager<2>>() <= MANAGER2_MAX_BYTES,
        "SessionManager<2> size {} bytes exceeds the approved bound of {} bytes; \
         growth requires an explicit crate-owner decision",
        size_of::<SessionManager<2>>(),
        MANAGER2_MAX_BYTES
    );
}

#[test]
fn manager_capacity_one_hundred_twenty_eight_stays_within_its_approved_bound() {
    assert!(
        size_of::<SessionManager<128>>() <= MANAGER128_MAX_BYTES,
        "SessionManager<128> size {} bytes exceeds the approved bound of {} bytes; \
         growth requires an explicit crate-owner decision",
        size_of::<SessionManager<128>>(),
        MANAGER128_MAX_BYTES
    );
}

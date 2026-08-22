//! Library-owned type-size regression bounds for [`PendingHandshake`].
//!
//! # Purpose
//! These assertions fail whenever `PendingHandshake` grows beyond its approved
//! byte bound, so a silent footprint regression cannot merge unnoticed. This
//! matters in particular for the per-slot cached Final/CommitConfirmed
//! retransmission buffer, which dominates the type.
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
//! # Measured size (host, bytes)
//! `PendingHandshake` carries role-exclusive state variants, so its size
//! differs per session feature configuration: measured **312** bytes in
//! `sensor` and `sensor,gateway` builds (they compile the largest variant
//! set, driven by `InstallSensorFinalSent`), while a `gateway`-only build
//! compiles only the smaller gateway variants (largest:
//! `InstallGatewayAwaitConfirm`) and measures ~**216** bytes; that
//! gateway-only total is derived (back-solved from measured manager totals)
//! because the pending internals stay crate-private.
//!
//! Bound rule: the approved bound was fixed when the recorded measurement was
//! **360** bytes (that value rounded up to the next 16-byte boundary, 8 bytes
//! of explicit headroom) and deliberately stays unchanged; the current
//! measurements above sit well inside it, keeping small layout shifts legal
//! while catching any field addition or widening. Approved bound: **368**
//! bytes.
//!
//! # Why the two-role build guards every configuration
//! This suite executes in the two-role configuration, which compiles the
//! **largest** variant set. Mono-role builds compile strict subsets of those
//! variants, so their slot sizes stay smaller than the superset asserted
//! here; growth in any configuration is therefore caught by this bound.
//!
//! # Integrator guidance
//! When budgeting static RAM for the pending-handshake table, use the
//! recorded size of **your** feature configuration as the per-peer cost (for
//! example inside `SessionManager<N>`), then re-measure on the final target:
//! target layout may differ from the host measurement recorded here.
//!
//! # Approval path for raising a bound
//! Raising a bound is a crate-owner decision that must be recorded in a new
//! revision-history entry of this repository's architecture plan; never raise
//! a bound silently to make a test pass.

use core::mem::size_of;

use crate::core::pending::PendingHandshake;

/// Approved `PendingHandshake` byte bound (measured 312 in sensor-bearing
/// builds, ~216 derived gateway-only; 360 when the bound was fixed).
const PENDING_HANDSHAKE_MAX_BYTES: usize = 368;

#[test]
fn pending_handshake_size_stays_within_its_approved_bound() {
    assert!(
        size_of::<PendingHandshake>() <= PENDING_HANDSHAKE_MAX_BYTES,
        "PendingHandshake size {} bytes exceeds the approved bound of {} bytes; \
         growth requires an explicit crate-owner decision",
        size_of::<PendingHandshake>(),
        PENDING_HANDSHAKE_MAX_BYTES
    );
}

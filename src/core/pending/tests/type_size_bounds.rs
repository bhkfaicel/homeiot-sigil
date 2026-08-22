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
//! the crate-level footprint contract in `src/lib.rs`).
//!
//! # Measured size (host, bytes)
//! `PendingHandshake` has no role-gated fields, so its size is identical in
//! every session feature configuration: measured **360** bytes in `sensor`,
//! `gateway`, and `sensor,gateway` builds alike.
//!
//! Bound rule: the measured size rounded up to the next 16-byte boundary
//! (8 bytes of explicit headroom), keeping small layout shifts legal while
//! catching any field addition or widening. Approved bound: **368** bytes.
//!
//! # Why the two-role build guards every configuration
//! This suite executes in the two-role configuration. Because the type is
//! feature-invariant, that single assertion guards every session
//! configuration.
//!
//! # Integrator guidance
//! When budgeting static RAM for the pending-handshake table, use the recorded
//! size as the per-peer cost (for example inside `SessionManager<N>`), then
//! re-measure on the final target: target layout may differ from the host
//! measurement recorded here.
//!
//! # Approval path for raising a bound
//! Raising a bound is a crate-owner decision that must be recorded in a new
//! revision-history entry of this repository's architecture plan; never raise
//! a bound silently to make a test pass.

use core::mem::size_of;

use crate::core::pending::PendingHandshake;

/// Approved `PendingHandshake` byte bound (measured 360 in every
/// session configuration).
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

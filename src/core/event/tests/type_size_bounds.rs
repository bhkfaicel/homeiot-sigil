//! Library-owned type-size regression bounds for [`SigilEvent`] and
//! [`SigilAction`].
//!
//! # Purpose
//! These assertions fail whenever the event/action exchange types grow beyond
//! their approved byte bounds, so a silent footprint regression cannot merge
//! unnoticed. Hosts return these types **by value** from the processing
//! pipeline, so their size also drives per-call stack usage in host firmware.
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
//! The asserted generic parameters are the documented LoRa defaults
//! (`DATA_MAX` = 200, `MSG_MAX` = 256). Neither type has role-gated fields, so
//! the sizes are identical in every session feature configuration: measured
//! **288** bytes for `SigilEvent<200, 256>` and **360** bytes for
//! `SigilAction<256>` in `sensor`, `gateway`, and `sensor,gateway` builds
//! alike.
//!
//! Bound rule: the measured size rounded up to the next 16-byte boundary
//! (8-24 bytes of explicit headroom), keeping small layout shifts legal while
//! catching any field addition or widening. Approved bounds: **304** and
//! **368** bytes.
//!
//! # Why every session configuration is guarded
//! This suite executes in **every** session feature configuration, and the
//! asserted sizes are feature-invariant, so each run directly guards all
//! supported configurations.
//!
//! # Integrator guidance
//! When budgeting stack for the packet-processing call path, account for one
//! returned `SigilEvent` plus one `SigilAction` (about 0.6 KiB combined at the
//! default LoRa capacities). Custom `DATA`/`MSG` generic parameters scale the
//! embedded buffers; re-measure for your parameters and final target, since
//! target layout may differ from the host measurements recorded here.
//!
//! # Approval path for raising a bound
//! Raising a bound is a crate-owner decision that must be recorded in a new
//! revision-history entry of this repository's architecture plan; never raise
//! a bound silently to make a test pass.

use core::mem::size_of;

use crate::core::event::{SigilAction, SigilEvent};

/// Approved `SigilEvent<200, 256>` byte bound (measured 288 in every
/// session configuration).
const SIGIL_EVENT_MAX_BYTES: usize = 304;

/// Approved `SigilAction<256>` byte bound (measured 360 in every session
/// configuration).
const SIGIL_ACTION_MAX_BYTES: usize = 368;

#[test]
fn sigil_event_size_stays_within_its_approved_bound() {
    assert!(
        size_of::<SigilEvent<200, 256>>() <= SIGIL_EVENT_MAX_BYTES,
        "SigilEvent<200, 256> size {} bytes exceeds the approved bound of {} bytes; \
         growth requires an explicit crate-owner decision",
        size_of::<SigilEvent<200, 256>>(),
        SIGIL_EVENT_MAX_BYTES
    );
}

#[test]
fn sigil_action_size_stays_within_its_approved_bound() {
    assert!(
        size_of::<SigilAction<256>>() <= SIGIL_ACTION_MAX_BYTES,
        "SigilAction<256> size {} bytes exceeds the approved bound of {} bytes; \
         growth requires an explicit crate-owner decision",
        size_of::<SigilAction<256>>(),
        SIGIL_ACTION_MAX_BYTES
    );
}

#![cfg(all(feature = "ota", feature = "sensor", feature = "gateway"))]
//! Host-verifiable `size_of` regression bounds for the OTA engines,
//! following the crate-wide footprint contract (see the crate-level
//! rustdoc): dominant fixed-capacity types must fail a test instead of
//! silently growing inside RTIC resources or on task stacks.
//!
//! Measured baselines (host target, this crate, feature set
//! `sensor,gateway,ota`): `OtaSender` = 336 B, `OtaReceiver` = 376 B,
//! `BeginFrame` = 108 B, `TrailerRecord` = 44 B. The approved caps below add
//! explicit headroom for small additive fields; ANY growth beyond them is a
//! deliberate, reviewed decision that must update these numbers.
//!
//! Target-level flash/RAM/stack budgets remain the host firmware's
//! responsibility (see the performance-audit handoff note in the plan).

use crate::core::ota::trailer::TrailerRecord;
use crate::core::ota::{BeginFrame, OtaReceiver, OtaSender};
use core::mem::size_of;

/// The send half permanently embeds one max-size chunk buffer (196 B), the
/// manifest (108 B) and its scheduling state.
#[test]
fn ota_sender_size_bound() {
    assert!(
        size_of::<OtaSender>() <= 352,
        "OtaSender grew beyond the approved bound: {} bytes",
        size_of::<OtaSender>()
    );
}

/// The receive half embeds a SHA-256 state, the BEGIN copy and the 64-byte
/// erase-once bitmap.
#[test]
fn ota_receiver_size_bound() {
    assert!(
        size_of::<OtaReceiver>() <= 400,
        "OtaReceiver grew beyond the approved bound: {} bytes",
        size_of::<OtaReceiver>()
    );
}

#[test]
fn wire_metadata_type_bounds() {
    assert!(size_of::<BeginFrame>() <= 112);
    assert!(size_of::<TrailerRecord>() <= 48);
}

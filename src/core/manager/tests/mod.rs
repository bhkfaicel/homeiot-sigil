//! Unit tests for the session-manager facade tree.
//!
//! Gating contract of this tree:
//! - [`host_flows`] and [`capacity_domains`] are architecture-contract suites
//!   over the **public** facade; they compile in every session-bearing test
//!   build (`sensor`, `gateway`, and the explicit two-role composition) and
//!   select role-gated public API paths with per-test feature gates.
//! - [`facade`] holds the historical facade unit suite (storage semantics,
//!   tick / cancel housekeeping, commit-recovery abandonment, documented
//!   capacity constants). Its fixtures construct dual-role staging state and
//!   call dual-role test seams, so it keeps its original two-role gate and
//!   its execution set is unchanged.
//! - [`store_saturation`] and [`type_size_bounds`] stay two-role-gated like
//!   their original introduction; they share the fixtures below.

#![cfg(test)]

mod capacity_domains;
mod host_flows;

#[cfg(all(feature = "sensor", feature = "gateway"))]
mod facade;

#[cfg(all(feature = "sensor", feature = "gateway"))]
mod store_saturation;

#[cfg(all(feature = "sensor", feature = "gateway"))]
mod type_size_bounds;

// Replay-defense adversarial suite (dual-role: drives real sensor/gateway
// handshake flows through the public facade).
#[cfg(all(feature = "sensor", feature = "gateway"))]
mod replay_cache;

// Host-side performance measurement suite (dev-only, prints with
// --nocapture); uses the dual-role test seams below for pending fixtures.
#[cfg(all(feature = "sensor", feature = "gateway"))]
mod perf_measurements;

// Shared two-role fixtures (used by this module's gated children through
// `super::`). Compiled out of mono-role builds together with their callers.
#[cfg(all(feature = "sensor", feature = "gateway"))]
const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

/// Deterministic gateway-side install staging payload for pending-table
/// tests (phase content is irrelevant to capacity / tick scenarios).
#[cfg(all(feature = "sensor", feature = "gateway"))]
fn install_gateway_staged() -> crate::core::pending::InstallGatewayStaged {
    crate::core::pending::InstallGatewayStaged {
        keys: crate::core::session::DirectionalMaterial::symmetric_for_test(
            [0xCDu8; 32],
            [0xEFu8; 4],
        ),
        resume_psk: crate::core::pending::ResumePskStash::new(RESUME_PSK),
        sensor_static_pubkey: [0x02u8; 33],
        key_lifetime_secs: 86_400,
        gateway_nonce: crate::core::pending::Nonce16Stash::new([0x11u8; 16]),
        sensor_nonce: crate::core::pending::Nonce16Stash::new([0x22u8; 16]),
    }
}

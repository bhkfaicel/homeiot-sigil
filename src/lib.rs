//! `sigil`: a `no_std`, heap-free secure session engine for LoRa sensor and
//! gateway firmware. The host owns the radio, the clock, the secure element,
//! the CSPRNG, persistence, and scheduling; the library owns the protocol
//! state machine and its fixed-capacity storage.
//!
//! # Footprint contract
//! The library guards its dominant fixed-capacity types
//! (`Session`, `PendingHandshake`, `SessionManager<N>`, `SigilEvent`,
//! `SigilAction`) with `size_of` regression-bound tests located next to each
//! module. Those host-target measurements are the crate's internal regression
//! contract: they fail the test suite whenever a type grows beyond its
//! crate-owner-approved bound.
//!
//! **Final flash, static RAM, and stack budgets remain the host firmware's
//! responsibility.** An integrator must measure and enforce them on its own
//! final linked image for the chosen target and feature set; the recorded
//! per-type sizes (see each bounds test's measurement table) are planning
//! inputs for that budgeting, not a substitute for target-level measurement.

#![no_std]

// Feature-configuration contract (asserted by scripts/test-feature-matrix.sh):
// - Supported: `wire` (manufacturing contract), `sensor`, `gateway`, the
//   explicit two-role composition `sensor,gateway`, and `ota` (OTA protocol
//   tiers, optionally crossed with the roles); `--all-features` is the
//   future-facing superset gate.
// - Unsupported: the empty feature set. It is rejected here at compile time
//   with a deliberate diagnostic so integrators always select a documented
//   configuration.
#[cfg(not(any(feature = "wire", feature = "session", feature = "ota")))]
compile_error!(
    "sigil: no supported feature configuration selected; enable `wire` (manufacturing contract), \
     one of the session roles `sensor` / `gateway`, or the OTA protocol tiers via `ota`"
);

// Core non-blocking session module (always available)
pub mod core;

#[cfg(test)]
extern crate alloc;

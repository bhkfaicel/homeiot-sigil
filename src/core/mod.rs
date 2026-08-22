//! Non-blocking session core for sigil
//!
//! This module provides a hardware-agnostic, non-blocking implementation of the sigil
//! cryptographic communication protocol. It separates protocol logic from I/O operations,
//! allowing the host to control timing and device interactions through trait-based interfaces.
//!
//! ## Architecture
//!
//! The core is organized around several key components:
//!
//! - **Session Management**: `SessionManager<N>` handles multiple peer sessions with fixed capacity
//! - **Protocol Pipeline**: `process_incoming_packet()` provides non-blocking packet processing
//! - **Host Traits**: `SecureElement` and `RandomSource` define host-provided capabilities
//! - **Protocol Phases**: Install, renew, and resume flows are implemented as separate modules
//!
//! ## Protocol Phases
//!
//! 1. **Install** (`install/`): First-time pairing with identity authentication via secure element
//! 2. **Renew** (`renew/`): Sensor-initiated session key rotation using ephemeral ECDH
//! 3. **Resume** (`resume/`): Fast session re-establishment using static↔static ECDH
//!
//! ## Non-Blocking Design
//!
//! Public APIs never wait for radio traffic and never sleep. Waiting for responses is expressed
//! through [`SigilAction::Transmit`] with
//! `wait_timeout_ms: Some(...)`, allowing the host to manage scheduling and I/O timing.
//! Handshake calls invoke the host's synchronous [`SecureElement`]
//! methods and therefore occupy the calling task until those hardware operations complete.
//! Pending reclaim is also host-driven: manual [`SessionManager::cancel_pending`](crate::core::manager::SessionManager::cancel_pending)
//! and/or optional [`SessionManager::tick`](crate::core::manager::SessionManager::tick).

//!
//! ## Memory Constraints
//!
//! The core uses only stack-allocated data structures with `no_std` and no heap allocation.
//! Session tables have compile-time fixed capacity. Because the backing
//! `heapless::FnvIndexMap` requires `N` to be a power of two **and** `>= 2`,
//! the recommended defaults are `N = 2` for single-peer sensors and `N = 128`
//! for gateways (next power of two above the ~100-peer target).
//!
//! ## Host timebase (seconds)
//!
//! Product contract: `now` is local monotonic time and wire-v3
//! `key_lifetime_secs` is an authenticated duration, both expressed in
//! **whole seconds**. [`crate::core::resume::RESUME_REQUEST_COOLDOWN`] is
//! **15 seconds**. Handshake `*_TIMEOUT_MS` values remain **milliseconds**
//! (radio wait hints only) and must not be mixed with `now`.

// Internal crypto / protocol helpers (not part of the host-facing API)
// These require the full `session` feature set.
#[cfg(feature = "session")]
pub(crate) mod aead;
#[cfg(feature = "session")]
pub(crate) mod derive;
#[cfg(feature = "session")]
pub(crate) mod pending;
#[cfg(feature = "session")]
pub(crate) mod secret;

// The manufacturing / provisioning wire contract is enabled via `wire`.
// Session-enabled builds pull `wire` implicitly.
#[cfg(feature = "wire")]
pub mod factory_cert;

// The session protocol implementation (and its deps) is behind `session`.
#[cfg(feature = "session")]
pub mod error;
#[cfg(feature = "session")]
pub mod event;
#[cfg(feature = "session")]
pub mod frame;
#[cfg(feature = "session")]
pub mod install;
#[cfg(feature = "session")]
pub mod manager;
#[cfg(feature = "session")]
pub mod pipeline;
#[cfg(feature = "session")]
pub mod renew;
#[cfg(feature = "session")]
pub mod resume;
#[cfg(feature = "session")]
pub mod session;
#[cfg(feature = "session")]
pub mod traits;

// Shared mock implementations and mono-role configuration tests for unit
// tests. They exercise the session-protocol modules, so they must never
// compile when `session` is disabled: the empty configuration is rejected in
// src/lib.rs, and wire-only test runs contain only the factory_cert tests.
#[cfg(all(test, feature = "session"))]
mod role_config_tests;
#[cfg(all(test, feature = "session"))]
mod test_support;

// Re-export commonly used types for convenience
#[cfg(feature = "session")]
pub use error::SigilError;
#[cfg(feature = "session")]
pub use event::{DATA_MAX, MSG_MAX, ResumePskSecret, SigilAction, SigilEvent};
#[cfg(feature = "session")]
pub use manager::SessionManager;
#[cfg(feature = "sensor")]
pub use pipeline::EVENT_ACK_TIMEOUT_MS;
#[cfg(feature = "session")]
pub use pipeline::EVENT_ID_SIZE;
#[cfg(feature = "gateway")]
pub use pipeline::{EVENT_ACK_WIRE_LEN, TIME_SYNC_REQUEST_COOLDOWN_SECS};
#[cfg(feature = "session")]
pub use session::{Session, SessionRole};
#[cfg(feature = "session")]
pub use traits::{FactoryCertificateMetadata, RandomSource, SecureElement};

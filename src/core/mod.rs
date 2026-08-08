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
//! All public APIs are non-blocking and return immediately. Waiting for responses is expressed
//! through [`SigilAction::Transmit`](crate::core::event::SigilAction::Transmit) with
//! `wait_timeout_ms: Some(...)`, allowing the host to manage scheduling and I/O timing.
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
pub(crate) mod aead;
pub(crate) mod derive;
pub(crate) mod ecdh_soft;
pub(crate) mod pending;
pub(crate) mod secret;

pub mod error;
pub mod event;
pub mod frame;
pub mod install;
pub mod manager;
pub mod pipeline;
pub mod renew;
pub mod resume;
pub mod session;
pub mod traits;

// Shared mock implementations for unit tests (only compiled under cfg(test))
#[cfg(all(test, feature = "sensor", feature = "gateway"))]
mod test_support;

// Re-export commonly used types for convenience
pub use error::SigilError;
pub use event::{DATA_MAX, MSG_MAX, SigilAction, SigilEvent};
pub use manager::SessionManager;
pub use pipeline::EVENT_ID_SIZE;
#[cfg(feature = "sensor")]
pub use pipeline::EVENT_ACK_TIMEOUT_MS;
#[cfg(feature = "gateway")]
pub use pipeline::{EVENT_ACK_WIRE_LEN, TIME_SYNC_REQUEST_COOLDOWN_SECS};
pub use session::{Session, SessionRole};
pub use traits::{FactoryCertificateMetadata, RandomSource, SecureElement};

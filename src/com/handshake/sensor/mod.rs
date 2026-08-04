//! Sensor-side install flow. Re-exports for backward compatibility.
pub use crate::com::handshake::install::sensor::*;
pub use crate::com::handshake::install_core::{HandshakeConfirm, HandshakeSession};

#[cfg(test)]
pub mod tests;

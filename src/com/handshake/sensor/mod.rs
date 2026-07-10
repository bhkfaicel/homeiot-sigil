//! Sensor-side install flow. Re-exports for backward compatibility.
pub use crate::com::handshake::install_core::{HandshakeConfirm, HandshakeSession};
pub use crate::com::handshake::install::sensor::*;

#[cfg(test)]
pub mod tests;

//! Gateway-side install flow. Re-exports for backward compatibility.
pub use crate::com::handshake::install::gateway::*;
pub use crate::com::handshake::install_core::{HandshakeChallenge, HandshakeResult};

#[cfg(test)]
pub mod tests;

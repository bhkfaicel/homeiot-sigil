pub mod gateway;
pub mod sensor;
pub mod types;

pub use types::{HandshakeChallenge, HandshakeConfirm, HandshakeResult, HandshakeSession};

/// Sensor listen iterations while waiting for `HandshakeChallenge`.
pub const SENSOR_CHALLENGE_RX_TIMEOUT: usize = 800;

/// First receive attempt before rebroadcasting a trigger message during challenge wait.
pub const SENSOR_REBROADCAST_FIRST_ATTEMPT: u16 = 50;

/// Rebroadbast interval (in receive attempts) while waiting for a challenge.
pub const SENSOR_REBROADCAST_INTERVAL: u16 = 50;

/// Number of times the sensor sends `HandshakeConfirm` for robustness.
pub const CONFIRM_RETRIES: u8 = 3;

/// Recovery behaviour while the gateway waits for `HandshakeConfirm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRecovery {
    /// Re-send the challenge when the same sensor re-sends `HandshakeRequest`.
    Install,
}

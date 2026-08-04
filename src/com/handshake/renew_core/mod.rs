pub mod gateway;
pub mod sensor;
pub mod types;

pub use types::{KeyRenewAck, KeyRenewChallenge};

/// Re-exports install-side listen constants (same LoRa timing).
pub use crate::com::handshake::install_core::{
    CONFIRM_RETRIES, SENSOR_CHALLENGE_RX_TIMEOUT, SENSOR_REBROADCAST_FIRST_ATTEMPT,
    SENSOR_REBROADCAST_INTERVAL,
};

/// Gateway listen iterations while waiting for `KeyRenewAck`.
pub const GATEWAY_RENEW_ACK_RX_TIMEOUT: usize = 180;

/// Re-send the identical renew challenge every N receive attempts.
pub const GATEWAY_RENEW_CHALLENGE_RESEND_PERIOD: usize = 10;

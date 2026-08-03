pub mod gateway;
pub mod sensor;
pub mod types;

pub use types::SessionResumeRequest;

/// Re-exports install-side sensor timing constants.
pub use crate::com::handshake::install_core::{
    CONFIRM_RETRIES, SENSOR_CHALLENGE_RX_TIMEOUT, SENSOR_REBROADCAST_FIRST_ATTEMPT,
    SENSOR_REBROADCAST_INTERVAL,
};

/// Re-exports gateway confirm listen constants (shared with install).
pub use crate::com::handshake::{GATEWAY_CHALLENGE_RESEND_PERIOD, GATEWAY_CONFIRM_RX_TIMEOUT};

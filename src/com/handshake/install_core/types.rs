use crate::com::handshake::{ECIES_CIPHERTEXT_LEN, PUBLIC_KEY_LEN};
use bincode::{Decode, Encode};

/// ECIES-encrypted challenge sent by the gateway to the sensor (install only).
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeChallenge {
    pub data: [u8; ECIES_CIPHERTEXT_LEN],
}

/// ECDSA confirmation sent by the sensor to the gateway (install only).
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeConfirm {
    sig_gateway_nonce: [u8; crate::com::handshake::SIGNATURE_LEN],
}

impl HandshakeConfirm {
    pub fn new(sig_gateway_nonce: [u8; crate::com::handshake::SIGNATURE_LEN]) -> Self {
        Self { sig_gateway_nonce }
    }

    /// Returns the sensor's ECDSA signature of the gateway nonce.
    pub fn sig_gateway_nonce(&self) -> &[u8; crate::com::handshake::SIGNATURE_LEN] {
        &self.sig_gateway_nonce
    }
}

/// Successful sensor-side session: session keys plus the gateway that issued the challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSession {
    pub keys: crate::com::keys::Keys,
    pub gateway_mac: [u8; 17],
}

/// Result returned by the gateway after a successful session establishment.
#[derive(Debug)]
pub struct HandshakeResult {
    pub session_key: [u8; 32],
    pub sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    pub key_expire_at: u32,
}

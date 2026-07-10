use crate::com::handshake::PUBLIC_KEY_LEN;
use bincode::{Decode, Encode};

/// Lightweight renew challenge: ephemeral ECDH pubkey + nonces (no ECDSA, no ECIES).
///
/// Sent encrypted with the **current** session key. The sensor performs ECDH with
/// `eph_pubkey_compressed` and derives the new session key via HKDF.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct KeyRenewChallenge {
    eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
}

impl KeyRenewChallenge {
    pub fn new(
        eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN],
        gateway_nonce: [u8; 32],
        key_expire_at: u32,
    ) -> Self {
        Self {
            eph_pubkey_compressed,
            gateway_nonce,
            key_expire_at,
        }
    }

    pub fn eph_pubkey_compressed(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.eph_pubkey_compressed
    }

    pub fn gateway_nonce(&self) -> &[u8; 32] {
        &self.gateway_nonce
    }

    pub fn key_expire_at(&self) -> u32 {
        self.key_expire_at
    }
}

/// Empty acknowledgment for renew (authentication via AEAD on the current session key).
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct KeyRenewAck;

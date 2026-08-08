//! Renew wire message builders and parsers
//!
//! Renew messages are AEAD-encrypted under the **current** session key.
//! The outer header is `[peer_mac: 17] [protocol_version: 1 = 0x03] [frame_type: 1]`,
//! followed by the standard encrypted data format: `[nonce_prefix: 4] [counter: 8 BE]
//! [ciphertext + AEAD tag]`.
//!
//! The frame_type byte is one of:
//! - `0x11` (RenewRequest, sensor → gateway)
//! - `0x12` (RenewChallenge, gateway → sensor)
//! - `0x13` (RenewAck, sensor → gateway)
//! - `0x14` (RenewCommitConfirmed, gateway → sensor)
//!
//! # Plaintext layouts (after AEAD decryption)
//!
//! ## RenewRequest (sensor → gateway)
//! ```text
//! [sensor_eph_pubkey:32]   // X25519 public key
//! ```
//! ## RenewChallenge (gateway → sensor)
//! ```text
//! [gateway_eph_pubkey:32] [key_lifetime_secs:4]
//! ```
//! ## RenewAck (sensor → gateway)
//! ```text
//! (empty — the frame_type byte alone is sufficient)
//! ```
//! ## RenewCommitConfirmed (gateway → sensor)
//! ```text
//! (empty plaintext — AEAD under new g2s key, counter 0)
//! ```
//!
//! Note: the old `msg_type` byte inside the plaintext is no longer present
//! since the outer `frame_type` byte disambiguates the message. The plaintext
//! starts directly with the payload.

use crate::core::error::SigilError;
use heapless::Vec;

/// Builds the plaintext body of a renew request (sensor X25519 eph pubkey).
/// The frame_type is carried in the outer header, so the plaintext starts
/// directly with the ephemeral public key.
#[cfg(feature = "sensor")]
pub(crate) fn build_renew_request_body(
    sensor_eph_pubkey: &[u8; 32],
) -> Result<Vec<u8, 64>, SigilError> {
    let mut body = Vec::new();
    body.extend_from_slice(sensor_eph_pubkey)
.map_err(|_| SigilError::CapacityExceeded)?;
    Ok(body)
}

/// Parses a renew request body and returns the sensor ephemeral public key.
#[cfg(feature = "gateway")]
pub(crate) fn parse_renew_request_body(body: &[u8]) -> Option<[u8; 32]> {
    if body.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&body[..32]);
    Some(k)
}

/// Builds the plaintext body of a renew challenge (gateway key + lifetime).
#[cfg(feature = "gateway")]
pub(crate) fn build_renew_challenge_body(
    gateway_eph_pubkey: &[u8; 32],
    key_lifetime_secs: u32,
) -> Result<Vec<u8, 64>, SigilError> {
    let mut body = Vec::new();
    body.extend_from_slice(gateway_eph_pubkey)
.map_err(|_| SigilError::CapacityExceeded)?;
    body.extend_from_slice(&key_lifetime_secs.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    Ok(body)
}

/// Parsed renew challenge fields.
#[cfg(feature = "sensor")]
pub(crate) struct RenewChallengeFields {
    pub gateway_eph_pubkey: [u8; 32],
    pub key_lifetime_secs: u32,
}

/// Parses a renew challenge body.
#[cfg(feature = "sensor")]
pub(crate) fn parse_renew_challenge_body(body: &[u8]) -> Option<RenewChallengeFields> {
    if body.len() != 32 + 4 {
        return None;
    }
    let mut gateway_eph_pubkey = [0u8; 32];
    gateway_eph_pubkey.copy_from_slice(&body[..32]);
    let mut expire = [0u8; 4];
    expire.copy_from_slice(&body[32..36]);
    Some(RenewChallengeFields {
        gateway_eph_pubkey,
        key_lifetime_secs: u32::from_be_bytes(expire),
    })
}

/// Builds the plaintext body of a renew ack.
/// The ack body is empty — the frame_type in the outer header is sufficient.
#[cfg(feature = "sensor")]
pub(crate) fn build_renew_ack_body() -> Result<Vec<u8, 8>, SigilError> {
    Ok(Vec::new())
}

/// Parses a renew ack body (must be empty).
#[cfg(feature = "gateway")]
pub(crate) fn parse_renew_ack_body(body: &[u8]) -> bool {
    body.is_empty()
}

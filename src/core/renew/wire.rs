//! Renew P-256 wire bodies.
//!
//! All four frames use the standard encrypted framing. Request, Challenge and
//! Confirm are authenticated with the current session; CommitConfirmed uses
//! the staged new gateway→sensor key.

use crate::core::error::SigilError;
use heapless::Vec;

pub(crate) const P256_COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;
pub(crate) const RENEW_PROOF_SIZE: usize = 16;
pub(crate) const RENEW_CHALLENGE_BODY_SIZE: usize = 33 + 4;
pub(crate) const RENEW_CONFIRM_BODY_SIZE: usize = 33 + 16;

#[cfg(feature = "sensor")]
pub(crate) fn build_renew_request_body() -> Result<Vec<u8, 1>, SigilError> {
    Ok(Vec::new())
}

#[cfg(feature = "gateway")]
pub(crate) fn parse_renew_request_body(body: &[u8]) -> bool {
    body.is_empty()
}

#[cfg(feature = "gateway")]
pub(crate) fn build_renew_challenge_body(
    gateway_ephemeral_pubkey: &[u8; P256_COMPRESSED_PUBLIC_KEY_SIZE],
    key_lifetime_secs: u32,
) -> Result<Vec<u8, RENEW_CHALLENGE_BODY_SIZE>, SigilError> {
    let mut body = Vec::new();
    body.extend_from_slice(gateway_ephemeral_pubkey)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    body.extend_from_slice(&key_lifetime_secs.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(body)
}

#[cfg(feature = "sensor")]
pub(crate) struct RenewChallengeFields {
    pub gateway_ephemeral_pubkey: [u8; P256_COMPRESSED_PUBLIC_KEY_SIZE],
    pub key_lifetime_secs: u32,
}

#[cfg(feature = "sensor")]
pub(crate) fn parse_renew_challenge_body(body: &[u8]) -> Option<RenewChallengeFields> {
    if body.len() != RENEW_CHALLENGE_BODY_SIZE {
        return None;
    }
    let mut gateway_ephemeral_pubkey = [0u8; P256_COMPRESSED_PUBLIC_KEY_SIZE];
    gateway_ephemeral_pubkey.copy_from_slice(&body[..P256_COMPRESSED_PUBLIC_KEY_SIZE]);
    if !matches!(gateway_ephemeral_pubkey[0], 0x02 | 0x03) {
        return None;
    }
    let mut lifetime = [0u8; 4];
    lifetime.copy_from_slice(&body[P256_COMPRESSED_PUBLIC_KEY_SIZE..]);
    Some(RenewChallengeFields {
        gateway_ephemeral_pubkey,
        key_lifetime_secs: u32::from_be_bytes(lifetime),
    })
}

#[cfg(feature = "sensor")]
pub(crate) fn build_renew_confirm_body(
    sensor_ephemeral_pubkey: &[u8; P256_COMPRESSED_PUBLIC_KEY_SIZE],
    proof: &[u8; RENEW_PROOF_SIZE],
) -> Result<Vec<u8, RENEW_CONFIRM_BODY_SIZE>, SigilError> {
    if !matches!(sensor_ephemeral_pubkey[0], 0x02 | 0x03) {
        return Err(SigilError::InvalidStaticKey);
    }
    let mut body = Vec::new();
    body.extend_from_slice(sensor_ephemeral_pubkey)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    body.extend_from_slice(proof)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(body)
}

#[cfg(feature = "gateway")]
pub(crate) struct RenewConfirmFields {
    pub sensor_ephemeral_pubkey: [u8; P256_COMPRESSED_PUBLIC_KEY_SIZE],
    pub proof: [u8; RENEW_PROOF_SIZE],
}

#[cfg(feature = "gateway")]
pub(crate) fn parse_renew_confirm_body(body: &[u8]) -> Option<RenewConfirmFields> {
    if body.len() != RENEW_CONFIRM_BODY_SIZE {
        return None;
    }
    let mut sensor_ephemeral_pubkey = [0u8; P256_COMPRESSED_PUBLIC_KEY_SIZE];
    sensor_ephemeral_pubkey.copy_from_slice(&body[..P256_COMPRESSED_PUBLIC_KEY_SIZE]);
    if !matches!(sensor_ephemeral_pubkey[0], 0x02 | 0x03) {
        return None;
    }
    let mut proof = [0u8; RENEW_PROOF_SIZE];
    proof.copy_from_slice(&body[P256_COMPRESSED_PUBLIC_KEY_SIZE..]);
    Some(RenewConfirmFields {
        sensor_ephemeral_pubkey,
        proof,
    })
}

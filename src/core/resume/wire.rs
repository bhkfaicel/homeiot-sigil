//! Resume wire message builders and parsers
//!
//! Resume **request** is clear text but carries a 16-byte MAC keyed by the
//! durable [`crate::core::session::ResumePsk`] derived at install:
//! spoofed MACs without the PSK fail **before** gateway SE-ECDH.
//! The **challenge** is clear text but carries a MAC over
//! `(sensor_nonce ‖ gateway_nonce ‖ key_lifetime_secs)` keyed by the static
//! ECDH shared secret.
//! The **confirm** is AEAD under the new session key.
//!
//! The outer header `[peer_mac: 17] [protocol_version: 1 = 0x03] [frame_type: 1]`
//! always carries the **sender** MAC (`SessionManager::local_mac`).
//!
//! # Layouts
//!
//! ## ResumeRequest (sensor → gateway, clear text + req MAC) — **51 bytes**
//! ```text
//! [peer_mac:17] [protocol_version:1 = 0x03] [frame_type:1 = 0x21]
//! [sensor_nonce:16] [req_mac:16]
//! ```
//!
//! ## ResumeChallenge (gateway → sensor, clear text + MAC)
//! ```text
//! [peer_mac:17] [protocol_version:1 = 0x03] [frame_type:1 = 0x22]
//! [gateway_nonce:16] [key_lifetime_secs:4] [chal_mac:16]
//! ```
//!
//! ## ResumeConfirm (sensor → gateway, AEAD under new session key)
//! ```text
//! [peer_mac:17] [protocol_version:1 = 0x03] [frame_type:1 = 0x23]
//! [nonce_prefix:4] [tx_counter_be:8] [ciphertext + tag]
//! ```
//! Plaintext body is empty; AAD = outer header (`peer_mac ‖ version ‖ frame_type`).

use crate::core::derive::derive_session_key;
use crate::core::error::SigilError;
use crate::core::session::{PeerId, ResumePsk};
use heapless::Vec;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Nonce size carried in resume messages (host random).
pub(crate) const RESUME_NONCE_SIZE: usize = 16;

/// Challenge integrity MAC size (truncated HKDF output).
pub(crate) const RESUME_CHAL_MAC_SIZE: usize = 16;

/// ResumeRequest proof MAC size (truncated HKDF over resume PSK).
pub(crate) const RESUME_REQ_MAC_SIZE: usize = 16;

/// Resume challenge body length: nonce + expire + mac.
#[cfg(feature = "sensor")]
pub(crate) const RESUME_CHALLENGE_BODY_LEN: usize = RESUME_NONCE_SIZE + 4 + RESUME_CHAL_MAC_SIZE;

/// Resume request body length: nonce + req_mac.
#[cfg(feature = "gateway")]
pub(crate) const RESUME_REQUEST_BODY_LEN: usize = RESUME_NONCE_SIZE + RESUME_REQ_MAC_SIZE;

/// Derives the durable resume PSK at install time.
/// `psk = HKDF(shared, info="sigil-resume-psk" ‖ sensor_nonce ‖ gateway_nonce)[0..32]`
/// Distinct from the AEAD session key (`sigil-install` info). Host persists this
/// with the peer static pubkey for post-reboot resume.
pub(crate) fn derive_resume_psk(
    shared: &[u8; 32],
    sensor_nonce: &[u8; RESUME_NONCE_SIZE],
    gateway_nonce: &[u8; RESUME_NONCE_SIZE],
) -> Result<ResumePsk, SigilError> {
    let mut info = heapless::Vec::<u8, 64>::new();
    info.extend_from_slice(b"sigil-resume-psk")
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(gateway_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    let (psk, mut prefix) = derive_session_key(shared, Some(&info))?;
    prefix.zeroize();
    Ok(psk)
}

/// Builds a resume request **body** (nonce ‖ req_mac).
#[cfg(feature = "sensor")]
pub(crate) fn build_resume_request_body(
    sensor_nonce: &[u8; RESUME_NONCE_SIZE],
    req_mac: &[u8; RESUME_REQ_MAC_SIZE],
) -> Result<Vec<u8, 32>, SigilError> {
    let mut body = Vec::new();
    body.extend_from_slice(sensor_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    body.extend_from_slice(req_mac)
.map_err(|_| SigilError::CapacityExceeded)?;
    Ok(body)
}

/// Parsed resume request fields.
#[cfg(feature = "gateway")]
pub(crate) struct ResumeRequestFields {
    pub sensor_nonce: [u8; RESUME_NONCE_SIZE],
    pub req_mac: [u8; RESUME_REQ_MAC_SIZE],
}

/// Parses a resume request body (after the outer header).
#[cfg(feature = "gateway")]
pub(crate) fn parse_resume_request_body(body: &[u8]) -> Option<ResumeRequestFields> {
    if body.len() != RESUME_REQUEST_BODY_LEN {
        return None;
    }
    let mut sensor_nonce = [0u8; RESUME_NONCE_SIZE];
    sensor_nonce.copy_from_slice(&body[..RESUME_NONCE_SIZE]);
    let mut req_mac = [0u8; RESUME_REQ_MAC_SIZE];
    req_mac.copy_from_slice(&body[RESUME_NONCE_SIZE..RESUME_REQUEST_BODY_LEN]);
    Some(ResumeRequestFields {
        sensor_nonce,
        req_mac,
    })
}

/// Derives the ResumeRequest integrity MAC.
/// `tag = HKDF(resume_psk, info="sigil-resume-req" ‖ sensor_mac ‖ sensor_nonce)[0..16]`
pub(crate) fn resume_request_mac(
    resume_psk: &ResumePsk,
    sensor_mac: &PeerId,
    sensor_nonce: &[u8; RESUME_NONCE_SIZE],
) -> Result<[u8; RESUME_REQ_MAC_SIZE], SigilError> {
    let mut info = heapless::Vec::<u8, 64>::new();
    info.extend_from_slice(b"sigil-resume-req")
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_mac)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    let (mut okm, mut prefix) = derive_session_key(resume_psk, Some(&info))?;
    let mut tag = [0u8; RESUME_REQ_MAC_SIZE];
    tag.copy_from_slice(&okm[..RESUME_REQ_MAC_SIZE]);
    okm.zeroize();
    prefix.zeroize();
    Ok(tag)
}

/// Derives the resume-challenge integrity MAC.
/// `tag = HKDF(shared, info="sigil-resume-mac" ‖ sensor_nonce ‖ gateway_nonce ‖ lifetime)[0..16]`
pub(crate) fn resume_challenge_mac(
    shared: &[u8; 32],
    sensor_nonce: &[u8; RESUME_NONCE_SIZE],
    gateway_nonce: &[u8; RESUME_NONCE_SIZE],
    key_lifetime_secs: u32,
) -> Result<[u8; RESUME_CHAL_MAC_SIZE], SigilError> {
    let mut info = heapless::Vec::<u8, 64>::new();
    info.extend_from_slice(b"sigil-resume-mac")
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(gateway_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(&key_lifetime_secs.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    let (mut okm, _) = derive_session_key(shared, Some(&info))?;
    let mut tag = [0u8; RESUME_CHAL_MAC_SIZE];
    tag.copy_from_slice(&okm[..RESUME_CHAL_MAC_SIZE]);
    okm.zeroize();
    Ok(tag)
}

/// Constant-time equality for resume MACs (request or challenge).
pub(crate) fn resume_chal_mac_eq(
    expected: &[u8; RESUME_CHAL_MAC_SIZE],
    received: &[u8; RESUME_CHAL_MAC_SIZE],
) -> bool {
    bool::from(expected.ct_eq(received))
}

/// Builds a resume challenge **body** (without outer header).
#[cfg(feature = "gateway")]
pub(crate) fn build_resume_challenge_body(
    gateway_nonce: &[u8; RESUME_NONCE_SIZE],
    key_lifetime_secs: u32,
    chal_mac: &[u8; RESUME_CHAL_MAC_SIZE],
) -> Result<Vec<u8, 48>, SigilError> {
    let mut body = Vec::new();
    body.extend_from_slice(gateway_nonce)
.map_err(|_| SigilError::CapacityExceeded)?;
    body.extend_from_slice(&key_lifetime_secs.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    body.extend_from_slice(chal_mac)
.map_err(|_| SigilError::CapacityExceeded)?;
    Ok(body)
}

/// Parsed resume challenge fields.
#[cfg(feature = "sensor")]
pub(crate) struct ResumeChallengeFields {
    pub gateway_nonce: [u8; RESUME_NONCE_SIZE],
    pub key_lifetime_secs: u32,
    pub chal_mac: [u8; RESUME_CHAL_MAC_SIZE],
}

/// Parses a resume challenge body (after the outer header).
#[cfg(feature = "sensor")]
pub(crate) fn parse_resume_challenge_body(body: &[u8]) -> Option<ResumeChallengeFields> {
    if body.len() != RESUME_CHALLENGE_BODY_LEN {
        return None;
    }
    let mut gateway_nonce = [0u8; RESUME_NONCE_SIZE];
    gateway_nonce.copy_from_slice(&body[..RESUME_NONCE_SIZE]);
    let mut expire = [0u8; 4];
    expire.copy_from_slice(&body[RESUME_NONCE_SIZE..RESUME_NONCE_SIZE + 4]);
    let mut chal_mac = [0u8; RESUME_CHAL_MAC_SIZE];
    chal_mac.copy_from_slice(
        &body[RESUME_NONCE_SIZE + 4..RESUME_NONCE_SIZE + 4 + RESUME_CHAL_MAC_SIZE],
    );
    Some(ResumeChallengeFields {
        gateway_nonce,
        key_lifetime_secs: u32::from_be_bytes(expire),
        chal_mac,
    })
}

/// Builds the resume confirm **plaintext** body (encrypted under the new key).
#[cfg(feature = "sensor")]
pub(crate) fn build_resume_confirm_body() -> Result<Vec<u8, 8>, SigilError> {
    Ok(Vec::new())
}

/// Validates a decrypted resume confirm plaintext body (must be empty).
#[cfg(feature = "gateway")]
pub(crate) fn parse_resume_confirm_body(body: &[u8]) -> bool {
    body.is_empty()
}

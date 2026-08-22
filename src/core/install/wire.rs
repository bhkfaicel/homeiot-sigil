//! Install wire message builders and parsers
//!
//! Wire layouts. All messages share the outer header:
//! `[peer_mac: 17] [protocol_version: 1 = 0x03] [frame_type: 1]`.
//!
//! After the outer header, install messages carry a clear-text body
//! (except [`InstallMessageType::CommitConfirmed`], which is AEAD under the
//! new session key, not built here yet).
//!
//! # Stack sizing
//!
//! Builders return `heapless::Vec` sized to the exact wire length
//! ([`INSTALL_REQUEST_LEN`] / [`INSTALL_CHALLENGE_LEN`] / [`INSTALL_CONFIRM_LEN`]),
//! not a blanket 256-byte buffer. Callers that need a larger host TX buffer
//! (`MSG`) copy via `extend_from_slice`. This keeps SAMD21 stack use tight
//! (Confirm is ~100 B instead of 256 B on the builder frame).
//!
//! # InstallRequest (sensor → gateway)
//!
//! ```text
//! [peer_mac:17] [protocol_version:1 = 0x03] [frame_type:1 = 0x01]
//! [sensor_peer_mac:17]
//! [hardware_profile_id:1] [factory_key_id:1]
//! [sensor_static_pubkey:33]
//! [factory_cert_sig:64] // ECDSA(factory, version‖product‖hw‖key_id‖PeerId‖pubkey)

//! [sensor_nonce:16]
//! [sensor_signature:64]   // ECDSA over identity ‖ factory metadata ‖ key ‖ nonce
//! ```
//!
//! # InstallChallenge (gateway → sensor)
//!
//! ```text
//! [peer_mac:17] [protocol_version:1 = 0x03] [frame_type:1 = 0x02]
//! [gateway_peer_mac:17]
//! [hardware_profile_id:1] [factory_key_id:1]
//! [gateway_static_pubkey:33]
//! [factory_cert_sig:64] // ECDSA(factory, version‖product‖hw‖key_id‖PeerId‖pubkey)

//! [gateway_nonce:16]
//! [key_lifetime_secs:4]    // BE u32 authenticated duration
//! [gateway_signature:64]  // domain-separated full install transcript
//! ```
//!
//! # InstallConfirm (sensor → gateway)
//!
//! ```text
//! [peer_mac:17] [protocol_version:1 = 0x03] [frame_type:1 = 0x03]
//! [sensor_peer_mac:17]
//! [confirm_signature:64]  // domain-separated full install transcript
//! ```

use crate::core::error::SigilError;
use crate::core::frame::{
    self, FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION,
    PROTOCOL_VERSION_OFFSET,
};
use crate::core::session::PeerId;
use heapless::Vec;

/// Nonce size used during install handshake (host random).
pub(crate) const INSTALL_NONCE_SIZE: usize = 16;

/// Wire length of an InstallRequest including the outer header.
pub(crate) const INSTALL_REQUEST_LEN: usize = 215;

/// Wire length of an InstallChallenge including the outer header.
pub(crate) const INSTALL_CHALLENGE_LEN: usize = 219;

/// Wire length of an InstallConfirm including the outer header.
pub(crate) const INSTALL_CONFIRM_LEN: usize = 100;

/// Message type identifiers for install protocol
/// These mirror the [`crate::core::frame::FrameType`] install variants and
/// are used by the install dispatcher to select the correct handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum InstallMessageType {
    /// Install request (sensor → gateway)
    Request = 0x01,
    /// Install challenge (gateway → sensor)
    Challenge = 0x02,
    /// Install confirm (sensor → gateway)
    Confirm = 0x03,
    /// Install commit confirmed (gateway → sensor)
    CommitConfirmed = 0x04,
}

impl InstallMessageType {
    /// Parses a message type byte.
    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Request),
            0x02 => Some(Self::Challenge),
            0x03 => Some(Self::Confirm),
            0x04 => Some(Self::CommitConfirmed),
            _ => None,
        }
    }
}

/// ECDSA P-256 signature in r||s form.
pub(crate) type EcdsaSig = [u8; 64];

/// Compressed P-256 public key.
pub(crate) type CompressedPub = [u8; 33];

/// Install request fields.
pub(crate) struct InstallRequest {
    pub sensor_peer_mac: PeerId,
    pub hardware_profile_id: u8,
    pub factory_key_id: u8,
    pub sensor_static_pubkey: CompressedPub,
    /// Factory certificate over product, metadata, PeerId and public key.
    pub factory_cert_sig: EcdsaSig,
    pub sensor_nonce: [u8; INSTALL_NONCE_SIZE],
    pub sensor_signature: EcdsaSig,
}

/// Install challenge fields.
pub(crate) struct InstallChallenge {
    pub gateway_peer_mac: PeerId,
    pub hardware_profile_id: u8,
    pub factory_key_id: u8,
    pub gateway_static_pubkey: CompressedPub,
    /// Factory certificate over product, metadata, PeerId and public key.
    pub factory_cert_sig: EcdsaSig,
    pub gateway_nonce: [u8; INSTALL_NONCE_SIZE],
    pub key_lifetime_secs: u32,
    pub gateway_signature: EcdsaSig,
}

/// Install confirm fields.
pub(crate) struct InstallConfirm {
    pub sensor_peer_mac: PeerId,
    pub confirm_signature: EcdsaSig,
}

/// Appends chunks into a fixed-capacity packet buffer.
fn push_all<const N: usize>(packet: &mut Vec<u8, N>, chunks: &[&[u8]]) -> Result<(), SigilError> {
    for chunk in chunks {
        packet
            .extend_from_slice(chunk)
            .map_err(|_| SigilError::OutputBufferTooSmall)?;
    }
    Ok(())
}

/// Serializes an install request with the outer header (peer + version + frame_type).
/// Layout:
/// `[peer:17] [version:1 = 0x03] [frame_type:1 = 0x01] [sensor_peer_mac:17]
///  [hardware_profile_id:1] [factory_key_id:1] [pubkey:33] [factory_cert:64]
///  [nonce:16] [sig:64]`
/// Buffer capacity is exactly [`INSTALL_REQUEST_LEN`].
#[cfg(any(feature = "sensor", test))]
pub(crate) fn build_install_request(
    req: &InstallRequest,
) -> Result<Vec<u8, INSTALL_REQUEST_LEN>, SigilError> {
    let mut packet = Vec::new();
    let header = frame::build_header(&req.sensor_peer_mac, FrameType::InstallRequest);
    push_all(
        &mut packet,
        &[
            &header,
            &req.sensor_peer_mac,
            &[req.hardware_profile_id, req.factory_key_id],
            &req.sensor_static_pubkey,
            &req.factory_cert_sig,
            &req.sensor_nonce,
            &req.sensor_signature,
        ],
    )?;
    debug_assert_eq!(packet.len(), INSTALL_REQUEST_LEN);
    Ok(packet)
}

/// Parses an install request from its wire form (with outer header).
/// Expected length: [`INSTALL_REQUEST_LEN`] (215 bytes).
#[cfg(feature = "gateway")]
pub(crate) fn parse_install_request(packet: &[u8]) -> Option<InstallRequest> {
    let header = frame::parse_header(packet)?;
    if packet.len() != INSTALL_REQUEST_LEN || header.frame_type != FrameType::InstallRequest {
        return None;
    }
    let body = &packet[OUTER_HEADER_SIZE..];
    let mut sensor_peer_mac = [0u8; 17];
    sensor_peer_mac.copy_from_slice(&body[0..17]);
    let hardware_profile_id = body[17];
    let factory_key_id = body[18];
    let mut sensor_static_pubkey = [0u8; 33];
    sensor_static_pubkey.copy_from_slice(&body[19..52]);
    let mut factory_cert_sig = [0u8; 64];
    factory_cert_sig.copy_from_slice(&body[52..116]);
    let mut sensor_nonce = [0u8; INSTALL_NONCE_SIZE];
    sensor_nonce.copy_from_slice(&body[116..132]);
    let mut sensor_signature = [0u8; 64];
    sensor_signature.copy_from_slice(&body[132..196]);
    Some(InstallRequest {
        sensor_peer_mac,
        hardware_profile_id,
        factory_key_id,
        sensor_static_pubkey,
        factory_cert_sig,
        sensor_nonce,
        sensor_signature,
    })
}

/// Serializes an install challenge with the outer header.
/// Buffer capacity is exactly [`INSTALL_CHALLENGE_LEN`].
#[cfg(feature = "gateway")]
pub(crate) fn build_install_challenge(
    chal: &InstallChallenge,
) -> Result<Vec<u8, INSTALL_CHALLENGE_LEN>, SigilError> {
    let mut packet = Vec::new();
    let header = frame::build_header(&chal.gateway_peer_mac, FrameType::InstallChallenge);
    let lifetime = chal.key_lifetime_secs.to_be_bytes();
    push_all(
        &mut packet,
        &[
            &header,
            &chal.gateway_peer_mac,
            &[chal.hardware_profile_id, chal.factory_key_id],
            &chal.gateway_static_pubkey,
            &chal.factory_cert_sig,
            &chal.gateway_nonce,
            &lifetime,
            &chal.gateway_signature,
        ],
    )?;
    debug_assert_eq!(packet.len(), INSTALL_CHALLENGE_LEN);
    Ok(packet)
}

/// Parses an install challenge from its wire form (with outer header).
/// Expected length: [`INSTALL_CHALLENGE_LEN`] (219 bytes).
#[cfg(feature = "sensor")]
pub(crate) fn parse_install_challenge(packet: &[u8]) -> Option<InstallChallenge> {
    let header = frame::parse_header(packet)?;
    if packet.len() != INSTALL_CHALLENGE_LEN || header.frame_type != FrameType::InstallChallenge {
        return None;
    }
    let body = &packet[OUTER_HEADER_SIZE..];
    let mut gateway_peer_mac = [0u8; 17];
    gateway_peer_mac.copy_from_slice(&body[0..17]);
    let hardware_profile_id = body[17];
    let factory_key_id = body[18];
    let mut gateway_static_pubkey = [0u8; 33];
    gateway_static_pubkey.copy_from_slice(&body[19..52]);
    let mut factory_cert_sig = [0u8; 64];
    factory_cert_sig.copy_from_slice(&body[52..116]);
    let mut gateway_nonce = [0u8; INSTALL_NONCE_SIZE];
    gateway_nonce.copy_from_slice(&body[116..132]);
    let mut expire_bytes = [0u8; 4];
    expire_bytes.copy_from_slice(&body[132..136]);
    let key_lifetime_secs = u32::from_be_bytes(expire_bytes);
    let mut gateway_signature = [0u8; 64];
    gateway_signature.copy_from_slice(&body[136..200]);
    Some(InstallChallenge {
        gateway_peer_mac,
        hardware_profile_id,
        factory_key_id,
        gateway_static_pubkey,
        factory_cert_sig,
        gateway_nonce,
        key_lifetime_secs,
        gateway_signature,
    })
}

/// Serializes an install confirm with the outer header.
/// Buffer capacity is exactly [`INSTALL_CONFIRM_LEN`] — ~156 B less
/// stack than a blanket 256-byte builder buffer.
#[cfg(feature = "sensor")]
pub(crate) fn build_install_confirm(
    cfm: &InstallConfirm,
) -> Result<Vec<u8, INSTALL_CONFIRM_LEN>, SigilError> {
    let mut packet = Vec::new();
    let header = frame::build_header(&cfm.sensor_peer_mac, FrameType::InstallConfirm);
    push_all(
        &mut packet,
        &[&header, &cfm.sensor_peer_mac, &cfm.confirm_signature],
    )?;
    debug_assert_eq!(packet.len(), INSTALL_CONFIRM_LEN);
    Ok(packet)
}

/// Parses an install confirm from its wire form (with outer header).
/// Expected length: [`INSTALL_CONFIRM_LEN`] (100 bytes).
#[cfg(feature = "gateway")]
pub(crate) fn parse_install_confirm(packet: &[u8]) -> Option<InstallConfirm> {
    let header = frame::parse_header(packet)?;
    if packet.len() != INSTALL_CONFIRM_LEN || header.frame_type != FrameType::InstallConfirm {
        return None;
    }
    let body = &packet[OUTER_HEADER_SIZE..];
    let mut sensor_peer_mac = [0u8; 17];
    sensor_peer_mac.copy_from_slice(&body[0..17]);
    let mut confirm_signature = [0u8; 64];
    confirm_signature.copy_from_slice(&body[17..81]);
    Some(InstallConfirm {
        sensor_peer_mac,
        confirm_signature,
    })
}

/// Returns the install message type without parsing the whole packet.
/// Requires a valid outer header (`protocol_version` + known frame type).
pub(crate) fn parse_install_message_type(packet: &[u8]) -> Option<InstallMessageType> {
    if packet.len() < OUTER_HEADER_SIZE {
        return None;
    }
    if packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION {
        return None;
    }
    InstallMessageType::from_byte(packet[FRAME_TYPE_OFFSET])
}

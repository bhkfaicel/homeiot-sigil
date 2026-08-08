//! Unified frame type discriminator for all sigil messages
//!
//! Every sigil frame on the wire starts with a common outer header:
//! ```text
//! [peer_mac: 17 bytes] [protocol_version: 1 byte = 0x03] [frame_type: 1 byte]
//! [type-specific payload]
//! ```
//! The `protocol_version` byte at position 17 and `frame_type` at position 18
//! allow the receiver to reject foreign protocols and classify the message
//! **without decryption**, enabling easy client-side routing.
//!
//! # Frame type byte assignments
//!
//! | Range  | Protocol | Types                                      |
//! |--------|----------|--------------------------------------------|
//! | 0x00   | Data     | Application data (encrypted, no ACK)       |
//! | 0x01-4 | Install  | Request, Challenge, Confirm, CommitConfirmed |
//! | 0x11-4 | Renew    | Request, Challenge, Ack, CommitConfirmed   |
//! | 0x21-4 | Resume   | Request, Challenge, Confirm, CommitConfirmed |
//! | 0x31-2 | Event    | Reliable Event, EventAck                    |
//! | 0x33   | Time     | TimeSyncRequest (sensor → gateway, AEAD)    |

use crate::core::session::PeerId;

/// Wire protocol version carried at [`PROTOCOL_VERSION_OFFSET`].
/// Receivers must reject frames whose version byte is not this value.
pub const PROTOCOL_VERSION: u8 = 0x03;

/// Byte offset of [`PROTOCOL_VERSION`] in the outer header.
pub const PROTOCOL_VERSION_OFFSET: usize = 17;

/// Byte offset of the [`FrameType`] discriminator in the outer header.
pub const FRAME_TYPE_OFFSET: usize = 18;

/// Size of the outer header: peer MAC (17) + protocol version (1) + frame type (1) = 19 bytes.
pub const OUTER_HEADER_SIZE: usize = 19;

/// Frame type discriminator (byte 18 of every sigil frame).
/// This enum is carried **in clear text** in the outer header so the
/// receiver can route the frame to the appropriate handler without
/// touching cryptographic material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Encrypted application data (AEAD under session key)
    Data = 0x00,
    /// Install handshake Step 1 (sensor → gateway, clear text + ECDSA)
    InstallRequest = 0x01,
    /// Install handshake Step 2 (gateway → sensor, clear text + ECDSA)
    InstallChallenge = 0x02,
    /// Install handshake Step 3 (sensor → gateway, clear text + ECDSA)
    InstallConfirm = 0x03,
    /// Install Step 4 (gateway → sensor, AEAD under **new** session key)
    InstallCommitConfirmed = 0x04,
    /// Renew Step 1 (sensor → gateway, encrypted under **old** session key)
    RenewRequest = 0x11,
    /// Renew Step 2 (gateway → sensor, encrypted under **old** session key)
    RenewChallenge = 0x12,
    /// Renew Step 3 (sensor → gateway, encrypted under **new** session key)
    RenewAck = 0x13,
    /// Renew Step 4 (gateway → sensor, AEAD under **new** session key)
    RenewCommitConfirmed = 0x14,
    /// Resume Step 1 (sensor → gateway, clear text)
    ResumeRequest = 0x21,
    /// Resume Step 2 (gateway → sensor, clear text)
    ResumeChallenge = 0x22,
    /// Resume Step 3 (sensor → gateway, AEAD under the **new** session key)
    ResumeConfirm = 0x23,
    /// Resume Step 4 (gateway → sensor, AEAD under **new** session key)
    ResumeCommitConfirmed = 0x24,
    /// Gateway → sensor authenticated application-clock synchronization.
    TimeSync = 0x30,
    /// Sensor → gateway reliable application event (AEAD).
    Event = 0x31,
    /// Gateway → sensor authenticated acknowledgement of an Event (AEAD).
    EventAck = 0x32,
    /// Sensor → gateway authenticated request for a fresh TimeSync sample.
    TimeSyncRequest = 0x33,
}

impl FrameType {
    /// Parses a frame type byte.
    /// Returns `None` if the byte does not correspond to a known frame type.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::InstallRequest),
            0x02 => Some(Self::InstallChallenge),
            0x03 => Some(Self::InstallConfirm),
            0x04 => Some(Self::InstallCommitConfirmed),
            0x11 => Some(Self::RenewRequest),
            0x12 => Some(Self::RenewChallenge),
            0x13 => Some(Self::RenewAck),
            0x14 => Some(Self::RenewCommitConfirmed),
            0x21 => Some(Self::ResumeRequest),
            0x22 => Some(Self::ResumeChallenge),
            0x23 => Some(Self::ResumeConfirm),
            0x24 => Some(Self::ResumeCommitConfirmed),
            0x30 => Some(Self::TimeSync),
            0x31 => Some(Self::Event),
            0x32 => Some(Self::EventAck),
            0x33 => Some(Self::TimeSyncRequest),
            _ => None,
        }
    }

    /// Returns `true` if this frame type carries an AEAD-encrypted payload
    /// (i.e. the payload after the outer header is
    /// `[nonce_prefix:4] [counter:8] [ciphertext+tag]`).
    /// Data, all renew messages, ResumeConfirm / ResumeCommitConfirmed, and
    /// InstallCommitConfirmed use this encrypted format (CommitConfirmed under
    /// the new session key for wire-v2 consistency).
    pub fn is_encrypted_payload(&self) -> bool {
        matches!(
            self,
            Self::Data
                | Self::RenewRequest
                | Self::RenewChallenge
                | Self::RenewAck
                | Self::RenewCommitConfirmed
                | Self::ResumeConfirm
                | Self::ResumeCommitConfirmed
                | Self::InstallCommitConfirmed
                | Self::TimeSync
                | Self::Event
                | Self::EventAck
                | Self::TimeSyncRequest
        )
    }

    /// Returns `true` if this frame type belongs to the install protocol.
    pub fn is_install(&self) -> bool {
        matches!(
            self,
            Self::InstallRequest
                | Self::InstallChallenge
                | Self::InstallConfirm
                | Self::InstallCommitConfirmed
        )
    }

    /// Returns `true` if this frame type belongs to the renew protocol.
    pub fn is_renew(&self) -> bool {
        matches!(
            self,
            Self::RenewRequest | Self::RenewChallenge | Self::RenewAck | Self::RenewCommitConfirmed
        )
    }

    /// Returns `true` if this frame type belongs to the resume protocol.
    pub fn is_resume(&self) -> bool {
        matches!(
            self,
            Self::ResumeRequest
                | Self::ResumeChallenge
                | Self::ResumeConfirm
                | Self::ResumeCommitConfirmed
        )
    }
}

/// Parsed outer header extracted from a raw sigil frame.
/// The outer header is always present and carried in clear text. It allows
/// the receiver to identify the peer and classify the message before any
/// cryptographic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Peer MAC address (17 bytes)
    pub peer: PeerId,
    /// Frame type discriminator
    pub frame_type: FrameType,
}

/// Parses the outer header (peer + protocol_version + frame_type) from a raw frame.
/// The header occupies the first [`OUTER_HEADER_SIZE`] (19) bytes.
/// Frames whose protocol version is not [`PROTOCOL_VERSION`] are rejected.
/// # Returns
/// `Some(FrameHeader)` if the frame is long enough, carries the expected
/// protocol version, and a known frame type byte; `None` otherwise.
pub fn parse_header(packet: &[u8]) -> Option<FrameHeader> {
    if packet.len() < OUTER_HEADER_SIZE {
        return None;
    }
    if packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION {
        return None;
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);
    let frame_type = FrameType::from_byte(packet[FRAME_TYPE_OFFSET])?;
    Some(FrameHeader { peer, frame_type })
}

/// Builds the 19-byte outer header for a given peer and frame type.
/// Writes [`PROTOCOL_VERSION`] at offset 17 and `frame_type` at offset 18.
/// The caller appends the type-specific payload after this header.
pub fn build_header(peer: &PeerId, frame_type: FrameType) -> [u8; OUTER_HEADER_SIZE] {
    let mut header = [0u8; OUTER_HEADER_SIZE];
    header[..17].copy_from_slice(peer);
    header[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    header[FRAME_TYPE_OFFSET] = frame_type as u8;
    header
}

mod tests;

//! Staging-trailer record: the bootable marker written after full
//! verification.
//!
//! The record lives at the END of the host's staging window (one erase block
//! is enough: 46 bytes). Layout (all integers LITTLE-endian, matching the
//! digest convention):
//!
//! ```text
//! [magic "SOTA":4] [version:4 LE] [img_len:4 LE] [sha256:32]
//! [attempts:1] [status:1]                                    = 46 bytes
//! ```
//!
//! # Trust-chain position
//!
//! The receiver writes `status = StagedValid` ONLY after the incremental
//! SHA-256 matched OTA_BEGIN and the manifest signature verified through the
//! secure element. A future bootloader re-checks the image hash before
//! applying; physical flash attackers can forge trailers regardless, so the
//! trailer is an anti-corruption gate, not an anti-tamper boundary.
//!
//! Bootloaders that cannot afford a sigil dependency may duplicate this
//! layout; the conformance vector in the tests module is the drift guard.

use crate::core::ota::error::OtaError;

/// Magic bytes `"SOTA"` opening every trailer record.
pub const TRAILER_MAGIC: [u8; 4] = [0x53, 0x4F, 0x54, 0x41];

/// Serialized size of one [`TrailerRecord`].
pub const TRAILER_LEN: usize = 46;

/// Lifecycle byte of a staged image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrailerStatus {
    /// Written by the receiver after full verification; a bootloader may
    /// apply this image.
    StagedValid = 0x01,
    /// Explicitly invalidated (applied, rejected by attempts exhaustion, or
    /// manually cleared).
    Invalidated = 0x00,
}

impl TrailerStatus {
    /// Parses a status byte; `None` for values outside the contract.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::StagedValid),
            0x00 => Some(Self::Invalidated),
            _ => None,
        }
    }
}

/// One staging-trailer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailerRecord {
    /// Image version from OTA_BEGIN.
    pub img_version: u32,
    /// Image length from OTA_BEGIN.
    pub img_len: u32,
    /// Expected image SHA-256 from OTA_BEGIN.
    pub sha256: [u8; 32],
    /// Apply-attempt counter owned by the bootloader (engine writes zero).
    pub attempts: u8,
    /// Current lifecycle state.
    pub status: TrailerStatus,
}

impl Default for TrailerRecord {
    fn default() -> Self {
        Self {
            img_version: 0,
            img_len: 0,
            sha256: [0u8; 32],
            attempts: 0,
            status: TrailerStatus::Invalidated,
        }
    }
}

impl TrailerRecord {
    /// Creates a fresh record marked valid for the bootloader, with the
    /// apply-attempt counter at zero.
    pub fn staged_valid(img_version: u32, img_len: u32, sha256: [u8; 32]) -> Self {
        Self {
            img_version,
            img_len,
            sha256,
            attempts: 0,
            status: TrailerStatus::StagedValid,
        }
    }

    /// Serializes into `out`; returns the written length ([`TRAILER_LEN`]).
    ///
    /// Fails with [`OtaError::BufferTooSmall`] when `out` is too short.
    pub fn serialize(&self, out: &mut [u8]) -> Result<usize, OtaError> {
        if out.len() < TRAILER_LEN {
            return Err(OtaError::BufferTooSmall {
                needed: TRAILER_LEN,
                available: out.len(),
            });
        }
        out[0..4].copy_from_slice(&TRAILER_MAGIC);
        out[4..8].copy_from_slice(&self.img_version.to_le_bytes());
        out[8..12].copy_from_slice(&self.img_len.to_le_bytes());
        out[12..44].copy_from_slice(&self.sha256);
        out[44] = self.attempts;
        out[45] = self.status as u8;
        Ok(TRAILER_LEN)
    }

    /// Parses and validates a serialized record; rejects wrong magic or
    /// unknown status bytes with [`OtaError::Malformed`].
    pub fn parse(raw: &[u8]) -> Result<Self, OtaError> {
        if raw.len() != TRAILER_LEN || raw[0..4] != TRAILER_MAGIC {
            return Err(OtaError::Malformed {
                id: 0,
                reason: "trailer magic or length mismatch",
            });
        }
        let status = TrailerStatus::from_byte(raw[45]).ok_or(OtaError::Malformed {
            id: 0,
            reason: "unknown trailer status byte",
        })?;
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&raw[12..44]);
        Ok(Self {
            img_version: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
            img_len: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
            sha256,
            attempts: raw[44],
            status,
        })
    }
}

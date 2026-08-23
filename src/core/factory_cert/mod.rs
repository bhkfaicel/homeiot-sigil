//! Sigil factory-certificate wire contract — the single source of truth shared
//! by the manufacturing tool (configAtecc) and the firmware.
//!
//! These bytes are part of the immutable install/identity protocol: the
//! manufacturing station writes them into the ATECC608B (slots 0, 8, 9) and the
//! firmware reads/verifies them at install time. Defining the layout once here
//! removes the drift risk of two independent definitions. Any change requires a
//! new certificate/record version byte, never an in-place edit after the first
//! locked lot.

// ---- Constants -----------------------------------------------------------

/// Factory certificate version byte (Sigil V1).
pub const FACTORY_CERT_VERSION: u8 = 0x01;

/// Canonical factory-certificate message length: 55 bytes.
///
/// `version[1] || product_id[2 BE] || hardware_profile_id[1] ||
/// factory_key_id[1] || peer_id[17] || device_pubkey_compressed[33]`
pub const FACTORY_CERT_MSG_LEN: usize = 1 + 2 + 1 + 1 + 17 + 33;

/// Factory record (slot 9) length: 72 bytes.
pub const FACTORY_RECORD_LEN: usize = 72;

/// ASCII "SGM1" magic stored at offset 64 of the factory record.
pub const FACTORY_METADATA_MAGIC: [u8; 4] = *b"SGM1";

/// PeerId / `local_mac` wire length.
pub const PEER_ID_LEN: usize = 17;

/// SEC1 compressed P-256 public key length.
pub const COMPRESSED_PUBKEY_LEN: usize = 33;

/// ECDSA-P256 raw signature length (`r || s`).
pub const SIGNATURE_RS_LEN: usize = 64;

// ---- ProductId -----------------------------------------------------------

/// Sigil product line — the closed set encoded as `product_id[2 BE]` at
/// offset 1 of the factory-certificate message.
///
/// Kept as a typed enum (not a free `u16`) so any value outside the known
/// product line is rejected at the API boundary instead of flowing silently
/// into the signed message. The wire encoding stays a big-endian `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProductId {
    /// Sensor device.
    Sensor = 0x0001,
    /// Gateway device.
    Gateway = 0x0002,
}

impl ProductId {
    /// Canonical wire value of the product.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Big-endian bytes for `product_id[2 BE]` at offset 1 of the message.
    pub const fn to_be_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    /// Parses a raw wire `u16`; returns `None` for unknown products.
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(ProductId::Sensor),
            0x0002 => Some(ProductId::Gateway),
            _ => None,
        }
    }
}

// ---- Errors --------------------------------------------------------------

/// Errors returned by the record builders/validators.
//
// The shared `Invalid` prefix is intentional (these are all input-validation
// failures); the names are clearer with it than without.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// `product_id` is neither sensor (0x0001) nor gateway (0x0002).
    InvalidProductId(u16),
    /// `peer_id` is not exactly 17 bytes.
    InvalidPeerIdLen(usize),
    /// Compressed public key is not exactly 33 bytes.
    InvalidCompressedPubkeyLen(usize),
    /// Signature (`r || s`) is not exactly 64 bytes.
    InvalidSignatureLen(usize),
    /// Magic bytes at offset 64 are not "SGM1".
    InvalidMagic([u8; 4]),
    /// Reserved bytes at offset 70 are not zero.
    InvalidReserved([u8; 2]),
}

// ---- Factory certificate message (55 bytes) ------------------------------

/// Builds the canonical 55-byte factory-certificate message.
///
/// All 55 bytes are covered by the factory ECDSA-P256 signature. `product_id`
/// is a typed [`ProductId`]: unknown products are rejected at the API boundary
/// (via `from_u16` / CLI parsing), not inside this builder.
pub fn build_factory_cert_message(
    product_id: ProductId,
    hardware_profile_id: u8,
    factory_key_id: u8,
    peer_id: &[u8],
    device_pubkey_compressed: &[u8],
) -> Result<[u8; FACTORY_CERT_MSG_LEN], RecordError> {
    if peer_id.len() != PEER_ID_LEN {
        return Err(RecordError::InvalidPeerIdLen(peer_id.len()));
    }
    if device_pubkey_compressed.len() != COMPRESSED_PUBKEY_LEN {
        return Err(RecordError::InvalidCompressedPubkeyLen(
            device_pubkey_compressed.len(),
        ));
    }

    let mut msg = [0u8; FACTORY_CERT_MSG_LEN];
    msg[0] = FACTORY_CERT_VERSION;
    msg[1..3].copy_from_slice(&product_id.to_be_bytes());
    msg[3] = hardware_profile_id;
    msg[4] = factory_key_id;
    msg[5..22].copy_from_slice(peer_id);
    msg[22..55].copy_from_slice(device_pubkey_compressed);
    Ok(msg)
}

// ---- Factory record (slot 9, 72 bytes) -----------------------------------

/// Decoded multi-SKU metadata + signature read back from the 72-byte record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryRecord {
    /// ECDSA-P256 raw signature `r || s` (64 bytes).
    pub signature_rs: [u8; SIGNATURE_RS_LEN],
    /// Hardware profile id (BOM) — mirrors the certificate message.
    pub hardware_profile_id: u8,
    /// Factory key id (signing-root selector) — mirrors the certificate message.
    pub factory_key_id: u8,
}

impl FactoryRecord {
    /// Assemble the 72-byte slot-9 record from a signature and metadata.
    ///
    /// Layout: `signature_rs[64] || "SGM1"[4] || hw_profile_id[1] ||
    /// factory_key_id[1] || reserved[2]=0x0000`.
    pub fn build(
        signature_rs: &[u8],
        hardware_profile_id: u8,
        factory_key_id: u8,
    ) -> Result<[u8; FACTORY_RECORD_LEN], RecordError> {
        if signature_rs.len() != SIGNATURE_RS_LEN {
            return Err(RecordError::InvalidSignatureLen(signature_rs.len()));
        }
        let mut rec = [0u8; FACTORY_RECORD_LEN];
        rec[0..64].copy_from_slice(signature_rs);
        rec[64..68].copy_from_slice(&FACTORY_METADATA_MAGIC);
        rec[68] = hardware_profile_id;
        rec[69] = factory_key_id;
        // rec[70..72] reserved, already zero.
        Ok(rec)
    }

    /// Parse and validate a 72-byte record read back from the chip.
    ///
    /// Verifies the `SGM1` magic and the zero reserved bytes; the cryptographic
    /// integrity of the identifiers is guaranteed by the certificate signature.
    pub fn from_bytes(record: &[u8; FACTORY_RECORD_LEN]) -> Result<Self, RecordError> {
        let magic = [record[64], record[65], record[66], record[67]];
        if magic != FACTORY_METADATA_MAGIC {
            return Err(RecordError::InvalidMagic(magic));
        }
        let reserved = [record[70], record[71]];
        if reserved != [0, 0] {
            return Err(RecordError::InvalidReserved(reserved));
        }
        let mut signature_rs = [0u8; SIGNATURE_RS_LEN];
        signature_rs.copy_from_slice(&record[0..64]);
        Ok(Self {
            signature_rs,
            hardware_profile_id: record[68],
            factory_key_id: record[69],
        })
    }
}

mod tests;

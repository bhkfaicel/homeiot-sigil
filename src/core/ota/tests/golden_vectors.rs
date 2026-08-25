//! Hand-written golden wire vectors for the OTA codec.
//!
//! These literals are the authoritative conformance contract between
//! implementations: sigil's codec, future host projects, and any external
//! signing tool MUST produce/consume exactly these bytes. They are written
//! by hand from the documented frame layouts (big-endian fields after the
//! two-byte envelope), so an encoder regression cannot silently pass by
//! re-deriving its own expectations.
//!
//! Copy this file verbatim into consuming repositories when wiring their own
//! conformance suites.

/// OTA_BEGIN golden vector: version=256, img_len=112640, chunk_len=192,
/// img_sha256 = bytes `00..1f`, manifest_sig = `5a` repeated 64 times.
pub const BEGIN_HEX: &str = concat!(
    "7f10",
    "00000100",
    "0001b800",
    "c0",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
);

/// Image version encoded in [`BEGIN_HEX`] (BE on the wire).
pub const BEGIN_VERSION: u32 = 256;
/// Image length encoded in [`BEGIN_HEX`] (BE on the wire).
pub const BEGIN_IMG_LEN: u32 = 112_640;
/// Negotiated chunk length encoded in [`BEGIN_HEX`].
pub const BEGIN_CHUNK_LEN: u8 = 192;

/// OTA_CHUNK golden vector: seq=7, data=[deadbeef].
pub const CHUNK_HEX: &str = "7f110007deadbeef";
/// Sequence number encoded in [`CHUNK_HEX`].
pub const CHUNK_SEQ: u16 = 7;
/// Chunk payload bytes encoded in [`CHUNK_HEX`].
pub const CHUNK_DATA: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

/// OTA_FINALIZE golden vector (no body).
pub const FINALIZE_HEX: &str = "7f12";

/// OTA_REBOOT golden vector: delay_ms=1500.
pub const REBOOT_HEX: &str = "7f1305dc";
/// Reboot delay encoded in [`REBOOT_HEX`].
pub const REBOOT_DELAY_MS: u16 = 1500;

/// OTA_ABORT golden vector (no body).
pub const ABORT_HEX: &str = "7f14";

/// OTA_ACK_READY golden vector: accepted_chunk_len=192.
pub const ACK_READY_HEX: &str = "7f15c0";

/// OTA_ACK_CHUNK golden vector: next_seq=42.
pub const ACK_CHUNK_HEX: &str = "7f16002a";
/// Next sequence number encoded in [`ACK_CHUNK_HEX`].
pub const ACK_NEXT_SEQ: u16 = 42;

/// OTA_ACK_FINAL golden vector: result=Ok.
pub const ACK_FINAL_OK_HEX: &str = "7f1700";

/// OTA_STATUS golden vector: state=Streaming, next_seq=9, version=256,
/// img_len=112640.
pub const STATUS_HEX: &str = "7f18010009000001000001b800";

// -------------------------------------------------------------------------
// Manifest-v2 signed-material literals (security conformance contract)
//
// These bytes were produced ONCE by the deterministic generator in
// `golden_vectors_material.rs` (fixed test scalar) and MUST be copied
// verbatim by signers/bootloaders. The verification test cross-checks them
// against an INDEPENDENT implementation (the `p256` crate), not against
// sigil's own code paths.
// -------------------------------------------------------------------------

/// SHA-256 of the canonical 300 B interop image (bytes `(i*13+5)%241`).
pub const MANIFEST_V2_IMAGE_SHA_HEX: &str =
    "A68BA90935019C9820352CE14AC052AC24ACFA2374C9980052CE26AA2649A628";

/// Frozen 55-byte manifest v2 input: `"sigil-ota-v2"` ‖ product_id_le(1) ‖
/// version_le(11) ‖ len_le(300) ‖ chunk_len(64) ‖ image_sha256.
pub const MANIFEST_V2_INPUT_HEX: &str = "736967696C2D6F74612D763201000B0000002C01000040A68BA90935019C9820352CE14AC052AC24ACFA2374C9980052CE26AA2649A628";

/// Compressed P-256 public key of the fixed test identity.
pub const MANIFEST_V2_PUBKEY_HEX: &str =
    "033AD3861A95621392516BB593EF05583ED2E5866F5CB6260A3017237FD89B90AF";

/// Real ECDSA signature (64-byte r‖s) over [`MANIFEST_V2_INPUT_HEX`] by the
/// matching private key.
pub const MANIFEST_V2_SIGNATURE_HEX: &str = "7AB69D55F3BCF02A823D74A19E71767FAFE914C44438C9283FC8A53AF014747A6CEE7F18A98C258C4C9AFEAF8A68EAF24010B8774F160178E6C005ABACDB80CF";

/// Decodes a lowercase hex string into bytes. Panics only on test-authoring
/// mistakes (odd length or non-hex characters), never on codec behavior.
#[cfg(test)]
pub(crate) fn unhex(s: &str) -> alloc::vec::Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len() % 2 == 0, "golden vector has odd hex length");
    let mut out = alloc::vec::Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).expect("bad hex digit") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("bad hex digit") as u8;
        out.push((hi << 4) | lo);
    }
    out
}

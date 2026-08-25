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

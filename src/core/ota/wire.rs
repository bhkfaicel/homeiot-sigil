//! OTA wire contract: command ids, frame codec, and manifest digest.
//!
//! All frames are AEAD `Data` plaintexts sharing the product envelope
//! `[0x7F][command_id][body..]`. Encoding writes into a caller-provided
//! buffer and returns the written length (single-buffer, no heap, no stack
//! blowout for variable-length chunks); parsing borrows the input and
//! returns owned fixed-size field structs plus borrowed chunk data.
//!
//! Every function validates its inputs against the bounds documented in the
//! module docs and returns [`OtaError`] instead of panicking.

use crate::core::ota::error::OtaError;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Envelope and command identifiers
// ---------------------------------------------------------------------------

/// Product gateway-command opcode byte shared with existing application
/// commands; every OTA payload starts with this byte.
pub const GATEWAY_CMD_OPCODE: u8 = 0x7F;

/// OTA_BEGIN (sender → receiver): open/confirm a transfer session.
pub const CMD_BEGIN: u8 = 0x10;
/// OTA_CHUNK (sender → receiver): one contiguous image chunk.
pub const CMD_CHUNK: u8 = 0x11;
/// OTA_FINALIZE (sender → receiver): request end-of-transfer verification.
pub const CMD_FINALIZE: u8 = 0x12;
/// OTA_REBOOT (sender → receiver): apply-and-reboot request.
pub const CMD_REBOOT: u8 = 0x13;
/// OTA_ABORT (sender → receiver): abandon the transfer session.
pub const CMD_ABORT: u8 = 0x14;
/// OTA_ACK_READY (receiver → sender): transfer parameters accepted.
pub const CMD_ACK_READY: u8 = 0x15;
/// OTA_ACK_CHUNK (receiver → sender): cumulative contiguous acknowledgement.
pub const CMD_ACK_CHUNK: u8 = 0x16;
/// OTA_ACK_FINAL (receiver → sender): finalize verdict.
pub const CMD_ACK_FINAL: u8 = 0x17;
/// OTA_STATUS (receiver → sender): current transfer state projection.
pub const CMD_STATUS: u8 = 0x18;

// Envelope offsets inside a Data payload.
const OPCODE_OFFSET: usize = 0;
const COMMAND_ID_OFFSET: usize = 1;
const BODY_OFFSET: usize = 2;

// Fixed total frame lengths (envelope + body).
/// Total length of an OTA_BEGIN frame.
pub const BEGIN_LEN: usize = BODY_OFFSET + 4 + 4 + 1 + 32 + 64;
/// Total length of an OTA_FINALIZE frame.
pub const FINALIZE_LEN: usize = BODY_OFFSET;
/// Total length of an OTA_REBOOT frame.
pub const REBOOT_LEN: usize = BODY_OFFSET + 2;
/// Total length of an OTA_ABORT frame.
pub const ABORT_LEN: usize = BODY_OFFSET;
/// Total length of an OTA_ACK_READY frame.
pub const ACK_READY_LEN: usize = BODY_OFFSET + 1;
/// Total length of an OTA_ACK_CHUNK frame.
pub const ACK_CHUNK_LEN: usize = BODY_OFFSET + 2;
/// Total length of an OTA_ACK_FINAL frame.
pub const ACK_FINAL_LEN: usize = BODY_OFFSET + 1;
/// Total length of an OTA_STATUS frame.
pub const STATUS_LEN: usize = BODY_OFFSET + 1 + 2 + 4 + 4;
/// Total header length of an OTA_CHUNK frame (everything before chunk data).
pub const CHUNK_HEADER_LEN: usize = BODY_OFFSET + 2;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/// Inclusive lower bound of a negotiated `chunk_len`.
///
/// Small chunks waste airtime on framing overhead; the floor keeps transfers
/// meaningful over slow links.
pub const CHUNK_LEN_MIN: usize = 64;

/// Inclusive upper bound of a negotiated `chunk_len`, and of any individual
/// chunk data length.
///
/// Derivation: product Data payload bound (200) minus the OTA envelope and
/// sequence overhead (4). A drift-guard test asserts consistency whenever
/// the `session` feature is also compiled.
pub const CHUNK_LEN_MAX: usize = 196;

// ---------------------------------------------------------------------------
// Enumerations carried in reply bodies
// ---------------------------------------------------------------------------

/// Verdict reported by OTA_ACK_FINAL (`0x17`).
///
/// Values are part of the wire contract; unknown values are rejected by the
/// parser so both sides fail loudly on protocol drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FinalResult {
    /// Image staged, hash and signature verified.
    Ok = 0,
    /// Staged content hash does not match OTA_BEGIN.
    HashMismatch = 1,
    /// Manifest signature rejected by the host secure element.
    SigRejected = 2,
    /// Storage sink failed while staging or marking the image.
    StorageError = 3,
    /// Command invalid for the receiver's current state.
    BadState = 4,
    /// Transfer parameters exceed host capacity (e.g. image larger than the
    /// staging window).
    SizeRejected = 5,
    /// Signed image version is OLDER than the host's rollback-protection
    /// floor (anti-downgrade policy; see `OtaReceiver` construction).
    VersionRejected = 6,
}

impl FinalResult {
    /// Parses a result byte; `None` for values outside the contract.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Ok),
            1 => Some(Self::HashMismatch),
            2 => Some(Self::SigRejected),
            3 => Some(Self::StorageError),
            4 => Some(Self::BadState),
            5 => Some(Self::SizeRejected),
            6 => Some(Self::VersionRejected),
            _ => None,
        }
    }
}

/// Receiver state byte carried by OTA_STATUS (`0x18`).
///
/// The terminal failure path is expressed through [`FinalResult`], not
/// through a persistent state value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerState {
    /// No transfer session exists (or it was aborted/expired).
    Idle = 0,
    /// A transfer is open and waiting for chunks.
    Streaming = 1,
    /// Image verified and bootable marker written; awaiting reboot.
    PendingReboot = 2,
}

impl PeerState {
    /// Parses a state byte; `None` for values outside the contract.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Idle),
            1 => Some(Self::Streaming),
            2 => Some(Self::PendingReboot),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Frame field structures
// ---------------------------------------------------------------------------

/// Decoded OTA_BEGIN fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginFrame {
    /// Firmware image version (product semantics; monotonic per device line).
    pub img_version: u32,
    /// Total image length in bytes (non-zero).
    pub img_len: u32,
    /// Negotiated chunk size in bytes, `CHUNK_LEN_MIN..=CHUNK_LEN_MAX`.
    pub chunk_len: u8,
    /// SHA-256 digest of the full image.
    pub img_sha256: [u8; 32],
    /// ECDSA P-256 signature (r‖s) over [`manifest_digest`] of these fields.
    pub manifest_sig: [u8; 64],
}

/// Decoded OTA_CHUNK fields. Chunk data borrows the input payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkFrame<'a> {
    /// Zero-based chunk index; valid range is bounded by the negotiated
    /// transfer geometry (engine-side check).
    pub seq: u16,
    /// Chunk bytes (1..=`CHUNK_LEN_MAX`; last chunk may be short).
    pub data: &'a [u8],
}

/// Decoded OTA_STATUS fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFrame {
    /// Current receiver state.
    pub state: PeerState,
    /// Next expected contiguous chunk sequence number.
    pub next_seq: u16,
    /// Image version of the open (or completed) transfer session.
    pub img_version: u32,
    /// Image length of the open (or completed) transfer session.
    pub img_len: u32,
}

/// Any decodable OTA command. Chunk data borrows the parsed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtaCommand<'a> {
    /// Open or re-confirm a transfer session.
    Begin(BeginFrame),
    /// One image chunk.
    Chunk(ChunkFrame<'a>),
    /// Request end-of-transfer verification.
    Finalize,
    /// Apply-and-reboot request after a successful finalize.
    Reboot {
        /// Delay before reset, letting the ACK flush through the radio.
        delay_ms: u16,
    },
    /// Abandon the transfer session.
    Abort,
    /// Transfer parameters accepted.
    AckReady {
        /// Echo of the accepted negotiated chunk length.
        chunk_len: u8,
    },
    /// Cumulative contiguous acknowledgement.
    AckChunk {
        /// Next expected chunk sequence number.
        next_seq: u16,
    },
    /// Finalize verdict.
    AckFinal(FinalResult),
    /// Current transfer state projection.
    Status(StatusFrame),
}

// ---------------------------------------------------------------------------
// Manifest digest
// ---------------------------------------------------------------------------

/// Domain-separation tag prefixed to every manifest digest. The `v2` tag
/// marks the layout that BINDS the product identifier (see
/// [`manifest_digest_input`]); v1 never shipped, so no cross-version
/// compatibility is required.
const MANIFEST_DOMAIN: &[u8] = b"sigil-ota-v2";

/// Builds the canonical 55-byte manifest input that is signed and verified.
///
/// This is the byte string handed to
/// [`SecureElement::verify_ecdsa`](crate::core::traits::SecureElement::verify_ecdsa)
/// (implementations hash the message themselves, mirroring the install
/// paths) and the preimage of [`manifest_digest`]. Signers sign
/// `SHA256(manifest_digest_input(..))`; verifiers pass the same input to the
/// secure element. Single source of truth for both directions.
///
/// Layout:
/// `"sigil-ota-v2"` ‖ product_id_le ‖ version_le ‖ len_le ‖ chunk_len ‖
/// img_sha256. Binding `product_id` into the SIGNED material prevents a
/// validly-signed image for one product from being accepted by another
/// product sharing the same factory root key. Integer fields use
/// LITTLE-endian by design (native order on Cortex-M0+); wire frames stay
/// big-endian.
pub fn manifest_digest_input(
    product_id: u16,
    img_version: u32,
    img_len: u32,
    chunk_len: u8,
    img_sha256: &[u8; 32],
) -> [u8; 55] {
    // 12 (domain) + 2 + 4 + 4 + 1 + 32 = 55 bytes of domain-separated input.
    let mut input = [0u8; 55];
    let mut off = 0;
    input[..MANIFEST_DOMAIN.len()].copy_from_slice(MANIFEST_DOMAIN);
    off += MANIFEST_DOMAIN.len();
    input[off..off + 2].copy_from_slice(&product_id.to_le_bytes());
    off += 2;
    input[off..off + 4].copy_from_slice(&img_version.to_le_bytes());
    off += 4;
    input[off..off + 4].copy_from_slice(&img_len.to_le_bytes());
    off += 4;
    input[off] = chunk_len;
    off += 1;
    input[off..off + 32].copy_from_slice(img_sha256);
    input
}

/// Computes the canonical manifest digest signed by the factory key.
///
/// ```text
/// manifest_digest(m) = SHA256(manifest_digest_input(m))
/// ```
///
/// This function is the SINGLE SOURCE OF TRUTH for signers and verifiers:
/// offline signing tools must call (or byte-for-byte replicate, via the
/// golden vectors) this construction instead of inventing their own.
pub fn manifest_digest(
    product_id: u16,
    img_version: u32,
    img_len: u32,
    chunk_len: u8,
    img_sha256: &[u8; 32],
) -> [u8; 32] {
    let input = manifest_digest_input(product_id, img_version, img_len, chunk_len, img_sha256);
    let digest = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Writes the two-byte envelope header into `out` and returns the body slice
/// position. Fails with [`OtaError::BufferTooSmall`] when `out` cannot hold
/// `need` bytes.
fn write_header(out: &mut [u8], id: u8, need: usize) -> Result<&mut [u8], OtaError> {
    if out.len() < need {
        return Err(OtaError::BufferTooSmall {
            needed: need,
            available: out.len(),
        });
    }
    out[OPCODE_OFFSET] = GATEWAY_CMD_OPCODE;
    out[COMMAND_ID_OFFSET] = id;
    Ok(&mut out[BODY_OFFSET..])
}

/// Validates transfer-geometry fields shared by encode and parse paths.
fn validate_begin(chunk_len: u8, img_len: u32) -> Result<(), OtaError> {
    let chunk = usize::from(chunk_len);
    if !(CHUNK_LEN_MIN..=CHUNK_LEN_MAX).contains(&chunk) {
        return Err(OtaError::InvalidParams {
            reason: "chunk_len outside CHUNK_LEN_MIN..=CHUNK_LEN_MAX",
        });
    }
    if img_len == 0 {
        return Err(OtaError::InvalidParams {
            reason: "img_len must be non-zero",
        });
    }
    Ok(())
}

/// Encodes an OTA_BEGIN frame into `out`, returning the written length.
///
/// `out` must be at least [`BEGIN_LEN`] bytes.
pub fn encode_begin(begin: &BeginFrame, out: &mut [u8]) -> Result<usize, OtaError> {
    validate_begin(begin.chunk_len, begin.img_len)?;
    let body = write_header(out, CMD_BEGIN, BEGIN_LEN)?;
    body[0..4].copy_from_slice(&begin.img_version.to_be_bytes());
    body[4..8].copy_from_slice(&begin.img_len.to_be_bytes());
    body[8] = begin.chunk_len;
    body[9..41].copy_from_slice(&begin.img_sha256);
    body[41..105].copy_from_slice(&begin.manifest_sig);
    Ok(BEGIN_LEN)
}

/// Encodes one OTA_CHUNK frame into `out`, returning the written length.
///
/// `data` must be 1..=[`CHUNK_LEN_MAX`] bytes; `out` at least
/// `CHUNK_HEADER_LEN + data.len()`.
pub fn encode_chunk(seq: u16, data: &[u8], out: &mut [u8]) -> Result<usize, OtaError> {
    if data.is_empty() {
        return Err(OtaError::InvalidParams {
            reason: "chunk data must not be empty",
        });
    }
    if data.len() > CHUNK_LEN_MAX {
        return Err(OtaError::InvalidParams {
            reason: "chunk data exceeds CHUNK_LEN_MAX",
        });
    }
    let need = CHUNK_HEADER_LEN + data.len();
    let body = write_header(out, CMD_CHUNK, need)?;
    body[0..2].copy_from_slice(&seq.to_be_bytes());
    body[2..data.len() + 2].copy_from_slice(data);
    Ok(need)
}

/// Encodes an OTA_FINALIZE frame into `out`, returning the written length.
pub fn encode_finalize(out: &mut [u8]) -> Result<usize, OtaError> {
    write_header(out, CMD_FINALIZE, FINALIZE_LEN)?;
    Ok(FINALIZE_LEN)
}

/// Encodes an OTA_REBOOT frame into `out`, returning the written length.
pub fn encode_reboot(delay_ms: u16, out: &mut [u8]) -> Result<usize, OtaError> {
    let body = write_header(out, CMD_REBOOT, REBOOT_LEN)?;
    body[0..2].copy_from_slice(&delay_ms.to_be_bytes());
    Ok(REBOOT_LEN)
}

/// Encodes an OTA_ABORT frame into `out`, returning the written length.
pub fn encode_abort(out: &mut [u8]) -> Result<usize, OtaError> {
    write_header(out, CMD_ABORT, ABORT_LEN)?;
    Ok(ABORT_LEN)
}

/// Encodes an OTA_ACK_READY frame into `out`, returning the written length.
pub fn encode_ack_ready(chunk_len: u8, out: &mut [u8]) -> Result<usize, OtaError> {
    if !(CHUNK_LEN_MIN..=CHUNK_LEN_MAX).contains(&usize::from(chunk_len)) {
        return Err(OtaError::InvalidParams {
            reason: "accepted chunk_len outside CHUNK_LEN_MIN..=CHUNK_LEN_MAX",
        });
    }
    let body = write_header(out, CMD_ACK_READY, ACK_READY_LEN)?;
    body[0] = chunk_len;
    Ok(ACK_READY_LEN)
}

/// Encodes an OTA_ACK_CHUNK frame into `out`, returning the written length.
pub fn encode_ack_chunk(next_seq: u16, out: &mut [u8]) -> Result<usize, OtaError> {
    let body = write_header(out, CMD_ACK_CHUNK, ACK_CHUNK_LEN)?;
    body[0..2].copy_from_slice(&next_seq.to_be_bytes());
    Ok(ACK_CHUNK_LEN)
}

/// Encodes an OTA_ACK_FINAL frame into `out`, returning the written length.
pub fn encode_ack_final(result: FinalResult, out: &mut [u8]) -> Result<usize, OtaError> {
    let body = write_header(out, CMD_ACK_FINAL, ACK_FINAL_LEN)?;
    body[0] = result as u8;
    Ok(ACK_FINAL_LEN)
}

/// Encodes an OTA_STATUS frame into `out`, returning the written length.
pub fn encode_status(status: &StatusFrame, out: &mut [u8]) -> Result<usize, OtaError> {
    let body = write_header(out, CMD_STATUS, STATUS_LEN)?;
    body[0] = status.state as u8;
    body[1..3].copy_from_slice(&status.next_seq.to_be_bytes());
    body[3..7].copy_from_slice(&status.img_version.to_be_bytes());
    body[7..11].copy_from_slice(&status.img_len.to_be_bytes());
    Ok(STATUS_LEN)
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parses one OTA command from a decrypted Data payload.
///
/// Returns a borrowed view; no allocation. Every structural violation maps
/// to [`OtaError::Malformed`]; both sides reject unknown enum values so
/// protocol drift fails loudly instead of silently misbehaving.
pub fn parse_command(payload: &[u8]) -> Result<OtaCommand<'_>, OtaError> {
    if payload.len() < BODY_OFFSET {
        return Err(OtaError::Malformed {
            id: 0,
            reason: "payload shorter than the envelope header",
        });
    }
    if payload[OPCODE_OFFSET] != GATEWAY_CMD_OPCODE {
        return Err(OtaError::Malformed {
            id: 0,
            reason: "envelope opcode is not the gateway-command opcode",
        });
    }
    let id = payload[COMMAND_ID_OFFSET];
    let body = &payload[BODY_OFFSET..];
    match id {
        CMD_BEGIN => {
            if body.len() != BEGIN_LEN - BODY_OFFSET {
                return Err(OtaError::Malformed {
                    id,
                    reason: "BEGIN body has wrong length",
                });
            }
            let img_version = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let img_len = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let chunk_len = body[8];
            validate_begin(chunk_len, img_len).map_err(|_| OtaError::Malformed {
                id,
                reason: "BEGIN geometry fields out of contract bounds",
            })?;
            let mut img_sha256 = [0u8; 32];
            img_sha256.copy_from_slice(&body[9..41]);
            let mut manifest_sig = [0u8; 64];
            manifest_sig.copy_from_slice(&body[41..105]);
            Ok(OtaCommand::Begin(BeginFrame {
                img_version,
                img_len,
                chunk_len,
                img_sha256,
                manifest_sig,
            }))
        }
        CMD_CHUNK => {
            if body.len() < 2 || body.len() > 2 + CHUNK_LEN_MAX {
                return Err(OtaError::Malformed {
                    id,
                    reason: "CHUNK body length out of contract bounds",
                });
            }
            if body.len() == 2 {
                return Err(OtaError::Malformed {
                    id,
                    reason: "CHUNK data must not be empty",
                });
            }
            let seq = u16::from_be_bytes([body[0], body[1]]);
            Ok(OtaCommand::Chunk(ChunkFrame {
                seq,
                data: &body[2..],
            }))
        }
        CMD_FINALIZE => {
            if !body.is_empty() {
                return Err(OtaError::Malformed {
                    id,
                    reason: "FINALIZE carries unexpected trailing bytes",
                });
            }
            Ok(OtaCommand::Finalize)
        }
        CMD_REBOOT => {
            if body.len() != 2 {
                return Err(OtaError::Malformed {
                    id,
                    reason: "REBOOT body has wrong length",
                });
            }
            Ok(OtaCommand::Reboot {
                delay_ms: u16::from_be_bytes([body[0], body[1]]),
            })
        }
        CMD_ABORT => {
            if !body.is_empty() {
                return Err(OtaError::Malformed {
                    id,
                    reason: "ABORT carries unexpected trailing bytes",
                });
            }
            Ok(OtaCommand::Abort)
        }
        CMD_ACK_READY => {
            if body.len() != 1 {
                return Err(OtaError::Malformed {
                    id,
                    reason: "ACK_READY body has wrong length",
                });
            }
            if !(CHUNK_LEN_MIN..=CHUNK_LEN_MAX).contains(&usize::from(body[0])) {
                return Err(OtaError::Malformed {
                    id,
                    reason: "ACK_READY chunk_len out of contract bounds",
                });
            }
            Ok(OtaCommand::AckReady { chunk_len: body[0] })
        }
        CMD_ACK_CHUNK => {
            if body.len() != 2 {
                return Err(OtaError::Malformed {
                    id,
                    reason: "ACK_CHUNK body has wrong length",
                });
            }
            Ok(OtaCommand::AckChunk {
                next_seq: u16::from_be_bytes([body[0], body[1]]),
            })
        }
        CMD_ACK_FINAL => {
            if body.len() != 1 {
                return Err(OtaError::Malformed {
                    id,
                    reason: "ACK_FINAL body has wrong length",
                });
            }
            let result = FinalResult::from_byte(body[0]).ok_or(OtaError::Malformed {
                id,
                reason: "unknown ACK_FINAL result code",
            })?;
            Ok(OtaCommand::AckFinal(result))
        }
        CMD_STATUS => {
            if body.len() != STATUS_LEN - BODY_OFFSET {
                return Err(OtaError::Malformed {
                    id,
                    reason: "STATUS body has wrong length",
                });
            }
            let state = PeerState::from_byte(body[0]).ok_or(OtaError::Malformed {
                id,
                reason: "unknown STATUS state byte",
            })?;
            Ok(OtaCommand::Status(StatusFrame {
                state,
                next_seq: u16::from_be_bytes([body[1], body[2]]),
                img_version: u32::from_be_bytes([body[3], body[4], body[5], body[6]]),
                img_len: u32::from_be_bytes([body[7], body[8], body[9], body[10]]),
            }))
        }
        _ => Err(OtaError::Malformed {
            id,
            reason: "unknown OTA command id",
        }),
    }
}

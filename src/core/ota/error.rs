//! Error taxonomy for the OTA protocol module.
//!
//! [`OtaError`] is deliberately LOCAL to `core::ota`: it never touches the
//! session-level [`SigilError`](crate::core::error::SigilError) enum, so this
//! additive module cannot break downstream exhaustive matches of that type.
//!
//! # Host policy categories
//!
//! Every variant maps to exactly one deterministic host policy category,
//! mirroring the crate-wide convention:
//!
//! - **Reject input**: malformed or out-of-bounds wire input; drop the frame.
//! - **Fix integration**: caller-provided buffer or parameter is statically
//!   wrong; correct the firmware, retrying as-is cannot help.
//! - **Back off / report**: engine-level conditions (storage sink failure,
//!   command invalid for the current state) surfaced to hosts in later
//!   receive/send half tasks.

use core::fmt;

/// Errors returned by the OTA wire codec and protocol engines.
///
/// # Evolution policy
///
/// Marked `#[non_exhaustive]` from day one: future minor releases may add
/// variants without a breaking release, and downstream matches MUST carry a
/// wildcard arm. The wire-level enums
/// ([`FinalResult`](crate::core::ota::wire::FinalResult) /
/// [`PeerState`](crate::core::ota::wire::PeerState)) are deliberately CLOSED
/// v1 sets instead: parsers reject unknown bytes so both sides fail loudly
/// on protocol drift; extending them is a protocol revision requiring a
/// coordinated major version bump.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtaError {
    /// A received payload violated the wire contract (wrong envelope opcode,
    /// unknown command id, wrong body length, field out of range).
    /// Host policy: reject input (drop the frame).
    Malformed {
        /// Command id byte when it was readable; `0` otherwise (e.g. the
        /// envelope opcode itself was wrong).
        id: u8,
        /// Static reason describing which rule failed (never secret data).
        reason: &'static str,
    },

    /// The caller-provided output buffer could not hold the encoded frame.
    /// Host policy: fix integration (size the TX buffer to the documented
    /// frame length and retry).
    BufferTooSmall {
        /// Exact number of bytes required for the frame.
        needed: usize,
        /// Number of bytes the caller offered.
        available: usize,
    },

    /// An encode-side parameter is outside the contract bounds (e.g.
    /// `chunk_len` not in `CHUNK_LEN_MIN..=CHUNK_LEN_MAX`, empty chunk data,
    /// zero image length). Host policy: fix integration (the sender must be
    /// constructed with valid transfer parameters; nothing was transmitted).
    InvalidParams {
        /// Static reason describing which parameter failed (never secret data).
        reason: &'static str,
    },

    /// The host storage sink failed while persisting staged image data or
    /// metadata. Host policy: back off / report — the engine leaves the
    /// session retryable, and the HOST decides whether to answer the peer
    /// with [`FinalResult::StorageError`](crate::core::ota::wire::FinalResult::StorageError),
    /// wait, or abort; the engine itself never fabricates that wire reply.
    Storage,

    /// A command arrived that is not valid for the engine's current state
    /// (e.g. a chunk before BEGIN). Host policy: reject input (optionally
    /// answer with
    /// [`FinalResult::BadState`](crate::core::ota::wire::FinalResult::BadState)).
    BadState {
        /// Static description of the rejected transition (never secret data).
        reason: &'static str,
    },
}

impl fmt::Display for OtaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtaError::Malformed { id, reason } => {
                write!(f, "malformed OTA frame (id={id:#04x}): {reason}")
            }
            OtaError::BufferTooSmall { needed, available } => write!(
                f,
                "OTA output buffer too small: needed {needed} bytes, have {available}"
            ),
            OtaError::InvalidParams { reason } => {
                write!(f, "invalid OTA transfer parameters: {reason}")
            }
            OtaError::Storage => write!(f, "OTA storage sink failed"),
            OtaError::BadState { reason } => {
                write!(f, "OTA command invalid for current state: {reason}")
            }
        }
    }
}

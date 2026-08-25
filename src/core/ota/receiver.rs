//! Receive-side OTA transfer engine (sensor half).
//!
//! Pure protocol policy over injected effects ([`OtaStorage`] sink plus the
//! crate-wide [`SecureElement`] trait): no hardware, radio, clock, or
//! crypto-vendor types. The host feeds DECODED commands ([`OtaCommand`],
//! produced by [`parse_command`](crate::core::ota::wire::parse_command) on
//! decrypted Data payloads) and transmits whatever reply the returned
//! [`RxOutcome`] carries.
//!
//! # Session semantics (v1 contract)
//!
//! - Strictly contiguous chunks: any sequence number other than `next_seq`
//!   is answered with the CURRENT cumulative acknowledgement, which both
//!   rejects the frame and re-teaches the sender's position (lost-ACK
//!   recovery needs no extra message type).
//! - An identical re-transmitted BEGIN mid-stream is idempotent (progress
//!   kept); a DIFFERENT one is rejected (`BadState`) until an explicit
//!   ABORT clears the session.
//! - FINALIZE before every chunk arrived answers `BadState` and KEEPS the
//!   session (recoverable). A hash or signature failure tears the session
//!   down (staged data cannot be trusted; restart required). A storage
//!   failure surfaces as [`OtaError::Storage`] and leaves the session
//!   retryable verbatim.
//! - Re-FINALIZE after success (lost final ACK) re-answers `Ok`
//!   idempotently without touching storage again.
//! - An idle timeout (`tick`) expires an unfinished session; a verified
//!   pending-reboot session never times out here (reboot is host policy).
//!
//! # Storage sequencing
//!
//! Chunks are persisted BEFORE any in-RAM progress advances, so storage
//! faults leave the engine byte-identical and the triggering command can be
//! retried verbatim. Each granularity block is erased exactly once per
//! session (erase-once bitmap, bounded by [`MAX_STAGING_BLOCKS`]); the
//! trailer marker is written as a single unconditional aligned erase+write
//! outside that bookkeeping.
//!
//! # Trust chain position
//!
//! The bootable marker ([`TrailerRecord`] with `StagedValid`) is written
//! ONLY after the incremental SHA-256 matched OTA_BEGIN and the manifest
//! signature verified through the host secure element.

use crate::core::ota::error::OtaError;
use crate::core::ota::storage::OtaStorage;
use crate::core::ota::trailer::{TRAILER_LEN, TrailerRecord};
use crate::core::ota::wire::{
    BeginFrame, FinalResult, OtaCommand, PeerState, StatusFrame, manifest_digest_input,
};
use crate::core::traits::SecureElement;
use sha2::{Digest, Sha256};

/// Default idle timeout applied when a streaming session receives nothing.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u32 = 30;

/// Reply frames the engine asks the host to transmit (encode with the
/// matching `wire::encode_*` function).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// OTA_ACK_READY: transfer parameters accepted.
    Ready {
        /// Echo of the negotiated chunk length.
        chunk_len: u8,
    },
    /// OTA_ACK_CHUNK: cumulative contiguous acknowledgement.
    ChunkAck {
        /// Next expected chunk sequence number.
        next_seq: u16,
    },
    /// OTA_ACK_FINAL: finalize verdict.
    Final(FinalResult),
    /// OTA_STATUS: current state projection.
    Status(StatusFrame),
}

/// What the host should do after one processed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxOutcome {
    /// Transmit this reply frame.
    Respond(Reply),
    /// Nothing to transmit (ABORT is fire-and-forget by contract).
    Silent,
    /// Schedule the deferred system reset (REBOOT command accepted).
    RebootAfterMs(u16),
}

/// Outcome of one [`OtaReceiver::tick`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// No change.
    Continue,
    /// The streaming session was torn down after the idle timeout.
    ExpiredIdleTimeout,
}

/// Active streaming session (private; projected through accessors).
struct StreamingSession {
    img_version: u32,
    img_len: u32,
    chunk_len: u8,
    /// Total number of chunks for the negotiated geometry (> 0, <= u16::MAX).
    total_chunks: u16,
    /// Next contiguous chunk index expected.
    next_seq: u16,
    /// Incremental digest over accepted chunk bytes.
    hasher: Sha256,
    /// BEGIN copy driving identical-reBEGIN detection and verification.
    begin: BeginFrame,
    /// Last activity stamp (whole seconds) feeding the idle timeout.
    last_activity_secs: u32,
    /// Erase-once bookkeeping: bit `b` set means granularity block `b` was
    /// already erased in THIS session, so later writes into it must not
    /// erase again (they would destroy neighboring staged chunks).
    erased_blocks: BlockBitmap,
}

/// Fixed-capacity bitmap over staging erase blocks.
///
/// Capacity bound: 512 blocks. With the product SAMD21 row size (256 B) this
/// covers a 128 KiB window; hosts whose granularity would need more blocks
/// get `SizeRejected` at BEGIN rather than silent truncation.
const BLOCK_BITMAP_WORDS: usize = 8;
/// Maximum number of distinct erase blocks a transfer may track.
pub const MAX_STAGING_BLOCKS: u32 = (BLOCK_BITMAP_WORDS * 64) as u32;

#[derive(Clone, Copy)]
struct BlockBitmap {
    words: [u64; BLOCK_BITMAP_WORDS],
}

impl BlockBitmap {
    fn new() -> Self {
        Self {
            words: [0u64; BLOCK_BITMAP_WORDS],
        }
    }

    /// Marks block `idx` erased; returns `true` when it was NOT marked
    /// before (i.e. the caller must erase it now).
    fn test_and_set(&mut self, idx: usize) -> bool {
        debug_assert!(idx < MAX_STAGING_BLOCKS as usize);
        let prev = self.words[idx / 64] & (1u64 << (idx % 64)) != 0;
        self.words[idx / 64] |= 1u64 << (idx % 64);
        !prev
    }
}

// Deliberately uneven variants: fixed-capacity by design (no_std, no
// heap). The engine embeds exactly one `RxState`, so total size equals the
// streaming arm; bounds tests pin it.
#[allow(clippy::large_enum_variant)]
enum RxState {
    Idle,
    Streaming(StreamingSession),
    /// Verified image awaiting the reboot decision (host policy).
    PendingReboot {
        img_version: u32,
        img_len: u32,
        total_chunks: u16,
    },
}

impl RxState {
    fn coarse(&self) -> PeerState {
        match self {
            RxState::Idle => PeerState::Idle,
            RxState::Streaming(_) => PeerState::Streaming,
            RxState::PendingReboot { .. } => PeerState::PendingReboot,
        }
    }
}

/// Receive-side OTA transfer engine.
///
/// The engine owns NO hardware handles: storage and secure element are
/// passed per command so hosts (RTIC tasks, tests) control borrowing.
pub struct OtaReceiver {
    /// Factory root public key (33-byte compressed SEC1) verifying manifests.
    factory_pubkey: [u8; 33],
    /// Maximum image size the host staging window accepts.
    staging_cap: u32,
    /// Offset (relative to the staging window base) of the trailer record.
    trailer_offset: u32,
    /// Whole-second idle timeout for unfinished sessions.
    idle_timeout_secs: u32,
    state: RxState,
}

/// Rounds `value` up to a multiple of `granularity` (> 0).
fn align_up(value: u32, granularity: u32) -> u32 {
    debug_assert!(granularity > 0);
    value.div_ceil(granularity) * granularity
}

impl OtaReceiver {
    /// Creates an engine bound to the host's staging geometry.
    ///
    /// * `factory_pubkey`: root key verifying manifest signatures.
    /// * `staging_cap`: maximum acceptable `img_len`.
    /// * `trailer_offset`: write position of the [`TrailerRecord`]; must not
    ///   overlap the image area (host layout responsibility).
    /// * `idle_timeout_secs`: whole seconds without traffic before `tick`
    ///   expires a streaming session.
    pub fn new(
        factory_pubkey: [u8; 33],
        staging_cap: u32,
        trailer_offset: u32,
        idle_timeout_secs: u32,
    ) -> Self {
        Self {
            factory_pubkey,
            staging_cap,
            trailer_offset,
            idle_timeout_secs,
            state: RxState::Idle,
        }
    }

    /// Current coarse state projection.
    pub fn state(&self) -> PeerState {
        self.state.coarse()
    }

    /// Next expected chunk sequence while streaming (`None` otherwise).
    pub fn next_seq(&self) -> Option<u16> {
        match &self.state {
            RxState::Streaming(s) => Some(s.next_seq),
            _ => None,
        }
    }

    /// Builds the STATUS reply for the current state. The host transmits it
    /// on its own diagnostic schedule (the v1 wire contract defines STATUS
    /// as a reply only; there is no request frame).
    pub fn status(&self) -> Reply {
        self.status_reply()
    }

    /// Geometry of the open or completed session: `(version, img_len)`.
    pub fn session_geometry(&self) -> Option<(u32, u32)> {
        match &self.state {
            RxState::Streaming(s) => Some((s.img_version, s.img_len)),
            RxState::PendingReboot {
                img_version,
                img_len,
                ..
            } => Some((*img_version, *img_len)),
            RxState::Idle => None,
        }
    }

    /// Processes one decoded command at monotonic time `now` (seconds).
    ///
    /// Storage failures return [`OtaError::Storage`] and leave the engine
    /// state untouched, so the triggering command can be retried verbatim.
    pub fn on_command<S: OtaStorage, SE: SecureElement>(
        &mut self,
        storage: &mut S,
        se: &mut SE,
        cmd: OtaCommand<'_>,
        now: u32,
    ) -> Result<RxOutcome, OtaError> {
        match cmd {
            OtaCommand::Begin(begin) => self.on_begin(storage, begin, now),
            OtaCommand::Chunk(chunk) => self.on_chunk(storage, chunk.seq, chunk.data, now),
            OtaCommand::Finalize => self.on_finalize(storage, se),
            OtaCommand::Reboot { delay_ms } => self.on_reboot(delay_ms),
            OtaCommand::Abort => self.on_abort(),
            // Replies (including our own STATUS frames echoed back by a
            // confused peer) are inert input on the receive half.
            OtaCommand::AckReady { .. }
            | OtaCommand::AckChunk { .. }
            | OtaCommand::AckFinal(_)
            | OtaCommand::Status(_) => Ok(RxOutcome::Silent),
        }
    }

    /// Drives the idle-timeout policy; call periodically (e.g. once per
    /// second from host housekeeping).
    pub fn tick(&mut self, now: u32) -> TickOutcome {
        let expired = match &self.state {
            RxState::Streaming(s) => {
                now.saturating_sub(s.last_activity_secs) >= self.idle_timeout_secs
            }
            _ => false,
        };
        if expired {
            self.state = RxState::Idle;
            TickOutcome::ExpiredIdleTimeout
        } else {
            TickOutcome::Continue
        }
    }

    // -- BEGIN ----------------------------------------------------------

    fn on_begin<S: OtaStorage>(
        &mut self,
        storage: &mut S,
        begin: BeginFrame,
        now: u32,
    ) -> Result<RxOutcome, OtaError> {
        match &self.state {
            RxState::PendingReboot { .. } => Ok(bad_state_reply()),
            RxState::Streaming(s) => {
                if s.begin == begin {
                    // Identical re-BEGIN (lost ACK_READY): progress kept.
                    let chunk_len = s.chunk_len;
                    if let RxState::Streaming(active) = &mut self.state {
                        active.last_activity_secs = now;
                    }
                    Ok(RxOutcome::Respond(Reply::Ready { chunk_len }))
                } else {
                    Ok(bad_state_reply())
                }
            }
            RxState::Idle => {
                // Capacity gate first, then wire-sequence overflow gate
                // (chunk indices are u16 on the wire).
                if begin.img_len > self.staging_cap || begin.img_len == 0 {
                    return Ok(size_rejected_reply());
                }
                let total_chunks = chunk_count(begin.img_len, u32::from(begin.chunk_len));
                if total_chunks > u16::MAX as u32 {
                    return Ok(size_rejected_reply());
                }
                // Erase-block bookkeeping bound: the bitmap tracks at most
                // MAX_STAGING_BLOCKS granularity blocks per session.
                let granularity = storage.erase_granularity();
                debug_assert!(granularity > 0);
                let blocks_needed = chunk_count(begin.img_len, granularity.max(1));
                if blocks_needed > MAX_STAGING_BLOCKS {
                    return Ok(size_rejected_reply());
                }
                let accepted = begin.chunk_len;
                self.state = RxState::Streaming(StreamingSession {
                    img_version: begin.img_version,
                    img_len: begin.img_len,
                    chunk_len: begin.chunk_len,
                    total_chunks: total_chunks as u16,
                    next_seq: 0,
                    hasher: Sha256::new(),
                    last_activity_secs: now,
                    begin,
                    erased_blocks: BlockBitmap::new(),
                });
                Ok(RxOutcome::Respond(Reply::Ready {
                    chunk_len: accepted,
                }))
            }
        }
    }

    // -- CHUNK ----------------------------------------------------------

    fn on_chunk<S: OtaStorage>(
        &mut self,
        storage: &mut S,
        seq: u16,
        data: &[u8],
        now: u32,
    ) -> Result<RxOutcome, OtaError> {
        let (next_seq, total_chunks) = match &self.state {
            RxState::Streaming(s) => (s.next_seq, s.total_chunks),
            _ => return Ok(bad_state_reply()),
        };

        // Wrong position: reject AND re-teach with the cumulative ACK.
        if seq != next_seq || seq >= total_chunks {
            return Ok(RxOutcome::Respond(Reply::ChunkAck { next_seq }));
        }

        // Per-position length gate: only the LAST chunk may be short, and
        // nothing may exceed the declared geometry.
        let expected = {
            let (img_len, chunk_len) = match &self.state {
                RxState::Streaming(s) => (s.img_len, u32::from(s.chunk_len)),
                _ => unreachable!("state matched above"),
            };
            let offset = u64::from(seq) * u64::from(chunk_len);
            let remaining = u64::from(img_len) - offset;
            // Bounded by chunk_len (<= 196), so the narrowing is safe.
            remaining.min(u64::from(chunk_len)) as usize
        };
        if data.len() != expected {
            // Geometry violation corrupts the staged layout: tear down.
            self.state = RxState::Idle;
            return Ok(size_rejected_reply());
        }

        // Persist BEFORE advancing any in-RAM progress so a storage fault
        // leaves the engine byte-identical for a verbatim retry. Each
        // granularity block is erased exactly ONCE per session (bitmap
        // bookkeeping): re-erasing before every write would destroy
        // neighboring staged chunks in the same block.
        {
            let session = match &mut self.state {
                RxState::Streaming(s) => s,
                _ => unreachable!("state matched above"),
            };
            let granularity = storage.erase_granularity();
            debug_assert!(granularity > 0);
            let offset = u32::from(seq) * u32::from(session.chunk_len);
            let first_block = (offset / granularity) as usize;
            let last_byte = offset + data.len() as u32 - 1;
            let last_block = (last_byte / granularity) as usize;
            for block in first_block..=last_block {
                if session.erased_blocks.test_and_set(block) {
                    let base = block as u32 * granularity;
                    storage.erase_range(base, granularity)?;
                }
            }
            storage.write(offset, data)?;
        }

        if let RxState::Streaming(s) = &mut self.state {
            s.hasher.update(data);
            s.next_seq += 1;
            s.last_activity_secs = now;
        }
        Ok(RxOutcome::Respond(Reply::ChunkAck {
            next_seq: next_seq + 1,
        }))
    }

    // -- FINALIZE -------------------------------------------------------

    fn on_finalize<S: OtaStorage, SE: SecureElement>(
        &mut self,
        storage: &mut S,
        se: &mut SE,
    ) -> Result<RxOutcome, OtaError> {
        // Lost final ACK: re-answer Ok WITHOUT rewriting the trailer.
        if matches!(self.state, RxState::PendingReboot { .. }) {
            return Ok(RxOutcome::Respond(Reply::Final(FinalResult::Ok)));
        }

        let complete = match &self.state {
            RxState::Streaming(s) => s.next_seq == s.total_chunks,
            _ => return Ok(bad_state_reply()),
        };
        if !complete {
            // Premature finalize: recoverable, session stays open.
            return Ok(RxOutcome::Respond(Reply::Final(FinalResult::BadState)));
        }

        // 1. Integrity: incremental digest over exactly the staged bytes.
        //    Cloned so verification never consumes the live hasher.
        let (digest_ok, begin_copy) = {
            let s = match &self.state {
                RxState::Streaming(s) => s,
                _ => unreachable!("matched above"),
            };
            let digest: [u8; 32] = s.hasher.clone().finalize().into();
            (digest == s.begin.img_sha256, s.begin.clone())
        };

        // 2. Authenticity: manifest signature via the host secure element.
        //    Transport errors and bad signatures collapse into SigRejected:
        //    both mean "do not mark bootable".
        let sig_ok = digest_ok
            && se
                .verify_ecdsa(
                    &self.factory_pubkey,
                    &manifest_digest_input(
                        begin_copy.img_version,
                        begin_copy.img_len,
                        begin_copy.chunk_len,
                        &begin_copy.img_sha256,
                    ),
                    &begin_copy.manifest_sig,
                )
                .is_ok();

        if !sig_ok {
            // Untrusted staged content: tear the session down.
            self.state = RxState::Idle;
            let result = if digest_ok {
                FinalResult::SigRejected
            } else {
                FinalResult::HashMismatch
            };
            return Ok(RxOutcome::Respond(Reply::Final(result)));
        }

        // 3. Mark bootable. Storage faults keep the session retryable. The
        // trailer is a single one-shot write: unconditional aligned erase
        // then write (it lives outside the chunk bitmap bookkeeping).
        let mut raw = [0u8; TRAILER_LEN];
        TrailerRecord::staged_valid(
            begin_copy.img_version,
            begin_copy.img_len,
            begin_copy.img_sha256,
        )
        .serialize(&mut raw)?;
        {
            let granularity = storage.erase_granularity();
            debug_assert!(granularity > 0);
            let t = self.trailer_offset;
            let start = t - t % granularity;
            let end = align_up(t + TRAILER_LEN as u32, granularity);
            storage.erase_range(start, end - start)?;
            storage.write(t, &raw)?;
        }
        self.state = RxState::PendingReboot {
            img_version: begin_copy.img_version,
            img_len: begin_copy.img_len,
            total_chunks: begin_total_chunks(&begin_copy),
        };
        Ok(RxOutcome::Respond(Reply::Final(FinalResult::Ok)))
    }

    // -- REBOOT / ABORT / STATUS ----------------------------------------

    fn on_reboot(&mut self, delay_ms: u16) -> Result<RxOutcome, OtaError> {
        match &self.state {
            RxState::PendingReboot { .. } => Ok(RxOutcome::RebootAfterMs(delay_ms)),
            _ => Ok(bad_state_reply()),
        }
    }

    fn on_abort(&mut self) -> Result<RxOutcome, OtaError> {
        self.state = RxState::Idle;
        Ok(RxOutcome::Silent)
    }

    fn status_reply(&self) -> Reply {
        let status = match &self.state {
            RxState::Idle => StatusFrame {
                state: PeerState::Idle,
                next_seq: 0,
                img_version: 0,
                img_len: 0,
            },
            RxState::Streaming(s) => StatusFrame {
                state: PeerState::Streaming,
                next_seq: s.next_seq,
                img_version: s.img_version,
                img_len: s.img_len,
            },
            RxState::PendingReboot {
                img_version,
                img_len,
                total_chunks,
            } => StatusFrame {
                state: PeerState::PendingReboot,
                next_seq: *total_chunks,
                img_version: *img_version,
                img_len: *img_len,
            },
        };
        Reply::Status(status)
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Uniform "command invalid for current state" verdict.
fn bad_state_reply() -> RxOutcome {
    RxOutcome::Respond(Reply::Final(FinalResult::BadState))
}

/// Uniform capacity/geometry rejection verdict.
fn size_rejected_reply() -> RxOutcome {
    RxOutcome::Respond(Reply::Final(FinalResult::SizeRejected))
}

/// Number of chunks for `(len, chunk)` geometry (both > 0).
fn chunk_count(len: u32, chunk: u32) -> u32 {
    len.div_ceil(chunk)
}

/// Total chunks of a parsed BEGIN (validated non-zero upstream).
fn begin_total_chunks(begin: &BeginFrame) -> u16 {
    chunk_count(begin.img_len, u32::from(begin.chunk_len)) as u16
}

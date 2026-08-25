//! Send-side OTA transfer engine (gateway half).
//!
//! Pure stop-and-wait scheduler over an injected [`OtaImageSource`]: one
//! frame in flight at a time, every reply-bearing transmission armed with a
//! deadline, bounded resends, cumulative-ACK bookkeeping, STATUS-driven
//! resume, and a full-image digest preflight before the first byte goes on
//! air. No radio, clock, or crypto-vendor types; the host encodes emitted
//! [`TxFrame`]s with the matching `wire::encode_*` functions, transmits
//! them, feeds decoded replies back through [`OtaSender::on_reply`], and
//! calls [`OtaSender::poll`] when its timers fire.
//!
//! # Stop-and-wait contract
//!
//! - Exactly one unacknowledged frame exists at any time; the returned
//!   `deadline_secs` tells the host when to convert silence into a resend.
//! - Any cumulative ACK strictly beyond the in-flight chunk advances the
//!   transfer (lost-ACK recovery falls out naturally: the next accepted
//!   chunk re-teaches the position).
//! - Stale ACKs are ignored silently.
//! - An unsolicited STATUS frame aligning ahead of the local position
//!   resumes the transfer at the peer's position (`next_seq == total`
//!   jumps straight to FINALIZE); a peer reporting `Idle` mid-transfer
//!   restarts the session from BEGIN.
//! - Retry budget: up to `1 + max_retries` transmissions per frame, then
//!   the transfer ends with [`TransferEnd::TimedOut`].

use crate::core::ota::error::OtaError;
use crate::core::ota::image::OtaImageSource;
use crate::core::ota::wire::{
    BeginFrame, CHUNK_LEN_MAX, CHUNK_LEN_MIN, FinalResult, OtaCommand, PeerState,
};
use sha2::{Digest, Sha256};

/// Default whole-second wait before an unanswered frame is resent.
pub const DEFAULT_ACK_TIMEOUT_SECS: u32 = 2;

/// Default extra resend budget per frame (total attempts = 1 + this).
pub const DEFAULT_MAX_RETRIES: u8 = 5;

/// One frame the host must encode and transmit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxFrame<'a> {
    /// OTA_BEGIN opening (or restarting) the session.
    Begin(&'a BeginFrame),
    /// OTA_CHUNK with the staged copy owned by the engine.
    Chunk {
        /// Zero-based chunk index.
        seq: u16,
        /// Chunk bytes (valid until the next engine call).
        data: &'a [u8],
    },
    /// OTA_FINALIZE end-of-transfer verification request.
    Finalize,
    /// OTA_REBOOT apply-and-reset request (fire-and-forget).
    Reboot {
        /// Deferred-reset delay in milliseconds.
        delay_ms: u16,
    },
    /// OTA_ABORT session teardown (fire-and-forget).
    Abort,
}

/// Terminal outcomes reported exactly once via [`SenderAction::End`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEnd {
    /// Peer verified hash and signature; image staged bootable.
    Completed,
    /// Peer rejected the transfer with this verdict.
    Failed(FinalResult),
    /// Local retry budget exhausted waiting for a reply.
    TimedOut,
}

/// What the host should do after one engine call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderAction<'a> {
    /// Transmit and arm the host timer until `deadline_secs`.
    Transmit {
        /// Frame to encode and send.
        frame: TxFrame<'a>,
        /// Whole-second monotonic stamp past which the frame counts as lost.
        deadline_secs: u32,
    },
    /// Fire-and-forget transmission: no reply will ever arrive.
    TransmitFinal {
        /// Frame to encode and send.
        frame: TxFrame<'a>,
    },
    /// Terminal state reached; the transfer loop is over.
    End(TransferEnd),
}

/// Per-frame attempt bookkeeping shared by every reply-bearing state.
#[derive(Clone, Copy)]
struct Attempts(u16);

impl Attempts {
    fn first() -> Self {
        Self(1)
    }

    fn bump(&mut self) {
        self.0 += 1;
    }

    fn exhausted(&self, max_retries: u8) -> bool {
        // `self.0` counts transmissions already made for this frame
        // (first send included). A further resend is allowed only while
        // that count is still within the budget of 1 + max_retries.
        self.0 > u16::from(max_retries)
    }
}

enum TxState {
    Idle,
    /// BEGIN sent, ACK_READY pending.
    AwaitingReady(Attempts),
    /// Chunks flowing under stop-and-wait.
    Streaming {
        /// Outstanding chunk awaiting its cumulative ACK. `None` only
        /// transiently inside state transitions.
        inflight: Option<u16>,
        attempts: Attempts,
        total_chunks: u16,
    },
    /// FINALIZE sent, verdict pending.
    AwaitingFinal(Attempts),
    /// Terminal state reached; carries HOW it ended so post-transfer
    /// actions (REBOOT) unlock only on success.
    Done(TransferEnd),
}

/// Send-side OTA transfer engine.
///
/// The engine buffers at most one chunk ([`CHUNK_LEN_MAX`] bytes) plus the
/// manifest; no heap anywhere.
pub struct OtaSender {
    max_retries: u8,
    ack_timeout_secs: u32,
    begin: BeginFrame,
    total_chunks: u16,
    /// Staged copy of the chunk most recently prepared for TX.
    buffer: [u8; CHUNK_LEN_MAX],
    buffered_len: usize,
    /// Deadline of the outstanding frame (meaningless when none is).
    deadline_secs: u32,
    state: TxState,
}

impl OtaSender {
    /// Creates an idle sender with the given retry/timeout policy.
    pub fn new(max_retries: u8, ack_timeout_secs: u32) -> Self {
        Self {
            max_retries,
            ack_timeout_secs,
            begin: BeginFrame {
                img_version: 0,
                img_len: 0,
                chunk_len: 0,
                img_sha256: [0u8; 32],
                manifest_sig: [0u8; 64],
            },
            total_chunks: 0,
            buffer: [0u8; CHUNK_LEN_MAX],
            buffered_len: 0,
            deadline_secs: 0,
            state: TxState::Idle,
        }
    }

    /// `true` while no transfer session exists.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, TxState::Idle)
    }

    /// Opens (or restarts) a transfer session.
    ///
    /// Validates the manifest geometry against the wire contract AND the
    /// declared digest against the actual image content (full SHA-256
    /// preflight): a doomed transfer never spends airtime.
    pub fn start<IMG: OtaImageSource>(
        &mut self,
        image: &mut IMG,
        begin: BeginFrame,
        now: u32,
    ) -> Result<SenderAction<'_>, OtaError> {
        if !self.is_idle() {
            return Err(OtaError::BadState {
                reason: "transfer already in progress",
            });
        }
        // Geometry mirrors the receiver-side gates.
        let chunk = usize::from(begin.chunk_len);
        if !(CHUNK_LEN_MIN..=CHUNK_LEN_MAX).contains(&chunk) {
            return Err(OtaError::InvalidParams {
                reason: "chunk_len outside CHUNK_LEN_MIN..=CHUNK_LEN_MAX",
            });
        }
        if begin.img_len == 0 {
            return Err(OtaError::InvalidParams {
                reason: "img_len must be non-zero",
            });
        }
        // The source must declare exactly the manifest length: a shorter
        // source would fault mid-transfer, a longer one would silently ship
        // unverified trailing bytes.
        if image.len() != begin.img_len {
            return Err(OtaError::InvalidParams {
                reason: "image source length differs from the signed manifest",
            });
        }
        let count = u64::from(begin.img_len).div_ceil(u64::try_from(chunk).unwrap_or(0));
        if count > u64::from(u16::MAX) {
            return Err(OtaError::InvalidParams {
                reason: "chunk count exceeds the u16 sequence space",
            });
        }
        // Digest preflight: sign what you ship.
        let mut hasher = Sha256::new();
        let mut done = 0u32;
        while done < begin.img_len {
            let n = (begin.img_len - done).min(CHUNK_LEN_MAX as u32) as usize;
            image.read_at(done, &mut self.buffer[..n])?;
            hasher.update(&self.buffer[..n]);
            done += n as u32;
        }
        let got: [u8; 32] = hasher.finalize().into();
        if got != begin.img_sha256 {
            return Err(OtaError::InvalidParams {
                reason: "image content does not match the signed digest",
            });
        }

        self.total_chunks = count as u16;
        self.begin = begin;
        self.state = TxState::AwaitingReady(Attempts::first());
        Ok(self.transmit_armed(now, |s| TxFrame::Begin(&s.begin)))
    }

    /// Feeds one decoded reply frame (from decrypted Data payloads).
    ///
    /// Unknown/stale frames yield `Ok(None)`; progress yields the next
    /// transmission action. State facts are snapshotted before acting so
    /// the emitted frame payloads never overlap the state borrow.
    pub fn on_reply<IMG: OtaImageSource>(
        &mut self,
        image: &mut IMG,
        reply: OtaCommand<'_>,
        now: u32,
    ) -> Result<Option<SenderAction<'_>>, OtaError> {
        // Snapshot phase (immutable, closed before any mutation).
        enum Snap {
            AwaitingReady,
            Streaming {
                inflight: Option<u16>,
                total_chunks: u16,
            },
            AwaitingFinal,
            Other,
        }
        let snap = match &self.state {
            TxState::AwaitingReady(_) => Snap::AwaitingReady,
            TxState::Streaming {
                inflight,
                total_chunks,
                ..
            } => Snap::Streaming {
                inflight: *inflight,
                total_chunks: *total_chunks,
            },
            TxState::AwaitingFinal(_) => Snap::AwaitingFinal,
            _ => Snap::Other,
        };

        // Act phase. Reply correlation: ACK_READY and STATUS frames carry
        // transfer-identity fields; any mismatch with the ACTIVE manifest is
        // treated as stale/inert so a delayed reply from another OTA attempt
        // can never steer this session.
        match reply {
            // BEGIN acknowledged (echo must match the negotiated chunk_len):
            // start the chunk pipeline at chunk 0.
            OtaCommand::AckReady { chunk_len }
                if matches!(snap, Snap::AwaitingReady) && chunk_len == self.begin.chunk_len =>
            {
                self.enter_streaming(image, 0, now).map(Some)
            }
            // Cumulative ACK strictly beyond the in-flight chunk advances.
            OtaCommand::AckChunk {
                next_seq: acked_through,
            } if matches!(
                &snap,
                Snap::Streaming {
                    inflight: Some(inflight),
                    ..
                } if acked_through > *inflight
            ) =>
            {
                let total = match &snap {
                    Snap::Streaming { total_chunks, .. } => *total_chunks,
                    _ => unreachable!("guarded above"),
                };
                if acked_through >= total {
                    self.state = TxState::AwaitingFinal(Attempts::first());
                    Ok(Some(self.transmit_armed(now, |_| TxFrame::Finalize)))
                } else {
                    self.enter_streaming(image, acked_through, now).map(Some)
                }
            }
            // Verdict on FINALIZE terminates the loop either way.
            OtaCommand::AckFinal(result) if matches!(snap, Snap::AwaitingFinal) => {
                let end = match result {
                    FinalResult::Ok => TransferEnd::Completed,
                    other => TransferEnd::Failed(other),
                };
                self.state = TxState::Done(end);
                Ok(Some(SenderAction::End(end)))
            }
            // STATUS-driven resume: peer realigned ahead or restarted. The
            // status must describe the ACTIVE transfer (version AND length
            // match); anything else is inert.
            OtaCommand::Status(status)
                if status.img_version == self.begin.img_version
                    && status.img_len == self.begin.img_len =>
            {
                match (&snap, status.state) {
                    (
                        Snap::Streaming {
                            inflight,
                            total_chunks,
                        },
                        PeerState::Streaming,
                    ) => {
                        let local_next = inflight.map_or(0, |i| i + 1);
                        if status.next_seq > local_next && status.next_seq < *total_chunks {
                            self.enter_streaming(image, status.next_seq, now).map(Some)
                        } else if status.next_seq >= *total_chunks && *total_chunks > 0 {
                            // Peer already holds every chunk: finalize now.
                            self.state = TxState::AwaitingFinal(Attempts::first());
                            Ok(Some(self.transmit_armed(now, |_| TxFrame::Finalize)))
                        } else {
                            Ok(None)
                        }
                    }
                    (Snap::Streaming { .. }, PeerState::Idle) => {
                        // Peer dropped the session: restart from BEGIN.
                        self.state = TxState::AwaitingReady(Attempts::first());
                        Ok(Some(self.transmit_armed(now, |s| TxFrame::Begin(&s.begin))))
                    }
                    _ => Ok(None),
                }
            }
            // Everything else is stale or inert on the send half.
            _ => Ok(None),
        }
    }

    /// Timer callback: resends the outstanding frame once its deadline has
    /// passed, ending the transfer when the budget is exhausted.
    pub fn poll<IMG: OtaImageSource>(
        &mut self,
        image: &mut IMG,
        now: u32,
    ) -> Result<Option<SenderAction<'_>>, OtaError> {
        if now < self.deadline_secs {
            return Ok(None);
        }
        // Snapshot what is outstanding, then act (avoids overlapping borrows
        // between the state enum and the emitted frame payloads).
        let outstanding = match &self.state {
            TxState::AwaitingReady(attempts) => Some(Outstanding::Begin(*attempts)),
            TxState::Streaming {
                inflight, attempts, ..
            } => inflight.map(|seq| Outstanding::Chunk {
                seq,
                attempts: *attempts,
            }),
            TxState::AwaitingFinal(attempts) => Some(Outstanding::Final(*attempts)),
            TxState::Idle | TxState::Done(_) => None,
        };
        let action = match outstanding {
            None => None,
            Some(outstanding) => {
                if outstanding.attempts().exhausted(self.max_retries) {
                    self.state = TxState::Done(TransferEnd::TimedOut);
                    Some(SenderAction::End(TransferEnd::TimedOut))
                } else {
                    Some(match outstanding {
                        Outstanding::Begin(mut attempts) => {
                            attempts.bump();
                            if let TxState::AwaitingReady(a) = &mut self.state {
                                *a = attempts;
                            }
                            self.transmit_armed(now, |s| TxFrame::Begin(&s.begin))
                        }
                        Outstanding::Chunk { seq, mut attempts } => {
                            attempts.bump();
                            self.stage_chunk(image, seq)?;
                            if let TxState::Streaming { attempts: a, .. } = &mut self.state {
                                *a = attempts;
                            }
                            self.transmit_armed(now, |s| TxFrame::Chunk {
                                seq,
                                data: &s.buffer[..s.buffered_len],
                            })
                        }
                        Outstanding::Final(mut attempts) => {
                            attempts.bump();
                            if let TxState::AwaitingFinal(a) = &mut self.state {
                                *a = attempts;
                            }
                            self.transmit_armed(now, |_| TxFrame::Finalize)
                        }
                    })
                }
            }
        };
        Ok(action)
    }

    /// Fire-and-forget ABORT; tears the local session down immediately.
    pub fn abort(&mut self) -> Result<SenderAction<'_>, OtaError> {
        if self.is_idle() {
            return Err(OtaError::BadState {
                reason: "no transfer session",
            });
        }
        self.state = TxState::Idle;
        Ok(SenderAction::TransmitFinal {
            frame: TxFrame::Abort,
        })
    }

    /// Fire-and-forget REBOOT; valid only after a terminal state where the
    /// transfer COMPLETED.
    pub fn reboot(&mut self, delay_ms: u16) -> Result<SenderAction<'_>, OtaError> {
        match self.state {
            TxState::Done(TransferEnd::Completed) => Ok(SenderAction::TransmitFinal {
                frame: TxFrame::Reboot { delay_ms },
            }),
            _ => Err(OtaError::BadState {
                reason: "reboot allowed only after completion",
            }),
        }
    }

    // -- internals -------------------------------------------------------

    /// (Re)enters Streaming positioned at `seq` and emits that chunk.
    fn enter_streaming<IMG: OtaImageSource>(
        &mut self,
        image: &mut IMG,
        seq: u16,
        now: u32,
    ) -> Result<SenderAction<'_>, OtaError> {
        self.stage_chunk(image, seq)?;
        self.state = TxState::Streaming {
            inflight: Some(seq),
            attempts: Attempts::first(),
            total_chunks: self.total_chunks,
        };
        Ok(self.transmit_armed(now, |s| TxFrame::Chunk {
            seq,
            data: &s.buffer[..s.buffered_len],
        }))
    }

    /// Reads chunk `seq` from the image into the internal staging buffer.
    fn stage_chunk<IMG: OtaImageSource>(
        &mut self,
        image: &mut IMG,
        seq: u16,
    ) -> Result<(), OtaError> {
        let chunk_len = usize::from(self.begin.chunk_len);
        // Bounded by total_chunks * chunk_len <= img_len <= u32::MAX.
        let offset = u64::from(seq) * chunk_len as u64;
        let remaining = u64::from(self.begin.img_len) - offset;
        let len = remaining.min(chunk_len as u64) as usize;
        image.read_at(offset as u32, &mut self.buffer[..len])?;
        self.buffered_len = len;
        Ok(())
    }

    /// Arms the resend deadline, then builds the Transmit action through
    /// `make`, whose borrow of the engine starts only AFTER the mutable
    /// bookkeeping is done. The HRTB ties the frame's lifetime to whatever
    /// reborrow the closure is given, so callers may consume the action
    /// immediately.
    fn transmit_armed(
        &mut self,
        now: u32,
        make: impl for<'x> FnOnce(&'x OtaSender) -> TxFrame<'x>,
    ) -> SenderAction<'_> {
        self.deadline_secs = now.saturating_add(self.ack_timeout_secs);
        let deadline_secs = self.deadline_secs;
        SenderAction::Transmit {
            frame: make(self),
            deadline_secs,
        }
    }
}

/// Internal snapshot of the outstanding frame used by `poll`.
enum Outstanding {
    Begin(Attempts),
    Chunk { seq: u16, attempts: Attempts },
    Final(Attempts),
}

impl Outstanding {
    fn attempts(&self) -> Attempts {
        match self {
            Outstanding::Begin(a) | Outstanding::Final(a) => *a,
            Outstanding::Chunk { attempts, .. } => *attempts,
        }
    }
}

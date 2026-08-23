//! Error types for the sigil core
//!
//! This module defines all error types that can be returned by the core APIs,
//! providing clear and specific error information for host applications.
//!
//! # Host policy categories
//!
//! Every [`SigilError`] maps to exactly **one** deterministic host policy
//! category, so firmware can `match` once and act:
//!
//! - **Reject input**: the received frame or requested operation is invalid;
//!   drop it (optionally log). Never retry as-is.
//! - **Fix integration**: a static integration problem (buffer sizing, wrong
//!   role, bad configuration, secure-element/RNG health, corrupt NVRAM).
//!   Correct the firmware; retrying cannot help.
//! - **Back off / reclaim capacity**: transient resource pressure. Free the
//!   resource (`tick`, `cancel_pending`, key rotation) or back off, then retry.
//! - **Report invariant failure**: an unrepresentable internal state was
//!   reached — this is always a library bug; capture diagnostics and report.
//!
//! The taxonomy distinguishes fixed-buffer sizing ([`SigilError::OutputBufferTooSmall`]),
//! session-table saturation ([`SigilError::SessionTableFull`]), pending-table
//! saturation ([`SigilError::PendingTableFull`]), admission-table saturation
//! ([`SigilError::AdmissionTableFull`]), malformed wire input
//! ([`SigilError::MalformedFrame`]), wrong role ([`SigilError::WrongRole`]),
//! invalid transitions ([`SigilError::InvalidStep`]) and internal invariant
//! failures ([`SigilError::InvariantViolation`]). The clear-text handshake
//! replay defense adds [`SigilError::HandshakeReplay`] (a recorded
//! authenticated initiator re-delivered inside its horizon) and
//! [`SigilError::ReplayCacheFull`] (fail-closed bounded refusal of fresh
//! initiators while the cache is saturated with live entries).
//!
//! # Secrecy
//!
//! `Display` never renders key material, MAC tags, PSKs or shared secrets.
//! Peer MACs are acceptable: they are clear-text on every wire frame header.

use core::fmt;

/// Error types returned by sigil core operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigilError {
    /// No session exists for the specified peer
    /// Host policy: reject input (drop the frame / skip the operation until
    /// the peer is enrolled; for TX this means the peer handle is stale).
    UnknownSession {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Session key has expired
    /// Host policy: reject input (do not use the expired key; re-key with
    /// renew or resume).
    SessionExpired {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Replayed or non-monotonic packet counter detected
    /// Host policy: reject input (drop the frame; the replay window already
    /// rejected it).
    Replay {
        /// Peer identifier
        peer: [u8; 17],
        /// Expected counter value
        expected: u64,
        /// Received counter value
        received: u64,
    },

    /// TX counter would overflow (exhausted)
    /// Host policy: back off / reclaim capacity (rotate the session keys via
    /// renew or resume to reset the counters).
    CounterExhausted {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Cryptographic verification failed (ECDSA, AEAD tag, etc.)
    /// Host policy: reject input (the frame or signature failed
    /// authentication; drop it).
    VerificationFailed,

    /// No pending handshake for the specified peer
    /// Host policy: fix integration (sequence the handshake calls correctly;
    /// the pending entry may have been cancelled, tick-purged or committed —
    /// restart the handshake when needed).
    NoPending {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// A pending handshake already exists for the specified peer
    /// Host policy: reject input (a handshake is already in flight for this
    /// peer; reclaim with `cancel_pending`/`tick` before starting another).
    PendingAlreadyExists {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// ECDH operation failed
    /// Host policy: fix integration (secure-element/driver health or wiring).
    EcdhFailed,

    /// Random source operation failed
    /// Host policy: fix integration (RNG driver/hardware must be healthy
    /// before any cryptographic operation).
    RandomFailed,

    /// Invalid static public key format
    /// Host policy: fix integration (provisioned key encoding is invalid).
    InvalidStaticKey,

    /// Durable Resume PSK is invalid (currently: all-zero enrollment secret)
    /// Host policy: fix integration (NVRAM content missing/corrupt — re-enroll).
    InvalidResumePsk,

    /// Session not active (no session key or expired)
    /// Host policy: reject input (no usable key; establish keys first).
    SessionNotActive {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Resume rejected because a session key is already **active** (not expired)
    /// Use renew to rotate an active key; resume is for cold enrolled peers
    /// (static pubkey known, session key absent or soft-expired).
    /// Host policy: reject input (wrong recovery path — use renew instead).
    SessionAlreadyActive {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Invalid handshake step or state for the specified peer
    ///
    /// Canonical transition-mismatch error: a frame arrived out of order for
    /// the pending protocol state, or a facade API was called in a state that
    /// forbids it (e.g. cancel after the commit boundary).
    /// Host policy: reject input (drop the out-of-order frame; never retry it
    /// against the same state).
    InvalidStep {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Pending handshake timed out
    /// Semantic error for a pending entry reclaimed because the host seconds
    /// clock passed its `deadline_at`. Produced when the host maps a peer
    /// returned by [`crate::core::manager::SessionManager::tick`] (the library
    /// returns the peer MAC list from `tick` rather than this enum directly).
    /// Manual [`crate::core::manager::SessionManager::cancel_pending`] after a
    /// radio timer does **not** return this variant (`Ok` / `NoPending`).
    /// Host policy: back off / reclaim capacity (entry reclaimed by timeout;
    /// restart the handshake if still needed).
    TimeoutElapsed {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Operation rejected by a per-peer rate limit / cooldown
    /// Used when a gateway `ResumeRequest`, `InstallRequest` or authenticated
    /// `TimeSyncRequest` arrives too soon after the previous accepted request (see
    /// [`crate::core::resume::RESUME_REQUEST_COOLDOWN`] and
    /// [`crate::core::install::INSTALL_REQUEST_COOLDOWN`], plus
    /// [`crate::core::pipeline::TIME_SYNC_REQUEST_COOLDOWN_SECS`], all
    /// **15 seconds**).
    /// Host policy: back off / reclaim capacity (retry after the cooldown).
    RateLimited {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Session-key expiry rejected by policy
    /// Returned when `key_expire_at <= now` or the lifetime
    /// `key_expire_at - now` exceeds
    /// [`crate::core::session::MAX_SESSION_LIFETIME_SECS`] (2 days).
    /// Host policy: fix integration (host passed an invalid expiry value).
    InvalidKeyExpire {
        /// Host clock at validation (`now`, seconds)
        now: u32,
        /// Rejected absolute expiry (seconds)
        key_expire_at: u32,
    },

    /// Authenticated wire-v3 lifetime is zero, too long, or overflows local time.
    /// Host policy: fix integration (host passed an invalid lifetime value).
    InvalidKeyLifetime {
        /// Rejected duration in seconds.
        lifetime_secs: u32,
    },

    /// Another reliable Event is already waiting for its EventAck.
    /// Host policy: back off / reclaim capacity (finish or cancel the
    /// in-flight Event, then retry).
    EventAckPending {
        /// Peer identifier.
        peer: [u8; 17],
        /// Event id that is still pending.
        event_id: u64,
    },

    /// Gateway already has another Event awaiting durable processing/ACK.
    /// Host policy: back off / reclaim capacity (ACK or release the pending
    /// delivery, then retry).
    EventDeliveryPending {
        /// Sensor peer identifier.
        peer: [u8; 17],
        /// Event id awaiting host completion.
        event_id: u64,
    },

    /// No matching uncommitted gateway Event delivery exists.
    /// Host policy: reject input (unknown/mismatched id supplied by the host).
    UnexpectedEventDelivery {
        /// Sensor peer identifier.
        peer: [u8; 17],
        /// Event id supplied by the host.
        event_id: u64,
    },

    /// Event id was reused or moved backwards.
    /// Host policy: reject input (id monotonicity violated; use a fresh id).
    InvalidEventId {
        /// Peer identifier.
        peer: [u8; 17],
        /// Greatest Event id previously started.
        last: u64,
        /// Rejected id.
        received: u64,
    },

    /// Authenticated EventAck does not match the pending Event.
    /// Host policy: reject input (mismatched ACK id; drop it).
    UnexpectedEventAck {
        /// Peer identifier.
        peer: [u8; 17],
        /// Acknowledged Event id.
        event_id: u64,
    },

    // ------------------------------------------------------------------
    // Final taxonomy: these domain-specific variants replace the former
    // coarse capacity/parsing/handshake-state variants outright — a
    // conscious breaking removal approved by the crate owner before any
    // production use of this crate; no deprecated alias is retained.
    // ------------------------------------------------------------------
    /// A caller-provided output buffer cannot hold the produced data
    /// (e.g. the `MSG` transmit buffer or the `DATA` receive payload buffer
    /// of the generic APIs, or the output `Vec` of the AEAD helpers).
    /// Host policy: fix integration (enlarge the buffer generic constant).
    OutputBufferTooSmall,

    /// The fixed-capacity established-session table is full and the peer is
    /// unknown (a known peer is replaced in place without growth).
    /// Host policy: back off / reclaim capacity (remove stale sessions).
    SessionTableFull,

    /// The fixed-capacity pending-handshake table is full and no slot can be
    /// freed for a new peer (a duplicate peer yields
    /// [`SigilError::PendingAlreadyExists`] instead).
    /// Host policy: back off / reclaim capacity (`cancel_pending`/`tick`).
    PendingTableFull,

    /// The gateway admission/cooldown table is full after purging expired
    /// entries and the peer is new.
    /// Host policy: back off / reclaim capacity (entries expire with their
    /// cooldown window; apply the documented global admission policy).
    AdmissionTableFull,

    /// Malformed wire input: truncated frame, wrong protocol version or
    /// frame type, outer/body identity mismatch, or an authenticated payload
    /// whose shape does not match its frame type.
    /// Host policy: reject input (drop the frame).
    MalformedFrame,

    /// A clear-text handshake initiator frame whose exact
    /// `(handshake_kind, peer_mac, initiator_nonce)` triple was already
    /// accepted as cryptographically authenticated **to successful
    /// completion** by the same handler within the replay horizon
    /// (see `REPLAY_HORIZON_SECS`). Distinct from the AEAD data-path
    /// [`SigilError::Replay`]. Install and Resume namespaces are disjoint
    /// via the handshake-kind tag.
    /// Host policy: reject input (drop the frame; never retry it as-is,
    /// never cancel pending for it).
    HandshakeReplay {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// The gateway replay cache is saturated with live (in-horizon) entries
    /// and the fresh initiator was refused fail-closed **before any
    /// cryptographic work**. This is the documented bounded-refusal
    /// trade-off of the replay defense: recovery flows through TTL expiry
    /// once filling pressure stops or the host budget throttles it.
    /// Family of the table-full variants.
    /// Host policy: back off / reclaim capacity (enforce the global admission
    /// budget; entries expire with their horizon window).
    ReplayCacheFull {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// The session's configured role does not permit this operation or frame
    /// type (e.g. starting a sensor-only handshake from the gateway side, or
    /// receiving a frame whose direction contradicts the local role).
    /// Host policy: fix integration (static role/config mismatch: correct the
    /// firmware call site; for ingress frames, drop them).
    WrongRole {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// An internally unrepresentable state was reached (e.g. a tagged
    /// recovery state without its cached frame). Fail closed; this is always
    /// a library bug.
    /// Host policy: report invariant failure (capture diagnostics and report).
    InvariantViolation,
}

impl fmt::Display for SigilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigilError::UnknownSession { peer } => {
                write!(f, "Unknown session for peer: {:02x?}", peer)
            }
            SigilError::SessionExpired { peer } => {
                write!(f, "Session expired for peer: {:02x?}", peer)
            }
            SigilError::Replay {
                peer,
                expected,
                received,
            } => {
                write!(
                    f,
                    "Replay detected for peer {:02x?}: expected {}, received {}",
                    peer, expected, received
                )
            }
            SigilError::CounterExhausted { peer } => {
                write!(f, "TX counter exhausted for peer: {:02x?}", peer)
            }
            SigilError::VerificationFailed => {
                write!(f, "Cryptographic verification failed")
            }
            SigilError::NoPending { peer } => {
                write!(f, "No pending handshake for peer: {:02x?}", peer)
            }
            SigilError::PendingAlreadyExists { peer } => {
                write!(
                    f,
                    "Pending handshake already exists for peer: {:02x?}",
                    peer
                )
            }
            SigilError::EcdhFailed => {
                write!(f, "ECDH operation failed")
            }
            SigilError::RandomFailed => {
                write!(f, "Random source operation failed")
            }
            SigilError::InvalidStaticKey => {
                write!(f, "Invalid static public key format")
            }
            SigilError::InvalidResumePsk => {
                write!(f, "Invalid Resume PSK")
            }
            SigilError::SessionNotActive { peer } => {
                write!(f, "Session not active for peer: {:02x?}", peer)
            }
            SigilError::SessionAlreadyActive { peer } => {
                write!(
                    f,
                    "Session already active for peer (use renew, not resume): {:02x?}",
                    peer
                )
            }
            SigilError::InvalidStep { peer } => {
                write!(f, "Invalid handshake step for peer: {:02x?}", peer)
            }
            SigilError::TimeoutElapsed { peer } => {
                write!(
                    f,
                    "Timeout elapsed for pending handshake with peer: {:02x?}",
                    peer
                )
            }
            SigilError::RateLimited { peer } => {
                write!(f, "Rate limited for peer: {:02x?}", peer)
            }
            SigilError::InvalidKeyExpire { now, key_expire_at } => {
                write!(
                    f,
                    "Invalid key_expire_at {} for now {} (must be in (now, now+MAX_SESSION_LIFETIME])",
                    key_expire_at, now
                )
            }
            SigilError::InvalidKeyLifetime { lifetime_secs } => {
                write!(f, "Invalid session lifetime: {} seconds", lifetime_secs)
            }
            SigilError::EventAckPending { peer, event_id } => write!(
                f,
                "Event {} is still waiting for an ACK from peer {:02x?}",
                event_id, peer
            ),
            SigilError::EventDeliveryPending { peer, event_id } => write!(
                f,
                "Event {} from peer {:02x?} still awaits durable processing",
                event_id, peer
            ),
            SigilError::UnexpectedEventDelivery { peer, event_id } => write!(
                f,
                "No pending delivery for Event {} from peer {:02x?}",
                event_id, peer
            ),
            SigilError::InvalidEventId {
                peer,
                last,
                received,
            } => write!(
                f,
                "Invalid Event id {} for peer {:02x?}; last id was {}",
                received, peer, last
            ),
            SigilError::UnexpectedEventAck { peer, event_id } => write!(
                f,
                "Unexpected ACK for Event {} from peer {:02x?}",
                event_id, peer
            ),
            SigilError::OutputBufferTooSmall => {
                write!(f, "Output buffer too small for the produced data")
            }
            SigilError::SessionTableFull => {
                write!(f, "Session table full")
            }
            SigilError::PendingTableFull => {
                write!(f, "Pending handshake table full")
            }
            SigilError::AdmissionTableFull => {
                write!(f, "Admission table full")
            }
            SigilError::MalformedFrame => {
                write!(f, "Malformed frame received")
            }
            SigilError::HandshakeReplay { peer } => {
                write!(f, "Handshake replay detected for peer: {:02x?}", peer)
            }
            SigilError::ReplayCacheFull { peer } => {
                write!(
                    f,
                    "Replay cache full, fresh handshake refused for peer: {:02x?}",
                    peer
                )
            }
            SigilError::WrongRole { peer } => {
                write!(
                    f,
                    "Operation not valid for the session role of peer: {:02x?}",
                    peer
                )
            }
            SigilError::InvariantViolation => {
                write!(f, "Internal invariant violated")
            }
        }
    }
}

mod tests;

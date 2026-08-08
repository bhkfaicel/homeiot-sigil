//! Error types for the sigil core
//!
//! This module defines all error types that can be returned by the core APIs,
//! providing clear and specific error information for host applications.

use core::fmt;

/// Error types returned by sigil core operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigilError {
    /// No session exists for the specified peer
    UnknownSession {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Session key has expired
    SessionExpired {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Replayed or non-monotonic packet counter detected
    Replay {
        /// Peer identifier
        peer: [u8; 17],
        /// Expected counter value
        expected: u64,
        /// Received counter value
        received: u64,
    },

    /// TX counter would overflow (exhausted)
    CounterExhausted {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Cryptographic verification failed (ECDSA, AEAD tag, etc.)
    VerificationFailed,

    /// Session manager capacity exceeded
    CapacityExceeded,

    /// Failed to parse incoming packet (truncated or malformed)
    ParseError,

    /// No pending handshake for the specified peer
    NoPending {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// A pending handshake already exists for the specified peer
    PendingAlreadyExists {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// ECDH operation failed
    EcdhFailed,

    /// Random source operation failed
    RandomFailed,

    /// Invalid static public key format
    InvalidStaticKey,

    /// Session not active (no session key or expired)
    SessionNotActive {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Resume rejected because a session key is already **active** (not expired)
    /// Use renew to rotate an active key; resume is for cold enrolled peers
    /// (static pubkey known, session key absent or soft-expired).
    SessionAlreadyActive {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Invalid handshake step or state for the specified peer
    InvalidStep {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Invalid handshake step or state
    InvalidHandshakeState,

    /// Pending handshake timed out
    /// Semantic error for a pending entry reclaimed because the host seconds
    /// clock passed its `deadline_at`. Produced when the host maps a peer
    /// returned by [`crate::core::manager::SessionManager::tick`] (the library
    /// returns the peer MAC list from `tick` rather than this enum directly).
    /// Manual [`crate::core::manager::SessionManager::cancel_pending`] after a
    /// radio timer does **not** return this variant (`Ok` / `NoPending`).
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
    RateLimited {
        /// Peer identifier
        peer: [u8; 17],
    },

    /// Session-key expiry rejected by policy
    /// Returned when `key_expire_at <= now` or the lifetime
    /// `key_expire_at - now` exceeds
    /// [`crate::core::session::MAX_SESSION_LIFETIME_SECS`] (2 days).
    InvalidKeyExpire {
        /// Host clock at validation (`now`, seconds)
        now: u32,
        /// Rejected absolute expiry (seconds)
        key_expire_at: u32,
    },

    /// Authenticated wire-v3 lifetime is zero, too long, or overflows local time.
    InvalidKeyLifetime {
        /// Rejected duration in seconds.
        lifetime_secs: u32,
    },

    /// Another reliable Event is already waiting for its EventAck.
    EventAckPending {
        /// Peer identifier.
        peer: [u8; 17],
        /// Event id that is still pending.
        event_id: u64,
    },

    /// Gateway already has another Event awaiting durable processing/ACK.
    EventDeliveryPending {
        /// Sensor peer identifier.
        peer: [u8; 17],
        /// Event id awaiting host completion.
        event_id: u64,
    },

    /// No matching uncommitted gateway Event delivery exists.
    UnexpectedEventDelivery {
        /// Sensor peer identifier.
        peer: [u8; 17],
        /// Event id supplied by the host.
        event_id: u64,
    },

    /// Event id was reused or moved backwards.
    InvalidEventId {
        /// Peer identifier.
        peer: [u8; 17],
        /// Greatest Event id previously started.
        last: u64,
        /// Rejected id.
        received: u64,
    },

    /// Authenticated EventAck does not match the pending Event.
    UnexpectedEventAck {
        /// Peer identifier.
        peer: [u8; 17],
        /// Acknowledged Event id.
        event_id: u64,
    },
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
            SigilError::CapacityExceeded => {
                write!(f, "Session manager capacity exceeded")
            }
            SigilError::ParseError => {
                write!(f, "Failed to parse packet (truncated or malformed)")
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
            SigilError::InvalidHandshakeState => {
                write!(f, "Invalid handshake step or state")
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
        }
    }
}

mod tests;

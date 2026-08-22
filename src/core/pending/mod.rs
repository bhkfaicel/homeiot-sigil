//! Pending handshake state management
//!
//! This module defines the [`PendingHandshake`] type which tracks in-progress
//! install, renew, and resume attempts as one **tagged** [`PendingState`]
//! per (protocol, role, step) group. Each variant carries exactly the fields
//! that are valid at that point of the handshake, so cross-phase combinations
//! of steps, secrets, and transcript material cannot be constructed through
//! normal crate code.
//!
//! # State model
//!
//! - Handshakes only move forward through the checked `*_stage_final` /
//!   `*_commit_sent` transition methods on [`PendingHandshake`]. Every
//!   transition validates its predecessor variant, builds the cached wire
//!   frame **before** swapping the variant (fail-atomic), and refreshes
//!   [`Self::deadline_at`] from `now`.
//! - Commit-criticality and cached-retransmission capability are derived from
//!   the tagged state in exactly one place:
//!   [`PendingState::is_commit_critical`] and
//!   [`PendingState::cached_retransmission_frame`].
//! - Secret-bearing fields use zeroizing wrappers
//!   ([`crate::core::secret::SecretBytes`] and `DirectionalMaterial`), so
//!   replacing or dropping a variant wipes the ephemeral material it owned.
//!   Committing a handshake therefore clears the staged secrets by
//!   construction instead of relying on manual wipe calls.
//!
//! # Pending lifetime (two host policies)
//!
//! The library has **no internal clock**. Pending entries are removed when:
//! - the handshake **succeeds** (protocol clears it),
//! - the host calls [`SessionManager::cancel_pending`](crate::core::manager::SessionManager::cancel_pending)
//!   before the commit boundary (manual radio-timer policy),
//! - the host calls [`SessionManager::tick`](crate::core::manager::SessionManager::tick)
//!   with a `now` past [`PendingHandshake::deadline_at`] for a pre-commit state
//!   (optional housekeeping),
//! - the host calls [`SessionManager::remove`](crate::core::manager::SessionManager::remove), or
//! - a new host `start_*` intentionally **replaces** the pending for that peer.
//!
//! [`PendingHandshake::suggested_timeout_ms`] and
//! [`SigilAction::Transmit::wait_timeout_ms`](crate::core::event::SigilAction::Transmit)
//! remain **advisory radio-wait hints** (milliseconds). `deadline_at` is the
//! same hint converted to the host **seconds** timebase for [`SessionManager::tick`].
//!
//! Hosts may use **either** policy (or both):
//! 1. **Manual:** on `Transmit { wait_timeout_ms: Some(t) }`, start a timer; on
//!    expiry call `cancel_pending(&peer)`.
//! 2. **Tick:** periodically call `tick(now)` in the main loop to purge expired
//!    pending slots (returns the peer MACs that timed out).

use crate::core::error::SigilError;
use crate::core::secret::SecretBytes;
use crate::core::session::{DirectionalMaterial, PeerId};

/// Zeroizing stash for the durable resume PSK between install derivation and
/// commit / host persist.
pub(crate) type ResumePskStash = SecretBytes<32>;

/// Zeroizing stash for a 16-byte handshake nonce.
pub(crate) type Nonce16Stash = SecretBytes<16>;

/// Zeroizing stash for the backend-defined P-256 provider context.
#[cfg(feature = "gateway")]
pub(crate) type P256ContextStash = SecretBytes<32>;

/// Cached Final / CommitConfirmed wire frame kept for idempotent
/// retransmission. Ciphertext / clear-text handshake bytes — no zeroize
/// required.
pub(crate) type CachedWire = heapless::Vec<u8, 128>;

/// Material the gateway stages between the verified `InstallRequest` and the
/// sensor Final (`InstallConfirm`). Grouped in one struct because every field
/// is produced by the same request handler.
#[cfg(feature = "gateway")]
pub(crate) struct InstallGatewayStaged {
    /// Directional AEAD material derived from the static ECDH secret.
    pub(crate) keys: DirectionalMaterial,
    /// Durable resume PSK handed to the host at commit.
    pub(crate) resume_psk: ResumePskStash,
    /// Sensor static public key (verified against the factory root).
    pub(crate) sensor_static_pubkey: [u8; 33],
    /// Agreed session-key lifetime in seconds.
    pub(crate) key_lifetime_secs: u32,
    /// Gateway challenge nonce (needed to verify the Final signature).
    pub(crate) gateway_nonce: Nonce16Stash,
    /// Initiator nonce from the request (bound into the HKDF info).
    pub(crate) sensor_nonce: Nonce16Stash,
}

/// Tagged in-progress handshake state: one variant per (protocol, role, step)
/// group, carrying exactly the data that phase needs. Role-exclusive variants
/// are compiled only for the matching cargo feature.
pub(crate) enum PendingState {
    /// Install sensor: request sent, awaiting the gateway challenge.
    #[cfg(feature = "sensor")]
    InstallSensorAwaitChallenge {
        /// Initiator nonce mixed into the HKDF info at challenge time.
        sensor_nonce: Nonce16Stash,
    },
    /// Install sensor: Final sent, awaiting CommitConfirmed (commit-critical).
    #[cfg(feature = "sensor")]
    InstallSensorFinalSent {
        /// Staged directional AEAD material for the new session.
        keys: DirectionalMaterial,
        /// Staged durable resume PSK.
        resume_psk: ResumePskStash,
        /// Gateway static public key verified at challenge time.
        gateway_static_pubkey: [u8; 33],
        /// Agreed session-key lifetime in seconds.
        key_lifetime_secs: u32,
        /// Cached Final frame for idempotent retransmission.
        cached: CachedWire,
    },
    /// Install gateway: challenge sent, awaiting the sensor Final.
    #[cfg(feature = "gateway")]
    InstallGatewayAwaitConfirm(InstallGatewayStaged),
    /// Install gateway: CommitConfirmed sent, kept for idempotent reTX
    /// (commit-critical). Staged secrets were consumed at commit.
    #[cfg(feature = "gateway")]
    InstallGatewayCommitSent {
        /// Cached CommitConfirmed frame for idempotent retransmission.
        cached: CachedWire,
    },
    /// Renew sensor: request sent, awaiting the gateway challenge. The
    /// secure element generates and consumes the ephemeral scalar at
    /// challenge time, so no private material is retained here.
    #[cfg(feature = "sensor")]
    RenewSensorAwaitChallenge,
    /// Renew sensor: Final sent, awaiting CommitConfirmed (commit-critical).
    #[cfg(feature = "sensor")]
    RenewSensorFinalSent {
        /// Staged directional AEAD material for the rotated session.
        keys: DirectionalMaterial,
        /// Agreed session-key lifetime in seconds.
        key_lifetime_secs: u32,
        /// Cached Final frame for idempotent retransmission.
        cached: CachedWire,
    },
    /// Renew gateway: challenge sent, awaiting the sensor Final. Holds the
    /// backend-defined P-256 context until the sensor public key arrives.
    #[cfg(feature = "gateway")]
    RenewGatewayAwaitConfirm {
        /// Backend-defined provider context / handle (zeroizing).
        p256_context: P256ContextStash,
        /// Gateway ephemeral public key sent in the challenge.
        gateway_ephemeral_pubkey: [u8; 33],
        /// Agreed session-key lifetime in seconds.
        key_lifetime_secs: u32,
    },
    /// Renew gateway: CommitConfirmed sent (commit-critical).
    #[cfg(feature = "gateway")]
    RenewGatewayCommitSent {
        /// Cached CommitConfirmed frame for idempotent retransmission.
        cached: CachedWire,
    },
    /// Resume sensor: request sent, awaiting the gateway challenge.
    #[cfg(feature = "sensor")]
    ResumeSensorAwaitChallenge {
        /// Request nonce stashed until the challenge (HKDF + challenge MAC).
        sensor_nonce: Nonce16Stash,
    },
    /// Resume sensor: Final sent, awaiting CommitConfirmed (commit-critical).
    #[cfg(feature = "sensor")]
    ResumeSensorFinalSent {
        /// Staged directional AEAD material for the resumed session.
        keys: DirectionalMaterial,
        /// Agreed session-key lifetime in seconds.
        key_lifetime_secs: u32,
        /// Cached Final frame for idempotent retransmission.
        cached: CachedWire,
    },
    /// Resume gateway: challenge sent, awaiting the sensor Final.
    #[cfg(feature = "gateway")]
    ResumeGatewayAwaitConfirm {
        /// Directional AEAD material derived from the static↔static ECDH.
        keys: DirectionalMaterial,
        /// Agreed session-key lifetime in seconds.
        key_lifetime_secs: u32,
    },
    /// Resume gateway: CommitConfirmed sent (commit-critical).
    #[cfg(feature = "gateway")]
    ResumeGatewayCommitSent {
        /// Cached CommitConfirmed frame for idempotent retransmission.
        cached: CachedWire,
    },
}

impl PendingState {
    /// Returns `true` once either peer has crossed the handshake commit
    /// boundary (Final sent on the sensor side, CommitConfirmed sent on the
    /// gateway side). Ordinary radio timeouts must not discard these recovery
    /// states — only successful completion or an explicit unpair may do so.
    /// Single source of truth for commit-criticality.
    pub(crate) fn is_commit_critical(&self) -> bool {
        #[cfg(feature = "sensor")]
        {
            if self.is_sensor_final_sent() {
                return true;
            }
        }
        #[cfg(feature = "gateway")]
        {
            if self.is_gateway_commit_sent() {
                return true;
            }
        }
        false
    }

    /// Sensor-side post-Final recovery states. A fresh authenticated
    /// `start_resume` / `start_install` may explicitly replace one of these
    /// after the peer lost the CommitConfirmed frame.
    #[cfg(feature = "sensor")]
    pub(crate) fn is_sensor_final_sent(&self) -> bool {
        matches!(
            self,
            Self::InstallSensorFinalSent { .. }
                | Self::RenewSensorFinalSent { .. }
                | Self::ResumeSensorFinalSent { .. }
        )
    }

    /// Gateway-side post-commit states whose cached CommitConfirmed may be
    /// released once authenticated traffic under the new key proves the peer
    /// received it.
    #[cfg(feature = "gateway")]
    pub(crate) fn is_gateway_commit_sent(&self) -> bool {
        matches!(
            self,
            Self::InstallGatewayCommitSent { .. }
                | Self::RenewGatewayCommitSent { .. }
                | Self::ResumeGatewayCommitSent { .. }
        )
    }

    /// Cached Final / CommitConfirmed frame available for idempotent
    /// retransmission, present exactly in the post-Final recovery states.
    /// Single source of truth for cached-retransmission capability.
    pub(crate) fn cached_retransmission_frame(&self) -> Option<&[u8]> {
        #[cfg(feature = "sensor")]
        {
            // Sensor recovery states cache their Final frame.
            if let Some(cached) = match self {
                Self::InstallSensorFinalSent { cached, .. }
                | Self::RenewSensorFinalSent { cached, .. }
                | Self::ResumeSensorFinalSent { cached, .. } => Some(cached.as_slice()),
                _ => None,
            } {
                return Some(cached);
            }
        }
        #[cfg(feature = "gateway")]
        {
            // Gateway recovery states cache their CommitConfirmed frame.
            if let Some(cached) = match self {
                Self::InstallGatewayCommitSent { cached }
                | Self::RenewGatewayCommitSent { cached }
                | Self::ResumeGatewayCommitSent { cached } => Some(cached.as_slice()),
                _ => None,
            } {
                return Some(cached);
            }
        }
        None
    }
}

/// Converts an advisory millisecond radio timeout into whole **seconds** for
/// [`PendingHandshake::deadline_at`] / [`SessionManager::tick`](crate::core::manager::SessionManager::tick).
/// Uses ceiling division so a 1500 ms hint becomes 2 s (never shorter than the
/// host radio wait when the session clock is second-granular). Zero maps to 1 s
/// so a stamped pending is always eventually reclaimable via `tick`.
pub(crate) fn timeout_ms_to_secs_ceil(timeout_ms: u32) -> u32 {
    let secs = timeout_ms.div_ceil(1000);
    if secs == 0 { 1 } else { secs }
}

/// Absolute pending expiry in the host **seconds** timebase.
/// `deadline_at = now_at_insert.saturating_add(timeout_ms_to_secs_ceil(timeout_ms))`.
pub(crate) fn deadline_from_now(now: u32, timeout_ms: u32) -> u32 {
    now.saturating_add(timeout_ms_to_secs_ceil(timeout_ms))
}

/// Builds a [`CachedWire`] from a wire frame, failing closed on overflow.
/// The cache capacity is library-fixed and only ever holds Final /
/// CommitConfirmed frames whose sizes are protocol constants, so an overflow
/// is an internally unrepresentable state (`InvariantViolation`).
fn cached_wire_from(frame: &[u8]) -> Result<CachedWire, SigilError> {
    let mut cached = CachedWire::new();
    cached
        .extend_from_slice(frame)
        .map_err(|_| SigilError::InvariantViolation)?;
    Ok(cached)
}

/// In-progress handshake state for a peer.
/// Tracks the state of an in-progress handshake (install, renew, or resume)
/// as one tagged [`PendingState`] plus per-peer bookkeeping. Cleared on
/// success, explicit cancel, [`SessionManager::tick`](crate::core::manager::SessionManager::tick)
/// past [`Self::deadline_at`], or host-initiated replace.
pub(crate) struct PendingHandshake {
    /// Peer identifier (table key; rebound during install discovery).
    pub(crate) peer_mac: PeerId,

    /// Tagged protocol/role/step state; mutated only through the checked
    /// transition methods below.
    state: PendingState,

    /// Suggested radio wait for the next handshake step (milliseconds).
    /// Advisory for `Transmit.wait_timeout_ms`. Elapsing this duration alone
    /// does **not** clear the pending entry — use host `cancel_pending` and/or
    /// [`SessionManager::tick`](crate::core::manager::SessionManager::tick).
    pub(crate) suggested_timeout_ms: u32,

    /// Absolute expiry for optional [`SessionManager::tick`](crate::core::manager::SessionManager::tick)
    /// reclaim (host **seconds** timebase). See [`deadline_from_now`].
    pub(crate) deadline_at: u32,
}

impl PendingHandshake {
    /// Immutable access to the tagged state (dispatch / tests).
    pub(crate) fn state(&self) -> &PendingState {
        &self.state
    }

    /// Refreshes the absolute tick deadline from `now` (host seconds) using
    /// the current suggested timeout. Called by every forward transition,
    /// replacing the previous explicit `update_timeout` call sites.
    fn refresh_deadline(&mut self, now: u32) {
        self.deadline_at = deadline_from_now(now, self.suggested_timeout_ms);
    }

    /// Creates the sensor-side install pending: request sent with
    /// `sensor_nonce`, awaiting the gateway challenge.
    #[cfg(feature = "sensor")]
    pub(crate) fn new_install_sensor(
        peer_mac: PeerId,
        sensor_nonce: [u8; 16],
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        Self {
            peer_mac,
            state: PendingState::InstallSensorAwaitChallenge {
                sensor_nonce: Nonce16Stash::new(sensor_nonce),
            },
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
        }
    }

    /// Creates the gateway-side install pending holding everything needed to
    /// verify the sensor Final and commit the session.
    #[cfg(feature = "gateway")]
    pub(crate) fn new_install_gateway_await_confirm(
        peer_mac: PeerId,
        staged: InstallGatewayStaged,
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        Self {
            peer_mac,
            state: PendingState::InstallGatewayAwaitConfirm(staged),
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
        }
    }

    /// Creates the sensor-side renew pending. No ephemeral private material
    /// is retained: the secure element generates and consumes it at challenge
    /// time.
    #[cfg(feature = "sensor")]
    pub(crate) fn new_renew_sensor(peer_mac: PeerId, timeout_ms: u32, now: u32) -> Self {
        Self {
            peer_mac,
            state: PendingState::RenewSensorAwaitChallenge,
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
        }
    }

    /// Creates the gateway-side renew pending holding the backend-defined
    /// P-256 context until the sensor confirmation supplies the peer public
    /// key and proof.
    #[cfg(feature = "gateway")]
    pub(crate) fn new_renew_gateway_await_confirm(
        peer_mac: PeerId,
        p256_context: [u8; 32],
        gateway_ephemeral_pubkey: [u8; 33],
        key_lifetime_secs: u32,
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        Self {
            peer_mac,
            state: PendingState::RenewGatewayAwaitConfirm {
                p256_context: P256ContextStash::new(p256_context),
                gateway_ephemeral_pubkey,
                key_lifetime_secs,
            },
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
        }
    }

    /// Creates the sensor-side resume pending with the request nonce stashed
    /// until the challenge arrives.
    #[cfg(feature = "sensor")]
    pub(crate) fn new_resume_sensor(
        peer_mac: PeerId,
        sensor_nonce: [u8; 16],
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        Self {
            peer_mac,
            state: PendingState::ResumeSensorAwaitChallenge {
                sensor_nonce: Nonce16Stash::new(sensor_nonce),
            },
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
        }
    }

    /// Creates the gateway-side resume pending with the directional material
    /// derived from the static↔static ECDH.
    #[cfg(feature = "gateway")]
    pub(crate) fn new_resume_gateway_await_confirm(
        peer_mac: PeerId,
        keys: DirectionalMaterial,
        key_lifetime_secs: u32,
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        Self {
            peer_mac,
            state: PendingState::ResumeGatewayAwaitConfirm {
                keys,
                key_lifetime_secs,
            },
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
        }
    }

    /// Install sensor transition: the challenge was verified and the Final
    /// (`InstallConfirm`) frame is ready. Only
    /// [`PendingState::InstallSensorAwaitChallenge`] may stage a Final; any
    /// other state fails closed with [`SigilError::InvalidStep`] and is left
    /// untouched. Swapping the variant atomically wipes the stashed initiator
    /// nonce and stages the new secrets; the deadline is refreshed from `now`.
    #[cfg(feature = "sensor")]
    pub(crate) fn install_sensor_stage_final(
        &mut self,
        keys: DirectionalMaterial,
        resume_psk: [u8; 32],
        gateway_static_pubkey: [u8; 33],
        key_lifetime_secs: u32,
        final_frame: &[u8],
        now: u32,
    ) -> Result<(), SigilError> {
        if !matches!(self.state, PendingState::InstallSensorAwaitChallenge { .. }) {
            return Err(SigilError::InvalidStep {
                peer: self.peer_mac,
            });
        }
        let cached = cached_wire_from(final_frame)?;
        self.state = PendingState::InstallSensorFinalSent {
            keys,
            resume_psk: ResumePskStash::new(resume_psk),
            gateway_static_pubkey,
            key_lifetime_secs,
            cached,
        };
        self.refresh_deadline(now);
        Ok(())
    }

    /// Install gateway transition: the Final was verified and the session
    /// committed. Only [`PendingState::InstallGatewayAwaitConfirm`] may
    /// transition; swapping the variant consumes (zeroizes) the staged keys,
    /// PSK, and nonces while keeping the cached CommitConfirmed for
    /// idempotent retransmission.
    #[cfg(feature = "gateway")]
    pub(crate) fn install_gateway_commit_sent(
        &mut self,
        commit_frame: &[u8],
        now: u32,
    ) -> Result<(), SigilError> {
        if !matches!(self.state, PendingState::InstallGatewayAwaitConfirm(_)) {
            return Err(SigilError::InvalidStep {
                peer: self.peer_mac,
            });
        }
        let cached = cached_wire_from(commit_frame)?;
        self.state = PendingState::InstallGatewayCommitSent { cached };
        self.refresh_deadline(now);
        Ok(())
    }

    /// Renew sensor transition: the challenge was processed and the Final
    /// (`RenewConfirm`) frame is ready. Only
    /// [`PendingState::RenewSensorAwaitChallenge`] may stage a Final.
    #[cfg(feature = "sensor")]
    pub(crate) fn renew_sensor_stage_final(
        &mut self,
        keys: DirectionalMaterial,
        key_lifetime_secs: u32,
        final_frame: &[u8],
        now: u32,
    ) -> Result<(), SigilError> {
        if !matches!(self.state, PendingState::RenewSensorAwaitChallenge) {
            return Err(SigilError::InvalidStep {
                peer: self.peer_mac,
            });
        }
        let cached = cached_wire_from(final_frame)?;
        self.state = PendingState::RenewSensorFinalSent {
            keys,
            key_lifetime_secs,
            cached,
        };
        self.refresh_deadline(now);
        Ok(())
    }

    /// Renew gateway transition: the sensor proof was verified and the
    /// session committed. Only [`PendingState::RenewGatewayAwaitConfirm`] may
    /// transition; swapping the variant consumes (zeroizes) the P-256
    /// provider context while keeping the cached CommitConfirmed.
    #[cfg(feature = "gateway")]
    pub(crate) fn renew_gateway_commit_sent(
        &mut self,
        commit_frame: &[u8],
        now: u32,
    ) -> Result<(), SigilError> {
        if !matches!(self.state, PendingState::RenewGatewayAwaitConfirm { .. }) {
            return Err(SigilError::InvalidStep {
                peer: self.peer_mac,
            });
        }
        let cached = cached_wire_from(commit_frame)?;
        self.state = PendingState::RenewGatewayCommitSent { cached };
        self.refresh_deadline(now);
        Ok(())
    }

    /// Resume sensor transition: the challenge was processed and the Final
    /// (`ResumeConfirm`) frame is ready. Only
    /// [`PendingState::ResumeSensorAwaitChallenge`] may stage a Final;
    /// swapping the variant wipes the stashed request nonce.
    #[cfg(feature = "sensor")]
    pub(crate) fn resume_sensor_stage_final(
        &mut self,
        keys: DirectionalMaterial,
        key_lifetime_secs: u32,
        final_frame: &[u8],
        now: u32,
    ) -> Result<(), SigilError> {
        if !matches!(self.state, PendingState::ResumeSensorAwaitChallenge { .. }) {
            return Err(SigilError::InvalidStep {
                peer: self.peer_mac,
            });
        }
        let cached = cached_wire_from(final_frame)?;
        self.state = PendingState::ResumeSensorFinalSent {
            keys,
            key_lifetime_secs,
            cached,
        };
        self.refresh_deadline(now);
        Ok(())
    }

    /// Resume gateway transition: the Final was decrypted and the session
    /// committed. Only [`PendingState::ResumeGatewayAwaitConfirm`] may
    /// transition; swapping the variant consumes (zeroizes) the directional
    /// material while keeping the cached CommitConfirmed.
    #[cfg(feature = "gateway")]
    pub(crate) fn resume_gateway_commit_sent(
        &mut self,
        commit_frame: &[u8],
        now: u32,
    ) -> Result<(), SigilError> {
        if !matches!(self.state, PendingState::ResumeGatewayAwaitConfirm { .. }) {
            return Err(SigilError::InvalidStep {
                peer: self.peer_mac,
            });
        }
        let cached = cached_wire_from(commit_frame)?;
        self.state = PendingState::ResumeGatewayCommitSent { cached };
        self.refresh_deadline(now);
        Ok(())
    }
}

mod tests;

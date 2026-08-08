//! Pending handshake state management
//!
//! This module defines the [`PendingHandshake`] type which tracks in-progress
//! install, renew, and resume attempts.
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
//! remain **advisory radio-wait hints** (milliseconds). [`deadline_at`] is the
//! same hint converted to the host **seconds** timebase for [`SessionManager::tick`].
//!
//! Hosts may use **either** policy (or both):
//! 1. **Manual:** on `Transmit { wait_timeout_ms: Some(t) }`, start a timer; on
//!    expiry call `cancel_pending(&peer)`.
//! 2. **Tick:** periodically call `tick(now)` in the main loop to purge expired
//!    pending slots (returns the peer MACs that timed out).

use crate::core::error::SigilError;
use crate::core::session::{DirectionalMaterial, PeerId};
use zeroize::Zeroize;

/// Handshake phase types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakePhase {
    /// First-time installation pairing
    Install,
    /// Session key renewal
    Renew,
    /// Fast resume after reboot
    Resume,
}

/// Handshake role (sensor or gateway)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeRole {
    /// Sensor device (can initiate install/renew/resume)
    #[cfg(feature = "sensor")]
    Sensor,
    /// Gateway device (responds to install/renew/resume)
    #[cfg(feature = "gateway")]
    Gateway,
}

/// Handshake step indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandshakeStep {
    /// Install: waiting for challenge
    InstallWaitingForChallenge,
    /// Install: waiting for confirm (Final)
    InstallWaitingForConfirm,
    /// Install sensor: Final sent, waiting for CommitConfirmed
    InstallWaitingForCommitConfirmed,
    /// Install gateway: CommitConfirmed sent, pending kept for idempotent reTX
    InstallCommitSent,
    /// Renew: waiting for challenge
    RenewWaitingForChallenge,
    /// Renew: waiting for ack (Final)
    RenewWaitingForAck,
    /// Renew sensor: Final sent, waiting for CommitConfirmed
    RenewWaitingForCommitConfirmed,
    /// Renew gateway: CommitConfirmed sent, pending kept for idempotent reTX
    RenewCommitSent,
    /// Resume: waiting for challenge
    ResumeWaitingForChallenge,
    /// Resume: waiting for confirm (Final)
    ResumeWaitingForConfirm,
    /// Resume sensor: Final sent, waiting for CommitConfirmed
    ResumeWaitingForCommitConfirmed,
    /// Resume gateway: CommitConfirmed sent, pending kept for idempotent reTX
    ResumeCommitSent,
}

/// Typed secrets held across handshake steps.
/// Replaces the overloaded `Option<[u8; 32]>` that previously mixed X25519
/// scalars, session keys, and padded nonces under one name. Each variant is
/// zeroized on [`Drop`] / [`Self::zeroize`].
#[derive(Clone)]
pub(crate) enum PendingSecrets {
    /// Renew: local X25519 ephemeral scalar
    EphScalar([u8; 32]),
    /// Install / renew / resume gateway: directional AEAD material
    DirectionalKeys(DirectionalMaterial),
    /// Resume sensor: request nonce stashed until challenge
    Nonce16([u8; 16]),
}

impl PendingSecrets {
    /// Overwrites secret bytes (Zeroize — not subject to dead-store elimination).
    pub(crate) fn zeroize(&mut self) {
        match self {
            Self::EphScalar(b) => b.zeroize(),
            Self::DirectionalKeys(m) => m.zeroize(),
            Self::Nonce16(b) => b.zeroize(),
        }
    }

    /// Returns the X25519 scalar if this is [`Self::EphScalar`].
    pub(crate) fn as_eph_scalar(&self) -> Option<&[u8; 32]> {
        match self {
            Self::EphScalar(s) => Some(s),
            _ => None,
        }
    }

    /// Returns directional AEAD material if this is [`Self::DirectionalKeys`].
    pub(crate) fn as_directional(&self) -> Option<&DirectionalMaterial> {
        match self {
            Self::DirectionalKeys(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the 16-byte nonce if this is [`Self::Nonce16`].
    pub(crate) fn as_nonce16(&self) -> Option<&[u8; 16]> {
        match self {
            Self::Nonce16(n) => Some(n),
            _ => None,
        }
    }
}

impl Drop for PendingSecrets {
    fn drop(&mut self) {
        self.zeroize();
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

/// In-progress handshake state for a peer
/// Tracks the state of an in-progress handshake (install, renew, or resume).
/// Cleared on success, explicit cancel, [`SessionManager::tick`](crate::core::manager::SessionManager::tick)
/// past [`Self::deadline_at`], or host-initiated replace.
/// Some fields (e.g. `peer_mac`, `phase`) are kept for debugging and future
/// inspection hooks and may be unread by current call sites.
#[allow(dead_code)]
pub(crate) struct PendingHandshake {
    /// Peer identifier
    pub(crate) peer_mac: PeerId,

    /// Handshake phase
    pub(crate) phase: HandshakePhase,

    /// Handshake role
    pub(crate) role: HandshakeRole,

    /// Current step in the handshake
    pub(crate) step: HandshakeStep,

 /// Phase-specific secret material (typed enum).
    pub(crate) secrets: Option<PendingSecrets>,

    /// Install gateway: durable resume PSK stashed until confirm.
    pub(crate) resume_psk: Option<[u8; 32]>,

    /// Transcript material: nonce prefix derived during the handshake.
    pub(crate) transcript_nonce_prefix: Option<[u8; 4]>,
    /// Transcript material: peer compressed static public key.
    pub(crate) transcript_pubkey: Option<[u8; 33]>,
    /// Transcript material: agreed key expiry timestamp.
    pub(crate) transcript_expire: Option<u32>,
    /// Challenge / local nonce stashed for handshake continuity:
    /// - Install **sensor**: `sensor_nonce` (needed at challenge time for HKDF)
    /// - Install **gateway**: `gateway_nonce` (needed at confirm time for ECDSA verify)
    pub(crate) transcript_challenge_nonce: Option<[u8; 16]>,

    /// Initiator nonce used to bind the full Install transcript.
    pub(crate) transcript_initiator_nonce: Option<[u8; 16]>,

    /// Suggested radio wait for the next handshake step (milliseconds).
    /// Advisory for `Transmit.wait_timeout_ms`. Elapsing this duration alone
    /// does **not** clear the pending entry — use host `cancel_pending` and/or
    /// [`SessionManager::tick`](crate::core::manager::SessionManager::tick).
    pub(crate) suggested_timeout_ms: u32,

    /// Absolute expiry for optional [`SessionManager::tick`](crate::core::manager::SessionManager::tick)
    /// reclaim (host **seconds** timebase). See [`deadline_from_now`].
    pub(crate) deadline_at: u32,

    /// Cached Final / CommitConfirmed wire frame for idempotent retransmission
    /// Ciphertext / clear-text handshake bytes — no zeroize required.
    /// Cleared on [`Self::zeroize_secrets`] / drop of pending.
    pub(crate) cached_wire: Option<heapless::Vec<u8, 128>>,
}

impl PendingHandshake {
    /// Returns `true` once either peer has crossed the handshake commit boundary.
    /// Ordinary radio timeouts must not discard these recovery states
    /// only successful completion or an explicit unpair may do so.
    pub(crate) fn is_commit_critical(&self) -> bool {
        matches!(
            self.step,
            HandshakeStep::InstallWaitingForCommitConfirmed
                | HandshakeStep::InstallCommitSent
                | HandshakeStep::RenewWaitingForCommitConfirmed
                | HandshakeStep::RenewCommitSent
                | HandshakeStep::ResumeWaitingForCommitConfirmed
                | HandshakeStep::ResumeCommitSent
        )
    }

    /// Creates a new pending handshake for install
    pub(crate) fn new_install(
        peer_mac: PeerId,
        role: HandshakeRole,
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        let step = match role {
            #[cfg(feature = "sensor")]
            HandshakeRole::Sensor => HandshakeStep::InstallWaitingForChallenge,
            #[cfg(feature = "gateway")]
            HandshakeRole::Gateway => HandshakeStep::InstallWaitingForConfirm,
        };

        Self {
            peer_mac,
            phase: HandshakePhase::Install,
            role,
            step,
            secrets: None,
            resume_psk: None,
            transcript_nonce_prefix: None,
            transcript_pubkey: None,
            transcript_expire: None,
            transcript_challenge_nonce: None,
            transcript_initiator_nonce: None,
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
            cached_wire: None,
        }
    }

    /// Creates a new pending handshake for renew **sensor** (stores eph scalar).
    #[cfg(feature = "sensor")]
    pub(crate) fn new_renew(
        peer_mac: PeerId,
        role: HandshakeRole,
        eph_scalar: [u8; 32],
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        let step = match role {
            HandshakeRole::Sensor => HandshakeStep::RenewWaitingForChallenge,
            #[cfg(feature = "gateway")]
            HandshakeRole::Gateway => HandshakeStep::RenewWaitingForAck,
        };

        Self {
            peer_mac,
            phase: HandshakePhase::Renew,
            role,
            step,
            secrets: Some(PendingSecrets::EphScalar(eph_scalar)),
            resume_psk: None,
            transcript_nonce_prefix: None,
            transcript_pubkey: None,
            transcript_expire: None,
            transcript_challenge_nonce: None,
            transcript_initiator_nonce: None,
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
            cached_wire: None,
        }
    }

    /// Creates a renew **gateway** pending holding directional keys until ack.
    #[cfg(feature = "gateway")]
    pub(crate) fn new_renew_gateway(
        peer_mac: PeerId,
        material: DirectionalMaterial,
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        Self {
            peer_mac,
            phase: HandshakePhase::Renew,
            role: HandshakeRole::Gateway,
            step: HandshakeStep::RenewWaitingForAck,
            secrets: Some(PendingSecrets::DirectionalKeys(material)),
            resume_psk: None,
            transcript_nonce_prefix: None,
            transcript_pubkey: None,
            transcript_expire: None,
            transcript_challenge_nonce: None,
            transcript_initiator_nonce: None,
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
            cached_wire: None,
        }
    }

    /// Creates a new pending handshake for resume
    pub(crate) fn new_resume(
        peer_mac: PeerId,
        role: HandshakeRole,
        timeout_ms: u32,
        now: u32,
    ) -> Self {
        let step = match role {
            #[cfg(feature = "sensor")]
            HandshakeRole::Sensor => HandshakeStep::ResumeWaitingForChallenge,
            #[cfg(feature = "gateway")]
            HandshakeRole::Gateway => HandshakeStep::ResumeWaitingForConfirm,
        };

        Self {
            peer_mac,
            phase: HandshakePhase::Resume,
            role,
            step,
            secrets: None,
            resume_psk: None,
            transcript_nonce_prefix: None,
            transcript_pubkey: None,
            transcript_expire: None,
            transcript_challenge_nonce: None,
            transcript_initiator_nonce: None,
            suggested_timeout_ms: timeout_ms,
            deadline_at: deadline_from_now(now, timeout_ms),
            cached_wire: None,
        }
    }

    /// Updates the handshake step
    pub(crate) fn update_step(&mut self, step: HandshakeStep) {
        self.step = step;
    }

    /// Updates the suggested radio timeout and refreshes [`Self::deadline_at`] from `now`.
    pub(crate) fn update_timeout(&mut self, timeout_ms: u32, now: u32) {
        self.suggested_timeout_ms = timeout_ms;
        self.deadline_at = deadline_from_now(now, timeout_ms);
    }

    /// Stashes directional AEAD material (install / renew / resume gateway).
    pub(crate) fn set_directional_keys(&mut self, material: DirectionalMaterial) {
        self.secrets = Some(PendingSecrets::DirectionalKeys(material));
    }

    /// Stashes a resume-request nonce (sensor).
    pub(crate) fn set_nonce16(&mut self, nonce: [u8; 16]) {
        self.secrets = Some(PendingSecrets::Nonce16(nonce));
    }

    /// Returns the renew ephemeral scalar, if present and typed correctly.
    pub(crate) fn eph_scalar(&self) -> Option<&[u8; 32]> {
        self.secrets
.as_ref()
.and_then(PendingSecrets::as_eph_scalar)
    }

    /// Returns stashed directional AEAD material, if present and typed correctly.
    pub(crate) fn directional_keys(&self) -> Option<&DirectionalMaterial> {
        self.secrets
.as_ref()
.and_then(PendingSecrets::as_directional)
    }

    /// Returns the stashed resume nonce, if present and typed correctly.
    pub(crate) fn nonce16(&self) -> Option<&[u8; 16]> {
        self.secrets.as_ref().and_then(PendingSecrets::as_nonce16)
    }

    /// Stores a Final / CommitConfirmed wire frame for idempotent reTX.
    pub(crate) fn set_cached_wire(&mut self, frame: &[u8]) -> Result<(), SigilError> {
        let mut buf = heapless::Vec::<u8, 128>::new();
        buf.extend_from_slice(frame)
.map_err(|_| SigilError::CapacityExceeded)?;
        self.cached_wire = Some(buf);
        Ok(())
    }

    /// Returns a clone of the cached wire frame, if any.
    #[allow(dead_code)]
    pub(crate) fn cached_wire_clone(&self) -> Option<heapless::Vec<u8, 128>> {
        self.cached_wire.clone()
    }

    /// Clears and zeroizes any ephemeral secrets and challenge transcript material.
    /// Uses [`Zeroize`] (not a plain `fill(0)`) so compilers cannot dead-store
    /// eliminate the wipe of session keys / X25519 scalars held in pending.
    /// Also clears [`Self::cached_wire`] (public ciphertext cache).
    pub(crate) fn zeroize_secrets(&mut self) {
        if let Some(mut secrets) = self.secrets.take() {
            secrets.zeroize();
        }
        if let Some(mut psk) = self.resume_psk.take() {
            psk.zeroize();
        }
        if let Some(mut nonce) = self.transcript_challenge_nonce.take() {
            nonce.zeroize();
        }
        if let Some(mut nonce) = self.transcript_initiator_nonce.take() {
            nonce.zeroize();
        }
        if let Some(mut prefix) = self.transcript_nonce_prefix.take() {
            prefix.zeroize();
        }
        self.cached_wire = None;
    }
}

impl Drop for PendingHandshake {
    fn drop(&mut self) {
        // Ensure secrets are zeroized when dropped
        self.zeroize_secrets();
    }
}

mod tests;

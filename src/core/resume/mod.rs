//! Fast session resume after reboot
//!
//! Re-establishes a session key using **static-to-static ECDH via the secure
//! element**, without ephemeral keys or ECDSA signatures. This minimizes
//! airtime and energy after a reboot where the host reloaded the peer's static
//! public key from NVRAM but the session key is gone.
//!
//! # Flow (4 messages)
//!
//! 1. **Sensor** → `start_resume_internal(..., now)` → emits `ResumeRequest`;
//!    any old active/expired key is retained until commit for reboot recovery.
//!    Requires [`SessionRole::Sensor`](crate::core::SessionRole).
//! 2. **Gateway** → `handle_resume_request_internal` → verifies req MAC **before**
//!    SE-ECDH, then derives key and emits `ResumeChallenge`.
//! 3. **Sensor** → `continue_resume_internal` → performs ECDH, derives the same
//!    key, **stages** it, emits AEAD-protected `ResumeConfirm` (Final).
//! 4. **Gateway** → `continue_resume_internal` → decrypts confirm, **commits**,
//!    emits `ResumeCommitConfirmed`, keeps pending for idempotent reTX.
//! 5. **Sensor** → `continue_resume_internal` on CommitConfirmed → verifies,
//!    **commits**, clears pending.
//!
//! Host must call [`SessionManager::continue_resume`](crate::core::manager::SessionManager::continue_resume)
//! on Challenge, Confirm, and CommitConfirmed events.
//!
//! # Resume request authentication
//!
//! At install both peers derive a durable [`crate::core::session::ResumePsk`]
//! (`sigil-resume-psk`). The sensor MACs each `ResumeRequest`; the gateway
//! rejects spoofed MACs without that PSK **before** calling the secure element.
//! Host must persist `resume_psk` with the peer static pubkey across reboot.
//!
//! # Authenticated lifetime
//!
//! `key_lifetime_secs` is mixed into HKDF info together with both nonces, and
//! the clear-text challenge carries a MAC keyed by the static ECDH shared
//! secret (`sigil-resume-mac`). A MITM that alters the expire field fails the
//! MAC check on the sensor **before** any session key is staged.
//!
//! The public API is exposed as methods on [`SessionManager`].

#[cfg(feature = "gateway")]
pub(crate) mod gateway;
#[cfg(feature = "sensor")]
pub(crate) mod sensor;
pub(crate) mod wire;

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{
    FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
};
use crate::core::manager::SessionManager;
#[cfg(feature = "sensor")]
use crate::core::pending::PendingHandshake;
use crate::core::pending::PendingState;
#[cfg(feature = "sensor")]
use crate::core::resume::sensor::{
    build_resume_request_frame, handle_resume_challenge, handle_resume_commit_confirmed,
};
use crate::core::resume::wire::RESUME_NONCE_SIZE;
#[cfg(feature = "sensor")]
use crate::core::session::PeerId;
#[cfg(feature = "sensor")]
use crate::core::session::SessionRole;
use crate::core::traits::{RandomSource, SecureElement};

/// Suggested radio wait for resume handshake steps (milliseconds).
/// Advisory for the host scheduler / `Transmit.wait_timeout_ms` only.
/// Also converted to a seconds `deadline_at` for optional [`SessionManager::tick`](crate::core::manager::SessionManager::tick).
/// Elapsing this duration alone does **not** clear pending — call `cancel_pending` and/or `tick`.
/// Do not confuse with `key_lifetime_secs` (session-key duration in **seconds**).
pub const RESUME_TIMEOUT_MS: u32 = 5000;

/// Minimum gap between accepted gateway `ResumeRequest` ECDH work, in **seconds**.
/// # Host timebase contract
/// Product convention: [`SessionManager`]
/// APIs use **seconds** for local `now`, `key_lifetime_secs`, and this cooldown.
/// `RESUME_REQUEST_COOLDOWN = 15` therefore means **15 seconds**.
/// A second request for the same peer before this delta elapses returns
/// [`SigilError::RateLimited`]. Combined with
/// [`SigilError::PendingAlreadyExists`] when a resume is already in flight,
/// this limits resume SE-ECDH amplification after a valid request MAC.
/// Do **not** pass millisecond clocks into `now` while keeping this constant
/// at 15 — that would shrink the effective cooldown to 15 ms.
/// Spoofed requests without a valid resume-PSK MAC are rejected with
/// [`SigilError::VerificationFailed`] before ECDH.
pub const RESUME_REQUEST_COOLDOWN: u32 = 15;

/// HKDF info for resume key derivation.
/// `info = b"sigil-resume" ‖ sensor_nonce ‖ gateway_nonce ‖ key_lifetime_secs_be`
/// Mixing `key_lifetime_secs` authenticates the clear-text lifetime: if a MITM
/// flips those 4 bytes, the peers derive different keys and ResumeConfirm AEAD
/// fails.
pub(crate) fn resume_hkdf_info(
    sensor_nonce: &[u8; RESUME_NONCE_SIZE],
    gateway_nonce: &[u8; RESUME_NONCE_SIZE],
    key_lifetime_secs: u32,
) -> Result<heapless::Vec<u8, 64>, SigilError> {
    let mut info = heapless::Vec::<u8, 64>::new();
    info.extend_from_slice(b"sigil-resume")
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(sensor_nonce)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(gateway_nonce)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(&key_lifetime_secs.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(info)
}

/// Internal implementation of [`SessionManager::start_resume`].
/// Starts a resume handshake on the sensor side. Requires an enrolled session
/// (static pubkey + resume PSK known) and [`SessionRole::Sensor`].
/// An active or soft-expired key may remain usable while Resume is pending.
/// This explicit recovery path is required when the gateway rebooted and lost
/// its RAM-only active key; the old key is replaced only after confirmation.
/// `now` is the sensor's local monotonic time in seconds.
#[cfg(feature = "sensor")]
pub(crate) fn start_resume_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: PeerId,
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let _ = se; // resume request does not need the SE; ECDH happens at challenge time
    // Lend the storage capabilities once: every pending / session access
    // below goes through the narrow store view instead of manager internals.
    // Field mutation flows through the view's own `&mut` store references.
    let stores = manager.protocol_stores();
    // A stale post-Final sensor recovery state (cached Final the gateway never
    // acknowledged) may be replaced by a fresh authenticated request; every
    // other pending for this peer blocks a new handshake.
    let replacing_stale_commit = stores
        .pending
        .get(&peer)
        .is_some_and(|pending| pending.state().is_sensor_final_sent());
    if stores.pending.get(&peer).is_some() && !replacing_stale_commit {
        return Err(SigilError::PendingAlreadyExists { peer });
    }
    if !stores.pending.slot_available(&peer) {
        return Err(SigilError::PendingTableFull);
    }

    {
        let session = stores
            .sessions
            .get_mut(&peer)
            .ok_or(SigilError::UnknownSession { peer })?;
        // Only the sensor role may initiate resume.
        if session.role() != SessionRole::Sensor {
            return Err(SigilError::WrongRole { peer });
        }
        if session.peer_static_pubkey() == &[0u8; 33] {
            return Err(SigilError::InvalidStaticKey);
        }
    }

    let resume_psk = stores
        .sessions
        .get(&peer)
        .ok_or(SigilError::UnknownSession { peer })?
        .require_resume_psk()?;

    let (frame, sensor_nonce) =
        build_resume_request_frame::<MSG>(stores.local_mac, resume_psk, rng)?;

    // The tagged sensor state stashes the request nonce until the challenge.
    let pending = PendingHandshake::new_resume_sensor(peer, sensor_nonce, RESUME_TIMEOUT_MS, now);
    // Preserve staged post-Final material until validation/RNG/frame building
    // for the explicit recovery request have all succeeded.
    if replacing_stale_commit {
        let _ = stores.pending.remove(&peer);
    }
    stores.pending.insert(peer, pending)?;

    Ok(SigilAction::Transmit {
        dest: peer,
        payload: frame,
        wait_timeout_ms: Some(RESUME_TIMEOUT_MS),
    })
}

/// Internal implementation of [`SessionManager::handle_resume_request`].
/// Gateway-only: processes a clear-text resume request and emits the challenge.
/// `now` is the gateway's local monotonic timestamp in seconds.
/// `key_lifetime_secs` is the duration for the new session key; the sensor may
/// use a different clock epoch and computes its own absolute expiry.
/// It must not be confused with [`RESUME_TIMEOUT_MS`], which only bounds the
/// handshake pending wait hint in **milliseconds**.
/// [`RESUME_REQUEST_COOLDOWN`] is **15 seconds** in that same second timebase.
#[cfg(feature = "gateway")]
pub(crate) fn handle_resume_request_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    if packet.len() < 17 {
        return Err(SigilError::MalformedFrame);
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);
    let mut stores = manager.protocol_stores();
    gateway::handle_resume_request(&mut stores, &peer, packet, se, rng, now, key_lifetime_secs)
}

/// Internal implementation of [`SessionManager::continue_resume`].
/// Dispatches by role / step / frame type:
/// - Sensor + Challenge → stage keys, emit Final
/// - Sensor + CommitConfirmed → verify, commit
/// - Sensor WaitingForCommitConfirmed + Challenge again → reTX cached Final
/// - Gateway + Confirm → commit + CommitConfirmed (or reTX if CommitSent)
pub(crate) fn continue_resume_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    #[cfg(not(feature = "sensor"))]
    let _ = se;
    if packet.len() < 17 {
        return Err(SigilError::MalformedFrame);
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);

    // Validate the frame_type matches a resume protocol message.
    if packet.len() < OUTER_HEADER_SIZE
        || !FrameType::from_byte(packet[FRAME_TYPE_OFFSET])
            .map(|ft| ft.is_resume())
            .unwrap_or(false)
        || packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
    {
        return Err(SigilError::MalformedFrame);
    }

    let frame_type =
        FrameType::from_byte(packet[FRAME_TYPE_OFFSET]).ok_or(SigilError::MalformedFrame)?;

    // Lend the storage capabilities once: the dispatch peek and the handlers
    // all work on this narrow view.
    let mut stores = manager.protocol_stores();

    /// Dispatch decision derived from the tagged pending state plus the
    /// incoming frame type. Kept as a local Copy enum so the immutable
    /// pending borrow ends before the handlers take `&mut stores`.
    enum ResumeDispatch {
        /// Sensor: challenge arrived while awaiting it → verify + stage Final
        /// (carries the stashed request nonce).
        #[cfg(feature = "sensor")]
        Challenge {
            /// Request nonce stashed in `ResumeSensorAwaitChallenge`.
            sensor_nonce: [u8; RESUME_NONCE_SIZE],
        },
        /// Sensor: CommitConfirmed arrived after Final → commit the session.
        #[cfg(feature = "sensor")]
        CommitConfirmed,
        /// Sensor: duplicate challenge after Final → retransmit cached Final.
        #[cfg(feature = "sensor")]
        RetransmitFinal,
        /// Gateway: Confirm (or duplicate Confirm while CommitSent) → commit
        /// or retransmit cached CommitConfirmed.
        #[cfg(feature = "gateway")]
        GatewayConfirm,
        /// No (state, frame) pair matches: fail closed.
        Invalid,
    }

    let dispatch = {
        let pending = stores
            .pending
            .get(&peer)
            .ok_or(SigilError::NoPending { peer })?;
        match (pending.state(), frame_type) {
            #[cfg(feature = "sensor")]
            (
                PendingState::ResumeSensorAwaitChallenge { sensor_nonce },
                FrameType::ResumeChallenge,
            ) => ResumeDispatch::Challenge {
                sensor_nonce: *sensor_nonce.as_array(),
            },
            #[cfg(feature = "sensor")]
            (PendingState::ResumeSensorFinalSent { .. }, FrameType::ResumeCommitConfirmed) => {
                ResumeDispatch::CommitConfirmed
            }
            #[cfg(feature = "sensor")]
            (PendingState::ResumeSensorFinalSent { .. }, FrameType::ResumeChallenge) => {
                ResumeDispatch::RetransmitFinal
            }
            #[cfg(feature = "gateway")]
            (PendingState::ResumeGatewayAwaitConfirm { .. }, FrameType::ResumeConfirm)
            | (PendingState::ResumeGatewayCommitSent { .. }, FrameType::ResumeConfirm) => {
                ResumeDispatch::GatewayConfirm
            }
            _ => ResumeDispatch::Invalid,
        }
    };

    match dispatch {
        #[cfg(feature = "sensor")]
        ResumeDispatch::Challenge { sensor_nonce } => {
            handle_resume_challenge(&mut stores, &peer, packet, se, &sensor_nonce, now)
        }
        #[cfg(feature = "sensor")]
        ResumeDispatch::CommitConfirmed => {
            handle_resume_commit_confirmed(&mut stores, &peer, packet, now)
        }
        #[cfg(feature = "sensor")]
        ResumeDispatch::RetransmitFinal => stores.pending.retransmit_cached_action::<MSG>(&peer),
        #[cfg(feature = "gateway")]
        ResumeDispatch::GatewayConfirm => {
            gateway::handle_resume_confirm(&mut stores, &peer, packet, now)
        }
        ResumeDispatch::Invalid => Err(SigilError::InvalidStep { peer }),
    }
}

mod tests;

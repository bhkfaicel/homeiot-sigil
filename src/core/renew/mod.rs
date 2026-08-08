//! Sensor-initiated session renewal protocol
//!
//! Lightweight key rotation using ephemeral-to-ephemeral **X25519** ECDH
//! performed **in software** (no secure element identity operations). Renew
//! Request/Challenge are AEAD-encrypted under the **current** session key;
//! Final (`RenewAck`) and CommitConfirmed use the **new** directional keys.
//!
//! # Flow (4 messages)
//!
//! 1. **Sensor** → `start_renew_sensor_internal` → emits encrypted `RenewRequest`
//!    (sensor ephemeral pubkey). Requires [`SessionRole::Sensor`](crate::core::SessionRole).
//! 2. **Gateway** → `handle_renew_request_internal` → decrypts, generates its
//!    own ephemeral scalar, performs eph↔eph ECDH, derives the new key, emits
//!    encrypted `RenewChallenge`.
//! 3. **Sensor** → `continue_renew_internal` → decrypts, performs ECDH, derives
//!    the same key, **stages** it in pending, emits encrypted `RenewAck` (Final).
//!    Live session keeps the **old** key until step 4.
//! 4. **Gateway** → `continue_renew_internal` → decrypts ack under the new key,
//!    **commits** the session, emits `RenewCommitConfirmed`, keeps pending at
//!    `RenewCommitSent` for idempotent reTX.
//! 5. **Sensor** → `continue_renew_internal` on CommitConfirmed → verifies AEAD
//!    under staged keys, **commits**, clears pending.
//!
//! Only sensors initiate renew. The gateway exposes no `start_renew_*` API.
//! Host must call [`SessionManager::continue_renew`](crate::core::manager::SessionManager::continue_renew)
//! on `RenewChallenge`, `RenewAck`, and `RenewCommitConfirmed` events.
//!
//! The public API is exposed as methods on [`SessionManager`].

#[cfg(feature = "gateway")]
pub(crate) mod gateway;
#[cfg(feature = "sensor")]
pub(crate) mod sensor;
pub(crate) mod wire;

#[cfg(feature = "sensor")]
use crate::core::ecdh_soft::zeroize_secret;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType};
use crate::core::manager::SessionManager;
use crate::core::pending::{HandshakeRole, HandshakeStep};
#[cfg(feature = "sensor")]
use crate::core::pending::PendingHandshake;
use crate::core::session::PeerId;
#[cfg(feature = "sensor")]
use crate::core::session::SessionRole;
use crate::core::traits::RandomSource;

/// Suggested radio wait for renew handshake steps (milliseconds).
/// Advisory for the host scheduler / `Transmit.wait_timeout_ms` only.
/// Also converted to a seconds `deadline_at` for optional [`SessionManager::tick`](crate::core::manager::SessionManager::tick).
/// Elapsing this duration alone does **not** clear pending — call `cancel_pending` and/or `tick`.
pub const RENEW_TIMEOUT_MS: u32 = 10000;

/// HKDF info for renew key derivation.
/// `info = b"sigil-renew" ‖ sensor_mac[17] ‖ sensor_eph[32] ‖ gateway_eph[32] ‖ key_lifetime_secs_be[4]`
/// Binding both ephemeral public keys, the **sensor** MAC, and the advertised
/// expiry ties the derived session key to the renew transcript. Both peers
/// must pass the sensor identity (gateway: session key; sensor: `local_mac`).
pub(crate) fn renew_hkdf_info(
    sensor_mac: &PeerId,
    sensor_eph_pubkey: &[u8; 32],
    gateway_eph_pubkey: &[u8; 32],
    key_lifetime_secs: u32,
) -> Result<heapless::Vec<u8, 96>, SigilError> {
    let mut info = heapless::Vec::<u8, 96>::new();
    info.extend_from_slice(b"sigil-renew")
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_mac)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_eph_pubkey)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(gateway_eph_pubkey)
.map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(&key_lifetime_secs.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    Ok(info)
}

/// Internal implementation of [`SessionManager::start_renew`].
/// Starts a renewal handshake on the sensor side. Requires an active session
/// key and [`SessionRole::Sensor`]; generates an ephemeral keypair,
/// encrypts the request under the current session key, and stores the ephemeral
/// scalar in the pending handshake.
#[cfg(feature = "sensor")]
pub(crate) fn start_renew_sensor_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: PeerId,
    rng: &mut impl RandomSource,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // Reject before encrypt / TX advance so a full pending table cannot
    // burn a counter without emitting a frame. Never roll back tx_counter after
    // AEAD encrypt — that would risk nonce reuse under the same session key.
    if manager.get_pending(&peer).is_some() {
        return Err(SigilError::PendingAlreadyExists { peer });
    }
    if !manager.pending_slot_available(&peer) {
        return Err(SigilError::CapacityExceeded);
    }

    let session = manager
.get(&peer)
.ok_or(SigilError::UnknownSession { peer })?;
    // Only the sensor role may initiate renew.
    if session.role() != SessionRole::Sensor {
        return Err(SigilError::InvalidStep { peer });
    }
    // Refuse soft-expired keys before RNG / encrypt / TX advance.
    // Enrolled-without-key still surfaces as SessionNotActive via require_key_material.
    if session.session_key().is_some() && session.is_expired(now) {
        return Err(SigilError::SessionExpired { peer });
    }
    let (session_key, nonce_prefix) = session.require_key_material(&peer)?;
    let tx_counter = session.tx_counter;
    let local = *manager.local_mac();

    // Build and encrypt while holding the session borrow.
    let (frame, eph_scalar) = sensor::build_renew_request_frame::<MSG>(
        &local,
        session_key,
        nonce_prefix,
        tx_counter,
        rng,
    )?;

    // Advance the tx_counter for the request we just encrypted.
    let next_tx = crate::core::aead::check_tx_counter(tx_counter)
.map_err(|_| SigilError::CounterExhausted { peer })?;
    let session = manager
.get_mut(&peer)
.ok_or(SigilError::UnknownSession { peer })?;
    session.tx_counter = next_tx;

    // Stash the ephemeral scalar in the pending handshake.
    let pending = PendingHandshake::new_renew(
        peer,
        HandshakeRole::Sensor,
        eph_scalar,
        RENEW_TIMEOUT_MS,
        now,
    );
    manager.insert_pending(peer, pending)?;

    Ok(SigilAction::Transmit {
        dest: peer,
        payload: frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

/// Internal implementation of [`SessionManager::handle_renew_request`].
/// Gateway-only: processes an encrypted renew request and emits the challenge.
/// `now` is the current host timestamp in **seconds** (validates the old session key).
/// `key_lifetime_secs` is the authenticated duration advertised for the new key.
#[cfg(feature = "gateway")]
pub(crate) fn handle_renew_request_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // The renew request is encrypted; the outer 17 bytes are the peer MAC.
    if packet.len() < 17 {
        return Err(SigilError::ParseError);
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);

    gateway::handle_renew_request(manager, &peer, packet, rng, now, key_lifetime_secs)
}

/// Internal implementation of [`SessionManager::continue_renew`].
/// Dispatches by role / step / frame type:
/// - Sensor + Challenge → stage keys, emit Final (`RenewAck`)
/// - Sensor + CommitConfirmed → verify staged keys, commit
/// - Sensor WaitingForCommitConfirmed + Challenge again → reTX cached Final
/// - Gateway + Ack → commit, emit CommitConfirmed (or reTX if CommitSent)
pub(crate) fn continue_renew_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    rng: &mut impl RandomSource,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let _ = rng;
    if packet.len() < crate::core::frame::OUTER_HEADER_SIZE {
        return Err(SigilError::ParseError);
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);

    let frame_type =
        FrameType::from_byte(packet[FRAME_TYPE_OFFSET]).ok_or(SigilError::ParseError)?;
    if !frame_type.is_renew() {
        return Err(SigilError::ParseError);
    }

    let pending = manager
.get_pending(&peer)
.ok_or(SigilError::NoPending { peer })?;
    let role = pending.role;
    let step = pending.step;

    match (role, step, frame_type) {
        #[cfg(feature = "sensor")]
        (
            HandshakeRole::Sensor,
            HandshakeStep::RenewWaitingForChallenge,
            FrameType::RenewChallenge,
        ) => {
            let eph_scalar = *pending
.eph_scalar()
.ok_or(SigilError::InvalidHandshakeState)?;
            let mut scalar_copy = eph_scalar;
            let result = sensor::handle_renew_challenge(manager, &peer, packet, &scalar_copy, now);
            zeroize_secret(&mut scalar_copy);
            result
        }
        #[cfg(feature = "sensor")]
        (
            HandshakeRole::Sensor,
            HandshakeStep::RenewWaitingForCommitConfirmed,
            FrameType::RenewCommitConfirmed,
        ) => sensor::handle_renew_commit_confirmed(manager, &peer, packet, now),
        // Lost CommitConfirmed: host re-delivers Challenge → reTX cached Final.
        #[cfg(feature = "sensor")]
        (
            HandshakeRole::Sensor,
            HandshakeStep::RenewWaitingForCommitConfirmed,
            FrameType::RenewChallenge,
        ) => manager.retransmit_pending_cached(&peer),
        #[cfg(feature = "gateway")]
        (HandshakeRole::Gateway, HandshakeStep::RenewWaitingForAck, FrameType::RenewAck)
        | (HandshakeRole::Gateway, HandshakeStep::RenewCommitSent, FrameType::RenewAck) => {
            gateway::handle_renew_ack(manager, &peer, packet, now)
        }
        _ => Err(SigilError::InvalidStep { peer }),
    }
}

mod tests;

//! Sensor-initiated P-256 session renewal.
//!
//! Request, Challenge and Confirm use the current directional session keys.
//! The sensor creates its private key only after receiving the gateway public
//! key and asks [`SecureElement`] to perform
//! an atomic TempKey generation + ECDH. CommitConfirmed is authenticated with
//! the staged new gateway→sensor key.

#[cfg(feature = "gateway")]
pub(crate) mod gateway;
#[cfg(feature = "sensor")]
pub(crate) mod sensor;
pub(crate) mod wire;

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType};
use crate::core::manager::SessionManager;
#[cfg(feature = "sensor")]
use crate::core::pending::PendingHandshake;
use crate::core::pending::PendingState;
use crate::core::session::PeerId;
#[cfg(feature = "sensor")]
use crate::core::session::SessionRole;
#[cfg(feature = "gateway")]
use crate::core::traits::RandomSource;
#[cfg(any(feature = "sensor", feature = "gateway"))]
use crate::core::traits::SecureElement;
use hkdf::Hkdf;
use sha2::Sha256;
pub const RENEW_TIMEOUT_MS: u32 = 10_000;

const RENEW_HKDF_DOMAIN: &[u8] = b"sigil-renew-p256-v4";
const RENEW_SENSOR_PROOF_DOMAIN: &[u8] = b"sigil-renew-sensor-proof-v4";

/// Canonical transcript bound into the directional key derivation.
pub(crate) fn renew_hkdf_info(
    sensor_peer_id: &PeerId,
    sensor_ephemeral_pubkey: &[u8; 33],
    gateway_ephemeral_pubkey: &[u8; 33],
    key_lifetime_secs: u32,
) -> Result<heapless::Vec<u8, 128>, SigilError> {
    let mut info = heapless::Vec::<u8, 128>::new();
    info.extend_from_slice(RENEW_HKDF_DOMAIN)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(sensor_peer_id)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(sensor_ephemeral_pubkey)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(gateway_ephemeral_pubkey)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    info.extend_from_slice(&key_lifetime_secs.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(info)
}

/// Derives the 16-byte sensor proof from the new sensor→gateway key and the
/// complete Renew transcript.
pub(crate) fn renew_sensor_proof(
    new_s2g_key: &[u8; 32],
    transcript: &[u8],
) -> Result<[u8; 16], SigilError> {
    let mut proof_info = heapless::Vec::<u8, 160>::new();
    proof_info
        .extend_from_slice(RENEW_SENSOR_PROOF_DOMAIN)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    proof_info
        .extend_from_slice(transcript)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    let hk = Hkdf::<Sha256>::new(None, new_s2g_key);
    let mut proof = [0u8; 16];
    hk.expand(&proof_info, &mut proof)
        .map_err(|_| SigilError::EcdhFailed)?;
    Ok(proof)
}

#[cfg(feature = "sensor")]
pub(crate) fn start_renew_sensor_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: PeerId,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // Lend the storage capabilities once: every pending / session access
    // below goes through the narrow store view instead of manager internals.
    // Field mutation flows through the view's own `&mut` store references.
    let stores = manager.protocol_stores();

    if stores.pending.get(&peer).is_some() {
        return Err(SigilError::PendingAlreadyExists { peer });
    }
    if !stores.pending.slot_available(&peer) {
        return Err(SigilError::PendingTableFull);
    }

    let session = stores
        .sessions
        .get(&peer)
        .ok_or(SigilError::UnknownSession { peer })?;
    if session.role() != SessionRole::Sensor {
        return Err(SigilError::WrongRole { peer });
    }
    if session.session_key().is_some() && session.is_expired(now) {
        return Err(SigilError::SessionExpired { peer });
    }
    let (session_key, nonce_prefix) = session.require_key_material(&peer)?;
    let tx_counter = session.tx_counter;
    let local = *stores.local_mac;

    let frame =
        sensor::build_renew_request_frame::<MSG>(&local, session_key, nonce_prefix, tx_counter)?;
    let next_tx = crate::core::aead::check_tx_counter(tx_counter)
        .map_err(|_| SigilError::CounterExhausted { peer })?;

    // The tagged state retains no request material: the secure element
    // generates and consumes the ephemeral scalar at challenge time.
    let pending = PendingHandshake::new_renew_sensor(peer, RENEW_TIMEOUT_MS, now);
    stores.pending.insert(peer, pending)?;
    stores
        .sessions
        .get_mut(&peer)
        .ok_or(SigilError::UnknownSession { peer })?
        .tx_counter = next_tx;

    Ok(SigilAction::Transmit {
        dest: peer,
        payload: frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

#[cfg(feature = "gateway")]
pub(crate) fn handle_renew_request_internal<const N: usize, const MSG: usize>(
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
    gateway::handle_renew_request(&mut stores, &peer, packet, se, rng, now, key_lifetime_secs)
}

#[cfg(feature = "sensor")]
pub(crate) fn continue_renew_sensor_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    if packet.len() < crate::core::frame::OUTER_HEADER_SIZE {
        return Err(SigilError::MalformedFrame);
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);
    let frame_type =
        FrameType::from_byte(packet[FRAME_TYPE_OFFSET]).ok_or(SigilError::MalformedFrame)?;

    // Lend the storage capabilities once: the dispatch peek and the handlers
    // all work on this narrow view.
    let mut stores = manager.protocol_stores();

    /// Dispatch decision derived from the tagged pending state plus the
    /// incoming frame type. Kept as a local Copy enum so the immutable
    /// pending borrow ends before the handlers take `&mut stores`.
    enum RenewDispatch {
        /// Challenge arrived while awaiting it → verify + stage Final.
        Challenge,
        /// CommitConfirmed arrived after Final → commit the rotated key.
        CommitConfirmed,
        /// Duplicate challenge after Final → retransmit cached Final.
        RetransmitFinal,
        /// No (state, frame) pair matches: fail closed.
        Invalid,
    }

    let dispatch = {
        let pending = stores
            .pending
            .get(&peer)
            .ok_or(SigilError::NoPending { peer })?;
        match (pending.state(), frame_type) {
            (PendingState::RenewSensorAwaitChallenge, FrameType::RenewChallenge) => {
                RenewDispatch::Challenge
            }
            (PendingState::RenewSensorFinalSent { .. }, FrameType::RenewCommitConfirmed) => {
                RenewDispatch::CommitConfirmed
            }
            (PendingState::RenewSensorFinalSent { .. }, FrameType::RenewChallenge) => {
                RenewDispatch::RetransmitFinal
            }
            _ => RenewDispatch::Invalid,
        }
    };

    match dispatch {
        RenewDispatch::Challenge => {
            sensor::handle_renew_challenge(&mut stores, &peer, packet, se, now)
        }
        RenewDispatch::CommitConfirmed => {
            sensor::handle_renew_commit_confirmed(&mut stores, &peer, packet, now)
        }
        RenewDispatch::RetransmitFinal => stores.pending.retransmit_cached_action::<MSG>(&peer),
        RenewDispatch::Invalid => Err(SigilError::InvalidStep { peer }),
    }
}

#[cfg(feature = "gateway")]
pub(crate) fn handle_renew_confirm_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    if packet.len() < crate::core::frame::OUTER_HEADER_SIZE {
        return Err(SigilError::MalformedFrame);
    }
    let mut peer = [0u8; 17];
    peer.copy_from_slice(&packet[..17]);
    if FrameType::from_byte(packet[FRAME_TYPE_OFFSET]) != Some(FrameType::RenewConfirm) {
        return Err(SigilError::MalformedFrame);
    }
    let mut stores = manager.protocol_stores();
    let pending = stores
        .pending
        .get(&peer)
        .ok_or(SigilError::NoPending { peer })?;
    // Gateway renew dispatch: only the challenge-waiting and post-commit
    // recovery variants may process a RenewConfirm (idempotent reTX).
    if !matches!(
        pending.state(),
        PendingState::RenewGatewayAwaitConfirm { .. } | PendingState::RenewGatewayCommitSent { .. }
    ) {
        return Err(SigilError::InvalidStep { peer });
    }
    gateway::handle_renew_confirm(&mut stores, &peer, packet, se, now)
}

mod tests;

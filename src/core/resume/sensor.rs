//! Sensor-side resume implementation
//!
//! Implements the sensor steps of the fast resume handshake:
//! 1. Build a `ResumeRequest` with nonce + MAC over the durable resume PSK.
//! 2. On receiving the `ResumeChallenge`, verify the challenge MAC (binds
//!    `key_lifetime_secs` to the static ECDH secret), derive directional keys,
//!    encrypt confirm (Final) under the **new** s2g half, **stage** keys in
//!    pending (do **not** `update_key` yet).
//! 3. On `ResumeCommitConfirmed`, verify AEAD under staged g2s, then commit.
//!
//! Outer headers carry **local_mac** (sender identity).
//!
//! # Commit ordering
//!
//! Confirm is encrypted under the new s2g key and staged. The live session
//! stays without an active key until CommitConfirmed verifies.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::FrameType;
use crate::core::manager::ProtocolStores;
use crate::core::pending::PendingState;
use crate::core::resume::RESUME_TIMEOUT_MS;
use crate::core::resume::wire::{
    build_resume_confirm_body, build_resume_request_body, parse_resume_challenge_body,
    resume_chal_mac_eq, resume_challenge_mac, resume_request_mac,
};
use crate::core::session::{PeerId, ResumePsk};
use crate::core::traits::{RandomSource, SecureElement};

/// Re-exported nonce size so `resume::mod` and `gateway` share one constant.
pub(crate) const RESUME_NONCE_SIZE: usize = 16;

/// Builds the resume request (sensor → gateway): nonce ‖ req_mac.
/// Frame:
/// `local_mac(17) ‖ protocol_version(1) ‖ frame_type(1 = 0x21) ‖ sensor_nonce(16) ‖ req_mac(16)`.
pub(crate) fn build_resume_request_frame<const MSG: usize>(
    local_mac: &PeerId,
    resume_psk: &ResumePsk,
    rng: &mut impl RandomSource,
) -> Result<(heapless::Vec<u8, MSG>, [u8; RESUME_NONCE_SIZE]), SigilError> {
    use crate::core::frame::{self, FrameType};

    let mut sensor_nonce = [0u8; RESUME_NONCE_SIZE];
    rng.fill_bytes(&mut sensor_nonce)?;
    let req_mac = resume_request_mac(resume_psk, local_mac, &sensor_nonce)?;
    let body = build_resume_request_body(&sensor_nonce, &req_mac)?;

    let mut frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let header = frame::build_header(local_mac, FrameType::ResumeRequest);
    frame
        .extend_from_slice(&header)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(&body)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok((frame, sensor_nonce))
}

/// Processes a resume challenge on the sensor side: stages keys + emits Final.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_resume_challenge<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    packet: &[u8],
    se: &mut impl SecureElement,
    sensor_nonce: &[u8; RESUME_NONCE_SIZE],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::{
        FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    };
    use crate::core::resume::wire::RESUME_CHALLENGE_BODY_LEN;

    if packet.len() < OUTER_HEADER_SIZE + RESUME_CHALLENGE_BODY_LEN {
        return Err(SigilError::MalformedFrame);
    }
    if packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
        || packet[FRAME_TYPE_OFFSET] != FrameType::ResumeChallenge as u8
    {
        return Err(SigilError::MalformedFrame);
    }
    let body = &packet[OUTER_HEADER_SIZE..];
    let challenge = parse_resume_challenge_body(body).ok_or(SigilError::MalformedFrame)?;

    let session = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;

    // Wipe shared on Drop (MAC fail, validate, HKDF, or encrypt errors).
    let shared =
        crate::core::secret::validated_ecdh_shared_secret(se.ecdh(session.peer_static_pubkey())?)?;

    let expected_mac = resume_challenge_mac(
        shared.as_array(),
        sensor_nonce,
        &challenge.gateway_nonce,
        challenge.key_lifetime_secs,
    )?;
    if !resume_chal_mac_eq(&expected_mac, &challenge.chal_mac) {
        return Err(SigilError::VerificationFailed);
    }

    // After MAC proves authenticity, refuse past / over-long expiry.
    crate::core::session::validate_key_lifetime(challenge.key_lifetime_secs)?;

    let info = crate::core::resume::resume_hkdf_info(
        sensor_nonce,
        &challenge.gateway_nonce,
        challenge.key_lifetime_secs,
    )?;

    let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
    drop(shared);

    let confirm_body = build_resume_confirm_body()?;
    let local = *stores.local_mac;
    let confirm_aad = aead::build_aad(&local, FrameType::ResumeConfirm);

    // Encrypt confirm under the new s2g half **before** staging.
    let mut frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let confirm_header = crate::core::frame::build_header(&local, FrameType::ResumeConfirm);
    frame
        .extend_from_slice(&confirm_header)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(&material.s2g_prefix)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(&0u64.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    aead::encrypt_append(
        &material.s2g_key,
        &material.s2g_prefix,
        0,
        &confirm_body,
        &confirm_aad,
        &mut frame,
    )?;

    // Checked transition to the FinalSent recovery state: stages the resumed
    // directional material, caches the Final frame, refreshes the deadline,
    // and wipes the stashed request nonce — all atomically (fail-atomic on
    // any error). Do not update_key yet.
    let pending = stores
        .pending
        .get_mut(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    pending.resume_sensor_stage_final(material, challenge.key_lifetime_secs, &frame, now)?;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: frame,
        wait_timeout_ms: Some(RESUME_TIMEOUT_MS),
    })
}

/// Handles `ResumeCommitConfirmed`: verify staged keys, then commit.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_resume_commit_confirmed<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // The tagged FinalSent recovery state carries exactly the staged resume
    // material and lifetime; any other state fails closed with InvalidStep.
    let (material, lifetime) = match stores
        .pending
        .get(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?
        .state()
    {
        PendingState::ResumeSensorFinalSent {
            keys,
            key_lifetime_secs,
            ..
        } => (keys.clone(), *key_lifetime_secs),
        _ => return Err(SigilError::InvalidStep { peer: *peer }),
    };

    aead::verify_commit_confirmed(
        frame,
        FrameType::ResumeCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
    )
    .map_err(|e| match e {
        SigilError::Replay {
            expected, received, ..
        } => SigilError::Replay {
            peer: *peer,
            expected,
            received,
        },
        other => other,
    })?;

    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    let expire = crate::core::session::expire_from_lifetime(now, lifetime)?;
    session.update_key(material, expire, now)?;
    session.tx_counter = 1;
    session.rx_counter = 1;
    let _ = stores.pending.remove(peer);

    Ok(SigilAction::Success { peer: *peer })
}

//! Gateway-side resume implementation
//!
//! Implements the gateway steps of the fast resume handshake:
//! 1. On receiving a `ResumeRequest`, verify the **req_mac** with the durable
//!    resume PSK **before** any SE-ECDH; then pending/cooldown guards,
//!    ECDH, challenge.
//! 2. On receiving the AEAD-protected `ResumeConfirm` (Final), decrypt under the
//!    stashed **s2g** half, commit directional keys, emit CommitConfirmed, keep
//!    pending at `ResumeCommitSent` for idempotent reTX.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::manager::SessionManager;
use crate::core::pending::{HandshakeRole, HandshakeStep, PendingHandshake};
use crate::core::resume::wire::{
    RESUME_NONCE_SIZE, RESUME_REQUEST_BODY_LEN, build_resume_challenge_body,
    parse_resume_confirm_body, parse_resume_request_body, resume_chal_mac_eq, resume_challenge_mac,
    resume_request_mac,
};
use crate::core::resume::{RESUME_REQUEST_COOLDOWN, RESUME_TIMEOUT_MS};
use crate::core::session::{PeerId, SessionRole};
use crate::core::traits::{RandomSource, SecureElement};

/// Handles a resume request on the gateway side.
/// `now` is gateway-local time; `key_lifetime_secs` is a duration in seconds.
/// [`RESUME_REQUEST_COOLDOWN`] is therefore **15 seconds**.
pub(crate) fn handle_resume_request<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    packet: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::{
        FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    };

    // Reject zero / over-long lifetimes before MAC verify / SE-ECDH.
    crate::core::session::validate_key_lifetime(key_lifetime_secs)?;

    if packet.len() < OUTER_HEADER_SIZE + RESUME_REQUEST_BODY_LEN {
        return Err(SigilError::ParseError);
    }
    if packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
        || packet[FRAME_TYPE_OFFSET] != FrameType::ResumeRequest as u8
    {
        return Err(SigilError::ParseError);
    }
    let body = &packet[OUTER_HEADER_SIZE..];
    let req = parse_resume_request_body(body).ok_or(SigilError::ParseError)?;

    // Verify request MAC with durable PSK **before** SE-ECDH.
    let resume_psk = {
        let session = manager
.get(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;
        // Inbound resume is a gateway-only operation.
        if session.role() != SessionRole::Gateway {
            return Err(SigilError::InvalidStep { peer: *peer });
        }
        session.require_resume_psk()?
    };
    let expected = resume_request_mac(&resume_psk, peer, &req.sensor_nonce)?;
    if !resume_chal_mac_eq(&expected, &req.req_mac) {
        return Err(SigilError::VerificationFailed);
    }

    let replacing_stale_commit = if let Some(pending) = manager.get_pending(peer) {
        let recoverable = pending.role == HandshakeRole::Gateway
            && matches!(
                pending.step,
                HandshakeStep::InstallCommitSent
                    | HandshakeStep::RenewCommitSent
                    | HandshakeStep::ResumeCommitSent
            );
        if !recoverable {
            return Err(SigilError::PendingAlreadyExists { peer: *peer });
        }
        true
    } else {
        false
    };

    {
        let session = manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;

        if !session.resume_cooldown_elapsed(now, RESUME_REQUEST_COOLDOWN) {
            return Err(SigilError::RateLimited { peer: *peer });
        }
    }

    let peer_static = manager
.get(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?
.peer_static_pubkey;

    // ECDH shared wiped on Drop even if MAC / HKDF / frame build fails.
    let shared = crate::core::secret::SharedSecretBuf::new(se.ecdh(&peer_static)?);

    let mut gateway_nonce = [0u8; RESUME_NONCE_SIZE];
    rng.fill_bytes(&mut gateway_nonce)?;

    let chal_mac = resume_challenge_mac(
        shared.as_array(),
        &req.sensor_nonce,
        &gateway_nonce,
        key_lifetime_secs,
    )?;

    let info = crate::core::resume::resume_hkdf_info(
        &req.sensor_nonce,
        &gateway_nonce,
        key_lifetime_secs,
    )?;

    let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
    drop(shared);

    let local = *manager.local_mac();
    let challenge_body = build_resume_challenge_body(&gateway_nonce, key_lifetime_secs, &chal_mac)?;
    let mut frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let chal_header = crate::core::frame::build_header(&local, FrameType::ResumeChallenge);
    frame
.extend_from_slice(&chal_header)
.map_err(|_| SigilError::CapacityExceeded)?;
    frame
.extend_from_slice(&challenge_body)
.map_err(|_| SigilError::CapacityExceeded)?;

    let mut pending =
        PendingHandshake::new_resume(*peer, HandshakeRole::Gateway, RESUME_TIMEOUT_MS, now);
    pending.update_step(HandshakeStep::ResumeWaitingForConfirm);
    pending.set_directional_keys(material);
    pending.transcript_expire = Some(key_lifetime_secs);
    // Preserve the previous CommitSent recovery state across every fallible
    // verification/crypto/build operation. Replace it only once the complete
    // new challenge and pending state are ready.
    if replacing_stale_commit {
        let _ = manager.remove_pending(peer);
    }
    manager.insert_pending(*peer, pending)?;

    if let Some(s) = manager.get_mut(peer) {
        s.mark_resume_request(now);
    }

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: frame,
        wait_timeout_ms: Some(RESUME_TIMEOUT_MS),
    })
}

/// Handles the resume confirm (Final) on the gateway side.
/// Commits the session, emits CommitConfirmed, keeps pending at CommitSent.
/// Duplicate Final while CommitSent retransmits cached CommitConfirmed.
pub(crate) fn handle_resume_confirm<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    packet: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::{
        FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    };

    let pending = manager
.get_pending(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;

    if pending.step == HandshakeStep::ResumeCommitSent {
        return retransmit_cached(manager, peer, RESUME_TIMEOUT_MS);
    }

    if pending.step != HandshakeStep::ResumeWaitingForConfirm {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    let material = pending
.directional_keys()
.ok_or(SigilError::ParseError)?
.clone();
    let lifetime = pending.transcript_expire.ok_or(SigilError::ParseError)?;

    // Confirm is sensor→gateway under the new s2g half.
    let confirm_key = &material.s2g_key;
    let confirm_prefix = &material.s2g_prefix;

    if packet.len() < OUTER_HEADER_SIZE + 4 + 8 + aead::TAG_SIZE {
        return Err(SigilError::ParseError);
    }
    if packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
        || packet[FRAME_TYPE_OFFSET] != FrameType::ResumeConfirm as u8
    {
        return Err(SigilError::ParseError);
    }
    let wire_prefix: &[u8; 4] = packet[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4]
.try_into()
.map_err(|_| SigilError::ParseError)?;
    if wire_prefix != confirm_prefix {
        return Err(SigilError::ParseError);
    }
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&packet[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12]);
    let received_counter = u64::from_be_bytes(counter_bytes);
    if received_counter != 0 {
        return Err(SigilError::Replay {
            peer: *peer,
            expected: 0,
            received: received_counter,
        });
    }

    {
        let mut plaintext: heapless::Vec<u8, { aead::HANDSHAKE_PLAINTEXT_CAP }> =
            heapless::Vec::new();
        aead::decrypt_into(
            confirm_key,
            confirm_prefix,
            0,
            &packet[OUTER_HEADER_SIZE + 12..],
            aead::aad_from_frame(packet).ok_or(SigilError::ParseError)?,
            &mut plaintext,
        )?;
        if !parse_resume_confirm_body(&plaintext) {
            return Err(SigilError::VerificationFailed);
        }
    }

    let local = *manager.local_mac();
    let commit_frame = aead::build_commit_confirmed_frame::<MSG>(
        &local,
        FrameType::ResumeCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
        0,
    )?;

    let session = manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;
    let expire = crate::core::session::expire_from_lifetime(now, lifetime)?;
    session.update_key(material, expire, now)?;
    session.rx_counter = 1;
    session.tx_counter = 1;

    let pending = manager
.get_pending_mut(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;
    if let Some(mut secrets) = pending.secrets.take() {
        secrets.zeroize();
    }
    pending.set_cached_wire(&commit_frame)?;
    pending.update_step(HandshakeStep::ResumeCommitSent);
    pending.update_timeout(RESUME_TIMEOUT_MS, now);

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: commit_frame,
        wait_timeout_ms: Some(RESUME_TIMEOUT_MS),
    })
}

/// Retransmits `pending.cached_wire` as a `Transmit` action.
pub(crate) fn retransmit_cached<const N: usize, const MSG: usize>(
    manager: &SessionManager<N>,
    peer: &PeerId,
    timeout_ms: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let pending = manager
.get_pending(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;
    let cached = pending
.cached_wire
.as_ref()
.ok_or(SigilError::InvalidHandshakeState)?;
    let mut payload: heapless::Vec<u8, MSG> = heapless::Vec::new();
    payload
.extend_from_slice(cached)
.map_err(|_| SigilError::CapacityExceeded)?;
    Ok(SigilAction::Transmit {
        dest: *peer,
        payload,
        wait_timeout_ms: Some(timeout_ms),
    })
}

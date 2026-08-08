//! Sensor-side renew implementation
//!
//! Implements the sensor steps of the renew handshake (4-message):
//! 1. Generate an ephemeral X25519 scalar, derive the public key, build the
//!    `RenewRequest`, encrypt it under the current **TX** session key, and transmit.
//! 2. On receiving the `RenewChallenge`, decrypt under **RX**, perform eph↔eph ECDH,
//!    derive directional keys, encrypt `RenewAck` (Final) under the **new** s2g half,
//!    **stage** keys in pending (do **not** `update_key` yet), cache Final wire bytes.
//! 3. On receiving `RenewCommitConfirmed`, verify AEAD under staged g2s (RX), then
//!    commit (`update_key`) and clear pending.
//!
//! Outer headers carry **local_mac** (sender). HKDF binds the **sensor** MAC
//! so both peers derive the same material when `SENSOR_MAC ≠ GW_MAC`.
//!
//! # Commit ordering
//!
//! The renew ack is encrypted under the **new** s2g key and staged in pending.
//! The live session keeps the **old** key until CommitConfirmed verifies, so a
//! lost CommitConfirmed cannot leave the sensor on a new key the gateway never
//! confirmed.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::ecdh_soft::{
    ecdh_from_scalar, generate_ephemeral_scalar, pubkey_from_scalar, zeroize_secret,
};
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::FrameType;
use crate::core::manager::SessionManager;
use crate::core::pending::HandshakeStep;
use crate::core::renew::RENEW_TIMEOUT_MS;
use crate::core::renew::wire::{
    build_renew_ack_body, build_renew_request_body, parse_renew_challenge_body,
};
use crate::core::session::PeerId;
use crate::core::traits::RandomSource;

/// Builds and encrypts the sensor's renew request under the current TX session key.
/// Layout:
/// `[local_mac:17] [protocol_version:1] [frame_type:1 = 0x11]
///  [nonce_prefix:4] [counter:8] [ciphertext+tag]`
pub(crate) fn build_renew_request_frame<const MSG: usize>(
    local_mac: &PeerId,
    session_key: &[u8; 32],
    nonce_prefix: &[u8; 4],
    tx_counter: u64,
    rng: &mut impl RandomSource,
) -> Result<(heapless::Vec<u8, MSG>, [u8; 32]), SigilError> {
    use crate::core::frame::{self, FrameType};

    let eph_scalar = generate_ephemeral_scalar(rng)?;
    let eph_pub = pubkey_from_scalar(&eph_scalar)?;
    let body = build_renew_request_body(&eph_pub)?;

    let aad = aead::build_aad(local_mac, FrameType::RenewRequest);

    let mut frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let header = frame::build_header(local_mac, FrameType::RenewRequest);
    frame
.extend_from_slice(&header)
.map_err(|_| SigilError::CapacityExceeded)?;
    frame
.extend_from_slice(nonce_prefix)
.map_err(|_| SigilError::CapacityExceeded)?;
    frame
.extend_from_slice(&tx_counter.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    aead::encrypt_append(
        session_key,
        nonce_prefix,
        tx_counter,
        &body,
        &aad,
        &mut frame,
    )?;

    Ok((frame, eph_scalar))
}

/// Processes a renew challenge on the sensor side: decrypts, performs ECDH,
/// derives directional keys, builds the renew ack (Final), and **stages** keys
/// without committing the live session.
/// `peer` is the remote gateway MAC (session / pending key).
pub(crate) fn handle_renew_challenge<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame: &[u8],
    eph_scalar: &[u8; 32],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::{
        FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    };

    let sensor_mac = *manager.local_mac();
    let (material, key_lifetime_secs, new_rx) = {
        let session = manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;
        if !session.is_active(now) {
            return Err(SigilError::SessionExpired { peer: *peer });
        }

        if frame.len() < OUTER_HEADER_SIZE + 4 + 8 + aead::TAG_SIZE {
            return Err(SigilError::ParseError);
        }
        if frame[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
            || frame[FRAME_TYPE_OFFSET] != FrameType::RenewChallenge as u8
        {
            return Err(SigilError::ParseError);
        }
        let wire_prefix: &[u8; 4] = frame[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4]
.try_into()
.map_err(|_| SigilError::ParseError)?;
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12]);
        let received_counter = u64::from_be_bytes(counter_bytes);

        let new_rx = aead::verify_and_advance_rx_counter(session.rx_counter, received_counter)
.map_err(|_| SigilError::Replay {
                peer: *peer,
                expected: session.rx_counter,
                received: received_counter,
            })?;

        let mut plaintext: heapless::Vec<u8, { aead::HANDSHAKE_PLAINTEXT_CAP }> =
            heapless::Vec::new();
        {
            let (old_key, old_prefix) = session.require_rx_material(peer)?;
            if wire_prefix != old_prefix {
                return Err(SigilError::ParseError);
            }
            aead::decrypt_into(
                old_key,
                old_prefix,
                received_counter,
                &frame[OUTER_HEADER_SIZE + 12..],
                aead::aad_from_frame(frame).ok_or(SigilError::ParseError)?,
                &mut plaintext,
            )?;
        }
        let challenge = parse_renew_challenge_body(&plaintext).ok_or(SigilError::ParseError)?;
        // Refuse past / over-long expiry advertised in the challenge.
        crate::core::session::validate_key_lifetime(challenge.key_lifetime_secs)?;
        let sensor_eph_pub = pubkey_from_scalar(eph_scalar)?;
        // Shared wiped on Drop if HKDF / ack encrypt fails.
        let shared = crate::core::secret::SharedSecretBuf::new(ecdh_from_scalar(
            eph_scalar,
            &challenge.gateway_eph_pubkey,
        )?);
        let info = crate::core::renew::renew_hkdf_info(
            &sensor_mac,
            &sensor_eph_pub,
            &challenge.gateway_eph_pubkey,
            challenge.key_lifetime_secs,
        )?;
        let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
        drop(shared);

        (material, challenge.key_lifetime_secs, new_rx)
    };

    // Zeroize the ephemeral scalar now that ECDH is done (caller may also clear pending).
    let mut scalar_scratch = *eph_scalar;
    zeroize_secret(&mut scalar_scratch);

    let ack_body = build_renew_ack_body()?;
    let ack_aad = aead::build_aad(&sensor_mac, FrameType::RenewAck);

    // Encrypt ack under the new s2g half **before** staging.
    let mut ack_frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let ack_header = crate::core::frame::build_header(&sensor_mac, FrameType::RenewAck);
    ack_frame
.extend_from_slice(&ack_header)
.map_err(|_| SigilError::CapacityExceeded)?;
    ack_frame
.extend_from_slice(&material.s2g_prefix)
.map_err(|_| SigilError::CapacityExceeded)?;
    ack_frame
.extend_from_slice(&0u64.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    aead::encrypt_append(
        &material.s2g_key,
        &material.s2g_prefix,
        0,
        &ack_body,
        &ack_aad,
        &mut ack_frame,
    )?;

    // Stage new keys + cache Final; do **not** update_key / remove pending.
    let pending = manager
.get_pending_mut(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;
    pending.set_directional_keys(material);
    pending.transcript_expire = Some(key_lifetime_secs);
    pending.set_cached_wire(&ack_frame)?;
    pending.update_step(HandshakeStep::RenewWaitingForCommitConfirmed);
    pending.update_timeout(RENEW_TIMEOUT_MS, now);

    // Commit the old-key RX counter only after ECDH, Final encryption and
    // pending staging all succeeded, preserving retry after transient errors.
    manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?
.rx_counter = new_rx;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: ack_frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

/// Handles `RenewCommitConfirmed` on the sensor: verify AEAD with staged keys,
/// then commit and clear pending.
pub(crate) fn handle_renew_commit_confirmed<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let pending = manager
.get_pending(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;
    if pending.step != HandshakeStep::RenewWaitingForCommitConfirmed {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    let material = pending
.directional_keys()
.ok_or(SigilError::InvalidHandshakeState)?
.clone();
    let lifetime = pending
.transcript_expire
.ok_or(SigilError::InvalidHandshakeState)?;

    // CommitConfirmed is gateway→sensor under the new g2s half (sensor RX).
    aead::verify_commit_confirmed(
        frame,
        FrameType::RenewCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
    )
.map_err(|e| match e {
        SigilError::Replay {
            expected, received,..
        } => SigilError::Replay {
            peer: *peer,
            expected,
            received,
        },
        other => other,
    })?;

    let session = manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;
    let expire = crate::core::session::expire_from_lifetime(now, lifetime)?;
    session.update_key(material, expire, now)?;
    // Final (ack) used s2g counter 0; CommitConfirmed used g2s counter 0.
    session.tx_counter = 1;
    session.rx_counter = 1;
    let _ = manager.remove_pending(peer);

    Ok(SigilAction::Success { peer: *peer })
}

//! Sensor side of Renew P-256.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::FrameType;
use crate::core::manager::ProtocolStores;
use crate::core::pending::PendingState;
use crate::core::renew::RENEW_TIMEOUT_MS;
use crate::core::renew::wire::{
    build_renew_confirm_body, build_renew_request_body, parse_renew_challenge_body,
};
use crate::core::session::PeerId;
use crate::core::traits::SecureElement;

/// Builds the empty RenewRequest under the current sensor→gateway key.
pub(crate) fn build_renew_request_frame<const MSG: usize>(
    local_mac: &PeerId,
    session_key: &[u8; 32],
    nonce_prefix: &[u8; 4],
    tx_counter: u64,
) -> Result<heapless::Vec<u8, MSG>, SigilError> {
    let body = build_renew_request_body()?;
    let aad = aead::build_aad(local_mac, FrameType::RenewRequest);
    let mut frame = heapless::Vec::new();
    frame
        .extend_from_slice(&crate::core::frame::build_header(
            local_mac,
            FrameType::RenewRequest,
        ))
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(nonce_prefix)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(&tx_counter.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    aead::encrypt_append(
        session_key,
        nonce_prefix,
        tx_counter,
        &body,
        &aad,
        &mut frame,
    )?;
    Ok(frame)
}

/// Processes the gateway public key, performs one atomic ATECC TempKey ECDH,
/// stages the new keys and sends RenewConfirm under the old session key.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_renew_challenge<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let sensor_peer_id = *stores.local_mac;
    let (challenge, new_rx, old_tx_key, old_tx_prefix, confirm_counter) = {
        let session = stores
            .sessions
            .get_mut(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
        if !session.is_active(now) {
            return Err(SigilError::SessionExpired { peer: *peer });
        }
        let (rx_key, rx_prefix) = session.require_rx_material(peer)?;
        let opened = aead::open_frame::<{ aead::HANDSHAKE_PLAINTEXT_CAP }>(
            peer,
            FrameType::RenewChallenge,
            frame,
            rx_key,
            rx_prefix,
            aead::RxCounterPolicy::Window {
                current: session.rx_counter,
            },
        )?;
        let challenge =
            parse_renew_challenge_body(&opened.plaintext).ok_or(SigilError::MalformedFrame)?;
        crate::core::session::validate_key_lifetime(challenge.key_lifetime_secs)?;
        let (tx_key, tx_prefix) = session.require_tx_material(peer)?;
        (
            challenge,
            opened.next_rx_counter,
            crate::core::secret::SharedSecretBuf::new(*tx_key),
            crate::core::secret::NoncePrefixBuf::new(*tx_prefix),
            session.tx_counter,
        )
    };

    // One host call maps to GenKey TempKey + immediate ECDH in the ATECC.
    let (sensor_ephemeral_pubkey, raw_shared) =
        se.ephemeral_p256_ecdh(&challenge.gateway_ephemeral_pubkey)?;
    crate::core::session::validate_static_public_key_encoding(&sensor_ephemeral_pubkey)?;
    let shared = crate::core::secret::validated_ecdh_shared_secret(raw_shared)?;
    let transcript = crate::core::renew::renew_hkdf_info(
        &sensor_peer_id,
        &sensor_ephemeral_pubkey,
        &challenge.gateway_ephemeral_pubkey,
        challenge.key_lifetime_secs,
    )?;
    let material = derive_directional_session_keys(shared.as_array(), Some(&transcript))?;
    drop(shared);
    let proof = crate::core::renew::renew_sensor_proof(&material.s2g_key, &transcript)?;
    let confirm_body = build_renew_confirm_body(&sensor_ephemeral_pubkey, &proof)?;
    let next_tx = aead::check_tx_counter(confirm_counter)
        .map_err(|_| SigilError::CounterExhausted { peer: *peer })?;

    let mut confirm_frame = heapless::Vec::new();
    confirm_frame
        .extend_from_slice(&crate::core::frame::build_header(
            &sensor_peer_id,
            FrameType::RenewConfirm,
        ))
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    confirm_frame
        .extend_from_slice(old_tx_prefix.as_array())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    confirm_frame
        .extend_from_slice(&confirm_counter.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    aead::encrypt_append(
        old_tx_key.as_array(),
        old_tx_prefix.as_array(),
        confirm_counter,
        &confirm_body,
        &aead::build_aad(&sensor_peer_id, FrameType::RenewConfirm),
        &mut confirm_frame,
    )?;

    // Checked transition to the FinalSent recovery state: stages the rotated
    // directional material, caches the Final frame, and refreshes the deadline
    // atomically (fail-atomic on any error).
    let pending = stores
        .pending
        .get_mut(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    pending.renew_sensor_stage_final(material, challenge.key_lifetime_secs, &confirm_frame, now)?;

    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    session.rx_counter = new_rx;
    session.tx_counter = next_tx;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: confirm_frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

pub(crate) fn handle_renew_commit_confirmed<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // The tagged FinalSent recovery state carries exactly the staged rotated
    // material and lifetime; any other state fails closed with InvalidStep.
    let (material, lifetime) = match stores
        .pending
        .get(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?
        .state()
    {
        PendingState::RenewSensorFinalSent {
            keys,
            key_lifetime_secs,
            ..
        } => (keys.clone(), *key_lifetime_secs),
        _ => return Err(SigilError::InvalidStep { peer: *peer }),
    };

    aead::verify_commit_confirmed(
        frame,
        FrameType::RenewCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
    )
    .map_err(|error| match error {
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
    // Confirm used the old s2g key; only CommitConfirmed consumed a new-key
    // counter (g2s counter 0).
    session.tx_counter = 0;
    session.rx_counter = 1;
    let _ = stores.pending.remove(peer);
    Ok(SigilAction::Success { peer: *peer })
}

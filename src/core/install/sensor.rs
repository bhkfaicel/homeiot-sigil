//! Sensor-side installation implementation
//!
//! Implements the sensor steps of the install handshake (4-message):

//! 1. Build the initial `InstallRequest` (static pubkey + factory cert +
//!    nonce + device signature) using **local_mac** as sensor identity.
//! 2. On receiving an `InstallChallenge`, verify the gateway factory
//!    certificate against the cached factory root, verify the gateway
//!    device signature, perform ECDH(static_priv, gw_static_pub), derive
//!    directional keys + resume PSK, build `InstallConfirm` (Final), **stage**
//!    material in pending (do **not** insert session yet).
//! 3. On `InstallCommitConfirmed`, verify AEAD under staged g2s, insert the
//!    session, emit [`SigilAction::PersistPeerStaticKey`], clear pending.
//!
//! # Commit ordering

//!
//! The confirm frame is fully built and signed **before** keys are staged.
//! The live session table stays empty until CommitConfirmed verifies, so a
//! lost CommitConfirmed cannot leave the sensor enrolled while the gateway
//! never confirmed.
//!
//! # Host sensing priority

//!
//! `start_install` / `continue_install` chain multiple `SecureElement` calls.
//! On the sensor product, **door-open / vibration interrupts outrank install**.
//! The host must keep those IRQs unmasked during SE I/O and may defer starting
//! install while a critical sensing window is active. See
//! [`crate::core::traits::SecureElement`] and CLAUDE.md.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::FrameType;
use crate::core::install::INSTALL_TIMEOUT_MS;
use crate::core::install::wire::{
    EcdsaSig, InstallConfirm, InstallRequest, build_install_confirm, build_install_request,
    parse_install_challenge,
};
use crate::core::manager::ProtocolStores;
use crate::core::pending::PendingState;
use crate::core::session::{PeerId, Session, SessionRole};
use crate::core::traits::{FactoryCertificateMetadata, RandomSource, SecureElement};

/// Builds and signs the sensor's initial install request.
/// Embeds the factory certificate from [`SecureElement::get_factory_cert`] so
/// the gateway can attest that this device was manufactured under the shared
/// factory root.
/// `local_mac` is written into `sensor_peer_mac` and the outer header (sender
/// identity). `dest` is the gateway MAC used only for [`SigilAction::Transmit`].
/// Returns the serialized `InstallRequest` frame and the `sensor_nonce` so the
/// caller can stash it for HKDF at the challenge step.
pub(crate) fn build_install_request_action<const MSG: usize>(
    local_mac: PeerId,
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
) -> Result<(heapless::Vec<u8, MSG>, [u8; 16]), SigilError> {
    let sensor_static_pubkey = se.get_static_pubkey()?;
    crate::core::session::validate_static_public_key_encoding(&sensor_static_pubkey)?;
    let factory_cert_sig = se.get_factory_cert()?;
    let factory_metadata = se.get_factory_cert_metadata()?;

    let mut sensor_nonce = [0u8; 16];
    rng.fill_bytes(&mut sensor_nonce)?;

    // Domain-separated wire-v3 proof binds sensor identity, key and nonce.
    let to_sign = crate::core::install::install_request_sign_message(
        &local_mac,
        factory_metadata,
        &sensor_static_pubkey,
        &sensor_nonce,
    )?;
    let sensor_signature: EcdsaSig = se.sign_ecdsa(&to_sign)?;

    let request = InstallRequest {
        sensor_peer_mac: local_mac,
        hardware_profile_id: factory_metadata.hardware_profile_id,
        factory_key_id: factory_metadata.factory_key_id,
        sensor_static_pubkey,
        factory_cert_sig,
        sensor_nonce,
        sensor_signature,
    };

    let packet = build_install_request(&request)?;
    let mut out: heapless::Vec<u8, MSG> = heapless::Vec::new();
    out.extend_from_slice(&packet)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok((out, sensor_nonce))
}

/// Processes an install challenge packet on the sensor side.
/// Verifies attestation / signatures, derives keys, emits Final (`InstallConfirm`),
/// and **stages** material in pending without inserting a session.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
/// # Returns
/// `SigilAction::Transmit` carrying the `InstallConfirm` on success.
pub(crate) fn handle_install_challenge<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let challenge = parse_install_challenge(packet).ok_or(SigilError::MalformedFrame)?;
    // Outer header MAC must match the body gateway MAC.
    if !crate::core::install::outer_peer_matches_body(packet, &challenge.gateway_peer_mac) {
        return Err(SigilError::MalformedFrame);
    }

    // Pending is keyed by the remote gateway MAC.
    if challenge.gateway_peer_mac != *peer {
        return Err(SigilError::MalformedFrame);
    }
    crate::core::session::validate_static_public_key_encoding(&challenge.gateway_static_pubkey)?;
    if stores.sessions.is_full() && stores.sessions.get(peer).is_none() {
        return Err(SigilError::SessionTableFull);
    }

    // The tagged state both gates the step and carries the stashed initiator
    // nonce needed for the HKDF info and the challenge signature transcript.
    let sensor_nonce = match stores
        .pending
        .get(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?
        .state()
    {
        PendingState::InstallSensorAwaitChallenge { sensor_nonce } => *sensor_nonce.as_array(),
        _ => return Err(SigilError::InvalidStep { peer: *peer }),
    };
    let local = *stores.local_mac;

    // Factory attestation: cert binds gateway PeerId ‖ pubkey.

    let cert_msg = crate::core::install::factory_cert_message(
        crate::core::install::FACTORY_PRODUCT_ID_GATEWAY,
        FactoryCertificateMetadata {
            hardware_profile_id: challenge.hardware_profile_id,
            factory_key_id: challenge.factory_key_id,
        },
        &challenge.gateway_peer_mac,
        &challenge.gateway_static_pubkey,
    )?;
    se.verify_ecdsa(
        stores.factory_pubkey,
        &cert_msg,
        &challenge.factory_cert_sig,
    )
    .map_err(|_| SigilError::VerificationFailed)?;

    // Verify the gateway signature over
    // (frame_type ‖ gateway_mac ‖ pubkey ‖ nonce ‖ key_expire).
    let signed = crate::core::install::install_challenge_sign_message(
        &local,
        &sensor_nonce,
        &challenge.gateway_peer_mac,
        FactoryCertificateMetadata {
            hardware_profile_id: challenge.hardware_profile_id,
            factory_key_id: challenge.factory_key_id,
        },
        &challenge.gateway_static_pubkey,
        &challenge.gateway_nonce,
        challenge.key_lifetime_secs,
    )?;

    se.verify_ecdsa(
        &challenge.gateway_static_pubkey,
        &signed,
        &challenge.gateway_signature,
    )
    .map_err(|_| SigilError::VerificationFailed)?;

    // refuse past / over-long expiry from the gateway challenge.

    crate::core::session::validate_key_lifetime(challenge.key_lifetime_secs)?;

    // ECDH(static_priv, gateway_static_pub) → shared secret (ZeroizeOnDrop).

    let shared = crate::core::secret::validated_ecdh_shared_secret(
        se.ecdh(&challenge.gateway_static_pubkey)?,
    )?;

    // Derive directional AEAD material with both handshake nonces in HKDF info.
    let info = crate::core::install::install_hkdf_info(&sensor_nonce, &challenge.gateway_nonce)?;
    let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
    let resume_psk = crate::core::resume::wire::derive_resume_psk(
        shared.as_array(),
        &sensor_nonce,
        &challenge.gateway_nonce,
    )?;
    drop(shared);

    // Build confirm **before** staging.

    let confirm_message = crate::core::install::install_confirm_sign_message(
        &local,
        &sensor_nonce,
        &challenge.gateway_peer_mac,
        &challenge.gateway_nonce,
        challenge.key_lifetime_secs,
    )?;
    let confirm_signature: EcdsaSig = se.sign_ecdsa(&confirm_message)?;

    let cfm = InstallConfirm {
        sensor_peer_mac: local,
        confirm_signature,
    };
    let confirm_packet = build_install_confirm(&cfm)?;
    let mut out: heapless::Vec<u8, MSG> = heapless::Vec::new();
    out.extend_from_slice(&confirm_packet)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;

    // Stage keys + resume PSK + peer pubkey via the checked transition; no
    // session insert yet. Swapping the variant atomically wipes the stashed
    // initiator nonce, stages the new secrets, caches the Final frame, and
    // refreshes the deadline — fail-atomic on any error.
    let pending = stores
        .pending
        .get_mut(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    pending.install_sensor_stage_final(
        material,
        resume_psk,
        challenge.gateway_static_pubkey,
        challenge.key_lifetime_secs,
        &out,
        now,
    )?;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: out,
        wait_timeout_ms: Some(INSTALL_TIMEOUT_MS),
    })
}

/// Handles `InstallCommitConfirmed`: verify staged keys, insert session, persist.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_install_commit_confirmed<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // The tagged FinalSent recovery state carries exactly the staged commit
    // material; any other state fails closed with InvalidStep.
    let (material, resume_psk, gateway_pubkey, key_lifetime_secs) = match stores
        .pending
        .get(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?
        .state()
    {
        PendingState::InstallSensorFinalSent {
            keys,
            resume_psk,
            gateway_static_pubkey,
            key_lifetime_secs,
            ..
        } => (
            keys.clone(),
            *resume_psk.as_array(),
            *gateway_static_pubkey,
            *key_lifetime_secs,
        ),
        _ => return Err(SigilError::InvalidStep { peer: *peer }),
    };

    aead::verify_commit_confirmed(
        frame,
        FrameType::InstallCommitConfirmed,
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

    let key_expire_at = crate::core::session::expire_from_lifetime(now, key_lifetime_secs)?;
    let session = Session::new_active(
        *peer,
        gateway_pubkey,
        material,
        SessionRole::Sensor,
        resume_psk,
        key_expire_at,
        now,
    )?;
    // CommitConfirmed used g2s counter 0; install Final was clear-text (no s2g TX).
    let mut session = session;
    session.rx_counter = 1;
    stores.sessions.insert(session)?;
    let _ = stores.pending.remove(peer);

    Ok(SigilAction::PersistPeerStaticKey {
        peer: *peer,
        pubkey: gateway_pubkey,
        resume_psk: crate::core::event::ResumePskSecret::new(resume_psk),
        transmit: heapless::Vec::new(),
        wait_timeout_ms: None,
    })
}

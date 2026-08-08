//! Gateway-side installation implementation
//!
//! Implements the gateway steps of the install handshake (4-message):
//! 1. On receiving an `InstallRequest`, apply **library DoS guards** (pending /
//!    capacity / cooldown) **before** any secure-element work; then verify the
//!    sensor factory certificate, verify the sensor device signature, perform
//!    ECDH, derive the session key, build the `InstallChallenge`, and store the
//!    pending handshake awaiting confirm.
//! 2. On receiving an `InstallConfirm` (Final), verify the confirm signature
//!    over the stashed `gateway_nonce`, **commit** the session, emit
//!    [`SigilAction::PersistPeerStaticKey`] with CommitConfirmed follow-up TX,
//!    and keep pending at `InstallCommitSent` for idempotent reTX.
//!
//! Sessions are keyed by the **sensor** MAC (`sensor_peer_mac`).
//!
//! MAC allowlisting remains a host policy decision, but **rate-limiting and
//! pending/capacity checks are enforced inside the library** so SE-ECDH cannot
//! be amplified by RF floods of factory-valid requests.
//!
//! # Host scheduling
//!
//! This handler chains several SE operations in one call. Gateway hosts should
//! budget wall time accordingly. On **sensors**, sensing IRQs (door / vibration)
//! remain higher priority than install — see [`crate::core::traits::SecureElement`].

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::FrameType;
use crate::core::install::INSTALL_TIMEOUT_MS;
use crate::core::install::wire::{
    EcdsaSig, InstallChallenge, build_install_challenge, parse_install_confirm,
    parse_install_request,
};
use crate::core::manager::SessionManager;
use crate::core::pending::{HandshakeRole, HandshakeStep, PendingHandshake};
use crate::core::session::{Session, SessionRole};
use crate::core::traits::{FactoryCertificateMetadata, RandomSource, SecureElement};

/// Processes an install request packet on the gateway side.
/// Cheap DoS guards run before SE work; the per-peer cooldown is stamped after
/// factory verification binds the claimed identity and before device-signature,
/// ECDH, or signing work:
/// - existing pending → [`SigilError::PendingAlreadyExists`]
/// - no pending slot / cooldown table full → [`SigilError::CapacityExceeded`]
/// - within [`crate::core::install::INSTALL_REQUEST_COOLDOWN`] → [`SigilError::RateLimited`]
///
/// # Arguments
/// * `now` - Current host time in **seconds** (cooldown)
/// * `key_lifetime_secs` - Authenticated session-key duration in seconds.
///   Each peer applies it to its local clock. Not the handshake timeout
///   ([`INSTALL_TIMEOUT_MS`](crate::core::install::INSTALL_TIMEOUT_MS), ms).
pub(crate) fn handle_install_request<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    crate::core::session::validate_key_lifetime(key_lifetime_secs)?;

    let req = parse_install_request(packet).ok_or(SigilError::ParseError)?;
    let peer = req.sensor_peer_mac;

    // Outer header MAC must match the body sensor MAC (sender identity).
    if !crate::core::install::outer_peer_matches_body(packet, &peer) {
        return Err(SigilError::ParseError);
    }

    // --- Cheap library DoS guards (before any SE work) ---
    let replacing_stale_commit = manager.get_pending(&peer).is_some_and(|pending| {
        pending.step == HandshakeStep::InstallCommitSent && pending.role == HandshakeRole::Gateway
    });
    if manager.get_pending(&peer).is_some() && !replacing_stale_commit {
        return Err(SigilError::PendingAlreadyExists { peer });
    }
    if manager.is_full() && manager.get(&peer).is_none() {
        return Err(SigilError::CapacityExceeded);
    }
    if !manager.pending_slot_available(&peer) {
        return Err(SigilError::CapacityExceeded);
    }
    if !manager.install_cooldown_elapsed(&peer, now) {
        return Err(SigilError::RateLimited { peer });
    }
    // purge-aware capacity check.
    if manager.install_last_at_full_for(&peer, now) {
        return Err(SigilError::CapacityExceeded);
    }
    // Factory attestation: cert binds PeerId ‖ pubkey.
    let cert_msg = crate::core::install::factory_cert_message(
        crate::core::install::FACTORY_PRODUCT_ID_SENSOR,
        FactoryCertificateMetadata {
            hardware_profile_id: req.hardware_profile_id,
            factory_key_id: req.factory_key_id,
        },
        &peer,
        &req.sensor_static_pubkey,
    )?;
    se.verify_ecdsa(manager.factory_pubkey(), &cert_msg, &req.factory_cert_sig)
        .map_err(|_| SigilError::VerificationFailed)?;

    // Stamp only after the factory certificate binds the claimed PeerId.
    // Otherwise an unauthenticated packet can poison a legitimate device's
    // per-peer cooldown. This remains before device-signature and ECDH work.
    manager.mark_install_request(peer, now)?;

    // Verify the domain-separated wire-v3 sensor request proof.
    let signed = crate::core::install::install_request_sign_message(
        &peer,
        FactoryCertificateMetadata {
            hardware_profile_id: req.hardware_profile_id,
            factory_key_id: req.factory_key_id,
        },
        &req.sensor_static_pubkey,
        &req.sensor_nonce,
    )?;
    se.verify_ecdsa(&req.sensor_static_pubkey, &signed, &req.sensor_signature)
        .map_err(|_| SigilError::VerificationFailed)?;
    // Gateway identity material for the challenge — generate nonce BEFORE
    // HKDF so both handshake nonces are mixed into the session key.
    let gateway_static_pubkey = se.get_static_pubkey()?;
    let factory_cert_sig = se.get_factory_cert()?;
    let factory_metadata = se.get_factory_cert_metadata()?;
    let mut gateway_nonce = [0u8; 16];
    rng.fill_bytes(&mut gateway_nonce)?;

    // ECDH(static_priv, sensor_static_pub) then HKDF with both nonces.
    // wrap so Drop zeroizes even if HKDF / resume_psk `?` fails.
    let shared = crate::core::secret::SharedSecretBuf::new(se.ecdh(&req.sensor_static_pubkey)?);
    let info = crate::core::install::install_hkdf_info(&req.sensor_nonce, &gateway_nonce)?;
    let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
    let resume_psk = crate::core::resume::wire::derive_resume_psk(
        shared.as_array(),
        &req.sensor_nonce,
        &gateway_nonce,
    )?;
    drop(shared);

    let local = *manager.local_mac();

    // Sign (frame_type ‖ gateway_mac ‖ pubkey ‖ nonce ‖ key_expire).
    let to_sign = crate::core::install::install_challenge_sign_message(
        &peer,
        &req.sensor_nonce,
        &local,
        factory_metadata,
        &gateway_static_pubkey,
        &gateway_nonce,
        key_lifetime_secs,
    )?;
    let gateway_signature: EcdsaSig = se.sign_ecdsa(&to_sign)?;

    let challenge = InstallChallenge {
        gateway_peer_mac: local,
        hardware_profile_id: factory_metadata.hardware_profile_id,
        factory_key_id: factory_metadata.factory_key_id,
        gateway_static_pubkey,
        factory_cert_sig,
        gateway_nonce,
        key_lifetime_secs,
        gateway_signature,
    };

    // Build wire frame before committing pending / cooldown (fail closed).
    let packet = build_install_challenge(&challenge)?;
    let mut out: heapless::Vec<u8, MSG> = heapless::Vec::new();
    out.extend_from_slice(&packet)
        .map_err(|_| SigilError::CapacityExceeded)?;

    let mut pending = PendingHandshake::new_install(
        peer,
        HandshakeRole::Gateway,
        crate::core::install::INSTALL_TIMEOUT_MS,
        now,
    );
    pending.update_step(HandshakeStep::InstallWaitingForConfirm);
    pending.set_directional_keys(material);
    pending.resume_psk = Some(resume_psk);
    pending.transcript_pubkey = Some(req.sensor_static_pubkey);
    pending.transcript_expire = Some(key_lifetime_secs);
    pending.transcript_challenge_nonce = Some(gateway_nonce);
    pending.transcript_initiator_nonce = Some(req.sensor_nonce);
    // Keep the cached CommitConfirmed recoverable until all verification,
    // ATECC work, RNG, derivation, signing and frame building have succeeded.
    if replacing_stale_commit {
        let _ = manager.remove_pending(&peer);
    }
    manager.insert_pending(peer, pending)?;

    Ok(SigilAction::Transmit {
        dest: peer,
        payload: out,
        wait_timeout_ms: Some(crate::core::install::INSTALL_TIMEOUT_MS),
    })
}

/// Processes an install confirm (Final) packet on the gateway side.
/// Verifies the sensor's confirm signature, commits the session, builds
/// CommitConfirmed, caches it, and returns PersistPeerStaticKey with follow-up TX.
/// Duplicate Final while CommitSent retransmits cached CommitConfirmed.
pub(crate) fn handle_install_confirm<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let cfm = parse_install_confirm(packet).ok_or(SigilError::ParseError)?;
    let peer = cfm.sensor_peer_mac;

    if !crate::core::install::outer_peer_matches_body(packet, &peer) {
        return Err(SigilError::ParseError);
    }

    let pending = manager
        .get_pending(&peer)
        .ok_or(SigilError::NoPending { peer })?;

    if pending.step == HandshakeStep::InstallCommitSent {
        return retransmit_cached_persist::<N, MSG>(manager, &peer);
    }

    if pending.step != HandshakeStep::InstallWaitingForConfirm {
        return Err(SigilError::InvalidStep { peer });
    }

    let sensor_pubkey = pending.transcript_pubkey.ok_or(SigilError::ParseError)?;
    let gateway_nonce = pending
        .transcript_challenge_nonce
        .ok_or(SigilError::ParseError)?;
    let sensor_nonce = pending
        .transcript_initiator_nonce
        .ok_or(SigilError::ParseError)?;
    let key_lifetime_secs = pending.transcript_expire.ok_or(SigilError::ParseError)?;
    let confirm_message = crate::core::install::install_confirm_sign_message(
        &peer,
        &sensor_nonce,
        manager.local_mac(),
        &gateway_nonce,
        key_lifetime_secs,
    )?;
    se.verify_ecdsa(&sensor_pubkey, &confirm_message, &cfm.confirm_signature)
        .map_err(|_| SigilError::VerificationFailed)?;

    let material = pending
        .directional_keys()
        .ok_or(SigilError::ParseError)?
        .clone();
    let resume_psk = pending.resume_psk.ok_or(SigilError::ParseError)?;

    let local = *manager.local_mac();
    let commit_frame = aead::build_commit_confirmed_frame::<MSG>(
        &local,
        FrameType::InstallCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
        0,
    )?;

    let key_expire_at = crate::core::session::expire_from_lifetime(now, key_lifetime_secs)?;
    let session = Session::new_active(
        peer,
        sensor_pubkey,
        material,
        SessionRole::Gateway,
        resume_psk,
        key_expire_at,
        now,
    )?;
    // CommitConfirmed used g2s counter 0; install Final was clear-text.
    let mut session = session;
    session.tx_counter = 1;
    // Insert/replace session **without** `remove()` — that would also clear
    // pending (needed for CommitSent idempotent reTX).
    manager.insert(session)?;

    let pending = manager
        .get_pending_mut(&peer)
        .ok_or(SigilError::NoPending { peer })?;
    if let Some(mut secrets) = pending.secrets.take() {
        secrets.zeroize();
    }
    if let Some(mut psk) = pending.resume_psk.take() {
        use zeroize::Zeroize;
        psk.zeroize();
    }
    pending.set_cached_wire(&commit_frame)?;
    pending.update_step(HandshakeStep::InstallCommitSent);
    pending.update_timeout(INSTALL_TIMEOUT_MS, now);

    Ok(SigilAction::PersistPeerStaticKey {
        peer,
        pubkey: sensor_pubkey,
        resume_psk,
        transmit: commit_frame,
        wait_timeout_ms: Some(INSTALL_TIMEOUT_MS),
    })
}

/// Retransmits cached CommitConfirmed wrapped as PersistPeerStaticKey follow-up
/// (no re-persist of already-durable enrollment — host may ignore duplicate persist).
fn retransmit_cached_persist<const N: usize, const MSG: usize>(
    manager: &SessionManager<N>,
    peer: &crate::core::session::PeerId,
) -> Result<SigilAction<MSG>, SigilError> {
    let pending = manager
        .get_pending(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    let cached = pending
        .cached_wire
        .as_ref()
        .ok_or(SigilError::InvalidHandshakeState)?;
    let session = manager
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    let pubkey = session.peer_static_pubkey;
    let resume_psk = session.require_resume_psk()?;
    let mut transmit: heapless::Vec<u8, MSG> = heapless::Vec::new();
    transmit
        .extend_from_slice(cached)
        .map_err(|_| SigilError::CapacityExceeded)?;
    Ok(SigilAction::PersistPeerStaticKey {
        peer: *peer,
        pubkey,
        resume_psk,
        transmit,
        wait_timeout_ms: Some(INSTALL_TIMEOUT_MS),
    })
}

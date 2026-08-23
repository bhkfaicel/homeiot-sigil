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
use crate::core::manager::{HandshakeKind, ProtocolStores};
use crate::core::pending::{InstallGatewayStaged, PendingHandshake, PendingState};
use crate::core::session::{Session, SessionRole};
use crate::core::traits::{FactoryCertificateMetadata, RandomSource, SecureElement};

/// Processes an install request packet on the gateway side.
/// Cheap DoS guards run before SE work; the per-peer cooldown is stamped only
/// after both the factory certificate and the sensor's dynamic request
/// signature authenticate the claimed identity, but before ECDH or signing:
/// - existing pending → [`SigilError::PendingAlreadyExists`]
/// - session table full for a new peer → [`SigilError::SessionTableFull`]
/// - no pending slot → [`SigilError::PendingTableFull`]
/// - cooldown table full → [`SigilError::AdmissionTableFull`]
/// - within [`crate::core::install::INSTALL_REQUEST_COOLDOWN`] → [`SigilError::RateLimited`]
///
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
///
/// # Arguments
/// * `now` - Current host time in **seconds** (cooldown)
/// * `key_lifetime_secs` - Authenticated session-key duration in seconds.
///   Each peer applies it to its local clock. Not the handshake timeout
///   ([`INSTALL_TIMEOUT_MS`](crate::core::install::INSTALL_TIMEOUT_MS), ms).
pub(crate) fn handle_install_request<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    crate::core::session::validate_key_lifetime(key_lifetime_secs)?;

    let req = parse_install_request(packet).ok_or(SigilError::MalformedFrame)?;
    let peer = req.sensor_peer_mac;

    // Outer header MAC must match the body sensor MAC (sender identity).
    if !crate::core::install::outer_peer_matches_body(packet, &peer) {
        return Err(SigilError::MalformedFrame);
    }
    crate::core::session::validate_static_public_key_encoding(&req.sensor_static_pubkey)?;

    // --- Cheap library DoS guards (before any SE work) ---
    // A stale install recovery state (cached CommitConfirmed the sensor never
    // acknowledged) may be replaced by a fresh authenticated request; every
    // other pending for this peer blocks a new handshake.
    let replacing_stale_commit = stores.pending.get(&peer).is_some_and(|pending| {
        matches!(
            pending.state(),
            PendingState::InstallGatewayCommitSent { .. }
        )
    });
    if stores.pending.get(&peer).is_some() && !replacing_stale_commit {
        return Err(SigilError::PendingAlreadyExists { peer });
    }
    if stores.sessions.is_full() && stores.sessions.get(&peer).is_none() {
        return Err(SigilError::SessionTableFull);
    }
    if !stores.pending.slot_available(&peer) {
        return Err(SigilError::PendingTableFull);
    }
    // Single-scan admission decision (cooldown window first, then
    // post-purge capacity — the documented guard order). The one O(C)
    // cooldown-table purge of this request happens here; unauthenticated
    // senders can trigger only that expired-entry reclamation.
    stores.admission.admit_install(&peer, now)?;

    // Replay defense (runs BEFORE the first cryptographic operation): purge
    // strictly-expired entries (the only permitted pre-authentication cache
    // effect — expired stamps form a ring prefix), then exact-triple lookup
    // over the live remainder. A hit is a re-delivery of a triple this
    // handler already authenticated to successful completion within the
    // replay horizon; it costs zero SE/HKDF work and mutates nothing.
    stores.replay_cache.prefix_purge(now);
    if stores
        .replay_cache
        .contains(HandshakeKind::Install, &peer, &req.sensor_nonce)
    {
        return Err(SigilError::HandshakeReplay { peer });
    }
    // Fail-closed bounded refusal: a full cache of live entries rejects the
    // fresh initiator here instead of evicting any entry. Recovery flows
    // through TTL expiry once filling pressure stops.
    if stores.replay_cache.is_full() {
        return Err(SigilError::ReplayCacheFull { peer });
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
    se.verify_ecdsa(stores.factory_pubkey, &cert_msg, &req.factory_cert_sig)
        .map_err(|_| SigilError::VerificationFailed)?;

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

    // Stamp only after the dynamic request proof authenticates possession of
    // the factory-certified device key. A certificate is public wire data and
    // is not sufficient by itself to let a sender consume this peer's
    // cooldown. Keep the stamp before ECDH and gateway signing so authenticated
    // request replays still cannot amplify the more expensive work. The stamp
    // performs no scan: the decide phase above already purged expired entries
    // and reserved this peer's slot in the same single-threaded call.
    stores.admission.stamp_install_request(peer, now)?;

    // Gateway identity material for the challenge — generate nonce BEFORE
    // HKDF so both handshake nonces are mixed into the session key.
    let gateway_static_pubkey = se.get_static_pubkey()?;
    crate::core::session::validate_static_public_key_encoding(&gateway_static_pubkey)?;
    let factory_cert_sig = se.get_factory_cert()?;
    let factory_metadata = se.get_factory_cert_metadata()?;
    let mut gateway_nonce = [0u8; 16];
    rng.fill_bytes(&mut gateway_nonce)?;

    // ECDH(static_priv, sensor_static_pub) then HKDF with both nonces.
    // wrap so Drop zeroizes even if HKDF / resume_psk `?` fails.
    let shared =
        crate::core::secret::validated_ecdh_shared_secret(se.ecdh(&req.sensor_static_pubkey)?)?;
    let info = crate::core::install::install_hkdf_info(&req.sensor_nonce, &gateway_nonce)?;
    let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
    let resume_psk = crate::core::resume::wire::derive_resume_psk(
        shared.as_array(),
        &req.sensor_nonce,
        &gateway_nonce,
    )?;
    drop(shared);

    let local = *stores.local_mac;

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
        .map_err(|_| SigilError::OutputBufferTooSmall)?;

    // The tagged gateway state carries every field needed to verify the
    // sensor Final and commit the session. Building the whole struct first
    // keeps the pending table untouched until all SE work succeeded.
    let staged = InstallGatewayStaged {
        keys: material,
        resume_psk: crate::core::pending::ResumePskStash::new(resume_psk),
        sensor_static_pubkey: req.sensor_static_pubkey,
        key_lifetime_secs,
        gateway_nonce: crate::core::pending::Nonce16Stash::new(gateway_nonce),
        sensor_nonce: crate::core::pending::Nonce16Stash::new(req.sensor_nonce),
    };
    let pending = PendingHandshake::new_install_gateway_await_confirm(
        peer,
        staged,
        crate::core::install::INSTALL_TIMEOUT_MS,
        now,
    );
    // Keep the cached CommitConfirmed recoverable until all verification,
    // ATECC work, RNG, derivation, signing and frame building have succeeded.
    if replacing_stale_commit {
        let _ = stores.pending.remove(&peer);
    }
    stores.pending.insert(peer, pending)?;

    // Success-only cache insertion — the FINAL mutation of this invocation,
    // after the fail-atomic pending commit and immediately before returning
    // Transmit. Every error return above therefore leaves the cache
    // byte-identical: a failed handshake writes no triple, so no legitimate
    // retry is ever denied `HandshakeReplay` by its own earlier failure.
    stores
        .replay_cache
        .insert(HandshakeKind::Install, peer, &req.sensor_nonce, now)?;

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
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_install_confirm<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let cfm = parse_install_confirm(packet).ok_or(SigilError::MalformedFrame)?;
    let peer = cfm.sensor_peer_mac;

    if !crate::core::install::outer_peer_matches_body(packet, &peer) {
        return Err(SigilError::MalformedFrame);
    }

    // Extract every commit input from the tagged state while the pending
    // borrow is immutable; the clone ends the borrow before mutations.
    // The durable-PSK copy is wrapped in its zeroizing carrier immediately so
    // every fallible step below (signature verify, commit-frame build, session
    // insert, recovery transition) wipes it on any error path instead of
    // leaving a plain stack copy behind.
    let (sensor_pubkey, gateway_nonce, sensor_nonce, key_lifetime_secs, material, resume_psk) = {
        let pending = stores
            .pending
            .get(&peer)
            .ok_or(SigilError::NoPending { peer })?;
        match pending.state() {
            PendingState::InstallGatewayCommitSent { .. } => {
                // Duplicate Final after commit → idempotent reTX below.
                return retransmit_cached_persist::<N, MSG>(stores, &peer);
            }
            PendingState::InstallGatewayAwaitConfirm(staged) => (
                staged.sensor_static_pubkey,
                *staged.gateway_nonce.as_array(),
                *staged.sensor_nonce.as_array(),
                staged.key_lifetime_secs,
                staged.keys.clone(),
                crate::core::event::ResumePskSecret::new(*staged.resume_psk.as_array()),
            ),
            _ => return Err(SigilError::InvalidStep { peer }),
        }
    };
    let confirm_message = crate::core::install::install_confirm_sign_message(
        &peer,
        &sensor_nonce,
        stores.local_mac,
        &gateway_nonce,
        key_lifetime_secs,
    )?;
    se.verify_ecdsa(&sensor_pubkey, &confirm_message, &cfm.confirm_signature)
        .map_err(|_| SigilError::VerificationFailed)?;

    let local = *stores.local_mac;
    let commit_frame = aead::build_commit_confirmed_frame::<MSG>(
        &local,
        FrameType::InstallCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
        0,
    )?;

    let key_expire_at = crate::core::session::expire_from_lifetime(now, key_lifetime_secs)?;
    // Borrow-only hand-off: the constructor validates through the carrier and
    // copies into the session-owned field itself, so this handler never
    // unwraps a plain copy; `resume_psk` stays owned here for the persist
    // action below and wipes if any remaining step fails.
    let session = Session::new_active(
        peer,
        sensor_pubkey,
        material,
        SessionRole::Gateway,
        resume_psk.expose_secret(),
        key_expire_at,
        now,
    )?;
    // CommitConfirmed used g2s counter 0; install Final was clear-text.
    let mut session = session;
    session.tx_counter = 1;
    // Insert/replace session **without** `remove()` — that would also clear
    // pending (needed for CommitSent idempotent reTX).
    stores.sessions.insert(session)?;

    // Checked transition to the recovery state: swapping the variant consumes
    // (zeroizes) the staged keys, PSK, and nonces by construction while
    // keeping the cached CommitConfirmed for idempotent retransmission.
    let pending = stores
        .pending
        .get_mut(&peer)
        .ok_or(SigilError::NoPending { peer })?;
    pending.install_gateway_commit_sent(&commit_frame, now)?;

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
    stores: &ProtocolStores<'_, N>,
    peer: &crate::core::session::PeerId,
) -> Result<SigilAction<MSG>, SigilError> {
    let pending = stores
        .pending
        .get(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    // The cached CommitConfirmed lives only in the tagged recovery variant.
    let cached = match pending.state() {
        PendingState::InstallGatewayCommitSent { cached } => cached.as_slice(),
        _ => return Err(SigilError::InvariantViolation),
    };
    let session = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    let pubkey = *session.peer_static_pubkey();
    let resume_psk = session.require_resume_psk()?;
    let mut transmit: heapless::Vec<u8, MSG> = heapless::Vec::new();
    transmit
        .extend_from_slice(cached)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(SigilAction::PersistPeerStaticKey {
        peer: *peer,
        pubkey,
        resume_psk: crate::core::event::ResumePskSecret::new(*resume_psk),
        transmit,
        wait_timeout_ms: Some(INSTALL_TIMEOUT_MS),
    })
}

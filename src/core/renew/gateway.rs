//! Gateway side of Renew P-256.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::FrameType;
use crate::core::manager::ProtocolStores;
use crate::core::pending::{PendingHandshake, PendingState};
use crate::core::renew::RENEW_TIMEOUT_MS;
use crate::core::renew::wire::{
    build_renew_challenge_body, parse_renew_confirm_body, parse_renew_request_body,
};
use crate::core::session::{PeerId, SessionRole};
use crate::core::traits::{RandomSource, SecureElement};
use subtle::ConstantTimeEq;

/// Authenticates an empty request under the old key, asks the host backend for
/// a P-256 keypair and returns the Challenge under the old key.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_renew_request<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    crate::core::session::validate_key_lifetime(key_lifetime_secs)?;
    if stores.pending.get(peer).is_some() {
        return Err(SigilError::PendingAlreadyExists { peer: *peer });
    }
    if !stores.pending.slot_available(peer) {
        return Err(SigilError::PendingTableFull);
    }

    let (old_tx_key, old_tx_prefix, challenge_counter, new_rx) = {
        let session = stores
            .sessions
            .get_mut(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
        if session.role() != SessionRole::Gateway {
            return Err(SigilError::WrongRole { peer: *peer });
        }
        if !session.is_active(now) {
            return Err(SigilError::SessionExpired { peer: *peer });
        }
        let (rx_key, rx_prefix) = session.require_rx_material(peer)?;
        let opened = aead::open_frame::<{ aead::HANDSHAKE_PLAINTEXT_CAP }>(
            peer,
            FrameType::RenewRequest,
            frame,
            rx_key,
            rx_prefix,
            aead::RxCounterPolicy::Window {
                current: session.rx_counter,
            },
        )?;
        if !parse_renew_request_body(&opened.plaintext) {
            return Err(SigilError::MalformedFrame);
        }
        let (tx_key, tx_prefix) = session.require_tx_material(peer)?;
        (
            crate::core::secret::SharedSecretBuf::new(*tx_key),
            crate::core::secret::NoncePrefixBuf::new(*tx_prefix),
            session.tx_counter,
            opened.next_rx_counter,
        )
    };

    let (gateway_public_key, gateway_context) = se.generate_ephemeral_p256_keypair(rng)?;
    crate::core::session::validate_static_public_key_encoding(&gateway_public_key)?;
    let challenge_body = build_renew_challenge_body(&gateway_public_key, key_lifetime_secs)?;
    let next_tx = aead::check_tx_counter(challenge_counter)
        .map_err(|_| SigilError::CounterExhausted { peer: *peer })?;
    let local = *stores.local_mac;
    let mut challenge_frame = heapless::Vec::new();
    challenge_frame
        .extend_from_slice(&crate::core::frame::build_header(
            &local,
            FrameType::RenewChallenge,
        ))
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    challenge_frame
        .extend_from_slice(old_tx_prefix.as_array())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    challenge_frame
        .extend_from_slice(&challenge_counter.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    aead::encrypt_append(
        old_tx_key.as_array(),
        old_tx_prefix.as_array(),
        challenge_counter,
        &challenge_body,
        &aead::build_aad(&local, FrameType::RenewChallenge),
        &mut challenge_frame,
    )?;

    // The tagged gateway state carries the backend P-256 context, the
    // challenge public key, and the agreed lifetime until the sensor Final
    // arrives. The challenge frame itself is not cached: only the post-commit
    // state owns a retransmittable frame.
    let pending = PendingHandshake::new_renew_gateway_await_confirm(
        *peer,
        gateway_context,
        gateway_public_key,
        key_lifetime_secs,
        RENEW_TIMEOUT_MS,
        now,
    );
    // Gateway TX advance happens only after the challenge encrypt **and**
    // the pending insert both succeeded (no counter rollback on failure).
    stores.pending.insert(*peer, pending)?;
    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    session.rx_counter = new_rx;
    session.tx_counter = next_tx;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: challenge_frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

/// Validates RenewConfirm under the old key, derives the candidate material,
/// checks the sensor proof in constant time and only then commits.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_renew_confirm<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // Extract the renewal inputs from the tagged state while the pending
    // borrow is immutable; the clone/copy ends the borrow before mutations.
    // A duplicate Final after commit retransmits the cached CommitConfirmed.
    let (gateway_context, gateway_public_key, lifetime) = {
        let pending = stores
            .pending
            .get(peer)
            .ok_or(SigilError::NoPending { peer: *peer })?;
        match pending.state() {
            PendingState::RenewGatewayCommitSent { .. } => {
                // Duplicate Final after commit → idempotent reTX below.
                return retransmit_cached(stores, peer, RENEW_TIMEOUT_MS);
            }
            PendingState::RenewGatewayAwaitConfirm {
                p256_context,
                gateway_ephemeral_pubkey,
                key_lifetime_secs,
            } => (
                crate::core::secret::SharedSecretBuf::new(*p256_context.as_array()),
                *gateway_ephemeral_pubkey,
                *key_lifetime_secs,
            ),
            _ => return Err(SigilError::InvalidStep { peer: *peer }),
        }
    };

    let confirm = {
        let session = stores
            .sessions
            .get(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
        let (rx_key, rx_prefix) = session.require_rx_material(peer)?;
        let opened = aead::open_frame::<{ aead::HANDSHAKE_PLAINTEXT_CAP }>(
            peer,
            FrameType::RenewConfirm,
            frame,
            rx_key,
            rx_prefix,
            aead::RxCounterPolicy::Window {
                current: session.rx_counter,
            },
        )?;
        parse_renew_confirm_body(&opened.plaintext).ok_or(SigilError::MalformedFrame)?
    };

    let shared =
        crate::core::secret::validated_ecdh_shared_secret(se.complete_ephemeral_p256_ecdh(
            gateway_context.as_array(),
            &confirm.sensor_ephemeral_pubkey,
        )?)?;
    let transcript = crate::core::renew::renew_hkdf_info(
        peer,
        &confirm.sensor_ephemeral_pubkey,
        &gateway_public_key,
        lifetime,
    )?;
    let material = derive_directional_session_keys(shared.as_array(), Some(&transcript))?;
    drop(shared);
    let expected_proof = crate::core::renew::renew_sensor_proof(&material.s2g_key, &transcript)?;
    if expected_proof.ct_eq(&confirm.proof).unwrap_u8() != 1 {
        return Err(SigilError::VerificationFailed);
    }

    let local = *stores.local_mac;
    let commit_frame = aead::build_commit_confirmed_frame::<MSG>(
        &local,
        FrameType::RenewCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
        0,
    )?;
    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    let expire = crate::core::session::expire_from_lifetime(now, lifetime)?;
    session.update_key(material, expire, now)?;
    // Confirm consumed only an old-key counter. CommitConfirmed consumes new
    // g2s counter 0; no new s2g frame has been received yet.
    session.rx_counter = 0;
    session.tx_counter = 1;

    // Checked transition to the recovery state: swapping the variant consumes
    // (zeroizes) the backend P-256 provider context by construction while
    // keeping the cached CommitConfirmed for idempotent retransmission.
    let pending = stores
        .pending
        .get_mut(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    pending.renew_gateway_commit_sent(&commit_frame, now)?;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: commit_frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

pub(crate) fn retransmit_cached<const N: usize, const MSG: usize>(
    stores: &ProtocolStores<'_, N>,
    peer: &PeerId,
    timeout_ms: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let cached = stores
        .pending
        .get(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?
        .state()
        .cached_retransmission_frame()
        .ok_or(SigilError::InvariantViolation)?;
    let mut payload = heapless::Vec::new();
    payload
        .extend_from_slice(cached)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(SigilAction::Transmit {
        dest: *peer,
        payload,
        wait_timeout_ms: Some(timeout_ms),
    })
}

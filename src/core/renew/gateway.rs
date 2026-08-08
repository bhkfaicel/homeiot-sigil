//! Gateway-side renew implementation
//!
//! Implements the gateway steps of the renew handshake (4-message).
//! The gateway only **responds** — there is no `start_renew` on the gateway side.
//!
//! Outer headers carry **local_mac** (gateway). HKDF binds the **sensor** MAC
//! (`peer` session key). Ephemeral scalars are zeroized after ECDH.
//!
//! Decrypt uses RX (sensor→gateway half); challenge encrypt uses TX
//! (gateway→sensor half). The ack (Final) is decrypted under the **new** s2g
//! half; CommitConfirmed is encrypted under the **new** g2s half.
//!
//! # TX counter ordering
//!
//! The challenge is encrypted and pending inserted **before** advancing
//! `tx_counter`, so a capacity failure does not burn a nonce without emitting
//! a challenge.
//!
//! # Commit
//!
//! On valid Final (`RenewAck`) the gateway commits (`update_key`), builds
//! `RenewCommitConfirmed`, caches it, and keeps pending at `RenewCommitSent`
//! for idempotent reTX of a duplicate ack.

use crate::core::aead;
use crate::core::derive::derive_directional_session_keys;
use crate::core::ecdh_soft::{
    ecdh_from_scalar, generate_ephemeral_scalar, pubkey_from_scalar, zeroize_secret,
};
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::manager::SessionManager;
use crate::core::pending::{HandshakeStep, PendingHandshake};
use crate::core::renew::RENEW_TIMEOUT_MS;
use crate::core::renew::wire::{
    build_renew_challenge_body, parse_renew_ack_body, parse_renew_request_body,
};
use crate::core::session::{PeerId, SessionRole};
use crate::core::traits::RandomSource;

/// Handles a renew request frame on the gateway side.
/// Decrypts the request, runs ECDH, derives directional keys (stored in pending),
/// and returns the encrypted `RenewChallenge` frame.
pub(crate) fn handle_renew_request<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame: &[u8],
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::{
        FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    };

 // reject past / over-long expiries before decrypt / ECDH.

    crate::core::session::validate_key_lifetime(key_lifetime_secs)?;

    let (sensor_eph_pub, old_tx_key, old_tx_prefix, challenge_counter, new_rx) = {
        let session = manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;

        // Inbound renew is a gateway-only operation. Reject a
        // misconfigured sensor manager before decrypting or advancing counters.
        if session.role() != SessionRole::Gateway {
            return Err(SigilError::InvalidStep { peer: *peer });
        }

        if !session.is_active(now) {
            return Err(SigilError::SessionExpired { peer: *peer });
        }

        if frame.len() < OUTER_HEADER_SIZE + 4 + 8 + aead::TAG_SIZE {
            return Err(SigilError::ParseError);
        }
        if frame[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
            || frame[FRAME_TYPE_OFFSET] != FrameType::RenewRequest as u8
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
        let (sensor_eph_pub, old_tx_key, old_tx_prefix, challenge_counter) = {
            // Request decrypt = RX (s2g); challenge encrypt = TX (g2s).
            let (rx_key, rx_prefix) = session.require_rx_material(peer)?;
            if wire_prefix != rx_prefix {
                return Err(SigilError::ParseError);
            }
            aead::decrypt_into(
                rx_key,
                rx_prefix,
                received_counter,
                &frame[OUTER_HEADER_SIZE + 12..],
                aead::aad_from_frame(frame).ok_or(SigilError::ParseError)?,
                &mut plaintext,
            )?;
            let sensor_eph_pub =
                parse_renew_request_body(&plaintext).ok_or(SigilError::ParseError)?;
            let challenge_counter = session.tx_counter;
            let (tx_key, tx_prefix) = session.require_tx_material(peer)?;
            // ZeroizeOnDrop copies — wiped if encrypt / ECDH / capacity fails.
            (
                sensor_eph_pub,
                crate::core::secret::SharedSecretBuf::new(*tx_key),
                crate::core::secret::NoncePrefixBuf::new(*tx_prefix),
                challenge_counter,
            )
        };
        (
            sensor_eph_pub,
            old_tx_key,
            old_tx_prefix,
            challenge_counter,
            new_rx,
        )
    };

    let mut gw_scalar = generate_ephemeral_scalar(rng)?;
    let gw_pub = pubkey_from_scalar(&gw_scalar)?;
    // Shared wiped on Drop if HKDF / frame build fails after ECDH.
    let shared =
        crate::core::secret::SharedSecretBuf::new(ecdh_from_scalar(&gw_scalar, &sensor_eph_pub)?);
    // HKDF binds the sensor MAC (session table key on the gateway).
    let info =
        crate::core::renew::renew_hkdf_info(peer, &sensor_eph_pub, &gw_pub, key_lifetime_secs)?;
    let material = derive_directional_session_keys(shared.as_array(), Some(&info))?;
    drop(shared);
    zeroize_secret(&mut gw_scalar);

    let local = *manager.local_mac();
    let challenge_body = build_renew_challenge_body(&gw_pub, key_lifetime_secs)?;
    let challenge_aad = aead::build_aad(&local, FrameType::RenewChallenge);
    let next_tx = aead::check_tx_counter(challenge_counter)
.map_err(|_| SigilError::CounterExhausted { peer: *peer })?;

    // Encrypt + stash pending **before** advancing TX.
    let mut out: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let chal_header = crate::core::frame::build_header(&local, FrameType::RenewChallenge);
    out.extend_from_slice(&chal_header)
.map_err(|_| SigilError::CapacityExceeded)?;
    out.extend_from_slice(old_tx_prefix.as_array())
.map_err(|_| SigilError::CapacityExceeded)?;
    out.extend_from_slice(&challenge_counter.to_be_bytes())
.map_err(|_| SigilError::CapacityExceeded)?;
    aead::encrypt_append(
        old_tx_key.as_array(),
        old_tx_prefix.as_array(),
        challenge_counter,
        &challenge_body,
        &challenge_aad,
        &mut out,
    )?;
    drop(old_tx_key);
    drop(old_tx_prefix);

    let mut pending = PendingHandshake::new_renew_gateway(*peer, material, RENEW_TIMEOUT_MS, now);
    pending.transcript_expire = Some(key_lifetime_secs);
    let _ = manager.remove_pending(peer);
    manager.insert_pending(*peer, pending)?;

    if let Some(s) = manager.get_mut(peer) {
        // Commit both old-key counters only after the complete challenge and
        // replacement pending state exist. A transient RNG/ECDH/capacity error
        // leaves the exact request retransmittable instead of classed replay.
        s.rx_counter = new_rx;
        s.tx_counter = next_tx;
    }

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: out,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
    })
}

/// Handles the renew ack (Final) on the gateway: decrypts under the new s2g half,
/// commits the session, sends CommitConfirmed, and keeps pending at CommitSent.
/// Duplicate Final while `RenewCommitSent` retransmits the cached CommitConfirmed
/// without re-committing.
pub(crate) fn handle_renew_ack<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::{
        FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    };

    let pending = manager
.get_pending(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;

    // Idempotent reTX of CommitConfirmed on duplicate Final.
    if pending.step == HandshakeStep::RenewCommitSent {
        return retransmit_cached(manager, peer, RENEW_TIMEOUT_MS);
    }

    if pending.step != HandshakeStep::RenewWaitingForAck {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    let material = pending
.directional_keys()
.ok_or(SigilError::ParseError)?
.clone();
    let lifetime = pending.transcript_expire.ok_or(SigilError::ParseError)?;

    // Ack is sensor→gateway traffic under the *new* s2g half.
    let ack_key = &material.s2g_key;
    let ack_prefix = &material.s2g_prefix;

    if frame.len() < OUTER_HEADER_SIZE + 4 + 8 + aead::TAG_SIZE {
        return Err(SigilError::ParseError);
    }
    if frame[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
        || frame[FRAME_TYPE_OFFSET] != FrameType::RenewAck as u8
    {
        return Err(SigilError::ParseError);
    }
    let wire_prefix: &[u8; 4] = frame[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4]
.try_into()
.map_err(|_| SigilError::ParseError)?;
    if wire_prefix != ack_prefix {
        return Err(SigilError::ParseError);
    }
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12]);
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
            ack_key,
            ack_prefix,
            0,
            &frame[OUTER_HEADER_SIZE + 12..],
            aead::aad_from_frame(frame).ok_or(SigilError::ParseError)?,
            &mut plaintext,
        )?;
        if !parse_renew_ack_body(&plaintext) {
            return Err(SigilError::VerificationFailed);
        }
    }

    let local = *manager.local_mac();
    // Build CommitConfirmed under new g2s (gateway TX) counter 0 **before**
    // mutating session, using material copies.
    let commit_frame = aead::build_commit_confirmed_frame::<MSG>(
        &local,
        FrameType::RenewCommitConfirmed,
        &material.g2s_key,
        &material.g2s_prefix,
        0,
    )?;

    let session = manager
.get_mut(peer)
.ok_or(SigilError::UnknownSession { peer: *peer })?;
    let expire = crate::core::session::expire_from_lifetime(now, lifetime)?;
    session.update_key(material, expire, now)?;
    // Final used s2g counter 0; CommitConfirmed used g2s counter 0.
    session.rx_counter = 1;
    session.tx_counter = 1;

    let pending = manager
.get_pending_mut(peer)
.ok_or(SigilError::NoPending { peer: *peer })?;
    // Directional keys already committed into the session; clear pending secrets
    // but keep cached CommitConfirmed for reTX.
    if let Some(mut secrets) = pending.secrets.take() {
        secrets.zeroize();
    }
    pending.set_cached_wire(&commit_frame)?;
    pending.update_step(HandshakeStep::RenewCommitSent);
    pending.update_timeout(RENEW_TIMEOUT_MS, now);

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: commit_frame,
        wait_timeout_ms: Some(RENEW_TIMEOUT_MS),
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

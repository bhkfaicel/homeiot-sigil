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
use crate::core::frame::{
    FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
};
use crate::core::manager::{HandshakeKind, ProtocolStores};
use crate::core::pending::{PendingHandshake, PendingState};
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
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_resume_request<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    packet: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // Reject zero / over-long lifetimes before MAC verify / SE-ECDH.
    crate::core::session::validate_key_lifetime(key_lifetime_secs)?;

    if packet.len() < OUTER_HEADER_SIZE + RESUME_REQUEST_BODY_LEN {
        return Err(SigilError::MalformedFrame);
    }
    if packet[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
        || packet[FRAME_TYPE_OFFSET] != FrameType::ResumeRequest as u8
    {
        return Err(SigilError::MalformedFrame);
    }
    let body = &packet[OUTER_HEADER_SIZE..];
    let req = parse_resume_request_body(body).ok_or(SigilError::MalformedFrame)?;

    // Session existence and local-role validation run BEFORE the request MAC
    // is computed: the PSK needed for that MAC lives in the session record,
    // so this precedence is pre-MAC in the current source already (position
    // unchanged by the replay defense).
    {
        let session = stores
            .sessions
            .get(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
        // Inbound resume is a gateway-only operation.
        if session.role() != SessionRole::Gateway {
            return Err(SigilError::WrongRole { peer: *peer });
        }
    }

    // A stale gateway post-commit recovery state (cached CommitConfirmed the
    // sensor never received) may be replaced by a fresh authenticated
    // request; every other pending for this peer blocks a new handshake.
    // Intentional ordering delta of the replay defense: this guard and the
    // per-peer cooldown below advance ahead of the request-MAC verification
    // so in-cooldown duplicates keep returning `RateLimited` inside the
    // cached-retransmission recovery window and peers stuck in pending keep
    // their specific guard error.
    let replacing_stale_commit = stores
        .pending
        .get(peer)
        .is_some_and(|pending| pending.state().is_gateway_commit_sent());
    if stores.pending.get(peer).is_some() && !replacing_stale_commit {
        return Err(SigilError::PendingAlreadyExists { peer: *peer });
    }

    {
        let session = stores
            .sessions
            .get_mut(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;

        if !session.resume_cooldown_elapsed(now, RESUME_REQUEST_COOLDOWN) {
            return Err(SigilError::RateLimited { peer: *peer });
        }
    }

    // Replay defense, between the cheap guards above and the request-MAC
    // verification below: purge strictly-expired entries (the only permitted
    // pre-authentication cache effect), exact-triple lookup, then the
    // fail-closed capacity pre-check. A hit costs zero crypto units — no PSK
    // MAC computation, no SE-ECDH — and mutates nothing; the capacity check
    // sits BEFORE the MAC verify so a saturated refusal performs zero
    // cryptography as well.
    stores.replay_cache.prefix_purge(now);
    if stores
        .replay_cache
        .contains(HandshakeKind::Resume, peer, &req.sensor_nonce)
    {
        return Err(SigilError::HandshakeReplay { peer: *peer });
    }
    if stores.replay_cache.is_full() {
        return Err(SigilError::ReplayCacheFull { peer: *peer });
    }

    // Verify request MAC with durable PSK **before** SE-ECDH (mandatory,
    // preserved).
    let expected = {
        let session = stores
            .sessions
            .get(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
        resume_request_mac(session.require_resume_psk()?, peer, &req.sensor_nonce)?
    };
    if !resume_chal_mac_eq(&expected, &req.req_mac) {
        return Err(SigilError::VerificationFailed);
    }

    let peer_static = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?
        .peer_static_pubkey();

    // ECDH shared wiped on Drop even if MAC / HKDF / frame build fails.
    let shared = crate::core::secret::validated_ecdh_shared_secret(se.ecdh(peer_static)?)?;

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

    let local = *stores.local_mac;
    let challenge_body = build_resume_challenge_body(&gateway_nonce, key_lifetime_secs, &chal_mac)?;
    let mut frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let chal_header = crate::core::frame::build_header(&local, FrameType::ResumeChallenge);
    frame
        .extend_from_slice(&chal_header)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(&challenge_body)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;

    // The tagged gateway state carries the directional material derived from
    // the static↔static ECDH and the agreed lifetime until the sensor Final.
    let pending = PendingHandshake::new_resume_gateway_await_confirm(
        *peer,
        material,
        key_lifetime_secs,
        RESUME_TIMEOUT_MS,
        now,
    );
    // Preserve the previous CommitSent recovery state across every fallible
    // verification/crypto/build operation. Replace it only once the complete
    // new challenge and pending state are ready.
    if replacing_stale_commit {
        let _ = stores.pending.remove(peer);
    }
    stores.pending.insert(*peer, pending)?;

    if let Some(s) = stores.sessions.get_mut(peer) {
        s.mark_resume_request(now);
    }

    // Success-only cache insertion — the FINAL mutation of this invocation,
    // after the fail-atomic pending insert and the cooldown stamp, and
    // immediately before returning Transmit. Every error return above
    // leaves the cache byte-identical: a failed handshake writes no triple,
    // so no legitimate retry is ever denied `HandshakeReplay` by its own
    // earlier failure.
    stores
        .replay_cache
        .insert(HandshakeKind::Resume, *peer, &req.sensor_nonce, now)?;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: frame,
        wait_timeout_ms: Some(RESUME_TIMEOUT_MS),
    })
}

/// Handles the resume confirm (Final) on the gateway side.
/// Commits the session, emits CommitConfirmed, keeps pending at CommitSent.
/// Duplicate Final while CommitSent retransmits cached CommitConfirmed.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
pub(crate) fn handle_resume_confirm<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    packet: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    // Extract the commit inputs from the tagged state while the pending
    // borrow is immutable; the clone ends the borrow before mutations.
    // A duplicate Final after commit retransmits the cached CommitConfirmed.
    let (material, lifetime) = {
        let pending = stores
            .pending
            .get(peer)
            .ok_or(SigilError::NoPending { peer: *peer })?;
        match pending.state() {
            PendingState::ResumeGatewayCommitSent { .. } => {
                // Duplicate Final after commit → idempotent reTX below.
                return retransmit_cached(stores, peer, RESUME_TIMEOUT_MS);
            }
            PendingState::ResumeGatewayAwaitConfirm {
                keys,
                key_lifetime_secs,
            } => (keys.clone(), *key_lifetime_secs),
            _ => return Err(SigilError::InvalidStep { peer: *peer }),
        }
    };

    // Confirm is sensor→gateway under the new s2g half.
    let confirm_key = &material.s2g_key;
    let confirm_prefix = &material.s2g_prefix;

    let opened = aead::open_frame::<{ aead::HANDSHAKE_PLAINTEXT_CAP }>(
        peer,
        crate::core::frame::FrameType::ResumeConfirm,
        packet,
        confirm_key,
        confirm_prefix,
        aead::RxCounterPolicy::Exact { expected: 0 },
    )?;
    if !parse_resume_confirm_body(&opened.plaintext) {
        return Err(SigilError::VerificationFailed);
    }

    let local = *stores.local_mac;
    let commit_frame = aead::build_commit_confirmed_frame::<MSG>(
        &local,
        FrameType::ResumeCommitConfirmed,
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
    session.rx_counter = 1;
    session.tx_counter = 1;

    // Checked transition to the recovery state: swapping the variant consumes
    // (zeroizes) the directional material by construction while keeping the
    // cached CommitConfirmed for idempotent retransmission.
    let pending = stores
        .pending
        .get_mut(peer)
        .ok_or(SigilError::NoPending { peer: *peer })?;
    pending.resume_gateway_commit_sent(&commit_frame, now)?;

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: commit_frame,
        wait_timeout_ms: Some(RESUME_TIMEOUT_MS),
    })
}

/// Retransmits the cached CommitConfirmed from the tagged state as a
/// `Transmit` action. Single source of truth:
/// [`PendingState::cached_retransmission_frame`].
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
    let mut payload: heapless::Vec<u8, MSG> = heapless::Vec::new();
    payload
        .extend_from_slice(cached)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(SigilAction::Transmit {
        dest: *peer,
        payload,
        wait_timeout_ms: Some(timeout_ms),
    })
}

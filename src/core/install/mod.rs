//! Non-blocking installation pairing protocol
//!
//! This module implements the first-time installation pairing protocol where
//! devices establish initial trust and exchange static public keys.
//!
//! # Gateway discovery is mandatory
//!
//! First-time install **requires** gateway discovery. The sensor does **not**
//! know the gateway MAC a priori and must not start install as a unicast to a
//! pre-provisioned gateway address.
//!
//! Required host flow:
//! 1. Sensor calls [`SessionManager::start_install`](crate::core::manager::SessionManager::start_install)
//!    with a **provisional / broadcast** destination (use
//!    [`INSTALL_DISCOVERY_DEST`] or the host radio broadcast address).
//! 2. Host transmits `InstallRequest` as a **discovery** (broadcast / join)
//!    frame — not a unicast to a known gateway.
//! 3. Gateway answers with `InstallChallenge` carrying its real `gateway_peer_mac`.
//! 4. [`continue_install`](crate::core::manager::SessionManager::continue_install)
//!    rebinds the sole sensor pending entry from the provisional dest to that
//!    gateway MAC, then completes crypto.
//!
//! Trust model: the first **factory-attested** challenge wins. Host firmware
//! may still refuse pairing via allowlist on the gateway; the sensor relies on
//! factory attestation of the challenge. Discovery therefore assumes a trusted
//! factory root and a controlled RF environment (or host-side rate limits).
//!
//! **Gateway hosts must also enforce a global handshake admission policy**
//!: library install/resume cooldowns are per-peer only, and the
//! `pending` table can fill independently of `sessions`. See
//! `contracts/session-api.md` and CLAUDE.md.
//!
//! # Factory attestation
//!
//! Before accepting a peer identity, both sides verify that the peer's static
//! public key **and wire PeerId** were signed by the shared factory root stored
//! on [`SessionManager`](crate::core::manager::SessionManager) at construction.
//! Canonical message: [`factory_cert_message`] —
//! `version ‖ product_id ‖ hardware_profile_id ‖ factory_key_id ‖ peer_mac ‖
//! pubkey`. The signature travels on the wire
//! in `InstallRequest` / `InstallChallenge`; the root itself never comes from
//! the packet.
//!
//! MAC allowlisting ("should this MAC be installed?") is a **host** decision
//! after classification via `process_incoming_packet` — not part of this
//! module.
//!
//! # Peer MAC binding
//!
//! Dynamic device signatures are domain-separated. The challenge/final bind
//! both peer identities, both nonces and the negotiated lifetime so a recorded
//! challenge cannot be rebound to a different sensor. The request also binds
//! the sensor identity, factory metadata, key and nonce. The static factory
//! certificate remains unchanged and factory-provisioned in the ATECC.
//! The request proof is `"sigil-install-request-v3" ‖ sensor_mac ‖
//! hardware_profile_id ‖ factory_key_id ‖ pubkey ‖ nonce`.
//!
//! Cost on the sensor is negligible: same 64-byte signature, ~19 extra bytes
//! hashed inside the ATECC.
//!
//! # Flow (4 messages)
//!
//! 1. **Sensor** → `start_install_sensor_internal` → emits `InstallRequest`
//!    (ECDSA-signed static pubkey + factory cert + nonce) with provisional dest.
//! 2. **Gateway** → `handle_install_request_internal` → verifies factory
//!    cert, verifies the sensor device signature, runs ECDH(static_priv,
//!    sensor_pub), derives the session key via HKDF(`sigil-install` ‖
//!    sensor_nonce ‖ gateway_nonce), emits `InstallChallenge` (gateway
//!    pubkey + factory cert + nonce + signature + expiry).
//! 3. **Sensor** → `continue_install_internal` → **discovers** gateway MAC,
//!    rebinds pending, verifies gateway factory cert + device signature, runs
//!    ECDH, derives the same key, **stages** material, emits `InstallConfirm`
//!    (Final). No session insert yet.
//! 4. **Gateway** → `continue_install_internal` → verifies the confirm
//!    signature, **commits** the session, emits `PersistPeerStaticKey` with
//!    `InstallCommitConfirmed` follow-up TX; keeps pending at CommitSent.
//! 5. **Sensor** → `continue_install_internal` on CommitConfirmed → verifies
//!    AEAD under staged keys, inserts session, emits `PersistPeerStaticKey`.
//!
//! Host must call `continue_install` on Challenge, Confirm, **and**
//! CommitConfirmed events.
//!
//! The public API is exposed as methods on [`SessionManager`]:
//! - [`SessionManager::start_install`]
//! - [`SessionManager::handle_install_request`]
//! - [`SessionManager::continue_install`]

#[cfg(feature = "gateway")]
pub(crate) mod gateway;
#[cfg(feature = "sensor")]
pub(crate) mod sensor;
pub(crate) mod wire;

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
#[cfg(feature = "sensor")]
use crate::core::install::sensor::build_install_request_action;
use crate::core::install::wire::{CompressedPub, INSTALL_NONCE_SIZE};
use crate::core::manager::SessionManager;
use crate::core::pending::HandshakeRole;
#[cfg(feature = "sensor")]
use crate::core::pending::PendingHandshake;
use crate::core::session::PeerId;
use crate::core::traits::{RandomSource, SecureElement};

/// Provisional destination MAC for **mandatory** sensor install discovery.
/// Pass this (or the host radio broadcast address) to
/// [`SessionManager::start_install`](crate::core::manager::SessionManager::start_install).
/// The real gateway MAC is learned from `InstallChallenge` and the pending
/// entry is rebound automatically in `continue_install`.
/// # Product flow (accepted: not enforced in-lib)
/// Typical fleet pairing:
/// 1. Sensor calls `start_install(INSTALL_DISCOVERY_DEST)` (or host broadcast) and
///    TXes discovery.
/// 2. Gateway classifies `InstallRequest`, shows the **sensor** MAC on a host UI.
/// 3. Operator allowlists that MAC in the pairing DB, then calls
///    `handle_install_request`.
///
/// The library does **not** reject a unicast `peer` here: host broadcast addresses
/// may differ from `[0xFF; 17]`, and who-may-pair remains host policy. Firmware
/// must still follow discovery for first pairing — unicast-to-known-gateway is
/// not the supported model.
pub const INSTALL_DISCOVERY_DEST: PeerId = [0xFFu8; 17];

/// Suggested radio wait for install handshake steps (milliseconds).
/// Advisory for the host scheduler / `Transmit.wait_timeout_ms` only.
/// Also converted to a seconds `deadline_at` for optional [`SessionManager::tick`](crate::core::manager::SessionManager::tick).
/// Elapsing this duration alone does **not** clear pending — call `cancel_pending` and/or `tick`.
pub const INSTALL_TIMEOUT_MS: u32 = 30000;

/// Minimum gap between accepted gateway `InstallRequest` SE work, in **seconds**.
/// Product timebase is seconds (same unit as local `now`).
/// `INSTALL_REQUEST_COOLDOWN = 15` means **15 seconds**.
/// Combined with an early [`SigilError::PendingAlreadyExists`] check (before any
/// secure-element work), this is the library's install DoS guard: the host
/// allowlist remains policy, but rate-limiting SE-ECDH is enforced here.
pub const INSTALL_REQUEST_COOLDOWN: u32 = 15;

/// Factory certificate version byte.
/// Bumped only when the canonical cert message layout changes.
pub const FACTORY_CERT_VERSION: u8 = 0x01;

/// Product id embedded in sensor factory certificates.
pub const FACTORY_PRODUCT_ID_SENSOR: u16 = 0x0001;

/// Product id embedded in gateway factory certificates.
pub const FACTORY_PRODUCT_ID_GATEWAY: u16 = 0x0002;

/// Canonical factory-cert message length:
/// `version[1] ‖ product_id[2] ‖ hardware_profile_id[1] ‖ factory_key_id[1]
/// ‖ peer_mac[17] ‖ pubkey[33]` = 55 bytes.
pub(crate) const FACTORY_CERT_MSG_LEN: usize = 1 + 2 + 1 + 1 + 17 + 33;

/// Builds the canonical factory certificate message.
/// ```text
/// FACTORY_CERT_VERSION ‖ product_id_be ‖ hardware_profile_id ‖ factory_key_id
/// ‖ peer_mac ‖ compressed_pubkey
/// ```
/// Manufacturing tools (`configAtecc`) and install verify must use the exact
/// same bytes. `peer_mac` is the device's wire [`PeerId`] (host-derived).
pub fn factory_cert_message(
    product_id: u16,
    metadata: crate::core::traits::FactoryCertificateMetadata,
    peer_mac: &PeerId,
    pubkey: &CompressedPub,
) -> Result<heapless::Vec<u8, FACTORY_CERT_MSG_LEN>, SigilError> {
    let mut msg = heapless::Vec::<u8, FACTORY_CERT_MSG_LEN>::new();
    msg.push(FACTORY_CERT_VERSION)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(&product_id.to_be_bytes())
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.push(metadata.hardware_profile_id)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.push(metadata.factory_key_id)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(peer_mac)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(pubkey)
        .map_err(|_| SigilError::CapacityExceeded)?;
    Ok(msg)
}

/// Max size of the ECDSA message for InstallRequest
/// (`domain ‖ peer_mac ‖ factory metadata ‖ pubkey ‖ nonce`).
const INSTALL_REQUEST_SIGN_DOMAIN: &[u8] = b"sigil-install-request-v3";
pub(crate) const INSTALL_REQUEST_SIGN_LEN: usize =
    INSTALL_REQUEST_SIGN_DOMAIN.len() + 17 + 2 + 33 + 16;

/// Builds the InstallRequest ECDSA message:
/// `"sigil-install-request-v3" ‖ peer_mac ‖ hardware_profile_id ‖ factory_key_id
/// ‖ pubkey ‖ sensor_nonce`.
pub(crate) fn install_request_sign_message(
    peer_mac: &PeerId,
    metadata: crate::core::traits::FactoryCertificateMetadata,
    pubkey: &CompressedPub,
    sensor_nonce: &[u8; INSTALL_NONCE_SIZE],
) -> Result<heapless::Vec<u8, INSTALL_REQUEST_SIGN_LEN>, SigilError> {
    let mut msg = heapless::Vec::<u8, INSTALL_REQUEST_SIGN_LEN>::new();
    msg.extend_from_slice(INSTALL_REQUEST_SIGN_DOMAIN)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(peer_mac)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.push(metadata.hardware_profile_id)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.push(metadata.factory_key_id)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(pubkey)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(sensor_nonce)
        .map_err(|_| SigilError::CapacityExceeded)?;
    Ok(msg)
}

/// Builds the InstallChallenge ECDSA message:
/// Domain-separated wire-v3 transcript binding both identities, both nonces,
/// the gateway public key, and `key_lifetime_secs`.
pub(crate) fn install_challenge_sign_message(
    sensor_mac: &PeerId,
    sensor_nonce: &[u8; INSTALL_NONCE_SIZE],
    peer_mac: &PeerId,
    metadata: crate::core::traits::FactoryCertificateMetadata,
    pubkey: &CompressedPub,
    gateway_nonce: &[u8; INSTALL_NONCE_SIZE],
    key_lifetime_secs: u32,
) -> Result<heapless::Vec<u8, 160>, SigilError> {
    let mut msg = heapless::Vec::<u8, 160>::new();
    msg.extend_from_slice(b"sigil-install-challenge-v3")
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(sensor_mac)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(sensor_nonce)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(peer_mac)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.push(metadata.hardware_profile_id)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.push(metadata.factory_key_id)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(pubkey)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(gateway_nonce)
        .map_err(|_| SigilError::CapacityExceeded)?;
    msg.extend_from_slice(&key_lifetime_secs.to_be_bytes())
        .map_err(|_| SigilError::CapacityExceeded)?;
    Ok(msg)
}

/// Dynamic ATECC signature transcript for the sensor's Install Final.
pub(crate) fn install_confirm_sign_message(
    sensor_mac: &PeerId,
    sensor_nonce: &[u8; INSTALL_NONCE_SIZE],
    gateway_mac: &PeerId,
    gateway_nonce: &[u8; INSTALL_NONCE_SIZE],
    key_lifetime_secs: u32,
) -> Result<heapless::Vec<u8, 128>, SigilError> {
    let mut msg = heapless::Vec::<u8, 128>::new();
    for part in [
        b"sigil-install-confirm-v3".as_slice(),
        sensor_mac,
        sensor_nonce,
        gateway_mac,
        gateway_nonce,
        &key_lifetime_secs.to_be_bytes(),
    ] {
        msg.extend_from_slice(part)
            .map_err(|_| SigilError::CapacityExceeded)?;
    }
    Ok(msg)
}

/// Returns true if the outer header peer MAC matches the body peer MAC.
pub(crate) fn outer_peer_matches_body(packet: &[u8], body_peer: &PeerId) -> bool {
    packet.len() >= 17 && &packet[..17] == body_peer
}

/// HKDF info for install key derivation.
/// `info = b"sigil-install" ‖ sensor_nonce ‖ gateway_nonce`
/// Mixing both handshake nonces ensures each install produces a fresh
/// session key + nonce_prefix even when the static ECDH shared secret is
/// unchanged (prevents ChaCha20 nonce reuse after re-install).
pub(crate) fn install_hkdf_info(
    sensor_nonce: &[u8; INSTALL_NONCE_SIZE],
    gateway_nonce: &[u8; INSTALL_NONCE_SIZE],
) -> Result<heapless::Vec<u8, 64>, SigilError> {
    let mut info = heapless::Vec::<u8, 64>::new();
    info.extend_from_slice(b"sigil-install")
        .map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(sensor_nonce)
        .map_err(|_| SigilError::CapacityExceeded)?;
    info.extend_from_slice(gateway_nonce)
        .map_err(|_| SigilError::CapacityExceeded)?;
    Ok(info)
}

/// Internal implementation of [`SessionManager::start_install`].
/// Starts an installation handshake on the sensor side. **Gateway discovery is
/// mandatory:** `peer` must be a provisional / broadcast destination (typically
/// [`INSTALL_DISCOVERY_DEST`]), not a pre-known unicast gateway MAC.
/// Creates a pending handshake keyed by that provisional dest and returns a
/// `Transmit` action carrying the signed `InstallRequest` (outer header =
/// sensor `local_mac`) with [`SigilAction::Transmit::wait_timeout_ms`] set.
/// The host must send the frame as discovery/broadcast; the real gateway MAC
/// is bound later in `continue_install` from `InstallChallenge`.
#[cfg(feature = "sensor")]
pub(crate) fn start_install_sensor_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: PeerId,
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    if manager.get_pending(&peer).is_some() {
        return Err(SigilError::PendingAlreadyExists { peer });
    }
    if !manager.pending_slot_available(&peer) {
        return Err(SigilError::CapacityExceeded);
    }

    let local = *manager.local_mac();
    // Build the signed request first — may fail on SE/RNG before we commit state.
    let (payload, sensor_nonce) = build_install_request_action::<MSG>(local, se, rng)?;

    // Explicit reboot recovery: retain the previous staged Commit state until
    // the replacement request has been completely constructed.
    manager.clear_sensor_install_commit_recovery();

    let mut handshake =
        PendingHandshake::new_install(peer, HandshakeRole::Sensor, INSTALL_TIMEOUT_MS, now);
    // Stash sensor_nonce so the challenge step can mix it into HKDF.
    handshake.transcript_initiator_nonce = Some(sensor_nonce);
    manager.insert_pending(peer, handshake)?;

    Ok(SigilAction::Transmit {
        dest: peer,
        payload,
        wait_timeout_ms: Some(INSTALL_TIMEOUT_MS),
    })
}

/// Internal implementation of [`SessionManager::handle_install_request`].
/// Processes an install request packet on the gateway side and returns
/// the challenge to transmit. Delegates to [`gateway::handle_install_request`].
#[cfg(feature = "gateway")]
pub(crate) fn handle_install_request_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    rng: &mut impl RandomSource,
    now: u32,
    key_lifetime_secs: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    gateway::handle_install_request(manager, packet, se, rng, now, key_lifetime_secs)
}

/// Internal implementation of [`SessionManager::continue_install`].
/// Continues an in-progress install handshake based on the current role/step
/// (4-message):
/// - Sensor waiting for challenge → verifies, **stages** keys, emits confirm (Final).
/// - Sensor waiting for CommitConfirmed → verifies AEAD, inserts session, Persist.
/// - Sensor WaitingForCommitConfirmed + Challenge again → reTX cached Final.
/// - Gateway waiting for confirm → commits session, Persist + CommitConfirmed TX.
/// - Gateway CommitSent + duplicate Confirm → reTX cached CommitConfirmed.
///
/// On the sensor, a discovery pending keyed by [`INSTALL_DISCOVERY_DEST`] (or
/// another provisional dest) is rebound to the gateway MAC from the challenge
/// **only after** outer≡body MAC checks. If challenge crypto fails, the pending
/// is rolled back to the provisional key so a later valid challenge can proceed.
/// Host must call this on Challenge, Confirm, **and** CommitConfirmed events.
pub(crate) fn continue_install_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    se: &mut impl SecureElement,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    use crate::core::frame::OUTER_HEADER_SIZE;
    use crate::core::install::wire::parse_install_message_type;
    use crate::core::pending::HandshakeStep;
    let msg_type = parse_install_message_type(packet).ok_or(SigilError::ParseError)?;

    // CommitConfirmed is AEAD — peer is only in the outer header (no body MAC).
    let peer = if matches!(msg_type, wire::InstallMessageType::CommitConfirmed) {
        if packet.len() < OUTER_HEADER_SIZE {
            return Err(SigilError::ParseError);
        }
        let mut peer = [0u8; 17];
        peer.copy_from_slice(&packet[..17]);
        peer
    } else {
        // Peek the peer from the body (bytes OUTER_HEADER_SIZE..OUTER_HEADER_SIZE+17
        // for install clear-text messages, after the 19-byte wire-v2 outer header).
        if packet.len() < OUTER_HEADER_SIZE + 17 {
            return Err(SigilError::ParseError);
        }
        let mut peer = [0u8; 17];
        peer.copy_from_slice(&packet[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 17]);
        peer
    };

    // Structural check before any pending mutation (challenge discovery path).
    if matches!(msg_type, wire::InstallMessageType::Challenge)
        && !crate::core::install::outer_peer_matches_body(packet, &peer)
    {
        return Err(SigilError::ParseError);
    }

    // Mandatory discovery: pending may still be keyed by INSTALL_DISCOVERY_DEST
    // (or another provisional broadcast dest). Rebind only after outer≡body.
    #[cfg(feature = "sensor")]
    let mut rebound_from: Option<PeerId> = None;
    #[cfg(feature = "sensor")]
    if matches!(msg_type, wire::InstallMessageType::Challenge)
        && manager.get_pending(&peer).is_none()
    {
        rebound_from = manager.rebind_sole_sensor_install_pending(peer)?;
    }

    let pending = manager
        .get_pending(&peer)
        .ok_or(SigilError::NoPending { peer })?;
    let role = pending.role;
    let step = pending.step;
    #[cfg(feature = "sensor")]
    let cached_retx = if step == HandshakeStep::InstallWaitingForCommitConfirmed
        && matches!(msg_type, wire::InstallMessageType::Challenge)
    {
        pending.cached_wire.clone()
    } else {
        None
    };
    // drop(pending) is a no-op on a reference; role/step already copied.

    let result = match (role, step, msg_type) {
        #[cfg(feature = "sensor")]
        (
            HandshakeRole::Sensor,
            HandshakeStep::InstallWaitingForChallenge,
            wire::InstallMessageType::Challenge,
        ) => sensor::handle_install_challenge(manager, &peer, packet, se, now),
        #[cfg(feature = "sensor")]
        (
            HandshakeRole::Sensor,
            HandshakeStep::InstallWaitingForCommitConfirmed,
            wire::InstallMessageType::CommitConfirmed,
        ) => sensor::handle_install_commit_confirmed(manager, &peer, packet, now),
        #[cfg(feature = "sensor")]
        (
            HandshakeRole::Sensor,
            HandshakeStep::InstallWaitingForCommitConfirmed,
            wire::InstallMessageType::Challenge,
        ) => {
            let cached = cached_retx.ok_or(SigilError::InvalidHandshakeState)?;
            let mut payload: heapless::Vec<u8, MSG> = heapless::Vec::new();
            payload
                .extend_from_slice(&cached)
                .map_err(|_| SigilError::CapacityExceeded)?;
            Ok(SigilAction::Transmit {
                dest: peer,
                payload,
                wait_timeout_ms: Some(INSTALL_TIMEOUT_MS),
            })
        }
        #[cfg(feature = "gateway")]
        (
            HandshakeRole::Gateway,
            HandshakeStep::InstallWaitingForConfirm,
            wire::InstallMessageType::Confirm,
        )
        | (
            HandshakeRole::Gateway,
            HandshakeStep::InstallCommitSent,
            wire::InstallMessageType::Confirm,
        ) => gateway::handle_install_confirm(manager, packet, se, now),
        _ => Err(SigilError::InvalidStep { peer }),
    };

    // If challenge crypto failed after a discovery rebind, restore the
    // provisional pending key so the sensor can accept a later valid challenge.
    #[cfg(feature = "sensor")]
    if result.is_err()
        && let Some(old) = rebound_from
    {
        let _ = manager.rollback_install_pending_rebind(peer, old);
    }

    result
}

mod tests;

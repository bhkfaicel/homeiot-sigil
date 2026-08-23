//! Encrypted **Data** plane and the single authenticated egress primitive.
//!
//! This submodule owns two responsibilities of the packet pipeline:
//!
//! - The **Data** semantic handler for already-authenticated ingress frames
//!   ([`handle_data_frame`]). Data carries no domain state of its own: the
//!   decrypted payload is forwarded to the host unchanged.
//! - [`encrypt_application_payload`], the **one** TX-side AEAD primitive used
//!   by every egress builder (Data, EventAck, TimeSync, TimeSyncRequest).
//!   Centralizing it mirrors the single RX-side authenticated ingress
//!   primitive in the parent module: session lookup, expiry check, TX-counter
//!   overflow guard, and counter advance happen in exactly one place and fail
//!   closed, so no control-plane builder can bypass or reorder them.
//!
//! Crate-internal: host firmware uses the public facade on
//! [`SessionManager`](crate::core::manager::SessionManager) instead.

use crate::core::aead;
use crate::core::error::SigilError;
use crate::core::event::SigilEvent;
use crate::core::frame::{self, FrameType};
use crate::core::manager::{ProtocolStores, SessionManager};
use crate::core::session::PeerId;
use heapless::Vec;

/// Builds the `SigilEvent::Data` for an already-authenticated, replay-checked
/// Data frame.
///
/// The decrypted plaintext buffer is moved into the event unchanged — Data has
/// no domain state, so this step cannot fail after authentication succeeded.
pub(super) fn handle_data_frame<const DATA: usize, const MSG: usize>(
    peer: PeerId,
    payload: Vec<u8, DATA>,
) -> SigilEvent<DATA, MSG> {
    SigilEvent::Data { peer, payload }
}

/// Internal implementation of [`SessionManager::encrypt_data`].
/// Encrypts application data for transmission to a peer.
/// # Wire format
/// `[peer_mac: 17] [protocol_version: 1] [frame_type: 1 = Data] [nonce_prefix: 4] [tx_counter: 8 BE] [ciphertext + tag]`
/// # Errors
/// - `SigilError::UnknownSession` - No session exists for the peer
/// - `SigilError::SessionExpired` - Session key has expired
/// - `SigilError::CounterExhausted` - TX counter would overflow
pub(crate) fn encrypt_data_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    plaintext: &[u8],
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let mut stores = manager.protocol_stores();
    encrypt_application_payload(&mut stores, peer, FrameType::Data, plaintext, now)
}

/// Encrypts any authenticated application / control frame body onto the wire.
/// Operates on the lent [`ProtocolStores`] view (session table + local MAC),
/// never on the manager facade, so it cannot touch unrelated manager state.
///
/// This is the single TX-side mutation point of the AEAD transmit counter:
/// `tx_counter` advances only after the full frame (header, nonce, ciphertext,
/// tag) was built successfully. Every capacity or crypto failure above leaves
/// the counter untouched so the same key/counter pair is retried later.
pub(super) fn encrypt_application_payload<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    frame_type: FrameType,
    plaintext: &[u8],
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let local = *stores.local_mac;

    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;

    // Check if session is active and not expired
    if !session.is_active(now) {
        return Err(SigilError::SessionExpired { peer: *peer });
    }

    // Check TX counter for overflow (fail closed before any byte is emitted)
    let next_tx_counter = aead::check_tx_counter(session.tx_counter)
        .map_err(|_| SigilError::CounterExhausted { peer: *peer })?;
    let tx_counter = session.tx_counter;

    // AAD binds ciphertext to the clear-text outer header (sender = local_mac).
    let aad = aead::build_aad(&local, frame_type);

    // Single MSG-sized stack buffer: clear header then append AEAD in place.
    let mut frame: Vec<u8, MSG> = Vec::new();
    let header = frame::build_header(&local, frame_type);
    frame
        .extend_from_slice(&header)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;

    {
        let (session_key, nonce_prefix) = session.require_tx_material(peer)?;
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
            plaintext,
            &aad,
            &mut frame,
        )?;
    }

    // Mutation point: advance the TX counter only on full success. Any error
    // path above returns before this assignment, keeping the old counter.
    session.tx_counter = next_tx_counter;

    Ok(frame)
}

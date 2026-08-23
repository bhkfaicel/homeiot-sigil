//! Durable **Event / EventAck** delivery plane.
//!
//! This submodule owns the reliable-delivery transaction between a sensor and
//! a gateway:
//!
//! - Sensor egress: [`send_event_internal`] starts (or retries) an ACK wait,
//!   [`cancel_pending_event_internal`] abandons it.
//! - Gateway egress: [`ack_event_internal`] commits a delivery only after the
//!   host durably processed it and the ACK frame was fully built;
//!   [`release_event_delivery_internal`] drops an uncommitted delivery so the
//!   sensor can redeliver.
//! - Ingress semantics for already-authenticated frames:
//!   [`handle_event_frame`] stamps the gateway delivery transaction,
//!   [`handle_event_ack_frame`] clears the sensor ACK wait. Both receive the
//!   decrypted plaintext plus the pre-open session state snapshots taken by
//!   the single authenticated ingress primitive in the parent module; they own
//!   only their domain mutations.
//!
//! Every counter/state mutation point below carries a comment stating when the
//! mutation happens relative to the error paths around it.

#[cfg(feature = "gateway")]
use super::EVENT_ACK_WIRE_LEN;
#[cfg(feature = "sensor")]
use crate::core::aead;
use crate::core::error::SigilError;
use crate::core::event::{SigilAction, SigilEvent};
#[cfg(feature = "sensor")]
use crate::core::frame;
use crate::core::frame::FrameType;
use crate::core::manager::{ProtocolStores, SessionManager};
use crate::core::session::PeerId;
use heapless::Vec;

#[cfg(feature = "sensor")]
use super::EVENT_ACK_TIMEOUT_MS;
use super::EVENT_ID_SIZE;

/// Handles an already-authenticated gateway-side Event frame.
///
/// Receives the **owned** decrypted plaintext
/// (`[event_id: 8 BE][application payload]`, already carried in a
/// `DATA`-capacity buffer by the ingress primitive) and the pre-open
/// snapshots of `last_rx_event_id` / `pending_rx_event_id`.
///
/// Ordering (byte-identical with the former inline arm):
/// 1. length + id parse failures reject **before** any mutation;
/// 2. a parallel delivery is rejected **before** any mutation;
/// 3. a committed duplicate is reported without any mutation;
/// 4. otherwise the delivery stamp below happens **before** the application
///    payload is exposed: the id prefix is stripped **in place** (a
///    `rotate_left` + `truncate` pair) inside the very buffer the AEAD open
///    filled, so no second `DATA`-capacity buffer ever exists. That strip
///    cannot fail — the authenticated plaintext already fits `DATA`, hence
///    the application payload fits `DATA` a fortiori — so every rejection
///    happens strictly before the stamp and, once stamped, no fallible step
///    remains between the stamp and delivery. Fail closed is preserved end
///    to end: a stamped id is always delivered here or explicitly released
///    by the host, never lost to a buffer error.
#[cfg(feature = "gateway")]
pub(super) fn handle_event_frame<const N: usize, const DATA: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    mut payload: Vec<u8, DATA>,
    last_rx_event_id: Option<u64>,
    pending_rx_event_id: Option<u64>,
) -> Result<SigilEvent<DATA, MSG>, SigilError> {
    if payload.len() < EVENT_ID_SIZE {
        return Err(SigilError::MalformedFrame);
    }
    let event_id = u64::from_be_bytes(
        payload[..EVENT_ID_SIZE]
            .try_into()
            .map_err(|_| SigilError::MalformedFrame)?,
    );
    let already_committed = last_rx_event_id.is_some_and(|last| event_id <= last);
    if !already_committed {
        if let Some(pending) = pending_rx_event_id {
            return Err(SigilError::EventDeliveryPending {
                peer: *peer,
                event_id: pending,
            });
        }
        // Mutation point: open the durable-delivery transaction. Only reached
        // for a fresh id while no other delivery is pending; every rejection
        // above returns before this stamp.
        stores
            .sessions
            .get_mut(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?
            .pending_rx_event_id = Some(event_id);
    }
    // In-place id strip inside the single `DATA`-capacity plaintext buffer:
    // shift the application payload over the id prefix, then shorten the
    // vector. Infallible by construction (length pre-checked above; capacity
    // unchanged), so this introduces no error path past the delivery stamp.
    let payload_len = payload.len() - EVENT_ID_SIZE;
    payload.rotate_left(EVENT_ID_SIZE);
    payload.truncate(payload_len);

    Ok(SigilEvent::Event {
        peer: *peer,
        event_id,
        payload,
        duplicate: already_committed,
    })
}

/// Handles an already-authenticated sensor-side EventAck frame.
///
/// Receives the decrypted plaintext (`[event_id: 8 BE]`) and the pre-open
/// snapshot of `pending_tx_event_id`.
///
/// Mutation point: the ACK-wait state is cleared **only** after the id parse
/// succeeded and the authenticated id matches the one being waited for; any
/// mismatch returns before the state changes.
#[cfg(feature = "sensor")]
pub(super) fn handle_event_ack_frame<const N: usize, const DATA: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    payload: &[u8],
    pending_tx_event_id: Option<u64>,
) -> Result<SigilEvent<DATA, MSG>, SigilError> {
    if payload.len() != EVENT_ID_SIZE {
        return Err(SigilError::MalformedFrame);
    }
    let event_id = u64::from_be_bytes(
        payload[..EVENT_ID_SIZE]
            .try_into()
            .map_err(|_| SigilError::MalformedFrame)?,
    );
    if pending_tx_event_id != Some(event_id) {
        return Err(SigilError::UnexpectedEventAck {
            peer: *peer,
            event_id,
        });
    }
    // Mutation point: commit the ACK — the Event id stays consumed (it can
    // never be reused) but the one-in-flight wait is released.
    stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?
        .pending_tx_event_id = None;
    Ok(SigilEvent::EventAck {
        peer: *peer,
        event_id,
    })
}

/// Encrypts a reliable sensor Event or retransmits the current Event.
#[cfg(feature = "sensor")]
pub(crate) fn send_event_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    event_id: u64,
    plaintext: &[u8],
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    let mut stores = manager.protocol_stores();
    let session = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Sensor {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    match session.pending_tx_event_id {
        Some(pending) if pending != event_id => {
            return Err(SigilError::EventAckPending {
                peer: *peer,
                event_id: pending,
            });
        }
        Some(_) => {} // retry of the same id; encryption uses a fresh counter
        None => {
            if let Some(last) = session.last_tx_event_id
                && event_id <= last
            {
                return Err(SigilError::InvalidEventId {
                    peer: *peer,
                    last,
                    received: event_id,
                });
            }
        }
    }

    let frame = encrypt_event_payload(&mut stores, peer, event_id, plaintext, now)?;

    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    // Mutation point: start (or refresh) the ACK wait only after the frame was
    // fully encrypted. A retry of the same id keeps the original stamp; every
    // encryption failure above leaves the wait state untouched.
    if session.pending_tx_event_id.is_none() {
        session.last_tx_event_id = Some(event_id);
        session.pending_tx_event_id = Some(event_id);
    }

    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: frame,
        wait_timeout_ms: Some(EVENT_ACK_TIMEOUT_MS),
    })
}

/// Event-specialized AEAD builder: writes id and payload directly into the
/// final frame, keeping only one `MSG`-sized stack buffer on SAMD21.
/// Operates on the lent [`ProtocolStores`] view, not the manager facade.
///
/// Mutation point: the TX counter advances only after the complete Event frame
/// (header, nonce, id, payload, tag) was built; every capacity or crypto
/// failure returns before the assignment, so the same key/counter pair is
/// retried later.
#[cfg(feature = "sensor")]
fn encrypt_event_payload<const N: usize, const MSG: usize>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    event_id: u64,
    plaintext: &[u8],
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let local = *stores.local_mac;
    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if !session.is_active(now) {
        return Err(SigilError::SessionExpired { peer: *peer });
    }
    let next_tx_counter = aead::check_tx_counter(session.tx_counter)
        .map_err(|_| SigilError::CounterExhausted { peer: *peer })?;
    let tx_counter = session.tx_counter;
    let aad = aead::build_aad(&local, FrameType::Event);

    let mut frame = Vec::<u8, MSG>::new();
    frame
        .extend_from_slice(&frame::build_header(&local, FrameType::Event))
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    {
        let (session_key, nonce_prefix) = session.require_tx_material(peer)?;
        frame
            .extend_from_slice(nonce_prefix)
            .map_err(|_| SigilError::OutputBufferTooSmall)?;
        frame
            .extend_from_slice(&tx_counter.to_be_bytes())
            .map_err(|_| SigilError::OutputBufferTooSmall)?;
        let plaintext_start = frame.len();
        frame
            .extend_from_slice(&event_id.to_be_bytes())
            .map_err(|_| SigilError::OutputBufferTooSmall)?;
        frame
            .extend_from_slice(plaintext)
            .map_err(|_| SigilError::OutputBufferTooSmall)?;
        aead::encrypt_tail_in_place(
            session_key,
            nonce_prefix,
            tx_counter,
            plaintext_start,
            &aad,
            &mut frame,
        )?;
    }
    session.tx_counter = next_tx_counter;
    Ok(frame)
}

/// Abandons an Event after host retry policy is exhausted.
#[cfg(feature = "sensor")]
pub(crate) fn cancel_pending_event_internal<const N: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    event_id: u64,
) -> Result<(), SigilError> {
    let stores = manager.protocol_stores();
    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.pending_tx_event_id != Some(event_id) {
        return Err(SigilError::UnexpectedEventAck {
            peer: *peer,
            event_id,
        });
    }
    // Mutation point: release the ACK wait. The id remains consumed via
    // `last_tx_event_id`, so a cancelled Event can never be resent as new.
    session.pending_tx_event_id = None;
    Ok(())
}

/// Builds an authenticated ACK only after the host has durably processed the
/// Event. Already committed duplicate ids may be ACKed again after ACK loss.
#[cfg(feature = "gateway")]
pub(crate) fn ack_event_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    event_id: u64,
    now: u32,
) -> Result<SigilAction<MSG>, SigilError> {
    if MSG < EVENT_ACK_WIRE_LEN {
        return Err(SigilError::OutputBufferTooSmall);
    }
    let mut stores = manager.protocol_stores();
    let session = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Gateway {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    let committing_new = session.pending_rx_event_id == Some(event_id);
    let already_committed = session
        .last_rx_event_id
        .is_some_and(|last| event_id <= last);
    if !committing_new && !already_committed {
        return Err(SigilError::UnexpectedEventAck {
            peer: *peer,
            event_id,
        });
    }
    let ack = super::data::encrypt_application_payload(
        &mut stores,
        peer,
        FrameType::EventAck,
        &event_id.to_be_bytes(),
        now,
    )?;
    if committing_new {
        let session = stores
            .sessions
            .get_mut(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
        // Mutation point: commit the durable delivery strictly AFTER the ACK
        // frame was fully encrypted. Every buffer/crypto failure above leaves
        // the delivery pending so the commit is never lost or half-applied.
        session.last_rx_event_id = Some(event_id);
        session.pending_rx_event_id = None;
    }
    Ok(SigilAction::Transmit {
        dest: *peer,
        payload: ack,
        wait_timeout_ms: None,
    })
}

/// Drops an uncommitted gateway delivery without emitting an ACK. This lets a
/// transient host-storage failure be retried from the next sensor transmission.
#[cfg(feature = "gateway")]
pub(crate) fn release_event_delivery_internal<const N: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    event_id: u64,
) -> Result<(), SigilError> {
    let stores = manager.protocol_stores();
    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Gateway {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    if session.pending_rx_event_id != Some(event_id) {
        return Err(SigilError::UnexpectedEventDelivery {
            peer: *peer,
            event_id,
        });
    }
    // Mutation point: abandon the delivery transaction. No ACK is emitted and
    // nothing is committed, so the sensor retry re-delivers with
    // `duplicate == false`; a mismatching id returns before this clear.
    session.pending_rx_event_id = None;
    Ok(())
}

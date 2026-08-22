//! **TimeSync / TimeSyncRequest** control plane.
//!
//! This submodule owns the gateway-clock distribution semantics:
//!
//! - Gateway egress: [`encrypt_time_sync_internal`] builds an authenticated
//!   clock sample for a sensor session.
//! - Sensor egress: [`request_time_sync_internal`] builds an authenticated
//!   request for a fresh clock sample.
//! - Ingress semantics for already-authenticated frames:
//!   [`handle_time_sync_frame`] parses the sensor-side clock sample (pure —
//!   no protocol state is mutated), and [`handle_time_sync_request_frame`]
//!   applies the per-session request cooldown on the gateway.
//!
//! Every state mutation point below carries a comment stating when the
//! mutation happens relative to the error paths around it.

#[cfg(feature = "gateway")]
use super::TIME_SYNC_REQUEST_COOLDOWN_SECS;
use crate::core::error::SigilError;
use crate::core::event::SigilEvent;
use crate::core::frame::FrameType;
use crate::core::manager::SessionManager;
use crate::core::session::{PeerId, SessionRole};
use heapless::Vec;

#[cfg(feature = "gateway")]
use crate::core::manager::ProtocolStores;

/// Parses an already-authenticated sensor-side TimeSync sample.
///
/// Pure handler: `[gateway_time: 4 BE][sync_sequence: 4 BE][uncertainty: 2 BE]`.
/// TimeSync reception mutates no domain state, so every malformed length or
/// field simply rejects without any side effect; replay protection and key
/// handling already happened in the single authenticated ingress primitive.
#[cfg(feature = "sensor")]
pub(super) fn handle_time_sync_frame<const DATA: usize, const MSG: usize>(
    peer: &PeerId,
    payload: &[u8],
) -> Result<SigilEvent<DATA, MSG>, SigilError> {
    if payload.len() != 10 {
        return Err(SigilError::MalformedFrame);
    }
    let gateway_time = u32::from_be_bytes(
        payload[0..4]
            .try_into()
            .map_err(|_| SigilError::MalformedFrame)?,
    );
    let sync_sequence = u32::from_be_bytes(
        payload[4..8]
            .try_into()
            .map_err(|_| SigilError::MalformedFrame)?,
    );
    let uncertainty_secs = u16::from_be_bytes(
        payload[8..10]
            .try_into()
            .map_err(|_| SigilError::MalformedFrame)?,
    );
    Ok(SigilEvent::TimeSync {
        peer: *peer,
        gateway_time,
        sync_sequence,
        uncertainty_secs,
    })
}

/// Applies the gateway-side TimeSync-request cooldown to an
/// already-authenticated request frame.
///
/// Receives the decrypted plaintext (must be empty) and the pre-open snapshot
/// of `last_time_sync_request_at`.
///
/// Ordering (byte-identical with the former inline arm): malformed payloads
/// and throttled requests reject **before** any mutation; only an in-window
/// request stamps the cooldown below. Note the AEAD RX counter was already
/// advanced by the ingress primitive, so a rejected request can never be
/// replayed later into an accepted one.
#[cfg(feature = "gateway")]
pub(super) fn handle_time_sync_request_frame<
    const N: usize,
    const DATA: usize,
    const MSG: usize,
>(
    stores: &mut ProtocolStores<'_, N>,
    peer: &PeerId,
    payload: &[u8],
    last_time_sync_request_at: Option<u32>,
    now: u32,
) -> Result<SigilEvent<DATA, MSG>, SigilError> {
    if !payload.is_empty() {
        return Err(SigilError::MalformedFrame);
    }
    if last_time_sync_request_at
        .is_some_and(|last| now.saturating_sub(last) < TIME_SYNC_REQUEST_COOLDOWN_SECS)
    {
        return Err(SigilError::RateLimited { peer: *peer });
    }
    // Mutation point: stamp the per-session request cooldown only after the
    // request passed the shape and cooldown checks above; both error paths
    // return before this write leaves the previous stamp untouched.
    stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?
        .last_time_sync_request_at = Some(now);
    Ok(SigilEvent::TimeSyncRequest { peer: *peer })
}

/// Builds an authenticated TimeSync control frame on a gateway session.
#[cfg(feature = "gateway")]
pub(crate) fn encrypt_time_sync_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    gateway_time: u32,
    sync_sequence: u32,
    uncertainty_secs: u16,
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let mut stores = manager.protocol_stores();
    let session = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != SessionRole::Gateway {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    let mut body = [0u8; 10];
    body[0..4].copy_from_slice(&gateway_time.to_be_bytes());
    body[4..8].copy_from_slice(&sync_sequence.to_be_bytes());
    body[8..10].copy_from_slice(&uncertainty_secs.to_be_bytes());
    super::data::encrypt_application_payload(&mut stores, peer, FrameType::TimeSync, &body, now)
}

/// Builds an authenticated request for a fresh gateway TimeSync sample.
#[cfg(feature = "sensor")]
pub(crate) fn request_time_sync_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let mut stores = manager.protocol_stores();
    let session = stores
        .sessions
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != SessionRole::Sensor {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    super::data::encrypt_application_payload(
        &mut stores,
        peer,
        FrameType::TimeSyncRequest,
        &[],
        now,
    )
}

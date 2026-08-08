//! Non-blocking packet processing pipeline
//!
//! This module provides the internal packet processing entry points used by
//! [`SessionManager`](crate::core::manager::SessionManager). The public API
//! is exposed as methods on `SessionManager`; these functions are the
//! implementations behind those methods.
//!
//! # Wire format
//!
//! Every sigil frame starts with a common outer header:
//! ```text
//! [peer_mac: 17 bytes] [protocol_version: 1 byte = 0x03] [frame_type: 1 byte]
//! [type-specific payload]
//! ```
//!
//! See [`crate::core::frame::FrameType`] for the discriminator values.
//!
//! ## Encrypted payload (Data, Event/Ack, TimeSync, Renew*, ResumeConfirm,
//! *CommitConfirmed)
//! ```text
//! [peer_mac: 17] [protocol_version: 1] [frame_type: 1]
//! [nonce_prefix: 4] [tx_counter: 8 BE] [ciphertext + AEAD tag: variable]
//! ```
//! The full 12-byte AEAD nonce is reconstructed as `nonce_prefix ‖ tx_counter_be`.
//!
//! ## Clear-text payload (Install Request/Challenge/Confirm, Resume Request/Challenge)
//! The payload after the outer header is protocol-specific and not encrypted.
//!
//! ## Stack budget
//!
//! Data/Event encrypt and decrypt use a **single** caller-sized `heapless::Vec` via
//! [`aead::encrypt_append`] / [`aead::decrypt_into`] — no second 256-byte
//! AEAD scratch alongside the output frame/payload.
//!
//! **Crate-internal**: host firmware uses [`SessionManager::process_incoming_packet`]
//! and [`SessionManager::encrypt_data`] instead.
//!
//! # Buffer capacities
//!
//! `process_incoming_packet::<DATA, MSG>` uses `DATA` for decrypted Data and
//! Event plaintext. An Event reserves 8 bytes of `DATA` for its id, so its
//! application payload limit is `DATA - 8`. Handshake classification copies
//! the raw wire frame into `MSG`. Hosts must set `MSG >= 219`
//! (InstallChallenge) when using install; the README default `<200, 256>` is valid.

use crate::core::aead::{self, TAG_SIZE};
use crate::core::error::SigilError;
use crate::core::event::{SigilAction, SigilEvent};
use crate::core::frame::{self, FrameType, OUTER_HEADER_SIZE};
use crate::core::manager::SessionManager;
use crate::core::session::PeerId;
use heapless::Vec;

/// Minimum wire size for a valid encrypted data frame:
/// 17 (peer) + 1 (version) + 1 (frame_type) + 4 (prefix) + 8 (counter) + 16 (tag) = 47 bytes.
const MIN_ENCRYPTED_FRAME: usize = OUTER_HEADER_SIZE + 4 + 8 + TAG_SIZE;

/// Event id prefix size inside authenticated Event/EventAck plaintext.
pub const EVENT_ID_SIZE: usize = 8;

/// Minimum EventAck wire size: header + nonce + id + Poly1305 tag.
#[cfg(feature = "gateway")]
pub const EVENT_ACK_WIRE_LEN: usize = MIN_ENCRYPTED_FRAME + EVENT_ID_SIZE;

/// Advisory host wait before retransmitting an Event.
#[cfg(feature = "sensor")]
pub const EVENT_ACK_TIMEOUT_MS: u32 = 10_000;

/// Minimum interval between accepted TimeSyncRequest frames from one sensor.
/// The request is authenticated before this inexpensive policy is evaluated.
#[cfg(feature = "gateway")]
pub const TIME_SYNC_REQUEST_COOLDOWN_SECS: u32 = 15;

/// Internal implementation of [`SessionManager::process_incoming_packet`].
/// Processes an incoming packet in a non-blocking manner. Parses the outer
/// header, classifies the frame by `FrameType`, and returns a typed event.
/// - **Data** frames are fully processed: session lookup, key validation,
///   decryption, replay check. Returns [`SigilEvent::Data`].
/// - **Event/EventAck** frames additionally enforce direction, monotonic event
///   ids, one in-flight delivery, authenticated ACK matching and deduplication.
/// - **Handshake** frames are classified **per step**: e.g.
///   [`SigilEvent::InstallChallenge`] vs [`SigilEvent::InstallRequest`],
///   paired with [`SigilAction::NeedsHostDispatch`] (not [`SigilAction::Success`]).
///
/// This method never blocks or sleeps. The data path does not require a
/// secure element or random source — those are only needed for handshake
/// steps, which are dispatched through the dedicated methods.
pub(crate) fn process_incoming_packet_internal<
    const N: usize,
    const DATA: usize,
    const MSG: usize,
>(
    manager: &mut SessionManager<N>,
    packet: &[u8],
    now: u32,
) -> Result<(SigilEvent<DATA, MSG>, SigilAction<MSG>), SigilError> {
    // Parse the outer header (peer MAC + frame_type).
    let header = frame::parse_header(packet).ok_or(SigilError::ParseError)?;
    let peer = header.peer;

    #[allow(unreachable_patterns)]
    match header.frame_type {
        FrameType::Data => {
            process_encrypted_application_frame(manager, &peer, header.frame_type, packet, now)
        }
        #[cfg(feature = "sensor")]
        FrameType::TimeSync | FrameType::EventAck => {
            process_encrypted_application_frame(manager, &peer, header.frame_type, packet, now)
        }
        #[cfg(feature = "gateway")]
        FrameType::TimeSyncRequest | FrameType::Event => {
            process_encrypted_application_frame(manager, &peer, header.frame_type, packet, now)
        }
        // handshake frames use MSG (wire capacity), not DATA (plaintext).
        #[cfg(feature = "gateway")]
        FrameType::InstallRequest => Ok((
            SigilEvent::InstallRequest {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "sensor")]
        FrameType::InstallChallenge => Ok((
            SigilEvent::InstallChallenge {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "gateway")]
        FrameType::InstallConfirm => Ok((
            SigilEvent::InstallConfirm {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "gateway")]
        FrameType::RenewRequest => Ok((
            SigilEvent::RenewRequest {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "sensor")]
        FrameType::RenewChallenge => Ok((
            SigilEvent::RenewChallenge {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "gateway")]
        FrameType::RenewAck => Ok((
            SigilEvent::RenewAck {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "gateway")]
        FrameType::ResumeRequest => Ok((
            SigilEvent::ResumeRequest {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "sensor")]
        FrameType::ResumeChallenge => Ok((
            SigilEvent::ResumeChallenge {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "gateway")]
        FrameType::ResumeConfirm => Ok((
            SigilEvent::ResumeConfirm {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        // CommitConfirmed frames are classified for host continue_*.
        #[cfg(feature = "sensor")]
        FrameType::InstallCommitConfirmed => Ok((
            SigilEvent::InstallCommitConfirmed {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "sensor")]
        FrameType::RenewCommitConfirmed => Ok((
            SigilEvent::RenewCommitConfirmed {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        #[cfg(feature = "sensor")]
        FrameType::ResumeCommitConfirmed => Ok((
            SigilEvent::ResumeCommitConfirmed {
                peer,
                frame: copy_packet::<MSG>(packet)?,
            },
            SigilAction::NeedsHostDispatch { peer },
        )),
        _ => Err(SigilError::InvalidStep { peer }),
    }
}

/// Bulk-copies a received packet into a fixed-capacity `Vec`.
/// Uses a single [`Vec::extend_from_slice`] instead of per-byte `push` so
/// capacity is checked once and the copy stays branch-light on Cortex-M.
fn copy_packet<const CAP: usize>(packet: &[u8]) -> Result<Vec<u8, CAP>, SigilError> {
    let mut frame = Vec::new();
    frame
        .extend_from_slice(packet)
        .map_err(|_| SigilError::CapacityExceeded)?;
    Ok(frame)
}

/// Processes an encrypted data frame: session lookup, expiry check, replay
/// protection, decryption. Returns the decrypted payload as `SigilEvent::Data`.
fn process_encrypted_application_frame<const N: usize, const DATA: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame_type: FrameType,
    packet: &[u8],
    now: u32,
) -> Result<(SigilEvent<DATA, MSG>, SigilAction<MSG>), SigilError> {
    // Look up session — unknown peer
    let session = manager
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;

    // Time synchronization is strictly gateway → sensor. The sender-side API
    // already requires Gateway; enforce the reciprocal role on reception too.
    #[cfg(feature = "sensor")]
    if frame_type == FrameType::TimeSync
        && session.role() != crate::core::session::SessionRole::Sensor
    {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    #[cfg(feature = "gateway")]
    if frame_type == FrameType::TimeSyncRequest
        && session.role() != crate::core::session::SessionRole::Gateway
    {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    #[cfg(feature = "gateway")]
    if frame_type == FrameType::Event
        && session.role() != crate::core::session::SessionRole::Gateway
    {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    #[cfg(feature = "sensor")]
    if frame_type == FrameType::EventAck
        && session.role() != crate::core::session::SessionRole::Sensor
    {
        return Err(SigilError::InvalidStep { peer: *peer });
    }

    // Check session key expiry (do not auto-renew)
    if !session.is_active(now) {
        return Err(SigilError::SessionExpired { peer: *peer });
    }

    // Frame too short for encrypted data
    if packet.len() < MIN_ENCRYPTED_FRAME {
        return Err(SigilError::ParseError);
    }

    // Extract prefix from wire (should match session nonce_prefix)
    let wire_prefix = &packet[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4];

    // Extract TX counter (sent as BE u64)
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&packet[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12]);
    let received_counter = u64::from_be_bytes(counter_bytes);

    // Ciphertext + tag is the remainder
    let ciphertext = &packet[OUTER_HEADER_SIZE + 12..];

    // Verify RX counter (replay protection).
    // `session.rx_counter` is already the next-expected value — do not add 1.
    let new_rx_counter = aead::verify_and_advance_rx_counter(session.rx_counter, received_counter)
        .map_err(|_| SigilError::Replay {
            peer: *peer,
            expected: session.rx_counter,
            received: received_counter,
        })?;

    // AAD = outer header from the received frame (binds peer + version + frame_type).
    let aad = aead::aad_from_frame(packet).ok_or(SigilError::ParseError)?;

    // Decrypt with key refs in a short scope, then advance RX.

    let mut payload: Vec<u8, DATA> = Vec::new();
    {
        let (session_key, nonce_prefix) = session.require_rx_material(peer)?;
        if wire_prefix != nonce_prefix.as_slice() {
            return Err(SigilError::ParseError);
        }
        aead::decrypt_into(
            session_key,
            nonce_prefix,
            received_counter,
            ciphertext,
            aad,
            &mut payload,
        )?;
    }
    session.rx_counter = new_rx_counter;
    #[cfg(feature = "gateway")]
    let last_rx_event_id = session.last_rx_event_id;
    #[cfg(feature = "sensor")]
    let pending_tx_event_id = session.pending_tx_event_id;
    #[cfg(feature = "gateway")]
    let pending_rx_event_id = session.pending_rx_event_id;
    #[cfg(feature = "gateway")]
    let last_time_sync_request_at = session.last_time_sync_request_at;

    // Authenticated traffic under the newly committed RX key proves
    // that the peer received CommitConfirmed. The gateway may now release its
    // cached commit state. WaitingForCommitConfirmed states are intentionally
    // excluded because their live session still uses the old key.
    #[cfg(feature = "gateway")]
    let peer_confirmed_commit = manager.get_pending(peer).is_some_and(|pending| {
        matches!(
            pending.step,
            crate::core::pending::HandshakeStep::InstallCommitSent
                | crate::core::pending::HandshakeStep::RenewCommitSent
                | crate::core::pending::HandshakeStep::ResumeCommitSent
        )
    });
    #[cfg(feature = "gateway")]
    if peer_confirmed_commit {
        let _ = manager.remove_pending(peer);
    }

    let event = match frame_type {
        FrameType::Data => SigilEvent::Data {
            peer: *peer,
            payload,
        },
        #[cfg(feature = "sensor")]
        FrameType::TimeSync => {
            if payload.len() != 10 {
                return Err(SigilError::ParseError);
            }
            let gateway_time = u32::from_be_bytes(
                payload[0..4]
                    .try_into()
                    .map_err(|_| SigilError::ParseError)?,
            );
            let sync_sequence = u32::from_be_bytes(
                payload[4..8]
                    .try_into()
                    .map_err(|_| SigilError::ParseError)?,
            );
            let uncertainty_secs = u16::from_be_bytes(
                payload[8..10]
                    .try_into()
                    .map_err(|_| SigilError::ParseError)?,
            );
            SigilEvent::TimeSync {
                peer: *peer,
                gateway_time,
                sync_sequence,
                uncertainty_secs,
            }
        }
        #[cfg(feature = "gateway")]
        FrameType::TimeSyncRequest => {
            if !payload.is_empty() {
                return Err(SigilError::ParseError);
            }
            if last_time_sync_request_at.is_some_and(|last| {
                now.saturating_sub(last) < TIME_SYNC_REQUEST_COOLDOWN_SECS
            }) {
                return Err(SigilError::RateLimited { peer: *peer });
            }
            manager
                .get_mut(peer)
                .ok_or(SigilError::UnknownSession { peer: *peer })?
                .last_time_sync_request_at = Some(now);
            SigilEvent::TimeSyncRequest { peer: *peer }
        }
        #[cfg(feature = "gateway")]
        FrameType::Event => {
            if payload.len() < EVENT_ID_SIZE {
                return Err(SigilError::ParseError);
            }
            let event_id = u64::from_be_bytes(
                payload[..EVENT_ID_SIZE]
                    .try_into()
                    .map_err(|_| SigilError::ParseError)?,
            );
            let already_committed = last_rx_event_id.is_some_and(|last| event_id <= last);
            if !already_committed {
                if let Some(pending) = pending_rx_event_id {
                    return Err(SigilError::EventDeliveryPending {
                        peer: *peer,
                        event_id: pending,
                    });
                }
                manager
                    .get_mut(peer)
                    .ok_or(SigilError::UnknownSession { peer: *peer })?
                    .pending_rx_event_id = Some(event_id);
            }
            let mut event_payload = Vec::<u8, DATA>::new();
            event_payload
                .extend_from_slice(&payload[EVENT_ID_SIZE..])
                .map_err(|_| SigilError::CapacityExceeded)?;

            return Ok((
                SigilEvent::Event {
                    peer: *peer,
                    event_id,
                    payload: event_payload,
                    duplicate: already_committed,
                },
                SigilAction::Success { peer: *peer },
            ));
        }
        #[cfg(feature = "sensor")]
        FrameType::EventAck => {
            if payload.len() != EVENT_ID_SIZE {
                return Err(SigilError::ParseError);
            }
            let event_id = u64::from_be_bytes(
                payload[..EVENT_ID_SIZE]
                    .try_into()
                    .map_err(|_| SigilError::ParseError)?,
            );
            if pending_tx_event_id != Some(event_id) {
                return Err(SigilError::UnexpectedEventAck {
                    peer: *peer,
                    event_id,
                });
            }
            manager
                .get_mut(peer)
                .ok_or(SigilError::UnknownSession { peer: *peer })?
                .pending_tx_event_id = None;
            SigilEvent::EventAck {
                peer: *peer,
                event_id,
            }
        }
        _ => return Err(SigilError::ParseError),
    };
    Ok((event, SigilAction::Success { peer: *peer }))
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
    encrypt_application_payload(manager, peer, FrameType::Data, plaintext, now)
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
    let session = manager
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Sensor {
        return Err(SigilError::InvalidStep { peer: *peer });
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

    let frame = encrypt_event_payload(manager, peer, event_id, plaintext, now)?;

    let session = manager
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
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
#[cfg(feature = "sensor")]
fn encrypt_event_payload<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    event_id: u64,
    plaintext: &[u8],
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let local = *manager.local_mac();
    let session = manager
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
        .map_err(|_| SigilError::CapacityExceeded)?;
    {
        let (session_key, nonce_prefix) = session.require_tx_material(peer)?;
        frame
            .extend_from_slice(nonce_prefix)
            .map_err(|_| SigilError::CapacityExceeded)?;
        frame
            .extend_from_slice(&tx_counter.to_be_bytes())
            .map_err(|_| SigilError::CapacityExceeded)?;
        let plaintext_start = frame.len();
        frame
            .extend_from_slice(&event_id.to_be_bytes())
            .map_err(|_| SigilError::CapacityExceeded)?;
        frame
            .extend_from_slice(plaintext)
            .map_err(|_| SigilError::CapacityExceeded)?;
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
    let session = manager
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.pending_tx_event_id != Some(event_id) {
        return Err(SigilError::UnexpectedEventAck {
            peer: *peer,
            event_id,
        });
    }
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
        return Err(SigilError::CapacityExceeded);
    }
    let session = manager
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Gateway {
        return Err(SigilError::InvalidStep { peer: *peer });
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
    let ack = encrypt_application_payload(
        manager,
        peer,
        FrameType::EventAck,
        &event_id.to_be_bytes(),
        now,
    )?;
    if committing_new {
        let session = manager
            .get_mut(peer)
            .ok_or(SigilError::UnknownSession { peer: *peer })?;
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
    let session = manager
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Gateway {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    if session.pending_rx_event_id != Some(event_id) {
        return Err(SigilError::UnexpectedEventDelivery {
            peer: *peer,
            event_id,
        });
    }
    session.pending_rx_event_id = None;
    Ok(())
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
    let session = manager
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Gateway {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    let mut body = [0u8; 10];
    body[0..4].copy_from_slice(&gateway_time.to_be_bytes());
    body[4..8].copy_from_slice(&sync_sequence.to_be_bytes());
    body[8..10].copy_from_slice(&uncertainty_secs.to_be_bytes());
    encrypt_application_payload(manager, peer, FrameType::TimeSync, &body, now)
}

/// Builds an authenticated request for a fresh gateway TimeSync sample.
#[cfg(feature = "sensor")]
pub(crate) fn request_time_sync_internal<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let session = manager
        .get(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;
    if session.role() != crate::core::session::SessionRole::Sensor {
        return Err(SigilError::InvalidStep { peer: *peer });
    }
    encrypt_application_payload(manager, peer, FrameType::TimeSyncRequest, &[], now)
}

fn encrypt_application_payload<const N: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame_type: FrameType,
    plaintext: &[u8],
    now: u32,
) -> Result<Vec<u8, MSG>, SigilError> {
    let local = *manager.local_mac();

    let session = manager
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;

    // Check if session is active and not expired
    if !session.is_active(now) {
        return Err(SigilError::SessionExpired { peer: *peer });
    }

    // Check TX counter for overflow
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
        .map_err(|_| SigilError::CapacityExceeded)?;

    {
        let (session_key, nonce_prefix) = session.require_tx_material(peer)?;
        frame
            .extend_from_slice(nonce_prefix)
            .map_err(|_| SigilError::CapacityExceeded)?;
        frame
            .extend_from_slice(&tx_counter.to_be_bytes())
            .map_err(|_| SigilError::CapacityExceeded)?;

        aead::encrypt_append(
            session_key,
            nonce_prefix,
            tx_counter,
            plaintext,
            &aad,
            &mut frame,
        )?;
    }

    // Advance TX counter on success
    session.tx_counter = next_tx_counter;

    Ok(frame)
}

mod tests;

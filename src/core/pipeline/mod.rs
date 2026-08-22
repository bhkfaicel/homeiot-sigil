//! Non-blocking packet processing pipeline
//!
//! This module provides the internal packet processing entry points used by
//! [`SessionManager`]. The public API
//! is exposed as methods on `SessionManager`; these functions are the
//! implementations behind those methods.
//!
//! # Internal layout
//!
//! The pipeline is split so that exactly **one** primitive performs the
//! authenticated, replay-checked ingress (`process_incoming_packet_internal`
//! plus `process_encrypted_application_frame` below): outer-header parse,
//! session lookup, per-frame-type direction checks, expiry check, AEAD open
//! with replay window, and the RX-counter advance all happen there and fail
//! closed. The semantic handlers in the cohesive submodules receive that
//! already-authenticated context and own only their domain state:
//!
//! - `data` — Data frames (stateless passthrough) and the
//!   single authenticated egress AEAD primitive shared by every builder;
//! - `event` — the Event/EventAck durable-delivery
//!   transaction (delivery stamp, ACK commit/release, retry state);
//! - `timesync` — clock samples and request cooldown.
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
//! `aead::encrypt_append` / `aead::decrypt_into` — no second 256-byte
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

use crate::core::aead;
#[cfg(feature = "gateway")]
use crate::core::aead::TAG_SIZE;
use crate::core::error::SigilError;
use crate::core::event::{SigilAction, SigilEvent};
#[cfg(feature = "gateway")]
use crate::core::frame::OUTER_HEADER_SIZE;
use crate::core::frame::{self, FrameType};
use crate::core::manager::SessionManager;
use crate::core::session::PeerId;
use heapless::Vec;

// Cohesive semantic handlers behind the pipeline surface: `data` owns Data
// plus the single authenticated TX AEAD primitive, `event` owns the
// Event/EventAck durable-delivery transaction, and `timesync` owns clock
// distribution. The RX-side authenticated ingress primitive (session lookup,
// direction checks, expiry, AEAD open, replay window, RX-counter advance,
// commit release) stays HERE in exactly one place; the submodules receive
// already-authenticated context and own only their domain mutations.
mod data;
mod event;
mod timesync;

// Facade implementations live in their cohesive submodules; the manager calls
// them through this module surface (`crate::core::pipeline::<name>`).
pub(crate) use data::encrypt_data_internal;
#[cfg(feature = "gateway")]
pub(crate) use event::{ack_event_internal, release_event_delivery_internal};
#[cfg(feature = "sensor")]
pub(crate) use event::{cancel_pending_event_internal, send_event_internal};
#[cfg(feature = "gateway")]
pub(crate) use timesync::encrypt_time_sync_internal;
#[cfg(feature = "sensor")]
pub(crate) use timesync::request_time_sync_internal;

/// Minimum wire size for a valid encrypted data frame:
/// 17 (peer) + 1 (version) + 1 (frame_type) + 4 (prefix) + 8 (counter) + 16 (tag) = 47 bytes.
#[cfg(feature = "gateway")]
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
    let header = frame::parse_header(packet).ok_or(SigilError::MalformedFrame)?;
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
        FrameType::RenewConfirm => Ok((
            SigilEvent::RenewConfirm {
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
        _ => Err(SigilError::WrongRole { peer }),
    }
}

/// Bulk-copies a received packet into a fixed-capacity `Vec`.
/// Uses a single [`Vec::extend_from_slice`] instead of per-byte `push` so
/// capacity is checked once and the copy stays branch-light on Cortex-M.
fn copy_packet<const CAP: usize>(packet: &[u8]) -> Result<Vec<u8, CAP>, SigilError> {
    let mut frame = Vec::new();
    frame
        .extend_from_slice(packet)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(frame)
}

/// The single authenticated, replay-checked ingress primitive for every
/// encrypted application/control frame (Data, Event/EventAck,
/// TimeSync/TimeSyncRequest).
///
/// Ordering (fail closed, in one place): session lookup → per-frame-type
/// direction checks → key expiry → AEAD open with the replay window. Only
/// after full authentication are the domain semantic handlers in [`data`],
/// [`event`], and [`timesync`] invoked with the decrypted payload plus the
/// pre-open state snapshots; they own only their domain mutations.
///
/// Mutation points owned here:
/// 1. the RX counter advance — only after successful AEAD verification, so a
///    tampered or replayed frame never consumes a counter value;
/// 2. the gateway commit release — authenticated traffic under the newly
///    committed RX key removes the cached commit-recovery pending entry.
fn process_encrypted_application_frame<const N: usize, const DATA: usize, const MSG: usize>(
    manager: &mut SessionManager<N>,
    peer: &PeerId,
    frame_type: FrameType,
    packet: &[u8],
    now: u32,
) -> Result<(SigilEvent<DATA, MSG>, SigilAction<MSG>), SigilError> {
    // Lend the storage capabilities once: every session / pending access below
    // goes through the narrow store view instead of manager internals.
    let mut stores = manager.protocol_stores();

    // Look up session — unknown peer
    let session = stores
        .sessions
        .get_mut(peer)
        .ok_or(SigilError::UnknownSession { peer: *peer })?;

    // Time synchronization is strictly gateway → sensor. The sender-side API
    // already requires Gateway; enforce the reciprocal role on reception too.
    #[cfg(feature = "sensor")]
    if frame_type == FrameType::TimeSync
        && session.role() != crate::core::session::SessionRole::Sensor
    {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    #[cfg(feature = "gateway")]
    if frame_type == FrameType::TimeSyncRequest
        && session.role() != crate::core::session::SessionRole::Gateway
    {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    #[cfg(feature = "gateway")]
    if frame_type == FrameType::Event
        && session.role() != crate::core::session::SessionRole::Gateway
    {
        return Err(SigilError::WrongRole { peer: *peer });
    }
    #[cfg(feature = "sensor")]
    if frame_type == FrameType::EventAck
        && session.role() != crate::core::session::SessionRole::Sensor
    {
        return Err(SigilError::WrongRole { peer: *peer });
    }

    // Check session key expiry (do not auto-renew)
    if !session.is_active(now) {
        return Err(SigilError::SessionExpired { peer: *peer });
    }

    let opened = {
        let (session_key, nonce_prefix) = session.require_rx_material(peer)?;
        aead::open_frame::<DATA>(
            peer,
            frame_type,
            packet,
            session_key,
            nonce_prefix,
            aead::RxCounterPolicy::Window {
                current: session.rx_counter,
            },
        )?
    };
    let payload = opened.plaintext;
    // Mutation point (1): advance the RX counter only after the frame fully
    // authenticated; every failure above returns with the old counter.
    session.rx_counter = opened.next_rx_counter;
    // Pre-open snapshots handed to the semantic handlers so they can decide
    // on exactly the state the authenticated frame was verified against.
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
    // cached commit state. Sensor post-Final states are intentionally
    // excluded because their live session still uses the old key.
    // Mutation point (2): release the commit-recovery pending entry. This has
    // no error path — removal of an absent entry is a no-op by construction.
    #[cfg(feature = "gateway")]
    let peer_confirmed_commit = stores
        .pending
        .get(peer)
        .is_some_and(|pending| pending.state().is_gateway_commit_sent());
    #[cfg(feature = "gateway")]
    if peer_confirmed_commit {
        let _ = stores.pending.remove(peer);
    }

    let event = match frame_type {
        FrameType::Data => data::handle_data_frame(*peer, payload),
        #[cfg(feature = "sensor")]
        FrameType::TimeSync => timesync::handle_time_sync_frame::<DATA, MSG>(peer, &payload)?,
        #[cfg(feature = "gateway")]
        FrameType::TimeSyncRequest => timesync::handle_time_sync_request_frame(
            &mut stores,
            peer,
            &payload,
            last_time_sync_request_at,
            now,
        )?,
        #[cfg(feature = "gateway")]
        FrameType::Event => event::handle_event_frame(
            &mut stores,
            peer,
            &payload,
            last_rx_event_id,
            pending_rx_event_id,
        )?,
        #[cfg(feature = "sensor")]
        FrameType::EventAck => {
            event::handle_event_ack_frame(&mut stores, peer, &payload, pending_tx_event_id)?
        }
        // Unreachable by construction: the authenticated ingress primitive
        // only dispatches the frame types whose direction checks passed.
        _ => return Err(SigilError::InvariantViolation),
    };
    Ok((event, SigilAction::Success { peer: *peer }))
}

mod tests;

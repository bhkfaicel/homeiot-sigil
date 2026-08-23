//! AEAD encryption and decryption with directional counters
//!
//! This module provides ChaCha20-Poly1305 AEAD encryption/decryption using
//! directional counters for nonce construction.
//!
//! Operations use [`AeadInPlace`] on caller-owned `heapless::Vec` buffers —
//! **no heap allocation** and **no extra intermediate 256-byte scratch** on
//! the hot paths (`encrypt_append` / `decrypt_into`). That keeps stack use
//! bounded on Cortex-M devices with a 4–8 KiB stack.
//!
//! **AAD policy:** every encrypted frame authenticates the clear-text outer
//! header as Additional Authenticated Data (19 bytes):
//!
//! ```text
//! AAD = peer_mac[17] ‖ protocol_version[1] ‖ frame_type[1]
//! ```
//!
//! That binds the ciphertext to its routing type and protocol version so an
//! attacker cannot flip e.g. `Data (0x00)` → `RenewRequest (0x11)` without
//! failing the Poly1305 tag.
//!
//! **Crate-internal**: host firmware should use [`crate::core::pipeline::encrypt_data`]
//! and [`crate::core::pipeline::process_incoming_packet`] instead of calling these
//! helpers directly.

use crate::core::error::SigilError;
use crate::core::frame::{FrameType, OUTER_HEADER_SIZE, build_header};
use crate::core::session::{NoncePrefix, PeerId, SessionKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag, aead::AeadInPlace};
use heapless::Vec;

/// Maximum ciphertext+tag capacity for the test-only [`encrypt`] / [`decrypt`]
/// helpers (LoRa-oriented full-frame budget).
/// Hot paths use [`encrypt_append`] / [`decrypt_into`] so the only large
/// buffer on the stack is the caller's output `Vec`.
#[cfg(test)]
pub(crate) const AEAD_BUF_CAP: usize = 256;

/// Nonce size in bytes (12 bytes for ChaCha20-Poly1305)
pub(crate) const NONCE_SIZE: usize = 12;

/// Tag size in bytes (16 bytes for Poly1305)
pub(crate) const TAG_SIZE: usize = 16;

/// AAD size in bytes (= outer header: peer MAC + protocol version + frame type)
pub(crate) const AAD_SIZE: usize = OUTER_HEADER_SIZE;

/// Stack budget for decrypting handshake plaintext (renew / resume bodies).
/// Renew/resume clear bodies are tens of bytes; 64 leaves headroom without
/// allocating a full 256-byte AEAD scratch alongside the output frame.
pub(crate) const HANDSHAKE_PLAINTEXT_CAP: usize = 64;

/// Builds the AEAD associated data for an encrypted frame.
/// AAD = `peer_mac ‖ protocol_version ‖ frame_type` (the clear-text outer header).
pub(crate) fn build_aad(peer: &PeerId, frame_type: FrameType) -> [u8; AAD_SIZE] {
    build_header(peer, frame_type)
}

/// Extracts AAD from a received frame (first [`OUTER_HEADER_SIZE`] bytes).
/// Returns `None` if the frame is shorter than the outer header.
pub(crate) fn aad_from_frame(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < OUTER_HEADER_SIZE {
        return None;
    }
    Some(&frame[..OUTER_HEADER_SIZE])
}

/// Constructs an AEAD nonce from prefix and counter
/// The nonce is constructed as: `prefix[4] || counter_be[8]`
/// where prefix is a 4-byte session-specific value and counter is an 8-byte
/// big-endian counter value.
/// # Arguments
/// * `prefix` - 4-byte nonce prefix
/// * `counter` - Counter value
///
/// # Returns
/// 12-byte nonce suitable for ChaCha20-Poly1305
pub(crate) fn build_nonce(prefix: &NoncePrefix, counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..4].copy_from_slice(prefix);
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Encrypts `plaintext` and **appends** `ciphertext ‖ tag` to `out`.
/// Encrypts in place in the newly appended region so callers can build the
/// clear-text outer header first, then append the AEAD payload into the
/// **same** `Vec` — avoiding a second large stack buffer.
/// # Errors
/// - `OutputBufferTooSmall` if `out` cannot hold `plaintext.len() + TAG_SIZE`
/// - `VerificationFailed` if the cipher reports an error
pub(crate) fn encrypt_append<const CAP: usize>(
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter: u64,
    plaintext: &[u8],
    associated_data: &[u8],
    out: &mut Vec<u8, CAP>,
) -> Result<(), SigilError> {
    let start = out.len();
    let need = plaintext.len().saturating_add(TAG_SIZE);
    if start.saturating_add(need) > CAP {
        return Err(SigilError::OutputBufferTooSmall);
    }

    out.extend_from_slice(plaintext)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from(build_nonce(prefix, counter));

    let tag = cipher
        .encrypt_in_place_detached(&nonce, associated_data, &mut out.as_mut_slice()[start..])
        .map_err(|_| SigilError::VerificationFailed)?;

    out.extend_from_slice(tag.as_slice())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(())
}

/// Encrypts the already-appended plaintext tail `out[plaintext_start..]` and
/// appends its detached tag. This lets callers assemble a small structured
/// plaintext directly in the final frame without allocating a second
/// `heapless::Vec` on constrained targets.
#[cfg(feature = "sensor")]
pub(crate) fn encrypt_tail_in_place<const CAP: usize>(
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter: u64,
    plaintext_start: usize,
    associated_data: &[u8],
    out: &mut Vec<u8, CAP>,
) -> Result<(), SigilError> {
    if plaintext_start > out.len() || out.len().saturating_add(TAG_SIZE) > CAP {
        return Err(SigilError::OutputBufferTooSmall);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from(build_nonce(prefix, counter));
    let tag = cipher
        .encrypt_in_place_detached(
            &nonce,
            associated_data,
            &mut out.as_mut_slice()[plaintext_start..],
        )
        .map_err(|_| SigilError::VerificationFailed)?;
    out.extend_from_slice(tag.as_slice())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    Ok(())
}

/// Decrypts `ciphertext ‖ tag` **into** `out` (replacing prior contents).
/// Copies the ciphertext body into `out`, authenticates/decrypts in place,
/// and leaves only the plaintext. Callers pass their final destination buffer
/// (e.g. `SigilEvent::Data` payload) so no intermediate AEAD scratch is needed.
/// # Errors
/// - `VerificationFailed` if the tag is missing/invalid or authentication fails
/// - `OutputBufferTooSmall` if the plaintext cannot fit in `out`
pub(crate) fn decrypt_into<const CAP: usize>(
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter: u64,
    ciphertext: &[u8],
    associated_data: &[u8],
    out: &mut Vec<u8, CAP>,
) -> Result<(), SigilError> {
    if ciphertext.len() < TAG_SIZE {
        return Err(SigilError::VerificationFailed);
    }

    let (msg, tag_bytes) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
    if msg.len() > CAP {
        return Err(SigilError::OutputBufferTooSmall);
    }

    out.clear();
    out.extend_from_slice(msg)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from(build_nonce(prefix, counter));
    let tag = Tag::from_slice(tag_bytes);

    cipher
        .decrypt_in_place_detached(&nonce, associated_data, out.as_mut_slice(), tag)
        .map_err(|_| SigilError::VerificationFailed)?;
    Ok(())
}

/// Counter acceptance policy used by [`open_frame`].
pub(crate) enum RxCounterPolicy {
    /// Normal session traffic: accept the current watermark or a bounded gap.
    Window { current: u64 },
    /// Commit-boundary traffic whose protocol requires one exact counter.
    #[cfg(feature = "gateway")]
    Exact { expected: u64 },
}

/// Authenticated result returned by [`open_frame`]. The caller commits
/// `next_rx_counter` only after all message-specific validation succeeds.
pub(crate) struct OpenedFrame<const CAP: usize> {
    pub plaintext: Vec<u8, CAP>,
    pub next_rx_counter: u64,
}

/// Parses and authenticates one encrypted Sigil frame without mutating session
/// state. This is the single policy point for outer identity/type validation,
/// nonce-prefix matching, replay checks, AAD selection and AEAD decryption.
pub(crate) fn open_frame<const CAP: usize>(
    peer: &PeerId,
    expected_type: FrameType,
    frame: &[u8],
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter_policy: RxCounterPolicy,
) -> Result<OpenedFrame<CAP>, SigilError> {
    let min_len = OUTER_HEADER_SIZE + NONCE_SIZE + TAG_SIZE;
    if frame.len() < min_len {
        return Err(SigilError::MalformedFrame);
    }
    let header = crate::core::frame::parse_header(frame).ok_or(SigilError::MalformedFrame)?;
    if header.peer != *peer || header.frame_type != expected_type {
        return Err(SigilError::MalformedFrame);
    }

    let wire_prefix: &[u8; 4] = frame[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4]
        .try_into()
        .map_err(|_| SigilError::MalformedFrame)?;
    if wire_prefix != prefix {
        return Err(SigilError::MalformedFrame);
    }

    let received_counter = u64::from_be_bytes(
        frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + NONCE_SIZE]
            .try_into()
            .map_err(|_| SigilError::MalformedFrame)?,
    );
    let next_rx_counter = match counter_policy {
        RxCounterPolicy::Window { current } => verify_and_advance_rx_counter(
            current,
            received_counter,
        )
        .map_err(|error| match error {
            SigilError::CounterExhausted { .. } => SigilError::CounterExhausted { peer: *peer },
            _ => SigilError::Replay {
                peer: *peer,
                expected: current,
                received: received_counter,
            },
        })?,
        #[cfg(feature = "gateway")]
        RxCounterPolicy::Exact { expected } => {
            if received_counter != expected {
                return Err(SigilError::Replay {
                    peer: *peer,
                    expected,
                    received: received_counter,
                });
            }
            expected
                .checked_add(1)
                .ok_or(SigilError::CounterExhausted { peer: *peer })?
        }
    };

    let mut plaintext = Vec::new();
    decrypt_into(
        key,
        prefix,
        received_counter,
        &frame[OUTER_HEADER_SIZE + NONCE_SIZE..],
        aad_from_frame(frame).ok_or(SigilError::MalformedFrame)?,
        &mut plaintext,
    )?;
    Ok(OpenedFrame {
        plaintext,
        next_rx_counter,
    })
}

/// Encrypts plaintext using ChaCha20-Poly1305 AEAD (test convenience wrapper).
/// Production paths use [`encrypt_append`] to avoid an extra stack buffer.
/// # Errors
/// - `OutputBufferTooSmall` if `plaintext.len() + TAG_SIZE > 256`
/// - `VerificationFailed` if the cipher reports an error
#[cfg(test)]
pub(crate) fn encrypt(
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter: u64,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8, AEAD_BUF_CAP>, SigilError> {
    let mut buffer = Vec::<u8, AEAD_BUF_CAP>::new();
    encrypt_append(
        key,
        prefix,
        counter,
        plaintext,
        associated_data,
        &mut buffer,
    )?;
    Ok(buffer)
}

/// Decrypts ciphertext using ChaCha20-Poly1305 AEAD (test convenience wrapper).
/// Production paths use [`decrypt_into`] to avoid an extra stack buffer.
/// # Errors
/// Returns `SigilError::VerificationFailed` if authentication fails (wrong key,
/// wrong nonce, or AAD mismatch such as a flipped `frame_type`)
#[cfg(test)]
pub(crate) fn decrypt(
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter: u64,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8, AEAD_BUF_CAP>, SigilError> {
    let mut buffer = Vec::<u8, AEAD_BUF_CAP>::new();
    decrypt_into(
        key,
        prefix,
        counter,
        ciphertext,
        associated_data,
        &mut buffer,
    )?;
    Ok(buffer)
}

/// Maximum allowed gap between the next-expected RX counter and a received
/// counter (inclusive of the expected value itself as a zero-sized gap).
/// A packet is accepted when
/// `expected <= received <= expected + RX_COUNTER_MAX_GAP`.
/// This tolerates lost LoRa frames while preventing an attacker who already
/// holds the session key from jumping the counter near `u64::MAX` and
/// exhausting the nonce space (DoS until renew/resume).
pub const RX_COUNTER_MAX_GAP: u64 = 256;

/// Verifies and advances the RX counter for replay protection
/// # Policy
/// `current_rx_counter` represents the **next expected** inbound counter value
/// (i.e. last accepted + 1; starts at 0 after key establishment).
/// - Accept if `current_rx_counter <= received_counter <= current_rx_counter + RX_COUNTER_MAX_GAP`
///   (allows limited packet gaps).
/// - Reject if `received_counter < current_rx_counter` (replay / non-monotonic).
/// - Reject if `received_counter > current_rx_counter + RX_COUNTER_MAX_GAP` (gap too large).
/// - Reject if `received_counter == u64::MAX` — advancing would wrap; same
///   semantics as [`check_tx_counter`] → [`SigilError::CounterExhausted`].
/// - On accept, the new RX counter becomes `received_counter + 1`.
///
/// # Arguments
/// * `current_rx_counter` - Next expected counter value
/// * `received_counter` - Counter value from received packet
///
/// # Returns
/// `Ok(new_rx_counter)` (= `received_counter + 1`) if accepted,
/// `Err(SigilError::Replay)` if the counter is stale, non-monotonic, or
/// beyond the allowed gap window,
/// `Err(SigilError::CounterExhausted)` if accepting would wrap past `u64::MAX`.
pub(crate) fn verify_and_advance_rx_counter(
    current_rx_counter: u64,
    received_counter: u64,
) -> Result<u64, SigilError> {
    if received_counter < current_rx_counter {
        return Err(SigilError::Replay {
            peer: [0u8; 17], // Placeholder, caller should fill in
            expected: current_rx_counter,
            received: received_counter,
        });
    }

    let max_allowed = current_rx_counter.saturating_add(RX_COUNTER_MAX_GAP);
    if received_counter > max_allowed {
        return Err(SigilError::Replay {
            peer: [0u8; 17],
            expected: current_rx_counter,
            received: received_counter,
        });
    }

    // mirror TX — never wrap the RX watermark at u64::MAX.
    received_counter
        .checked_add(1)
        .ok_or(SigilError::CounterExhausted { peer: [0u8; 17] })
}

/// Checks if TX counter would overflow
/// # Arguments
/// * `current_tx_counter` - Current TX counter value
///
/// # Returns
/// `Ok(advanced_counter)` if safe to increment, `Err(SigilError::CounterExhausted)` if overflow would occur
pub(crate) fn check_tx_counter(current_tx_counter: u64) -> Result<u64, SigilError> {
    if current_tx_counter == u64::MAX {
        return Err(SigilError::CounterExhausted {
            peer: [0u8; 17], // Placeholder, caller should fill in
        });
    }

    Ok(current_tx_counter + 1)
}

/// Builds a CommitConfirmed frame (AEAD under the new directional key).
/// Layout: outer header ‖ nonce_prefix ‖ counter_be ‖ ciphertext+tag.
/// Plaintext body is empty; AAD = outer header. First CommitConfirmed uses
/// counter `0` under the gateway TX (g2s) half after Final commit.
#[cfg(feature = "gateway")]
pub(crate) fn build_commit_confirmed_frame<const MSG: usize>(
    local_mac: &PeerId,
    frame_type: FrameType,
    key: &SessionKey,
    prefix: &NoncePrefix,
    counter: u64,
) -> Result<heapless::Vec<u8, MSG>, SigilError> {
    debug_assert!(
        matches!(
            frame_type,
            FrameType::InstallCommitConfirmed
                | FrameType::RenewCommitConfirmed
                | FrameType::ResumeCommitConfirmed
        ),
        "frame_type must be a CommitConfirmed variant"
    );
    let aad = build_aad(local_mac, frame_type);
    let mut frame: heapless::Vec<u8, MSG> = heapless::Vec::new();
    let header = build_header(local_mac, frame_type);
    frame
        .extend_from_slice(&header)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(prefix)
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    frame
        .extend_from_slice(&counter.to_be_bytes())
        .map_err(|_| SigilError::OutputBufferTooSmall)?;
    encrypt_append(key, prefix, counter, &[], &aad, &mut frame)?;
    Ok(frame)
}

/// Verifies a CommitConfirmed frame under staged / new directional keys.
/// Expects counter `0` and an empty plaintext body. Does **not** advance any
/// session counter — the caller commits keys afterwards.
#[cfg(feature = "sensor")]
pub(crate) fn verify_commit_confirmed(
    frame: &[u8],
    expected_type: FrameType,
    key: &SessionKey,
    prefix: &NoncePrefix,
) -> Result<(), SigilError> {
    use crate::core::frame::{FRAME_TYPE_OFFSET, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET};

    if frame.len() < OUTER_HEADER_SIZE + 4 + 8 + TAG_SIZE {
        return Err(SigilError::MalformedFrame);
    }
    if frame[PROTOCOL_VERSION_OFFSET] != PROTOCOL_VERSION
        || frame[FRAME_TYPE_OFFSET] != expected_type as u8
    {
        return Err(SigilError::MalformedFrame);
    }
    let wire_prefix: &[u8; 4] = frame[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4]
        .try_into()
        .map_err(|_| SigilError::MalformedFrame)?;
    if wire_prefix != prefix {
        return Err(SigilError::MalformedFrame);
    }
    let mut counter_bytes = [0u8; 8];
    counter_bytes.copy_from_slice(&frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12]);
    let received_counter = u64::from_be_bytes(counter_bytes);
    if received_counter != 0 {
        return Err(SigilError::Replay {
            peer: [0u8; 17],
            expected: 0,
            received: received_counter,
        });
    }
    let mut plaintext: heapless::Vec<u8, HANDSHAKE_PLAINTEXT_CAP> = heapless::Vec::new();
    decrypt_into(
        key,
        prefix,
        0,
        &frame[OUTER_HEADER_SIZE + 12..],
        aad_from_frame(frame).ok_or(SigilError::MalformedFrame)?,
        &mut plaintext,
    )?;
    if !plaintext.is_empty() {
        return Err(SigilError::VerificationFailed);
    }
    Ok(())
}

mod tests;

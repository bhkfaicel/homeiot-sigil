//! HKDF session key derivation helpers
//!
//! This module provides utilities for deriving session keys using HKDF.
//!
//! **Crate-internal**: called by install / renew / resume after ECDH, not by host firmware.
//!
//! # Directional AEAD material
//!
//! Session traffic keys are **not** shared between directions. After ECDH,
//! [`derive_directional_session_keys`] expands 72 bytes of OKM:
//!
//! ```text
//! s2g_key[32] ‖ s2g_prefix[4] ‖ g2s_key[32] ‖ g2s_prefix[4]
//! ```
//!
//! Sensor TX / gateway RX use the `s2g_*` half; gateway TX / sensor RX use
//! `g2s_*`. That prevents both peers from encrypting under the same
//! `(key, nonce)` when both TX counters start at 0.
//!
//! [`derive_session_key`] remains for non-AEAD uses (resume PSK / MAC OKM).

use crate::core::error::SigilError;
use crate::core::session::{DirectionalMaterial, NoncePrefix, SessionKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Session key size in bytes (32 bytes for ChaCha20-Poly1305)
pub(crate) const SESSION_KEY_SIZE: usize = 32;

/// Nonce prefix size in bytes (4 bytes)
pub(crate) const NONCE_PREFIX_SIZE: usize = 4;

/// Bytes expanded for one direction (key + prefix).
pub(crate) const DIRECTIONAL_HALF_SIZE: usize = SESSION_KEY_SIZE + NONCE_PREFIX_SIZE;

/// Bytes expanded for both AEAD directions.
pub(crate) const DIRECTIONAL_OKM_SIZE: usize = DIRECTIONAL_HALF_SIZE * 2;

/// Derives a single 32-byte key + 4-byte prefix (non-directional helpers).
/// Used for resume PSK / MAC material — **not** for session AEAD keys.
pub(crate) fn derive_session_key(
    shared_secret: &[u8; 32],
    context: Option<&[u8]>,
) -> Result<(SessionKey, NoncePrefix), SigilError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);

    let mut okm = [0u8; DIRECTIONAL_HALF_SIZE];
    hk.expand(context.unwrap_or(b""), &mut okm)
.map_err(|_| SigilError::EcdhFailed)?;

    let mut session_key = [0u8; SESSION_KEY_SIZE];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_SIZE];

    session_key.copy_from_slice(&okm[0..SESSION_KEY_SIZE]);
    nonce_prefix.copy_from_slice(&okm[SESSION_KEY_SIZE..]);
    okm.zeroize();

    Ok((session_key, nonce_prefix))
}

/// Derives independent sensor→gateway and gateway→sensor AEAD material.
/// `context` is the handshake-specific HKDF info (install / renew / resume).
/// Both directions share that transcript binding; separation is in the OKM layout.
pub(crate) fn derive_directional_session_keys(
    shared_secret: &[u8; 32],
    context: Option<&[u8]>,
) -> Result<DirectionalMaterial, SigilError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);

    let mut okm = [0u8; DIRECTIONAL_OKM_SIZE];
    hk.expand(context.unwrap_or(b""), &mut okm)
.map_err(|_| SigilError::EcdhFailed)?;

    let mut s2g_key = [0u8; SESSION_KEY_SIZE];
    let mut s2g_prefix = [0u8; NONCE_PREFIX_SIZE];
    let mut g2s_key = [0u8; SESSION_KEY_SIZE];
    let mut g2s_prefix = [0u8; NONCE_PREFIX_SIZE];

    s2g_key.copy_from_slice(&okm[0..SESSION_KEY_SIZE]);
    s2g_prefix.copy_from_slice(&okm[SESSION_KEY_SIZE..DIRECTIONAL_HALF_SIZE]);
    g2s_key.copy_from_slice(&okm[DIRECTIONAL_HALF_SIZE..DIRECTIONAL_HALF_SIZE + SESSION_KEY_SIZE]);
    g2s_prefix.copy_from_slice(&okm[DIRECTIONAL_HALF_SIZE + SESSION_KEY_SIZE..]);
    okm.zeroize();

    Ok(DirectionalMaterial {
        s2g_key,
        s2g_prefix,
        g2s_key,
        g2s_prefix,
    })
}

/// Derives a session key from an ECDH shared secret with explicit info
#[allow(dead_code)]
pub(crate) fn derive_with_info(
    shared_secret: &[u8; 32],
    info: &[u8],
) -> Result<(SessionKey, NoncePrefix), SigilError> {
    derive_session_key(shared_secret, Some(info))
}

mod tests;

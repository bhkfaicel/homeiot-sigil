//! Software ephemeral ECDH using X25519 (Curve25519)
//!
//! Used for **renew** only: ephemeral↔ephemeral key agreement without the
//! secure element. Install / resume keep P-256 via [`SecureElement`].
//!
//! # Critical: private scalar length and RFC 7748 clamping
//!
//! The X25519 private key material **must be exactly 32 bytes** of host RNG
//! output — never 31 (truncated) and never 33 (padded). Shorter entropy
//! collapses security; longer / padded material can introduce bias.
//!
//! After filling 32 random bytes, this module applies the mandatory
//! [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) clamp:
//!
//! ```text
//! s[0]  &= 248;   // clear bits 0,1,2
//! s[31] &= 127;   // clear bit 255
//! s[31] |= 64;    // set bit 254
//! ```
//!
//! Those bit forces are **required** for X25519 (small-subgroup / cofactor
//! safety). Do **not** skip clamping. What must never happen is generating
//! the wrong **byte length** from [`RandomSource`].

use crate::core::error::SigilError;
use zeroize::Zeroize;

/// ECDH shared secret size (32 bytes for X25519)
pub(crate) const SHARED_SECRET_SIZE: usize = 32;

/// X25519 public key size (32 bytes, little-endian u-coordinate)
pub(crate) const PUBLIC_KEY_SIZE: usize = 32;

/// Private scalar / seed size — **must** be exactly 32 bytes from the RNG.
pub(crate) const PRIVATE_KEY_SIZE: usize = 32;

/// Max attempts when the host RNG returns an all-zero buffer (degenerate).
const SCALAR_GEN_ATTEMPTS: usize = 64;

/// Applies RFC 7748 §5 clamping in place on a 32-byte X25519 private key.
/// This deliberately clears/sets specific bits — that is part of the X25519
/// definition, not optional “padding cleanup”.
pub(crate) fn clamp_x25519_scalar(scalar: &mut [u8; PRIVATE_KEY_SIZE]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Returns `true` if every byte is zero (unusable as raw entropy).
fn is_all_zero(buf: &[u8; PRIVATE_KEY_SIZE]) -> bool {
    let mut acc = 0u8;
    for b in buf {
        acc |= *b;
    }
    acc == 0
}

/// Generates a clamped 32-byte X25519 ephemeral private key.
/// # Security rules
/// 1. Calls [`RandomSource::fill_bytes`] on a `[u8; 32]` — the slice length is
///    fixed at 32 so the host cannot silently supply 31 or 33 bytes through
///    this API.
/// 2. Rejects an all-zero fill and retries (up to [`SCALAR_GEN_ATTEMPTS`]).
/// 3. Applies [`clamp_x25519_scalar`] before returning.
///
/// Host RNG errors propagate as [`SigilError::RandomFailed`].
pub(crate) fn generate_ephemeral_scalar<R>(
    rng: &mut R,
) -> Result<[u8; PRIVATE_KEY_SIZE], SigilError>
where
    R: crate::core::traits::RandomSource,
{
    for _ in 0..SCALAR_GEN_ATTEMPTS {
        let mut bytes = [0u8; PRIVATE_KEY_SIZE];
        rng.fill_bytes(&mut bytes)?;
        if is_all_zero(&bytes) {
            bytes.zeroize();
            continue;
        }
        clamp_x25519_scalar(&mut bytes);
        return Ok(bytes);
    }
    Err(SigilError::RandomFailed)
}

/// Generates an ephemeral key pair (clamped scalar + 32-byte public key).
#[allow(dead_code)]
pub(crate) fn generate_ephemeral_keypair<R>(
    rng: &mut R,
) -> Result<([u8; PRIVATE_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]), SigilError>
where
    R: crate::core::traits::RandomSource,
{
    let scalar = generate_ephemeral_scalar(rng)?;
    let pubkey = pubkey_from_scalar(&scalar)?;
    Ok((scalar, pubkey))
}

/// Performs X25519 ECDH: `scalar × peer_pubkey` → 32-byte shared secret.
/// `scalar` must already be RFC 7748-clamped (as produced by
/// [`generate_ephemeral_scalar`]). `peer_pubkey` is a raw 32-byte X25519
/// public key.
/// Rejects a non-contributory / all-zero shared secret (low-order peer point)
/// with [`SigilError::EcdhFailed`].
pub(crate) fn ecdh_from_scalar(
    scalar: &[u8; PRIVATE_KEY_SIZE],
    peer_pubkey_bytes: &[u8; PUBLIC_KEY_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], SigilError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(*scalar);
    let peer = PublicKey::from(*peer_pubkey_bytes);
    let shared = secret.diffie_hellman(&peer);
    if !shared.was_contributory() || is_all_zero(shared.as_bytes()) {
        return Err(SigilError::EcdhFailed);
    }
    let mut out = [0u8; SHARED_SECRET_SIZE];
    out.copy_from_slice(shared.as_bytes());
    Ok(out)
}

/// Alias kept for older call sites / tests — same as [`ecdh_from_scalar`].
#[allow(dead_code)]
pub(crate) fn ecdh_ephemeral(
    eph_secret: &[u8; PRIVATE_KEY_SIZE],
    peer_pubkey_bytes: &[u8; PUBLIC_KEY_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], SigilError> {
    ecdh_from_scalar(eph_secret, peer_pubkey_bytes)
}

/// Derives the 32-byte X25519 public key from a clamped private scalar.
pub(crate) fn pubkey_from_scalar(
    scalar: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_SIZE], SigilError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(*scalar);
    let public = PublicKey::from(&secret);
    Ok(*public.as_bytes())
}

/// Zeroizes an ephemeral secret buffer.
pub(crate) fn zeroize_secret(secret: &mut [u8; PRIVATE_KEY_SIZE]) {
    secret.zeroize();
}

mod tests;

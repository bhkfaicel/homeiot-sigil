//! Zeroizing stack buffers for temporary cryptographic secrets.
//!
//! Handshake paths often take `shared` / key copies then call fallible helpers
//! (`?`). Manual `zeroize()` after a successful sequence leaves the secret on
//! the stack when an earlier step fails. Wrapping bytes in [`SecretBytes`]
//! clears them on **every** drop (success or error).

use core::ops::Deref;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::error::SigilError;

/// Fixed-size secret wiped when dropped.
/// Prefer this over a bare `[u8; N]` for ECDH shared secrets and short-lived
/// session-key copies that outlive a borrow across fallible work.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Wraps raw bytes; they are cleared when this value is dropped.
    #[inline]
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow as a fixed-size array (for HKDF / AEAD APIs).
    #[inline]
    pub(crate) fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8; N]> for SecretBytes<N> {
    #[inline]
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretBytes<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// 32-byte ECDH shared secret or session-key copy.
pub(crate) type SharedSecretBuf = SecretBytes<32>;

/// Validates and wraps a provider-produced ECDH shared secret.
///
/// A null result is never valid for the P-256 exchanges used by Sigil. Reject
/// it at the protocol boundary even when the host provider claims to validate
/// peer points, so Install, Renew and Resume all fail closed consistently.
pub(crate) fn validated_ecdh_shared_secret(
    mut shared: [u8; 32],
) -> Result<SharedSecretBuf, SigilError> {
    if shared.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        shared.zeroize();
        return Err(SigilError::EcdhFailed);
    }
    Ok(SharedSecretBuf::new(shared))
}

/// 4-byte nonce-prefix copy used while constructing Renew frames.
pub(crate) type NoncePrefixBuf = SecretBytes<4>;

#[cfg(test)]
mod tests;

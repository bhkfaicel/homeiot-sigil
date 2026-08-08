//! Zeroizing stack buffers for temporary cryptographic secrets.
//!
//! Handshake paths often take `shared` / key copies then call fallible helpers
//! (`?`). Manual `zeroize()` after a successful sequence leaves the secret on
//! the stack when an earlier step fails. Wrapping bytes in [`SecretBytes`]
//! clears them on **every** drop (success or error).

use core::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// 4-byte nonce-prefix copy (renew gateway challenge encrypt).
#[cfg(any(feature = "gateway", test))]
pub(crate) type NoncePrefixBuf = SecretBytes<4>;

#[cfg(test)]
mod tests;

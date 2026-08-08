#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for [`super::SecretBytes`].

use super::{NoncePrefixBuf, SecretBytes, SharedSecretBuf};

#[test]
fn test_secret_bytes_as_array_and_deref() {
    let s = SecretBytes::new([1u8; 4]);
    assert_eq!(s.as_array(), &[1u8; 4]);
    assert_eq!(&*s, &[1u8; 4]);
    assert_eq!(AsRef::<[u8]>::as_ref(&s), &[1u8; 4][..]);
}

#[test]
fn test_secret_bytes_drop_path() {
    // Exercise ZeroizeOnDrop: construct typed aliases, drop at end of scope.
    // Portably observing wiped SRAM is not reliable; the derive + Drop path is
    // what requires (same approach as Session zeroize tests).
    {
        let shared = SharedSecretBuf::new([0xABu8; 32]);
        let prefix = NoncePrefixBuf::new([0xCDu8; 4]);
        assert_eq!(shared.as_array()[0], 0xAB);
        assert_eq!(prefix.as_array()[0], 0xCD);
        drop(shared);
        drop(prefix);
    }
}

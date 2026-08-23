#![cfg(test)]

//! Unit tests for HKDF session key derivation

use crate::core::derive::{
    NONCE_PREFIX_SIZE, SESSION_KEY_SIZE, derive_directional_session_keys, derive_session_key,
    derive_with_info,
};

#[test]
fn test_derive_session_key() {
    let shared_secret = [0x42u8; 32];

    let (session_key, nonce_prefix) = derive_session_key(&shared_secret, None).unwrap();

    // Verify sizes
    assert_eq!(session_key.len(), SESSION_KEY_SIZE);
    assert_eq!(nonce_prefix.len(), NONCE_PREFIX_SIZE);

    // Verify deterministic output
    let (session_key2, nonce_prefix2) = derive_session_key(&shared_secret, None).unwrap();
    assert_eq!(session_key, session_key2);
    assert_eq!(nonce_prefix, nonce_prefix2);
}

#[test]
fn test_derive_directional_session_keys() {
    // OKM expands to independent s2g / g2s halves.

    let shared = [0x42u8; 32];
    let m = derive_directional_session_keys(&shared, Some(b"sigil-test")).unwrap();
    assert_ne!(m.s2g_key, m.g2s_key);
    assert_ne!(m.s2g_prefix, m.g2s_prefix);
    let m2 = derive_directional_session_keys(&shared, Some(b"sigil-test")).unwrap();
    assert_eq!(m.s2g_key, m2.s2g_key);
    assert_eq!(m.g2s_key, m2.g2s_key);
    assert_eq!(m.s2g_key.len(), SESSION_KEY_SIZE);
    assert_eq!(m.s2g_prefix.len(), NONCE_PREFIX_SIZE);
}

#[test]
fn test_derive_with_info() {
    let shared_secret = [0x42u8; 32];

    let (key1, prefix1) = derive_with_info(&shared_secret, b"context1").unwrap();
    let (key2, prefix2) = derive_with_info(&shared_secret, b"context2").unwrap();

    // Different context should produce different keys
    assert_ne!(key1, key2);
    assert_ne!(prefix1, prefix2);
}

#[test]
fn test_derive_different_secrets() {
    let secret1 = [0x42u8; 32];
    let secret2 = [0x43u8; 32];

    let (key1, prefix1) = derive_session_key(&secret1, None).unwrap();
    let (key2, prefix2) = derive_session_key(&secret2, None).unwrap();

    assert_ne!(key1, key2);
    assert_ne!(prefix1, prefix2);
}

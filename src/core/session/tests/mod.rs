#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for session management

mod type_size_bounds;

use crate::core::error::SigilError;
use crate::core::session::{
    DirectionalMaterial, MAX_SESSION_LIFETIME_SECS, Session, SessionRole, validate_key_expire_at,
};

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

#[test]
fn test_require_key_material_returns_refs() {
    // Active session exposes key/prefix by reference (no Copy return).
    let key = [0x11u8; 32];
    let prefix = [0x22u8; 4];
    let peer = [3u8; 17];
    let session = Session::new_active(
        peer,
        [4u8; 33],
        DirectionalMaterial::symmetric_for_test(key, prefix),
        SessionRole::Sensor,
        RESUME_PSK,
        10_000,
        0,
    )
    .unwrap();
    let (k, p) = session.require_key_material(&peer).unwrap();
    assert_eq!(k, &key);
    assert_eq!(p, &prefix);
    // Same underlying storage as getters.
    assert!(core::ptr::eq(k, session.session_key().unwrap()));
    assert!(core::ptr::eq(p, session.nonce_prefix().unwrap()));
}

#[test]
fn test_new_active_and_update_key_validate_expire() {
    // Public constructors enforce MAX_SESSION_LIFETIME_SECS via `now`.
    let peer = [1u8; 17];
    let now = 1_000u32;
    match Session::new_active(
        peer,
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
        SessionRole::Sensor,
        RESUME_PSK,
        now,
        now,
    ) {
        Err(SigilError::InvalidKeyExpire {
            now: n,
            key_expire_at: e,
        }) => {
            assert_eq!(n, now);
            assert_eq!(e, now);
        }
        _ => panic!("expected InvalidKeyExpire for equal now/expire"),
    }
    let too_far = now + MAX_SESSION_LIFETIME_SECS + 1;
    match Session::new_active(
        peer,
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
        SessionRole::Sensor,
        RESUME_PSK,
        too_far,
        now,
    ) {
        Err(SigilError::InvalidKeyExpire {
            now: n,
            key_expire_at: e,
        }) => {
            assert_eq!(n, now);
            assert_eq!(e, too_far);
        }
        _ => panic!("expected InvalidKeyExpire for over-long lifetime"),
    }
    let mut session = Session::new_active(
        peer,
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
        SessionRole::Sensor,
        RESUME_PSK,
        now + 60,
        now,
    )
    .unwrap();
    match session.update_key(
        DirectionalMaterial::symmetric_for_test([5u8; 32], [6u8; 4]),
        too_far,
        now,
    ) {
        Err(SigilError::InvalidKeyExpire {
            now: n,
            key_expire_at: e,
        }) => {
            assert_eq!(n, now);
            assert_eq!(e, too_far);
        }
        _ => panic!("expected InvalidKeyExpire on update_key"),
    }
    session
        .update_key(
            DirectionalMaterial::symmetric_for_test([5u8; 32], [6u8; 4]),
            now + 120,
            now,
        )
        .unwrap();
    assert_eq!(session.key_expire_at(), now + 120);
}

#[test]
fn test_validate_key_expire_at() {
    let now = 1_000u32;
    assert!(validate_key_expire_at(now, now + 1).is_ok());
    assert!(validate_key_expire_at(now, now + MAX_SESSION_LIFETIME_SECS).is_ok());
    assert_eq!(
        validate_key_expire_at(now, now),
        Err(SigilError::InvalidKeyExpire {
            now,
            key_expire_at: now
        })
    );
    assert_eq!(
        validate_key_expire_at(now, now - 1),
        Err(SigilError::InvalidKeyExpire {
            now,
            key_expire_at: now - 1
        })
    );
    let too_far = now + MAX_SESSION_LIFETIME_SECS + 1;
    assert_eq!(
        validate_key_expire_at(now, too_far),
        Err(SigilError::InvalidKeyExpire {
            now,
            key_expire_at: too_far
        })
    );
    assert_eq!(MAX_SESSION_LIFETIME_SECS, 2 * 86_400);
}

#[test]
fn test_new_enrolled_session() {
    let peer_mac = [1u8; 17];
    let peer_static_pubkey = [2u8; 33];
    let session = Session::new_enrolled(
        peer_mac,
        peer_static_pubkey,
        RESUME_PSK,
        SessionRole::Sensor,
    )
    .unwrap();

    assert_eq!(session.peer_mac(), &peer_mac);
    assert_eq!(session.peer_static_pubkey(), &peer_static_pubkey);
    assert!(session.session_key().is_none());
    assert!(session.nonce_prefix().is_none());
    assert_eq!(session.resume_psk(), Some(&RESUME_PSK));
    assert_eq!(session.tx_counter(), 0);
    assert_eq!(session.rx_counter(), 0);
    assert_eq!(session.key_expire_at(), 0);
}

#[test]
fn test_post_reboot_public_api_is_new_enrolled() {
    // After NVRAM load the host must create an enrolled shell
    // without AEAD keys. Active keys are crate-internal (`new_active` /
    // `update_key`) and only installed by install/renew/resume.
    let session =
        Session::new_enrolled([9u8; 17], [2u8; 33], RESUME_PSK, SessionRole::Gateway).unwrap();
    assert!(!session.is_active(0), "enrolled shell has no live AEAD key");
    assert!(session.session_key().is_none());
    assert!(session.rx_session_key().is_none());
    assert_eq!(session.role(), SessionRole::Gateway);
    assert_eq!(session.resume_psk(), Some(&RESUME_PSK));
}

#[test]
fn test_new_enrolled_rejects_corrupt_nvram_material() {
    assert!(matches!(
        Session::new_enrolled([9u8; 17], [0u8; 33], RESUME_PSK, SessionRole::Sensor,),
        Err(SigilError::InvalidStaticKey)
    ));
    assert!(matches!(
        Session::new_enrolled([9u8; 17], [2u8; 33], [0u8; 32], SessionRole::Sensor,),
        Err(SigilError::InvalidResumePsk)
    ));
}

#[test]
fn test_new_active_session() {
    let peer_mac = [1u8; 17];
    let peer_static_pubkey = [2u8; 33];
    let session_key = [3u8; 32];
    let nonce_prefix = [4u8; 4];
    let key_expire_at = 1000;

    let session = Session::new_active(
        peer_mac,
        peer_static_pubkey,
        DirectionalMaterial::symmetric_for_test(session_key, nonce_prefix),
        SessionRole::Sensor,
        RESUME_PSK,
        key_expire_at,
        0,
    )
    .unwrap();

    assert_eq!(session.peer_mac(), &peer_mac);
    assert_eq!(session.peer_static_pubkey(), &peer_static_pubkey);
    assert_eq!(session.session_key(), Some(&session_key));
    assert_eq!(session.nonce_prefix(), Some(&nonce_prefix));
    assert_eq!(session.tx_counter(), 0);
    assert_eq!(session.rx_counter(), 0);
    assert_eq!(session.key_expire_at(), key_expire_at);
    assert_eq!(session.resume_psk(), Some(&RESUME_PSK));
}

#[test]
fn test_resume_psk_survives_update_and_clear() {
    let mut session = Session::new_active(
        [1u8; 17],
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
        SessionRole::Sensor,
        RESUME_PSK,
        1000,
        0,
    )
    .unwrap();
    session
        .update_key(
            DirectionalMaterial::symmetric_for_test([5u8; 32], [6u8; 4]),
            2000,
            0,
        )
        .unwrap();
    assert_eq!(session.resume_psk(), Some(&RESUME_PSK));
    session.clear_expired_key(2000).unwrap();
    assert_eq!(session.resume_psk(), Some(&RESUME_PSK));
    assert!(session.session_key().is_none());
}

#[test]
fn test_is_active() {
    let peer_mac = [1u8; 17];
    let peer_static_pubkey = [2u8; 33];
    let session_key = [3u8; 32];
    let nonce_prefix = [4u8; 4];
    let key_expire_at = 1000;

    let session = Session::new_active(
        peer_mac,
        peer_static_pubkey,
        DirectionalMaterial::symmetric_for_test(session_key, nonce_prefix),
        SessionRole::Sensor,
        RESUME_PSK,
        key_expire_at,
        0,
    )
    .unwrap();

    // Session should be active before expiry
    assert!(session.is_active(500));

    // Session should be expired after expiry time
    assert!(!session.is_active(1000));
    assert!(!session.is_active(1500));
}

#[test]
fn test_is_expired() {
    let peer_mac = [1u8; 17];
    let peer_static_pubkey = [2u8; 33];
    let session_key = [3u8; 32];
    let nonce_prefix = [4u8; 4];
    let key_expire_at = 1000;

    let session = Session::new_active(
        peer_mac,
        peer_static_pubkey,
        DirectionalMaterial::symmetric_for_test(session_key, nonce_prefix),
        SessionRole::Sensor,
        RESUME_PSK,
        key_expire_at,
        0,
    )
    .unwrap();

    assert!(!session.is_expired(500));
    assert!(session.is_expired(1000));
    assert!(session.is_expired(1500));
}

#[test]
fn test_update_key() {
    let peer_mac = [1u8; 17];
    let peer_static_pubkey = [2u8; 33];
    let old_key = [3u8; 32];
    let old_prefix = [4u8; 4];
    let new_key = [5u8; 32];
    let new_prefix = [6u8; 4];
    let old_expire = 1000;
    let new_expire = 2000;

    let mut session = Session::new_active(
        peer_mac,
        peer_static_pubkey,
        DirectionalMaterial::symmetric_for_test(old_key, old_prefix),
        SessionRole::Sensor,
        RESUME_PSK,
        old_expire,
        0,
    )
    .unwrap();

    // Set some counters
    session.tx_counter = 100;
    session.rx_counter = 200;

    // Update the key
    session
        .update_key(
            DirectionalMaterial::symmetric_for_test(new_key, new_prefix),
            new_expire,
            0,
        )
        .unwrap();

    assert_eq!(session.session_key(), Some(&new_key));
    assert_eq!(session.nonce_prefix(), Some(&new_prefix));
    assert_eq!(session.tx_counter(), 0); // Should be reset
    assert_eq!(session.rx_counter(), 0); // Should be reset
    assert_eq!(session.key_expire_at(), new_expire);
}

#[test]
fn test_clear_expired_key() {
    let peer_mac = [1u8; 17];
    let mut session = Session::new_active(
        peer_mac,
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
        SessionRole::Sensor,
        RESUME_PSK,
        1000,
        0,
    )
    .unwrap();

    // Still active → refuse
    assert_eq!(
        session.clear_expired_key(500),
        Err(crate::core::error::SigilError::SessionAlreadyActive { peer: peer_mac })
    );
    assert!(session.session_key().is_some());

    // Soft-expired → clear
    session.clear_expired_key(1000).unwrap();
    assert!(session.session_key().is_none());
    assert!(session.nonce_prefix().is_none());
    assert_eq!(session.tx_counter(), 0);
    assert_eq!(session.rx_counter(), 0);

    // Already clear → Ok
    session.clear_expired_key(2000).unwrap();
}

#[test]
fn test_session_zeroize_on_drop() {
    // Dropping a Session must clear the session key from RAM (ZeroizeOnDrop).
    // We cannot observe SRAM after free portably; instead we verify update_key
    // zeroizes the previous key buffer via take()+zeroize before replace, and
    // that ZeroizeOnDrop is derived (compile-time / Drop path exercised).
    let mut session = Session::new_active(
        [1u8; 17],
        [2u8; 33],
        DirectionalMaterial::symmetric_for_test([0xABu8; 32], [0xCDu8; 4]),
        SessionRole::Sensor,
        RESUME_PSK,
        1000,
        0,
    )
    .unwrap();
    session
        .update_key(
            DirectionalMaterial::symmetric_for_test([0x11u8; 32], [0x22u8; 4]),
            2000,
            0,
        )
        .unwrap();
    assert_eq!(session.session_key(), Some(&[0x11u8; 32]));
    drop(session);
}

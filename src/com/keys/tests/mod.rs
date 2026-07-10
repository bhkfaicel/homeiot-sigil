#![cfg(test)]

extern crate alloc;

use super::*;
use alloc::vec::Vec;

#[test]
fn test_key_manager_integration() {
    // Complete integration test: key derivation and usage
    let master_key = [0x42; 32];
    let device_id = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB,
    ];

    let key_manager = KeyManager::new(master_key, device_id);

    // Derive different keys
    let device_key = key_manager.derive_device_key();
    let nonce1 = [0x01; 12];
    let nonce2 = [0x02; 12];
    let session_key1 = key_manager.derive_session_key(&nonce1);
    let session_key2 = key_manager.derive_session_key(&nonce2);
    let installation_key = key_manager.derive_usage_key(b"installation");
    let validation_key = key_manager.derive_usage_key(b"validation");

    // Verifications
    assert_ne!(device_key, [0u8; 32]);
    assert_ne!(session_key1, session_key2);
    assert_ne!(installation_key, validation_key);
    assert_ne!(device_key, session_key1);
    assert_ne!(device_key, installation_key);
}

#[test]
fn test_key_manager_realistic_scenario() {
    // Realistic scenario: two devices with the same master secret
    let master_key = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08,
    ];

    // Device 1: MAC address 00:11:22:33:44:55
    let device1_id = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let key_manager1 = KeyManager::new(master_key, device1_id);
    let device1_key = key_manager1.derive_device_key();

    // Device 2: MAC address 00:11:22:33:44:56
    let device2_id = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let key_manager2 = KeyManager::new(master_key, device2_id);
    let device2_key = key_manager2.derive_device_key();

    // Both devices must have different keys
    assert_ne!(device1_key, device2_key);

    // But each device must have a stable key
    let device1_key_again = key_manager1.derive_device_key();
    assert_eq!(device1_key, device1_key_again);
}

#[test]
fn test_key_manager_session_keys() {
    // Test that session keys are unique per nonce
    let master_key = [0x42; 32];
    let device_id = [0xAA; 17];
    let key_manager = KeyManager::new(master_key, device_id);

    let mut session_keys = Vec::new();

    // Generate 10 session keys with different nonces
    for i in 0..10u8 {
        let nonce = [i; 12];
        let session_key = key_manager.derive_session_key(&nonce);
        session_keys.push(session_key);
    }

    // All keys must be different
    for i in 0..session_keys.len() {
        for j in (i + 1)..session_keys.len() {
            assert_ne!(
                session_keys[i], session_keys[j],
                "Session keys {} and {} are identical",
                i, j
            );
        }
    }
}

#[test]
fn test_key_manager_usage_separation() {
    // Test that usage keys are properly separated
    let master_key = [0x42; 32];
    let device_id = [0xAA; 17];
    let key_manager = KeyManager::new(master_key, device_id);

    let installation_key = key_manager.derive_usage_key(b"installation");
    let validation_key = key_manager.derive_usage_key(b"validation");
    let data_key = key_manager.derive_usage_key(b"data");
    let control_key = key_manager.derive_usage_key(b"control");

    // All keys must be different
    assert_ne!(installation_key, validation_key);
    assert_ne!(validation_key, data_key);
    assert_ne!(data_key, control_key);
    assert_ne!(installation_key, data_key);
    assert_ne!(installation_key, control_key);
    assert_ne!(validation_key, control_key);
}

fn ticks_for_seconds(seconds: u32) -> u64 {
    seconds as u64 * ValidatedKey::RTC_FREQ
}

fn keys_with_100s_lifetime() -> Keys {
    Keys {
        key: [0xAB; 32],
        timestamp: 1_000,
        expire_at: 1_100,
    }
}

#[test]
fn validated_key_never_expires_when_expire_at_is_zero() {
    let keys = Keys {
        key: [0xCD; 32],
        timestamp: 1_000,
        expire_at: 0,
    };
    let validated = ValidatedKey::new(keys, 0);
    let far_future = ticks_for_seconds(u32::MAX / ValidatedKey::RTC_FREQ as u32);

    assert!(validated.is_valid(far_future));
    assert!(!validated.should_renew(far_future));
}

#[test]
fn validated_key_should_renew_at_seventy_five_percent_elapsed() {
    let validated = ValidatedKey::new(keys_with_100s_lifetime(), 0);
    let at_threshold = ticks_for_seconds(75);

    assert!(validated.is_valid(at_threshold));
    assert!(validated.should_renew(at_threshold));
}

#[test]
fn validated_key_is_invalid_after_duration_elapsed() {
    let validated = ValidatedKey::new(keys_with_100s_lifetime(), 0);

    assert!(!validated.is_valid(ticks_for_seconds(100)));
    assert!(validated.should_renew(ticks_for_seconds(100)));
}

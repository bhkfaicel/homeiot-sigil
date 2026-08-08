#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for host capability traits
//!
//! The shared mock implementations (`MockSecureElement`, `MockRandom`) now live
//! in `crate::core::test_support` so they can be reused by other modules' tests.

use crate::core::test_support::{MockRandom, MockSecureElement};
use crate::core::traits::{RandomSource, SecureElement};

#[test]
fn test_secure_element_trait_documents_sensing_priority() {
    // Soft contract: trait rustdoc must mention door/vibration priority
    // over install so host integrators see it in `cargo doc`.
    let docs = include_str!("../mod.rs");
    assert!(
        docs.contains("door-open / vibration"),
        "SecureElement rustdoc must document sensing > install"
    );
}

#[test]
fn test_mock_secure_element() {
    let static_pubkey = [1u8; 33];
    let mut se = MockSecureElement::new(static_pubkey);

    let peer_pubkey = [2u8; 33];
    let shared = se.ecdh(&peer_pubkey).unwrap();
    assert_eq!(shared, [0x42u8; 32]);

    let signature = se.sign_ecdsa(b"test message").unwrap();
    // Signature is message-bound (not a fixed constant).
    se.verify_ecdsa(&peer_pubkey, b"test message", &signature)
        .unwrap();
    // Wrong message must fail verification.
    assert!(
        se.verify_ecdsa(&peer_pubkey, b"other message", &signature)
            .is_err()
    );

    let retrieved_pubkey = se.get_static_pubkey().unwrap();
    assert_eq!(retrieved_pubkey, static_pubkey);

    // Factory cert is a signature over the canonical message
    // (version ‖ product_id ‖ hardware_profile_id ‖ factory_key_id ‖
    // peer_mac ‖ pubkey), not the raw pubkey alone.
    let factory_cert = se.get_factory_cert().unwrap();
    let metadata = se.get_factory_cert_metadata().unwrap();
    let cert_msg = crate::core::install::factory_cert_message(
        crate::core::install::FACTORY_PRODUCT_ID_SENSOR,
        metadata,
        &se.device_mac,
        &static_pubkey,
    )
    .unwrap();
    se.verify_ecdsa(&[0xFAu8; 33], &cert_msg, &factory_cert)
        .unwrap();
    assert!(
        se.verify_ecdsa(&[0xFAu8; 33], &[0xFFu8; 33], &factory_cert)
            .is_err()
    );
}

#[test]
fn test_mock_random() {
    let mut rng = MockRandom::new();
    let mut buffer1 = [0u8; 10];
    let mut buffer2 = [0u8; 10];

    rng.fill_bytes(&mut buffer1).unwrap();
    rng.fill_bytes(&mut buffer2).unwrap();

    // Verify that we get different values
    assert_ne!(buffer1, buffer2);

    // Verify that values increment
    assert_eq!(buffer1[0], 0);
    assert_eq!(buffer1[9], 9);
    assert_eq!(buffer2[0], 10);
    assert_eq!(buffer2[9], 19);
}

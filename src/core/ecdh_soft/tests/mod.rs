#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for software ephemeral X25519 ECDH

use crate::core::ecdh_soft::{
    PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, clamp_x25519_scalar, ecdh_ephemeral,
    generate_ephemeral_keypair, generate_ephemeral_scalar, zeroize_secret,
};
use crate::core::error::SigilError;
use crate::core::test_support::{FailingRandom, MockRandom};
use crate::core::traits::RandomSource;

#[test]
fn test_generate_ephemeral_keypair() {
    let mut rng = MockRandom::new();

    let (secret, pubkey) = generate_ephemeral_keypair(&mut rng).unwrap();

    assert_eq!(secret.len(), PRIVATE_KEY_SIZE);
    assert_eq!(pubkey.len(), PUBLIC_KEY_SIZE);
    // RFC 7748 clamp bits must be applied on the returned scalar.
    assert_eq!(secret[0] & 0x07, 0);
    assert_eq!(secret[31] & 0x80, 0);
    assert_ne!(secret[31] & 0x40, 0);
}

#[test]
fn test_clamp_x25519_scalar_bits() {
    let mut scalar = [0xFFu8; 32];
    clamp_x25519_scalar(&mut scalar);
    assert_eq!(scalar[0], 0xF8);
    assert_eq!(scalar[31], 0x7F | 0x40);
}

#[test]
fn test_private_key_is_exactly_32_bytes_from_rng() {
    /// RNG that records the buffer length requested by the library.
    struct LenCheckRandom {
        last_len: usize,
        counter: u8,
    }

    impl RandomSource for LenCheckRandom {
        fn fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), SigilError> {
            self.last_len = buffer.len();
            for b in buffer.iter_mut() {
                *b = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            // Avoid an all-zero fill so generate_ephemeral_scalar succeeds.
            if buffer.iter().all(|&b| b == 0) {
                buffer[0] = 1;
            }
            Ok(())
        }
    }

    let mut rng = LenCheckRandom {
        last_len: 0,
        counter: 1,
    };
    let _ = generate_ephemeral_scalar(&mut rng).unwrap();
    assert_eq!(
        rng.last_len, 32,
        "X25519 private material must be exactly 32 RNG bytes"
    );
}

#[test]
fn test_host_rng_propagates_failure() {
    let mut rng = FailingRandom;
    assert_eq!(
        generate_ephemeral_scalar(&mut rng),
        Err(SigilError::RandomFailed)
    );
    let mut rng2 = FailingRandom;
    assert_eq!(
        generate_ephemeral_keypair(&mut rng2).map(|_| ()),
        Err(SigilError::RandomFailed)
    );
}

#[test]
fn test_ecdh_ephemeral() {
    let mut rng1 = MockRandom::new();
    let mut rng2 = MockRandom::new();

    let (secret1, pubkey1) = generate_ephemeral_keypair(&mut rng1).unwrap();
    let (secret2, pubkey2) = generate_ephemeral_keypair(&mut rng2).unwrap();

    let shared1 = ecdh_ephemeral(&secret1, &pubkey2).unwrap();
    let shared2 = ecdh_ephemeral(&secret2, &pubkey1).unwrap();

    assert_eq!(shared1, shared2);
}

#[test]
fn test_ecdh_different_peers() {
    let mut rng = MockRandom::new();

    let (secret1, _pubkey1) = generate_ephemeral_keypair(&mut rng).unwrap();
    let (_secret2, pubkey2) = generate_ephemeral_keypair(&mut rng).unwrap();
    let (_secret3, pubkey3) = generate_ephemeral_keypair(&mut rng).unwrap();

    let shared12 = ecdh_ephemeral(&secret1, &pubkey2).unwrap();
    let shared13 = ecdh_ephemeral(&secret1, &pubkey3).unwrap();

    assert_ne!(shared12, shared13);
    assert_ne!(pubkey2, pubkey3);
}

#[test]
fn test_ecdh_rejects_all_zero_peer_pubkey() {
    let mut rng = MockRandom::new();
    let (secret, _pubkey) = generate_ephemeral_keypair(&mut rng).unwrap();

    // The X25519 identity / low-order all-zero u-coordinate yields a
    // non-contributory shared secret that must be rejected.
    let zero_pubkey = [0u8; 32];
    assert_eq!(
        ecdh_ephemeral(&secret, &zero_pubkey),
        Err(SigilError::EcdhFailed)
    );
}

#[test]
fn test_reject_wrong_length_renew_pubkey_on_wire() {
    // X25519 accepts any 32-byte peer encoding at the ECDH layer; length
    // enforcement lives on the renew wire parsers (must be exactly 32).
    use crate::core::renew::wire::{parse_renew_challenge_body, parse_renew_request_body};

    assert!(parse_renew_request_body(&[0u8; 31]).is_none());
    assert!(parse_renew_request_body(&[0u8; 33]).is_none());
    assert!(parse_renew_request_body(&[0u8; 32]).is_some());

    assert!(parse_renew_challenge_body(&[0u8; 35]).is_none()); // 31+4
    assert!(parse_renew_challenge_body(&[0u8; 37]).is_none()); // 33+4
    assert!(parse_renew_challenge_body(&[0u8; 36]).is_some()); // 32+4
}

#[test]
fn test_zeroize_secret() {
    let mut secret = [0x42u8; 32];

    zeroize_secret(&mut secret);

    assert_eq!(secret, [0u8; 32]);
}

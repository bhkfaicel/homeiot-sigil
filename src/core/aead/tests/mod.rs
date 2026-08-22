#![cfg(test)]

//! Unit tests for AEAD encryption and decryption

use crate::core::aead::{
    HANDSHAKE_PLAINTEXT_CAP, RX_COUNTER_MAX_GAP, aad_from_frame, build_aad, build_nonce,
    check_tx_counter, decrypt, decrypt_into, encrypt, encrypt_append,
    verify_and_advance_rx_counter,
};
use crate::core::error::SigilError;
use crate::core::frame::{
    FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
    build_header,
};
use heapless::Vec;

const PEER: [u8; 17] = [7u8; 17];

#[test]
fn test_build_nonce() {
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let counter = 0x123456789ABCDEF0;

    let nonce = build_nonce(&prefix, counter);

    assert_eq!(nonce[0..4], prefix);
    assert_eq!(nonce[4..12], counter.to_be_bytes());
}

#[test]
fn test_build_aad_is_outer_header() {
    let aad = build_aad(&PEER, FrameType::Data);
    assert_eq!(&aad[..17], &PEER[..]);
    assert_eq!(aad[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(aad[FRAME_TYPE_OFFSET], FrameType::Data as u8);
    assert_eq!(aad.len(), OUTER_HEADER_SIZE);
}

#[test]
fn test_encrypt_decrypt() {
    let key = [0x42u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let counter = 0;
    let plaintext = b"Hello, world!";
    let aad = build_aad(&PEER, FrameType::Data);

    let ciphertext = encrypt(&key, &prefix, counter, plaintext, &aad).unwrap();
    let decrypted = decrypt(&key, &prefix, counter, &ciphertext, &aad).unwrap();

    assert_eq!(&decrypted[..], plaintext);
}

#[test]
fn test_encrypt_rejects_oversized_plaintext() {
    // plaintext + tag must fit in AEAD_BUF_CAP (256).
    let key = [0x42u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let aad = build_aad(&PEER, FrameType::Data);
    let too_big = [0u8; 241]; // 241 + 16 tag = 257 > 256
    let result = encrypt(&key, &prefix, 0, &too_big, &aad);
    assert_eq!(result, Err(SigilError::OutputBufferTooSmall));
}

#[test]
fn test_encrypt_append_into_prebuilt_header() {
    // Mimics the pipeline: one Vec holds header + ciphertext (no AEAD scratch).
    let key = [0x42u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let plaintext = b"single-buffer encrypt";
    let aad = build_aad(&PEER, FrameType::Data);

    let mut frame: Vec<u8, 128> = Vec::new();
    frame
        .extend_from_slice(&build_header(&PEER, FrameType::Data))
        .unwrap();
    frame.extend_from_slice(&prefix).unwrap();
    frame.extend_from_slice(&0u64.to_be_bytes()).unwrap();
    encrypt_append(&key, &prefix, 0, plaintext, &aad, &mut frame).unwrap();

    let ct = &frame[OUTER_HEADER_SIZE + 4 + 8..];
    let mut out: Vec<u8, 64> = Vec::new();
    decrypt_into(&key, &prefix, 0, ct, &aad, &mut out).unwrap();
    assert_eq!(&out[..], plaintext);
}

#[test]
fn test_decrypt_into_rejects_oversized_plaintext() {
    let key = [0x42u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let aad = build_aad(&PEER, FrameType::Data);
    let plaintext = [0xABu8; HANDSHAKE_PLAINTEXT_CAP + 1];
    let ct = encrypt(&key, &prefix, 0, &plaintext, &aad).unwrap();

    let mut out: Vec<u8, HANDSHAKE_PLAINTEXT_CAP> = Vec::new();
    let result = decrypt_into(&key, &prefix, 0, &ct, &aad, &mut out);
    assert_eq!(result, Err(SigilError::OutputBufferTooSmall));
}

#[test]
fn test_encrypt_decrypt_wrong_key() {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let counter = 0;
    let plaintext = b"Hello, world!";
    let aad = build_aad(&PEER, FrameType::Data);

    let ciphertext = encrypt(&key1, &prefix, counter, plaintext, &aad).unwrap();
    let result = decrypt(&key2, &prefix, counter, &ciphertext, &aad);

    assert_eq!(result, Err(SigilError::VerificationFailed));
}

#[test]
fn test_aad_mismatch_rejected() {
    // C2: encrypt under Data AAD, decrypt under RenewRequest AAD must fail.
    let key = [0x42u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let plaintext = b"application payload that looks like renew";
    let aad_data = build_aad(&PEER, FrameType::Data);
    let aad_renew = build_aad(&PEER, FrameType::RenewRequest);

    let ciphertext = encrypt(&key, &prefix, 0, plaintext, &aad_data).unwrap();
    let result = decrypt(&key, &prefix, 0, &ciphertext, &aad_renew);
    assert_eq!(result, Err(SigilError::VerificationFailed));
}

#[test]
fn test_frame_type_flip_fails_aad() {
    // Simulate an attacker flipping the frame_type byte after encryption.
    let key = [0x42u8; 32];
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let plaintext = [0xABu8; 32]; // representative handshake plaintext size
    let aad_data = build_aad(&PEER, FrameType::Data);

    let ciphertext = encrypt(&key, &prefix, 0, &plaintext, &aad_data).unwrap();

    // Build a full frame as Data, then flip frame_type to RenewRequest.
    let mut frame = heapless::Vec::<u8, 256>::new();
    frame
        .extend_from_slice(&build_header(&PEER, FrameType::Data))
        .unwrap();
    frame.extend_from_slice(&prefix).unwrap();
    frame.extend_from_slice(&0u64.to_be_bytes()).unwrap();
    frame.extend_from_slice(&ciphertext).unwrap();

    frame[FRAME_TYPE_OFFSET] = FrameType::RenewRequest as u8;
    let flipped_aad = aad_from_frame(&frame).unwrap();
    let result = decrypt(
        &key,
        &prefix,
        0,
        &frame[OUTER_HEADER_SIZE + 4 + 8..],
        flipped_aad,
    );
    assert_eq!(result, Err(SigilError::VerificationFailed));
}

#[test]
fn test_verify_rx_counter_valid_first_packet() {
    // Fresh session: rx_counter=0 (next expected), first packet uses counter 0
    let current = 0;
    let received = 0;

    let result = verify_and_advance_rx_counter(current, received).unwrap();
    assert_eq!(result, 1); // next expected becomes received + 1
}

#[test]
fn test_verify_rx_counter_valid_advance() {
    // Next expected = 10, received = 15 (gap within window)
    let current = 10;
    let received = 15;

    let result = verify_and_advance_rx_counter(current, received).unwrap();
    assert_eq!(result, 16); // next expected becomes received + 1
}

#[test]
fn test_verify_rx_counter_max_gap_accepted() {
    let current = 10;
    let received = current + RX_COUNTER_MAX_GAP;
    let result = verify_and_advance_rx_counter(current, received).unwrap();
    assert_eq!(result, received + 1);
}

#[test]
fn test_verify_rx_counter_gap_too_large_rejected() {
    let current = 10;
    let received = current + RX_COUNTER_MAX_GAP + 1;
    let result = verify_and_advance_rx_counter(current, received);
    assert!(matches!(result, Err(SigilError::Replay { .. })));
}

#[test]
fn test_verify_rx_counter_huge_jump_rejected() {
    // Attacker with session key cannot burn the counter space with a near-max jump.
    let current = 0;
    let received = u64::MAX / 2;
    let result = verify_and_advance_rx_counter(current, received);
    assert!(matches!(result, Err(SigilError::Replay { .. })));
}

#[test]
fn test_verify_rx_counter_equal_accepted() {
    // Next expected = 10, received = 10 (matches next expected)
    let current = 10;
    let received = 10;

    let result = verify_and_advance_rx_counter(current, received).unwrap();
    assert_eq!(result, 11);
}

#[test]
fn test_verify_rx_counter_replay() {
    let current = 10;
    let received = 5; // Lower than current → stale / replay

    let result = verify_and_advance_rx_counter(current, received);
    assert!(matches!(result, Err(SigilError::Replay { .. })));
}

#[test]
fn test_verify_rx_counter_duplicate_rejected() {
    // Next expected = 11 (counter 10 already consumed); replaying counter 10 fails
    let current = 11;
    let received = 10;

    let result = verify_and_advance_rx_counter(current, received);
    assert!(matches!(result, Err(SigilError::Replay { .. })));
}

#[test]
fn test_verify_rx_counter_max_rejects_wrap() {
    // accepting received == u64::MAX would wrap next watermark.

    let current = u64::MAX - 10;
    let received = u64::MAX;
    let result = verify_and_advance_rx_counter(current, received);
    assert_eq!(
        result,
        Err(SigilError::CounterExhausted { peer: [0u8; 17] })
    );
}

#[test]
fn test_verify_rx_counter_near_max_accepted() {
    // Last safe accept: watermark becomes u64::MAX (no further +1 possible).
    let current = u64::MAX - 1;
    let received = u64::MAX - 1;
    let result = verify_and_advance_rx_counter(current, received).unwrap();
    assert_eq!(result, u64::MAX);
}

#[test]
fn test_check_tx_counter() {
    assert!(check_tx_counter(0).is_ok());
    assert!(check_tx_counter(100).is_ok());
    assert!(check_tx_counter(u64::MAX - 1).is_ok());
    assert_eq!(
        check_tx_counter(u64::MAX),
        Err(SigilError::CounterExhausted { peer: [0u8; 17] })
    );
}

use chacha20poly1305::aead::heapless::Vec;

use crate::crypto::{decrypt, encrypt};

#[test]
fn test_encrypt_decrypt() {
    let key = [0u8; 32];
    let nonce = [1u8; 12];
    let aad = b"additional data";

    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer.extend_from_slice(b"Hello, world!").unwrap();

    let original_data = buffer.clone();

    encrypt(&mut buffer, &key, &nonce, Some(aad)).unwrap();
    assert_ne!(buffer, original_data);

    decrypt(&mut buffer, &key, Some(aad)).unwrap();
    assert_eq!(buffer, original_data);
}

#[test]
fn test_encrypt_decrypt_without_aad() {
    let key = [0u8; 32];
    let nonce = [1u8; 12];
    let aad = &[];

    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer.extend_from_slice(b"Hello, world!").unwrap();

    let original_data = buffer.clone();

    encrypt(&mut buffer, &key, &nonce, Some(aad)).unwrap();
    assert_ne!(buffer, original_data);

    decrypt(&mut buffer, &key, Some(aad)).unwrap();
    assert_eq!(buffer, original_data);
}

#[test]
fn test_decrypt_invalid_data() {
    let key = [0u8; 32];
    let aad = b"additional data";

    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer.extend_from_slice(b"Invalid data").unwrap();

    assert!(decrypt(&mut buffer, &key, Some(aad)).is_err());
}

#[test]
fn test_decrypt_invalid_data_without_aad() {
    let key = [0u8; 32];
    let aad = &[];

    let mut buffer: Vec<u8, 128> = Vec::new();
    buffer.extend_from_slice(b"Invalid data").unwrap();

    assert!(decrypt(&mut buffer, &key, Some(aad)).is_err());
}

#[test]
fn test_insufficient_buffer() {
    let key = [0u8; 32];
    let nonce = [1u8; 12];
    let aad = b"additional data";

    let mut buffer: Vec<u8, 4> = Vec::new(); // Insufficient capacity
    assert!(encrypt(&mut buffer, &key, &nonce, Some(aad)).is_err());
}

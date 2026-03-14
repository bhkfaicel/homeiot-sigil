pub mod gateway;
pub mod sensor;

/// P-256 compressed public key size (1-byte prefix + 32-byte X coordinate).
pub const PUBLIC_KEY_LEN: usize = 33;
/// ECDSA P-256 signature size (r || s, 32 + 32 bytes).
pub const SIGNATURE_LEN: usize = 64;

/// Maximum handshake message size (256-byte LoRa packet limit).
pub const HANDSHAKE_MESSAGE_MAX: usize = 250;

/// Plaintext inside the ECIES ciphertext:
/// `sig_sensor_nonce[64] || gateway_pubkey[33] || gateway_nonce[32]` = 129 bytes.
pub const CHALLENGE_PLAINTEXT_LEN: usize = SIGNATURE_LEN + PUBLIC_KEY_LEN + 32;

/// ECIES ciphertext overhead: `ephemeral_pubkey[33] || chacha_nonce[12] || poly1305_tag[16]`
/// = 61 bytes.
pub const ECIES_OVERHEAD: usize = PUBLIC_KEY_LEN + 12 + 16;

/// Total ECIES ciphertext size:
/// `ephemeral_pubkey[33] || chacha_nonce[12] || ciphertext[129] || poly1305_tag[16]` = 190 bytes.
///
/// This is the fixed size of the `HandshakeChallenge::data` field and the `out` buffer
/// expected by the `ecies_encrypt` callback in `handle_handshake_request`.
pub const ECIES_CIPHERTEXT_LEN: usize = CHALLENGE_PLAINTEXT_LEN + ECIES_OVERHEAD;

/// Derives the session key from the ECDH shared secret and both nonces using HKDF-SHA256.
///
/// Both the gateway (after `ecies_encrypt`) and the sensor (after `ecies_decrypt`) call
/// this with the same inputs and independently derive the same 32-byte session key.
pub(crate) fn derive_session_key(
    ecdh_shared_secret: &[u8; 32],
    sensor_nonce: &[u8; 32],
    gateway_nonce: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(sensor_nonce);
    salt[32..].copy_from_slice(gateway_nonce);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), ecdh_shared_secret);
    let mut session_key = [0u8; 32];
    hkdf.expand(b"session", &mut session_key)
        .expect("valid length");
    session_key
}

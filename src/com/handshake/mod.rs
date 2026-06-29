pub mod gateway;
pub mod sensor;

/// P-256 compressed public key size (1-byte prefix + 32-byte X coordinate).
pub const PUBLIC_KEY_LEN: usize = 33;
/// ECDSA P-256 signature size (r || s, 32 + 32 bytes).
pub const SIGNATURE_LEN: usize = 64;

/// Maximum handshake message size (256-byte LoRa packet limit).
pub const HANDSHAKE_MESSAGE_MAX: usize = 250;

/// Plaintext inside the ECIES ciphertext:
/// `sig_sensor_nonce[64] || gateway_pubkey[33] || gateway_nonce[32] || key_expire_at[4]` = 133 bytes.
///
/// `key_expire_at` is a big-endian `u32` Unix timestamp indicating when the session key expires
/// (0 = never expires). It is set by the gateway and read by the sensor.
pub const CHALLENGE_PLAINTEXT_LEN: usize = SIGNATURE_LEN + PUBLIC_KEY_LEN + 32 + 4;

/// ECIES ciphertext overhead: `ephemeral_pubkey[33] || chacha_nonce[12] || poly1305_tag[16]`
/// = 61 bytes.
pub const ECIES_OVERHEAD: usize = PUBLIC_KEY_LEN + 12 + 16;

/// Total ECIES ciphertext size:
/// `ephemeral_pubkey[33] || chacha_nonce[12] || ciphertext[133] || poly1305_tag[16]` = 194 bytes.
///
/// This is the fixed size of the `HandshakeChallenge::data` field and the `out` buffer
/// expected by the `ecies_encrypt` callback in `handle_handshake_request`.
pub const ECIES_CIPHERTEXT_LEN: usize = CHALLENGE_PLAINTEXT_LEN + ECIES_OVERHEAD;

/// Gateway listen iterations while waiting for `HandshakeConfirm` after the challenge is sent.
///
/// The gateway re-sends the **same** challenge every [`GATEWAY_CHALLENGE_RESEND_PERIOD`] attempts.
/// On `NoPacket`, each iteration waits ~200 ms before retrying. With the default of 180 attempts,
/// the gateway listens for roughly **36 s** before returning `ComError::Timeout`. This reduces
/// premature timeouts when the sensor is slow (ATECC608A ECDH + LoRa retries) and avoids starting
/// a new handshake (new ephemeral key / session key) while the sensor is still processing.
pub const GATEWAY_CONFIRM_RX_TIMEOUT: usize = 180;

/// Re-send the identical `HandshakeChallenge` buffer every N receive attempts (packet loss recovery).
pub const GATEWAY_CHALLENGE_RESEND_PERIOD: usize = 10;

/// Encrypts a handshake challenge using HKDF-SHA256 + ChaCha20Poly1305.
///
/// The caller provides:
/// - `eph_pubkey_compressed`: gateway ephemeral P-256 public key (compressed SEC1 format).
/// - `shared_secret`: 32-byte ECDH shared secret with the sensor public key.
/// - `chacha_nonce`: 12-byte ChaCha20Poly1305 nonce (from hardware RNG or host RNG).
/// - `plaintext`: 133-byte challenge payload.
///
/// On success, this function fills `out` with:
/// `ephemeral_pubkey[33] || chacha_nonce[12] || ciphertext[133] || poly1305_tag[16]`.
pub fn encrypt_challenge(
    eph_pubkey_compressed: &[u8; PUBLIC_KEY_LEN],
    shared_secret: &[u8; 32],
    chacha_nonce: &[u8; 12],
    plaintext: &[u8; CHALLENGE_PLAINTEXT_LEN],
    out: &mut [u8; ECIES_CIPHERTEXT_LEN],
) -> Result<(), ()> {
    use chacha20poly1305::aead::heapless::Vec as HVec;
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Derive encryption key via HKDF-SHA256 (same salt/info as decrypt_challenge).
    let hkdf = Hkdf::<Sha256>::new(Some(eph_pubkey_compressed), shared_secret);
    let mut enc_key = [0u8; 32];
    hkdf.expand(b"ecies-enc", &mut enc_key).map_err(|_| ())?;

    // Encrypt plaintext in-place with ChaCha20Poly1305 (appends 16-byte tag).
    let mut buf: HVec<u8, { CHALLENGE_PLAINTEXT_LEN + 16 }> = HVec::new();
    buf.extend_from_slice(plaintext).map_err(|_| ())?;
    let cipher = ChaCha20Poly1305::new((&enc_key).into());
    cipher
        .encrypt_in_place((&(*chacha_nonce)).into(), b"", &mut buf)
        .map_err(|_| ())?;

    // Layout: eph_pubkey[33] || chacha_nonce[12] || ciphertext+tag[145]
    out[0..PUBLIC_KEY_LEN].copy_from_slice(eph_pubkey_compressed);
    out[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 12].copy_from_slice(chacha_nonce);
    out[PUBLIC_KEY_LEN + 12..ECIES_CIPHERTEXT_LEN].copy_from_slice(&buf);

    Ok(())
}

/// Decrypts a handshake challenge ECIES ciphertext using HKDF-SHA256 + ChaCha20Poly1305.
///
/// Layout of `ciphertext`:
/// - `ephemeral_pubkey_compressed[PUBLIC_KEY_LEN]`
/// - `chacha_nonce[12]`
/// - `ciphertext[CHALLENGE_PLAINTEXT_LEN]`
/// - `poly1305_tag[16]`
///
/// The caller supplies a hardware-specific `ecdh_shared_secret` callback that computes
/// the 32-byte ECDH shared secret from the gateway's ephemeral public key
/// (P-256, compressed SEC1). On success, this function writes the 133-byte plaintext
/// into `out` and returns the shared secret.
pub fn decrypt_challenge<FECDH>(
    ciphertext: &[u8; ECIES_CIPHERTEXT_LEN],
    out: &mut [u8; CHALLENGE_PLAINTEXT_LEN],
    ecdh_shared_secret: &mut FECDH,
) -> Result<[u8; 32], ()>
where
    FECDH: FnMut(&[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
{
    use chacha20poly1305::aead::heapless::Vec as HVec;
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::KeyInit;
    use chacha20poly1305::ChaCha20Poly1305;
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Parse ECIES layout
    let eph_pubkey_compressed: [u8; PUBLIC_KEY_LEN] =
        ciphertext[0..PUBLIC_KEY_LEN].try_into().map_err(|_| ())?;
    let chacha_nonce: [u8; 12] = ciphertext[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 12]
        .try_into()
        .map_err(|_| ())?;
    let ct_and_tag = &ciphertext[PUBLIC_KEY_LEN + 12..];

    // Step 1: compute ECDH shared secret via caller callback
    let shared_secret = ecdh_shared_secret(&eph_pubkey_compressed)?;

    // Step 2: derive encryption key via HKDF-SHA256 (same salt/info as gateway).
    let hkdf = Hkdf::<Sha256>::new(Some(&eph_pubkey_compressed), &shared_secret);
    let mut enc_key = [0u8; 32];
    hkdf.expand(b"ecies-enc", &mut enc_key).map_err(|_| ())?;

    // Step 3: decrypt ChaCha20Poly1305 in-place into a heapless buffer.
    let mut buf: HVec<u8, { CHALLENGE_PLAINTEXT_LEN + 16 }> = HVec::new();
    buf.extend_from_slice(ct_and_tag).map_err(|_| ())?;
    let cipher = ChaCha20Poly1305::new((&enc_key).into());
    cipher
        .decrypt_in_place((&chacha_nonce).into(), b"", &mut buf)
        .map_err(|_| ())?;

    out.copy_from_slice(&buf.as_slice()[..CHALLENGE_PLAINTEXT_LEN]);
    Ok(shared_secret)
}

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

#[cfg(test)]
mod tests;

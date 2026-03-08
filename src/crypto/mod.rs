use chacha20poly1305::{
    aead::generic_array::GenericArray,
    aead::{heapless::Vec, AeadInPlace},
    ChaCha20Poly1305, KeyInit,
};

/// Encrypts a buffer in place using ChaCha20-Poly1305.
///
/// # Arguments
/// - `buffer`: A mutable buffer to encrypt (must have capacity for nonce + ciphertext).
/// - `key`: The encryption key (32 bytes).
/// - `nonce`: A 12-byte nonce.
/// - `aad`: Optional Additional Authenticated Data.
///
/// # Returns
/// - `Ok(())` if encryption succeeds.
/// - `Err(&str)` if encryption fails or buffer capacity is insufficient.

pub fn encrypt<const N: usize>(
    buffer: &mut Vec<u8, N>,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
) -> Result<usize, &'static str> {
    let aad = aad.unwrap_or(&[]);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce_ga = GenericArray::from_slice(nonce);

    // Encrypt in place
    cipher
        .encrypt_in_place(nonce_ga, aad, buffer)
        .map_err(|_| "Encryption failed")?;

    // Prepare a new buffer: [nonce | ciphertext]
    let mut temp_buffer: Vec<u8, N> = Vec::new();
    temp_buffer
        .extend_from_slice(nonce)
        .map_err(|_| "Nonce copy failed")?;
    temp_buffer
        .extend_from_slice(buffer)
        .map_err(|_| "Ciphertext copy failed")?;

    buffer.clear();
    buffer
        .extend_from_slice(&temp_buffer)
        .map_err(|_| "Final copy to buffer failed")?;

    Ok(buffer.len())
}

/// Decrypts a buffer in place using ChaCha20-Poly1305.
///
/// # Arguments
/// - `buffer`: A mutable buffer that includes [nonce | ciphertext].
/// - `key`: The decryption key (32 bytes).
/// - `aad`: Optional Additional Authenticated Data.
///
/// # Returns
/// - `Ok(())` if decryption succeeds.
/// - `Err(&str)` if decryption fails or buffer format is invalid.
pub fn decrypt<const N: usize>(
    buffer: &mut Vec<u8, N>,
    key: &[u8; 32],
    aad: Option<&[u8]>,
) -> Result<(), &'static str> {
    if buffer.len() < 12 {
        return Err("Buffer too short: missing nonce");
    }
    let aad = aad.unwrap_or(&[]);
    let nonce = GenericArray::clone_from_slice(&buffer[..12]);

    // Shift ciphertext to start
    let ciphertext_len = buffer.len() - 12;
    for i in 0..ciphertext_len {
        buffer[i] = buffer[i + 12];
    }
    buffer.truncate(ciphertext_len);

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    cipher
        .decrypt_in_place(&nonce, aad, buffer)
        .map_err(|_| "Decryption failed")
}

#[cfg(test)]
pub mod tests;

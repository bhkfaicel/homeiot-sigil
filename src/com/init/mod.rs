pub mod gateway;
pub mod sensor;

/// Maximum init message size (header + encrypted body). P-256 init (compressed pubkey 33 + sig 64)
/// needs a larger envelope; may exceed SX1278 single-packet limit (255); firmware may fragment or
/// use a different transport for init.
pub const INIT_MESSAGE_MAX: usize = 256;

/// Default key for compatibility with legacy tests and development.
///
/// ⚠️ **DEPRECATED** : This key should ONLY be used for tests.
/// In production, use `KeyManager` to derive unique keys per device.
///
/// # Security
///
/// This key is hardcoded and identical for all devices.
/// It must NEVER be used in production.
#[deprecated(note = "Use KeyManager to derive unique keys per device")]
pub const DEFAULT_KEY: [u8; 32] = [0x26; 32];

/// Test-only helpers shared across init-related tests.
#[cfg(test)]
pub mod test_helpers {
    use super::sensor::{PUBLIC_KEY_LEN, SIGNATURE_LEN};

    /// Dummy public key (all zeros, development size).
    pub fn dummy_pubkey() -> [u8; PUBLIC_KEY_LEN] {
        [0u8; PUBLIC_KEY_LEN]
    }

    /// Dummy signature (all zeros, development size).
    pub fn dummy_sig() -> [u8; SIGNATURE_LEN] {
        [0u8; SIGNATURE_LEN]
    }
}

use hkdf::Hkdf;
use sha2::Sha256;

/// Key manager using HKDF to derive unique keys per device.
///
/// This module implements cryptographic key derivation according to RFC 5869 (HKDF)
/// to ensure that each device uses a unique key derived from a master secret.
///
/// # Security
///
/// - Each device derives its key from a master secret + its unique identifier
/// - Session keys can be derived for each communication
/// - The master secret must NEVER be stored in the source code
///
/// # Example
///
/// ```rust
/// use sigil::com::keys::KeyManager;
///
/// // ⚠️ IN PRODUCTION: The master secret must be loaded from secure storage
/// // (Secure Element, TPM, or protected memory)
/// let master_key = [0x42; 32]; // Example only - NEVER hardcode in production!
/// let device_id = [0xAA; 17]; // Device MAC address or unique identifier
///
/// let key_manager = KeyManager::new(master_key, device_id);
///
/// // Derive the device key
/// let device_key = key_manager.derive_device_key();
///
/// // Derive a session key for a specific message
/// let nonce = [0x01; 12]; // Unique nonce for this session
/// let session_key = key_manager.derive_session_key(&nonce);
///
/// // Derive a usage-specific key
/// let installation_key = key_manager.derive_usage_key(b"installation");
/// ```
pub struct KeyManager {
    master_key: [u8; 32],
    device_id: [u8; 17],
}

impl KeyManager {
    /// Creates a new key manager.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master secret (32 bytes). **NEVER hardcode in source code!**
    /// * `device_id` - The unique device identifier (MAC address, UID, etc.)
    ///
    /// # Security
    ///
    /// The `master_key` must be:
    /// - Stored in a Secure Element or TPM if available
    /// - Or loaded from protected memory (encrypted flash)
    /// - Or derived from a securely stored secret
    /// - **NEVER** hardcoded in source code
    pub fn new(master_key: [u8; 32], device_id: [u8; 17]) -> Self {
        Self {
            master_key,
            device_id,
        }
    }

    /// Derives the unique device key from the master secret.
    ///
    /// This key is deterministic: the same `master_key` + `device_id` will always
    /// produce the same device key. This key can be used for normal device communications.
    ///
    /// # Returns
    ///
    /// A 32-byte key derived via HKDF-SHA256.
    pub fn derive_device_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.device_id), &self.master_key);
        let mut okm = [0u8; 32];
        hk.expand(b"device_key", &mut okm)
            .expect("HKDF expand should never fail for 32 bytes");
        okm
    }

    /// Derives an ephemeral session key for a specific communication.
    ///
    /// This key is derived from the device key + a unique nonce.
    /// Each message can use a different nonce to generate a unique session key.
    ///
    /// # Arguments
    ///
    /// * `nonce` - A unique nonce (12 bytes) for this session
    ///
    /// # Returns
    ///
    /// A 32-byte session key derived via HKDF-SHA256.
    pub fn derive_session_key(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let device_key = self.derive_device_key();
        let hk = Hkdf::<Sha256>::new(Some(nonce), &device_key);
        let mut okm = [0u8; 32];
        hk.expand(b"session", &mut okm)
            .expect("HKDF expand should never fail for 32 bytes");
        okm
    }

    /// Derives a key for a specific usage (installation, validation, etc.).
    ///
    /// Allows separating keys by function for better security.
    ///
    /// # Arguments
    ///
    /// * `usage` - The usage context (e.g., b"installation", b"validation", b"data")
    ///
    /// # Returns
    ///
    /// A 32-byte key derived via HKDF-SHA256 for the specified usage.
    pub fn derive_usage_key(&self, usage: &[u8]) -> [u8; 32] {
        let device_key = self.derive_device_key();
        let hk = Hkdf::<Sha256>::new(Some(usage), &device_key);
        let mut okm = [0u8; 32];
        hk.expand(b"usage", &mut okm)
            .expect("HKDF expand should never fail for 32 bytes");
        okm
    }

    /// Returns the device identifier.
    pub fn device_id(&self) -> &[u8; 17] {
        &self.device_id
    }
}

/// Validated key with local expiration tracking
///
/// Stores the key received from gateway along with the local timestamp
/// (in RTC ticks) when it was received, allowing expiration checking
/// without requiring absolute time synchronization.
///
/// # How it works
///
/// 1. When a key is received from the gateway, it contains:
///    - `timestamp`: Unix timestamp when the key was issued
///    - `expire_at`: Unix timestamp when the key expires
///
/// 2. We calculate the validity duration:
///    - `duration_seconds = expire_at - timestamp`
///
/// 3. We store the local RTC ticks when the key was received:
///    - `received_at_ticks = Mono::now().ticks()`
///
/// 4. To check if the key is still valid:
///    - Calculate elapsed time: `elapsed_ticks = Mono::now().ticks() - received_at_ticks`
///    - Convert to seconds: `elapsed_seconds = elapsed_ticks / RTC_FREQ`
///    - Compare: `elapsed_seconds < duration_seconds`
///
/// 5. Automatic renewal (when 1/4 of time remains):
///    - Renewal threshold: `elapsed_seconds >= duration_seconds * 3/4`
///    - Triggers proactive renewal to avoid service interruption
///
/// Session key with expiry metadata, as returned by the handshake.
///
/// `expire_at` is the Unix timestamp when the key expires (0 = never expires).
/// `timestamp` is the Unix timestamp when the key was issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub key: [u8; 32],
    pub expire_at: u32,
    pub timestamp: u32,
}

pub struct ValidatedKey {
    key: Keys,
    received_at_ticks: u64,
    duration_seconds: u32,
}

impl ValidatedKey {
    /// RTC frequency in Hz (32.768 kHz is standard for RTCs)
    pub const RTC_FREQ: u64 = 32768;

    /// Creates a new ValidatedKey from a Keys struct.
    ///
    /// # Arguments
    ///
    /// - `key`: The Keys struct (session key + expiry).
    /// - `received_at_ticks`: The RTC ticks when the key was received.
    pub fn new(key: Keys, received_at_ticks: u64) -> Self {
        let duration_seconds = if key.expire_at == 0 {
            u32::MAX // Never expires
        } else { key.expire_at.saturating_sub(key.timestamp) };

        Self {
            key,
            received_at_ticks,
            duration_seconds,
        }
    }

    /// Checks if the key is still valid based on elapsed time
    ///
    /// # Arguments
    ///
    /// - `current_ticks`: Current RTC ticks
    ///
    /// # Returns
    ///
    /// `true` if key is still valid, `false` if expired
    pub fn is_valid(&self, current_ticks: u64) -> bool {
        if self.duration_seconds == u32::MAX {
            return true;
        }

        let elapsed_ticks = current_ticks.saturating_sub(self.received_at_ticks);
        let elapsed_seconds = (elapsed_ticks / Self::RTC_FREQ) as u32;

        elapsed_seconds < self.duration_seconds
    }

    /// Checks if the key should be renewed (when 1/4 of time remains)
    ///
    /// # Arguments
    ///
    /// - `current_ticks`: Current RTC ticks
    ///
    /// # Returns
    ///
    /// `true` if key should be renewed (75% of duration elapsed)
    pub fn should_renew(&self, current_ticks: u64) -> bool {
        if self.duration_seconds == u32::MAX {
            return false;
        }

        let elapsed_ticks = current_ticks.saturating_sub(self.received_at_ticks);
        let elapsed_seconds = (elapsed_ticks / Self::RTC_FREQ) as u32;
        let renewal_threshold = ((self.duration_seconds as u64) * 3 / 4) as u32;

        elapsed_seconds >= renewal_threshold
    }

    /// Returns a reference to the underlying Keys
    pub fn keys(&self) -> &Keys {
        &self.key
    }

    /// Consumes self and returns the underlying Keys.
    pub fn into_keys(self) -> Keys {
        self.key
    }
}

#[cfg(test)]
mod tests;

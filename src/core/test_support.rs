//! Shared mock implementations for unit tests
//!
//! This module provides mock implementations of the `SecureElement` and
//! `RandomSource` traits, reused across the unit tests of the core modules.
//! It is only compiled under `cfg(test)`.

#![cfg(test)]

use crate::core::error::SigilError;
use crate::core::traits::{
    EcdhSharedSecret, EcdsaSignature, FactoryCertificateMetadata, RandomSource, SecureElement,
    StaticPublicKey,
};

/// Deterministic message→signature binding used by [`MockSecureElement`].
/// This is **not** real ECDSA. It folds the message into a 64-byte tag so that
/// `verify_ecdsa` rejects signatures produced for a different message. That
/// catches protocol bugs such as signing `gateway_nonce` while verifying
/// `b"install-confirm"`.
fn mock_message_tag(message: &[u8]) -> EcdsaSignature {
    let mut tag = [0x99u8; 64];
    for (i, byte) in message.iter().enumerate() {
        tag[i % 64] ^= byte.wrapping_add((i % 251) as u8);
    }
    // Mix in the length so prefixes of different lengths do not collide trivially.
    let len = message.len() as u8;
    tag[0] ^= len;
    tag[63] ^= len.wrapping_mul(3);
    tag
}

/// Mock implementation of `SecureElement` for testing
/// Returns deterministic values so tests are reproducible without a real
/// hardware secure element.
/// ECDSA is simulated with a message-bound tag ([`mock_message_tag`]) so
/// verify fails when the verified message does not match the signed one.
/// Factory certificates are tags over
/// [`crate::core::install::factory_cert_message`] using [`Self::device_mac`]
/// and [`Self::product_id`] — configure these to match the
/// [`SessionManager`](crate::core::manager::SessionManager) local MAC / role.
/// The mock can be switched into "reject" mode via [`Self::reject_signatures`]
/// to exercise verification-failure paths.
pub struct MockSecureElement {
    static_pubkey: StaticPublicKey,
    /// Wire PeerId this mock claims (must match manager `local_mac` in install tests).
    pub device_mac: [u8; 17],
    /// Factory product id ([`crate::core::install::FACTORY_PRODUCT_ID_SENSOR`] /
    /// [`FACTORY_PRODUCT_ID_GATEWAY`](crate::core::install::FACTORY_PRODUCT_ID_GATEWAY)).
    pub product_id: u16,
    /// Immutable metadata signed into the mock factory certificate.
    pub factory_metadata: FactoryCertificateMetadata,
    /// When true, `verify_ecdsa` always returns `VerificationFailed`.
    reject_verify: bool,
    /// When true, `ecdh` returns `EcdhFailed`.
    reject_ecdh: bool,
}

impl MockSecureElement {
    /// Creates a mock secure element with the given static public key.
    /// Defaults to sensor product id and MAC `[0x10; 17]` (matches
    /// [`test_manager`] default local MAC).
    pub fn new(static_pubkey: StaticPublicKey) -> Self {
        Self::with_identity(
            static_pubkey,
            [0x10u8; 17],
            crate::core::install::FACTORY_PRODUCT_ID_SENSOR,
        )
    }

    /// Creates a mock with explicit identity for factory cert tags.
    pub fn with_identity(
        static_pubkey: StaticPublicKey,
        device_mac: [u8; 17],
        product_id: u16,
    ) -> Self {
        Self {
            static_pubkey,
            device_mac,
            product_id,
            factory_metadata: FactoryCertificateMetadata {
                hardware_profile_id: 1,
                factory_key_id: 1,
            },
            reject_verify: false,
            reject_ecdh: false,
        }
    }

    /// Creates a mock with a distinct pubkey derived from the given byte.
    pub fn with_id(id: u8) -> Self {
        Self::new([id; 33])
    }

    /// Sensor-side mock bound to `device_mac`.
    pub fn sensor(id: u8, device_mac: [u8; 17]) -> Self {
        Self::with_identity(
            [id; 33],
            device_mac,
            crate::core::install::FACTORY_PRODUCT_ID_SENSOR,
        )
    }

    /// Gateway-side mock bound to `device_mac`.
    pub fn gateway(id: u8, device_mac: [u8; 17]) -> Self {
        Self::with_identity(
            [id; 33],
            device_mac,
            crate::core::install::FACTORY_PRODUCT_ID_GATEWAY,
        )
    }

    /// Switch the mock so subsequent `verify_ecdsa` calls fail.
    pub fn reject_signatures(&mut self) {
        self.reject_verify = true;
    }

    /// Switch the mock so subsequent `ecdh` calls fail.
    #[allow(dead_code)]
    pub fn reject_ecdh(&mut self) {
        self.reject_ecdh = true;
    }
}

impl Default for MockSecureElement {
    fn default() -> Self {
        Self::new([1u8; 33])
    }
}

impl SecureElement for MockSecureElement {
    fn ecdh(&mut self, _peer_static_pubkey: &[u8; 33]) -> Result<EcdhSharedSecret, SigilError> {
        if self.reject_ecdh {
            return Err(SigilError::EcdhFailed);
        }
        // For testing, return a deterministic shared secret.
        Ok([0x42u8; 32])
    }

    fn sign_ecdsa(&mut self, message: &[u8]) -> Result<EcdsaSignature, SigilError> {
        Ok(mock_message_tag(message))
    }

    fn verify_ecdsa(
        &mut self,
        _peer_static_pubkey: &[u8; 33],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), SigilError> {
        if self.reject_verify {
            return Err(SigilError::VerificationFailed);
        }
        if *signature != mock_message_tag(message) {
            return Err(SigilError::VerificationFailed);
        }
        Ok(())
    }

    fn get_static_pubkey(&mut self) -> Result<StaticPublicKey, SigilError> {
        Ok(self.static_pubkey)
    }

    fn get_factory_cert(&mut self) -> Result<EcdsaSignature, SigilError> {
        // Factory cert covers product, immutable metadata, PeerId and pubkey.
        let msg = crate::core::install::factory_cert_message(
            self.product_id,
            self.factory_metadata,
            &self.device_mac,
            &self.static_pubkey,
        )
        .expect("factory_cert_message fits FACTORY_CERT_MSG_LEN");
        Ok(mock_message_tag(&msg))
    }

    fn get_factory_cert_metadata(&mut self) -> Result<FactoryCertificateMetadata, SigilError> {
        Ok(self.factory_metadata)
    }
}

/// Factory root public key used by unit tests.
/// Arbitrary compressed-looking bytes; the mock verifier only checks the
/// message tag, not a real ECDSA curve point.
pub const TEST_FACTORY_PUBKEY: StaticPublicKey = [0xFAu8; 33];

/// Builds a [`crate::core::manager::SessionManager`] with [`TEST_FACTORY_PUBKEY`].
/// `local_mac` defaults to `[0x10; 17]` for single-manager tests. Pairwise
/// tests should call [`SessionManager::new`](crate::core::manager::SessionManager::new)
/// with distinct sensor/gateway MACs.
pub fn test_manager<const N: usize>() -> crate::core::manager::SessionManager<N> {
    crate::core::manager::SessionManager::new(TEST_FACTORY_PUBKEY, [0x10u8; 17])
}

/// Builds a manager with an explicit local MAC (multi-peer / pairwise tests).
pub fn test_manager_with_mac<const N: usize>(
    local_mac: [u8; 17],
) -> crate::core::manager::SessionManager<N> {
    crate::core::manager::SessionManager::new(TEST_FACTORY_PUBKEY, local_mac)
}

/// Active session helper with **symmetric** TX/RX halves (loopback / single-peer).
/// Prefer [`active_session_role`] / distinct material for pairwise sensor↔gateway.
#[allow(dead_code)]
pub fn active_session(
    peer: crate::core::session::PeerId,
    pubkey: crate::core::session::StaticPublicKeyBytes,
    key: crate::core::session::SessionKey,
    prefix: crate::core::session::NoncePrefix,
    resume_psk: crate::core::session::ResumePsk,
    key_expire_at: u32,
    now: u32,
) -> crate::core::session::Session {
    use crate::core::session::{DirectionalMaterial, Session, SessionRole};
    Session::new_active(
        peer,
        pubkey,
        DirectionalMaterial::symmetric_for_test(key, prefix),
        SessionRole::Sensor,
        resume_psk,
        key_expire_at,
        now,
    )
    .expect("test active session")
}

/// Active session with an explicit [`SessionRole`] and symmetric material.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn active_session_role(
    peer: crate::core::session::PeerId,
    pubkey: crate::core::session::StaticPublicKeyBytes,
    key: crate::core::session::SessionKey,
    prefix: crate::core::session::NoncePrefix,
    resume_psk: crate::core::session::ResumePsk,
    key_expire_at: u32,
    now: u32,
    role: crate::core::session::SessionRole,
) -> crate::core::session::Session {
    use crate::core::session::{DirectionalMaterial, Session};
    Session::new_active(
        peer,
        pubkey,
        DirectionalMaterial::symmetric_for_test(key, prefix),
        role,
        resume_psk,
        key_expire_at,
        now,
    )
    .expect("test active session")
}

/// Pair of sessions sharing **distinct** directional material.
#[allow(clippy::too_many_arguments)]
pub fn pair_active_sessions(
    sensor_peer: crate::core::session::PeerId,
    gateway_peer: crate::core::session::PeerId,
    pubkey: crate::core::session::StaticPublicKeyBytes,
    key: crate::core::session::SessionKey,
    prefix: crate::core::session::NoncePrefix,
    resume_psk: crate::core::session::ResumePsk,
    key_expire_at: u32,
    now: u32,
) -> (crate::core::session::Session, crate::core::session::Session) {
    use crate::core::session::{DirectionalMaterial, Session, SessionRole};
    let material = DirectionalMaterial::distinct_for_test(key, prefix);
    let sensor = Session::new_active(
        gateway_peer,
        pubkey,
        material.clone(),
        SessionRole::Sensor,
        resume_psk,
        key_expire_at,
        now,
    )
    .expect("sensor session");
    let gateway = Session::new_active(
        sensor_peer,
        pubkey,
        material,
        SessionRole::Gateway,
        resume_psk,
        key_expire_at,
        now,
    )
    .expect("gateway session");
    (sensor, gateway)
}

/// Mock implementation of `RandomSource` for testing
/// Produces an incrementing byte sequence so successive calls yield different
/// values, which is required by the ephemeral ECDH tests.
pub struct MockRandom {
    counter: u8,
}

impl MockRandom {
    /// Creates a mock random source that produces incrementing bytes
    pub fn new() -> Self {
        Self { counter: 0 }
    }
}

impl Default for MockRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl RandomSource for MockRandom {
    fn fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), SigilError> {
        // For testing, fill with incrementing values
        for byte in buffer.iter_mut() {
            *byte = self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}

/// Mock RNG that always fails — used to verify callers propagate `RandomFailed`.
pub struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill_bytes(&mut self, _buffer: &mut [u8]) -> Result<(), SigilError> {
        Err(SigilError::RandomFailed)
    }
}

//! Host-provided capability traits
//!
//! This module defines traits that the host firmware must implement to provide
//! cryptographic operations and randomness to the sigil core.

use crate::core::error::SigilError;

/// Static public key type (33-byte P-256 compressed format)
pub type StaticPublicKey = [u8; 33];

/// ECDH shared secret type (32 bytes)
pub type EcdhSharedSecret = [u8; 32];

/// Compressed SEC1 P-256 public key used by ephemeral Renew.
pub type EphemeralP256PublicKey = [u8; 33];

/// Opaque gateway state retained between RenewChallenge and RenewConfirm.
/// A software backend may store a scalar; a hardware backend may store a
/// handle. Sigil always treats it as secret and zeroizes it.
pub type GatewayEphemeralP256Context = [u8; 32];

/// ECDSA signature type (64 bytes for P-256)
pub type EcdsaSignature = [u8; 64];

/// Immutable identifiers provisioned with the factory certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactoryCertificateMetadata {
    /// Hardware/BOM profile selected at manufacturing time.
    pub hardware_profile_id: u8,
    /// Identifier of the factory signing key used for this certificate.
    pub factory_key_id: u8,
}

/// Secure element capability trait
/// This trait defines the cryptographic operations that must be provided by the host
/// through a secure element (e.g., ATECC608x). The host firmware implements this trait
/// to interface with the hardware secure element without exposing private keys.
/// # Host scheduling
/// Install / resume paths may call **several** SE methods in one sigil API
/// invocation (verify, ECDH, sign, …). That call is non-blocking for the
/// **radio** (sigil returns immediately after SE work), but it **occupies the
/// calling task** for the full SE chain.
/// Product rule on the **sensor** (PERF-M2): door-open / vibration (and similar) detection
/// is **higher priority** than install. Host requirements:
/// 1. Implement door / vibration as **IRQs** (or a high-priority task) that can
///    still run while the main task is inside `SecureElement` I2C waits — do
///    **not** globally mask those IRQs for the whole install chain.
/// 2. Keep ISRs short (latch “door open” / “vibrated”); process policy in the
///    main loop when not inside a long SE call if needed.
/// 3. Treat install as **best-effort background**: defer `start_install` /
///    `continue_install` if a critical sensing window is active, or accept that
///    the main loop will not poll until the SE call returns.
///
/// Splitting SE ops across multiple sigil API steps (async SE) is **not**
/// required for v1; revisit only if measured ATECC latency breaks sensing SLAs.
pub trait SecureElement {
    /// Performs ECDH key agreement with the peer's static public key
    /// # Arguments
    /// * `peer_static_pubkey` - The peer's static public key (33-byte compressed SEC1)
    ///
    /// # Returns
    /// The ECDH shared secret (32 bytes) on success, or an error if the operation fails
    /// # Security
    /// The private key used for ECDH must remain inside the secure element and
    /// never be extracted into RAM. Implementations must reject malformed,
    /// non-canonical, off-curve, infinity or non-compressed peer keys and must
    /// never return an all-zero shared secret. Sigil independently rejects a
    /// null result at every protocol call site as defense in depth.
    fn ecdh(&mut self, peer_static_pubkey: &[u8; 33]) -> Result<EcdhSharedSecret, SigilError>;

    /// Atomically generates a P-256 private key in volatile secure-element
    /// memory and immediately performs ECDH with `peer_ephemeral_pubkey`.
    ///
    /// The sensor implementation must execute ATECC `GenKey` with
    /// `KeyID=0xFFFF` followed immediately by ECDH from `TempKey`, without
    /// yielding, sleeping the ATECC, or writing a Data Slot between commands.
    /// It returns the local compressed SEC1 public key and raw 32-byte ECDH
    /// secret. The ephemeral private key must never leave the secure element.
    /// The implementation must reject invalid, non-canonical, off-curve or
    /// non-compressed peer keys.
    #[cfg(feature = "sensor")]
    fn ephemeral_p256_ecdh(
        &mut self,
        peer_ephemeral_pubkey: &EphemeralP256PublicKey,
    ) -> Result<(EphemeralP256PublicKey, EcdhSharedSecret), SigilError>;

    /// Gateway Renew step 1: creates a fresh P-256 keypair using host entropy
    /// and returns the compressed public key plus opaque continuation state.
    /// A software implementation may return its scalar as context; hardware
    /// may return a handle. Sigil zeroizes the context after use.
    #[cfg(feature = "gateway")]
    fn generate_ephemeral_p256_keypair(
        &mut self,
        rng: &mut impl RandomSource,
    ) -> Result<(EphemeralP256PublicKey, GatewayEphemeralP256Context), SigilError>;

    /// Gateway Renew step 2: completes ECDH with the context created at Request
    /// time. Implementations must reject malformed, non-canonical, off-curve or
    /// infinity peer keys and reject a null shared secret.
    #[cfg(feature = "gateway")]
    fn complete_ephemeral_p256_ecdh(
        &mut self,
        context: &GatewayEphemeralP256Context,
        peer_ephemeral_pubkey: &EphemeralP256PublicKey,
    ) -> Result<EcdhSharedSecret, SigilError>;

    /// Signs a message using the device's static identity key
    /// # Arguments
    /// * `message` - The message to sign
    ///
    /// # Returns
    /// The ECDSA signature (64 bytes) on success, or an error if the operation fails
    /// # Security
    /// The private key used for signing must remain inside the secure element and never
    /// be extracted into RAM.
    fn sign_ecdsa(&mut self, message: &[u8]) -> Result<EcdsaSignature, SigilError>;

    /// Verifies an ECDSA signature from a peer
    /// # Arguments
    /// * `peer_static_pubkey` - The peer's static public key (33-byte compressed SEC1)
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify (64 bytes)
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(SigilError::VerificationFailed)` if invalid
    /// # Security
    /// Implementations must reject malformed, non-canonical, non-compressed,
    /// off-curve or infinity public keys before signature verification.
    fn verify_ecdsa(
        &mut self,
        peer_static_pubkey: &[u8; 33],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), SigilError>;

    /// Returns the device's static public key
    /// # Returns
    /// The device's static public key (33-byte compressed SEC1 format)
    /// # Security
    /// The returned value must be a canonical compressed P-256 point with a
    /// `0x02` or `0x03` prefix. Sentinel or malformed keys must be rejected.
    fn get_static_pubkey(&mut self) -> Result<StaticPublicKey, SigilError>;

    /// Returns the factory certificate signature for this device.
    /// At manufacturing time the factory signs the canonical message
    /// [`crate::core::install::factory_cert_message`]:
    /// `version ‖ product_id ‖ hardware_profile_id ‖ factory_key_id ‖ peer_mac ‖
    /// compressed_pubkey` (55 bytes) with the
    /// factory private key. That signature is stored in the ATECC (or host NVRAM)
    /// and returned here so install can embed it on the wire. Peers reconstruct
    /// the same message from the wire PeerId + pubkey and verify against their
    /// locally cached factory public key
    /// ([`crate::core::manager::SessionManager::factory_pubkey`]).
    /// # Returns
    /// ECDSA P-256 signature (64 bytes, r‖s) of the factory-cert message under
    /// the factory key, or an error if the certificate cannot be read.
    fn get_factory_cert(&mut self) -> Result<EcdsaSignature, SigilError>;

    /// Returns the immutable metadata covered by the factory certificate.
    ///
    /// These values must come from the same protected manufacturing record as
    /// [`Self::get_factory_cert`]. They must not be inferred from runtime board
    /// detection or selected from untrusted radio input.
    fn get_factory_cert_metadata(&mut self) -> Result<FactoryCertificateMetadata, SigilError>;
}

/// Random source capability trait
/// This trait defines the random number generation capability that must be provided by
/// the host firmware. The host implements this trait to supply cryptographically secure
/// randomness from a hardware TRNG or the secure element's random number generator.
pub trait RandomSource {
    /// Fills a buffer with cryptographically secure random bytes
    /// # Arguments
    /// * `buffer` - The buffer to fill with random bytes
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(SigilError::RandomFailed)` if the operation fails
    /// # Security
    /// The random source must be cryptographically secure (CSPRNG) and must not be
    /// predictable or repeatable across reboots.
    fn fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), SigilError>;
}

mod tests;

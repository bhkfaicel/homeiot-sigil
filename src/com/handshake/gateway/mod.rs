use crate::com::error::model::ComError;
use crate::com::handshake::{
    derive_session_key, CHALLENGE_PLAINTEXT_LEN, ECIES_CIPHERTEXT_LEN, HANDSHAKE_MESSAGE_MAX,
    PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use crate::com::handshake::sensor::HandshakeRequest;
use crate::models::common::{
    BodySchema, Destination::OneDestination, MessageSchema, MessageType, RequestType,
    ResponseType, deserialize_clear,
};
use bincode::{Decode, Encode};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// ECIES-encrypted challenge sent by the gateway to the sensor (Step 2).
///
/// `data` is the raw ECIES ciphertext (190 bytes):
/// `ephemeral_pubkey[33] || chacha_nonce[12] || ciphertext[129] || poly1305_tag[16]`
///
/// The plaintext inside is:
/// `sig_sensor_nonce[64] || gateway_pubkey[33] || gateway_nonce[32]`
///
/// Only the sensor holding the matching private key can decrypt this.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeChallenge {
    pub(super) data: [u8; ECIES_CIPHERTEXT_LEN],
}

/// Result returned by `handle_handshake_request` on success.
pub struct HandshakeResult {
    /// HKDF-derived session key for subsequent encrypted communication.
    pub session_key: [u8; 32],
    /// Sensor's P-256 compressed public key (for future message verification).
    pub sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    /// Unix timestamp when the session key expires (0 = never expires).
    ///
    /// Set by the gateway caller and transmitted to the sensor inside the ECIES ciphertext.
    pub key_expire_at: u32,
}

/// Gateway-side handshake handler (Steps 2 + 3).
///
/// Mirrors `verify_sensor_and_send_validate()` from the old init flow:
///
/// 1. **Verifies the sensor** via `verify_sensor` before sending anything.
/// 2. Calls `ecies_encrypt` to build the ECIES ciphertext for the sensor.
/// 3. Sends `HandshakeChallenge` over LoRa; waits for `HandshakeConfirm`.
/// 4. Verifies the confirm signature via `verify_sig_gateway_nonce`.
/// 5. Derives the session key using `HKDF-SHA256(shared_secret, sensor_nonce || gateway_nonce)`.
///
/// # Callbacks
/// - `verify_sensor`: verifies `(sensor_pubkey, sig_sensor_pubkey)`. Called before any LoRa
///   traffic — returns `false` to silently reject unknown sensors.
/// - `ecies_encrypt`: encrypts the 133-byte challenge plaintext using the sensor's public key.
///   Writes the 194-byte ECIES ciphertext to `out`. Returns the ECDH shared secret.
/// - `verify_sig_gateway_nonce`: verifies `(sensor_pubkey, sig_gateway_nonce)`.
///
/// `key_expire_at` is the Unix timestamp when the session key expires (0 = never expires).
/// It is packed into the ECIES plaintext so the sensor can construct a [`Keys`] struct with
/// the correct expiry without any additional round-trip.
///
/// # Errors
/// - `Err(ComError::VerificationFailed)` if any signature check fails.
/// - `Err(ComError::Timeout)` if no valid `HandshakeConfirm` is received.
#[allow(clippy::too_many_arguments)]
pub fn handle_handshake_request<SPI, CS, RST, SpiErr, FV, FE, FVN>(
    request: &HandshakeRequest,
    verify_sensor: FV,
    ecies_encrypt: FE,
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    verify_sig_gateway_nonce: FVN,
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    timestamp: u32,
) -> Result<HandshakeResult, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    FV: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FE: Fn(
        &[u8; PUBLIC_KEY_LEN],
        &[u8; CHALLENGE_PLAINTEXT_LEN],
        &mut [u8; ECIES_CIPHERTEXT_LEN],
    ) -> [u8; 32],
    FVN: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
{
    let rx_timeout = 4;

    // Step 1: verify sensor identity before sending anything
    if !verify_sensor(request.sensor_pubkey(), request.sig_sensor_pubkey()) {
        return Err(ComError::VerificationFailed);
    }

    // Build ECIES plaintext: sig_sensor_nonce[64] | gateway_pubkey[33] | gateway_nonce[32] | key_expire_at[4]
    let mut plaintext = [0u8; CHALLENGE_PLAINTEXT_LEN];
    plaintext[..SIGNATURE_LEN].copy_from_slice(&sig_sensor_nonce);
    plaintext[SIGNATURE_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN].copy_from_slice(&gateway_pubkey);
    plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN + 32]
        .copy_from_slice(&gateway_nonce);
    plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN + 32..]
        .copy_from_slice(&key_expire_at.to_be_bytes());

    // Encrypt via ECIES callback; shared_secret is used later for session key derivation
    let mut ciphertext = [0u8; ECIES_CIPHERTEXT_LEN];
    let shared_secret = ecies_encrypt(request.sensor_pubkey(), &plaintext, &mut ciphertext);

    // Step 2: send HandshakeChallenge (ECIES ciphertext), then listen for HandshakeConfirm
    let mut challenge_msg = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::HandshakeChallenge,
        ResponseType::HandshakeChallenge(HandshakeChallenge { data: ciphertext }),
        timestamp,
    );
    let buffer = challenge_msg
        .serialize_clear::<HANDSHAKE_MESSAGE_MAX>()
        .map_err(ComError::Custom)?;
    lora.set_mode(lora::sx1278::Mode::Manual, delay);
    lora.send(&buffer, delay)?;
    lora.set_mode(lora::sx1278::Mode::Receiver, delay);

    // Step 3: wait for HandshakeConfirm
    let mut recv_buffer = [0u8; HANDSHAKE_MESSAGE_MAX];
    for _ in 0..rx_timeout {
        let receive_result =
            if let Ok(r) = lora.receive::<SpiErr, _>(&mut recv_buffer, delay) {
                r
            } else {
                delay.delay_ms(5000u32);
                continue;
            };

        let clear_msg = match deserialize_clear::<HANDSHAKE_MESSAGE_MAX>(
            &recv_buffer[..receive_result.size],
        ) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if clear_msg.header.message_type != MessageType::HandshakeConfirm {
            continue;
        }
        if clear_msg.header.dist != OneDestination(gateway_mac) {
            continue;
        }

        if let BodySchema::RequestType(RequestType::HandshakeConfirm(confirm)) = clear_msg.body {
            if !verify_sig_gateway_nonce(request.sensor_pubkey(), confirm.sig_gateway_nonce()) {
                return Err(ComError::VerificationFailed);
            }
            let session_key =
                derive_session_key(&shared_secret, request.sensor_nonce(), &gateway_nonce);
            return Ok(HandshakeResult {
                session_key,
                sensor_pubkey: *request.sensor_pubkey(),
                key_expire_at,
            });
        }
    }

    Err(ComError::Timeout)
}

#[cfg(test)]
pub mod tests;

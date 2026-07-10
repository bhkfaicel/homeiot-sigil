use crate::com::error::model::ComError;
use crate::com::handshake::install_core::gateway::send_install_challenge_and_wait_confirm;
use crate::com::handshake::install_core::HandshakeResult;
use crate::com::handshake::install::sensor::HandshakeRequest;
use crate::com::handshake::{
    CHALLENGE_PLAINTEXT_LEN, ECIES_CIPHERTEXT_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// First-time installation handler: verify sensor identity + install core (ECIES + ECDSA).
#[allow(clippy::too_many_arguments)]
pub fn handle_install_request<SPI, CS, RST, SpiErr, FV, FE, FVN>(
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
    SpiErr: core::fmt::Debug,
    FV: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FE: Fn(
        &[u8; PUBLIC_KEY_LEN],
        &[u8; CHALLENGE_PLAINTEXT_LEN],
        &mut [u8; ECIES_CIPHERTEXT_LEN],
    ) -> [u8; 32],
    FVN: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
{
    if !verify_sensor(request.sensor_pubkey(), request.sig_sensor_pubkey()) {
        return Err(ComError::VerificationFailed);
    }

    send_install_challenge_and_wait_confirm(
        sensor_mac,
        gateway_mac,
        request.sensor_pubkey(),
        request.sensor_nonce(),
        &gateway_pubkey,
        &sig_sensor_nonce,
        &gateway_nonce,
        key_expire_at,
        ecies_encrypt,
        verify_sig_gateway_nonce,
        lora,
        delay,
        timestamp,
    )
}

/// Backward-compatible alias for [`handle_install_request`].
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
    SpiErr: core::fmt::Debug,
    FV: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FE: Fn(
        &[u8; PUBLIC_KEY_LEN],
        &[u8; CHALLENGE_PLAINTEXT_LEN],
        &mut [u8; ECIES_CIPHERTEXT_LEN],
    ) -> [u8; 32],
    FVN: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
{
    handle_install_request(
        request,
        verify_sensor,
        ecies_encrypt,
        sensor_mac,
        gateway_mac,
        gateway_pubkey,
        sig_sensor_nonce,
        gateway_nonce,
        key_expire_at,
        verify_sig_gateway_nonce,
        lora,
        delay,
        timestamp,
    )
}

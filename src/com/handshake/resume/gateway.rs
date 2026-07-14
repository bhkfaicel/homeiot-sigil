use crate::com::error::model::ComError;
use crate::com::handshake::install_core::HandshakeResult;
use crate::com::handshake::resume_core::SessionResumeRequest;
use crate::com::handshake::resume_core::gateway::send_resume_challenge_and_wait_confirm;
use crate::com::handshake::PUBLIC_KEY_LEN;
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Session resume handler for an already-enrolled sensor (ECDSA + eph-eph ECDH, no old session key).
///
/// The gateway must look up `sensor_pubkey` from its enrollment registry (sensor MAC in the
/// request header). `verify_sig_sensor_nonce` validates the resume request signature.
#[allow(clippy::too_many_arguments)]
pub fn handle_resume_request<SPI, CS, RST, SpiErr, FVS, FGEN, FECDH, FVN>(
    request: &SessionResumeRequest,
    verify_sig_sensor_nonce: FVS,
    generate_gateway_ephemeral: FGEN,
    ecdh_with_sensor_ephemeral: FECDH,
    verify_sig_gateway_nonce: FVN,
    sensor_pubkey: &[u8; PUBLIC_KEY_LEN],
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_nonce: [u8; crate::com::handshake::SIGNATURE_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    timestamp: u32,
) -> Result<HandshakeResult, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    SpiErr: core::fmt::Debug,
    FVS: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; crate::com::handshake::SIGNATURE_LEN]) -> bool,
    FGEN: Fn() -> Result<[u8; PUBLIC_KEY_LEN], ()>,
    FECDH: Fn(&[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
    FVN: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; crate::com::handshake::SIGNATURE_LEN]) -> bool,
{
    if !verify_sig_sensor_nonce(sensor_pubkey, request.sig_sensor_nonce()) {
        return Err(ComError::VerificationFailed);
    }

    send_resume_challenge_and_wait_confirm(
        request,
        generate_gateway_ephemeral,
        ecdh_with_sensor_ephemeral,
        verify_sig_gateway_nonce,
        sensor_pubkey,
        sensor_mac,
        gateway_mac,
        &gateway_pubkey,
        &sig_sensor_nonce,
        &gateway_nonce,
        key_expire_at,
        lora,
        delay,
        timestamp,
    )
}

use crate::com::error::model::ComError;
use crate::com::handshake::PUBLIC_KEY_LEN;
use crate::com::handshake::install_core::HandshakeResult;
use crate::com::handshake::renew::sensor::KeyRenewRequest;
use crate::com::handshake::renew_core::gateway::send_renew_challenge_and_wait_ack;
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Session key renewal handler (lightweight: ephemeral-to-ephemeral ECDH, no ECDSA/ECIES).
///
/// The caller must decrypt `KeyRenewRequest` with the current session key before invoking
/// this function (authentication is provided by successful AEAD decryption).
///
/// Hardware callbacks:
/// - `generate_gateway_ephemeral`: create a gateway ephemeral keypair; return the compressed pubkey
///   (private key remains in the secure element).
/// - `ecdh_with_sensor_ephemeral`: ECDH between the stored gateway ephemeral private key and the
///   sensor ephemeral pubkey received in `KeyRenewAck`.
#[allow(clippy::too_many_arguments)]
pub fn handle_renew_request<SPI, CS, RST, SpiErr, FGEN, FECDH>(
    request: &KeyRenewRequest,
    session_key: &[u8; 32],
    chacha_nonce: &[u8; 12],
    generate_gateway_ephemeral: FGEN,
    ecdh_with_sensor_ephemeral: FECDH,
    sensor_pubkey: &[u8; PUBLIC_KEY_LEN],
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
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
    FGEN: Fn() -> Result<[u8; PUBLIC_KEY_LEN], ()>,
    FECDH: Fn(&[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
{
    send_renew_challenge_and_wait_ack(
        request,
        session_key,
        chacha_nonce,
        generate_gateway_ephemeral,
        ecdh_with_sensor_ephemeral,
        sensor_pubkey,
        sensor_mac,
        gateway_mac,
        gateway_nonce,
        key_expire_at,
        lora,
        delay,
        timestamp,
    )
}

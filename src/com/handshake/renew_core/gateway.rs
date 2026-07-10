use crate::com::error::model::ComError;
use crate::com::handshake::install_core::HandshakeResult;
use crate::com::handshake::lora_helpers::{send_encrypted, try_receive_encrypted};
use crate::com::handshake::renew::sensor::KeyRenewRequest;
use crate::com::handshake::renew_core::{
    GATEWAY_RENEW_ACK_RX_TIMEOUT, GATEWAY_RENEW_CHALLENGE_RESEND_PERIOD, KeyRenewAck,
    KeyRenewChallenge,
};
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, derive_session_key};
use crate::models::common::{
    BodySchema, Destination::OneDestination, MessageSchema, MessageType, RequestType,
    ResponseType,
};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Lightweight renew core (gateway): encrypted challenge (ECDH only) + wait for `KeyRenewAck`.
///
/// `ecdh_ephemeral` generates an ephemeral P-256 keypair and returns
/// `(eph_pubkey_compressed, shared_secret)` for the paired sensor's public key.
#[allow(clippy::too_many_arguments)]
pub fn send_renew_challenge_and_wait_ack<SPI, CS, RST, SpiErr, FEPH>(
    request: &KeyRenewRequest,
    session_key: &[u8; 32],
    chacha_nonce: &[u8; 12],
    ecdh_ephemeral: FEPH,
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
    FEPH: Fn(&[u8; PUBLIC_KEY_LEN]) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()>,
{
    let (eph_pubkey, shared_secret) = ecdh_ephemeral(sensor_pubkey)
        .map_err(|_| ComError::VerificationFailed)?;

    if eph_pubkey.iter().all(|&b| b == 0) || shared_secret.iter().all(|&b| b == 0) {
        return Err(ComError::VerificationFailed);
    }

    let mut challenge_msg = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::KeyRenewChallenge,
        ResponseType::KeyRenewChallenge(KeyRenewChallenge::new(
            eph_pubkey,
            gateway_nonce,
            key_expire_at,
        )),
        timestamp,
    );
    let (challenge_buffer, challenge_len) =
        send_encrypted(lora, delay, &mut challenge_msg, session_key, chacha_nonce)?;
    lora.set_mode(lora::sx1278::Mode::Receiver, delay);

    let mut recv_buffer = [0u8; HANDSHAKE_MESSAGE_MAX];
    for attempt in 0..GATEWAY_RENEW_ACK_RX_TIMEOUT {
        if attempt % GATEWAY_RENEW_CHALLENGE_RESEND_PERIOD == 0 && attempt > 0 {
            lora.set_mode(lora::sx1278::Mode::Manual, delay);
            lora.send(&challenge_buffer[..challenge_len], delay)?;
            lora.set_mode(lora::sx1278::Mode::Receiver, delay);
        }

        match try_receive_encrypted(
            lora,
            delay,
            &mut recv_buffer,
            session_key,
            MessageType::KeyRenewAck,
        ) {
            Ok(Some(msg)) => {
                if msg.header.dist != OneDestination(gateway_mac) {
                    continue;
                }
                if msg.header.src != sensor_mac {
                    continue;
                }
                if !matches!(
                    msg.body,
                    BodySchema::RequestType(RequestType::KeyRenewAck(KeyRenewAck))
                ) {
                    continue;
                }

                let session_key_new =
                    derive_session_key(&shared_secret, request.sensor_nonce(), &gateway_nonce);
                return Ok(HandshakeResult {
                    session_key: session_key_new,
                    sensor_pubkey: *sensor_pubkey,
                    key_expire_at,
                });
            }
            Ok(None) => {
                delay.delay_ms(200u32);
            }
            Err(e) => return Err(e),
        }
    }

    Err(ComError::Timeout)
}

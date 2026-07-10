use crate::com::error::model::ComError;
use crate::com::handshake::install_core::HandshakeSession;
use crate::com::handshake::lora_helpers::send_encrypted;
use crate::com::handshake::renew_core::sensor::complete_renew_as_sensor;
use crate::models::common::{
    Destination::OneDestination, MessageSchema, MessageType, RequestType,
};
use bincode::{Decode, Encode};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Renew trigger sent by the sensor over the **existing encrypted session**.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct KeyRenewRequest {
    sensor_nonce: [u8; 32],
}

impl KeyRenewRequest {
    pub fn new(sensor_nonce: [u8; 32]) -> Self {
        Self { sensor_nonce }
    }

    pub fn sensor_nonce(&self) -> &[u8; 32] {
        &self.sensor_nonce
    }
}

/// Session key renewal for an already-paired sensor (lightweight: ECDH only, no ECDSA/ECIES).
///
/// Sends an encrypted `KeyRenewRequest`, then runs [`complete_renew_as_sensor`].
#[allow(clippy::too_many_arguments)]
pub fn renew_session<SPI, CS, RST, SpiErr, FECDH>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    sensor_mac: [u8; 17],
    battery_level: u8,
    gateway_mac: [u8; 17],
    session_key: &[u8; 32],
    chacha_nonce: &[u8; 12],
    sensor_nonce: [u8; 32],
    ecdh_shared_secret: FECDH,
    timestamp: u32,
) -> Result<HandshakeSession, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    FECDH: FnMut(&[u8; crate::com::handshake::PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
{
    let mut msg = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        OneDestination(gateway_mac),
        MessageType::KeyRenewRequest,
        RequestType::KeyRenewRequest(KeyRenewRequest::new(sensor_nonce)),
        timestamp,
    );
    let (buffer, len) = send_encrypted(lora, delay, &mut msg, session_key, chacha_nonce)?;
    lora.set_mode(lora::sx1278::Mode::Receiver, delay);
    delay.delay_ms(120u32);
    log::debug!("handshake(renew): KeyRenewRequest sent, waiting KeyRenewChallenge");

    complete_renew_as_sensor(
        lora,
        delay,
        sensor_mac,
        battery_level,
        gateway_mac,
        sensor_nonce,
        session_key,
        chacha_nonce,
        ecdh_shared_secret,
        timestamp,
        Some((&buffer, len)),
    )
}

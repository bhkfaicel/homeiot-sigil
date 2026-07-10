use crate::com::error::model::ComError;
use crate::com::handshake::install_core::sensor::complete_install_as_sensor;
use crate::com::handshake::install_core::HandshakeSession;
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::models::common::{
    Destination::AllGateways, MessageSchema, MessageType, RequestType,
};
use bincode::{Decode, Encode};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Install Step 1: broadcast by the sensor to all gateways.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRequest {
    sensor_nonce: [u8; 32],
    sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_pubkey: [u8; SIGNATURE_LEN],
}

impl HandshakeRequest {
    pub fn new(
        sensor_nonce: [u8; 32],
        sensor_pubkey: [u8; PUBLIC_KEY_LEN],
        sig_sensor_pubkey: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            sensor_nonce,
            sensor_pubkey,
            sig_sensor_pubkey,
        }
    }

    pub fn sensor_nonce(&self) -> &[u8; 32] {
        &self.sensor_nonce
    }

    pub fn sensor_pubkey(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.sensor_pubkey
    }

    pub fn sig_sensor_pubkey(&self) -> &[u8; SIGNATURE_LEN] {
        &self.sig_sensor_pubkey
    }
}

/// First-time installation: identity broadcast + install core (ECIES + ECDSA).
#[allow(clippy::too_many_arguments)]
pub fn install_session<SPI, CS, RST, SpiErr, FECDH, FV, FS>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    sensor_mac: [u8; 17],
    battery_level: u8,
    sensor_nonce: [u8; 32],
    sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_pubkey: [u8; SIGNATURE_LEN],
    ecdh_shared_secret: FECDH,
    verify_sig_sensor_nonce: FV,
    sign_gateway_nonce: FS,
    timestamp: u32,
) -> Result<HandshakeSession, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    FECDH: FnMut(&[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
    FV: FnMut(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FS: FnMut(&[u8; 32]) -> [u8; SIGNATURE_LEN],
{
    let mut msg = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        AllGateways,
        MessageType::HandshakeRequest,
        RequestType::HandshakeRequest(HandshakeRequest::new(
            sensor_nonce,
            sensor_pubkey,
            sig_sensor_pubkey,
        )),
        timestamp,
    );
    let (buffer, len) = msg
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .map_err(ComError::Custom)?;
    if len > crate::models::common::LORA_USER_PAYLOAD_MAX {
        return Err(ComError::MessageTooLong {
            length: len,
            max: crate::models::common::LORA_USER_PAYLOAD_MAX,
        });
    }

    lora.set_mode(lora::sx1278::Mode::Manual, delay);
    lora.send(&buffer[..len], delay)?;
    lora.set_mode(lora::sx1278::Mode::Receiver, delay);
    delay.delay_ms(120u32);
    log::debug!("handshake(install): HandshakeRequest sent, waiting challenge");

    complete_install_as_sensor(
        lora,
        delay,
        sensor_mac,
        battery_level,
        sensor_nonce,
        ecdh_shared_secret,
        verify_sig_sensor_nonce,
        sign_gateway_nonce,
        timestamp,
        Some((&buffer, len)),
    )
}

/// Backward-compatible alias for [`install_session`].
#[allow(clippy::too_many_arguments)]
pub fn initiate_handshake<SPI, CS, RST, SpiErr, FECDH, FV, FS>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    sensor_mac: [u8; 17],
    battery_level: u8,
    sensor_nonce: [u8; 32],
    sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_pubkey: [u8; SIGNATURE_LEN],
    ecdh_shared_secret: FECDH,
    verify_sig_sensor_nonce: FV,
    sign_gateway_nonce: FS,
    timestamp: u32,
) -> Result<HandshakeSession, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    FECDH: FnMut(&[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
    FV: FnMut(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FS: FnMut(&[u8; 32]) -> [u8; SIGNATURE_LEN],
{
    install_session(
        lora,
        delay,
        sensor_mac,
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        ecdh_shared_secret,
        verify_sig_sensor_nonce,
        sign_gateway_nonce,
        timestamp,
    )
}

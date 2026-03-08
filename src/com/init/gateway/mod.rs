use crate::com::init::sensor::{Install, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::{
    com::error::model::ComError,
    models::common::{
        BodySchema, Destination::OneDestination, MessageSchema, MessageType, RequestType,
        ResponseType, deserialize, deserialize_body,
    },
};
use bincode::{Decode, Encode};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use heapless::Vec;
use lora;

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]

pub enum Status {
    /// The sensor is currently being installed.
    InProgress,
    /// The sensor has been successfully installed.
    Installed,
    /// The sensor is undergoing an update.
    OnUpdate,
}

/// Validate request: gateway sends key + expire + gateway public key + signature.
/// Sensor verifies gateway_public_key/signature via callback, then continues init.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Validate {
    key: [u8; 32],
    expire_at: u32,
    gateway_mac: [u8; 17],
    /// Gateway P-256 public key (X || Y, 64 bytes) for init handshake.
    gateway_public_key: [u8; PUBLIC_KEY_LEN],
    /// Gateway ECDSA signature, 64 bytes (sensor verifies with this).
    gateway_signature: [u8; SIGNATURE_LEN],
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub key: [u8; 32],
    pub expire_at: u32,
    pub timestamp: u32,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct ValidateResponse {
    //TODO remove pub
    pub status: Status,
    pub sensor_mac: [u8; 17],
}

impl Validate {
    pub fn new(
        key: [u8; 32],
        expire_at: u32,
        gateway_mac: [u8; 17],
        gateway_public_key: [u8; PUBLIC_KEY_LEN],
        gateway_signature: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            key,
            expire_at,
            gateway_mac,
            gateway_public_key,
            gateway_signature,
        }
    }

    /// Gateway public key (sensor verifies with this + gateway_signature).
    pub fn gateway_public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.gateway_public_key
    }

    /// Gateway signature (sensor verifies with gateway_public_key + this).
    pub fn gateway_signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.gateway_signature
    }

    /// Gateway MAC (sensor uses this as destination when sending ValidateResponse).
    pub fn gateway_mac(&self) -> &[u8; 17] {
        &self.gateway_mac
    }

    pub fn request<SPI, CS, RST, SpiErr>(
        &self,
        lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
        mut delay: &mut impl DelayNs,
        sensor_mac: [u8; 17],
        gateway_mac: [u8; 17],
        timestamp: u32,
        new_key: [u8; 32],
        expire_at: u32,
    ) -> Result<ValidateResponse, ComError<SpiErr>>
    where
        SPI: SpiBus<u8, Error = SpiErr>,
        CS: OutputPin,
        RST: OutputPin,
    {
        let mode = lora.get_mode();
        let rx_timeout = 4;

        let mut message = MessageSchema::create_body_request(
            gateway_mac,
            0,
            OneDestination(sensor_mac),
            MessageType::ValidateRequest,
            RequestType::Validate(Validate {
                key: new_key,
                expire_at,
                gateway_mac,
                gateway_public_key: self.gateway_public_key,
                gateway_signature: self.gateway_signature,
            }),
            timestamp,
        );
        let buffer = message
            .serialize_clear::<{ crate::com::init::INIT_MESSAGE_MAX }>()
            .map_err(ComError::Custom)?;
        lora.set_mode(lora::sx1278::Mode::Manual, delay);
        lora.send(&buffer, &mut delay)?;
        lora.set_mode(lora::sx1278::Mode::Receiver, &mut delay);
        let mut recv_buffer = [0u8; crate::com::init::INIT_MESSAGE_MAX];
        let mut received_response = None;
        for _ in 0..rx_timeout {
            let receive_result =
                if let Ok(result) = lora.receive::<SpiErr, _>(&mut recv_buffer, &mut delay) {
                    result
                } else {
                    delay.delay_ms(5000u32);
                    continue;
                };
            let mut recv_vec = match Vec::<u8, { crate::com::init::INIT_MESSAGE_MAX }>::from_slice(&recv_buffer[..receive_result.size])
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut msg = match deserialize::<{ crate::com::init::INIT_MESSAGE_MAX }>(&mut recv_vec) {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Populate signal quality metrics in the header
            msg.header.rssi = receive_result.rssi;
            msg.header.snr = receive_result.snr;
            if msg.header.dist != OneDestination(gateway_mac) {
                continue;
            }
            if msg.header.message_type != MessageType::ValidateResponse {
                continue;
            }
            let mut message = match deserialize_body::<{ crate::models::common::ENCRYPTED_BODY_MAX }>(msg.header, &msg.body, &new_key, None) {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Ensure signal quality is preserved in the final message
            message.header.rssi = receive_result.rssi;
            message.header.snr = receive_result.snr;
            match message.body {
                BodySchema::ResponseType(ResponseType::SensorValidate(init_response_body)) => {
                    lora.set_mode(mode, delay);
                    received_response = Some(init_response_body);
                    break;
                }
                _ => continue,
            }
        }
        lora.set_mode(mode, delay);
        received_response.ok_or(ComError::Timeout)
    }
    pub fn response<SPI, CS, RST, SpiErr>(
        &self,
        lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
        mut delay: &mut impl DelayNs,
        nonce: [u8; 12],
        sensor_mac: [u8; 17],
        timestamp: u32,
    ) -> Result<Keys, ComError<SpiErr>>
    where
        SPI: SpiBus<u8, Error = SpiErr>,
        CS: OutputPin,
        RST: OutputPin,
    {
        delay.delay_ms(1);
        let mode = lora.get_mode();
        let mut message = MessageSchema::create_body_response(
            self.gateway_mac,
            sensor_mac,
            MessageType::ValidateResponse,
            ResponseType::SensorValidate(ValidateResponse {
                status: Status::Installed,
                sensor_mac,
            }),
            timestamp,
        );
        let buffer = message
            .serialize::<{ crate::com::init::INIT_MESSAGE_MAX }>(&self.key, &nonce, None)
            .map_err(ComError::Custom)?;
        lora.set_mode(lora::sx1278::Mode::Manual, delay);
        lora.send(&buffer, &mut delay)?;
        lora.set_mode(mode, delay);
        Ok(Keys {
            key: self.key,
            expire_at: self.expire_at,
            timestamp,
        })
    }
    pub fn get_key(&self, timestamp: u32) -> Keys {
        Keys {
            key: self.key,
            expire_at: self.expire_at,
            timestamp,
        }
    }
}

/// Called by the gateway when it has received an Install request from a sensor.
/// Verifies the sensor's public key and signature via `verify_sensor`; if valid,
/// sends Validate (key, expire_at, gateway_public_key, gateway_signature) to the sensor
/// and returns the sensor's ValidateResponse. If verification fails, returns
/// `Err(ComError::VerificationFailed)`.
pub fn verify_sensor_and_send_validate<SPI, CS, RST, SpiErr, F>(
    install: &Install,
    verify_sensor: F,
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    nonce: [u8; 12],
    gateway_mac: [u8; 17],
    timestamp: u32,
    new_key: [u8; 32],
    expire_at: u32,
    gateway_public_key: [u8; PUBLIC_KEY_LEN],
    gateway_signature: [u8; SIGNATURE_LEN],
) -> Result<ValidateResponse, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    F: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
{
    if !verify_sensor(install.public_key(), install.signature()) {
        return Err(ComError::VerificationFailed);
    }
    install.response(
        lora,
        delay,
        nonce,
        gateway_mac,
        timestamp,
        new_key,
        expire_at,
        gateway_public_key,
        gateway_signature,
    )
}

#[cfg(test)]
pub mod tests;

use super::gateway::{Status, Validate, ValidateResponse};
use crate::{
    com::error::model::ComError,
    models::common::{
        Destination::AllGateways, MessageSchema, MessageType, ProductType, RequestType,
        ResponseType,
    },
};
use bincode::{Decode, Encode};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// P-256 public key size (compressed form: 1 byte prefix + 32 bytes X).
pub const PUBLIC_KEY_LEN: usize = 33;
/// ECDSA P-256 signature size (r || s, 32 + 32 bytes).
pub const SIGNATURE_LEN: usize = 64;

/// The `SensorMessageBodySchema` represents the request body of an initialization message
/// sent by a sensor (e.g., Open/Close sensor) to the gateway.
///
/// Init handshake: sensor sends public key + signature; gateway verifies via callback,
/// then sends its public key + signature; sensor verifies and continues init.
/// This secures the init exchange (only for init).

#[derive(Encode, Decode, Debug, Clone)]
pub struct Install {
    //TODO remove pub (tested)
    mac: [u8; 17],
    product_type: ProductType,
    /// Sensor public key for init handshake (placeholder size, see `PUBLIC_KEY_LEN`).
    public_key: [u8; PUBLIC_KEY_LEN],
    /// Signature over init payload (e.g. public_key || nonce), placeholder size.
    signature: [u8; SIGNATURE_LEN],
}
impl Install {
    pub fn new(
        mac: [u8; 17],
        product_type: ProductType,
        public_key: [u8; PUBLIC_KEY_LEN],
        signature: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            mac,
            product_type,
            public_key,
            signature,
        }
    }
    /// Maximum encoded message size allowed over LoRa.
    // const MAX_MSG_SIZE: usize = 200;

    /// Sends an `InitSensorRequest` message over LoRa and waits for the corresponding `InitResponse`.
    ///
    /// # Arguments
    /// - `lora`: The LoRa controller used for communication.
    /// - `delay`: Delay implementation for timing.
    /// - `mac`: The MAC address of the sensor.
    /// - `battery_level`: Current battery level of the device.
    ///
    /// # Returns
    /// `Ok(GatewayMessageBodySchema)` if a valid response was received.
    /// `Err(ComError<SpiErr>)` if an error occurred (timeout, CRC failure, SPI error, etc.).
    ///
    /// This function:
    /// - Sends a request in `Manual` mode,
    /// - Switches to `Receiver` mode,
    /// - Waits for a response addressed to the device,
    /// - Verifies the message type,
    /// - Decrypts and parses the response body.
    pub fn request<SPI, CS, RST, SpiErr>(
        lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
        mut delay: &mut impl DelayNs,
        sensor_mac: [u8; 17],
        battery_level: u8,
        product_type: ProductType,
        sensor_public_key: [u8; PUBLIC_KEY_LEN],
        sensor_signature: [u8; SIGNATURE_LEN],
        timestamp: u32,
    ) -> Result<(), ComError<SpiErr>>
    where
        SPI: SpiBus<u8, Error = SpiErr>,
        CS: OutputPin,
        RST: OutputPin,
    {
        let mut message = MessageSchema::create_body_request(
            sensor_mac,
            battery_level,
            AllGateways,
            MessageType::InstallSensorRequest,
            RequestType::Install(Install {
                mac: sensor_mac,
                product_type,
                public_key: sensor_public_key,
                signature: sensor_signature,
            }),
            timestamp,
        );
        let buffer = message
            .serialize_clear::<{ crate::com::init::INIT_MESSAGE_MAX }>()
            .map_err(ComError::Custom)?;
        lora.set_mode(lora::sx1278::Mode::Manual, delay);
        lora.send(&buffer, &mut delay)?;
        lora.set_mode(lora::sx1278::Mode::Receiver, &mut delay);
        Ok(())
    }

    /// Sends an `InitResponse` message back to the requesting sensor.
    ///
    /// # Arguments
    /// - `lora`: The LoRa controller used to send the message.
    /// - `delay`: Delay implementation.
    /// - `nonce`: The nonce used for encryption.
    /// - `mac`: MAC address of the responding gateway or device.
    /// - `timestamp`: Timestamp to include in the response.
    /// - `key`: The encryption key to send to the sensor.
    /// - `expire_at`: Expiration timestamp of the key or session.
    ///
    /// # Returns
    /// - `Ok(GatewayMessageBodyResponseSchema)` on success,
    /// - `Err(ComError<SpiErr>)` on failure.
    ///
    /// The message is encrypted and sent in `Manual` mode.
    /// Gateway sends Validate (key, expire_at, gateway_public_key, gateway_signature) to sensor.
    /// Call this from the gateway after verifying the sensor's Install (public_key + signature).
    ///
    /// This is an internal helper used by the gateway-side init logic and is not part of the
    /// public API surface of the `sigil` crate.
    pub(crate) fn response<SPI, CS, RST, SpiErr>(
        &self,
        lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
        delay: &mut impl DelayNs,
        _nonce: [u8; 12],
        src_mac: [u8; 17],
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
    {
        let response_body = Validate::new(
            new_key,
            expire_at,
            src_mac,
            gateway_public_key,
            gateway_signature,
        );
        response_body.request(
            lora, delay, self.mac, src_mac, timestamp, new_key, expire_at,
        )
    }

    /// Returns the MAC address contained in the request.
    pub fn get_mac(&self) -> [u8; 17] {
        self.mac
    }

    /// Returns the product type declared in the initialization request.
    pub fn get_product_type(&self) -> ProductType {
        self.product_type
    }

    /// Sensor public key for init handshake (gateway verifies with this + signature).
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Sensor signature for init handshake (gateway verifies with public_key + this).
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

/// Called by the sensor when it has received a Validate request from the gateway.
/// Verifies the gateway's public key and signature via `verify_gateway`; if valid,
/// sends ValidateResponse (encrypted with the new key from Validate) and returns `Ok(())`.
/// If verification fails, returns `Err(ComError::VerificationFailed)`.
pub fn respond_to_validate<SPI, CS, RST, SpiErr, F>(
    validate: &Validate,
    verify_gateway: F,
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    nonce: [u8; 12],
    sensor_mac: [u8; 17],
    timestamp: u32,
) -> Result<(), ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    F: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
{
    if !verify_gateway(validate.gateway_public_key(), validate.gateway_signature()) {
        return Err(ComError::VerificationFailed);
    }
    let key = validate.get_key(timestamp).key;
    let gateway_mac = *validate.gateway_mac();
    let mut message = MessageSchema::create_body_response(
        gateway_mac,
        sensor_mac,
        MessageType::ValidateResponse,
        ResponseType::SensorValidate(ValidateResponse {
            status: Status::Installed,
            sensor_mac,
        }),
        timestamp,
    );
    let buffer = message
        .serialize::<{ crate::com::init::INIT_MESSAGE_MAX }>(&key, &nonce, None)
        .map_err(ComError::Custom)?;
    lora.set_mode(lora::sx1278::Mode::Manual, delay);
    lora.send(&buffer, delay)?;
    Ok(())
}

#[cfg(test)]
pub mod tests;

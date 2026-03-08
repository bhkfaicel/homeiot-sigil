use crate::{
    com::error::model::ComError,
    com::event::message::Event,
    models::common::{
        Ack, Destination::OneDestination, MessageSchema, MessageType, RequestType, ResponseType,
        Status,
    },
};
use embedded_hal::{delay::DelayNs, digital::OutputPin, spi::SpiBus};
use lora;

/// Sends an `Event` message over LoRa.
///
/// # Arguments
/// - `lora`: The LoRa controller used for communication.
/// - `delay`: Delay implementation for precise timing control.
/// - `nonce`: 12-byte nonce used for message encryption (ChaCha20, AES, etc.).
/// - `sensor_mac`: The 17-byte MAC address of the source device (sender).
/// - `battery_level`: Current battery level percentage (0–100).
/// - `event`: The event payload to send (e.g. `IsOpen`, `VibrationCount`).
/// - `destination`: The 17-byte MAC address of the target device.
///
/// # Returns
/// - `Ok(())` if the event was successfully transmitted over LoRa.
/// - `Err(ComError<SpiErr>)` if an SPI, LoRa, or communication error occurred.
///
/// # Behavior
/// 1. Builds an encrypted message (`MessageSchema`) containing the event data.
/// 2. Serializes it using the provided symmetric `key` and `nonce`.
/// 3. Switches the LoRa module to `Manual` mode for transmission.
/// 4. Sends the serialized message buffer over LoRa.
/// 5. Returns immediately after successful send.
///
/// # Notes
/// - The function **does not wait for a response** (one-way event push).
/// - The maximum encoded message size is limited to **256 bytes**.
/// - This function is designed for use in `no_std` embedded environments.
///
/// # Errors
/// - `ComError::Spi(_)`: SPI communication failed.
/// - `ComError::Timeout`: TX did not complete.
/// - `ComError::CrcMismatch`: LoRa reported CRC failure.
/// - Other variants depending on your `ComError` implementation.
pub fn send<SPI, CS, RST, SpiErr>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    mut delay: &mut impl DelayNs,
    nonce: [u8; 12],
    key: [u8; 32],
    sensor_mac: [u8; 17],
    battery_level: u8,
    event: Event,
    destination: [u8; 17],
    timestamp: u32,
) -> Result<(), ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
{
    // Create encrypted message body with metadata and event payload
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        OneDestination(destination),
        MessageType::Event,
        RequestType::Event(event),
        timestamp,
    );

    let buffer = message
        .serialize::<256>(&key, &nonce, None)
        .map_err(ComError::Custom)?;

    // Send the serialized message via LoRa
    lora.send(&buffer, &mut delay)?;

    Ok(())
}

/// Sends an `Ack` message from the gateway to acknowledge receipt of an event.
///
/// This function is used by the gateway to send an acknowledgment after receiving
/// an event from a sensor. The acknowledgment confirms that the event was successfully received
/// and processed.
///
/// # Arguments
/// - `lora`: The LoRa controller used for communication.
/// - `delay`: Delay implementation for precise timing control.
/// - `nonce`: 12-byte nonce used for message encryption.
/// - `key`: 32-byte encryption key.
/// - `gateway_mac`: The 17-byte MAC address of the gateway (sender).
/// - `sensor_mac`: The 17-byte MAC address of the sensor that sent the original event.
/// - `status`: Status code indicating the result of processing the event (typically `Status::Ok`).
///
/// # Returns
/// - `Ok(())` if the response was successfully transmitted over LoRa.
/// - `Err(ComError<SpiErr>)` if an SPI, LoRa, or communication error occurred.
///
/// # Behavior
/// 1. Builds an encrypted response message (`MessageSchema`) containing the event acknowledgment.
/// 2. Serializes it using the provided symmetric `key` and `nonce`.
/// 3. Sends the serialized message buffer over LoRa.
/// 4. Returns immediately after successful send.
///
/// # Notes
/// - The function preserves the current LoRa mode and restores it after transmission.
/// - The maximum encoded message size is limited to **256 bytes**.
/// - This function is designed for use in `no_std` embedded environments.
///
/// # Errors
/// - `ComError::Spi(_)`: SPI communication failed.
/// - `ComError::Timeout`: TX did not complete.
/// - `ComError::CrcMismatch`: LoRa reported CRC failure.
/// - Other variants depending on your `ComError` implementation.
pub fn response<SPI, CS, RST, SpiErr>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    mut delay: &mut impl DelayNs,
    nonce: [u8; 12],
    key: [u8; 32],
    src: [u8; 17],
    dist: [u8; 17],
    status: Status,
    timestamp: u32,
) -> Result<(), ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
{
    delay.delay_ms(1);
    let mode = lora.get_mode();

    let mut message = MessageSchema::create_body_response(
        dist,
        src,
        MessageType::EventResponse,
        ResponseType::Event(Ack {
            status,
            device_mac: dist,
        }),
        timestamp,
    );

    let buffer = message
        .serialize::<256>(&key, &nonce, None)
        .map_err(ComError::Custom)?;

    lora.set_mode(lora::sx1278::Mode::Manual, delay);
    lora.send(&buffer, &mut delay)?;
    lora.set_mode(mode, delay);

    Ok(())
}

pub mod message;
#[cfg(test)]
pub mod tests;

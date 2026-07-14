use crate::com::error::model::ComError;
use crate::com::handshake::install_core::HandshakeSession;
use crate::com::handshake::resume_core::sensor::complete_resume_as_sensor;
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::models::common::{Destination::OneDestination, MessageSchema, MessageType, RequestType};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

pub use crate::com::handshake::resume_core::SessionResumeRequest;

/// Re-establishes a session for an already-enrolled sensor without the previous session key.
///
/// Sends a directed clear-text `SessionResumeRequest` (ECDSA over `sensor_nonce`), then runs
/// [`complete_resume_as_sensor`]. Use when the sensor is paired but the session key was lost
/// (flash wipe of session only, long disconnect) and renew is not possible.
#[allow(clippy::too_many_arguments)]
pub fn resume_session<SPI, CS, RST, SpiErr, FEPH, FV, FS>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    sensor_mac: [u8; 17],
    battery_level: u8,
    gateway_mac: [u8; 17],
    sensor_nonce: [u8; 32],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    ecdh_ephemeral_with_peer: FEPH,
    verify_sig_sensor_nonce: FV,
    sign_gateway_nonce: FS,
    timestamp: u32,
) -> Result<HandshakeSession, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    FEPH: FnMut(&[u8; PUBLIC_KEY_LEN]) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()>,
    FV: FnMut(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FS: FnMut(&[u8; 32]) -> [u8; SIGNATURE_LEN],
{
    let mut msg = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        OneDestination(gateway_mac),
        MessageType::SessionResumeRequest,
        RequestType::SessionResumeRequest(SessionResumeRequest::new(
            sensor_nonce,
            sig_sensor_nonce,
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
    log::debug!("handshake(resume): SessionResumeRequest sent, waiting challenge");

    complete_resume_as_sensor(
        lora,
        delay,
        sensor_mac,
        battery_level,
        sensor_nonce,
        ecdh_ephemeral_with_peer,
        verify_sig_sensor_nonce,
        sign_gateway_nonce,
        timestamp,
        Some((&buffer, len)),
    )
}

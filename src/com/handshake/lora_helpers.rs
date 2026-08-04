//! Shared LoRa TX/RX helpers for handshake flows.

use crate::com::error::model::ComError;
use crate::com::handshake::HANDSHAKE_MESSAGE_MAX;
use crate::models::common::{
    LORA_USER_PAYLOAD_MAX, MessageSchema, MessageType, deserialize, deserialize_body,
};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;
use lora::error::model::LoRaError;

/// Sends a clear-text buffer on LoRa (manual TX mode).
pub fn send_clear<SPI, CS, RST, SpiErr, D>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut D,
    payload: &[u8],
) -> Result<(), ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    D: DelayNs,
{
    if payload.len() > LORA_USER_PAYLOAD_MAX {
        return Err(ComError::MessageTooLong {
            length: payload.len(),
            max: LORA_USER_PAYLOAD_MAX,
        });
    }
    lora.set_mode(lora::sx1278::Mode::Manual, delay);
    lora.send(payload, delay)?;
    Ok(())
}

/// Serializes and sends an encrypted `MessageSchema`.
pub fn send_encrypted<SPI, CS, RST, SpiErr, D>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut D,
    msg: &mut MessageSchema,
    session_key: &[u8; 32],
    chacha_nonce: &[u8; 12],
) -> Result<([u8; HANDSHAKE_MESSAGE_MAX], usize), ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    D: DelayNs,
{
    let (buffer, len) = msg
        .serialize_with_len::<HANDSHAKE_MESSAGE_MAX>(session_key, chacha_nonce, None)
        .map_err(ComError::Custom)?;
    if len > LORA_USER_PAYLOAD_MAX {
        return Err(ComError::MessageTooLong {
            length: len,
            max: LORA_USER_PAYLOAD_MAX,
        });
    }
    send_clear(lora, delay, &buffer[..len])?;
    Ok((buffer, len))
}

/// Attempts to receive and decrypt one encrypted message matching `message_type`.
pub fn try_receive_encrypted<SPI, CS, RST, SpiErr, D>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut D,
    recv_buffer: &mut [u8; HANDSHAKE_MESSAGE_MAX],
    session_key: &[u8; 32],
    message_type: MessageType,
) -> Result<Option<MessageSchema>, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    D: DelayNs,
{
    let receive_result = match lora.receive::<SpiErr, _>(recv_buffer, delay) {
        Ok(r) => r,
        Err(LoRaError::NoPacket) => return Ok(None),
        Err(LoRaError::CrcError) | Err(LoRaError::DeCompressionFailed) => return Ok(None),
        Err(LoRaError::BufferTooSmall { .. }) => return Ok(None),
        Err(LoRaError::MessageTooLong { .. }) => {
            return Err(ComError::MessageTooLong {
                length: HANDSHAKE_MESSAGE_MAX + 1,
                max: HANDSHAKE_MESSAGE_MAX,
            });
        }
        Err(LoRaError::Timeout) => return Ok(None),
        Err(LoRaError::Canceled) => return Err(ComError::Canceled),
        Err(LoRaError::UnsupportedModule(code)) => return Err(ComError::UnsupportedModule(code)),
        Err(LoRaError::CompressionFailed) => return Err(ComError::CompressionFailed),
        Err(LoRaError::Spi(_)) => return Err(ComError::Custom("SPI error during receive")),
    };

    let encrypted = match deserialize::<HANDSHAKE_MESSAGE_MAX>(&recv_buffer[..receive_result.size])
    {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };

    if encrypted.header.message_type != message_type {
        return Ok(None);
    }

    let msg = match deserialize_body::<150>(encrypted.header, &encrypted.body, session_key, None) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };

    Ok(Some(msg))
}

/// Sends a buffer multiple times with short RX gaps between retries.
pub fn send_with_retries<SPI, CS, RST, SpiErr, D>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut D,
    payload: &[u8],
    retries: u8,
) -> Result<(), ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    D: DelayNs,
{
    for tx in 0..retries {
        send_clear(lora, delay, payload)?;
        if tx + 1 < retries {
            lora.set_mode(lora::sx1278::Mode::Receiver, delay);
            delay.delay_ms(150u32);
        }
    }
    Ok(())
}

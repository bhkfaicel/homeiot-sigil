use crate::models::common::{
    Ack, Destination::OneDestination, HeaderSchema, MessageSchema, MessageType, RSSI_NOT_AVAILABLE,
    ResponseType, SNR_NOT_AVAILABLE, Status,
};
use crate::{
    com::error::model::ComError,
    models::common::{deserialize, deserialize_body, deserialize_clear},
};
use embedded_hal::{delay::DelayNs, digital::OutputPin, spi::SpiBus};
use heapless::Vec;

pub mod error;
pub mod event;
pub mod handshake;
pub mod keys;
pub struct Sigil {}
impl Sigil {
    /// Reads and decrypts a message from LoRa.
    ///
    /// # Arguments
    /// - `lora`: The LoRa controller used for communication.
    /// - `delay`: Delay implementation for timing.
    /// - `validate_header`: A function that validates if the message header should be accepted.
    ///   Returns `true` if the message should be processed, `false` otherwise.
    ///   This allows flexible validation (e.g., check destination, message type, source, etc.).
    /// - `get_key`: A function that returns the appropriate decryption key based on the message type and source.
    ///   Returns `Some(key)` if a key is available, `None` otherwise.
    ///   This allows flexible key selection (e.g., installation key for init messages,
    ///   session key for regular messages, different keys per source, etc.).
    ///
    /// # Returns
    /// - `Ok(MessageSchema)` if a valid message was received and decrypted.
    /// - `Err(ComError<SpiErr>)` if an error occurred (no packet, header validation failed, no key available, decryption failed, etc.).
    pub fn read<SPI, CS, RST, SpiErr, V, F>(
        lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
        mut delay: &mut impl DelayNs,
        validate_header: V,
        get_key: F,
        timestamp: u32,
    ) -> Result<MessageSchema, ComError<SpiErr>>
    where
        SPI: SpiBus<u8, Error = SpiErr>,
        CS: OutputPin,
        RST: OutputPin,
        V: Fn(&HeaderSchema) -> bool,
        F: Fn(MessageType, [u8; 17]) -> Option<[u8; 32]>,
    {
        const RECV_BUFFER_SIZE: usize = 256;

        // Receive raw bytes from LoRa into a fixed-size buffer
        let mut recv_buffer = [0u8; RECV_BUFFER_SIZE];
        let receive_result =
            if let Ok(result) = lora.receive::<SpiErr, _>(&mut recv_buffer, &mut delay) {
                result
            } else {
                return Err(ComError::NoPacket);
            };

        let received = &recv_buffer[..receive_result.size];

        // First, try to decode as a clear-text init message (Install / Validate).
        // Init handshake messages are serialized with `MessageSchema::serialize_clear`
        // and are not wrapped in `EncryptedSchema`.
        if let Ok(mut clear_msg) = deserialize_clear::<RECV_BUFFER_SIZE>(received) {
            // Populate signal quality metrics in the header
            clear_msg.header.rssi = receive_result.rssi;
            clear_msg.header.snr = receive_result.snr;

            // Only treat clear-text messages as valid for handshake types
            match clear_msg.header.message_type {
                MessageType::HandshakeRequest
                | MessageType::HandshakeChallenge
                | MessageType::HandshakeConfirm => {
                    // Validate header using the provided validation function
                    if !validate_header(&clear_msg.header) {
                        return Err(ComError::DeserializeFailed);
                    }
                    // Init messages are clear-text: no decryption step needed
                    return Ok(clear_msg);
                }
                _ => {
                    // Not an init message - fall through to encrypted path below.
                }
            }
        }

        // Encrypted path: decode `EncryptedSchema` then decrypt body with the selected key.
        let recv_vec = match Vec::<u8, RECV_BUFFER_SIZE>::from_slice(received) {
            Ok(v) => v,
            Err(_) => {
                return Err(ComError::BufferTooSmall {
                    required: receive_result.size,
                    available: RECV_BUFFER_SIZE,
                });
            }
        };
        let mut msg = match deserialize::<RECV_BUFFER_SIZE>(&recv_vec) {
            Ok(m) => m,
            Err(_) => return Err(ComError::WrongDistination),
        };
        // Populate signal quality metrics in the header
        msg.header.rssi = receive_result.rssi;
        msg.header.snr = receive_result.snr;

        // Validate header using the provided validation function
        if !validate_header(&msg.header) {
            return Err(ComError::DeserializeFailed);
        }

        if msg.header.message_type == MessageType::Ack {
            let dist = match msg.header.dist {
                OneDestination(mac) => mac,
                _ => {
                    // If destination is not a specific MAC, we can't create a proper response
                    return Err(ComError::Custom(
                        "No key available and cannot determine gateway MAC",
                    ));
                }
            };
            let mut ack_message = MessageSchema::create_body_response(
                dist,
                msg.header.src,
                MessageType::Ack,
                ResponseType::Event(Ack {
                    status: Status::Unauthenticated,
                    device_mac: msg.header.src,
                }),
                timestamp,
            );
            ack_message.header.status = Status::Unauthenticated;
            return Ok(ack_message);
        }
        // Get the appropriate key based on message type and destination
        let key_to_use = match get_key(msg.header.message_type, msg.header.src) {
            Some(key) => key,
            None => {
                // Return an Ack message with Unauthenticated status instead of an error
                let dist: [u8; 17] = match msg.header.dist {
                    OneDestination(mac) => mac,
                    _ => {
                        // If destination is not a specific MAC, we can't create a proper response
                        return Err(ComError::Custom(
                            "No key available and cannot determine gateway MAC",
                        ));
                    }
                };
                let mut ack_message = MessageSchema::create_body_response(
                    msg.header.src,
                    dist,
                    MessageType::Ack,
                    ResponseType::Event(Ack {
                        status: Status::Unauthenticated,
                        device_mac: msg.header.src,
                    }),
                    timestamp,
                );
                ack_message.header.status = Status::Unauthenticated;
                ack_message.header.rssi = RSSI_NOT_AVAILABLE;
                ack_message.header.snr = SNR_NOT_AVAILABLE;

                // Send the Ack message via LoRa to inform the sender
                let mode = lora.get_mode();
                // Fallback key used only for unauthenticated ACK responses (not a session key)
                const FALLBACK_ACK_KEY: [u8; 32] = [0x26; 32];
                let nonce = [0u8; 12];
                let buffer = ack_message
                    .serialize::<256>(&FALLBACK_ACK_KEY, &nonce, None)
                    .map_err(ComError::Custom)?;

                lora.set_mode(lora::sx1278::Mode::Manual, delay);
                lora.send(&buffer, &mut delay)?;
                lora.set_mode(mode, delay);
                return Err(ComError::Custom(
                    "No key available for this message type and destination",
                ));
            }
        };

        let mut message = match deserialize_body::<150>(msg.header, &msg.body, &key_to_use, None) {
            Ok(m) => m,
            Err(_) => return Err(ComError::DeserializeFailed),
        };
        // Ensure signal quality is preserved in the final message
        message.header.rssi = receive_result.rssi;
        message.header.snr = receive_result.snr;
        Ok(message)
    }
}

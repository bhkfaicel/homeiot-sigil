use crate::com::event::message::Event;
use crate::com::handshake::install_core::{HandshakeChallenge, HandshakeConfirm};
use crate::com::handshake::install::sensor::HandshakeRequest;
use crate::com::handshake::renew::sensor::KeyRenewRequest;
use crate::com::handshake::renew_core::{KeyRenewAck, KeyRenewChallenge};
use crate::com::handshake::resume_core::SessionResumeRequest;
use crate::crypto::{decrypt, encrypt};
use crate::models::common::Destination::OneDestination;
use bincode::{Decode, Encode};
use chacha20poly1305::aead::heapless::Vec;

/// Maximum encrypted body size (init and regular messages).
///
/// The encoded `EncryptedSchema` (`HeaderSchema` + `[u8; ENCRYPTED_BODY_MAX]`) must fit
/// into the envelope used by `serialize::<N>()` (e.g. init uses 256). Header is ~47 bytes.
pub const ENCRYPTED_BODY_MAX: usize = 200;

/// Maximum user bytes passed to `lora::Controller::send` (254: one FIFO byte for compression flag).
pub const LORA_USER_PAYLOAD_MAX: usize = 254;

#[derive(Decode, Encode, Debug, Clone, Copy, PartialEq)]
pub struct EncryptedSchema {
    pub header: HeaderSchema,
    pub body: [u8; ENCRYPTED_BODY_MAX],
}

/// Default RSSI value indicating signal quality not available.
/// Typical RSSI values range from -120 to -30 dBm, so -200 is impossible.
pub const RSSI_NOT_AVAILABLE: i16 = -200;

/// Default SNR value indicating signal quality not available.
/// Typical SNR values range from -20 to +15 dB, so i8::MIN is impossible.
pub const SNR_NOT_AVAILABLE: i8 = i8::MIN;

/// Default timestamp value indicating timestamp not available.
/// Set to 0 when timestamp is not provided, gateway should populate this with current time.
pub const TIMESTAMP_NOT_AVAILABLE: u32 = 0;

/// Status code for message operations, similar to gRPC status codes.
///
/// This enum represents the result status of a message operation.
/// It can be used to indicate success, cancellation, errors, and various failure conditions.
#[repr(u8)]
#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Operation completed successfully.
    Ok = 0,
    /// Operation was cancelled (e.g., preempted by a higher priority message).
    Cancelled = 1,
    /// Unknown status or error.
    UnknownStatus = 2,
    /// Invalid argument provided.
    InvalidArgument = 3,
    /// Requested resource was not found.
    NotFound = 4,
    /// Resource already exists.
    AlreadyExists = 5,
    /// Permission denied for the operation.
    PermissionDenied = 6,
    /// Resource exhausted (e.g., buffer full, memory limit reached).
    ResourceExhausted = 7,
    /// Operation was aborted.
    Aborted = 8,
    /// Value is out of valid range.
    OutOfRange = 9,
    /// Internal error occurred.
    Internal = 10,
    /// Service is unavailable.
    Unavailable = 11,
    /// Request is not authenticated.
    Unauthenticated = 12,
}

#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq)]
pub struct HeaderSchema {
    pub src: [u8; 17],
    pub dist: Destination,
    pub message_type: MessageType,
    pub size: u8,
    pub version: u8,
    pub battery_level: u8,
    /// RSSI (Received Signal Strength Indicator) in dBm.
    /// Set to `RSSI_NOT_AVAILABLE` when sending, automatically populated when receiving.
    /// Typical values: -120 to -30 dBm (higher values indicate better signal).
    pub rssi: i16,
    /// SNR (Signal-to-Noise Ratio) in dB.
    /// Set to `SNR_NOT_AVAILABLE` when sending, automatically populated when receiving.
    /// Typical values: -20 to +15 dB (higher values indicate better signal).
    pub snr: i8,
    /// Status code indicating the result of the message operation.
    /// Set to `Status::Ok` for successful operations, or other status codes to indicate errors or special conditions.
    pub status: Status,
    /// Timestamp in seconds since epoch (Unix timestamp).
    /// Set to `TIMESTAMP_NOT_AVAILABLE` (0) when sending from sensor, gateway should populate with current time.
    /// Allows sensors to synchronize their clock during installation and subsequent communications.
    pub timestamp: u32,
}

#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    Event,
    EventResponse,
    Ack,
    /// Secure handshake Step 1: sensor broadcasts nonce + public key.
    HandshakeRequest,
    /// Secure handshake Step 2: gateway sends ECIES-encrypted challenge.
    HandshakeChallenge,
    /// Secure handshake Step 3: sensor confirms by signing the gateway nonce.
    HandshakeConfirm,
    /// Session key renewal trigger (encrypted with the current session key).
    KeyRenewRequest,
    /// Lightweight renew challenge (encrypted with the current session key).
    KeyRenewChallenge,
    /// Lightweight renew acknowledgment (encrypted with the current session key).
    KeyRenewAck,
    /// Session resume for enrolled sensors (clear-text, ECDSA + eph-eph, no old session key).
    SessionResumeRequest,
    SessionResumeChallenge,
    SessionResumeConfirm,
}

#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq)]
pub enum Destination {
    AllGateways,
    AllSensors,
    All,
    OneDestination([u8; 17]),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum RequestType {
    Event(Event),
    /// Secure handshake Step 1: sensor broadcasts nonce + public key.
    HandshakeRequest(HandshakeRequest),
    /// Secure handshake Step 3: sensor confirms by signing the gateway nonce.
    HandshakeConfirm(HandshakeConfirm),
    /// Session key renewal trigger (encrypted with the current session key).
    KeyRenewRequest(KeyRenewRequest),
    /// Lightweight renew acknowledgment (encrypted with the current session key).
    KeyRenewAck(KeyRenewAck),
    /// Session resume trigger (clear-text, directed to gateway).
    SessionResumeRequest(SessionResumeRequest),
    /// Session resume confirmation (clear-text).
    SessionResumeConfirm(HandshakeConfirm),
}

/// Acknowledgment structure for confirming receipt and processing of messages.
///
/// This structure provides a generic acknowledgment format that can be used across
/// different message types. It includes status information and the MAC address
/// of the device that sent the original request/event.
#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// Status indicating whether the operation was successfully processed.
    /// Uses the common Status enum to indicate success or various error conditions.
    pub status: Status,
    /// MAC address of the device that sent the original request/event.
    /// Used to confirm which message is being acknowledged.
    pub device_mac: [u8; 17],
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum ResponseType {
    Event(Ack),
    /// Secure handshake Step 2: gateway sends ECIES-encrypted challenge.
    HandshakeChallenge(HandshakeChallenge),
    /// Lightweight renew challenge (encrypted with the current session key).
    KeyRenewChallenge(KeyRenewChallenge),
    /// Session resume challenge (clear-text, same layout as install challenge).
    SessionResumeChallenge(HandshakeChallenge),
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum BodySchema {
    RequestType(RequestType),
    ResponseType(ResponseType),
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct MessageSchema {
    pub header: HeaderSchema,
    pub body: BodySchema,
}

impl MessageSchema {
    pub(crate) fn create_body_request(
        //TODO decomment pub(crate) (tested)
        // pub fn create_body_request(
        src: [u8; 17],
        battery_level: u8,
        dist: Destination,
        message_type: MessageType,
        body: RequestType,
        timestamp: u32,
    ) -> MessageSchema {
        MessageSchema {
            header: HeaderSchema {
                src,
                dist,
                message_type,
                size: 0,
                version: 0,
                battery_level,
                rssi: RSSI_NOT_AVAILABLE,
                snr: SNR_NOT_AVAILABLE,
                status: Status::Ok,
                timestamp,
            },
            body: BodySchema::RequestType(body),
        }
    }

    pub(crate) fn create_body_response(
        dist: [u8; 17],
        src: [u8; 17],
        message_type: MessageType,
        body: ResponseType,
        timestamp: u32,
    ) -> MessageSchema {
        MessageSchema {
            header: HeaderSchema {
                src,
                dist: OneDestination(dist),
                message_type,
                size: 0,
                version: 0,
                battery_level: 0,
                rssi: RSSI_NOT_AVAILABLE,
                snr: SNR_NOT_AVAILABLE,
                status: Status::Ok,
                timestamp,
            },
            body: BodySchema::ResponseType(body),
        }
    }

    pub fn serialize<const N: usize>(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<[u8; N], &'static str> {
        Ok(self.serialize_with_len::<N>(key, nonce, aad)?.0)
    }

    /// Serializes an encrypted envelope and returns `(buffer, encoded_len)`.
    pub fn serialize_with_len<const N: usize>(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<([u8; N], usize), &'static str> {
        let mut body_slice: [u8; N] = [0u8; N];
        let length =
            bincode::encode_into_slice(&self.body, &mut body_slice, bincode::config::standard())
                .map_err(|_| "Body serialization failed")?;
        let mut encrypted_body_buffer =
            Vec::<u8, N>::from_slice(&body_slice[..length]).map_err(|_| "buffer too small")?;

        let size = encrypt(&mut encrypted_body_buffer, key, nonce, aad)?;
        self.header.size = size as u8;
        let mut body = [0u8; ENCRYPTED_BODY_MAX];
        let data = &encrypted_body_buffer[..];
        body[..data.len()].copy_from_slice(data);
        let result = EncryptedSchema {
            header: self.header,
            body,
        };
        let mut slice: [u8; N] = [0u8; N];
        let len = bincode::encode_into_slice(result, &mut slice, bincode::config::standard())
            .map_err(|_| "Envelope serialization failed")?;
        Ok((slice, len))
    }

    /// Serialize the full `MessageSchema` in **clear text**, without encryption
    /// and without the `EncryptedSchema` wrapper.
    ///
    /// This is useful for large init messages (e.g. public key + signature)
    /// that would otherwise exceed the SX1278 single‑packet limit once wrapped
    /// in `EncryptedSchema` and encrypted.
    ///
    /// Security model:
    /// - Confidentiality: none (message is sent in clear),
    /// - Integrity/authenticity: expected to be provided by a signature
    ///   checked at application level.
    pub fn serialize_clear<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        Ok(self.serialize_clear_with_len::<N>()?.0)
    }

    /// Serializes a clear-text message and returns `(buffer, encoded_len)`.
    ///
    /// Callers must pass only `&buffer[..encoded_len]` to LoRa TX — trailing zeros break
    /// `deserialize_clear` on the receiver and can exceed the SX1278 user payload limit.
    pub fn serialize_clear_with_len<const N: usize>(&mut self) -> Result<([u8; N], usize), &'static str> {
        let mut slice: [u8; N] = [0u8; N];
        let len = bincode::encode_into_slice(&*self, &mut slice, bincode::config::standard())
            .map_err(|_| "Envelope serialization failed")?;
        Ok((slice, len))
    }
}

pub fn deserialize<const N: usize>(
    data: &[u8],
    // key: &[u8; 32],
    // aad: Option<&[u8]>,
) -> Result<EncryptedSchema, &'static str> {
    let (header, header_len) =
        bincode::decode_from_slice::<HeaderSchema, _>(data, bincode::config::standard())
            .map_err(|_| "Bad header")?;
    let (body, _) = bincode::decode_from_slice::<[u8; ENCRYPTED_BODY_MAX], _>(
        &data[header_len..],
        bincode::config::standard(),
    )
    .map_err(|_| "Bad body")?;
    Ok(EncryptedSchema {
        header,
        body,
    })
}

/// Deserialize a clear‑text `MessageSchema` that was serialized without
/// `EncryptedSchema`/encryption (see `MessageSchema::serialize_clear`).
pub fn deserialize_clear<const N: usize>(data: &[u8]) -> Result<MessageSchema, &'static str> {
    let (message, _len) =
        bincode::decode_from_slice::<MessageSchema, _>(data, bincode::config::standard())
            .map_err(|_| "Bad clear message")?;
    Ok(message)
}

pub fn deserialize_body<const N: usize>(
    header: HeaderSchema,
    body: &[u8],
    key: &[u8; 32],
    aad: Option<&[u8]>,
) -> Result<MessageSchema, &'static str> {
    let mut encrypted = Vec::<u8, N>::from_slice(&body[..header.size as usize])
        .map_err(|_| "Encrypted body too long")?;
    decrypt(&mut encrypted, key, aad)?;
    let (body, _) =
        bincode::decode_from_slice::<BodySchema, _>(&encrypted[..], bincode::config::standard())
            .map_err(|_| "Decryption decode failed")?;

    Ok(MessageSchema {
        header,
        body,
    })
}

pub mod error;

#[cfg(test)]
pub mod tests;

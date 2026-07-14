use crate::com::error::model::ComError;
use crate::com::handshake::install_core::{HandshakeConfirm, HandshakeSession};
use crate::com::handshake::lora_helpers::send_with_retries;
use crate::com::handshake::resume_core::{
    CONFIRM_RETRIES, SENSOR_CHALLENGE_RX_TIMEOUT, SENSOR_REBROADCAST_FIRST_ATTEMPT,
    SENSOR_REBROADCAST_INTERVAL,
};
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, SIGNATURE_LEN, derive_session_key};
use crate::com::keys::Keys;
use crate::models::common::{
    BodySchema, Destination::OneDestination, MessageSchema, MessageType, RequestType,
    ResponseType, deserialize_clear,
};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;
use lora::error::model::LoRaError;

/// Session resume core (sensor): waits for `SessionResumeChallenge`, eph-eph ECDH, sends confirm.
#[allow(clippy::too_many_arguments)]
pub fn complete_resume_as_sensor<SPI, CS, RST, SpiErr, FEPH, FV, FS, D>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut D,
    sensor_mac: [u8; 17],
    battery_level: u8,
    sensor_nonce: [u8; 32],
    mut ecdh_ephemeral_with_peer: FEPH,
    mut verify_sig_sensor_nonce: FV,
    mut sign_gateway_nonce: FS,
    timestamp: u32,
    rebroadcast_payload: Option<(&[u8], usize)>,
) -> Result<HandshakeSession, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    D: DelayNs,
    FEPH: FnMut(&[u8; PUBLIC_KEY_LEN]) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()>,
    FV: FnMut(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
    FS: FnMut(&[u8; 32]) -> [u8; SIGNATURE_LEN],
{
    let mut recv_buffer = [0u8; HANDSHAKE_MESSAGE_MAX];
    for attempt in 0..SENSOR_CHALLENGE_RX_TIMEOUT {
        let receive_result = match lora.receive::<SpiErr, _>(&mut recv_buffer, delay) {
            Ok(r) => r,
            Err(LoRaError::NoPacket) => {
                if let Some((payload, payload_len)) = rebroadcast_payload
                    && attempt >= SENSOR_REBROADCAST_FIRST_ATTEMPT as usize
                    && (attempt - SENSOR_REBROADCAST_FIRST_ATTEMPT as usize)
                        .is_multiple_of(SENSOR_REBROADCAST_INTERVAL as usize)
                {
                    lora.set_mode(lora::sx1278::Mode::Manual, delay);
                    lora.send(&payload[..payload_len], delay)?;
                    lora.set_mode(lora::sx1278::Mode::Receiver, delay);
                }
                delay.delay_ms(120u32);
                continue;
            }
            Err(LoRaError::CrcError)
            | Err(LoRaError::DeCompressionFailed)
            | Err(LoRaError::Timeout)
            | Err(LoRaError::BufferTooSmall { .. }) => {
                delay.delay_ms(80u32);
                continue;
            }
            Err(LoRaError::MessageTooLong { .. }) => {
                return Err(ComError::MessageTooLong {
                    length: HANDSHAKE_MESSAGE_MAX + 1,
                    max: HANDSHAKE_MESSAGE_MAX,
                });
            }
            Err(LoRaError::Canceled) => return Err(ComError::Canceled),
            Err(LoRaError::UnsupportedModule(code)) => return Err(ComError::UnsupportedModule(code)),
            Err(LoRaError::CompressionFailed) => return Err(ComError::CompressionFailed),
            Err(LoRaError::Spi(_)) => {
                return Err(ComError::Custom("SPI error during resume challenge receive"));
            }
        };

        let clear_msg =
            match deserialize_clear::<HANDSHAKE_MESSAGE_MAX>(&recv_buffer[..receive_result.size]) {
                Ok(m) => m,
                Err(_) => continue,
            };

        if clear_msg.header.message_type != MessageType::SessionResumeChallenge {
            continue;
        }
        if clear_msg.header.dist != OneDestination(sensor_mac) {
            continue;
        }

        let challenge = if let BodySchema::ResponseType(ResponseType::SessionResumeChallenge(c)) =
            clear_msg.body
        {
            c
        } else {
            continue;
        };

        let gw_eph_pubkey = *challenge.eph_pubkey_compressed();
        if gw_eph_pubkey.iter().all(|&b| b == 0) {
            continue;
        }

        if !verify_sig_sensor_nonce(challenge.gateway_pubkey(), challenge.sig_sensor_nonce()) {
            return Err(ComError::VerificationFailed);
        }

        let (sensor_eph_pubkey, shared_secret) = match ecdh_ephemeral_with_peer(&gw_eph_pubkey) {
            Ok(pair) => pair,
            Err(_) => return Err(ComError::VerificationFailed),
        };

        if sensor_eph_pubkey.iter().all(|&b| b == 0) || shared_secret.iter().all(|&b| b == 0) {
            return Err(ComError::VerificationFailed);
        }

        let gateway_nonce = *challenge.gateway_nonce();
        let key_expire_at = challenge.key_expire_at();
        let challenge_timestamp = clear_msg.header.timestamp;
        let gateway_mac = clear_msg.header.src;

        let sig_gw_nonce = sign_gateway_nonce(&gateway_nonce);

        let mut confirm_msg = MessageSchema::create_body_request(
            sensor_mac,
            battery_level,
            OneDestination(gateway_mac),
            MessageType::SessionResumeConfirm,
            RequestType::SessionResumeConfirm(HandshakeConfirm::new(
                sig_gw_nonce,
                sensor_eph_pubkey,
            )),
            timestamp,
        );
        let (confirm_buffer, confirm_len) = confirm_msg
            .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
            .map_err(ComError::Custom)?;
        if confirm_len > crate::models::common::LORA_USER_PAYLOAD_MAX {
            return Err(ComError::MessageTooLong {
                length: confirm_len,
                max: crate::models::common::LORA_USER_PAYLOAD_MAX,
            });
        }

        send_with_retries(lora, delay, &confirm_buffer[..confirm_len], CONFIRM_RETRIES)?;

        let session_key = derive_session_key(&shared_secret, &sensor_nonce, &gateway_nonce);
        return Ok(HandshakeSession {
            keys: Keys {
                key: session_key,
                expire_at: key_expire_at,
                timestamp: challenge_timestamp,
            },
            gateway_mac,
        });
    }

    Err(ComError::Timeout)
}

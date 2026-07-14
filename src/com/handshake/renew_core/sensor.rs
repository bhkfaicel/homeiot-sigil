use crate::com::error::model::ComError;
use crate::com::handshake::install_core::HandshakeSession;
use crate::com::handshake::lora_helpers::{send_encrypted, try_receive_encrypted};
use crate::com::handshake::renew_core::{
    CONFIRM_RETRIES, KeyRenewAck, SENSOR_CHALLENGE_RX_TIMEOUT,
    SENSOR_REBROADCAST_FIRST_ATTEMPT, SENSOR_REBROADCAST_INTERVAL,
};
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, derive_session_key};
use crate::com::keys::Keys;
use crate::models::common::{
    BodySchema, Destination::OneDestination, MessageSchema, MessageType, RequestType,
    ResponseType,
};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Lightweight renew core (sensor): waits for encrypted `KeyRenewChallenge`, ephemeral-to-ephemeral
/// ECDH, sends `KeyRenewAck` with the sensor ephemeral pubkey.
///
/// `ecdh_ephemeral_with_peer` must generate a fresh sensor ephemeral keypair, perform ECDH with the
/// gateway ephemeral pubkey from the challenge, and return `(sensor_eph_pubkey, shared_secret)`.
#[allow(clippy::too_many_arguments)]
pub fn complete_renew_as_sensor<SPI, CS, RST, SpiErr, FEPH, D>(
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut D,
    sensor_mac: [u8; 17],
    battery_level: u8,
    gateway_mac: [u8; 17],
    sensor_nonce: [u8; 32],
    session_key: &[u8; 32],
    chacha_nonce: &[u8; 12],
    mut ecdh_ephemeral_with_peer: FEPH,
    timestamp: u32,
    rebroadcast_payload: Option<(&[u8], usize)>,
) -> Result<HandshakeSession, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    D: DelayNs,
    FEPH: FnMut(&[u8; PUBLIC_KEY_LEN]) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()>,
{
    let mut recv_buffer = [0u8; HANDSHAKE_MESSAGE_MAX];
    for attempt in 0..SENSOR_CHALLENGE_RX_TIMEOUT {
        match try_receive_encrypted(
            lora,
            delay,
            &mut recv_buffer,
            session_key,
            MessageType::KeyRenewChallenge,
        ) {
            Ok(Some(msg)) => {
                if msg.header.dist != OneDestination(sensor_mac) {
                    continue;
                }

                let challenge = if let BodySchema::ResponseType(ResponseType::KeyRenewChallenge(c)) =
                    msg.body
                {
                    c
                } else {
                    continue;
                };

                let gw_eph_pubkey = *challenge.eph_pubkey_compressed();
                if gw_eph_pubkey.iter().all(|&b| b == 0) {
                    continue;
                }

                let (sensor_eph_pubkey, shared_secret) =
                    match ecdh_ephemeral_with_peer(&gw_eph_pubkey) {
                        Ok(pair) => pair,
                        Err(_) => return Err(ComError::VerificationFailed),
                    };

                if sensor_eph_pubkey.iter().all(|&b| b == 0) || shared_secret.iter().all(|&b| b == 0)
                {
                    return Err(ComError::VerificationFailed);
                }

                let gateway_nonce = *challenge.gateway_nonce();
                let key_expire_at = challenge.key_expire_at();
                let challenge_timestamp = msg.header.timestamp;
                let gateway_mac_from_header = msg.header.src;

                let session_key_new =
                    derive_session_key(&shared_secret, &sensor_nonce, &gateway_nonce);

                for tx in 0..CONFIRM_RETRIES {
                    let mut ack_msg = MessageSchema::create_body_request(
                        sensor_mac,
                        battery_level,
                        OneDestination(gateway_mac),
                        MessageType::KeyRenewAck,
                        RequestType::KeyRenewAck(KeyRenewAck::new(sensor_eph_pubkey)),
                        timestamp,
                    );
                    let ack_nonce = derive_ack_nonce(chacha_nonce, tx);
                    send_encrypted(lora, delay, &mut ack_msg, session_key, &ack_nonce)?;
                    if tx + 1 < CONFIRM_RETRIES {
                        lora.set_mode(lora::sx1278::Mode::Receiver, delay);
                        delay.delay_ms(150u32);
                    }
                }

                return Ok(HandshakeSession {
                    keys: Keys {
                        key: session_key_new,
                        expire_at: key_expire_at,
                        timestamp: challenge_timestamp,
                    },
                    gateway_mac: gateway_mac_from_header,
                });
            }
            Ok(None) => {
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
            }
            Err(e) => return Err(e),
        }
    }

    Err(ComError::Timeout)
}

/// Derives a distinct ChaCha nonce for each renew-ack retry from the base TX nonce.
fn derive_ack_nonce(base: &[u8; 12], tx_index: u8) -> [u8; 12] {
    let mut nonce = *base;
    nonce[11] = nonce[11].wrapping_add(tx_index);
    nonce
}

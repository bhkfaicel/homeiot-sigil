use crate::com::error::model::ComError;
use crate::com::handshake::install_core::{HandshakeChallenge, HandshakeResult, SessionRecovery};
use crate::com::handshake::{
    GATEWAY_CHALLENGE_RESEND_PERIOD, GATEWAY_CONFIRM_RX_TIMEOUT, HANDSHAKE_MESSAGE_MAX,
    PUBLIC_KEY_LEN, SIGNATURE_LEN, derive_session_key,
};
use crate::models::common::{
    BodySchema, Destination::OneDestination, MessageSchema, MessageType, RequestType, ResponseType,
    deserialize_clear,
};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::spi::SpiBus;
use lora;

/// Install session core: structured eph-eph challenge + ECDSA confirm wait.
///
/// `generate_gateway_ephemeral` creates the gateway ephemeral keypair (private key stays in HW).
/// After receiving `HandshakeConfirm`, `ecdh_with_sensor_ephemeral` completes ECDH with the
/// sensor ephemeral pubkey.
#[allow(clippy::too_many_arguments)]
pub fn send_install_challenge_and_wait_confirm<SPI, CS, RST, SpiErr, FGEN, FECDH, FVN>(
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    sensor_pubkey: &[u8; PUBLIC_KEY_LEN],
    sensor_nonce: &[u8; 32],
    gateway_pubkey: &[u8; PUBLIC_KEY_LEN],
    sig_sensor_nonce: &[u8; SIGNATURE_LEN],
    gateway_nonce: &[u8; 32],
    key_expire_at: u32,
    generate_gateway_ephemeral: FGEN,
    ecdh_with_sensor_ephemeral: FECDH,
    verify_sig_gateway_nonce: FVN,
    lora: &mut lora::sx1278::Controller<SPI, CS, RST>,
    delay: &mut impl DelayNs,
    timestamp: u32,
) -> Result<HandshakeResult, ComError<SpiErr>>
where
    SPI: SpiBus<u8, Error = SpiErr>,
    CS: OutputPin,
    RST: OutputPin,
    SpiErr: core::fmt::Debug,
    FGEN: Fn() -> Result<[u8; PUBLIC_KEY_LEN], ()>,
    FECDH: Fn(&[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()>,
    FVN: Fn(&[u8; PUBLIC_KEY_LEN], &[u8; SIGNATURE_LEN]) -> bool,
{
    let rx_timeout = GATEWAY_CONFIRM_RX_TIMEOUT;

    let gw_eph_pubkey = generate_gateway_ephemeral().map_err(|_| ComError::VerificationFailed)?;
    if gw_eph_pubkey.iter().all(|&b| b == 0) {
        return Err(ComError::VerificationFailed);
    }

    let mut challenge_msg = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::HandshakeChallenge,
        ResponseType::HandshakeChallenge(HandshakeChallenge::new(
            gw_eph_pubkey,
            *sig_sensor_nonce,
            *gateway_pubkey,
            *gateway_nonce,
            key_expire_at,
        )),
        timestamp,
    );
    let (buffer, len) = challenge_msg
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .map_err(ComError::Custom)?;
    if len > crate::models::common::LORA_USER_PAYLOAD_MAX {
        return Err(ComError::MessageTooLong {
            length: len,
            max: crate::models::common::LORA_USER_PAYLOAD_MAX,
        });
    }

    let _recovery = SessionRecovery::Install;
    let mut recv_buffer = [0u8; HANDSHAKE_MESSAGE_MAX];
    for attempt in 0..rx_timeout {
        if attempt % GATEWAY_CHALLENGE_RESEND_PERIOD == 0 {
            lora.set_mode(lora::sx1278::Mode::Manual, delay);
            lora.send(&buffer[..len], delay)?;
            lora.set_mode(lora::sx1278::Mode::Receiver, delay);
        }

        let receive_result = match lora.receive::<SpiErr, _>(&mut recv_buffer, delay) {
            Ok(r) => r,
            Err(_) => {
                delay.delay_ms(200u32);
                continue;
            }
        };

        let clear_msg =
            match deserialize_clear::<HANDSHAKE_MESSAGE_MAX>(&recv_buffer[..receive_result.size]) {
                Ok(m) => m,
                Err(_) => continue,
            };

        if clear_msg.header.message_type != MessageType::HandshakeConfirm {
            if clear_msg.header.message_type == MessageType::HandshakeRequest
                && clear_msg.header.src == sensor_mac
            {
                lora.set_mode(lora::sx1278::Mode::Manual, delay);
                lora.send(&buffer[..len], delay)?;
                lora.set_mode(lora::sx1278::Mode::Receiver, delay);
            }
            continue;
        }
        if clear_msg.header.dist != OneDestination(gateway_mac) {
            continue;
        }

        if let BodySchema::RequestType(RequestType::HandshakeConfirm(confirm)) = clear_msg.body {
            if !verify_sig_gateway_nonce(sensor_pubkey, confirm.sig_gateway_nonce()) {
                return Err(ComError::VerificationFailed);
            }

            let sensor_eph_pubkey = *confirm.sensor_eph_pubkey_compressed();
            if sensor_eph_pubkey.iter().all(|&b| b == 0) {
                continue;
            }

            let shared_secret = ecdh_with_sensor_ephemeral(&sensor_eph_pubkey)
                .map_err(|_| ComError::VerificationFailed)?;
            if shared_secret.iter().all(|&b| b == 0) {
                continue;
            }

            let session_key = derive_session_key(&shared_secret, sensor_nonce, gateway_nonce);
            return Ok(HandshakeResult {
                session_key,
                sensor_pubkey: *sensor_pubkey,
                key_expire_at,
            });
        }
    }

    Err(ComError::Timeout)
}

use crate::com::handshake::{
    CHALLENGE_PLAINTEXT_LEN, ECIES_CIPHERTEXT_LEN, HANDSHAKE_MESSAGE_MAX,
    PUBLIC_KEY_LEN, SIGNATURE_LEN, encrypt_challenge,
};
use crate::com::handshake::gateway::HandshakeChallenge;
use crate::com::handshake::sensor::{HandshakeConfirm, HandshakeRequest};
use crate::models::common::{
    Destination::{AllGateways, OneDestination},
    MessageSchema, MessageType, RequestType, ResponseType,
};
use alloc::vec;
use embedded_hal_mock::eh1::delay::NoopDelay;
use embedded_hal_mock::eh1::digital::{
    Mock as PinMock, State as PinState, Transaction as PinTransaction,
};
use embedded_hal_mock::eh1::spi::{Mock as SpiMock, Transaction as SpiTransaction};
use lora::sx1278::Mode;
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_no_packet, expectations_for_receive_success,
    expectations_for_receiver_mode, expectations_for_send,
};

/// Must match `initiate_handshake` challenge listen loop in `sensor/mod.rs`.
const SENSOR_CHALLENGE_RX_TIMEOUT: usize = 800;
const SENSOR_REBROADCAST_FIRST_ATTEMPT: u16 = 50;
const SENSOR_REBROADCAST_INTERVAL: u16 = 50;

/// SPI expectations for the sensor waiting until `ComError::Timeout` (no challenge received).
pub fn expectations_for_sensor_challenge_listen_timeout(
    rebroadcast_payload: &[u8],
) -> vec::Vec<SpiTransaction<u8>> {
    let mut expectations = vec![];
    for attempt in 0..SENSOR_CHALLENGE_RX_TIMEOUT {
        expectations.extend(expectations_for_receive_no_packet(1, Mode::Receiver));
        if attempt as u16 >= SENSOR_REBROADCAST_FIRST_ATTEMPT
            && (attempt as u16 - SENSOR_REBROADCAST_FIRST_ATTEMPT)
                .is_multiple_of(SENSOR_REBROADCAST_INTERVAL)
        {
            expectations.extend(expectations_for_send(rebroadcast_payload, Mode::Receiver));
        }
    }
    expectations
}

/// Builds the serialised `HandshakeRequest` buffer that the sensor broadcasts (Step 1).
pub fn build_handshake_request_buffer(
    sensor_mac: [u8; 17],
    battery_level: u8,
    sensor_nonce: [u8; 32],
    sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_pubkey: [u8; SIGNATURE_LEN],
    timestamp: u32,
) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        AllGateways,
        MessageType::HandshakeRequest,
        RequestType::HandshakeRequest(HandshakeRequest::new(
            sensor_nonce,
            sensor_pubkey,
            sig_sensor_pubkey,
        )),
        timestamp,
    );
    message
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .expect("serialize_clear_with_len")
}

/// Builds the serialised `HandshakeChallenge` buffer that the gateway sends (Step 2).
pub fn build_handshake_challenge_buffer(
    gateway_mac: [u8; 17],
    sensor_mac: [u8; 17],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    timestamp: u32,
) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut plaintext = [0u8; CHALLENGE_PLAINTEXT_LEN];
    plaintext[..SIGNATURE_LEN].copy_from_slice(&sig_sensor_nonce);
    plaintext[SIGNATURE_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN].copy_from_slice(&gateway_pubkey);
    plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN..SIGNATURE_LEN + PUBLIC_KEY_LEN + 32]
        .copy_from_slice(&gateway_nonce);
    plaintext[SIGNATURE_LEN + PUBLIC_KEY_LEN + 32..]
        .copy_from_slice(&key_expire_at.to_be_bytes());

    let mut ciphertext = [0u8; ECIES_CIPHERTEXT_LEN];
    let eph_pubkey_compressed = [0x11u8; PUBLIC_KEY_LEN];
    let shared_secret = [0xCCu8; 32];
    let chacha_nonce = [0x22u8; 12];
    encrypt_challenge(
        &eph_pubkey_compressed,
        &shared_secret,
        &chacha_nonce,
        &plaintext,
        &mut ciphertext,
    )
    .expect("encrypt_challenge");

    let mut message = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::HandshakeChallenge,
        ResponseType::HandshakeChallenge(HandshakeChallenge { data: ciphertext }),
        timestamp,
    );
    message
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .expect("serialize_clear_with_len")
}

/// Builds the serialised `HandshakeConfirm` buffer that the sensor sends (Step 3).
pub fn build_handshake_confirm_buffer(
    sensor_mac: [u8; 17],
    battery_level: u8,
    gateway_mac: [u8; 17],
    sig_gateway_nonce: [u8; SIGNATURE_LEN],
    timestamp: u32,
) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        OneDestination(gateway_mac),
        MessageType::HandshakeConfirm,
        RequestType::HandshakeConfirm(HandshakeConfirm::new(sig_gateway_nonce)),
        timestamp,
    );
    message
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .expect("serialize_clear_with_len")
}

/// SPI expectations for `initiate_handshake` (ok path).
#[allow(clippy::too_many_arguments)]
pub fn create_expectations_for_initiate_handshake(
    mode: Mode,
    sensor_mac: [u8; 17],
    battery_level: u8,
    sensor_nonce: [u8; 32],
    sensor_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_pubkey: [u8; SIGNATURE_LEN],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    gateway_mac: [u8; 17],
    timestamp: u32,
) -> vec::Vec<SpiTransaction<u8>> {
    let (request_buffer, request_len) = build_handshake_request_buffer(
        sensor_mac,
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    let (challenge_buffer, challenge_len) = build_handshake_challenge_buffer(
        gateway_mac,
        sensor_mac,
        sig_sensor_nonce,
        gateway_pubkey,
        gateway_nonce,
        key_expire_at,
        timestamp,
    );
    let (confirm_buffer, confirm_len) = build_handshake_confirm_buffer(
        sensor_mac,
        battery_level,
        gateway_mac,
        [0u8; SIGNATURE_LEN],
        timestamp,
    );

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(
        &request_buffer[..request_len],
        mode,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &challenge_buffer[..challenge_len],
        0x42,
        Mode::Receiver,
    ));
    expectations.extend(expectations_for_send(
        &confirm_buffer[..confirm_len],
        Mode::Manual,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_send(
        &confirm_buffer[..confirm_len],
        Mode::Manual,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_send(
        &confirm_buffer[..confirm_len],
        Mode::Manual,
    ));
    expectations
}

/// Creates a mock LoRa controller from the given SPI expectations.
pub fn create_controller(
    expectations: &[SpiTransaction<u8>],
) -> (
    embedded_hal_mock::common::Generic<SpiTransaction<u8>>,
    embedded_hal_mock::common::Generic<PinTransaction>,
    embedded_hal_mock::common::Generic<PinTransaction>,
    NoopDelay,
) {
    let spi = SpiMock::new(expectations);
    let mut cs_actions = vec![];
    for _ in 0..expectations.len() {
        cs_actions.push(PinTransaction::set(PinState::Low));
        cs_actions.push(PinTransaction::set(PinState::High));
    }
    let cs = PinMock::new(&cs_actions);
    let rst = PinMock::new(&[
        PinTransaction::set(PinState::Low),
        PinTransaction::set(PinState::High),
    ]);
    (spi, cs, rst, NoopDelay::new())
}

use crate::com::handshake::install::sensor::HandshakeRequest;
use crate::com::handshake::install_core::{
    HandshakeChallenge, HandshakeConfirm, SENSOR_CHALLENGE_RX_TIMEOUT,
    SENSOR_REBROADCAST_FIRST_ATTEMPT, SENSOR_REBROADCAST_INTERVAL,
};
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, SIGNATURE_LEN};
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

/// Must match `complete_install_as_sensor` challenge listen loop in `install_core/sensor.rs`.
const SENSOR_CHALLENGE_RX_TIMEOUT_LOCAL: usize = SENSOR_CHALLENGE_RX_TIMEOUT;
const SENSOR_REBROADCAST_FIRST_ATTEMPT_LOCAL: u16 = SENSOR_REBROADCAST_FIRST_ATTEMPT;
const SENSOR_REBROADCAST_INTERVAL_LOCAL: u16 = SENSOR_REBROADCAST_INTERVAL;

/// Gateway ephemeral pubkey used by install test mocks.
pub const TEST_GW_EPH_PUBKEY: [u8; PUBLIC_KEY_LEN] = [0x11u8; PUBLIC_KEY_LEN];

/// Sensor ephemeral pubkey returned by install test ECDH mocks.
pub const TEST_SENSOR_EPH_PUBKEY: [u8; PUBLIC_KEY_LEN] = [0x22u8; PUBLIC_KEY_LEN];

/// Shared secret returned by install test ECDH mocks on both sides.
pub const TEST_EPH_EPH_SHARED_SECRET: [u8; 32] = [0xCCu8; 32];

/// SPI expectations for the sensor waiting until `ComError::Timeout` (no challenge received).
pub fn expectations_for_sensor_challenge_listen_timeout(
    rebroadcast_payload: &[u8],
) -> vec::Vec<SpiTransaction<u8>> {
    let mut expectations = vec![];
    for attempt in 0..SENSOR_CHALLENGE_RX_TIMEOUT_LOCAL {
        expectations.extend(expectations_for_receive_no_packet(1, Mode::Receiver));
        if attempt as u16 >= SENSOR_REBROADCAST_FIRST_ATTEMPT_LOCAL
            && (attempt as u16 - SENSOR_REBROADCAST_FIRST_ATTEMPT_LOCAL)
                .is_multiple_of(SENSOR_REBROADCAST_INTERVAL_LOCAL)
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
    gw_eph_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    timestamp: u32,
) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut message = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::HandshakeChallenge,
        ResponseType::HandshakeChallenge(HandshakeChallenge::new(
            gw_eph_pubkey,
            sig_sensor_nonce,
            gateway_pubkey,
            gateway_nonce,
            key_expire_at,
        )),
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
    sensor_eph_pubkey: [u8; PUBLIC_KEY_LEN],
    timestamp: u32,
) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        battery_level,
        OneDestination(gateway_mac),
        MessageType::HandshakeConfirm,
        RequestType::HandshakeConfirm(HandshakeConfirm::new(sig_gateway_nonce, sensor_eph_pubkey)),
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
        TEST_GW_EPH_PUBKEY,
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
        TEST_SENSOR_EPH_PUBKEY,
        timestamp,
    );

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(&request_buffer[..request_len], mode));
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

/// Mock gateway ephemeral key generation for install tests.
pub fn test_generate_gateway_ephemeral() -> Result<[u8; PUBLIC_KEY_LEN], ()> {
    Ok(TEST_GW_EPH_PUBKEY)
}

/// Mock gateway-side eph-eph ECDH for install tests.
pub fn test_ecdh_with_sensor_ephemeral(
    _sensor_eph_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; 32], ()> {
    Ok(TEST_EPH_EPH_SHARED_SECRET)
}

/// Mock sensor-side eph-eph ECDH for install tests.
pub fn test_ecdh_ephemeral_with_peer(
    _gw_eph_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()> {
    Ok((TEST_SENSOR_EPH_PUBKEY, TEST_EPH_EPH_SHARED_SECRET))
}

use crate::com::error::model::ComError;
use crate::com::handshake::gateway::{HandshakeChallenge, handle_handshake_request};
use crate::com::handshake::sensor::tests::helpers::{
    TEST_GW_EPH_PUBKEY, TEST_SENSOR_EPH_PUBKEY, test_ecdh_with_sensor_ephemeral,
    test_generate_gateway_ephemeral,
};
use crate::com::handshake::sensor::{HandshakeConfirm, HandshakeRequest};
use crate::com::handshake::{
    GATEWAY_CHALLENGE_RESEND_PERIOD, GATEWAY_CONFIRM_RX_TIMEOUT, HANDSHAKE_MESSAGE_MAX,
    PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use crate::models::common::{
    Destination::OneDestination, MessageSchema, MessageType, RequestType, ResponseType,
};
use alloc::vec;
use embedded_hal_mock::eh1::delay::NoopDelay;
use embedded_hal_mock::eh1::digital::{
    Mock as PinMock, State as PinState, Transaction as PinTransaction,
};
use embedded_hal_mock::eh1::spi::{Mock as SpiMock, Transaction as SpiTransaction};
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_no_packet, expectations_for_receive_success,
    expectations_for_receiver_mode, expectations_for_send,
};
use lora::sx1278::{Controller, Mode};

fn sensor_mac() -> [u8; 17] {
    [
        67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51,
    ]
}

fn gateway_mac() -> [u8; 17] {
    [
        26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51,
    ]
}

fn dummy_pubkey() -> [u8; PUBLIC_KEY_LEN] {
    [0u8; PUBLIC_KEY_LEN]
}

fn dummy_sig() -> [u8; SIGNATURE_LEN] {
    [0u8; SIGNATURE_LEN]
}

fn dummy_gateway_nonce() -> [u8; 32] {
    [0xBB; 32]
}

/// Builds the expected structured `HandshakeChallenge` wire buffer.
fn build_challenge_buffer(
    timestamp: u32,
    key_expire_at: u32,
) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut message = MessageSchema::create_body_response(
        sensor_mac(),
        gateway_mac(),
        MessageType::HandshakeChallenge,
        ResponseType::HandshakeChallenge(HandshakeChallenge::new(
            TEST_GW_EPH_PUBKEY,
            dummy_sig(),
            dummy_pubkey(),
            dummy_gateway_nonce(),
            key_expire_at,
        )),
        timestamp,
    );
    message
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .expect("serialize_clear_with_len")
}

/// Builds the `HandshakeConfirm` buffer that the sensor would send back.
fn build_confirm_buffer(timestamp: u32) -> ([u8; HANDSHAKE_MESSAGE_MAX], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac(),
        80,
        OneDestination(gateway_mac()),
        MessageType::HandshakeConfirm,
        RequestType::HandshakeConfirm(HandshakeConfirm::new(dummy_sig(), TEST_SENSOR_EPH_PUBKEY)),
        timestamp,
    );
    message
        .serialize_clear_with_len::<HANDSHAKE_MESSAGE_MAX>()
        .expect("serialize_clear_with_len")
}

fn create_controller(
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

#[test]
fn ok() {
    let timestamp = 260691u32;
    let key_expire_at = 0u32;
    let mode = Mode::Manual;

    let (challenge_buffer, challenge_len) = build_challenge_buffer(timestamp, key_expire_at);
    let (confirm_buffer, confirm_len) = build_confirm_buffer(timestamp);

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        mode,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &confirm_buffer[..confirm_len],
        0x42,
        Mode::Receiver,
    ));

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let request = HandshakeRequest::new([0xAA; 32], dummy_pubkey(), dummy_sig());
    let result = handle_handshake_request(
        &request,
        |_pk, _sig| true,
        test_generate_gateway_ephemeral,
        test_ecdh_with_sensor_ephemeral,
        sensor_mac(),
        gateway_mac(),
        dummy_pubkey(),
        dummy_sig(),
        dummy_gateway_nonce(),
        key_expire_at,
        |_pk, _sig| true,
        &mut controller,
        &mut delay,
        timestamp,
    );

    assert!(result.is_ok());
    let hr = result.unwrap();
    assert_eq!(hr.sensor_pubkey, dummy_pubkey());
    assert_eq!(hr.key_expire_at, key_expire_at);
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn timeout() {
    let timestamp = 260691u32;
    let mode = Mode::Manual;

    let (challenge_buffer, challenge_len) = build_challenge_buffer(timestamp, 0u32);

    let mut expectations = expectations_for_new(mode);
    let challenge_rounds = GATEWAY_CONFIRM_RX_TIMEOUT / GATEWAY_CHALLENGE_RESEND_PERIOD;
    for _ in 0..challenge_rounds {
        expectations.extend(expectations_for_send(
            &challenge_buffer[..challenge_len],
            Mode::Receiver,
        ));
        expectations.extend(expectations_for_receive_no_packet(
            GATEWAY_CHALLENGE_RESEND_PERIOD,
            Mode::Receiver,
        ));
    }

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let request = HandshakeRequest::new([0xAA; 32], dummy_pubkey(), dummy_sig());
    let result = handle_handshake_request(
        &request,
        |_pk, _sig| true,
        test_generate_gateway_ephemeral,
        test_ecdh_with_sensor_ephemeral,
        sensor_mac(),
        gateway_mac(),
        dummy_pubkey(),
        dummy_sig(),
        dummy_gateway_nonce(),
        0u32,
        |_pk, _sig| true,
        &mut controller,
        &mut delay,
        timestamp,
    );

    assert!(matches!(result, Err(ComError::Timeout)));
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn verification_failed_verify_sensor() {
    // verify_sensor returns false → reject before any LoRa traffic
    let timestamp = 260691u32;
    let mode = Mode::Manual;

    let expectations = expectations_for_new(mode);
    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let request = HandshakeRequest::new([0xAA; 32], dummy_pubkey(), dummy_sig());
    let result = handle_handshake_request(
        &request,
        |_pk, _sig| false, // reject sensor identity
        test_generate_gateway_ephemeral,
        test_ecdh_with_sensor_ephemeral,
        sensor_mac(),
        gateway_mac(),
        dummy_pubkey(),
        dummy_sig(),
        dummy_gateway_nonce(),
        0u32,
        |_pk, _sig| true,
        &mut controller,
        &mut delay,
        timestamp,
    );

    assert!(matches!(result, Err(ComError::VerificationFailed)));
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn verification_failed_sig_gateway_nonce() {
    let timestamp = 260691u32;
    let mode = Mode::Manual;

    let (challenge_buffer, challenge_len) = build_challenge_buffer(timestamp, 0u32);
    let (confirm_buffer, confirm_len) = build_confirm_buffer(timestamp);

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        mode,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &confirm_buffer[..confirm_len],
        0x42,
        Mode::Receiver,
    ));

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let request = HandshakeRequest::new([0xAA; 32], dummy_pubkey(), dummy_sig());
    let result = handle_handshake_request(
        &request,
        |_pk, _sig| true,
        test_generate_gateway_ephemeral,
        test_ecdh_with_sensor_ephemeral,
        sensor_mac(),
        gateway_mac(),
        dummy_pubkey(),
        dummy_sig(),
        dummy_gateway_nonce(),
        0u32,
        |_pk, _sig| false, // reject sig_gateway_nonce
        &mut controller,
        &mut delay,
        timestamp,
    );

    assert!(matches!(result, Err(ComError::VerificationFailed)));
    spi.done();
    cs.done();
    rst.done();
}

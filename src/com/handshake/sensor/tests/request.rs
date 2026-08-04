use crate::com::error::model::ComError;
use crate::com::handshake::sensor::initiate_handshake;
use crate::com::handshake::sensor::tests::helpers::{
    TEST_GW_EPH_PUBKEY, TEST_SENSOR_EPH_PUBKEY, build_handshake_challenge_buffer,
    build_handshake_confirm_buffer, build_handshake_request_buffer, create_controller,
    expectations_for_sensor_challenge_listen_timeout, test_ecdh_ephemeral_with_peer,
};
use crate::com::handshake::{HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_success, expectations_for_receiver_mode,
    expectations_for_send,
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

#[test]
fn ok() {
    let battery_level = 80u8;
    let sensor_nonce = [0xAA; 32];
    let sensor_pubkey = [0u8; PUBLIC_KEY_LEN];
    let sig_sensor_pubkey = [0u8; SIGNATURE_LEN];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260691u32;
    let mode = Mode::Manual;

    let (request_buffer, request_len) = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    let (challenge_buffer, challenge_len) = build_handshake_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        TEST_GW_EPH_PUBKEY,
        [0u8; SIGNATURE_LEN],
        [0u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (confirm_buffer, confirm_len) = build_handshake_confirm_buffer(
        sensor_mac(),
        battery_level,
        gateway_mac(),
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

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let result = initiate_handshake(
        &mut controller,
        &mut delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_ecdh_ephemeral_with_peer,
        |_pk, _sig| true,
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    assert!(result.is_ok(), "initiate_handshake returned: {:?}", result);
    let session = result.unwrap();
    assert_eq!(session.keys.expire_at, 0u32);
    assert_eq!(session.keys.timestamp, timestamp);
    assert_eq!(session.gateway_mac, gateway_mac());
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn timeout() {
    let battery_level = 80u8;
    let sensor_nonce = [0xAA; 32];
    let sensor_pubkey = [0u8; PUBLIC_KEY_LEN];
    let sig_sensor_pubkey = [0u8; SIGNATURE_LEN];
    let timestamp = 260691u32;
    let mode = Mode::Manual;

    let (request_buffer, request_len) = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    let req = &request_buffer[..request_len];

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(req, mode));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_sensor_challenge_listen_timeout(req));

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let result = initiate_handshake(
        &mut controller,
        &mut delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_ecdh_ephemeral_with_peer,
        |_pk, _sig| true,
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    assert!(matches!(result, Err(ComError::Timeout)));
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn verification_failed_sig_sensor_nonce() {
    // verify_sig_sensor_nonce returns false → VerificationFailed before confirm is sent
    let battery_level = 80u8;
    let sensor_nonce = [0xAA; 32];
    let sensor_pubkey = [0u8; PUBLIC_KEY_LEN];
    let sig_sensor_pubkey = [0u8; SIGNATURE_LEN];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260691u32;
    let mode = Mode::Manual;

    let (request_buffer, request_len) = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    let (challenge_buffer, challenge_len) = build_handshake_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        TEST_GW_EPH_PUBKEY,
        [0u8; SIGNATURE_LEN],
        [0u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        0u32,
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

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let result = initiate_handshake(
        &mut controller,
        &mut delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_ecdh_ephemeral_with_peer,
        |_pk, _sig| false, // reject sig_sensor_nonce
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    assert!(matches!(result, Err(ComError::VerificationFailed)));
    spi.done();
    cs.done();
    rst.done();
}

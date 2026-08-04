#![cfg(test)]

mod e2e;

use crate::com::handshake::install_core::HandshakeChallenge;
use crate::com::handshake::install_core::HandshakeConfirm;
use crate::com::handshake::resume::gateway::handle_resume_request;
use crate::com::handshake::resume::sensor::resume_session;
use crate::com::handshake::resume_core::SessionResumeRequest;
use crate::com::handshake::sensor::tests::helpers::{
    TEST_GW_EPH_PUBKEY, TEST_SENSOR_EPH_PUBKEY, create_controller, test_ecdh_ephemeral_with_peer,
    test_ecdh_with_sensor_ephemeral, test_generate_gateway_ephemeral,
};
use crate::com::handshake::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::models::common::{
    Destination::OneDestination, MessageSchema, MessageType, RequestType, ResponseType,
};
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

pub(crate) fn build_session_resume_request_buffer(
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    sensor_nonce: [u8; 32],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        80,
        OneDestination(gateway_mac),
        MessageType::SessionResumeRequest,
        RequestType::SessionResumeRequest(SessionResumeRequest::new(
            sensor_nonce,
            sig_sensor_nonce,
        )),
        timestamp,
    );
    message
        .serialize_clear_with_len::<256>()
        .expect("serialize")
}

pub(crate) fn build_session_resume_challenge_buffer(
    gateway_mac: [u8; 17],
    sensor_mac: [u8; 17],
    gw_eph_pubkey: [u8; PUBLIC_KEY_LEN],
    sig_sensor_nonce: [u8; SIGNATURE_LEN],
    gateway_pubkey: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::SessionResumeChallenge,
        ResponseType::SessionResumeChallenge(HandshakeChallenge::new(
            gw_eph_pubkey,
            sig_sensor_nonce,
            gateway_pubkey,
            gateway_nonce,
            key_expire_at,
        )),
        timestamp,
    );
    message
        .serialize_clear_with_len::<256>()
        .expect("serialize")
}

pub(crate) fn build_session_resume_confirm_buffer(
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    sig_gateway_nonce: [u8; SIGNATURE_LEN],
    sensor_eph_pubkey: [u8; PUBLIC_KEY_LEN],
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        80,
        OneDestination(gateway_mac),
        MessageType::SessionResumeConfirm,
        RequestType::SessionResumeConfirm(HandshakeConfirm::new(
            sig_gateway_nonce,
            sensor_eph_pubkey,
        )),
        timestamp,
    );
    message
        .serialize_clear_with_len::<256>()
        .expect("serialize")
}

#[test]
fn session_resume_request_clear_wire_format() {
    let sensor_nonce = [0x55; 32];
    let sig = [0x66; SIGNATURE_LEN];
    let (buffer, len) =
        build_session_resume_request_buffer(sensor_mac(), gateway_mac(), sensor_nonce, sig, 1_000);

    assert!(len > 0);
    assert!(len <= crate::models::common::LORA_USER_PAYLOAD_MAX);

    let msg = crate::models::common::deserialize_clear::<256>(&buffer[..len]).expect("deserialize");
    match msg.body {
        crate::models::common::BodySchema::RequestType(RequestType::SessionResumeRequest(req)) => {
            assert_eq!(req.sensor_nonce(), &sensor_nonce);
            assert_eq!(req.sig_sensor_nonce(), &sig);
        }
        other => panic!("unexpected body: {:?}", other),
    }
}

#[test]
fn handle_resume_request_ok() {
    let sensor_nonce = [0xAA; 32];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260_691u32;
    let mode = Mode::Manual;

    let (challenge_buffer, challenge_len) = build_session_resume_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        TEST_GW_EPH_PUBKEY,
        [0u8; SIGNATURE_LEN],
        [0u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (confirm_buffer, confirm_len) = build_session_resume_confirm_buffer(
        sensor_mac(),
        gateway_mac(),
        [0u8; SIGNATURE_LEN],
        TEST_SENSOR_EPH_PUBKEY,
        timestamp,
    );

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        mode,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<256>(
        &confirm_buffer[..confirm_len],
        0x42,
        Mode::Receiver,
    ));

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let request = SessionResumeRequest::new(sensor_nonce, [0u8; SIGNATURE_LEN]);
    let result = handle_resume_request(
        &request,
        |_pk, _sig| true,
        test_generate_gateway_ephemeral,
        test_ecdh_with_sensor_ephemeral,
        |_pk, _sig| true,
        &[0u8; PUBLIC_KEY_LEN],
        sensor_mac(),
        gateway_mac(),
        [0u8; PUBLIC_KEY_LEN],
        [0u8; SIGNATURE_LEN],
        gateway_nonce,
        0u32,
        &mut controller,
        &mut delay,
        timestamp,
    );

    assert!(result.is_ok());
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn resume_session_ok() {
    let sensor_nonce = [0xAA; 32];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260_691u32;
    let mode = Mode::Manual;

    let (request_buffer, request_len) = build_session_resume_request_buffer(
        sensor_mac(),
        gateway_mac(),
        sensor_nonce,
        [0u8; SIGNATURE_LEN],
        timestamp,
    );
    let (challenge_buffer, challenge_len) = build_session_resume_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        TEST_GW_EPH_PUBKEY,
        [0u8; SIGNATURE_LEN],
        [0u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (confirm_buffer, confirm_len) = build_session_resume_confirm_buffer(
        sensor_mac(),
        gateway_mac(),
        [0u8; SIGNATURE_LEN],
        TEST_SENSOR_EPH_PUBKEY,
        timestamp,
    );

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(&request_buffer[..request_len], mode));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<256>(
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

    let result = resume_session(
        &mut controller,
        &mut delay,
        sensor_mac(),
        80,
        gateway_mac(),
        sensor_nonce,
        [0u8; SIGNATURE_LEN],
        test_ecdh_ephemeral_with_peer,
        |_pk, _sig| true,
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    assert!(result.is_ok(), "resume_session returned: {:?}", result);
    spi.done();
    cs.done();
    rst.done();
}

#![cfg(test)]

mod e2e;

use crate::com::handshake::renew::gateway::handle_renew_request;
use crate::com::handshake::renew::sensor::{KeyRenewRequest, renew_session};
use crate::com::handshake::renew_core::{KeyRenewAck, KeyRenewChallenge};
use crate::com::handshake::sensor::tests::helpers::create_controller;
use crate::com::handshake::PUBLIC_KEY_LEN;
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

fn session_key() -> [u8; 32] {
    [0xAB; 32]
}

fn chacha_nonce() -> [u8; 12] {
    [0x01; 12]
}

pub(crate) fn build_key_renew_request_buffer(
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    sensor_nonce: [u8; 32],
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        80,
        OneDestination(gateway_mac),
        MessageType::KeyRenewRequest,
        RequestType::KeyRenewRequest(KeyRenewRequest::new(sensor_nonce)),
        timestamp,
    );
    message
        .serialize_with_len::<256>(&session_key(), &chacha_nonce(), None)
        .expect("serialize")
}

pub(crate) fn build_key_renew_challenge_buffer(
    gateway_mac: [u8; 17],
    sensor_mac: [u8; 17],
    eph_pubkey: [u8; PUBLIC_KEY_LEN],
    gateway_nonce: [u8; 32],
    key_expire_at: u32,
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_response(
        sensor_mac,
        gateway_mac,
        MessageType::KeyRenewChallenge,
        ResponseType::KeyRenewChallenge(KeyRenewChallenge::new(
            eph_pubkey,
            gateway_nonce,
            key_expire_at,
        )),
        timestamp,
    );
    message
        .serialize_with_len::<256>(&session_key(), &chacha_nonce(), None)
        .expect("serialize")
}

pub(crate) fn build_key_renew_ack_buffer(
    sensor_mac: [u8; 17],
    gateway_mac: [u8; 17],
    ack_nonce: [u8; 12],
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        80,
        OneDestination(gateway_mac),
        MessageType::KeyRenewAck,
        RequestType::KeyRenewAck(KeyRenewAck),
        timestamp,
    );
    message
        .serialize_with_len::<256>(&session_key(), &ack_nonce, None)
        .expect("serialize")
}

fn ack_nonce_for_retry(base: [u8; 12], tx_index: u8) -> [u8; 12] {
    let mut nonce = base;
    nonce[11] = nonce[11].wrapping_add(tx_index);
    nonce
}

fn test_ecdh_ephemeral(
    _sensor_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()> {
    Ok(([0x11u8; PUBLIC_KEY_LEN], [0xCCu8; 32]))
}

fn test_ecdh_shared_secret(_eph_pubkey: &[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()> {
    Ok([0xCCu8; 32])
}

#[test]
fn key_renew_request_roundtrip_encode() {
    let request = KeyRenewRequest::new([0x55; 32]);
    let mut encoded = [0u8; 64];
    let len = bincode::encode_into_slice(&request, &mut encoded, bincode::config::standard())
        .expect("encode");
    let (decoded, _) =
        bincode::decode_from_slice::<KeyRenewRequest, _>(&encoded[..len], bincode::config::standard())
            .expect("decode");
    assert_eq!(decoded, request);
}

#[test]
fn key_renew_request_encrypted_wire_format() {
    let sensor_nonce = [0x55; 32];
    let (buffer, len) = build_key_renew_request_buffer(sensor_mac(), gateway_mac(), sensor_nonce, 1_000);

    assert!(len > 0);
    assert!(len <= crate::models::common::LORA_USER_PAYLOAD_MAX);

    let encrypted = crate::models::common::deserialize::<256>(&buffer[..len]).expect("deserialize");
    let decrypted = crate::models::common::deserialize_body::<150>(
        encrypted.header,
        &encrypted.body,
        &session_key(),
        None,
    )
    .expect("decrypt body");

    match decrypted.body {
        crate::models::common::BodySchema::RequestType(RequestType::KeyRenewRequest(req)) => {
            assert_eq!(req.sensor_nonce(), &sensor_nonce);
        }
        other => panic!("unexpected body: {:?}", other),
    }
}

#[test]
fn handle_renew_request_ok() {
    let sensor_nonce = [0xAA; 32];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260_691u32;
    let mode = Mode::Manual;

    let (challenge_buffer, challenge_len) = build_key_renew_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        [0x11u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (ack_buffer, ack_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        chacha_nonce(),
        timestamp,
    );

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        mode,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<256>(
        &ack_buffer[..ack_len],
        0x42,
        Mode::Receiver,
    ));

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let request = KeyRenewRequest::new(sensor_nonce);
    let result = handle_renew_request(
        &request,
        &session_key(),
        &chacha_nonce(),
        test_ecdh_ephemeral,
        &[0u8; PUBLIC_KEY_LEN],
        sensor_mac(),
        gateway_mac(),
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
fn renew_session_ok() {
    let sensor_nonce = [0xAA; 32];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260_691u32;
    let mode = Mode::Manual;
    let base_nonce = chacha_nonce();

    let (request_buffer, request_len) =
        build_key_renew_request_buffer(sensor_mac(), gateway_mac(), sensor_nonce, timestamp);
    let (challenge_buffer, challenge_len) = build_key_renew_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        [0x11u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (ack0, ack0_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        ack_nonce_for_retry(base_nonce, 0),
        timestamp,
    );
    let (ack1, ack1_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        ack_nonce_for_retry(base_nonce, 1),
        timestamp,
    );
    let (ack2, ack2_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        ack_nonce_for_retry(base_nonce, 2),
        timestamp,
    );

    let mut expectations = expectations_for_new(mode);
    expectations.extend(expectations_for_send(
        &request_buffer[..request_len],
        mode,
    ));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_receive_success::<256>(
        &challenge_buffer[..challenge_len],
        0x42,
        Mode::Receiver,
    ));
    expectations.extend(expectations_for_send(&ack0[..ack0_len], Mode::Manual));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_send(&ack1[..ack1_len], Mode::Manual));
    expectations.extend(expectations_for_receiver_mode());
    expectations.extend(expectations_for_send(&ack2[..ack2_len], Mode::Manual));

    let (mut spi, mut cs, mut rst, mut delay) = create_controller(&expectations);
    let mut controller = Controller::new(&mut spi, &mut cs, &mut rst, &mut delay, mode).unwrap();

    let result = renew_session(
        &mut controller,
        &mut delay,
        sensor_mac(),
        80,
        gateway_mac(),
        &session_key(),
        &base_nonce,
        sensor_nonce,
        test_ecdh_shared_secret,
        timestamp,
    );

    assert!(result.is_ok(), "renew_session returned: {:?}", result);
    let session = result.unwrap();
    assert_eq!(session.gateway_mac, gateway_mac());
    assert_eq!(session.keys.timestamp, timestamp);
    spi.done();
    cs.done();
    rst.done();
}

#[test]
fn key_renew_challenge_payload_is_smaller_than_install_ecies() {
    let challenge = KeyRenewChallenge::new([0x11u8; PUBLIC_KEY_LEN], [0xBB; 32], 0u32);
    let mut encoded = [0u8; 128];
    let len = bincode::encode_into_slice(&challenge, &mut encoded, bincode::config::standard())
        .expect("encode");

    assert!(
        len < crate::com::handshake::ECIES_CIPHERTEXT_LEN,
        "renew payload {}B vs install ECIES {}B",
        len,
        crate::com::handshake::ECIES_CIPHERTEXT_LEN
    );
}

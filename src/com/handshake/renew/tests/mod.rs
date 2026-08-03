#![cfg(test)]

mod e2e;

use crate::com::handshake::renew::gateway::handle_renew_request;
use crate::com::handshake::renew::sensor::{KeyRenewRequest, renew_session};
use crate::com::handshake::renew_core::{KeyRenewAck, KeyRenewChallenge};
use crate::com::handshake::sensor::tests::helpers::create_controller;
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
    sensor_eph_pubkey: [u8; PUBLIC_KEY_LEN],
    ack_nonce: [u8; 12],
    timestamp: u32,
) -> ([u8; 256], usize) {
    let mut message = MessageSchema::create_body_request(
        sensor_mac,
        80,
        OneDestination(gateway_mac),
        MessageType::KeyRenewAck,
        RequestType::KeyRenewAck(KeyRenewAck::new(sensor_eph_pubkey)),
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

/// Gateway ephemeral pubkey returned by the mock `generate_gateway_ephemeral` callback.
pub(crate) const TEST_GW_EPH_PUBKEY: [u8; PUBLIC_KEY_LEN] = [0x11u8; PUBLIC_KEY_LEN];

/// Sensor ephemeral pubkey returned by the mock `ecdh_ephemeral_with_peer` callback.
pub(crate) const TEST_SENSOR_EPH_PUBKEY: [u8; PUBLIC_KEY_LEN] = [0x22u8; PUBLIC_KEY_LEN];

/// Shared secret returned by both mock ECDH callbacks.
pub(crate) const TEST_EPH_EPH_SHARED_SECRET: [u8; 32] = [0xCCu8; 32];

pub(crate) fn test_generate_gateway_ephemeral() -> Result<[u8; PUBLIC_KEY_LEN], ()> {
    Ok(TEST_GW_EPH_PUBKEY)
}

pub(crate) fn test_ecdh_with_sensor_ephemeral(
    _sensor_eph_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> Result<[u8; 32], ()> {
    Ok(TEST_EPH_EPH_SHARED_SECRET)
}

pub(crate) fn test_ecdh_ephemeral_with_peer(
    _gw_eph_pubkey: &[u8; PUBLIC_KEY_LEN],
) -> Result<([u8; PUBLIC_KEY_LEN], [u8; 32]), ()> {
    Ok((TEST_SENSOR_EPH_PUBKEY, TEST_EPH_EPH_SHARED_SECRET))
}

#[test]
fn key_renew_request_roundtrip_encode() {
    let request = KeyRenewRequest::new([0x55; 32]);
    let mut encoded = [0u8; 64];
    let len = bincode::encode_into_slice(&request, &mut encoded, bincode::config::standard())
        .expect("encode");
    let (decoded, _) = bincode::decode_from_slice::<KeyRenewRequest, _>(
        &encoded[..len],
        bincode::config::standard(),
    )
    .expect("decode");
    assert_eq!(decoded, request);
}

#[test]
fn key_renew_request_encrypted_wire_format() {
    let sensor_nonce = [0x55; 32];
    let (buffer, len) =
        build_key_renew_request_buffer(sensor_mac(), gateway_mac(), sensor_nonce, 1_000);

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
fn key_renew_ack_encrypted_wire_format() {
    let sensor_eph = TEST_SENSOR_EPH_PUBKEY;
    let (buffer, len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        sensor_eph,
        chacha_nonce(),
        1_000,
    );

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
        crate::models::common::BodySchema::RequestType(RequestType::KeyRenewAck(ack)) => {
            assert_eq!(ack.sensor_eph_pubkey_compressed(), &sensor_eph);
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
        TEST_GW_EPH_PUBKEY,
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (ack_buffer, ack_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        TEST_SENSOR_EPH_PUBKEY,
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
        test_generate_gateway_ephemeral,
        test_ecdh_with_sensor_ephemeral,
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
        TEST_GW_EPH_PUBKEY,
        gateway_nonce,
        0u32,
        timestamp,
    );
    let (ack0, ack0_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        TEST_SENSOR_EPH_PUBKEY,
        ack_nonce_for_retry(base_nonce, 0),
        timestamp,
    );
    let (ack1, ack1_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        TEST_SENSOR_EPH_PUBKEY,
        ack_nonce_for_retry(base_nonce, 1),
        timestamp,
    );
    let (ack2, ack2_len) = build_key_renew_ack_buffer(
        sensor_mac(),
        gateway_mac(),
        TEST_SENSOR_EPH_PUBKEY,
        ack_nonce_for_retry(base_nonce, 2),
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
        test_ecdh_ephemeral_with_peer,
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
fn install_challenge_body_is_smaller_than_legacy_ecies_blob() {
    use crate::com::handshake::install_core::HandshakeChallenge;

    let challenge = HandshakeChallenge::new(
        [0x11u8; PUBLIC_KEY_LEN],
        [0x22u8; SIGNATURE_LEN],
        [0x33u8; PUBLIC_KEY_LEN],
        [0xBBu8; 32],
        0u32,
    );
    let mut encoded = [0u8; 256];
    let len = bincode::encode_into_slice(&challenge, &mut encoded, bincode::config::standard())
        .expect("encode");

    assert!(
        len < crate::com::handshake::ECIES_CIPHERTEXT_LEN,
        "structured install challenge {}B vs legacy ECIES blob {}B",
        len,
        crate::com::handshake::ECIES_CIPHERTEXT_LEN
    );
}

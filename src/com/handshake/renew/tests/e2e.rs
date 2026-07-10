//! End-to-end renew tests: sensor and gateway derive the same session key.

use super::{
    build_key_renew_ack_buffer, build_key_renew_challenge_buffer, build_key_renew_request_buffer,
    chacha_nonce, gateway_mac, sensor_mac, session_key, test_ecdh_ephemeral,
    test_ecdh_shared_secret,
};
use crate::com::handshake::renew::gateway::handle_renew_request;
use crate::com::handshake::renew::sensor::{KeyRenewRequest, renew_session};
use crate::com::handshake::sensor::tests::helpers::create_controller;
use crate::com::handshake::{derive_session_key, PUBLIC_KEY_LEN};
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_success, expectations_for_receiver_mode,
    expectations_for_send,
};
use lora::sx1278::{Controller, Mode};

fn ack_nonce_for_retry(base: [u8; 12], tx_index: u8) -> [u8; 12] {
    let mut nonce = base;
    nonce[11] = nonce[11].wrapping_add(tx_index);
    nonce
}

/// Both sides complete the lightweight renew exchange and derive the same session key.
#[test]
fn renew_session_keys_match() {
    let sensor_nonce = [0xAA; 32];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260_691u32;
    let key_expire_at = 1_700_000u32;
    let base_nonce = chacha_nonce();

    let (request_buffer, request_len) =
        build_key_renew_request_buffer(sensor_mac(), gateway_mac(), sensor_nonce, timestamp);
    let (challenge_buffer, challenge_len) = build_key_renew_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        [0x11u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        key_expire_at,
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

    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(
        &request_buffer[..request_len],
        Mode::Manual,
    ));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_receive_success::<256>(
        &challenge_buffer[..challenge_len],
        0x42,
        Mode::Receiver,
    ));
    sensor_exp.extend(expectations_for_send(&ack0[..ack0_len], Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_send(&ack1[..ack1_len], Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_send(&ack2[..ack2_len], Mode::Manual));

    let mut gateway_exp = expectations_for_new(Mode::Manual);
    gateway_exp.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        Mode::Manual,
    ));
    gateway_exp.extend(expectations_for_receiver_mode());
    gateway_exp.extend(expectations_for_receive_success::<256>(
        &ack0[..ack0_len],
        0x42,
        Mode::Receiver,
    ));

    let (mut s_spi, mut s_cs, mut s_rst, mut s_delay) = create_controller(&sensor_exp);
    let (mut g_spi, mut g_cs, mut g_rst, mut g_delay) = create_controller(&gateway_exp);
    let mut sensor_ctrl = Controller::new(
        &mut s_spi,
        &mut s_cs,
        &mut s_rst,
        &mut s_delay,
        Mode::Manual,
    )
    .unwrap();
    let mut gateway_ctrl = Controller::new(
        &mut g_spi,
        &mut g_cs,
        &mut g_rst,
        &mut g_delay,
        Mode::Manual,
    )
    .unwrap();

    let sensor_result = renew_session(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        80,
        gateway_mac(),
        &session_key(),
        &base_nonce,
        sensor_nonce,
        test_ecdh_shared_secret,
        timestamp,
    );

    let request = KeyRenewRequest::new(sensor_nonce);
    let gateway_result = handle_renew_request(
        &request,
        &session_key(),
        &base_nonce,
        test_ecdh_ephemeral,
        &[0u8; PUBLIC_KEY_LEN],
        sensor_mac(),
        gateway_mac(),
        gateway_nonce,
        key_expire_at,
        &mut gateway_ctrl,
        &mut g_delay,
        timestamp,
    );

    assert!(
        sensor_result.is_ok(),
        "renew_session returned: {:?}",
        sensor_result
    );
    assert!(gateway_result.is_ok(), "handle_renew_request returned: {:?}", gateway_result);

    let sensor_session = sensor_result.unwrap();
    let gateway_hr = gateway_result.unwrap();
    let expected_key = derive_session_key(&[0xCCu8; 32], &sensor_nonce, &gateway_nonce);

    assert_eq!(sensor_session.keys.key, expected_key);
    assert_eq!(gateway_hr.session_key, expected_key);
    assert_eq!(sensor_session.keys.expire_at, key_expire_at);
    assert_eq!(gateway_hr.key_expire_at, key_expire_at);
    assert_eq!(sensor_session.gateway_mac, gateway_mac());

    s_spi.done();
    s_cs.done();
    s_rst.done();
    g_spi.done();
    g_cs.done();
    g_rst.done();
}

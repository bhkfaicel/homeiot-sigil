//! End-to-end session resume tests: sensor and gateway derive the same session key.

use super::{
    build_session_resume_challenge_buffer, build_session_resume_confirm_buffer,
    build_session_resume_request_buffer, gateway_mac, sensor_mac,
};
use crate::com::handshake::resume::gateway::handle_resume_request;
use crate::com::handshake::resume::sensor::resume_session;
use crate::com::handshake::resume_core::SessionResumeRequest;
use crate::com::handshake::sensor::tests::helpers::{
    create_controller, test_ecdh_ephemeral_with_peer, test_ecdh_with_sensor_ephemeral,
    test_generate_gateway_ephemeral, TEST_GW_EPH_PUBKEY, TEST_SENSOR_EPH_PUBKEY,
};
use crate::com::handshake::{derive_session_key, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_success, expectations_for_receiver_mode,
    expectations_for_send,
};
use lora::sx1278::{Controller, Mode};

/// Both sides complete session resume and derive the same session key without the old session key.
#[test]
fn resume_session_keys_match() {
    let sensor_nonce = [0xAA; 32];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260_691u32;
    let key_expire_at = 1_700_000u32;

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
        key_expire_at,
        timestamp,
    );
    let (confirm_buffer, confirm_len) = build_session_resume_confirm_buffer(
        sensor_mac(),
        gateway_mac(),
        [0u8; SIGNATURE_LEN],
        TEST_SENSOR_EPH_PUBKEY,
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
    sensor_exp.extend(expectations_for_send(&confirm_buffer[..confirm_len], Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_send(&confirm_buffer[..confirm_len], Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_send(&confirm_buffer[..confirm_len], Mode::Manual));

    let mut gateway_exp = expectations_for_new(Mode::Manual);
    gateway_exp.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        Mode::Manual,
    ));
    gateway_exp.extend(expectations_for_receiver_mode());
    gateway_exp.extend(expectations_for_receive_success::<256>(
        &confirm_buffer[..confirm_len],
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

    let sensor_result = resume_session(
        &mut sensor_ctrl,
        &mut s_delay,
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

    let request = SessionResumeRequest::new(sensor_nonce, [0u8; SIGNATURE_LEN]);
    let gateway_result = handle_resume_request(
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
        key_expire_at,
        &mut gateway_ctrl,
        &mut g_delay,
        timestamp,
    );

    assert!(
        sensor_result.is_ok(),
        "resume_session returned: {:?}",
        sensor_result
    );
    assert!(
        gateway_result.is_ok(),
        "handle_resume_request returned: {:?}",
        gateway_result
    );

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

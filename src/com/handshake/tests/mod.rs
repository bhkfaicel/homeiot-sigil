use crate::com::error::model::ComError;
use crate::com::handshake::{
    CHALLENGE_PLAINTEXT_LEN, ECIES_CIPHERTEXT_LEN, HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN,
    SIGNATURE_LEN,
};
use crate::com::handshake::gateway::handle_handshake_request;
use crate::com::handshake::sensor::{initiate_handshake, HandshakeRequest};
use crate::com::handshake::sensor::tests::helpers::{
    build_handshake_challenge_buffer, build_handshake_confirm_buffer,
    build_handshake_request_buffer, create_controller,
};
use lora::sx1278::tests::common::{
    expectations_for_new, expectations_for_receive_no_packet, expectations_for_receive_success,
    expectations_for_receiver_mode, expectations_for_send,
};
use lora::sx1278::{Controller, Mode};

fn sensor_mac() -> [u8; 17] {
    [67, 56, 58, 67, 53, 58, 68, 55, 58, 48, 49, 58, 54, 50, 58, 50, 51]
}

fn gateway_mac() -> [u8; 17] {
    [26, 56, 58, 67, 53, 58, 06, 55, 58, 48, 49, 58, 54, 91, 58, 50, 51]
}

/// Fake ECIES encrypt: copies plaintext into the first CHALLENGE_PLAINTEXT_LEN bytes of out.
/// Returns a dummy shared secret [0xCC; 32] that matches test_decrypt's return value.
fn test_encrypt(
    _sensor_pubkey: &[u8; PUBLIC_KEY_LEN],
    plaintext: &[u8; CHALLENGE_PLAINTEXT_LEN],
    out: &mut [u8; ECIES_CIPHERTEXT_LEN],
) -> [u8; 32] {
    out[..CHALLENGE_PLAINTEXT_LEN].copy_from_slice(plaintext);
    [0xCCu8; 32]
}

/// Fake ECIES decrypt: reads the first CHALLENGE_PLAINTEXT_LEN bytes of ciphertext as plaintext.
/// Returns the same dummy shared secret [0xCC; 32] so both sides derive the same session key.
fn test_decrypt(
    ciphertext: &[u8; ECIES_CIPHERTEXT_LEN],
    out: &mut [u8; CHALLENGE_PLAINTEXT_LEN],
) -> Result<[u8; 32], ()> {
    out.copy_from_slice(&ciphertext[..CHALLENGE_PLAINTEXT_LEN]);
    Ok([0xCCu8; 32])
}

/// Both sides complete the full 3-step exchange and independently derive the same session key.
#[test]
fn session_keys_match() {
    let battery_level = 80u8;
    let sensor_nonce = [0xAA; 32];
    let sensor_pubkey = [0u8; PUBLIC_KEY_LEN];
    let sig_sensor_pubkey = [0u8; SIGNATURE_LEN];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260691u32;

    let request_buffer = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    // sig_sensor_nonce and gateway_pubkey are all-zero because the gateway callbacks return [0; _]
    let challenge_buffer = build_handshake_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        [0u8; SIGNATURE_LEN],
        [0u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        timestamp,
    );
    // sig_gateway_nonce is all-zero because sign_gateway_nonce callback returns [0; SIGNATURE_LEN]
    let confirm_buffer = build_handshake_confirm_buffer(
        sensor_mac(),
        battery_level,
        gateway_mac(),
        [0u8; SIGNATURE_LEN],
        timestamp,
    );

    // Sensor: send request → receive challenge → send confirm
    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(&request_buffer, Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &challenge_buffer,
        0x42,
        Mode::Receiver,
    ));
    sensor_exp.extend(expectations_for_send(&confirm_buffer, Mode::Manual));

    // Gateway: send challenge → receive confirm
    let mut gateway_exp = expectations_for_new(Mode::Manual);
    gateway_exp.extend(expectations_for_send(&challenge_buffer, Mode::Manual));
    gateway_exp.extend(expectations_for_receiver_mode());
    gateway_exp.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &confirm_buffer,
        0x42,
        Mode::Receiver,
    ));

    let (mut s_spi, mut s_cs, mut s_rst, mut s_delay) = create_controller(&sensor_exp);
    let (mut g_spi, mut g_cs, mut g_rst, mut g_delay) = create_controller(&gateway_exp);
    let mut sensor_ctrl =
        Controller::new(&mut s_spi, &mut s_cs, &mut s_rst, &mut s_delay, Mode::Manual).unwrap();
    let mut gateway_ctrl =
        Controller::new(&mut g_spi, &mut g_cs, &mut g_rst, &mut g_delay, Mode::Manual).unwrap();

    let sensor_result = initiate_handshake(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_decrypt,
        |_pk, _sig| true,
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    let request = HandshakeRequest::new(sensor_nonce, sensor_pubkey, sig_sensor_pubkey);
    let gateway_result = handle_handshake_request(
        &request,
        |_pk, _sig| true,
        test_encrypt,
        sensor_mac(),
        gateway_mac(),
        [0u8; PUBLIC_KEY_LEN],
        [0u8; SIGNATURE_LEN],
        gateway_nonce,
        |_pk, _sig| true,
        &mut gateway_ctrl,
        &mut g_delay,
        timestamp,
    );

    assert!(sensor_result.is_ok());
    assert!(gateway_result.is_ok());
    assert_eq!(sensor_result.unwrap(), gateway_result.unwrap().session_key);
    s_spi.done();
    s_cs.done();
    s_rst.done();
    g_spi.done();
    g_cs.done();
    g_rst.done();
}

/// Gateway rejects the sensor (verify_sensor = false): gateway returns VerificationFailed
/// immediately (no challenge sent), sensor receives nothing and times out.
#[test]
fn gateway_rejects_sensor() {
    let battery_level = 80u8;
    let sensor_nonce = [0xAA; 32];
    let sensor_pubkey = [0u8; PUBLIC_KEY_LEN];
    let sig_sensor_pubkey = [0u8; SIGNATURE_LEN];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260691u32;

    let request_buffer = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );

    // Sensor: sends request, waits, times out (no challenge arrives)
    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(&request_buffer, Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_receive_no_packet(4, Mode::Receiver));

    // Gateway: only initialisation — verify_sensor rejects before any LoRa traffic
    let gateway_exp = expectations_for_new(Mode::Manual);

    let (mut s_spi, mut s_cs, mut s_rst, mut s_delay) = create_controller(&sensor_exp);
    let (mut g_spi, mut g_cs, mut g_rst, mut g_delay) = create_controller(&gateway_exp);
    let mut sensor_ctrl =
        Controller::new(&mut s_spi, &mut s_cs, &mut s_rst, &mut s_delay, Mode::Manual).unwrap();
    let mut gateway_ctrl =
        Controller::new(&mut g_spi, &mut g_cs, &mut g_rst, &mut g_delay, Mode::Manual).unwrap();

    let sensor_result = initiate_handshake(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_decrypt,
        |_pk, _sig| true,
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    let request = HandshakeRequest::new(sensor_nonce, sensor_pubkey, sig_sensor_pubkey);
    let gateway_result = handle_handshake_request(
        &request,
        |_pk, _sig| false, // reject sensor identity
        test_encrypt,
        sensor_mac(),
        gateway_mac(),
        [0u8; PUBLIC_KEY_LEN],
        [0u8; SIGNATURE_LEN],
        gateway_nonce,
        |_pk, _sig| true,
        &mut gateway_ctrl,
        &mut g_delay,
        timestamp,
    );

    assert!(matches!(gateway_result, Err(ComError::VerificationFailed)));
    assert!(matches!(sensor_result, Err(ComError::Timeout)));
    s_spi.done();
    s_cs.done();
    s_rst.done();
    g_spi.done();
    g_cs.done();
    g_rst.done();
}

/// Sensor rejects the gateway (verify_sig_sensor_nonce = false): sensor returns
/// VerificationFailed after receiving the challenge (no confirm sent), gateway times out.
#[test]
fn sensor_rejects_gateway() {
    let battery_level = 80u8;
    let sensor_nonce = [0xAA; 32];
    let sensor_pubkey = [0u8; PUBLIC_KEY_LEN];
    let sig_sensor_pubkey = [0u8; SIGNATURE_LEN];
    let gateway_nonce = [0xBB; 32];
    let timestamp = 260691u32;

    let request_buffer = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    let challenge_buffer = build_handshake_challenge_buffer(
        gateway_mac(),
        sensor_mac(),
        [0u8; SIGNATURE_LEN],
        [0u8; PUBLIC_KEY_LEN],
        gateway_nonce,
        timestamp,
    );
    let confirm_buffer = build_handshake_confirm_buffer(
        sensor_mac(),
        battery_level,
        gateway_mac(),
        [0u8; SIGNATURE_LEN],
        timestamp,
    );

    // Sensor: sends request, receives challenge, then rejects it (no confirm sent)
    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(&request_buffer, Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &challenge_buffer,
        0x42,
        Mode::Receiver,
    ));

    // Gateway: sends challenge, waits for confirm, times out
    let mut gateway_exp = expectations_for_new(Mode::Manual);
    gateway_exp.extend(expectations_for_send(&challenge_buffer, Mode::Manual));
    gateway_exp.extend(expectations_for_receiver_mode());
    gateway_exp.extend(expectations_for_receive_no_packet(4, Mode::Receiver));

    // confirm_buffer is only used to ensure the gateway expectations are consistent —
    // it is never actually received here.
    let _ = confirm_buffer;

    let (mut s_spi, mut s_cs, mut s_rst, mut s_delay) = create_controller(&sensor_exp);
    let (mut g_spi, mut g_cs, mut g_rst, mut g_delay) = create_controller(&gateway_exp);
    let mut sensor_ctrl =
        Controller::new(&mut s_spi, &mut s_cs, &mut s_rst, &mut s_delay, Mode::Manual).unwrap();
    let mut gateway_ctrl =
        Controller::new(&mut g_spi, &mut g_cs, &mut g_rst, &mut g_delay, Mode::Manual).unwrap();

    let sensor_result = initiate_handshake(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_decrypt,
        |_pk, _sig| false, // reject gateway signature
        |_nonce| [0u8; SIGNATURE_LEN],
        timestamp,
    );

    let request = HandshakeRequest::new(sensor_nonce, sensor_pubkey, sig_sensor_pubkey);
    let gateway_result = handle_handshake_request(
        &request,
        |_pk, _sig| true,
        test_encrypt,
        sensor_mac(),
        gateway_mac(),
        [0u8; PUBLIC_KEY_LEN],
        [0u8; SIGNATURE_LEN],
        gateway_nonce,
        |_pk, _sig| true,
        &mut gateway_ctrl,
        &mut g_delay,
        timestamp,
    );

    assert!(matches!(sensor_result, Err(ComError::VerificationFailed)));
    assert!(matches!(gateway_result, Err(ComError::Timeout)));
    s_spi.done();
    s_cs.done();
    s_rst.done();
    g_spi.done();
    g_cs.done();
    g_rst.done();
}

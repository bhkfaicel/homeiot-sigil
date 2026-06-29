use crate::com::error::model::ComError;
use crate::com::handshake::gateway::handle_handshake_request;
use crate::com::handshake::sensor::tests::helpers::{
    build_handshake_challenge_buffer, build_handshake_confirm_buffer,
    build_handshake_request_buffer, create_controller,
    expectations_for_sensor_challenge_listen_timeout,
};
use crate::com::handshake::sensor::{HandshakeRequest, initiate_handshake};
use crate::com::handshake::{
    CHALLENGE_PLAINTEXT_LEN, ECIES_CIPHERTEXT_LEN, GATEWAY_CHALLENGE_RESEND_PERIOD,
    GATEWAY_CONFIRM_RX_TIMEOUT, HANDSHAKE_MESSAGE_MAX, PUBLIC_KEY_LEN, SIGNATURE_LEN,
    decrypt_challenge, encrypt_challenge,
};
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

#[test]
fn gateway_confirm_rx_timeout_is_three_times_previous_default() {
    assert_eq!(GATEWAY_CONFIRM_RX_TIMEOUT, 180);
    assert_eq!(GATEWAY_CHALLENGE_RESEND_PERIOD, 10);
    assert_eq!(
        GATEWAY_CONFIRM_RX_TIMEOUT / GATEWAY_CHALLENGE_RESEND_PERIOD,
        18,
        "challenge re-send rounds during a full timeout window"
    );
}

/// Fake ECIES encrypt: generates a deterministic ECIES ciphertext via `encrypt_challenge`.
/// Returns a dummy shared secret [0xCC; 32] that matches `test_ecdh_shared_secret`.
fn test_encrypt(
    _sensor_pubkey: &[u8; PUBLIC_KEY_LEN],
    plaintext: &[u8; CHALLENGE_PLAINTEXT_LEN],
    out: &mut [u8; ECIES_CIPHERTEXT_LEN],
) -> [u8; 32] {
    let eph_pubkey_compressed = [0x11u8; PUBLIC_KEY_LEN];
    let shared_secret = [0xCCu8; 32];
    let chacha_nonce = [0x22u8; 12];
    encrypt_challenge(
        &eph_pubkey_compressed,
        &shared_secret,
        &chacha_nonce,
        plaintext,
        out,
    )
    .expect("encrypt_challenge");
    shared_secret
}

/// Fake ECIES decrypt: reads the first CHALLENGE_PLAINTEXT_LEN bytes of ciphertext as plaintext.
/// Returns the same dummy shared secret [0xCC; 32] so both sides derive the same session key.
fn test_ecdh_shared_secret(_eph_pubkey_compressed: &[u8; PUBLIC_KEY_LEN]) -> Result<[u8; 32], ()> {
    Ok([0xCCu8; 32])
}

/// Unit test for `decrypt_challenge`: encrypts a plaintext with the same layout and
/// then ensures decryption recovers it and returns the expected shared secret.
#[test]
fn decrypt_challenge_roundtrip() {
    use chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::aead::heapless::Vec as HVec;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Test inputs (fixed values for deterministic behaviour)
    let plaintext = [0xABu8; CHALLENGE_PLAINTEXT_LEN];
    let eph_pubkey_compressed = [0x11u8; PUBLIC_KEY_LEN];
    let shared_secret = [0x22u8; 32];

    // Derive encryption key exactly like decrypt_challenge
    let hkdf = Hkdf::<Sha256>::new(Some(&eph_pubkey_compressed), &shared_secret);
    let mut enc_key = [0u8; 32];
    hkdf.expand(b"ecies-enc", &mut enc_key).expect("hkdf ok");

    // Encrypt plaintext to build ECIES ciphertext
    let chacha_nonce = [0x33u8; 12];

    let cipher = ChaCha20Poly1305::new((&enc_key).into());
    let mut buf: HVec<u8, { CHALLENGE_PLAINTEXT_LEN + 16 }> = HVec::new();
    buf.extend_from_slice(&plaintext).expect("buf extend");
    cipher
        .encrypt_in_place((&chacha_nonce).into(), b"", &mut buf)
        .expect("encrypt ok");

    // Assemble full ciphertext layout
    let mut ciphertext = [0u8; ECIES_CIPHERTEXT_LEN];
    ciphertext[0..PUBLIC_KEY_LEN].copy_from_slice(&eph_pubkey_compressed);
    ciphertext[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 12].copy_from_slice(&chacha_nonce);
    ciphertext[PUBLIC_KEY_LEN + 12..].copy_from_slice(&buf.as_slice());

    // Decrypt using decrypt_challenge with a FECDH that returns the same shared_secret
    let mut out = [0u8; CHALLENGE_PLAINTEXT_LEN];
    let mut ecdh = |_pk: &[u8; PUBLIC_KEY_LEN]| -> Result<[u8; 32], ()> { Ok(shared_secret) };
    let returned_secret =
        decrypt_challenge(&ciphertext, &mut out, &mut ecdh).expect("decrypt_challenge ok");

    assert_eq!(out, plaintext);
    assert_eq!(returned_secret, shared_secret);
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
        timestamp,
    );

    // Sensor: send request → receive challenge → send confirm
    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(
        &request_buffer[..request_len],
        Mode::Manual,
    ));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &challenge_buffer[..challenge_len],
        0x42,
        Mode::Receiver,
    ));
    sensor_exp.extend(expectations_for_send(
        &confirm_buffer[..confirm_len],
        Mode::Manual,
    ));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_send(
        &confirm_buffer[..confirm_len],
        Mode::Manual,
    ));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_send(
        &confirm_buffer[..confirm_len],
        Mode::Manual,
    ));

    // Gateway: send challenge → receive confirm
    let mut gateway_exp = expectations_for_new(Mode::Manual);
    gateway_exp.extend(expectations_for_send(
        &challenge_buffer[..challenge_len],
        Mode::Manual,
    ));
    gateway_exp.extend(expectations_for_receiver_mode());
    gateway_exp.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
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

    let sensor_result = initiate_handshake(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_ecdh_shared_secret,
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
        0u32,
        |_pk, _sig| true,
        &mut gateway_ctrl,
        &mut g_delay,
        timestamp,
    );

    assert!(
        sensor_result.is_ok(),
        "sensor initiate_handshake returned: {:?}",
        sensor_result
    );
    assert!(gateway_result.is_ok());
    let sensor_session = sensor_result.unwrap();
    let sensor_keys = sensor_session.keys;
    let gateway_hr = gateway_result.unwrap();
    assert_eq!(sensor_keys.key, gateway_hr.session_key);
    assert_eq!(sensor_keys.expire_at, gateway_hr.key_expire_at);
    assert_eq!(sensor_session.gateway_mac, gateway_mac());
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

    let (request_buffer, request_len) = build_handshake_request_buffer(
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        timestamp,
    );
    let req = &request_buffer[..request_len];

    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(req, Mode::Manual));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_sensor_challenge_listen_timeout(req));

    // Gateway: only initialisation — verify_sensor rejects before any LoRa traffic
    let gateway_exp = expectations_for_new(Mode::Manual);

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

    let sensor_result = initiate_handshake(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_ecdh_shared_secret,
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
        0u32,
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
        timestamp,
    );

    let mut sensor_exp = expectations_for_new(Mode::Manual);
    sensor_exp.extend(expectations_for_send(
        &request_buffer[..request_len],
        Mode::Manual,
    ));
    sensor_exp.extend(expectations_for_receiver_mode());
    sensor_exp.extend(expectations_for_receive_success::<HANDSHAKE_MESSAGE_MAX>(
        &challenge_buffer[..challenge_len],
        0x42,
        Mode::Receiver,
    ));

    let mut gateway_exp = expectations_for_new(Mode::Manual);
    let challenge_rounds = GATEWAY_CONFIRM_RX_TIMEOUT / GATEWAY_CHALLENGE_RESEND_PERIOD;
    for _ in 0..challenge_rounds {
        gateway_exp.extend(expectations_for_send(
            &challenge_buffer[..challenge_len],
            Mode::Receiver,
        ));
        gateway_exp.extend(expectations_for_receive_no_packet(
            GATEWAY_CHALLENGE_RESEND_PERIOD,
            Mode::Receiver,
        ));
    }

    let _ = (confirm_buffer, confirm_len);

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

    let sensor_result = initiate_handshake(
        &mut sensor_ctrl,
        &mut s_delay,
        sensor_mac(),
        battery_level,
        sensor_nonce,
        sensor_pubkey,
        sig_sensor_pubkey,
        test_ecdh_shared_secret,
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
        0u32,
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

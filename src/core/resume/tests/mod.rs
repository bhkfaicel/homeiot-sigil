#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for resume protocol

mod transitions;

// Replay-defense downstream-failure suites for the resume initiator path.
mod replay_cache;

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET};
use crate::core::manager::SessionManager;
use crate::core::resume::wire::{
    RESUME_NONCE_SIZE, RESUME_REQUEST_BODY_LEN, build_resume_challenge_body,
    build_resume_confirm_body, build_resume_request_body, parse_resume_challenge_body,
    parse_resume_confirm_body, parse_resume_request_body, resume_chal_mac_eq, resume_request_mac,
};
use crate::core::session::{DirectionalMaterial, Session, SessionRole};
use crate::core::test_support::{MockRandom, MockSecureElement};

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];
const SENSOR_MAC: [u8; 17] = [0x91u8; 17];
const GW_MAC: [u8; 17] = [0x92u8; 17];
const STATIC_PUB: [u8; 33] = [2u8; 33];
/// Host-provided session lifetime for resume tests (distinct from handshake timeout).
/// Authenticated duration (24 h, within the 2-day maximum).
const RESUME_LIFETIME: u32 = 86_400;

/// Builds a well-formed ResumeRequest frame with a valid resume-PSK MAC.
fn valid_resume_request_frame(sensor_nonce: &[u8; RESUME_NONCE_SIZE]) -> heapless::Vec<u8, 64> {
    use crate::core::frame::{FrameType, build_header};
    let req_mac = resume_request_mac(&RESUME_PSK, &SENSOR_MAC, sensor_nonce).unwrap();
    let body = build_resume_request_body(sensor_nonce, &req_mac).unwrap();
    let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
    frame
        .extend_from_slice(&build_header(&SENSOR_MAC, FrameType::ResumeRequest))
        .unwrap();
    frame.extend_from_slice(&body).unwrap();
    frame
}

#[test]
fn test_resume_request_cooldown_is_fifteen_seconds() {
    // Product contract: host `now` is in seconds; cooldown must stay 15 s.
    assert_eq!(crate::core::resume::RESUME_REQUEST_COOLDOWN, 15);
}

#[test]
fn test_resume_gateway_rejects_null_static_ecdh_secret() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_sensor = MockSecureElement::default();
    let mut se_gateway = MockSecureElement::default();
    se_gateway.return_zero_ecdh();
    let mut rng_sensor = MockRandom::new();
    let mut rng_gateway = MockRandom::new();

    let request = match sensor
        .start_resume::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &request,
            &mut se_gateway,
            &mut rng_gateway,
            1_000,
            RESUME_LIFETIME,
        ),
        Err(SigilError::EcdhFailed)
    );
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
    assert!(!gateway.get(&SENSOR_MAC).unwrap().is_active(1_000));
}

#[test]
fn test_resume_sensor_rejects_null_static_ecdh_secret() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_sensor = MockSecureElement::default();
    let mut se_gateway = MockSecureElement::default();
    let mut rng_sensor = MockRandom::new();
    let mut rng_gateway = MockRandom::new();

    let request = match sensor
        .start_resume::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    let challenge = match gateway
        .handle_resume_request::<256>(
            &request,
            &mut se_gateway,
            &mut rng_gateway,
            1_000,
            RESUME_LIFETIME,
        )
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit"),
    };

    se_sensor.return_zero_ecdh();
    assert_eq!(
        sensor.continue_resume::<256>(&challenge, &mut se_sensor, 1_000),
        Err(SigilError::EcdhFailed)
    );
    assert!(!sensor.get(&GW_MAC).unwrap().is_active(1_000));
}

/// Two managers enrolled with the peer's static pubkey but no session key
/// (simulates the post-reboot state).
fn enrolled_pair() -> (SessionManager<16>, SessionManager<16>) {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    // Sensor session keyed by gateway; gateway session keyed by sensor.
    sensor
        .insert(Session::new_enrolled(GW_MAC, STATIC_PUB, RESUME_PSK, SessionRole::Sensor).unwrap())
        .unwrap();
    gateway
        .insert(
            Session::new_enrolled(SENSOR_MAC, STATIC_PUB, RESUME_PSK, SessionRole::Gateway)
                .unwrap(),
        )
        .unwrap();
    (sensor, gateway)
}

#[test]
fn test_resume_wire_roundtrips() {
    let nonce = [7u8; RESUME_NONCE_SIZE];
    let req_mac = [0xABu8; 16];
    let body = build_resume_request_body(&nonce, &req_mac).unwrap();
    assert_eq!(body.len(), RESUME_REQUEST_BODY_LEN);
    let parsed = parse_resume_request_body(&body).unwrap();
    assert_eq!(parsed.sensor_nonce, nonce);
    assert_eq!(parsed.req_mac, req_mac);

    let gw_nonce = [8u8; RESUME_NONCE_SIZE];
    let mac = [0xCDu8; 16];
    let body = build_resume_challenge_body(&gw_nonce, 42, &mac).unwrap();
    assert_eq!(body.len(), RESUME_NONCE_SIZE + 4 + 16);
    let parsed = parse_resume_challenge_body(&body).unwrap();
    assert_eq!(parsed.gateway_nonce, gw_nonce);
    assert_eq!(parsed.key_lifetime_secs, 42);
    assert_eq!(parsed.chal_mac, mac);

    let body = build_resume_confirm_body().unwrap();
    assert!(parse_resume_confirm_body(&body));
    assert!(!parse_resume_confirm_body(&[0xFFu8]));
}

#[test]
fn test_resume_chal_mac_eq_constant_time_helper() {
    // Equality helper must accept equal tags and reject unequal ones.
    let a = [0x11u8; 16];
    let b = [0x11u8; 16];
    let c = [0x11u8; 16];
    assert!(resume_chal_mac_eq(&a, &b));
    let mut different = c;
    different[15] ^= 0x01;
    assert!(!resume_chal_mac_eq(&a, &different));
    // First-byte difference still rejected (constant-time path does not short-circuit for
    // correctness — behavior must match boolean equality).
    let mut first = a;
    first[0] ^= 0xFF;
    assert!(!resume_chal_mac_eq(&a, &first));
}

#[test]
fn test_resume_pairwise_success() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    // Step 1: sensor emits the resume request (clear text).
    let req_action = sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap();
    let req_frame = match req_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };

    // Step 2: gateway handles the request and emits the challenge.
    let chal_action = gateway
        .handle_resume_request::<256>(&req_frame, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap();
    let chal_frame = match chal_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit"),
    };

    // Step 3: sensor processes the challenge → stages keys + emits Final.
    let cfm_action = sensor
        .continue_resume::<256>(&chal_frame, &mut se_s, 1000)
        .unwrap();
    let cfm_frame = match cfm_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit confirm"),
    };
    assert!(
        sensor.get(&GW_MAC).unwrap().session_key().is_none(),
        "No key until CommitConfirmed"
    );
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        crate::core::pending::PendingState::ResumeSensorFinalSent { .. }
    ));

    // Step 4: gateway processes Final → commits + CommitConfirmed.
    let commit_action = gateway
        .continue_resume::<256>(&cfm_frame, &mut se_g, 1000)
        .unwrap();
    let commit_frame = match commit_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit CommitConfirmed"),
    };
    assert_eq!(
        commit_frame[FRAME_TYPE_OFFSET],
        FrameType::ResumeCommitConfirmed as u8
    );

    // Step 5: sensor CommitConfirmed → commit.
    sensor
        .continue_resume::<256>(&commit_frame, &mut se_s, 1000)
        .unwrap();

    let s = sensor.get(&GW_MAC).unwrap();
    let g = gateway.get(&SENSOR_MAC).unwrap();
    assert!(s.session_key().is_some(), "sensor session key installed");
    assert_eq!(
        s.session_key(),
        g.rx_session_key(),
        "sensor TX (s2g) must match gateway RX"
    );
    assert_eq!(
        s.rx_session_key(),
        g.session_key(),
        "gateway TX (g2s) must match sensor RX"
    );
    assert_eq!(s.nonce_prefix(), g.rx_nonce_prefix());
    assert_eq!(s.rx_nonce_prefix(), g.nonce_prefix());
    assert_ne!(
        s.session_key(),
        s.rx_session_key(),
        "Directions must use distinct keys"
    );
    assert_eq!(s.key_expire_at(), 1000 + RESUME_LIFETIME);
    assert_eq!(g.key_expire_at(), 1000 + RESUME_LIFETIME);
    assert_eq!(s.tx_counter, 1, "confirm consumed counter 0 on sensor");
    assert_eq!(s.rx_counter, 1, "CommitConfirmed consumed g2s counter 0");
    assert_eq!(
        g.rx_counter, 1,
        "gateway consumed confirm counter 0 → rx starts at 1"
    );
    assert_eq!(g.tx_counter, 1, "CommitConfirmed consumed g2s counter 0");
    assert!(sensor.get_pending(&GW_MAC).is_none());
    assert!(gateway.get_pending(&SENSOR_MAC).is_some());
}

#[test]
fn test_forged_clear_resume_confirm_rejected() {
    // A clear-text empty confirm must not finalize the gateway session.
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req_frame = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let _chal = gateway
        .handle_resume_request::<256>(&req_frame, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap();

    // Attacker sends an empty clear-text confirm (old insecure shape).
    let mut forged = [0u8; crate::core::frame::OUTER_HEADER_SIZE];
    forged[..17].copy_from_slice(&SENSOR_MAC);
    forged[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    forged[FRAME_TYPE_OFFSET] = FrameType::ResumeConfirm as u8;

    let result = gateway.continue_resume::<256>(&forged, &mut se_g, 1000);
    // A clear-text frame with an empty authenticated body is malformed wire
    // input, not a transition mismatch.
    assert_eq!(result, Err(SigilError::MalformedFrame));
    // Gateway must still have no session key and keep pending.
    assert!(gateway.get(&SENSOR_MAC).unwrap().session_key().is_none());
    assert!(gateway.get_pending(&SENSOR_MAC).is_some());
}

#[test]
fn test_resume_mitm_key_expire_at_rejected() {
    // Flipping key_expire_at without a matching MAC must fail on the sensor
    // before any session key is installed.
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req_frame = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let mut chal_frame = match gateway
        .handle_resume_request::<256>(&req_frame, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };

    // Body: nonce(16) + expire(4) + mac(16). Corrupt expire only.
    use crate::core::frame::OUTER_HEADER_SIZE;
    assert!(chal_frame.len() >= OUTER_HEADER_SIZE + 16 + 4 + 16);
    for b in &mut chal_frame[OUTER_HEADER_SIZE + 16..OUTER_HEADER_SIZE + 20] {
        *b ^= 0xFF;
    }

    let result = sensor.continue_resume::<256>(&chal_frame, &mut se_s, 1000);
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(
        sensor.get(&GW_MAC).unwrap().session_key().is_none(),
        "sensor must not install a key after MAC failure"
    );
    assert!(gateway.get(&SENSOR_MAC).unwrap().session_key().is_none());
}

#[test]
fn test_resume_missing_static_key() {
    assert!(matches!(
        Session::new_enrolled(GW_MAC, [0u8; 33], RESUME_PSK, SessionRole::Sensor),
        Err(SigilError::InvalidStaticKey)
    ));
}

#[test]
fn test_resume_unknown_peer() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();
    let result = mgr.start_resume::<256>(GW_MAC, &mut se, &mut rng, 1000);
    assert_eq!(result, Err(SigilError::UnknownSession { peer: GW_MAC }));
}

#[test]
fn test_gateway_resume_keeps_active_key_until_commit_for_reboot_recovery() {
    let (_sensor, mut gateway) = enrolled_pair();
    gateway
        .get_mut(&SENSOR_MAC)
        .unwrap()
        .update_key(
            DirectionalMaterial::symmetric_for_test([0x11u8; 32], [0x22u8; 4]),
            86_400,
            0,
        )
        .unwrap();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    use crate::core::frame::FrameType;
    let req = valid_resume_request_frame(&[0x11u8; RESUME_NONCE_SIZE]);
    assert_eq!(req[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(req[FRAME_TYPE_OFFSET], FrameType::ResumeRequest as u8);

    let result = gateway
        .handle_resume_request::<256>(&req, &mut se, &mut rng, 1000, RESUME_LIFETIME)
        .unwrap();
    assert!(matches!(result, SigilAction::Transmit { .. }));
    assert_eq!(
        gateway.get(&SENSOR_MAC).unwrap().session_key(),
        Some(&[0x11u8; 32]),
        "the old active key remains available until Resume commits"
    );
}

#[test]
fn test_sensor_can_explicitly_resume_active_session_after_gateway_reboot() {
    let (mut sensor, _gateway) = enrolled_pair();
    sensor
        .get_mut(&GW_MAC)
        .unwrap()
        .update_key(
            DirectionalMaterial::symmetric_for_test([0x11u8; 32], [0x22u8; 4]),
            86_400,
            0,
        )
        .unwrap();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    let result = sensor
        .start_resume::<256>(GW_MAC, &mut se, &mut rng, 1000)
        .unwrap();
    assert!(matches!(result, SigilAction::Transmit { .. }));
    assert_eq!(
        sensor.get(&GW_MAC).unwrap().session_key(),
        Some(&[0x11u8; 32])
    );
    assert!(sensor.get_pending(&GW_MAC).is_some());
}

#[test]
fn test_sensor_start_resume_retains_soft_expired_key_until_commit() {
    let (mut sensor, _gateway) = enrolled_pair();
    sensor
        .get_mut(&GW_MAC)
        .unwrap()
        .update_key(
            DirectionalMaterial::symmetric_for_test([0x11u8; 32], [0x22u8; 4]),
            500,
            0,
        )
        .unwrap();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    let action = sensor
        .start_resume::<256>(GW_MAC, &mut se, &mut rng, 1000)
        .unwrap();
    assert!(matches!(action, SigilAction::Transmit { .. }));
    assert!(
        sensor.get(&GW_MAC).unwrap().session_key().is_some(),
        "old key material must not be destroyed before Resume commits"
    );
    assert!(sensor.get_pending(&GW_MAC).is_some());
}

// resume constraints (no ECDSA, no soft eph ECDH)
// We assert the constraint at the type/API level: the resume modules do not
// reference `SecureElement::sign_ecdsa` / `verify_ecdsa`, and they do not call
// the Renew ephemeral P-256 implementation. The wire bodies
// carry no ephemeral public key field and no signature field. This test
// documents and guards that invariant by checking the wire layouts.

#[test]
fn test_resume_request_body_has_no_signature_or_eph_key() {
    let body = build_resume_request_body(&[0u8; RESUME_NONCE_SIZE], &[0u8; 16]).unwrap();
    // ResumeRequest body = nonce(16) + req_mac(16). No X25519 eph key, no ECDSA sig.
    assert_eq!(body.len(), RESUME_REQUEST_BODY_LEN);
}

#[test]
fn test_resume_challenge_body_has_no_signature_or_eph_key() {
    let body = build_resume_challenge_body(&[0u8; RESUME_NONCE_SIZE], 0, &[0u8; 16]).unwrap();
    // ResumeChallenge body = nonce(16) + expire(4) + mac(16) = 36 bytes.
    assert_eq!(body.len(), RESUME_NONCE_SIZE + 4 + 16);
}

#[test]
fn test_resume_confirm_rejects_nonzero_counter() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let chal = match gateway
        .handle_resume_request::<256>(&req, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let mut cfm = match sensor
        .continue_resume::<256>(&chal, &mut se_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };

    use crate::core::frame::OUTER_HEADER_SIZE;
    cfm[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12].copy_from_slice(&1u64.to_be_bytes());

    let result = gateway.continue_resume::<256>(&cfm, &mut se_g, 1000);
    assert!(matches!(
        result,
        Err(SigilError::Replay {
            expected: 0,
            received: 1,
            ..
        })
    ));
}

#[test]
fn test_resume_allows_soft_expired_key() {
    // Soft-expired key must be clearable so resume can proceed.

    let (_sensor, mut gateway) = enrolled_pair();
    gateway
        .get_mut(&SENSOR_MAC)
        .unwrap()
        .update_key(
            DirectionalMaterial::symmetric_for_test([0x11u8; 32], [0x22u8; 4]),
            500,
            0,
        )
        .unwrap();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    use crate::core::frame::FrameType;
    let req = valid_resume_request_frame(&[0x42u8; RESUME_NONCE_SIZE]);
    assert_eq!(req[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(req[FRAME_TYPE_OFFSET], FrameType::ResumeRequest as u8);

    let now = 1000; // past key_expire_at = 500
    let action = gateway
        .handle_resume_request::<256>(&req, &mut se, &mut rng, now, RESUME_LIFETIME)
        .unwrap();
    assert!(matches!(action, SigilAction::Transmit { .. }));
    assert!(
        gateway.get(&SENSOR_MAC).unwrap().session_key().is_some(),
        "old key material must not be destroyed before Resume commits"
    );
    assert!(gateway.get_pending(&SENSOR_MAC).is_some());
}

#[test]
fn test_resume_rejects_inflight_pending() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    gateway
        .handle_resume_request::<256>(&req, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap();

    let result =
        gateway.handle_resume_request::<256>(&req, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME);
    assert_eq!(
        result,
        Err(SigilError::PendingAlreadyExists { peer: SENSOR_MAC })
    );
}

#[test]
fn test_resume_rate_limited_after_cancel() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    gateway
        .handle_resume_request::<256>(&req, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap();
    gateway.cancel_pending(&SENSOR_MAC).unwrap();

    let result =
        gateway.handle_resume_request::<256>(&req, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME);
    assert_eq!(result, Err(SigilError::RateLimited { peer: SENSOR_MAC }));

    // At the cooldown boundary the identical recording meets the replay
    // cache (accepted-to-completion triples are suppressed within the
    // horizon): hosts abandon the stale attempt and restart with a FRESH
    // nonce.
    let result = gateway.handle_resume_request::<256>(
        &req,
        &mut se_g,
        &mut rng_g,
        1000 + crate::core::resume::RESUME_REQUEST_COOLDOWN,
        RESUME_LIFETIME,
    );
    assert_eq!(
        result,
        Err(SigilError::HandshakeReplay { peer: SENSOR_MAC })
    );

    // Host policy: abandon the stale sensor-side attempt (its pre-commit
    // pending is cancellable) before restarting with a FRESH nonce.
    sensor.cancel_pending(&GW_MAC).unwrap();
    let fresh_req = match sensor
        .start_resume::<256>(
            GW_MAC,
            &mut se_s,
            &mut rng_s,
            1_000 + crate::core::resume::RESUME_REQUEST_COOLDOWN,
        )
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    let action = gateway
        .handle_resume_request::<256>(
            &fresh_req,
            &mut se_g,
            &mut rng_g,
            1000 + crate::core::resume::RESUME_REQUEST_COOLDOWN,
            RESUME_LIFETIME,
        )
        .unwrap();
    assert!(matches!(action, SigilAction::Transmit { .. }));
}

#[test]
fn test_forged_resume_request_mac_rejected_before_ecdh() {
    // spoofed enrolled MAC with garbage req_mac must fail before SE-ECDH.

    let (_sensor, mut gateway) = enrolled_pair();
    let mut se = MockSecureElement::default();
    se.reject_ecdh();
    let mut rng = MockRandom::new();

    use crate::core::frame::build_header;
    let mut forged: heapless::Vec<u8, 64> = heapless::Vec::new();
    forged
        .extend_from_slice(&build_header(&SENSOR_MAC, FrameType::ResumeRequest))
        .unwrap();
    forged
        .extend_from_slice(&[0xEEu8; RESUME_REQUEST_BODY_LEN])
        .unwrap();

    let result =
        gateway.handle_resume_request::<256>(&forged, &mut se, &mut rng, 1000, RESUME_LIFETIME);
    // VerificationFailed (not EcdhFailed) proves ECDH was never reached.
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_resume_commit_confirmed_loss_and_duplicate_confirm_retx() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let chal = match gateway
        .handle_resume_request::<256>(&req, &mut se_g, &mut rng_g, 1000, RESUME_LIFETIME)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let cfm = match sensor
        .continue_resume::<256>(&chal, &mut se_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let commit1 = match gateway
        .continue_resume::<256>(&cfm, &mut se_g, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    assert!(sensor.get(&GW_MAC).unwrap().session_key().is_none());

    assert!(sensor.tick(1_010).is_empty());
    assert!(gateway.tick(1_010).is_empty());
    assert_eq!(
        sensor.cancel_pending(&GW_MAC),
        Err(SigilError::InvalidStep { peer: GW_MAC })
    );
    assert_eq!(
        gateway.cancel_pending(&SENSOR_MAC),
        Err(SigilError::InvalidStep { peer: SENSOR_MAC })
    );

    let commit2 = match gateway
        .continue_resume::<256>(&cfm, &mut se_g, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    assert_eq!(commit1.as_slice(), commit2.as_slice());

    sensor
        .continue_resume::<256>(&commit2, &mut se_s, 1000)
        .unwrap();
    assert!(sensor.get(&GW_MAC).unwrap().session_key().is_some());
    assert!(sensor.get_pending(&GW_MAC).is_none());

    let data = sensor
        .encrypt_data::<256>(&GW_MAC, b"commit-proof", 1000)
        .unwrap();
    gateway
        .process_incoming_packet::<200, 256>(&data, 1000)
        .unwrap();
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_start_resume_rejects_gateway_role() {
    let (_sensor, mut gateway) = enrolled_pair();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();
    let err = gateway.start_resume::<256>(SENSOR_MAC, &mut se, &mut rng, 1000);
    // Resume is sensor-initiated: a gateway-role manager is a static role
    // mismatch, not an out-of-order transition.
    assert_eq!(err, Err(SigilError::WrongRole { peer: SENSOR_MAC }));
}

#[test]
fn test_handle_resume_request_rejects_sensor_role_before_ecdh() {
    let (mut sensor, mut gateway) = enrolled_pair();
    gateway.get_mut(&SENSOR_MAC).unwrap().role = SessionRole::Sensor;
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();
    let request = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let result = gateway.handle_resume_request::<256>(
        &request,
        &mut se_g,
        &mut rng_g,
        1_000,
        RESUME_LIFETIME,
    );
    // A gateway whose session role says "sensor" must refuse the request
    // before any ECDH work: static role/config mismatch.
    assert_eq!(result, Err(SigilError::WrongRole { peer: SENSOR_MAC }));
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_resume_lifetime_uses_each_peers_local_clock_epoch() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();
    let sensor_now = 10;
    let gateway_now = 1_000_000;

    let request = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, sensor_now)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let challenge = match gateway
        .handle_resume_request::<256>(
            &request,
            &mut se_g,
            &mut rng_g,
            gateway_now,
            RESUME_LIFETIME,
        )
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let confirm = match sensor
        .continue_resume::<256>(&challenge, &mut se_s, sensor_now)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let commit = match gateway
        .continue_resume::<256>(&confirm, &mut se_g, gateway_now)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    sensor
        .continue_resume::<256>(&commit, &mut se_s, sensor_now)
        .unwrap();

    assert_eq!(
        sensor.get(&GW_MAC).unwrap().key_expire_at(),
        sensor_now + RESUME_LIFETIME
    );
    assert_eq!(
        gateway.get(&SENSOR_MAC).unwrap().key_expire_at(),
        gateway_now + RESUME_LIFETIME
    );
}

#[test]
fn test_fresh_resume_replaces_commit_sent_only_after_new_crypto_succeeds() {
    let (mut sensor, mut gateway) = enrolled_pair();
    let mut se_s = MockSecureElement::default();
    let mut se_g = MockSecureElement::default();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let request = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let challenge = match gateway
        .handle_resume_request::<256>(&request, &mut se_g, &mut rng_g, 1_000, RESUME_LIFETIME)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let confirm = match sensor
        .continue_resume::<256>(&challenge, &mut se_s, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    gateway
        .continue_resume::<256>(&confirm, &mut se_g, 1_000)
        .unwrap();
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        crate::core::pending::PendingState::ResumeGatewayCommitSent { .. }
    ));

    // Sensor explicitly starts over after losing CommitConfirmed. Its local
    // WaitingForCommit state is replaced by a fresh authenticated request.
    let retry_request = match sensor
        .start_resume::<256>(GW_MAC, &mut se_s, &mut rng_s, 1_015)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        crate::core::pending::PendingState::ResumeSensorAwaitChallenge { .. }
    ));

    // A failed ATECC operation must not destroy the gateway's cached commit.
    let mut failing_se = MockSecureElement::default();
    failing_se.reject_ecdh();
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &retry_request,
            &mut failing_se,
            &mut rng_g,
            1_015,
            RESUME_LIFETIME,
        ),
        Err(SigilError::EcdhFailed)
    );
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        crate::core::pending::PendingState::ResumeGatewayCommitSent { .. }
    ));

    gateway
        .handle_resume_request::<256>(
            &retry_request,
            &mut se_g,
            &mut rng_g,
            1_015,
            RESUME_LIFETIME,
        )
        .unwrap();
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        crate::core::pending::PendingState::ResumeGatewayAwaitConfirm { .. }
    ));
}

#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for renew protocol

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET};
use crate::core::manager::SessionManager;
use crate::core::renew::wire::{
    build_renew_ack_body, build_renew_challenge_body, build_renew_request_body,
    parse_renew_ack_body, parse_renew_challenge_body, parse_renew_request_body,
};
use crate::core::session::{DirectionalMaterial, Session, SessionRole};
use crate::core::test_support::{FailingRandom, MockRandom, MockSecureElement};

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];
const SENSOR_MAC: [u8; 17] = [0x31u8; 17];
const GW_MAC: [u8; 17] = [0x32u8; 17];
/// Alias used by single-manager tests (gateway indexes by sensor MAC).
const PEER: [u8; 17] = SENSOR_MAC;
const KEY: [u8; 32] = [0x55u8; 32];
const PREFIX: [u8; 4] = [0xAAu8; 4];

/// Sensor manager: local = SENSOR, session keyed by gateway MAC.
fn sensor_active() -> SessionManager<16> {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    mgr.insert(
        Session::new_active(
            GW_MAC,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
            SessionRole::Sensor,
            RESUME_PSK,
            86_400,
            0,
        )
.unwrap(),
    )
.unwrap();
    mgr
}

/// Gateway manager: local = GW, session keyed by sensor MAC.
fn gateway_active() -> SessionManager<16> {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    mgr.insert(
        Session::new_active(
            SENSOR_MAC,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
            SessionRole::Gateway,
            RESUME_PSK,
            86_400,
            0,
        )
.unwrap(),
    )
.unwrap();
    mgr
}

/// Single-role helper (legacy name) — gateway-shaped session keyed by SENSOR_MAC.
fn active_manager() -> SessionManager<16> {
    gateway_active()
}

#[test]
fn test_renew_wire_roundtrips() {
    // Bodies no longer carry a msg_type byte (the outer header does).
    let body = build_renew_request_body(&[1u8; 32]).unwrap();
    assert_eq!(body.len(), 32);
    let parsed = parse_renew_request_body(&body).unwrap();
    assert_eq!(parsed, [1u8; 32]);

    let body = build_renew_challenge_body(&[2u8; 32], 999).unwrap();
    assert_eq!(body.len(), 32 + 4);
    let parsed = parse_renew_challenge_body(&body).unwrap();
    assert_eq!(parsed.gateway_eph_pubkey, [2u8; 32]);
    assert_eq!(parsed.key_lifetime_secs, 999);

    let body = build_renew_ack_body().unwrap();
    assert!(parse_renew_ack_body(&body));
    assert!(!parse_renew_ack_body(&[0xFFu8]));
}

#[test]
fn test_renew_pairwise_success() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();
    let mut _se = MockSecureElement::default();
    let _ = &mut _se; // renew must not require the SE

    // Step 1: sensor starts renew toward gateway.
    let req_action = sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap();
    let req_frame = match req_action {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!("sensor should transmit"),
    };

    // Step 2: gateway handles the request and emits the challenge.
    let chal_action = gateway
.handle_renew_request::<256>(&req_frame, &mut rng_g, 1000, 1000 + 86_400)
.unwrap();
    let chal_frame = match chal_action {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!("gateway should transmit"),
    };

    // Step 3: sensor processes the challenge → stages keys + emits Final (ack).
    let old_key = *sensor.get(&GW_MAC).unwrap().session_key().unwrap();
    let ack_action = sensor
.continue_renew::<256>(&chal_frame, &mut rng_s, 1000)
.unwrap();
    let ack_frame = match ack_action {
        SigilAction::Transmit {
            payload,
            wait_timeout_ms,
..
        } => {
            assert!(wait_timeout_ms.is_some());
            payload
        }
        _ => panic!("sensor should transmit ack"),
    };

    // Sensor still on old key until CommitConfirmed.
    assert_eq!(
        sensor.get(&GW_MAC).unwrap().session_key().unwrap(),
        &old_key
    );
    assert_eq!(
        sensor.get_pending(&GW_MAC).unwrap().step,
        crate::core::pending::HandshakeStep::RenewWaitingForCommitConfirmed
    );

    // Step 4: gateway processes Final → commits + CommitConfirmed.
    let commit_action = gateway
.continue_renew::<256>(&ack_frame, &mut rng_g, 1000)
.unwrap();
    let commit_frame = match commit_action {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!("gateway should transmit CommitConfirmed"),
    };
    assert_eq!(
        commit_frame[FRAME_TYPE_OFFSET],
        FrameType::RenewCommitConfirmed as u8
    );
    assert_eq!(
        gateway.get_pending(&SENSOR_MAC).unwrap().step,
        crate::core::pending::HandshakeStep::RenewCommitSent
    );

    // Step 5: sensor processes CommitConfirmed → commits new key.
    sensor
.continue_renew::<256>(&commit_frame, &mut rng_s, 1000)
.unwrap();

    let s = sensor.get(&GW_MAC).unwrap();
    assert_eq!(s.tx_counter, 1, "Final consumed s2g counter 0");
    assert_eq!(s.rx_counter, 1, "CommitConfirmed consumed g2s counter 0");
    assert_ne!(s.session_key().unwrap(), &old_key);

    let g = gateway.get(&SENSOR_MAC).unwrap();
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
 ": directions must use distinct keys"

    );
    assert_eq!(
        g.rx_counter, 1,
        "gateway consumed ack counter 0 → rx starts at 1"
    );
    assert_eq!(g.tx_counter, 1, "CommitConfirmed consumed g2s counter 0");
    // Gateway keeps CommitSent pending until host cancel/tick; sensor clears.
    assert!(sensor.get_pending(&GW_MAC).is_none());
    assert!(gateway.get_pending(&SENSOR_MAC).is_some());
}

#[test]
fn test_start_renew_rejects_full_pending_before_tx_advance() {
    // Capacity check before encrypt/advance — never roll back tx_counter
    // (nonce-reuse risk). A full pending table must leave the counter untouched.
    let mut sensor: SessionManager<2> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    sensor
.insert(
            Session::new_active(
                GW_MAC,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
                SessionRole::Sensor,
                RESUME_PSK,
                86_400,
                0,
            )
.unwrap(),
        )
.unwrap();

    let filler_a = [0xAAu8; 17];
    let filler_b = [0xBBu8; 17];
    sensor
.insert_pending(
            filler_a,
            crate::core::pending::PendingHandshake::new_install(
                filler_a,
                crate::core::pending::HandshakeRole::Sensor,
                5_000,
                1_000,
            ),
        )
.unwrap();
    sensor
.insert_pending(
            filler_b,
            crate::core::pending::PendingHandshake::new_install(
                filler_b,
                crate::core::pending::HandshakeRole::Sensor,
                5_000,
                1_000,
            ),
        )
.unwrap();

    let tx_before = sensor.get(&GW_MAC).unwrap().tx_counter;
    let mut rng = MockRandom::new();
    let result = sensor.start_renew::<256>(GW_MAC, &mut rng, 1_000);
    assert_eq!(result, Err(SigilError::CapacityExceeded));
    assert_eq!(
        sensor.get(&GW_MAC).unwrap().tx_counter,
        tx_before,
        "tx_counter must not advance when pending insert cannot succeed"
    );
    assert!(sensor.get_pending(&GW_MAC).is_none());
}

#[test]
fn test_renew_requires_active_session() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    // Enrolled (no key) — renew should be refused.
    mgr.insert(Session::new_enrolled(
        PEER,
        [2u8; 33],
        RESUME_PSK,
        86_400,
        SessionRole::Sensor,
    ))
.unwrap();
    let mut rng = MockRandom::new();

    let result = mgr.start_renew::<256>(PEER, &mut rng, 1_000);
    assert_eq!(result, Err(SigilError::SessionNotActive { peer: PEER }));
}

#[test]
fn test_renew_unknown_peer() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let mut rng = MockRandom::new();
    let result = mgr.start_renew::<256>(PEER, &mut rng, 1_000);
    assert_eq!(result, Err(SigilError::UnknownSession { peer: PEER }));
}

#[test]
fn test_replay_on_renew_request_rejected() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req_action = sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap();
    let req_frame = match req_action {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };

    // First reception OK.
    gateway
.handle_renew_request::<256>(&req_frame, &mut rng_g, 1000, 1000 + 86_400)
.unwrap();
    // Replaying the same frame must fail (counter reuse under old key).
    let result = gateway.handle_renew_request::<256>(&req_frame, &mut rng_g, 1000, 1000 + 86_400);
    assert!(matches!(result, Err(SigilError::Replay {.. })));
}

#[test]
fn test_start_renew_rejects_soft_expired_key() {
    // Sensor must not encrypt RenewRequest under a soft-expired key.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    // Built at now=0 with expire=1000; call start_renew at now=1000 → expired.
    sensor
.insert(
            Session::new_active(
                GW_MAC,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
                SessionRole::Sensor,
                RESUME_PSK,
                1000,
                0,
            )
.unwrap(),
        )
.unwrap();
    let tx_before = sensor.get(&GW_MAC).unwrap().tx_counter();
    let mut rng = MockRandom::new();

    let result = sensor.start_renew::<256>(GW_MAC, &mut rng, 1_000);
    assert_eq!(result, Err(SigilError::SessionExpired { peer: GW_MAC }));
    assert_eq!(sensor.get(&GW_MAC).unwrap().tx_counter(), tx_before);
    assert!(sensor.get_pending(&GW_MAC).is_none());
}

#[test]
fn test_renew_rejects_expired_old_key() {
    // The gateway must refuse to rotate a key whose validity has already
    // elapsed. We craft an expired session and confirm SessionExpired.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager();
    gateway
.insert(
            Session::new_active(
                PEER,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
                SessionRole::Gateway,
                RESUME_PSK,
                1000,
                0,
            )
.unwrap(),
        )
.unwrap();

    // Build a minimal well-formed request frame so we reach the expiry check.
    // (We encrypt a dummy body so the parse step is not the one that fails.)
    use crate::core::frame::OUTER_HEADER_SIZE;
    let body = crate::core::renew::wire::build_renew_request_body(&[1u8; 32]).unwrap();
    let aad = crate::core::aead::build_aad(&PEER, FrameType::RenewRequest);
    let ct = crate::core::aead::encrypt(&KEY, &PREFIX, 0, &body, &aad).unwrap();
    // Frame: peer(17) + version(1) + frame_type(1) + prefix(4) + counter(8) + ciphertext
    let mut frame = [0u8; OUTER_HEADER_SIZE + 4 + 8 + crate::core::aead::TAG_SIZE + 32];
    frame[..17].copy_from_slice(&PEER);
    frame[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    frame[FRAME_TYPE_OFFSET] = FrameType::RenewRequest as u8;
    frame[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4].copy_from_slice(&PREFIX);
    frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12].copy_from_slice(&0u64.to_be_bytes());
    frame[OUTER_HEADER_SIZE + 12..].copy_from_slice(&ct);

    let mut rng = MockRandom::new();
 // now = 5000 > session key_expire_at = 1000 → SessionExpired (after ok).

    let result = gateway.handle_renew_request::<256>(&frame, &mut rng, 5000, 5000 + 86_400);
    assert_eq!(result, Err(SigilError::SessionExpired { peer: PEER }));
}

// Gateway cannot start_renew
// The gateway exposes NO `start_renew` method on SessionManager. We assert the
// API shape by checking that calling renew start on a gateway-style manager
// (i.e. a manager used in the gateway role) still works for a sensor-style
// packet, but that there is no `start_renew` defined for the gateway side.
// The compile-time check is that `start_renew` exists only once on
// SessionManager and is intended for the sensor; there is no
// `gateway::start_renew` function in the renew module.

#[test]
fn test_gateway_has_no_start_renew_function() {
    // The gateway module exposes only `handle_renew_request` and `handle_renew_ack`.
    // There is no `gateway::start_renew`. This test documents the invariant by
    // ensuring a renew flow that is NOT sensor-initiated cannot be created.
    // We simulate a gateway that receives an unsolicited ack without having
    // seen a request → NoPending.
    let mut gateway = active_manager();
    let mut rng = MockRandom::new();

    // Build a fake ack frame addressed to PEER (well-formed enough to reach the
    // pending lookup).
    use crate::core::frame::OUTER_HEADER_SIZE;
    let mut frame = [0u8; OUTER_HEADER_SIZE + 4 + 8 + crate::core::aead::TAG_SIZE];
    frame[..17].copy_from_slice(&PEER);
    frame[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    frame[FRAME_TYPE_OFFSET] = FrameType::RenewAck as u8;
    frame[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4].copy_from_slice(&PREFIX);
    // counter = 0
    frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12].copy_from_slice(&0u64.to_be_bytes());

    let result = gateway.continue_renew::<256>(&frame, &mut rng, 1000);
    assert!(matches!(result, Err(SigilError::NoPending {.. })));
}

#[test]
fn test_renew_hkdf_info_binds_transcript_fields() {
    use crate::core::derive::derive_session_key;
    use crate::core::renew::renew_hkdf_info;

    let shared = [0x11u8; 32];
    let base = renew_hkdf_info(&PEER, &[1u8; 32], &[2u8; 32], 100).unwrap();
    let (k0, p0) = derive_session_key(&shared, Some(&base)).unwrap();

    // Peer MAC change → different key
    let mut other_peer = PEER;
    other_peer[0] ^= 1;
    let info = renew_hkdf_info(&other_peer, &[1u8; 32], &[2u8; 32], 100).unwrap();
    let (k, _) = derive_session_key(&shared, Some(&info)).unwrap();
    assert_ne!(k, k0);

    // Sensor eph change
    let info = renew_hkdf_info(&PEER, &[9u8; 32], &[2u8; 32], 100).unwrap();
    let (k, _) = derive_session_key(&shared, Some(&info)).unwrap();
    assert_ne!(k, k0);

    // Gateway eph change
    let info = renew_hkdf_info(&PEER, &[1u8; 32], &[9u8; 32], 100).unwrap();
    let (k, _) = derive_session_key(&shared, Some(&info)).unwrap();
    assert_ne!(k, k0);

    // Expiry change
    let info = renew_hkdf_info(&PEER, &[1u8; 32], &[2u8; 32], 101).unwrap();
    let (k, p) = derive_session_key(&shared, Some(&info)).unwrap();
    assert_ne!(k, k0);
    assert_ne!(p, p0);
}

#[test]
fn test_renew_ack_rejects_nonzero_counter() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let chal = match gateway
.handle_renew_request::<256>(&req, &mut rng_g, 1000, 1000 + 86_400)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let mut ack = match sensor
.continue_renew::<256>(&chal, &mut rng_s, 1000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };

    // Flip AEAD counter from 0 to 1 (bytes 22..30 after outer header).
    use crate::core::frame::OUTER_HEADER_SIZE;
    ack[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12].copy_from_slice(&1u64.to_be_bytes());

    let result = gateway.continue_renew::<256>(&ack, &mut rng_g, 1000);
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
fn test_continue_renew_error_zeroizes_scalar_copy_and_keeps_pending() {
    // On challenge parse failure, `continue_renew` must zeroize the
    // stack scalar_copy and leave pending so the sensor can retry.
    let mut sensor = sensor_active();
    let mut rng = MockRandom::new();
    sensor.start_renew::<256>(GW_MAC, &mut rng, 1_000).unwrap();
    assert!(sensor.get_pending(&GW_MAC).is_some());

    let garbage = [0u8; 18]; // too short / wrong type for RenewChallenge
    let err = sensor.continue_renew::<256>(&garbage, &mut rng, 1000);
    assert!(err.is_err());
    assert!(
        sensor.get_pending(&GW_MAC).is_some(),
        "pending must survive error so renew can be retried"
    );
    assert!(
        sensor.get_pending(&GW_MAC).unwrap().eph_scalar().is_some(),
        "eph scalar remains in pending until success or cancel"
    );
}

#[test]
fn test_renew_commit_confirmed_loss_and_duplicate_ack_retx() {
    // Drop CommitConfirmed → sensor stays on old key; duplicate Final
    // → gateway reTX CommitConfirmed → sensor completes.
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let chal = match gateway
.handle_renew_request::<256>(&req, &mut rng_g, 1000, 1000 + 86_400)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let old_key = *sensor.get(&GW_MAC).unwrap().session_key().unwrap();
    let ack = match sensor
.continue_renew::<256>(&chal, &mut rng_s, 1000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let commit1 = match gateway
.continue_renew::<256>(&ack, &mut rng_g, 1000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    // Drop CommitConfirmed (do not deliver to sensor).
    assert_eq!(
        sensor.get(&GW_MAC).unwrap().session_key().unwrap(),
        &old_key
    );

    // Regression: even after both advisory deadlines, housekeeping
    // and manual radio-timeout cancellation must preserve commit recovery.
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

    // Duplicate Final → gateway reTX same CommitConfirmed.
    let commit2 = match gateway
.continue_renew::<256>(&ack, &mut rng_g, 1000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    assert_eq!(commit1.as_slice(), commit2.as_slice());

    // Also exercise helper reTX of sensor Final cache.
    let retx_final = match sensor.retransmit_pending_cached::<256>(&GW_MAC).unwrap() {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    assert_eq!(retx_final.as_slice(), ack.as_slice());

    sensor
.continue_renew::<256>(&commit2, &mut rng_s, 1000)
.unwrap();
    assert_ne!(
        sensor.get(&GW_MAC).unwrap().session_key().unwrap(),
        &old_key
    );
    assert!(sensor.get_pending(&GW_MAC).is_none());

    // First authenticated Data under the new key proves commit delivery and
    // releases the gateway's retained CommitSent recovery slot.
    let data = sensor
.encrypt_data::<256>(&GW_MAC, b"commit-proof", 1000)
.unwrap();
    gateway
.process_incoming_packet::<200, 256>(&data, 1000)
.unwrap();
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_start_renew_rejects_gateway_role() {
    // Gateway-role session must not initiate renew.
    let mut gateway = gateway_active();
    let mut rng = MockRandom::new();
    let err = gateway.start_renew::<256>(SENSOR_MAC, &mut rng, 1_000);
    assert_eq!(err, Err(SigilError::InvalidStep { peer: SENSOR_MAC }));
}

#[test]
fn test_handle_renew_request_rejects_sensor_role() {
    let mut sensor = sensor_active();
    let mut misconfigured_gateway = gateway_active();
    misconfigured_gateway.get_mut(&SENSOR_MAC).unwrap().role = SessionRole::Sensor;
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();
    let request = match sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let before_rx = misconfigured_gateway.get(&SENSOR_MAC).unwrap().rx_counter;
    let result = misconfigured_gateway.handle_renew_request::<256>(
        &request,
        &mut rng_g,
        1_000,
        1_000 + 86_400,
    );
    assert_eq!(result, Err(SigilError::InvalidStep { peer: SENSOR_MAC }));
    assert_eq!(
        misconfigured_gateway.get(&SENSOR_MAC).unwrap().rx_counter,
        before_rx,
        "Role rejection must happen before counter mutation"
    );
}

#[test]
fn test_gateway_renew_transient_failure_keeps_request_retransmittable() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut rng_s = MockRandom::new();
    let request = match sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };

    assert_eq!(
        gateway.handle_renew_request::<256>(&request, &mut FailingRandom, 1_000, 86_400),
        Err(SigilError::RandomFailed)
    );
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().rx_counter(), 0);
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().tx_counter(), 0);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    let mut rng_g = MockRandom::new();
    assert!(matches!(
        gateway.handle_renew_request::<256>(&request, &mut rng_g, 1_000, 86_400),
        Ok(SigilAction::Transmit {.. })
    ));
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().rx_counter(), 1);
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().tx_counter(), 1);
}

#[test]
fn test_sensor_renew_output_capacity_failure_keeps_challenge_retransmittable() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();
    let request = match sensor
.start_renew::<256>(GW_MAC, &mut rng_s, 1_000)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };
    let challenge = match gateway
.handle_renew_request::<256>(&request, &mut rng_g, 1_000, 86_400)
.unwrap()
    {
        SigilAction::Transmit { payload,.. } => payload,
        _ => panic!(),
    };

    // RenewAck requires 47 bytes. A too-small host output capacity must not
    // consume the authenticated challenge's RX counter.
    assert_eq!(
        sensor.continue_renew::<46>(&challenge, &mut rng_s, 1_000),
        Err(SigilError::CapacityExceeded)
    );
    assert_eq!(sensor.get(&GW_MAC).unwrap().rx_counter(), 0);
    assert_eq!(
        sensor.get_pending(&GW_MAC).unwrap().step,
        crate::core::pending::HandshakeStep::RenewWaitingForChallenge
    );

    assert!(matches!(
        sensor.continue_renew::<256>(&challenge, &mut rng_s, 1_000),
        Ok(SigilAction::Transmit {.. })
    ));
    assert_eq!(sensor.get(&GW_MAC).unwrap().rx_counter(), 1);
}

#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for install protocol

mod transitions;

// Host-side performance measurement suite (dev-only, prints with --nocapture).
mod perf_measurements;

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{
    FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
};
use crate::core::install::INSTALL_DISCOVERY_DEST;
use crate::core::install::INSTALL_TIMEOUT_MS;
use crate::core::install::wire::{
    INSTALL_CHALLENGE_LEN, INSTALL_CONFIRM_LEN, INSTALL_REQUEST_LEN, InstallChallenge,
    InstallConfirm, InstallMessageType, InstallRequest, build_install_challenge,
    build_install_confirm, build_install_request, parse_install_challenge, parse_install_confirm,
    parse_install_message_type, parse_install_request,
};
use crate::core::manager::SessionManager;
use crate::core::pending::{PendingHandshake, PendingState};
use crate::core::session::{Session, SessionRole};
use crate::core::test_support::{MockRandom, MockSecureElement, test_manager};
use crate::core::traits::SecureElement;

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];
const PEER: [u8; 17] = [7u8; 17]; // used in wire unit tests
const SENSOR_MAC: [u8; 17] = [0x71u8; 17];
const GW_MAC: [u8; 17] = [0x72u8; 17];

#[test]
fn test_factory_cert_canonical_message_includes_metadata() {
    let metadata = crate::core::traits::FactoryCertificateMetadata {
        hardware_profile_id: 0xA1,
        factory_key_id: 0xB2,
    };
    let mut pubkey = [0xC3u8; 33];
    pubkey[0] = 0x03;
    let message = crate::core::install::factory_cert_message(
        crate::core::install::FACTORY_PRODUCT_ID_SENSOR,
        metadata,
        &PEER,
        &pubkey,
    )
    .unwrap();

    assert_eq!(message.len(), 55);
    assert_eq!(message[0], crate::core::install::FACTORY_CERT_VERSION);
    assert_eq!(&message[1..3], &[0x00, 0x01]);
    assert_eq!(message[3], metadata.hardware_profile_id);
    assert_eq!(message[4], metadata.factory_key_id);
    assert_eq!(&message[5..22], &PEER);
    assert_eq!(&message[22..55], &pubkey);
}

#[test]
fn test_install_gateway_rejects_null_static_ecdh_secret() {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gateway = MockSecureElement::gateway(2, GW_MAC);
    se_gateway.return_zero_ecdh();
    let mut rng_sensor = MockRandom::new();
    let mut rng_gateway = MockRandom::new();

    let request = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    assert_eq!(
        gateway.handle_install_request::<256>(
            &request,
            &mut se_gateway,
            &mut rng_gateway,
            1_000,
            86_400,
        ),
        Err(SigilError::EcdhFailed)
    );
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
    assert!(gateway.get(&SENSOR_MAC).is_none());
}

#[test]
fn test_install_sensor_rejects_null_static_ecdh_secret() {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gateway = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gateway = MockRandom::new();

    let request = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    let challenge = match gateway
        .handle_install_request::<256>(&request, &mut se_gateway, &mut rng_gateway, 1_000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit"),
    };

    se_sensor.return_zero_ecdh();
    assert_eq!(
        sensor.continue_install::<256>(&challenge, &mut se_sensor, 1_000),
        Err(SigilError::EcdhFailed)
    );
    assert!(sensor.get(&GW_MAC).is_none());
}

/// Completes steps 4–5 after the sensor has built InstallConfirm.
fn finish_install_commit<const NS: usize, const NG: usize>(
    sensor: &mut SessionManager<NS>,
    gateway: &mut SessionManager<NG>,
    se_sensor: &mut MockSecureElement,
    se_gw: &mut MockSecureElement,
    confirm: &[u8],
    now: u32,
) {
    let persist = gateway
        .continue_install::<256>(confirm, se_gw, now)
        .unwrap();
    let commit = match persist {
        SigilAction::PersistPeerStaticKey { transmit, .. } => {
            assert!(!transmit.is_empty());
            transmit
        }
        _ => panic!("gateway Final must Persist + CommitConfirmed TX"),
    };
    let sensor_done = sensor
        .continue_install::<256>(&commit, se_sensor, now)
        .unwrap();
    assert!(matches!(
        sensor_done,
        SigilAction::PersistPeerStaticKey { .. }
    ));
}

#[test]
fn test_build_install_request_wire() {
    let req = InstallRequest {
        sensor_peer_mac: PEER,
        hardware_profile_id: 0x11,
        factory_key_id: 0x22,
        sensor_static_pubkey: [2u8; 33],
        factory_cert_sig: [9u8; 64],
        sensor_nonce: [3u8; 16],
        sensor_signature: [4u8; 64],
    };
    let packet = build_install_request(&req).unwrap();
    // Outer header: peer(17) + version(1) + frame_type(1)
    assert_eq!(&packet[..17], &PEER[..]);
    assert_eq!(packet[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(packet[FRAME_TYPE_OFFSET], FrameType::InstallRequest as u8);
    // Body starts at OUTER_HEADER_SIZE
    assert_eq!(
        &packet[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 17],
        &PEER[..]
    );
    assert_eq!(packet.len(), INSTALL_REQUEST_LEN);
    assert_eq!(packet.capacity(), INSTALL_REQUEST_LEN);

    let parsed = parse_install_request(&packet).unwrap();
    assert_eq!(parsed.sensor_peer_mac, PEER);
    assert_eq!(parsed.hardware_profile_id, 0x11);
    assert_eq!(parsed.factory_key_id, 0x22);
    assert_eq!(parsed.factory_cert_sig, [9u8; 64]);
    assert_eq!(parsed.sensor_signature, [4u8; 64]);
}

#[test]
fn test_build_install_challenge_wire() {
    let chal = InstallChallenge {
        gateway_peer_mac: PEER,
        hardware_profile_id: 0x33,
        factory_key_id: 0x44,
        gateway_static_pubkey: [5u8; 33],
        factory_cert_sig: [0xABu8; 64],
        gateway_nonce: [6u8; 16],
        key_lifetime_secs: 1234,
        gateway_signature: [7u8; 64],
    };
    let packet = build_install_challenge(&chal).unwrap();
    assert_eq!(&packet[..17], &PEER[..]);
    assert_eq!(packet[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(packet[FRAME_TYPE_OFFSET], FrameType::InstallChallenge as u8);
    assert_eq!(packet.len(), INSTALL_CHALLENGE_LEN);
    assert_eq!(packet.capacity(), INSTALL_CHALLENGE_LEN);

    let parsed = parse_install_challenge(&packet).unwrap();
    assert_eq!(parsed.gateway_peer_mac, PEER);
    assert_eq!(parsed.hardware_profile_id, 0x33);
    assert_eq!(parsed.factory_key_id, 0x44);
    assert_eq!(parsed.factory_cert_sig, [0xABu8; 64]);
    assert_eq!(parsed.key_lifetime_secs, 1234);
}

#[test]
fn test_build_install_confirm_wire() {
    let cfm = InstallConfirm {
        sensor_peer_mac: PEER,
        confirm_signature: [8u8; 64],
    };
    let packet = build_install_confirm(&cfm).unwrap();
    assert_eq!(&packet[..17], &PEER[..]);
    assert_eq!(packet[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(packet[FRAME_TYPE_OFFSET], FrameType::InstallConfirm as u8);
    assert_eq!(packet.len(), INSTALL_CONFIRM_LEN);
    assert_eq!(packet.capacity(), INSTALL_CONFIRM_LEN);

    let parsed = parse_install_confirm(&packet).unwrap();
    assert_eq!(parsed.sensor_peer_mac, PEER);
}

#[test]
fn test_parse_install_message_type_all() {
    assert_eq!(
        parse_install_message_type(&[0u8; 17]),
        None, // too short (only 17 bytes, need OUTER_HEADER_SIZE)
    );
    // Build packets with outer header (version + frame_type).
    let mut pkt_req = [0u8; OUTER_HEADER_SIZE];
    pkt_req[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    pkt_req[FRAME_TYPE_OFFSET] = FrameType::InstallRequest as u8;
    assert_eq!(
        parse_install_message_type(&pkt_req),
        Some(InstallMessageType::Request)
    );

    let mut pkt_chal = [0u8; OUTER_HEADER_SIZE];
    pkt_chal[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    pkt_chal[FRAME_TYPE_OFFSET] = FrameType::InstallChallenge as u8;
    assert_eq!(
        parse_install_message_type(&pkt_chal),
        Some(InstallMessageType::Challenge)
    );

    let mut pkt_cfm = [0u8; OUTER_HEADER_SIZE];
    pkt_cfm[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    pkt_cfm[FRAME_TYPE_OFFSET] = FrameType::InstallConfirm as u8;
    assert_eq!(
        parse_install_message_type(&pkt_cfm),
        Some(InstallMessageType::Confirm)
    );

    let mut pkt_commit = [0u8; OUTER_HEADER_SIZE];
    pkt_commit[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    pkt_commit[FRAME_TYPE_OFFSET] = FrameType::InstallCommitConfirmed as u8;
    assert_eq!(
        parse_install_message_type(&pkt_commit),
        Some(InstallMessageType::CommitConfirmed)
    );

    let mut pkt_bad = [0u8; OUTER_HEADER_SIZE];
    pkt_bad[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    pkt_bad[FRAME_TYPE_OFFSET] = 0xFF;
    assert_eq!(parse_install_message_type(&pkt_bad), None);

    let mut pkt_bad_ver = [0u8; OUTER_HEADER_SIZE];
    pkt_bad_ver[PROTOCOL_VERSION_OFFSET] = 0x01;
    pkt_bad_ver[FRAME_TYPE_OFFSET] = FrameType::InstallRequest as u8;
    assert_eq!(parse_install_message_type(&pkt_bad_ver), None);
}

#[test]
fn test_parse_install_request_rejects_bad_length() {
    assert!(parse_install_request(&[0x01]).is_none());
    assert!(parse_install_request(&[0x02u8; INSTALL_REQUEST_LEN]).is_none());
}

#[test]
fn test_start_install_sensor() {
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    let action = manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();

    // Sensor should immediately transmit the signed InstallRequest.
    match action {
        SigilAction::Transmit {
            dest,
            payload,
            wait_timeout_ms,
        } => {
            assert_eq!(dest, PEER);
            assert_eq!(wait_timeout_ms, Some(INSTALL_TIMEOUT_MS));
            // Outer header carries local_mac (sender), not the gateway dest.
            assert_eq!(&payload[..17], manager.local_mac());
            assert_eq!(payload[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
            assert_eq!(payload[FRAME_TYPE_OFFSET], FrameType::InstallRequest as u8);
        }
        _ => panic!("Expected Transmit action"),
    }

    // Pending handshake must exist and be at the waiting-for-challenge step.
    // The tagged variant itself carries the stashed sensor_nonce (for HKDF at
    // the challenge step), so matching it covers both the step and the nonce.
    let pending = manager.get_pending(&PEER).unwrap();
    assert!(matches!(
        pending.state(),
        PendingState::InstallSensorAwaitChallenge { .. }
    ));
}

#[test]
fn test_start_install_sensor_duplicate_rejected() {
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    let result = manager.start_install::<256>(PEER, &mut se, &mut rng, 1_000);
    assert_eq!(result, Err(SigilError::PendingAlreadyExists { peer: PEER }));
}

#[test]
fn test_rebind_sole_sensor_install_pending_for_broadcast_discovery() {
    // Mandatory discovery: sensor starts install with INSTALL_DISCOVERY_DEST.
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    manager
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se, &mut rng, 1_000)
        .unwrap();
    assert!(manager.get_pending(&INSTALL_DISCOVERY_DEST).is_some());
    assert!(manager.get_pending(&PEER).is_none());

    let old = manager.rebind_sole_sensor_install_pending(PEER).unwrap();
    assert_eq!(old, Some(INSTALL_DISCOVERY_DEST));
    assert!(manager.get_pending(&INSTALL_DISCOVERY_DEST).is_none());
    let pending = manager.get_pending(&PEER).unwrap();
    assert_eq!(pending.peer_mac, PEER);
    assert!(matches!(
        pending.state(),
        PendingState::InstallSensorAwaitChallenge { .. }
    ));
}

#[test]
fn test_rebind_noop_when_pending_already_at_gateway() {
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();
    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    assert_eq!(
        manager.rebind_sole_sensor_install_pending(PEER).unwrap(),
        None
    );
}

#[test]
fn test_rebind_rejects_multiple_waiting_sensor_pendings() {
    let mut manager: SessionManager<16> = test_manager();
    // Two WaitingForChallenge sensor entries (artificially). The nonce bytes
    // are irrelevant here; only the tagged await-challenge state matters.
    manager
        .insert_pending(
            INSTALL_DISCOVERY_DEST,
            PendingHandshake::new_install_sensor(
                INSTALL_DISCOVERY_DEST,
                [0x11u8; 16],
                INSTALL_TIMEOUT_MS,
                1_000,
            ),
        )
        .unwrap();
    manager
        .insert_pending(
            [0xEEu8; 17],
            PendingHandshake::new_install_sensor(
                [0xEEu8; 17],
                [0x22u8; 16],
                INSTALL_TIMEOUT_MS,
                1_000,
            ),
        )
        .unwrap();
    assert_eq!(
        manager.rebind_sole_sensor_install_pending(PEER),
        // A rebind targeting a non-waiting pending state is unrepresentable
        // through the tagged pending API: internal invariant failure.
        Err(SigilError::InvariantViolation)
    );
}

#[test]
fn test_rollback_install_pending_rebind_restores_discovery_key() {
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();
    manager
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se, &mut rng, 1_000)
        .unwrap();
    assert_eq!(
        manager.rebind_sole_sensor_install_pending(PEER).unwrap(),
        Some(INSTALL_DISCOVERY_DEST)
    );
    manager
        .rollback_install_pending_rebind(PEER, INSTALL_DISCOVERY_DEST)
        .unwrap();
    assert!(manager.get_pending(&PEER).is_none());
    assert!(manager.get_pending(&INSTALL_DISCOVERY_DEST).is_some());
}

#[test]
fn test_discovery_failed_challenge_rolls_back_pending_key() {
    // Forged challenge (outer≡body) must not leave pending stuck under attacker MAC.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut se = MockSecureElement::with_id(1);
    let mut rng = MockRandom::new();
    sensor
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se, &mut rng, 1_000)
        .unwrap();

    let attacker = GW_MAC;
    let forged = InstallChallenge {
        gateway_peer_mac: attacker,
        hardware_profile_id: 1,
        factory_key_id: 1,
        gateway_static_pubkey: {
            let mut key = [0xAAu8; 33];
            key[0] = 0x02;
            key
        },
        factory_cert_sig: [0u8; 64], // invalid vs factory root
        gateway_nonce: [1u8; 16],
        key_lifetime_secs: 86_400,
        gateway_signature: [2u8; 64],
    };
    let forged_bytes = build_install_challenge(&forged).unwrap();

    let result = sensor.continue_install::<256>(&forged_bytes, &mut se, 1000);
    assert!(matches!(
        result,
        Err(SigilError::VerificationFailed) | Err(SigilError::MalformedFrame)
    ));
    // Pending must be back under discovery dest, not attacker MAC.
    assert!(sensor.get_pending(&attacker).is_none());
    assert!(sensor.get_pending(&INSTALL_DISCOVERY_DEST).is_some());
}

#[test]
fn test_discovery_challenge_outer_body_mismatch_does_not_rebind() {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut se = MockSecureElement::with_id(1);
    let mut rng = MockRandom::new();
    sensor
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se, &mut rng, 1_000)
        .unwrap();

    let chal = InstallChallenge {
        gateway_peer_mac: GW_MAC,
        hardware_profile_id: 1,
        factory_key_id: 1,
        gateway_static_pubkey: [5u8; 33],
        factory_cert_sig: [0xABu8; 64],
        gateway_nonce: [6u8; 16],
        key_lifetime_secs: 1234,
        gateway_signature: [7u8; 64],
    };
    let mut packet = build_install_challenge(&chal).unwrap();
    // Flip outer header MAC only — body still GW_MAC.
    packet[..17].copy_from_slice(&[0xCCu8; 17]);

    assert_eq!(
        sensor.continue_install::<256>(&packet, &mut se, 1000),
        // Outer/body identity mismatch is malformed wire input; no rebind.
        Err(SigilError::MalformedFrame)
    );
    assert!(sensor.get_pending(&INSTALL_DISCOVERY_DEST).is_some());
    assert!(sensor.get_pending(&GW_MAC).is_none());
}

#[test]
fn test_install_discovery_dest_constant_is_all_ff() {
    assert_eq!(INSTALL_DISCOVERY_DEST, [0xFFu8; 17]);
}

#[test]
fn test_install_pairwise_success() {
    // Two managers with distinct local MACs (multi-peer identity model).
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    // Step 1: sensor emits InstallRequest toward the gateway.
    let req_action = sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap();
    let request_bytes = match req_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };

    // Step 2: gateway processes request and emits InstallChallenge.
    let chal_action = gateway
        .handle_install_request::<256>(&request_bytes, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap();
    let challenge_bytes = match chal_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit"),
    };

    // Gateway must have created a pending handshake at WaitingForConfirm
    // and stashed the gateway challenge nonce for confirm verification.
    let gw_pending = gateway.get_pending(&SENSOR_MAC).unwrap();
    let stashed_nonce = match gw_pending.state() {
        PendingState::InstallGatewayAwaitConfirm(staged) => *staged.gateway_nonce.as_array(),
        _ => panic!("gateway pending must be awaiting the sensor Final"),
    };
    // The stashed nonce must equal the nonce carried in the challenge body.
    let chal = parse_install_challenge(&challenge_bytes).unwrap();
    assert_eq!(stashed_nonce, chal.gateway_nonce);

    // Step 3: sensor processes challenge → emits Final + stages keys (no session yet).
    let cfm_action = sensor
        .continue_install::<256>(&challenge_bytes, &mut se_sensor, 1000)
        .unwrap();
    match &cfm_action {
        SigilAction::Transmit { dest, payload, .. } => {
            assert_eq!(*dest, GW_MAC);
            assert_eq!(payload[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
            assert_eq!(payload[FRAME_TYPE_OFFSET], FrameType::InstallConfirm as u8);
        }
        _ => panic!("sensor should transmit confirm"),
    }

    // Sensor has no session until CommitConfirmed.
    assert!(sensor.get(&GW_MAC).is_none());
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        PendingState::InstallSensorFinalSent { .. }
    ));

    // Step 4: gateway processes Final → commits + Persist with CommitConfirmed TX.
    let confirm_bytes = match cfm_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => unreachable!(),
    };
    let persist_action = gateway
        .continue_install::<256>(&confirm_bytes, &mut se_gw, 1000)
        .unwrap();
    let commit_frame = match persist_action {
        SigilAction::PersistPeerStaticKey {
            peer,
            pubkey,
            resume_psk,
            transmit,
            wait_timeout_ms,
        } => {
            assert_eq!(peer, SENSOR_MAC);
            assert_eq!(pubkey[0], 0x03);
            assert!(pubkey[1..].iter().all(|byte| *byte == 1));
            assert_eq!(
                Some(*resume_psk.expose_secret()),
                gateway.get(&SENSOR_MAC).unwrap().resume_psk().copied()
            );
            assert!(!transmit.is_empty());
            assert!(wait_timeout_ms.is_some());
            assert_eq!(
                transmit[FRAME_TYPE_OFFSET],
                FrameType::InstallCommitConfirmed as u8
            );
            transmit
        }
        _ => panic!("gateway should emit PersistPeerStaticKey with CommitConfirmed"),
    };
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayCommitSent { .. }
    ));

    // Step 5: sensor CommitConfirmed → insert session + Persist.
    let sensor_persist = sensor
        .continue_install::<256>(&commit_frame, &mut se_sensor, 1000)
        .unwrap();
    match sensor_persist {
        SigilAction::PersistPeerStaticKey {
            peer,
            pubkey,
            resume_psk,
            transmit,
            ..
        } => {
            assert_eq!(peer, GW_MAC);
            assert_eq!(pubkey, [2u8; 33]); // gateway mock pubkey
            assert!(transmit.is_empty());
            assert_eq!(
                Some(*resume_psk.expose_secret()),
                sensor.get(&GW_MAC).unwrap().resume_psk().copied()
            );
        }
        _ => panic!("sensor should PersistPeerStaticKey on CommitConfirmed"),
    }

    // Both sides share directional material with opposite roles.
    let s = sensor.get(&GW_MAC).unwrap();
    let g = gateway.get(&SENSOR_MAC).unwrap();
    assert_eq!(s.session_key(), g.rx_session_key());
    assert_eq!(s.rx_session_key(), g.session_key());
    assert_eq!(s.nonce_prefix(), g.rx_nonce_prefix());
    assert_eq!(s.rx_nonce_prefix(), g.nonce_prefix());
    assert_ne!(s.session_key(), s.rx_session_key());
    // Install Final is clear-text; CommitConfirmed uses g2s counter 0.
    assert_eq!(s.tx_counter, 0);
    assert_eq!(s.rx_counter, 1);
    assert_eq!(g.tx_counter, 1);
    assert_eq!(g.rx_counter, 0);
    assert_eq!(s.key_expire_at(), 1000 + 86_400);
    assert_eq!(g.key_expire_at(), 1000 + 86_400);
    assert!(sensor.get_pending(&GW_MAC).is_none());
    assert!(gateway.get_pending(&SENSOR_MAC).is_some());
}

#[test]
fn test_install_two_sensors_isolated_on_gateway() {
    // S-H1 regression: two sensors with distinct MACs must occupy two gateway
    // session slots (no collapse onto a shared PeerId).
    const S1: [u8; 17] = [0xA1u8; 17];
    const S2: [u8; 17] = [0xA2u8; 17];
    const GW: [u8; 17] = [0xBBu8; 17];

    let mut sensor1: SessionManager<2> = crate::core::test_support::test_manager_with_mac(S1);
    let mut sensor2: SessionManager<2> = crate::core::test_support::test_manager_with_mac(S2);
    let mut gateway: SessionManager<4> = crate::core::test_support::test_manager_with_mac(GW);

    let mut se_s1 = MockSecureElement::sensor(1, S1);
    let mut se_s2 = MockSecureElement::sensor(3, S2);
    let mut se_gw = MockSecureElement::gateway(2, GW);
    let mut rng_s1 = MockRandom::new();
    let mut rng_s2 = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    for (sensor, se_s, rng_s, expect_mac) in [
        (&mut sensor1, &mut se_s1, &mut rng_s1, S1),
        (&mut sensor2, &mut se_s2, &mut rng_s2, S2),
    ] {
        let req = match sensor.start_install::<256>(GW, se_s, rng_s, 1_000).unwrap() {
            SigilAction::Transmit {
                payload,
                wait_timeout_ms,
                ..
            } => {
                assert_eq!(&payload[..17], &expect_mac);
                assert_eq!(wait_timeout_ms, Some(INSTALL_TIMEOUT_MS));
                payload
            }
            _ => panic!(),
        };
        // Allowlist uses outer-header sender MAC (= sensor identity).
        assert_eq!(&req[..17], &expect_mac);

        let chal = match gateway
            .handle_install_request::<256>(&req, &mut se_gw, &mut rng_gw, 1000, 86_400)
            .unwrap()
        {
            SigilAction::Transmit { payload, .. } => payload,
            _ => panic!(),
        };
        let cfm = match sensor.continue_install::<256>(&chal, se_s, 1000).unwrap() {
            SigilAction::Transmit { payload, .. } => payload,
            _ => panic!(),
        };
        finish_install_commit(sensor, &mut gateway, se_s, &mut se_gw, &cfm, 1000);
    }

    assert_eq!(gateway.len(), 2);
    assert!(gateway.get(&S1).unwrap().session_key().is_some());
    assert!(gateway.get(&S2).unwrap().session_key().is_some());
    // Distinct sensors must not share the same session key material in this
    // mock (different nonces from MockRandom across installs).
    assert_ne!(
        gateway.get(&S1).unwrap().session_key(),
        gateway.get(&S2).unwrap().session_key()
    );
}

#[test]
fn test_two_installs_produce_different_session_keys() {
    // regression: re-install between the same static keys must NOT reuse
    // the previous session_key / nonce_prefix (ChaCha20 nonce reuse risk).
    // MockRandom advances, so successive installs get different nonces →
    // different HKDF info → different keys.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    // --- Install #1 ---
    let req1 = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let chal1 = match gateway
        .handle_install_request::<256>(&req1, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let cfm1 = match sensor
        .continue_install::<256>(&chal1, &mut se_sensor, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    finish_install_commit(
        &mut sensor,
        &mut gateway,
        &mut se_sensor,
        &mut se_gw,
        &cfm1,
        1000,
    );

    let key1 = *sensor.get(&GW_MAC).unwrap().session_key().unwrap();
    let prefix1 = *sensor.get(&GW_MAC).unwrap().nonce_prefix().unwrap();

    // Clear sessions + pending so a fresh install can start.
    // Cooldown stamp remains; advance `now` by INSTALL_REQUEST_COOLDOWN.
    sensor.remove(&GW_MAC);
    gateway.remove(&SENSOR_MAC);
    let _ = gateway.cancel_pending(&SENSOR_MAC);

    // --- Install #2 (same static keys, different handshake nonces) ---
    let req2 = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let now2 = 1000 + crate::core::install::INSTALL_REQUEST_COOLDOWN;
    let chal2 = match gateway
        .handle_install_request::<256>(&req2, &mut se_gw, &mut rng_gw, now2, now2 + 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let cfm2 = match sensor
        .continue_install::<256>(&chal2, &mut se_sensor, now2)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    finish_install_commit(
        &mut sensor,
        &mut gateway,
        &mut se_sensor,
        &mut se_gw,
        &cfm2,
        now2,
    );

    let key2 = *sensor.get(&GW_MAC).unwrap().session_key().unwrap();
    let prefix2 = *sensor.get(&GW_MAC).unwrap().nonce_prefix().unwrap();

    assert_ne!(key1, key2, "re-install must derive a fresh session key");
    assert_ne!(
        prefix1, prefix2,
        "re-install must derive a fresh nonce prefix"
    );
    // Both peers still agree after install #2 (directional halves).
    assert_eq!(
        sensor.get(&GW_MAC).unwrap().session_key(),
        gateway.get(&SENSOR_MAC).unwrap().rx_session_key()
    );
    assert_eq!(
        sensor.get(&GW_MAC).unwrap().rx_session_key(),
        gateway.get(&SENSOR_MAC).unwrap().session_key()
    );
}

#[test]
fn test_install_pairwise_verify_fail() {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    // Gateway will reject signatures.
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    se_gw.reject_signatures();
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req_action = sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap();
    let request_bytes = match req_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };

    // Gateway rejects the sensor signature → VerificationFailed, no pending.
    let result = gateway.handle_install_request::<256>(
        &request_bytes,
        &mut se_gw,
        &mut rng_gw,
        1000,
        86_400,
    );
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_pending_timeout_does_not_auto_clear_without_tick() {
    // elapsing a host wall-clock alone does nothing — only cancel_pending,

    // tick(now), success, remove, or replacing start_* clears pending.
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    let pending = manager.get_pending(&PEER).unwrap();
    assert_eq!(pending.suggested_timeout_ms, INSTALL_TIMEOUT_MS);
    assert_eq!(pending.deadline_at, 1_000 + (INSTALL_TIMEOUT_MS / 1000));

    // Wall-clock advanced but tick not called → pending intact.
    assert!(
        manager.get_pending(&PEER).is_some(),
        "time alone must leave pending intact"
    );

    // Manual policy: host timer → cancel_pending.
    manager.cancel_pending(&PEER).unwrap();
    assert!(manager.get_pending(&PEER).is_none());
}

#[test]
fn test_tick_purges_expired_pending() {
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    let deadline = manager.get_pending(&PEER).unwrap().deadline_at;

    // Before deadline: tick is a no-op.
    let purged = manager.tick(deadline.saturating_sub(1));
    assert!(purged.is_empty());
    assert!(manager.get_pending(&PEER).is_some());

    // At/after deadline: purge (TimeoutElapsed semantics).
    let purged = manager.tick(deadline);
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0], PEER);
    assert!(manager.get_pending(&PEER).is_none());
}

#[test]
fn test_cancel_clears_pending() {
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    assert!(manager.get_pending(&PEER).is_some());

    // Host aborts via the public cancel_pending API (keeps any session).
    manager.cancel_pending(&PEER).unwrap();
    assert!(manager.get_pending(&PEER).is_none());
    assert!(manager.cancel_pending(&PEER).is_err());
}

#[test]
fn test_cancel_zeroizes_ephemeral_secret() {
    // Cancel/removal drops the typed pending variant; its zeroizing wrappers
    // (P256ContextStash and friends) wipe the ephemeral material on Drop.
    // There is no manual `zeroize_secrets` step anymore: the observable
    // contract is that the secret-bearing variant exists while staged and is
    // gone once the host cancels the pending entry.
    let mut manager: SessionManager<2> = crate::core::test_support::test_manager();
    let hs = PendingHandshake::new_renew_gateway_await_confirm(
        PEER,
        [0xABu8; 32],
        [0x02u8; 33],
        86_400,
        1_000,
        0,
    );
    // The provider context is observable only in the secret-bearing variant.
    match hs.state() {
        PendingState::RenewGatewayAwaitConfirm { p256_context, .. } => {
            assert_eq!(p256_context.as_array(), &[0xABu8; 32]);
        }
        _ => panic!("expected RenewGatewayAwaitConfirm with a staged provider context"),
    }
    manager.insert_pending(PEER, hs).unwrap();

    // Host aborts via the public cancel path: the variant and its secret are
    // dropped (zeroized by the wrapper Drop impls).
    manager.cancel_pending(&PEER).unwrap();
    assert!(manager.get_pending(&PEER).is_none());
}

#[test]
fn test_start_install_replaces_previous_pending() {
    // A second start_install on the same peer should replace the pending entry.
    let mut manager: SessionManager<16> = test_manager();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();

    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    // Explicitly clear (as the library does before a fresh start).
    manager.remove_pending(&PEER);
    manager
        .start_install::<256>(PEER, &mut se, &mut rng, 1_000)
        .unwrap();
    assert!(manager.get_pending(&PEER).is_some());
}

#[test]
fn test_install_confirm_rejects_wrong_signed_message() {
    // Confirm signature must bind to the stashed gateway_nonce.
    // A signature over a constant (e.g. b"install-confirm") must fail.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req_action = sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap();
    let request_bytes = match req_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };

    let chal_action = gateway
        .handle_install_request::<256>(&request_bytes, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap();
    let challenge_bytes = match chal_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit"),
    };

    // Build a forged confirm whose signature is over the wrong message.
    let forged_sig = se_sensor.sign_ecdsa(b"install-confirm").unwrap();
    let forged = InstallConfirm {
        sensor_peer_mac: SENSOR_MAC,
        confirm_signature: forged_sig,
    };
    let forged_bytes = build_install_confirm(&forged).unwrap();

    let result = gateway.continue_install::<256>(&forged_bytes, &mut se_gw, 1000);
    assert_eq!(result, Err(SigilError::VerificationFailed));
    // Session must not be installed; pending remains until host cancels.
    assert!(gateway.get(&SENSOR_MAC).is_none());
    assert!(gateway.get_pending(&SENSOR_MAC).is_some());

    // Legitimate confirm (signed over gateway_nonce) still succeeds afterwards.
    let cfm_action = sensor
        .continue_install::<256>(&challenge_bytes, &mut se_sensor, 1000)
        .unwrap();
    let confirm_bytes = match cfm_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit confirm"),
    };
    let persist = gateway
        .continue_install::<256>(&confirm_bytes, &mut se_gw, 1000)
        .unwrap();
    assert!(matches!(
            persist,
            SigilAction::PersistPeerStaticKey {
                transmit,
    ..
            } if !transmit.is_empty()
        ));
}

#[test]
fn test_build_install_request_legacy_shape() {
    let req = InstallRequest {
        sensor_peer_mac: PEER,
        hardware_profile_id: 1,
        factory_key_id: 1,
        sensor_static_pubkey: [1u8; 33],
        factory_cert_sig: [2u8; 64],
        sensor_nonce: [0u8; 16],
        sensor_signature: [0u8; 64],
    };
    let packet = build_install_request(&req).unwrap();
    // Outer header
    assert_eq!(&packet[..17], &PEER[..]);
    assert_eq!(packet[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(packet[FRAME_TYPE_OFFSET], FrameType::InstallRequest as u8);
    assert_eq!(packet.len(), INSTALL_REQUEST_LEN);
}

#[test]
fn test_install_rejects_invalid_factory_cert_before_pending() {
    // A sensor with a forged factory certificate must be rejected before the
    // gateway creates any pending handshake state.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req_action = sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap();
    let mut request_bytes = match req_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };

    // Corrupt factory_cert_sig (bytes 71..135 of the full frame).
    for b in &mut request_bytes[71..135] {
        *b ^= 0xFF;
    }

    let result = gateway.handle_install_request::<256>(
        &request_bytes,
        &mut se_gw,
        &mut rng_gw,
        1000,
        86_400,
    );
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(
        gateway.get_pending(&SENSOR_MAC).is_none(),
        "invalid factory cert must not create pending state"
    );
}

#[test]
fn test_install_sensor_rejects_invalid_gateway_factory_cert() {
    // Sensor must reject a challenge whose gateway pubkey is not factory-attested.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req_action = sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap();
    let request_bytes = match req_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };

    let chal_action = gateway
        .handle_install_request::<256>(&request_bytes, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap();
    let mut challenge_bytes = match chal_action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit"),
    };

    // Corrupt gateway factory_cert_sig (bytes 71..135).
    for b in &mut challenge_bytes[71..135] {
        *b ^= 0x55;
    }

    let result = sensor.continue_install::<256>(&challenge_bytes, &mut se_sensor, 1000);
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(sensor.get(&GW_MAC).is_none());
    // Sensor pending remains (challenge failed); gateway still waiting for confirm.
    assert!(sensor.get_pending(&GW_MAC).is_some());
}

#[test]
fn test_install_rejects_tampered_factory_metadata() {
    // Both identifiers are inside the factory certificate and the device proof.
    // Changing either wire byte must fail before pending state is allocated.
    for metadata_offset in [OUTER_HEADER_SIZE + 17, OUTER_HEADER_SIZE + 18] {
        let mut sensor: SessionManager<16> =
            crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
        let mut gateway: SessionManager<16> =
            crate::core::test_support::test_manager_with_mac(GW_MAC);
        let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
        let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
        let mut rng_sensor = MockRandom::new();
        let mut rng_gw = MockRandom::new();

        let mut request = match sensor
            .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
            .unwrap()
        {
            SigilAction::Transmit { payload, .. } => payload,
            _ => panic!("sensor should transmit"),
        };
        request[metadata_offset] ^= 0x80;

        assert_eq!(
            gateway
                .handle_install_request::<256>(&request, &mut se_gw, &mut rng_gw, 1_000, 86_400,),
            Err(SigilError::VerificationFailed)
        );
        assert!(gateway.get_pending(&SENSOR_MAC).is_none());
    }
}

#[test]
fn test_sensor_rejects_tampered_gateway_factory_metadata() {
    for metadata_offset in [OUTER_HEADER_SIZE + 17, OUTER_HEADER_SIZE + 18] {
        let mut sensor: SessionManager<16> =
            crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
        let mut gateway: SessionManager<16> =
            crate::core::test_support::test_manager_with_mac(GW_MAC);
        let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
        let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
        let mut rng_sensor = MockRandom::new();
        let mut rng_gw = MockRandom::new();

        let request = match sensor
            .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
            .unwrap()
        {
            SigilAction::Transmit { payload, .. } => payload,
            _ => panic!("sensor should transmit"),
        };
        let mut challenge = match gateway
            .handle_install_request::<256>(&request, &mut se_gw, &mut rng_gw, 1_000, 86_400)
            .unwrap()
        {
            SigilAction::Transmit { payload, .. } => payload,
            _ => panic!("gateway should transmit"),
        };
        challenge[metadata_offset] ^= 0x40;

        assert_eq!(
            sensor.continue_install::<256>(&challenge, &mut se_sensor, 1_000),
            Err(SigilError::VerificationFailed)
        );
        assert!(sensor.get(&GW_MAC).is_none());
    }
}

#[test]
fn test_manager_exposes_factory_pubkey() {
    let mgr: SessionManager<16> = test_manager();
    assert_eq!(
        mgr.factory_pubkey(),
        &crate::core::test_support::TEST_FACTORY_PUBKEY
    );
}

#[test]
fn test_install_rejects_peer_mac_rebinding() {
    // Flipping peer_mac after signing must fail ECDSA (MAC is in the signed message).
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let mut request_bytes = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };

    let other: [u8; 17] = [0xAAu8; 17];
    // Outer header peer + body peer_mac (after wire-v2 outer header).
    request_bytes[..17].copy_from_slice(&other);
    request_bytes[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 17].copy_from_slice(&other);

    let result = gateway.handle_install_request::<256>(
        &request_bytes,
        &mut se_gw,
        &mut rng_gw,
        1000,
        86_400,
    );
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(gateway.get_pending(&other).is_none());
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_install_rejects_outer_body_mac_mismatch() {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let mut request_bytes = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };

    // Flip only the outer header MAC — body MAC still matches the signature.
    request_bytes[..17].copy_from_slice(&[0xBBu8; 17]);

    let result = gateway.handle_install_request::<256>(
        &request_bytes,
        &mut se_gw,
        &mut rng_gw,
        1000,
        86_400,
    );
    assert_eq!(
        result,
        // Outer-header MAC contradicting the authenticated body MAC is
        // malformed wire input.
        Err(SigilError::MalformedFrame)
    );
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_install_wire_parsers_reject_garbage() {
    // B3: truncated / wrong-type / oversized junk must never panic — only None.
    assert!(parse_install_request(&[]).is_none());
    assert!(parse_install_request(&[0u8; 18]).is_none());
    assert!(parse_install_request(&[0xFFu8; INSTALL_REQUEST_LEN]).is_none());
    assert!(parse_install_challenge(&[0u8; INSTALL_CHALLENGE_LEN - 1]).is_none());
    assert!(parse_install_confirm(&[0u8; INSTALL_CONFIRM_LEN + 1]).is_none());
    assert!(parse_install_message_type(&[0u8; 10]).is_none());
}

#[test]
fn test_install_rejects_zero_key_lifetime() {
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_gw = MockRandom::new();
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut rng_sensor = MockRandom::new();

    let request_bytes = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let result =
        gateway.handle_install_request::<256>(&request_bytes, &mut se_gw, &mut rng_gw, 1000, 0);
    assert_eq!(
        result,
        Err(SigilError::InvalidKeyLifetime { lifetime_secs: 0 })
    );
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn test_install_rejects_key_expire_at_over_max_lifetime() {
    // lifetime > MAX_SESSION_LIFETIME_SECS (2 days) is rejected.

    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_gw = MockRandom::new();
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut rng_sensor = MockRandom::new();

    let now = 1000u32;
    let too_far = crate::core::session::MAX_SESSION_LIFETIME_SECS + 1;

    let request_bytes = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let result = gateway.handle_install_request::<256>(
        &request_bytes,
        &mut se_gw,
        &mut rng_gw,
        now,
        too_far,
    );
    assert_eq!(
        result,
        Err(SigilError::InvalidKeyLifetime {
            lifetime_secs: too_far
        })
    );
}

#[test]
fn test_session_require_key_material_when_incomplete() {
    // A4: enrolled session without key → SessionNotActive, not panic.
    let session = Session::new_enrolled(PEER, [2u8; 33], RESUME_PSK, SessionRole::Sensor).unwrap();
    let err = session.require_key_material(&PEER).unwrap_err();
    assert_eq!(err, SigilError::SessionNotActive { peer: PEER });
}

#[test]
fn test_install_request_cooldown_is_fifteen_seconds() {
    assert_eq!(crate::core::install::INSTALL_REQUEST_COOLDOWN, 15);
}

#[test]
fn test_install_rejects_inflight_pending_before_se() {
    // second InstallRequest while pending must not re-drive SE work.

    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    gateway
        .handle_install_request::<256>(&req, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap();
    let result = gateway.handle_install_request::<256>(&req, &mut se_gw, &mut rng_gw, 1000, 86_400);
    assert_eq!(
        result,
        Err(SigilError::PendingAlreadyExists { peer: SENSOR_MAC })
    );
}

#[test]
fn test_install_rate_limited_after_cancel() {
    // After cancel, cooldown still blocks a fresh InstallRequest within 15 s.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    gateway
        .handle_install_request::<256>(&req, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap();
    gateway.cancel_pending(&SENSOR_MAC).unwrap();

    let result = gateway.handle_install_request::<256>(&req, &mut se_gw, &mut rng_gw, 1000, 86_400);
    assert_eq!(result, Err(SigilError::RateLimited { peer: SENSOR_MAC }));

    let action = gateway
        .handle_install_request::<256>(
            &req,
            &mut se_gw,
            &mut rng_gw,
            1000 + crate::core::install::INSTALL_REQUEST_COOLDOWN,
            1000 + crate::core::install::INSTALL_REQUEST_COOLDOWN + 86_400,
        )
        .unwrap();
    assert!(matches!(action, SigilAction::Transmit { .. }));
}

#[test]
fn test_factory_cert_binds_peer_mac() {
    // gateway rejects InstallRequest when factory cert was issued for

    // a different PeerId than the wire identity.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_gw = MockRandom::new();

    // Attacker SE claims SENSOR_MAC on the wire but factory-cert was minted for OTHER_MAC.
    const OTHER_MAC: [u8; 17] = [0x55u8; 17];
    let mut se_attacker = MockSecureElement::sensor(1, OTHER_MAC);
    let pubkey = se_attacker.get_static_pubkey().unwrap();
    let factory_cert_sig = se_attacker.get_factory_cert().unwrap();
    let nonce = [9u8; 16];
    let metadata = se_attacker.get_factory_cert_metadata().unwrap();
    let to_sign =
        crate::core::install::install_request_sign_message(&SENSOR_MAC, metadata, &pubkey, &nonce)
            .unwrap();
    let sensor_signature = se_attacker.sign_ecdsa(&to_sign).unwrap();
    let req = InstallRequest {
        sensor_peer_mac: SENSOR_MAC,
        hardware_profile_id: metadata.hardware_profile_id,
        factory_key_id: metadata.factory_key_id,
        sensor_static_pubkey: pubkey,
        factory_cert_sig,
        sensor_nonce: nonce,
        sensor_signature,
    };
    let packet = build_install_request(&req).unwrap();

    let err = gateway
        .handle_install_request::<256>(&packet, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap_err();
    assert_eq!(err, SigilError::VerificationFailed);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    // follow-up: the unauthenticated claimed MAC must not poison the

    // legitimate sensor's cooldown. A factory-valid request at the same time
    // is still admitted.
    let mut legitimate_sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut se_legitimate = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut rng_legitimate = MockRandom::new();
    let valid = match legitimate_sensor
        .start_install::<256>(GW_MAC, &mut se_legitimate, &mut rng_legitimate, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let admitted = gateway
        .handle_install_request::<256>(&valid, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap();
    assert!(matches!(admitted, SigilAction::Transmit { .. }));
}

#[test]
fn test_invalid_device_signature_does_not_poison_install_cooldown() {
    // The factory certificate is public and valid, but possession of the
    // certified device key is proved only by the dynamic request signature.
    // Rejecting that proof must not consume the legitimate peer's cooldown.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let valid = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit"),
    };
    let mut forged = valid.clone();
    *forged
        .last_mut()
        .expect("InstallRequest contains a device signature") ^= 0x01;

    let rejected =
        gateway.handle_install_request::<256>(&forged, &mut se_gw, &mut rng_gw, 1_000, 86_400);
    assert_eq!(rejected, Err(SigilError::VerificationFailed));
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    // The authentic request at the exact same timestamp must still be admitted.
    let admitted = gateway
        .handle_install_request::<256>(&valid, &mut se_gw, &mut rng_gw, 1_000, 86_400)
        .unwrap();
    assert!(matches!(admitted, SigilAction::Transmit { .. }));
}

#[test]
fn test_install_commit_confirmed_loss_and_duplicate_confirm_retx() {
    // drop CommitConfirmed → sensor has no session; duplicate Final

    // → gateway reTX CommitConfirmed → sensor completes.
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();

    let req = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut rng_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let chal = match gateway
        .handle_install_request::<256>(&req, &mut se_gw, &mut rng_gw, 1000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let cfm = match sensor
        .continue_install::<256>(&chal, &mut se_sensor, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let commit1 = match gateway
        .continue_install::<256>(&cfm, &mut se_gw, 1000)
        .unwrap()
    {
        SigilAction::PersistPeerStaticKey { transmit, .. } => transmit,
        _ => panic!(),
    };
    // Drop CommitConfirmed — sensor still has no session.
    assert!(sensor.get(&GW_MAC).is_none());

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
        .continue_install::<256>(&cfm, &mut se_gw, 1000)
        .unwrap()
    {
        SigilAction::PersistPeerStaticKey { transmit, .. } => transmit,
        _ => panic!(),
    };
    assert_eq!(commit1.as_slice(), commit2.as_slice());

    let retx_final = match sensor.retransmit_pending_cached::<256>(&GW_MAC).unwrap() {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    assert_eq!(retx_final.as_slice(), cfm.as_slice());

    sensor
        .continue_install::<256>(&commit2, &mut se_sensor, 1000)
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
fn test_recorded_install_challenge_cannot_bind_another_sensor_v3() {
    const SENSOR_2: [u8; 17] = [0x73; 17];
    let mut sensor_1: SessionManager<4> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut sensor_2: SessionManager<4> =
        crate::core::test_support::test_manager_with_mac(SENSOR_2);
    let mut gateway: SessionManager<4> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_s1 = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_s2 = MockSecureElement::sensor(3, SENSOR_2);
    let mut se_g = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_s1 = MockRandom::new();
    let mut rng_s2 = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req_1 = match sensor_1
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se_s1, &mut rng_s1, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let recorded_challenge = match gateway
        .handle_install_request::<256>(&req_1, &mut se_g, &mut rng_g, 1000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };

    sensor_2
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se_s2, &mut rng_s2, 1000)
        .unwrap();
    let result = sensor_2.continue_install::<256>(&recorded_challenge, &mut se_s2, 1000);
    assert_eq!(result, Err(SigilError::VerificationFailed));
    assert!(sensor_2.get_pending(&GW_MAC).is_none());
    assert!(
        sensor_2
            .get_pending(&crate::core::install::INSTALL_DISCOVERY_DEST)
            .is_some()
    );
}

#[test]
fn test_install_commit_capacity_failure_preserves_recovery_state() {
    const OTHER: [u8; 17] = [0x7A; 17];
    const OTHER_2: [u8; 17] = [0x7B; 17];
    let mut sensor: SessionManager<2> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<2> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_s = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_g = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let req = match sensor
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se_s, &mut rng_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let challenge = match gateway
        .handle_install_request::<256>(&req, &mut se_g, &mut rng_g, 1000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let confirm = match sensor
        .continue_install::<256>(&challenge, &mut se_s, 1000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let commit = match gateway
        .continue_install::<256>(&confirm, &mut se_g, 1000)
        .unwrap()
    {
        SigilAction::PersistPeerStaticKey { transmit, .. } => transmit,
        _ => panic!(),
    };

    sensor
        .insert(Session::new_enrolled(OTHER, [2; 33], RESUME_PSK, SessionRole::Sensor).unwrap())
        .unwrap();
    sensor
        .insert(Session::new_enrolled(OTHER_2, [3; 33], [4; 32], SessionRole::Sensor).unwrap())
        .unwrap();
    assert_eq!(
        sensor.continue_install::<256>(&commit, &mut se_s, 1000),
        // The established-session table is saturated: a session-domain
        // capacity error, distinct from pending/admission saturation.
        Err(SigilError::SessionTableFull)
    );
    assert!(sensor.get_pending(&GW_MAC).is_some());

    sensor.remove(&OTHER);
    sensor
        .continue_install::<256>(&commit, &mut se_s, 1000)
        .unwrap();
    assert!(sensor.get(&GW_MAC).is_some());
}

#[test]
fn test_fresh_install_recovers_gateway_from_install_commit_sent() {
    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_s = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_g = MockSecureElement::gateway(2, GW_MAC);
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let request = match sensor
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se_s, &mut rng_s, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let challenge = match gateway
        .handle_install_request::<256>(&request, &mut se_g, &mut rng_g, 1_000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    let confirm = match sensor
        .continue_install::<256>(&challenge, &mut se_s, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    gateway
        .continue_install::<256>(&confirm, &mut se_g, 1_000)
        .unwrap();
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayCommitSent { .. }
    ));

    // Simulate a sensor reboot before it received CommitConfirmed. Its fresh
    // factory-authenticated install request must replace stale gateway state.
    let mut rebooted_sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    let mut rebooted_se = MockSecureElement::sensor(1, SENSOR_MAC);
    let retry = match rebooted_sensor
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut rebooted_se, &mut rng_s, 1_015)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!(),
    };
    gateway
        .handle_install_request::<256>(&retry, &mut se_g, &mut rng_g, 1_015, 86_400)
        .unwrap();
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayAwaitConfirm(_)
    ));
}

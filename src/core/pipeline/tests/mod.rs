#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for non-blocking packet pipeline

// Isolated semantic-handler tests (Event delivery, TimeSync cooldown).
mod handlers;

// Host-side performance measurement suite (dev-only, prints with --nocapture).
mod perf_measurements;

use crate::core::error::SigilError;
use crate::core::frame::{
    FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_OFFSET,
};
use crate::core::manager::SessionManager;
use crate::core::session::{DirectionalMaterial, Session, SessionRole};
use heapless::Vec;

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

/// Default local MAC used by [`crate::core::test_support::test_manager`].
const LOCAL: [u8; 17] = [0x10u8; 17];
/// Remote peer MAC used as the session table key on the local manager.
const REMOTE: [u8; 17] = [1u8; 17];

/// Helper: create a manager with one active session at the given expiry.
/// Session is keyed by [`REMOTE`]; egress outer header uses [`LOCAL`].
fn manager_with_active_session(expire: u32) -> SessionManager<16> {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    mgr.insert(
        Session::new_active(
            REMOTE,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]),
            SessionRole::Sensor,
            &RESUME_PSK,
            expire,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr
}

/// Helper for encrypt→decrypt loopback on a single manager.
/// Session is keyed by [`LOCAL`] (same as egress outer header) so a device can
/// process its own frames in unit tests.
fn manager_loopback(expire: u32) -> SessionManager<16> {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    mgr.insert(
        Session::new_active(
            LOCAL,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]),
            SessionRole::Sensor,
            &RESUME_PSK,
            expire,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr
}

fn event_pair() -> (SessionManager<4>, SessionManager<4>) {
    let mut sensor = crate::core::test_support::test_manager_with_mac(LOCAL);
    let mut gateway = crate::core::test_support::test_manager_with_mac(REMOTE);
    let material = DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]);
    sensor
        .insert(
            Session::new_active(
                REMOTE,
                [2u8; 33],
                material.clone(),
                SessionRole::Sensor,
                &RESUME_PSK,
                100_000,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    gateway
        .insert(
            Session::new_active(
                LOCAL,
                [2u8; 33],
                material,
                SessionRole::Gateway,
                &RESUME_PSK,
                100_000,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    (sensor, gateway)
}

fn transmitted<const MSG: usize>(action: crate::core::event::SigilAction<MSG>) -> Vec<u8, MSG> {
    match action {
        crate::core::event::SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("expected transmit"),
    }
}

#[test]
fn test_process_empty_packet() {
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let result = manager.process_incoming_packet::<200, 256>(&[], 1000);
    assert_eq!(result, Err(SigilError::MalformedFrame));
}

#[test]
fn test_process_short_packet() {
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let packet = [1u8; 10]; // Less than 17 bytes
    let result = manager.process_incoming_packet::<200, 256>(&packet, 1000);
    assert_eq!(result, Err(SigilError::MalformedFrame));
}

#[test]
fn test_deterministic_wire_fuzz_smoke_never_panics() {
    // Stable, dependency-free fuzz smoke for every length around the supported
    // LoRa frame budget. The corpus mixes arbitrary headers with inputs that
    // reach the encrypted Data parser, nonce-prefix and tag verification paths.
    let mut manager = manager_with_active_session(100_000);
    let mut state = 0xA5A5_1234u32;

    for len in 0..=300usize {
        let mut packet = [0u8; 300];
        for byte in &mut packet[..len] {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let _ = manager.process_incoming_packet::<200, 256>(&packet[..len], 1_000);

        if len >= OUTER_HEADER_SIZE {
            packet[..17].copy_from_slice(&REMOTE);
            packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
            packet[FRAME_TYPE_OFFSET] = FrameType::Data as u8;
            if len >= OUTER_HEADER_SIZE + 4 {
                packet[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4].copy_from_slice(&[0x01u8; 4]);
            }
            let _ = manager.process_incoming_packet::<200, 256>(&packet[..len], 1_000);
        }
    }
}

#[test]
fn test_process_unknown_peer() {
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [5u8; 17];

    // Packet with a valid-looking structure but unknown peer.
    // Must have at least the outer header (19 bytes) + encrypted payload.
    let mut packet = [0u8; 46];
    packet[..17].copy_from_slice(&peer);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::Data as u8;

    let result = manager.process_incoming_packet::<200, 256>(&packet, 1000);
    assert_eq!(result, Err(SigilError::UnknownSession { peer }));
}

#[test]
fn test_process_expired_session() {
    let mut manager = manager_with_active_session(1000);

    // Ingress outer header = remote sender identity (= REMOTE for this helper).
    let mut packet = [0u8; 46];
    packet[..17].copy_from_slice(&REMOTE);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::Data as u8;

    let result = manager.process_incoming_packet::<200, 256>(&packet, 2000);
    assert_eq!(result, Err(SigilError::SessionExpired { peer: REMOTE }));
}

#[test]
fn test_encrypt_then_decrypt_roundtrip() {
    let mut manager = manager_with_active_session(100_000);
    let plaintext = b"hello sensor";

    // Encrypt toward REMOTE — outer header carries LOCAL (sender identity).
    let frame = manager
        .encrypt_data::<256>(&REMOTE, plaintext, 1000)
        .unwrap();
    assert_eq!(&frame[..17], &LOCAL[..]);

    // Peer manager: local = REMOTE, session keyed by LOCAL (sender).
    let mut peer_mgr: SessionManager<16> = crate::core::test_support::test_manager_with_mac(REMOTE);
    peer_mgr
        .insert(
            Session::new_active(
                LOCAL,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]),
                SessionRole::Gateway,
                &RESUME_PSK,
                100_000,
                0,
            )
            .unwrap(),
        )
        .unwrap();

    let (event, _action) = peer_mgr
        .process_incoming_packet::<200, 256>(&frame, 1000)
        .unwrap();

    match event {
        crate::core::event::SigilEvent::Data { peer: p, payload } => {
            assert_eq!(p, LOCAL);
            assert_eq!(&payload[..], plaintext);
        }
        _ => panic!("Expected Data event"),
    }
}

#[test]
fn test_event_ack_roundtrip_clears_pending() {
    let (mut sensor, mut gateway) = event_pair();
    let send = sensor
        .send_event::<256>(&REMOTE, 1, b"door-open", 1_000)
        .unwrap();
    assert!(matches!(
        send,
        crate::core::event::SigilAction::Transmit {
            dest: REMOTE,
            wait_timeout_ms: Some(super::EVENT_ACK_TIMEOUT_MS),
            ..
        }
    ));
    let event_frame = transmitted(send);
    assert_eq!(sensor.get(&REMOTE).unwrap().pending_event_id(), Some(1));

    let (event, action) = gateway
        .process_incoming_packet::<200, 256>(&event_frame, 1_000)
        .unwrap();
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::Event {
            peer: LOCAL,
            event_id: 1,
            duplicate: false,
            ref payload,
        } if payload.as_slice() == b"door-open"
    ));
    assert!(matches!(
        action,
        crate::core::event::SigilAction::Success { peer: LOCAL }
    ));
    let ack = transmitted(gateway.ack_event::<256>(&LOCAL, 1, 1_000).unwrap());
    assert_eq!(ack[FRAME_TYPE_OFFSET], FrameType::EventAck as u8);

    let (ack_event, action) = sensor
        .process_incoming_packet::<200, 256>(&ack, 1_000)
        .unwrap();
    assert!(matches!(
        ack_event,
        crate::core::event::SigilEvent::EventAck {
            peer: REMOTE,
            event_id: 1,
        }
    ));
    assert!(matches!(
        action,
        crate::core::event::SigilAction::Success { peer: REMOTE }
    ));
    assert_eq!(sensor.get(&REMOTE).unwrap().pending_event_id(), None);
}

#[test]
fn test_lost_event_ack_retry_is_deduplicated_and_reencrypted() {
    let (mut sensor, mut gateway) = event_pair();
    let first = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 7, b"alarm", 1_000)
            .unwrap(),
    );
    let (first_event, first_action) = gateway
        .process_incoming_packet::<200, 256>(&first, 1_000)
        .unwrap();
    assert!(matches!(
        first_event,
        crate::core::event::SigilEvent::Event {
            event_id: 7,
            duplicate: false,
            ..
        }
    ));
    assert!(matches!(
        first_action,
        crate::core::event::SigilAction::Success { peer: LOCAL }
    ));
    // The application has durably processed the Event before asking Sigil to ACK.
    let first_ack = transmitted(gateway.ack_event::<256>(&LOCAL, 7, 1_000).unwrap());

    // Simulate ACK loss. Retrying the same id must consume a fresh AEAD counter
    // and therefore produce different wire bytes.
    let retry = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 7, b"alarm", 1_001)
            .unwrap(),
    );
    assert_ne!(first.as_slice(), retry.as_slice());
    let (duplicate, retry_action) = gateway
        .process_incoming_packet::<200, 256>(&retry, 1_001)
        .unwrap();
    assert!(matches!(
        duplicate,
        crate::core::event::SigilEvent::Event {
            event_id: 7,
            duplicate: true,
            ..
        }
    ));
    assert!(matches!(
        retry_action,
        crate::core::event::SigilAction::Success { peer: LOCAL }
    ));
    let retry_ack = transmitted(gateway.ack_event::<256>(&LOCAL, 7, 1_001).unwrap());
    sensor
        .process_incoming_packet::<200, 256>(&retry_ack, 1_001)
        .unwrap();
    assert_eq!(sensor.get(&REMOTE).unwrap().pending_event_id(), None);

    // The delayed first ACK is an AEAD replay and cannot affect later state.
    assert!(matches!(
        sensor.process_incoming_packet::<200, 256>(&first_ack, 1_001),
        Err(SigilError::Replay { .. })
    ));
}

#[test]
fn test_event_rejects_wrong_ack_and_parallel_event() {
    let (mut sensor, mut gateway) = event_pair();
    let _ = sensor
        .send_event::<256>(&REMOTE, 10, b"first", 1_000)
        .unwrap();
    assert_eq!(
        sensor.send_event::<256>(&REMOTE, 11, b"second", 1_000),
        Err(SigilError::EventAckPending {
            peer: REMOTE,
            event_id: 10,
        })
    );

    let wrong_ack = super::data::encrypt_application_payload::<4, 256>(
        &mut gateway.protocol_stores(),
        &LOCAL,
        FrameType::EventAck,
        &99u64.to_be_bytes(),
        1_000,
    )
    .unwrap();
    assert_eq!(
        sensor.process_incoming_packet::<200, 256>(&wrong_ack, 1_000),
        Err(SigilError::UnexpectedEventAck {
            peer: REMOTE,
            event_id: 99,
        })
    );
    assert_eq!(sensor.get(&REMOTE).unwrap().pending_event_id(), Some(10));
}

#[test]
fn test_event_cancel_consumes_id_and_small_buffer_is_fail_closed() {
    let (mut sensor, _) = event_pair();
    assert_eq!(
        sensor.send_event::<54>(&REMOTE, 1, b"x", 1_000),
        Err(SigilError::OutputBufferTooSmall)
    );
    assert_eq!(sensor.get(&REMOTE).unwrap().pending_event_id(), None);
    assert_eq!(sensor.get(&REMOTE).unwrap().tx_counter(), 0);

    sensor.send_event::<256>(&REMOTE, 1, b"x", 1_000).unwrap();
    sensor.cancel_pending_event(&REMOTE, 1).unwrap();
    assert_eq!(
        sensor.send_event::<256>(&REMOTE, 1, b"x", 1_001),
        Err(SigilError::InvalidEventId {
            peer: REMOTE,
            last: 1,
            received: 1,
        })
    );
}

#[test]
fn test_event_is_not_acknowledgeable_until_host_completion() {
    let (mut sensor, mut gateway) = event_pair();
    let first = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 1, b"critical", 1_000)
            .unwrap(),
    );
    gateway
        .process_incoming_packet::<200, 256>(&first, 1_000)
        .unwrap();

    // A retry received while the host is still processing the first delivery
    // must not be exposed as an ACK-able committed duplicate.
    let retry = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 1, b"critical", 1_001)
            .unwrap(),
    );
    assert_eq!(
        gateway.process_incoming_packet::<200, 256>(&retry, 1_001),
        Err(SigilError::EventDeliveryPending {
            peer: LOCAL,
            event_id: 1,
        })
    );

    // Once durable processing finishes, the original id can be ACKed.
    let ack = transmitted(gateway.ack_event::<256>(&LOCAL, 1, 1_002).unwrap());
    sensor
        .process_incoming_packet::<200, 256>(&ack, 1_002)
        .unwrap();
    assert_eq!(sensor.get(&REMOTE).unwrap().pending_event_id(), None);
}

#[test]
fn test_event_ack_capacity_failure_preserves_delivery_state() {
    let (mut sensor, mut gateway) = event_pair();
    let event = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 3, b"persisted", 1_000)
            .unwrap(),
    );
    gateway
        .process_incoming_packet::<200, 256>(&event, 1_000)
        .unwrap();

    assert_eq!(
        gateway.ack_event::<54>(&LOCAL, 3, 1_000),
        Err(SigilError::OutputBufferTooSmall)
    );
    assert_eq!(gateway.get(&LOCAL).unwrap().tx_counter(), 0);

    // No commit was lost when frame construction failed.
    let ack = transmitted(gateway.ack_event::<256>(&LOCAL, 3, 1_001).unwrap());
    sensor
        .process_incoming_packet::<200, 256>(&ack, 1_001)
        .unwrap();
}

#[test]
fn test_failed_gateway_processing_can_release_event_for_redelivery() {
    let (mut sensor, mut gateway) = event_pair();
    let first = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 4, b"database-write", 1_000)
            .unwrap(),
    );
    gateway
        .process_incoming_packet::<200, 256>(&first, 1_000)
        .unwrap();

    assert_eq!(
        gateway.release_event_delivery(&LOCAL, 99),
        Err(SigilError::UnexpectedEventDelivery {
            peer: LOCAL,
            event_id: 99,
        })
    );
    gateway.release_event_delivery(&LOCAL, 4).unwrap();

    let retry = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 4, b"database-write", 1_001)
            .unwrap(),
    );
    let (redelivery, _) = gateway
        .process_incoming_packet::<200, 256>(&retry, 1_001)
        .unwrap();
    assert!(matches!(
        redelivery,
        crate::core::event::SigilEvent::Event {
            event_id: 4,
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn test_event_and_ack_enforce_session_roles() {
    let (mut sensor, mut gateway) = event_pair();
    assert_eq!(
        gateway.send_event::<256>(&LOCAL, 1, b"forbidden", 1_000),
        Err(SigilError::WrongRole { peer: LOCAL })
    );
    assert_eq!(
        sensor.ack_event::<256>(&REMOTE, 1, 1_000),
        Err(SigilError::WrongRole { peer: REMOTE })
    );
    assert_eq!(
        sensor.release_event_delivery(&REMOTE, 1),
        Err(SigilError::WrongRole { peer: REMOTE })
    );
}

#[test]
fn test_event_type_tampering_fails_authentication_without_consuming_counter() {
    let (mut sensor, mut gateway) = event_pair();
    let original = transmitted(
        sensor
            .send_event::<256>(&REMOTE, 5, b"alarm", 1_000)
            .unwrap(),
    );
    let mut tampered = original.clone();
    tampered[FRAME_TYPE_OFFSET] = FrameType::Data as u8;

    assert_eq!(
        gateway.process_incoming_packet::<200, 256>(&tampered, 1_000),
        Err(SigilError::VerificationFailed)
    );
    assert_eq!(gateway.get(&LOCAL).unwrap().rx_counter(), 0);

    // The authentic frame with the same counter remains acceptable.
    let (event, _) = gateway
        .process_incoming_packet::<200, 256>(&original, 1_000)
        .unwrap();
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::Event {
            event_id: 5,
            duplicate: false,
            ..
        }
    ));
}

#[test]
fn test_flipped_frame_type_data_to_renew_fails_aad() {
    // C2 regression: encrypt as Data, flip frame_type to RenewRequest.
    // Routing classifies as renew, but decrypt under Renew AAD must fail.
    use crate::core::test_support::{MockRandom, MockSecureElement};

    let mut sender = manager_with_active_session(100_000);
    let plaintext = [0xABu8; 33];
    let mut frame = sender
        .encrypt_data::<256>(&REMOTE, &plaintext, 1000)
        .unwrap();
    assert_eq!(frame[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(frame[FRAME_TYPE_OFFSET], FrameType::Data as u8);

    // Attacker flips the clear-text discriminator.
    frame[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    frame[FRAME_TYPE_OFFSET] = FrameType::RenewRequest as u8;

    // Gateway indexes by sender MAC (LOCAL) carried in the outer header.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(REMOTE);
    gateway
        .insert(
            Session::new_active(
                LOCAL,
                [2u8; 33],
                DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]),
                SessionRole::Gateway,
                &RESUME_PSK,
                100_000,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    let mut se = MockSecureElement::default();
    let mut rng = MockRandom::new();
    let result =
        gateway.handle_renew_request::<256>(&frame, &mut se, &mut rng, 1000, 1000 + 86_400);
    assert_eq!(result, Err(SigilError::VerificationFailed));
    let session = gateway.get(&LOCAL).unwrap();
    assert_eq!(session.session_key().unwrap(), &[0x42u8; 32]);
}

#[test]
fn test_encrypt_unknown_peer() {
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let plaintext = b"test data";

    let result = manager.encrypt_data::<256>(&REMOTE, plaintext, 1000);
    assert_eq!(result, Err(SigilError::UnknownSession { peer: REMOTE }));
}

#[test]
fn test_encrypt_expired_session() {
    let mut manager = manager_with_active_session(1000);
    let plaintext = b"test data";
    let result = manager.encrypt_data::<256>(&REMOTE, plaintext, 2000);
    assert_eq!(result, Err(SigilError::SessionExpired { peer: REMOTE }));
}

#[test]
fn test_encrypt_advances_tx_counter() {
    let mut manager = manager_with_active_session(100_000);

    // First encryption → counter 0
    manager
        .encrypt_data::<256>(&REMOTE, b"first", 1000)
        .unwrap();
    assert_eq!(manager.get(&REMOTE).unwrap().tx_counter, 1);

    // Second encryption → counter 1
    manager
        .encrypt_data::<256>(&REMOTE, b"second", 1000)
        .unwrap();
    assert_eq!(manager.get(&REMOTE).unwrap().tx_counter, 2);
}

#[test]
fn test_directional_keys_prevent_cross_direction_nonce_reuse() {
    // regression: with distinct directional halves, encrypting

    // counter-0 in both directions must NOT yield matching wire nonces, and
    // ciphertext XOR must not equal plaintext XOR (ChaCha20 keystream reuse).
    use crate::core::frame::OUTER_HEADER_SIZE;
    use crate::core::test_support::{pair_active_sessions, test_manager_with_mac};

    const SENSOR_MAC: [u8; 17] = [0xA1u8; 17];
    const GW_MAC: [u8; 17] = [0xB2u8; 17];
    let pt_s = b"sensor-hello!!!!"; // 16 bytes
    let pt_g = b"gateway-world!!!"; // 16 bytes

    let (sensor_sess, gateway_sess) = pair_active_sessions(
        SENSOR_MAC,
        GW_MAC,
        [2u8; 33],
        [0x55u8; 32],
        [0xAAu8; 4],
        RESUME_PSK,
        100_000,
        0,
    );
    // Confirm halves differ and roles map correctly.
    assert_ne!(sensor_sess.session_key(), sensor_sess.rx_session_key());
    assert_eq!(sensor_sess.session_key(), gateway_sess.rx_session_key());
    assert_eq!(sensor_sess.rx_session_key(), gateway_sess.session_key());

    let mut sensor = test_manager_with_mac::<16>(SENSOR_MAC);
    let mut gateway = test_manager_with_mac::<16>(GW_MAC);
    sensor.insert(sensor_sess).unwrap();
    gateway.insert(gateway_sess).unwrap();

    let frame_s = sensor.encrypt_data::<256>(&GW_MAC, pt_s, 1000).unwrap();
    let frame_g = gateway
        .encrypt_data::<256>(&SENSOR_MAC, pt_g, 1000)
        .unwrap();

    let prefix_s = &frame_s[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4];
    let prefix_g = &frame_g[OUTER_HEADER_SIZE..OUTER_HEADER_SIZE + 4];
    assert_ne!(
        prefix_s, prefix_g,
        "wire nonce prefixes must differ across directions"
    );

    let ct_s = &frame_s[OUTER_HEADER_SIZE + 12..];
    let ct_g = &frame_g[OUTER_HEADER_SIZE + 12..];
    // Compare first 16 ciphertext bytes (before Poly1305 tag).
    let n = 16;
    let mut xor_ct = [0u8; 16];
    let mut xor_pt = [0u8; 16];
    for i in 0..n {
        xor_ct[i] = ct_s[i] ^ ct_g[i];
        xor_pt[i] = pt_s[i] ^ pt_g[i];
    }
    assert_ne!(
        xor_ct, xor_pt,
        "keystream reuse would make ciphertext XOR == plaintext XOR"
    );

    // Cross-decrypt still works (sensor decrypts gateway frame).
    let (ev, _) = sensor
        .process_incoming_packet::<200, 256>(&frame_g, 1000)
        .unwrap();
    match ev {
        crate::core::event::SigilEvent::Data { payload, .. } => {
            assert_eq!(&payload[..], pt_g);
        }
        _ => panic!("expected Data"),
    }
}

#[test]
fn test_time_sync_is_gateway_only_authenticated_and_replay_protected() {
    use crate::core::test_support::{pair_active_sessions, test_manager_with_mac};
    const SENSOR_MAC: [u8; 17] = [0xC1; 17];
    const GW_MAC: [u8; 17] = [0xC2; 17];
    let (sensor_session, gateway_session) = pair_active_sessions(
        SENSOR_MAC, GW_MAC, [2u8; 33], [0x33; 32], [0x44; 4], RESUME_PSK, 100_000, 0,
    );
    let mut sensor = test_manager_with_mac::<4>(SENSOR_MAC);
    let mut gateway = test_manager_with_mac::<4>(GW_MAC);
    sensor.insert(sensor_session).unwrap();
    gateway.insert(gateway_session).unwrap();

    assert_eq!(
        sensor.encrypt_time_sync::<128>(&GW_MAC, 10, 1, 2, 1_000),
        Err(SigilError::WrongRole { peer: GW_MAC })
    );

    let frame = gateway
        .encrypt_time_sync::<128>(&SENSOR_MAC, 1_700_000_000, 42, 3, 1_000)
        .unwrap();
    let (event, _) = sensor
        .process_incoming_packet::<32, 128>(&frame, 1_000)
        .unwrap();
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::TimeSync {
            peer: GW_MAC,
            gateway_time: 1_700_000_000,
            sync_sequence: 42,
            uncertainty_secs: 3,
        }
    ));
    assert!(matches!(
        sensor.process_incoming_packet::<32, 128>(&frame, 1_000),
        Err(SigilError::Replay { .. })
    ));

    // A valid AEAD TimeSync in the wrong direction is rejected by the
    // gateway-role receiver. The private primitive simulates a nonconforming
    // peer implementation; the public sensor API already rejects this send.
    let wrong_direction = super::data::encrypt_application_payload::<4, 128>(
        &mut sensor.protocol_stores(),
        &GW_MAC,
        FrameType::TimeSync,
        &[0u8; 10],
        1_000,
    )
    .unwrap();
    assert_eq!(
        gateway.process_incoming_packet::<32, 128>(&wrong_direction, 1_000),
        Err(SigilError::WrongRole { peer: SENSOR_MAC })
    );
}

#[test]
fn test_time_sync_request_roundtrip_cooldown_and_response() {
    let (mut sensor, mut gateway) = event_pair();

    assert_eq!(
        gateway.request_time_sync::<128>(&LOCAL, 1_000),
        Err(SigilError::WrongRole { peer: LOCAL })
    );
    let request = sensor.request_time_sync::<128>(&REMOTE, 1_000).unwrap();
    assert_eq!(request[FRAME_TYPE_OFFSET], FrameType::TimeSyncRequest as u8);
    let (event, action) = gateway
        .process_incoming_packet::<32, 128>(&request, 1_000)
        .unwrap();
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::TimeSyncRequest { peer: LOCAL }
    ));
    assert!(matches!(
        action,
        crate::core::event::SigilAction::Success { peer: LOCAL }
    ));

    let response = gateway
        .encrypt_time_sync::<128>(&LOCAL, 1_700_000_123, 8, 2, 1_000)
        .unwrap();
    let (sync, _) = sensor
        .process_incoming_packet::<32, 128>(&response, 1_000)
        .unwrap();
    assert!(matches!(
        sync,
        crate::core::event::SigilEvent::TimeSync {
            gateway_time: 1_700_000_123,
            sync_sequence: 8,
            uncertainty_secs: 2,
            ..
        }
    ));

    // A fresh authenticated request is still throttled; the AEAD counter is
    // consumed, preventing the rejected packet from being replayed later.
    let too_soon = sensor.request_time_sync::<128>(&REMOTE, 1_001).unwrap();
    assert_eq!(
        gateway.process_incoming_packet::<32, 128>(&too_soon, 1_001),
        Err(SigilError::RateLimited { peer: LOCAL })
    );
    assert!(matches!(
        gateway.process_incoming_packet::<32, 128>(&too_soon, 1_015),
        Err(SigilError::Replay { .. })
    ));

    let after_cooldown = sensor.request_time_sync::<128>(&REMOTE, 1_015).unwrap();
    assert!(matches!(
        gateway.process_incoming_packet::<32, 128>(&after_cooldown, 1_015),
        Ok((
            crate::core::event::SigilEvent::TimeSyncRequest { peer: LOCAL },
            crate::core::event::SigilAction::Success { peer: LOCAL }
        ))
    ));
}

#[test]
fn test_time_sync_request_rejects_wrong_direction_malformed_and_small_buffer() {
    let (mut sensor, mut gateway) = event_pair();

    assert_eq!(
        sensor.request_time_sync::<46>(&REMOTE, 1_000),
        Err(SigilError::OutputBufferTooSmall)
    );
    assert_eq!(sensor.get(&REMOTE).unwrap().tx_counter(), 0);

    let wrong_direction = super::data::encrypt_application_payload::<4, 128>(
        &mut gateway.protocol_stores(),
        &LOCAL,
        FrameType::TimeSyncRequest,
        &[],
        1_000,
    )
    .unwrap();
    assert_eq!(
        sensor.process_incoming_packet::<32, 128>(&wrong_direction, 1_000),
        Err(SigilError::WrongRole { peer: REMOTE })
    );

    let malformed = super::data::encrypt_application_payload::<4, 128>(
        &mut sensor.protocol_stores(),
        &REMOTE,
        FrameType::TimeSyncRequest,
        &[0x01],
        1_000,
    )
    .unwrap();
    // An authenticated payload whose shape contradicts its frame type is
    // malformed wire input.
    assert_eq!(
        gateway.process_incoming_packet::<32, 128>(&malformed, 1_000),
        Err(SigilError::MalformedFrame)
    );
}

#[test]
fn test_decrypt_advances_rx_counter() {
    let mut manager = manager_loopback(100_000);

    let real_frame = manager.encrypt_data::<256>(&LOCAL, b"x", 1000).unwrap();
    let (_, _) = manager
        .process_incoming_packet::<200, 256>(&real_frame, 1000)
        .unwrap();

    assert_eq!(manager.get(&LOCAL).unwrap().rx_counter, 1);
}

#[test]
fn test_replay_rejected() {
    let mut manager = manager_loopback(100_000);

    let frame = manager
        .encrypt_data::<256>(&LOCAL, b"secret", 1000)
        .unwrap();

    manager
        .process_incoming_packet::<200, 256>(&frame, 1000)
        .unwrap();

    let result = manager.process_incoming_packet::<200, 256>(&frame, 1000);
    assert_eq!(
        result,
        Err(SigilError::Replay {
            peer: LOCAL,
            expected: 1,
            received: 0,
        })
    );
}

#[test]
fn test_non_monotonic_counter_rejected() {
    let mut manager = manager_loopback(100_000);

    let frame0 = manager.encrypt_data::<256>(&LOCAL, b"a", 1000).unwrap();
    let frame1 = manager.encrypt_data::<256>(&LOCAL, b"b", 1000).unwrap();

    manager
        .process_incoming_packet::<200, 256>(&frame1, 1000)
        .unwrap();

    let result = manager.process_incoming_packet::<200, 256>(&frame0, 1000);
    assert_eq!(
        result,
        Err(SigilError::Replay {
            peer: LOCAL,
            expected: 2,
            received: 0,
        })
    );
}

#[test]
fn test_wrong_nonce_prefix_rejected() {
    let mut manager = manager_loopback(100_000);

    let mut frame = manager.encrypt_data::<256>(&LOCAL, b"data", 1000).unwrap();
    // Flip the first nonce-prefix byte (immediately after the 19-byte outer header).
    use crate::core::frame::OUTER_HEADER_SIZE;
    frame[OUTER_HEADER_SIZE] ^= 0xFF;

    let result = manager.process_incoming_packet::<200, 256>(&frame, 1000);
    // A corrupted nonce prefix fails AEAD authentication: malformed input.
    assert!(matches!(result, Err(SigilError::MalformedFrame)));
}

#[test]
fn test_truncated_encrypted_frame_rejected() {
    let mut manager = manager_loopback(100_000);

    let mut short_frame = [0u8; 30];
    short_frame[..17].copy_from_slice(&LOCAL);
    short_frame[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    short_frame[FRAME_TYPE_OFFSET] = FrameType::Data as u8;

    let result = manager.process_incoming_packet::<200, 256>(&short_frame, 1000);
    assert_eq!(result, Err(SigilError::MalformedFrame));
}

#[test]
fn test_process_install_frame_classified() {
    // InstallRequest is classified per-step with NeedsHostDispatch,

    // not Success. Frame bytes are bulk-copied for the host handler.
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [3u8; 17];

    let mut packet = [0u8; 40];
    packet[..17].copy_from_slice(&peer);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::InstallRequest as u8;
    packet[OUTER_HEADER_SIZE] = 0xAA;
    packet[39] = 0xBB;

    let (event, action) = manager
        .process_incoming_packet::<200, 256>(&packet, 1000)
        .unwrap();

    match event {
        crate::core::event::SigilEvent::InstallRequest { peer: p, frame } => {
            assert_eq!(p, peer);
            assert_eq!(&frame[..], &packet[..]);
        }
        _ => panic!("Expected InstallRequest event"),
    }
    assert!(matches!(
        action,
        crate::core::event::SigilAction::NeedsHostDispatch { peer: p } if p == peer
    ));
}

#[test]
fn test_process_install_challenge_and_confirm_classified() {
    // Challenge/Confirm must NOT surface as InstallRequest.

    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [3u8; 17];

    let mut chal = [0u8; 40];
    chal[..17].copy_from_slice(&peer);
    chal[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    chal[FRAME_TYPE_OFFSET] = FrameType::InstallChallenge as u8;
    let (event, action) = manager
        .process_incoming_packet::<200, 256>(&chal, 1000)
        .unwrap();
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::InstallChallenge { peer: p,.. } if p == peer
    ));
    assert!(matches!(
        action,
        crate::core::event::SigilAction::NeedsHostDispatch { .. }
    ));

    let mut conf = [0u8; 40];
    conf[..17].copy_from_slice(&peer);
    conf[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    conf[FRAME_TYPE_OFFSET] = FrameType::InstallConfirm as u8;
    let (event, _) = manager
        .process_incoming_packet::<200, 256>(&conf, 1000)
        .unwrap();
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::InstallConfirm { peer: p,.. } if p == peer
    ));
}

#[test]
fn test_handshake_frame_copy_rejects_oversized_msg() {
    // MSG (not DATA) bounds handshake frame copies.

    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let mut packet = [0u8; 40];
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::InstallRequest as u8;

    let result = manager.process_incoming_packet::<200, 16>(&packet, 1000);
    // An undersized MSG generic constant is an integration buffer-sizing error.
    assert_eq!(result, Err(SigilError::OutputBufferTooSmall));
}

#[test]
fn test_install_challenge_fits_with_data_max_200() {
    // Regression: InstallChallenge wire = 219 > DATA_MAX (200), but

    // process_incoming_packet::<200, 256> must still classify it via MSG.
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [9u8; 17];
    let mut packet = [0u8; 219];
    packet[..17].copy_from_slice(&peer);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::InstallChallenge as u8;
    packet[215] = 0xEE;

    let (event, action) = manager
        .process_incoming_packet::<200, 256>(&packet, 1000)
        .expect("InstallChallenge must fit in MSG=256 even when DATA=200");

    match event {
        crate::core::event::SigilEvent::InstallChallenge { peer: p, frame } => {
            assert_eq!(p, peer);
            assert_eq!(frame.len(), 219);
            assert_eq!(frame[215], 0xEE);
        }
        _ => panic!("Expected InstallChallenge"),
    }
    assert!(matches!(
        action,
        crate::core::event::SigilAction::NeedsHostDispatch { peer: p } if p == peer
    ));
}

#[test]
fn test_install_request_fits_with_data_max_200() {
    // InstallRequest wire = 215 > DATA_MAX; MSG=256 must accept it.
    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [8u8; 17];
    let mut packet = [0u8; 215];
    packet[..17].copy_from_slice(&peer);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::InstallRequest as u8;

    let (event, _) = manager
        .process_incoming_packet::<200, 256>(&packet, 1000)
        .expect("InstallRequest must fit in MSG=256 even when DATA=200");
    assert!(matches!(
        event,
        crate::core::event::SigilEvent::InstallRequest { peer: p,.. } if p == peer
    ));
}

#[test]
fn test_process_renew_steps_classified() {
    // Renew Request / Challenge / Ack are distinct events.

    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [4u8; 17];

    for (ft, expect_req, expect_chal, expect_ack) in [
        (FrameType::RenewRequest, true, false, false),
        (FrameType::RenewChallenge, false, true, false),
        (FrameType::RenewConfirm, false, false, true),
    ] {
        let mut packet = [0u8; 40];
        packet[..17].copy_from_slice(&peer);
        packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
        packet[FRAME_TYPE_OFFSET] = ft as u8;
        let (event, action) = manager
            .process_incoming_packet::<200, 256>(&packet, 1000)
            .unwrap();
        assert_eq!(
            matches!(
                event,
                crate::core::event::SigilEvent::RenewRequest { peer: p,.. } if p == peer
            ),
            expect_req
        );
        assert_eq!(
            matches!(
                event,
                crate::core::event::SigilEvent::RenewChallenge { peer: p,.. } if p == peer
            ),
            expect_chal
        );
        assert_eq!(
            matches!(
                event,
                crate::core::event::SigilEvent::RenewConfirm { peer: p,.. } if p == peer
            ),
            expect_ack
        );
        assert!(matches!(
            action,
            crate::core::event::SigilAction::NeedsHostDispatch { .. }
        ));
    }
}

#[test]
fn test_process_resume_steps_classified() {
    // Resume Request / Challenge / Confirm are distinct events.

    let mut manager: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [5u8; 17];

    for (ft, expect_req, expect_chal, expect_conf) in [
        (FrameType::ResumeRequest, true, false, false),
        (FrameType::ResumeChallenge, false, true, false),
        (FrameType::ResumeConfirm, false, false, true),
    ] {
        let mut packet = [0u8; 40];
        packet[..17].copy_from_slice(&peer);
        packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
        packet[FRAME_TYPE_OFFSET] = ft as u8;
        let (event, action) = manager
            .process_incoming_packet::<200, 256>(&packet, 1000)
            .unwrap();
        assert_eq!(
            matches!(
                event,
                crate::core::event::SigilEvent::ResumeRequest { peer: p,.. } if p == peer
            ),
            expect_req
        );
        assert_eq!(
            matches!(
                event,
                crate::core::event::SigilEvent::ResumeChallenge { peer: p,.. } if p == peer
            ),
            expect_chal
        );
        assert_eq!(
            matches!(
                event,
                crate::core::event::SigilEvent::ResumeConfirm { peer: p,.. } if p == peer
            ),
            expect_conf
        );
        assert!(matches!(
            action,
            crate::core::event::SigilAction::NeedsHostDispatch { .. }
        ));
    }
}

//! Public host-flow architecture-contract tests.
//!
//! These suites walk **representative firmware usage flows through the
//! public API only** — `SessionManager::new`, ingress classification via
//! `process_incoming_packet`, `encrypt_data`, the role-gated handshake
//! entry points, `tick`, `cancel_pending`, `retransmit_pending_cached`,
//! and the post-reboot `Session::new_enrolled` reload path. They pin the
//! public surface *shape*: any signature, event, or action change that
//! would break host firmware breaks these tests first.
//!
//! Gating: the file compiles under every session-bearing configuration.
//! Role-exclusive flows are individually feature-gated so sensor-only,
//! gateway-only, and two-role builds each execute their own facade flow;
//! the cross-decryption flow uses only role-agnostic API and runs
//! everywhere. Handshake crypto uses the deterministic test mocks; no
//! real secure element is required.

use crate::core::error::SigilError;
use crate::core::event::{SigilAction, SigilEvent};
use crate::core::manager::SessionManager;
use crate::core::session::{DirectionalMaterial, PeerId, Session, SessionRole};
use crate::core::test_support::{MockRandom, MockSecureElement, TEST_FACTORY_PUBKEY};

const SENSOR_MAC: PeerId = [0xA1u8; 17];
const GATEWAY_MAC: PeerId = [0xB2u8; 17];
const PEER_PSK: [u8; 32] = [0x5Du8; 32];

/// Fresh sensor-side manager built exactly as a host would build it.
fn sensor_manager<const N: usize>() -> SessionManager<N> {
    SessionManager::new(TEST_FACTORY_PUBKEY, SENSOR_MAC).expect("valid factory key")
}

/// Fresh gateway-side manager built exactly as a host would build it.
fn gateway_manager<const N: usize>() -> SessionManager<N> {
    SessionManager::new(TEST_FACTORY_PUBKEY, GATEWAY_MAC).expect("valid factory key")
}

/// Inserts a symmetric-material active session into `mgr` so AEAD egress /
/// ingress can be exercised without a completed handshake. Symmetric halves
/// make two managers mutual decryption peers while keeping their roles
/// distinct for direction checks.
fn insert_symmetric_session(mgr: &mut SessionManager<4>, peer: PeerId, role: SessionRole) {
    mgr.insert(
        Session::new_active(
            peer,
            [0x02u8; 33],
            DirectionalMaterial::symmetric_for_test([0x55u8; 32], [0xAAu8; 4]),
            role,
            PEER_PSK,
            100_000,
            0,
        )
        .expect("active test session"),
    )
    .expect("session table has room");
}

/// Builds a fully attested install request frame exactly as sensor firmware
/// would emit it through the deterministic mocks: factory certificate tag
/// over the PeerId ‖ pubkey message plus the request proof signature.
/// Shared with the capacity-domain suite in this tests tree.
#[cfg(feature = "gateway")]
pub(super) fn build_install_request_frame(
    se: &mut MockSecureElement,
    sensor_mac: PeerId,
    hardware_profile_id: u8,
) -> Result<heapless::Vec<u8, 215>, SigilError> {
    use crate::core::install::wire::{InstallRequest, build_install_request};
    use crate::core::install::{
        FACTORY_PRODUCT_ID_SENSOR, factory_cert_message, install_request_sign_message,
    };
    use crate::core::traits::{FactoryCertificateMetadata, SecureElement};

    let metadata = FactoryCertificateMetadata {
        hardware_profile_id,
        factory_key_id: 1,
    };
    let pubkey = [0x02u8; 33];
    let cert_msg = factory_cert_message(FACTORY_PRODUCT_ID_SENSOR, metadata, &sensor_mac, &pubkey)?;
    let cert_sig = se.sign_ecdsa(&cert_msg)?;
    let nonce = [hardware_profile_id; 16];
    let signed = install_request_sign_message(&sensor_mac, metadata, &pubkey, &nonce)?;
    let sig = se.sign_ecdsa(&signed)?;
    build_install_request(&InstallRequest {
        sensor_peer_mac: sensor_mac,
        hardware_profile_id,
        factory_key_id: 1,
        sensor_static_pubkey: pubkey,
        factory_cert_sig: cert_sig,
        sensor_nonce: nonce,
        sensor_signature: sig,
    })
}

/// Builds a valid clear-text resume request frame (nonce ‖ PSK-derived MAC)
/// addressed from `sensor_mac`, as rebooted sensor firmware emits it before
/// any session key exists. The 32-byte body is laid out directly here because
/// the wire builder for this fixed clear-text shape is sensor-gated; gateway
/// parsers accept exactly nonce ‖ req MAC, so both sides agree byte-for-byte.
/// Shared with the capacity-domain suite.
#[cfg(feature = "gateway")]
pub(super) fn build_resume_request_frame(
    psk: &[u8; 32],
    sensor_mac: PeerId,
    nonce: [u8; 16],
) -> heapless::Vec<u8, 256> {
    use crate::core::frame::{FrameType, build_header};
    use crate::core::resume::wire::resume_request_mac;

    let req_mac = resume_request_mac(psk, &sensor_mac, &nonce).expect("request MAC derives");
    let mut frame = heapless::Vec::<u8, 256>::new();
    frame
        .extend_from_slice(&build_header(&sensor_mac, FrameType::ResumeRequest))
        .expect("header fits");
    // Direct assembly of the fixed clear-text request body: nonce ‖ req MAC.
    frame.extend_from_slice(&nonce).expect("nonce fits");
    frame.extend_from_slice(&req_mac).expect("req MAC fits");
    frame
}

// Role-agnostic public data path (runs in every session-bearing build).

// Cross-decryption roles: Data frames carry no role direction constraint on
// ingress or egress, so mono-role builds run this flow with their single
// available role on both managers; only the two-role build pairs a real
// Sensor against a real Gateway.
/// Uplink (first) manager role — Sensor wherever that variant exists.
#[cfg(feature = "sensor")]
const UPLINK_SESSION_ROLE: SessionRole = SessionRole::Sensor;
#[cfg(not(feature = "sensor"))]
const UPLINK_SESSION_ROLE: SessionRole = SessionRole::Gateway;

/// Inbound (second) manager role — Gateway wherever that variant exists.
#[cfg(feature = "gateway")]
const INBOUND_SESSION_ROLE: SessionRole = SessionRole::Gateway;
#[cfg(not(feature = "gateway"))]
const INBOUND_SESSION_ROLE: SessionRole = SessionRole::Sensor;

#[test]
fn data_frames_route_through_the_public_facade_in_both_directions() {
    let mut sensor = sensor_manager::<4>();
    let mut gateway = gateway_manager::<4>();
    insert_symmetric_session(&mut sensor, GATEWAY_MAC, UPLINK_SESSION_ROLE);
    insert_symmetric_session(&mut gateway, SENSOR_MAC, INBOUND_SESSION_ROLE);

    // Sensor → gateway application frame: encrypted through the public
    // egress primitive, classified and decrypted through public ingress.
    let uplink = sensor
        .encrypt_data::<256>(&GATEWAY_MAC, b"sensor-uplink", 1_000)
        .expect("uplink encrypts");
    let (event, _) = gateway
        .process_incoming_packet::<200, 256>(&uplink, 1_000)
        .expect("gateway decrypts uplink");
    match event {
        SigilEvent::Data { peer, payload } => {
            assert_eq!(peer, SENSOR_MAC);
            assert_eq!(&payload[..], b"sensor-uplink");
        }
        other => panic!("expected Data event, got {other:?}"),
    }

    // Gateway → sensor application frame over the same public primitives.
    let downlink = gateway
        .encrypt_data::<256>(&SENSOR_MAC, b"gw-downlink", 1_000)
        .expect("downlink encrypts");
    let (event, _) = sensor
        .process_incoming_packet::<200, 256>(&downlink, 1_000)
        .expect("sensor decrypts downlink");
    match event {
        SigilEvent::Data { peer, payload } => {
            assert_eq!(peer, GATEWAY_MAC);
            assert_eq!(&payload[..], b"gw-downlink");
        }
        other => panic!("expected Data event, got {other:?}"),
    }
}

// Sensor-role public flow.

#[cfg(feature = "sensor")]
#[test]
fn sensor_public_host_flow_smoke() {
    use crate::core::install::INSTALL_DISCOVERY_DEST;

    let mut mgr = sensor_manager::<4>();
    let mut se = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut rng = MockRandom::new();

    // Mandatory discovery install start: TX a broadcast-addressed request.
    match mgr
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se, &mut rng, 1_000)
        .expect("discovery install starts")
    {
        SigilAction::Transmit {
            dest,
            wait_timeout_ms,
            ..
        } => {
            assert_eq!(dest, INSTALL_DISCOVERY_DEST);
            assert!(wait_timeout_ms.is_some(), "handshake TX expects a reply");
        }
        other => panic!("expected Transmit from start_install, got {other:?}"),
    }
    assert_eq!(mgr.pending_len(), 1);

    // Cached retransmission is only valid post-Final: pre-Final state must
    // reject with the canonical transition error.
    assert_eq!(
        mgr.retransmit_pending_cached::<256>(&INSTALL_DISCOVERY_DEST),
        Err(SigilError::InvalidStep {
            peer: INSTALL_DISCOVERY_DEST
        })
    );

    // Manual host-timer policy: cancel frees the pending slot.
    mgr.cancel_pending(&INSTALL_DISCOVERY_DEST)
        .expect("cancel of a live pending succeeds");
    assert_eq!(mgr.pending_len(), 0);

    // Optional tick housekeeping on an empty table is a no-op.
    assert!(mgr.tick(2_000).is_empty());

    // Post-reboot reload path: enrollment-only session restore, then a
    // resume handshake may be started without any persisted AEAD key.
    mgr.insert(
        Session::new_enrolled(GATEWAY_MAC, [0x02u8; 33], PEER_PSK, SessionRole::Sensor)
            .expect("enrolled session"),
    )
    .expect("table has room");
    match mgr
        .start_resume::<256>(GATEWAY_MAC, &mut se, &mut rng, 3_000)
        .expect("resume starts from enrolled state")
    {
        SigilAction::Transmit { dest, .. } => assert_eq!(dest, GATEWAY_MAC),
        other => panic!("expected Transmit from start_resume, got {other:?}"),
    }
}

// Gateway-role public flow.

#[cfg(feature = "gateway")]
#[test]
fn gateway_public_host_flow_smoke() {
    let mut mgr = gateway_manager::<4>();
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GATEWAY_MAC);
    let mut rng = MockRandom::new();

    // A sensor install request arrives: classify first, then handle.
    let request = build_install_request_frame(&mut se_sensor, SENSOR_MAC, 0x11)
        .expect("request frame builds");
    let (event, action) = mgr
        .process_incoming_packet::<200, 256>(&request, 1_000)
        .expect("classification succeeds");
    match (event, action) {
        (
            SigilEvent::InstallRequest { peer, .. },
            SigilAction::NeedsHostDispatch {
                peer: dispatch_peer,
            },
        ) => {
            assert_eq!(peer, SENSOR_MAC);
            assert_eq!(dispatch_peer, SENSOR_MAC);
        }
        other => panic!("expected InstallRequest classification, got {other:?}"),
    }
    match mgr
        .handle_install_request::<256>(&request, &mut se_gw, &mut rng, 1_000, 86_400)
        .expect("attested request is accepted")
    {
        SigilAction::Transmit { dest, payload, .. } => {
            assert_eq!(dest, SENSOR_MAC);
            assert!(!payload.is_empty());
        }
        other => panic!("expected challenge Transmit, got {other:?}"),
    }
    assert_eq!(mgr.pending_len(), 1);
    mgr.cancel_pending(&SENSOR_MAC)
        .expect("host may abandon the handshake");

    // Post-reboot sensor resume ingress: MAC over the durable PSK is
    // verified before any SE work.
    mgr.insert(
        Session::new_enrolled(SENSOR_MAC, [0x02u8; 33], PEER_PSK, SessionRole::Gateway)
            .expect("enrolled gateway session"),
    )
    .expect("table has room");
    let resume_req = build_resume_request_frame(&PEER_PSK, SENSOR_MAC, [0x33u8; 16]);
    let (event, _) = mgr
        .process_incoming_packet::<200, 256>(&resume_req, 4_000)
        .expect("resume request classifies");
    assert!(matches!(event, SigilEvent::ResumeRequest { peer, .. } if peer == SENSOR_MAC));
    match mgr
        .handle_resume_request::<256>(&resume_req, &mut se_gw, &mut rng, 4_000, 86_400)
        .expect("authenticated resume is answered")
    {
        SigilAction::Transmit { dest, .. } => assert_eq!(dest, SENSOR_MAC),
        other => panic!("expected resume challenge Transmit, got {other:?}"),
    }

    // Gateway clock egress over an active session, plus fail-closed
    // delivery release for an unknown Event id.
    insert_symmetric_session(&mut mgr, [0xC3u8; 17], SessionRole::Gateway);
    let sample = mgr
        .encrypt_time_sync::<256>(&[0xC3u8; 17], 5_000, 1, 10, 5_000)
        .expect("time sync encrypts over an active session");
    assert!(!sample.is_empty());
    assert!(mgr.release_event_delivery(&[0xC3u8; 17], 99).is_err());
}

// Two-role composition: full pairwise discovery install through public API.

#[cfg(all(feature = "sensor", feature = "gateway"))]
#[test]
fn pairwise_install_discovery_flow_through_public_facade() {
    use crate::core::install::INSTALL_DISCOVERY_DEST;

    let mut sensor = sensor_manager::<4>();
    let mut gateway = gateway_manager::<4>();
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GATEWAY_MAC);
    let mut rng_sensor = MockRandom::new();
    let mut rng_gw = MockRandom::new();
    let now = 1_000u32;

    // Step 1: sensor broadcasts its attested install request.
    let request = match sensor
        .start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se_sensor, &mut rng_sensor, now)
        .expect("install starts")
    {
        SigilAction::Transmit { payload, .. } => payload,
        other => panic!("expected request Transmit, got {other:?}"),
    };

    // Step 2: gateway classifies (allowlist hook point), then handles.
    let (event, action) = gateway
        .process_incoming_packet::<200, 256>(&request, now)
        .expect("gateway classifies request");
    assert!(matches!(event, SigilEvent::InstallRequest { peer, .. } if peer == SENSOR_MAC));
    assert!(matches!(
        action,
        SigilAction::NeedsHostDispatch { peer } if peer == SENSOR_MAC
    ));
    let challenge = match gateway
        .handle_install_request::<256>(&request, &mut se_gw, &mut rng_gw, now, 86_400)
        .expect("attested sensor accepted")
    {
        SigilAction::Transmit { payload, .. } => payload,
        other => panic!("expected challenge Transmit, got {other:?}"),
    };

    // Step 3: sensor classifies the challenge, continues (rebinding the
    // discovery pending to the real gateway MAC), emits its Final confirm.
    let (event, _) = sensor
        .process_incoming_packet::<200, 256>(&challenge, now)
        .expect("sensor classifies challenge");
    assert!(matches!(event, SigilEvent::InstallChallenge { peer, .. } if peer == GATEWAY_MAC));
    let confirm = match sensor
        .continue_install::<256>(&challenge, &mut se_sensor, now)
        .expect("challenge verifies")
    {
        SigilAction::Transmit { payload, .. } => payload,
        other => panic!("expected confirm Transmit, got {other:?}"),
    };
    assert!(
        sensor.get_pending(&GATEWAY_MAC).is_some(),
        "pending rebound from the discovery address to the gateway MAC"
    );

    // Step 4: gateway commits and persists the sensor identity; the
    // CommitConfirmed follow-up must be transmitted after NVRAM write.
    let (event, _) = gateway
        .process_incoming_packet::<200, 256>(&confirm, now)
        .expect("gateway classifies confirm");
    assert!(matches!(event, SigilEvent::InstallConfirm { peer, .. } if peer == SENSOR_MAC));
    // The gateway persists the SENSOR static pubkey here; the sensor-side
    // gateway identity checked below is the distinct gateway static key,
    // so this value is deliberately not cross-compared with it.
    let (commit, gw_psk, _gw_pubkey) = match gateway
        .continue_install::<256>(&confirm, &mut se_gw, now)
        .expect("gateway finalizes")
    {
        SigilAction::PersistPeerStaticKey {
            pubkey,
            resume_psk,
            transmit,
            ..
        } => {
            assert!(
                !transmit.is_empty(),
                "gateway Final carries CommitConfirmed"
            );
            (transmit, *resume_psk.expose_secret(), pubkey)
        }
        other => panic!("expected PersistPeerStaticKey, got {other:?}"),
    };
    assert!(gateway.get(&SENSOR_MAC).is_some(), "gateway session live");

    // Step 5: sensor commits after CommitConfirmed and persists enrollment.
    let (event, _) = sensor
        .process_incoming_packet::<200, 256>(&commit, now)
        .expect("sensor classifies commit");
    assert!(
        matches!(event, SigilEvent::InstallCommitConfirmed { peer, .. } if peer == GATEWAY_MAC)
    );
    let (sensor_psk, gw_identity) = match sensor
        .continue_install::<256>(&commit, &mut se_sensor, now)
        .expect("sensor commit succeeds")
    {
        SigilAction::PersistPeerStaticKey {
            pubkey,
            resume_psk,
            transmit,
            ..
        } => {
            assert!(transmit.is_empty(), "sensor completion persists only");
            (*resume_psk.expose_secret(), pubkey)
        }
        other => panic!("expected persist-only completion, got {other:?}"),
    };
    // Both peers derived the same durable resume PSK from the handshake.
    assert_eq!(sensor_psk, gw_psk);
    assert!(sensor.get(&GATEWAY_MAC).is_some(), "sensor session live");

    // Application traffic flows over the freshly derived directional keys.
    let hello = sensor
        .encrypt_data::<256>(&GATEWAY_MAC, b"post-install", now + 10)
        .expect("new keys encrypt");
    let (event, _) = gateway
        .process_incoming_packet::<200, 256>(&hello, now + 10)
        .expect("new keys decrypt");
    match event {
        SigilEvent::Data { payload, .. } => assert_eq!(&payload[..], b"post-install"),
        other => panic!("expected Data over new keys, got {other:?}"),
    }

    // Post-reboot reload contract: the sensor restores an enrolled-only
    // session from its persisted NVRAM values (gateway identity + resume
    // PSK) into a fresh manager and immediately starts a resume handshake;
    // the live gateway answers it over static↔static ECDH.
    let mut reloaded = SessionManager::<4>::new(TEST_FACTORY_PUBKEY, SENSOR_MAC)
        .expect("fresh manager after reboot");
    reloaded
        .insert(
            Session::new_enrolled(GATEWAY_MAC, gw_identity, sensor_psk, SessionRole::Sensor)
                .expect("reload from persisted identity"),
        )
        .expect("empty table accepts enrollment");
    match reloaded
        .start_resume::<256>(GATEWAY_MAC, &mut se_sensor, &mut rng_sensor, now + 20)
        .expect("resume starts after reboot")
    {
        SigilAction::Transmit { payload: req, .. } => {
            gateway
                .handle_resume_request::<256>(&req, &mut se_gw, &mut rng_gw, now + 20, 86_400)
                .expect("post-reboot resume is answered");
        }
        other => panic!("expected resume request Transmit, got {other:?}"),
    }
}

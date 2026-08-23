#![cfg(all(test, feature = "sensor", feature = "gateway"))]

mod transitions;

use crate::core::aead;
use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FRAME_TYPE_OFFSET, FrameType, OUTER_HEADER_SIZE};
use crate::core::manager::SessionManager;
use crate::core::renew::wire::{
    build_renew_challenge_body, build_renew_confirm_body, build_renew_request_body,
    parse_renew_challenge_body, parse_renew_confirm_body, parse_renew_request_body,
};
use crate::core::session::{DirectionalMaterial, Session, SessionRole};
use crate::core::test_support::{FailingRandom, MockRandom, MockSecureElement};
use p256::elliptic_curve::sec1::ToEncodedPoint;

const RESUME_PSK: [u8; 32] = [0x5a; 32];
const SENSOR_MAC: [u8; 17] = [0x31; 17];
const GW_MAC: [u8; 17] = [0x32; 17];
const KEY: [u8; 32] = [0x55; 32];
const PREFIX: [u8; 4] = [0xaa; 4];

fn sensor_active() -> SessionManager<16> {
    let mut manager = crate::core::test_support::test_manager_with_mac(SENSOR_MAC);
    manager
        .insert(
            Session::new_active(
                GW_MAC,
                [2; 33],
                DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
                SessionRole::Sensor,
                &RESUME_PSK,
                86_400,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    manager
}

fn gateway_active() -> SessionManager<16> {
    let mut manager = crate::core::test_support::test_manager_with_mac(GW_MAC);
    manager
        .insert(
            Session::new_active(
                SENSOR_MAC,
                [2; 33],
                DirectionalMaterial::symmetric_for_test(KEY, PREFIX),
                SessionRole::Gateway,
                &RESUME_PSK,
                86_400,
                0,
            )
            .unwrap(),
        )
        .unwrap();
    manager
}

fn transmitted(action: SigilAction<256>) -> heapless::Vec<u8, 256> {
    match action {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("expected transmit"),
    }
}

fn start_to_confirm(
    sensor: &mut SessionManager<16>,
    gateway: &mut SessionManager<16>,
    sensor_se: &mut MockSecureElement,
    gateway_se: &mut MockSecureElement,
    gateway_rng: &mut MockRandom,
) -> (
    heapless::Vec<u8, 256>,
    heapless::Vec<u8, 256>,
    heapless::Vec<u8, 256>,
) {
    let request = transmitted(sensor.start_renew::<256>(GW_MAC, 1_000).unwrap());
    let challenge = transmitted(
        gateway
            .handle_renew_request::<256>(&request, gateway_se, gateway_rng, 1_000, 3_600)
            .unwrap(),
    );
    let confirm = transmitted(
        sensor
            .continue_renew::<256>(&challenge, sensor_se, 1_000)
            .unwrap(),
    );
    (request, challenge, confirm)
}

fn public_from_scalar(scalar: &[u8; 32]) -> [u8; 33] {
    let secret = p256::SecretKey::from_slice(scalar).unwrap();
    let encoded = secret.public_key().to_encoded_point(true);
    let mut public = [0u8; 33];
    public.copy_from_slice(encoded.as_bytes());
    public
}

fn decrypt_old_confirm(frame: &[u8]) -> heapless::Vec<u8, 64> {
    let counter = u64::from_be_bytes(
        frame[OUTER_HEADER_SIZE + 4..OUTER_HEADER_SIZE + 12]
            .try_into()
            .unwrap(),
    );
    let mut plaintext = heapless::Vec::new();
    aead::decrypt_into(
        &KEY,
        &PREFIX,
        counter,
        &frame[OUTER_HEADER_SIZE + 12..],
        aead::aad_from_frame(frame).unwrap(),
        &mut plaintext,
    )
    .unwrap();
    plaintext
}

fn encrypt_old_confirm(body: &[u8], counter: u64) -> heapless::Vec<u8, 256> {
    let mut frame = heapless::Vec::new();
    frame
        .extend_from_slice(&crate::core::frame::build_header(
            &SENSOR_MAC,
            FrameType::RenewConfirm,
        ))
        .unwrap();
    frame.extend_from_slice(&PREFIX).unwrap();
    frame.extend_from_slice(&counter.to_be_bytes()).unwrap();
    aead::encrypt_append(
        &KEY,
        &PREFIX,
        counter,
        body,
        &aead::build_aad(&SENSOR_MAC, FrameType::RenewConfirm),
        &mut frame,
    )
    .unwrap();
    frame
}

#[test]
fn renew_wire_v4_has_only_new_shapes() {
    let request = build_renew_request_body().unwrap();
    assert!(request.is_empty());
    assert!(parse_renew_request_body(&request));
    assert!(!parse_renew_request_body(&[0u8; 32]));

    let gateway_scalar = [3u8; 32];
    let gateway_public = public_from_scalar(&gateway_scalar);
    let challenge = build_renew_challenge_body(&gateway_public, 900).unwrap();
    assert_eq!(challenge.len(), 37);
    let parsed = parse_renew_challenge_body(&challenge).unwrap();
    assert_eq!(parsed.gateway_ephemeral_pubkey, gateway_public);
    assert_eq!(parsed.key_lifetime_secs, 900);
    assert!(parse_renew_challenge_body(&[0u8; 36]).is_none());

    let sensor_public = public_from_scalar(&[4u8; 32]);
    let confirm = build_renew_confirm_body(&sensor_public, &[7u8; 16]).unwrap();
    assert_eq!(confirm.len(), 49);
    let parsed = parse_renew_confirm_body(&confirm).unwrap();
    assert_eq!(parsed.sensor_ephemeral_pubkey, sensor_public);
    assert_eq!(parsed.proof, [7u8; 16]);
    assert!(parse_renew_confirm_body(&[0u8; 48]).is_none());
}

#[test]
fn renew_pairwise_success_and_exact_lora_sizes() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let old_key = *sensor.get(&GW_MAC).unwrap().session_key().unwrap();
    let (request, challenge, confirm) = start_to_confirm(
        &mut sensor,
        &mut gateway,
        &mut sensor_se,
        &mut gateway_se,
        &mut gateway_rng,
    );
    assert_eq!(request.len(), 47);
    assert_eq!(challenge.len(), 84);
    assert_eq!(confirm.len(), 96);
    assert_eq!(confirm[FRAME_TYPE_OFFSET], FrameType::RenewConfirm as u8);
    assert_eq!(sensor.get(&GW_MAC).unwrap().session_key(), Some(&old_key));

    let commit = transmitted(
        gateway
            .handle_renew_confirm::<256>(&confirm, &mut gateway_se, 1_000)
            .unwrap(),
    );
    assert_eq!(commit.len(), 47);
    assert_eq!(
        commit[FRAME_TYPE_OFFSET],
        FrameType::RenewCommitConfirmed as u8
    );
    assert_ne!(
        gateway.get(&SENSOR_MAC).unwrap().session_key(),
        Some(&old_key)
    );

    assert!(matches!(
        sensor
            .continue_renew::<256>(&commit, &mut sensor_se, 1_000)
            .unwrap(),
        SigilAction::Success { peer } if peer == GW_MAC
    ));
    let sensor_session = sensor.get(&GW_MAC).unwrap();
    let gateway_session = gateway.get(&SENSOR_MAC).unwrap();
    assert_eq!(
        sensor_session.session_key(),
        gateway_session.rx_session_key()
    );
    assert_eq!(
        sensor_session.rx_session_key(),
        gateway_session.session_key()
    );
    assert_eq!(sensor_session.tx_counter, 0);
    assert_eq!(sensor_session.rx_counter, 1);
    assert_eq!(gateway_session.rx_counter, 0);
    assert_eq!(gateway_session.tx_counter, 1);
}

#[test]
fn sensor_pending_never_contains_an_ephemeral_private_key() {
    let mut sensor = sensor_active();
    sensor.start_renew::<256>(GW_MAC, 1_000).unwrap();
    let pending = sensor.get_pending(&GW_MAC).unwrap();
    // The sensor-side renew state is a fieldless variant: the ephemeral
    // scalar is generated and consumed inside the secure element at
    // challenge time, so no private material can be retained here.
    assert!(matches!(
        pending.state(),
        crate::core::pending::PendingState::RenewSensorAwaitChallenge
    ));
}

#[test]
fn atecc_failure_preserves_old_session_and_retriable_challenge() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let request = transmitted(sensor.start_renew::<256>(GW_MAC, 1_000).unwrap());
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let challenge = transmitted(
        gateway
            .handle_renew_request::<256>(&request, &mut gateway_se, &mut gateway_rng, 1_000, 3_600)
            .unwrap(),
    );
    let before = sensor.get(&GW_MAC).unwrap().rx_counter;
    let mut se = MockSecureElement::default();
    se.reject_ecdh();
    assert_eq!(
        sensor.continue_renew::<256>(&challenge, &mut se, 1_000),
        Err(SigilError::EcdhFailed)
    );
    assert_eq!(sensor.get(&GW_MAC).unwrap().rx_counter, before);
    // Failed SE work must leave the pre-challenge sensor state intact.
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        crate::core::pending::PendingState::RenewSensorAwaitChallenge
    ));
}

#[test]
fn gateway_provider_generation_failure_does_not_consume_old_counters() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let request = transmitted(sensor.start_renew::<256>(GW_MAC, 1_000).unwrap());
    let before_rx = gateway.get(&SENSOR_MAC).unwrap().rx_counter;
    let before_tx = gateway.get(&SENSOR_MAC).unwrap().tx_counter;
    let mut gateway_se = MockSecureElement::default();
    assert_eq!(
        gateway.handle_renew_request::<256>(
            &request,
            &mut gateway_se,
            &mut FailingRandom,
            1_000,
            3_600,
        ),
        Err(SigilError::RandomFailed)
    );
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().rx_counter, before_rx);
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().tx_counter, before_tx);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
}

#[test]
fn authenticated_wrong_proof_never_commits_gateway() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let (_, _, confirm) = start_to_confirm(
        &mut sensor,
        &mut gateway,
        &mut sensor_se,
        &mut gateway_se,
        &mut gateway_rng,
    );
    let old_key = *gateway.get(&SENSOR_MAC).unwrap().session_key().unwrap();
    let mut body = decrypt_old_confirm(&confirm);
    let last = body.len() - 1;
    body[last] ^= 1;
    let forged = encrypt_old_confirm(&body, 1);
    assert_eq!(
        gateway.handle_renew_confirm::<256>(&forged, &mut gateway_se, 1_000),
        Err(SigilError::VerificationFailed)
    );
    assert_eq!(
        gateway.get(&SENSOR_MAC).unwrap().session_key(),
        Some(&old_key)
    );
    // A rejected proof must keep the gateway at the await-confirm state.
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        crate::core::pending::PendingState::RenewGatewayAwaitConfirm { .. }
    ));
}

#[test]
fn gateway_provider_ecdh_failure_preserves_old_session() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let (_, _, confirm) = start_to_confirm(
        &mut sensor,
        &mut gateway,
        &mut sensor_se,
        &mut gateway_se,
        &mut gateway_rng,
    );
    let old_key = *gateway.get(&SENSOR_MAC).unwrap().session_key().unwrap();
    let old_rx = gateway.get(&SENSOR_MAC).unwrap().rx_counter;
    gateway_se.reject_ecdh();

    assert_eq!(
        gateway.handle_renew_confirm::<256>(&confirm, &mut gateway_se, 1_000),
        Err(SigilError::EcdhFailed)
    );
    assert_eq!(
        gateway.get(&SENSOR_MAC).unwrap().session_key(),
        Some(&old_key)
    );
    assert_eq!(gateway.get(&SENSOR_MAC).unwrap().rx_counter, old_rx);
    // SE failure after challenge must preserve the await-confirm state.
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        crate::core::pending::PendingState::RenewGatewayAwaitConfirm { .. }
    ));
}

#[test]
fn authenticated_off_curve_sensor_key_is_rejected_before_commit() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let (_, _, confirm) = start_to_confirm(
        &mut sensor,
        &mut gateway,
        &mut sensor_se,
        &mut gateway_se,
        &mut gateway_rng,
    );
    let mut body = decrypt_old_confirm(&confirm);
    body[..33].fill(0xff);
    body[0] = 0x02;
    let forged = encrypt_old_confirm(&body, 1);
    assert_eq!(
        gateway.handle_renew_confirm::<256>(&forged, &mut gateway_se, 1_000),
        Err(SigilError::InvalidStaticKey)
    );
    // An off-curve key must be rejected before any state change.
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        crate::core::pending::PendingState::RenewGatewayAwaitConfirm { .. }
    ));
}

#[test]
fn radio_tampering_is_rejected_without_counter_advance() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let request = transmitted(sensor.start_renew::<256>(GW_MAC, 1_000).unwrap());
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let mut challenge = transmitted(
        gateway
            .handle_renew_request::<256>(&request, &mut gateway_se, &mut gateway_rng, 1_000, 3_600)
            .unwrap(),
    );
    let last = challenge.len() - 1;
    challenge[last] ^= 1;
    let before = sensor.get(&GW_MAC).unwrap().rx_counter;
    assert_eq!(
        sensor.continue_renew::<256>(&challenge, &mut MockSecureElement::default(), 1_000),
        Err(SigilError::VerificationFailed)
    );
    assert_eq!(sensor.get(&GW_MAC).unwrap().rx_counter, before);
}

#[test]
fn commit_loss_duplicate_confirm_retransmits_identical_frame() {
    let mut sensor = sensor_active();
    let mut gateway = gateway_active();
    let mut sensor_se = MockSecureElement::default();
    let mut gateway_se = MockSecureElement::default();
    let mut gateway_rng = MockRandom::new();
    let (_, _, confirm) = start_to_confirm(
        &mut sensor,
        &mut gateway,
        &mut sensor_se,
        &mut gateway_se,
        &mut gateway_rng,
    );
    let first = transmitted(
        gateway
            .handle_renew_confirm::<256>(&confirm, &mut gateway_se, 1_000)
            .unwrap(),
    );
    let second = transmitted(
        gateway
            .handle_renew_confirm::<256>(&confirm, &mut gateway_se, 1_001)
            .unwrap(),
    );
    assert_eq!(first, second);
    assert!(gateway.tick(2_000).is_empty());
    assert!(sensor.tick(2_000).is_empty());
    sensor
        .continue_renew::<256>(&second, &mut sensor_se, 1_001)
        .unwrap();
}

#[test]
fn transcript_changes_derived_material_and_proof() {
    let shared = [9u8; 32];
    let sensor_pub = public_from_scalar(&[3u8; 32]);
    let gateway_pub = public_from_scalar(&[4u8; 32]);
    let base =
        crate::core::renew::renew_hkdf_info(&SENSOR_MAC, &sensor_pub, &gateway_pub, 10).unwrap();
    let base_material =
        crate::core::derive::derive_directional_session_keys(&shared, Some(&base)).unwrap();
    let base_proof = crate::core::renew::renew_sensor_proof(&base_material.s2g_key, &base).unwrap();

    let mut other_peer = SENSOR_MAC;
    other_peer[0] ^= 1;
    let changed =
        crate::core::renew::renew_hkdf_info(&other_peer, &sensor_pub, &gateway_pub, 10).unwrap();
    let changed_material =
        crate::core::derive::derive_directional_session_keys(&shared, Some(&changed)).unwrap();
    let changed_proof =
        crate::core::renew::renew_sensor_proof(&changed_material.s2g_key, &changed).unwrap();
    assert_ne!(base_material.s2g_key, changed_material.s2g_key);
    assert_ne!(base_proof, changed_proof);
}

#[test]
fn all_zero_provider_shared_secret_is_rejected() {
    assert_eq!(
        crate::core::secret::validated_ecdh_shared_secret([0u8; 32]).map(|_| ()),
        Err(SigilError::EcdhFailed)
    );
    assert_eq!(
        crate::core::secret::validated_ecdh_shared_secret([1u8; 32])
            .map(|shared| *shared.as_array()),
        Ok([1u8; 32])
    );
}

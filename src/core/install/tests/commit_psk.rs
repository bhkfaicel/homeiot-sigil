#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Commit-path durable-PSK handling tests for the install handshake.
//!
//! These suites pin the zeroization contract of both install commit
//! handlers: the temporary durable-PSK copy extracted from the staged
//! pending state is carried inside a zeroizing wrapper, so success
//! persists it into the session and the host persist action while every
//! error path (rejected device-signature proof, key-expiry overflow,
//! corrupted CommitConfirmed frame, saturated session table, failed
//! transition) drops and wipes the carrier instead of leaving a plain
//! stack copy behind. Coverage spans both roles' success paths, every
//! injectable post-extraction failure with retry recovery, gateway-side
//! insertion failure, idempotent retransmission of an already-persisted
//! enrollment, and wrapper wipe-on-drop behavior.

use crate::core::error::SigilError;
use crate::core::event::{ResumePskSecret, SigilAction};
use crate::core::manager::SessionManager;
use crate::core::pending::{PendingState, ResumePskStash};
use crate::core::session::{PeerId, Session, SessionRole};
use crate::core::test_support::{MockRandom, MockSecureElement};

/// Sensor MAC used by the pairwise flows.
const SENSOR_MAC: PeerId = [0x71u8; 17];
/// Gateway MAC used by the pairwise flows.
const GW_MAC: PeerId = [0x72u8; 17];
/// First filler peer used to saturate the gateway session table.
const FILLER_1: PeerId = [0x7Au8; 17];
/// Second filler peer used to saturate the gateway session table.
const FILLER_2: PeerId = [0x7Bu8; 17];

/// Drives a pairwise install until the gateway holds the sensor Final.
///
/// Returns the **live sensor manager** (its pending entry is staged and able
/// to reach `FinalSent`) together with the serialized `InstallConfirm`, so
/// callers can continue either side of the handshake afterwards.
fn pairwise_install_up_to_final<const NG: usize>(
    gateway: &mut SessionManager<NG>,
    se_sensor: &mut MockSecureElement,
    se_gw: &mut MockSecureElement,
) -> (SessionManager<16>, heapless::Vec<u8, 256>) {
    let mut rng_s = MockRandom::new();
    let mut rng_g = MockRandom::new();

    let mut sensor: SessionManager<16> =
        crate::core::test_support::test_manager_with_mac(SENSOR_MAC);

    let request = match sensor
        .start_install::<256>(GW_MAC, se_sensor, &mut rng_s, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit the install request"),
    };
    let challenge = match gateway
        .handle_install_request::<256>(&request, se_gw, &mut rng_g, 1_000, 86_400)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("gateway should transmit the install challenge"),
    };
    let confirm = match sensor
        .continue_install::<256>(&challenge, se_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit the install confirm"),
    };
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayAwaitConfirm(_)
    ));
    (sensor, confirm)
}

/// Gateway-focused convenience: drives the handshake to the sensor Final and
/// discards the sensor manager.
fn install_up_to_final<const NG: usize>(
    gateway: &mut SessionManager<NG>,
    se_sensor: &mut MockSecureElement,
    se_gw: &mut MockSecureElement,
) -> heapless::Vec<u8, 256> {
    pairwise_install_up_to_final(gateway, se_sensor, se_gw).1
}

/// Drives a pairwise install through the gateway commit.
///
/// Returns the live **sensor manager** (pending staged at `FinalSent`) plus
/// the gateway's cached CommitConfirmed frame, so tests can corrupt, replay
/// or deliver it against the sensor's final commit step. On return the
/// gateway has committed its session and sits in the recovery state.
fn install_through_gateway_commit<const NG: usize>(
    gateway: &mut SessionManager<NG>,
    se_sensor: &mut MockSecureElement,
    se_gw: &mut MockSecureElement,
) -> (SessionManager<16>, heapless::Vec<u8, 256>) {
    let (sensor, confirm) = pairwise_install_up_to_final(gateway, se_sensor, se_gw);
    let commit_frame = match gateway
        .continue_install::<256>(&confirm, se_gw, 1_000)
        .unwrap()
    {
        SigilAction::PersistPeerStaticKey { transmit, .. } => transmit,
        _ => panic!("gateway commit should emit PersistPeerStaticKey with CommitConfirmed"),
    };
    (sensor, commit_frame)
}

/// Asserts that a gateway persist action carries exactly the PSK stored in
/// the committed session (the value the host must make durable) and returns
/// the follow-up transmit payload.
fn assert_persist_psk_matches_session<const MSG: usize, const NG: usize>(
    persist: SigilAction<MSG>,
    gateway: &SessionManager<NG>,
) -> heapless::Vec<u8, MSG> {
    match persist {
        SigilAction::PersistPeerStaticKey {
            peer,
            pubkey,
            resume_psk,
            transmit,
            ..
        } => {
            assert_eq!(peer, SENSOR_MAC);
            assert_eq!(pubkey[0], 0x03);
            assert_eq!(
                Some(*resume_psk.expose_secret()),
                gateway.get(&SENSOR_MAC).unwrap().resume_psk().copied(),
                "persisted PSK must equal the committed session PSK"
            );
            transmit
        }
        _ => panic!("expected PersistPeerStaticKey from the gateway commit"),
    }
}

#[test]
fn test_install_commit_success_carries_wrapped_psk() {
    // Success path: the gateway commit persists the durable PSK through the
    // zeroizing action carrier, byte-identical to the committed session copy.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let confirm = install_up_to_final(&mut gateway, &mut se_sensor, &mut se_gw);

    // Gateway processes the Final: commit + PersistPeerStaticKey with a
    // CommitConfirmed follow-up frame.
    let persist = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    let transmit = assert_persist_psk_matches_session(persist, &gateway);
    assert!(!transmit.is_empty());
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayCommitSent { .. }
    ));
}

#[test]
fn test_gateway_commit_session_table_full_preserves_staged_psk_and_recovers() {
    // Insertion-failure path (after PSK extraction): a saturated session
    // table must fail the gateway commit closed, leave the staged state (and
    // its zeroizing PSK stash) intact for retry, and succeed once capacity
    // frees up — with the same persisted PSK on success.
    const FILLER_PSK_1: [u8; 32] = [0xA1u8; 32];
    const FILLER_PSK_2: [u8; 32] = [0xB2u8; 32];

    let mut gateway: SessionManager<2> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let confirm = install_up_to_final(&mut gateway, &mut se_sensor, &mut se_gw);

    // Saturate the gateway session table before the commit is attempted.
    gateway
        .insert(
            Session::new_enrolled(FILLER_1, [2u8; 33], FILLER_PSK_1, SessionRole::Sensor).unwrap(),
        )
        .unwrap();
    gateway
        .insert(
            Session::new_enrolled(FILLER_2, [3u8; 33], FILLER_PSK_2, SessionRole::Sensor).unwrap(),
        )
        .unwrap();

    // Commit fails at session insertion; nothing is committed or cleared.
    assert_eq!(
        gateway.continue_install::<256>(&confirm, &mut se_gw, 1_000),
        Err(SigilError::SessionTableFull)
    );
    assert!(gateway.get(&SENSOR_MAC).is_none());
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayAwaitConfirm(_)
    ));

    // Free one slot: the identical Final retries cleanly end-to-end.
    gateway.remove(&FILLER_1);
    let persist = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    let transmit = assert_persist_psk_matches_session(persist, &gateway);
    assert!(!transmit.is_empty());
    assert!(gateway.get(&SENSOR_MAC).unwrap().session_key().is_some());
}

#[test]
fn test_gateway_duplicate_confirm_retx_carries_persisted_psk() {
    // Retransmission path: a duplicate Final after the gateway already
    // committed re-emits the cached CommitConfirmed wrapped in
    // PersistPeerStaticKey carrying the same durable PSK (host may ignore
    // the duplicate persist) without touching the live session.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let confirm = install_up_to_final(&mut gateway, &mut se_sensor, &mut se_gw);

    let first = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    let commit_frame = assert_persist_psk_matches_session(first, &gateway);
    assert!(!commit_frame.is_empty());

    let retx = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    let retx_frame = assert_persist_psk_matches_session(retx, &gateway);
    assert_eq!(
        retx_frame.as_slice(),
        commit_frame.as_slice(),
        "duplicate Final must reTX the cached CommitConfirmed unchanged"
    );
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayCommitSent { .. }
    ));
}

#[test]
fn test_commit_path_psk_wrappers_wipe_on_drop() {
    // Zeroization contract of the commit-path PSK chain: staged stash copy →
    // zeroizing action carrier. Both are ZeroizeOnDrop; following the crate's
    // portable precedent we exercise construction, content access, and scope
    // exit rather than observing raw SRAM.
    const STAGED_PSK: [u8; 32] = [0x5Du8; 32];
    {
        let staged = ResumePskStash::new(STAGED_PSK);
        assert_eq!(staged.as_array(), &STAGED_PSK);

        // This is exactly the commit-path extraction: one copy out of the
        // stash straight into the zeroizing wrapper that later becomes the
        // host persist value.
        let carried = ResumePskSecret::new(*staged.as_array());
        assert_eq!(carried.expose_secret(), &STAGED_PSK);
        // Both wrappers drop here (success shape).
    }

    // Error shape: the carrier alone is created and dropped when a commit
    // step after extraction fails; it must wipe independently of the stash.
    {
        let carried = ResumePskSecret::new(STAGED_PSK);
        assert_eq!(carried.expose_secret(), &STAGED_PSK);
    }
}

#[test]
fn test_gateway_commit_rejected_proof_preserves_staged_psk_for_retry() {
    // Post-extraction failure path: the sensor's device-signature proof is
    // verified AFTER the durable PSK has been extracted into the zeroizing
    // carrier. A rejected proof must drop and wipe that carrier on the error
    // return, leave no session behind, and keep the staged pending state (and
    // its zeroizing PSK stash) intact so an identical Final retries cleanly.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let confirm = install_up_to_final(&mut gateway, &mut se_sensor, &mut se_gw);

    // Fail the commit-path signature verification.
    se_gw.reject_signatures();
    assert_eq!(
        gateway.continue_install::<256>(&confirm, &mut se_gw, 1_000),
        Err(SigilError::VerificationFailed)
    );
    assert!(gateway.get(&SENSOR_MAC).is_none());
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayAwaitConfirm(_)
    ));

    // Fresh provider instance: mock signatures are deterministic message
    // tags, so an unmodified mock verifies the same Final. The retry commits
    // and persists exactly the same durable PSK as the session copy.
    let mut se_gw_ok = MockSecureElement::gateway(2, GW_MAC);
    let persist = gateway
        .continue_install::<256>(&confirm, &mut se_gw_ok, 1_000)
        .unwrap();
    let transmit = assert_persist_psk_matches_session(persist, &gateway);
    assert!(!transmit.is_empty());
}

#[test]
fn test_gateway_commit_expiry_overflow_preserves_staged_psk_for_retry() {
    // Post-extraction failure path driven by host time: with `now` near the
    // u32 wrap, the key-expiry computation fails inside the commit handler —
    // after extraction but before any state mutation. The error return wipes
    // the carrier while the staged state survives for a clean retry.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let confirm = install_up_to_final(&mut gateway, &mut se_sensor, &mut se_gw);

    assert!(matches!(
        gateway.continue_install::<256>(&confirm, &mut se_gw, u32::MAX),
        Err(SigilError::InvalidKeyLifetime { .. })
    ));
    assert!(gateway.get(&SENSOR_MAC).is_none());
    assert!(matches!(
        gateway.get_pending(&SENSOR_MAC).unwrap().state(),
        PendingState::InstallGatewayAwaitConfirm(_)
    ));

    // Same Final at a sane timebase commits end-to-end with the same PSK.
    let persist = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    let transmit = assert_persist_psk_matches_session(persist, &gateway);
    assert!(!transmit.is_empty());
}

#[test]
fn test_sensor_commit_confirmed_corruption_preserves_staged_psk_for_retry() {
    // Post-extraction failure path on the sensor: AEAD verification of the
    // CommitConfirmed runs AFTER the staged PSK was extracted into the
    // zeroizing carrier. A corrupted tag must fail closed, wipe the carrier,
    // leave no session, keep the FinalSent staging (and cached retransmit)
    // untouched, and still allow the intact frame to complete the install
    // with the identical durable PSK on both sides.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let (mut sensor, commit_frame) =
        install_through_gateway_commit(&mut gateway, &mut se_sensor, &mut se_gw);

    // Corrupt the final tag byte: authentication must fail.
    let mut corrupted = commit_frame.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0x01;

    assert_eq!(
        sensor.continue_install::<256>(&corrupted, &mut se_sensor, 1_000),
        Err(SigilError::VerificationFailed)
    );
    assert!(sensor.get(&GW_MAC).is_none());
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        PendingState::InstallSensorFinalSent { .. }
    ));

    // The intact frame (counter-0 CommitConfirmed is not consumed by the
    // failed attempt) completes the install; both sides hold the same PSK.
    let persist = sensor
        .continue_install::<256>(&commit_frame, &mut se_sensor, 1_000)
        .unwrap();
    match persist {
        SigilAction::PersistPeerStaticKey {
            peer,
            pubkey,
            resume_psk,
            transmit,
            ..
        } => {
            assert_eq!(peer, GW_MAC);
            // The sensor persists its PEER's static key: the gateway mock
            // uses even id 2, whose compressed SEC1 prefix is 0x02.
            assert_eq!(pubkey[0], 0x02);
            assert_eq!(
                Some(*resume_psk.expose_secret()),
                gateway.get(&SENSOR_MAC).unwrap().resume_psk().copied(),
                "persisted PSK must equal the gateway-side committed PSK"
            );
            assert!(transmit.is_empty());
        }
        _ => panic!("expected PersistPeerStaticKey from the sensor commit"),
    }
    assert!(sensor.get(&GW_MAC).unwrap().session_key().is_some());
}

#[test]
fn test_sensor_commit_expiry_overflow_preserves_staged_psk_for_retry() {
    // Sensor-side post-extraction failure driven by host time: the lifetime
    // check inside the commit handler overflows for `now` near u32::MAX —
    // after AEAD verification of the frame but before any mutation. The
    // carrier wipes on return and the identical frame retries cleanly.
    let mut gateway: SessionManager<16> = crate::core::test_support::test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    let (mut sensor, commit_frame) =
        install_through_gateway_commit(&mut gateway, &mut se_sensor, &mut se_gw);

    assert!(matches!(
        sensor.continue_install::<256>(&commit_frame, &mut se_sensor, u32::MAX),
        Err(SigilError::InvalidKeyLifetime { .. })
    ));
    assert!(sensor.get(&GW_MAC).is_none());
    assert!(matches!(
        sensor.get_pending(&GW_MAC).unwrap().state(),
        PendingState::InstallSensorFinalSent { .. }
    ));

    // Retry at a sane timebase completes with matching PSKs on both sides.
    let persist = sensor
        .continue_install::<256>(&commit_frame, &mut se_sensor, 1_000)
        .unwrap();
    match persist {
        SigilAction::PersistPeerStaticKey {
            peer,
            resume_psk,
            transmit,
            ..
        } => {
            assert_eq!(peer, GW_MAC);
            assert_eq!(
                Some(*resume_psk.expose_secret()),
                gateway.get(&SENSOR_MAC).unwrap().resume_psk().copied(),
                "persisted PSK must equal the gateway-side committed PSK"
            );
            assert!(transmit.is_empty());
        }
        _ => panic!("expected PersistPeerStaticKey from the sensor commit"),
    }
    assert!(sensor.get(&GW_MAC).unwrap().session_key().is_some());
}

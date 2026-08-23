#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Replay-defense downstream-failure suites for the clear-text resume
//! initiator path.
//!
//! Contract under test: every injectable fallible site after the request-MAC
//! verification propagates its error and leaves the replay cache
//! byte-identical (NO insertion). The resume cooldown stamp is written only
//! AFTER the fail-atomic pending insert, so an identical immediate retry at
//! the SAME time succeeds on every downstream failure (no stamp was written).

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FrameType, build_header};
use crate::core::manager::SessionManager;
use crate::core::resume::wire::{RESUME_NONCE_SIZE, build_resume_request_body, resume_request_mac};
use crate::core::session::{Session, SessionRole};
use crate::core::test_support::{
    FailingRandom, MockRandom, MockSecureElement, test_manager_with_mac,
};

const SENSOR_MAC: [u8; 17] = [0x91u8; 17];
const GW_MAC: [u8; 17] = [0x92u8; 17];
const STATIC_PUB: [u8; 33] = [2u8; 33];
const RESUME_LIFETIME: u32 = 86_400;

/// Builds a well-formed ResumeRequest frame carrying a valid resume-PSK MAC
/// over `(sensor_mac ‖ nonce)` under the given PSK.
fn valid_resume_request_frame(
    psk: &[u8; 32],
    sensor_mac: &[u8; 17],
    nonce: &[u8; RESUME_NONCE_SIZE],
) -> heapless::Vec<u8, 64> {
    let req_mac = resume_request_mac(psk, sensor_mac, nonce).unwrap();
    let body = build_resume_request_body(nonce, &req_mac).unwrap();
    let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
    frame
        .extend_from_slice(&build_header(sensor_mac, FrameType::ResumeRequest))
        .unwrap();
    frame.extend_from_slice(&body).unwrap();
    frame
}

/// Gateway-side manager with one enrolled peer shell (post-reboot state:
/// static key + durable PSK, no session key).
fn gateway_with_peer<const N: usize>(peer_mac: [u8; 17], psk: [u8; 32]) -> SessionManager<N> {
    let mut gateway: SessionManager<N> = test_manager_with_mac(GW_MAC);
    gateway
        .insert(Session::new_enrolled(peer_mac, STATIC_PUB, psk, SessionRole::Gateway).unwrap())
        .unwrap();
    gateway
}

#[test]
fn resume_downstream_ecdh_failure_retry_not_replay() {
    let mut gateway = gateway_with_peer::<4>(SENSOR_MAC, [0x5Au8; 32]);
    let mut rng_gateway = MockRandom::new();
    let frame = valid_resume_request_frame(&[0x5Au8; 32], &SENSOR_MAC, &[0xA1u8; 16]);

    // SE-ECDH fails AFTER the request MAC verifies.
    let mut se_bad = MockSecureElement::default();
    se_bad.reject_ecdh();
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &frame,
            &mut se_bad,
            &mut rng_gateway,
            1_000,
            RESUME_LIFETIME
        ),
        Err(SigilError::EcdhFailed)
    );
    assert_eq!(gateway.replay_cache().len(), 0);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    // No cooldown stamp exists yet (stamped only after the pending insert):
    // the identical retry succeeds immediately at the SAME time.
    let mut se_good = MockSecureElement::default();
    let retry = gateway.handle_resume_request::<256>(
        &frame,
        &mut se_good,
        &mut rng_gateway,
        1_000,
        RESUME_LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn resume_downstream_rng_failure_retry_not_replay() {
    let mut gateway = gateway_with_peer::<4>(SENSOR_MAC, [0x5Au8; 32]);
    let mut se_good = MockSecureElement::default();
    let frame = valid_resume_request_frame(&[0x5Au8; 32], &SENSOR_MAC, &[0xB2u8; 16]);

    // The gateway nonce fill fails after MAC verification / ECDH.
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &frame,
            &mut se_good,
            &mut FailingRandom,
            1_000,
            RESUME_LIFETIME
        ),
        Err(SigilError::RandomFailed)
    );
    assert_eq!(gateway.replay_cache().len(), 0);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    // Immediate identical retry succeeds (mirror of the ECDH case).
    let retry = gateway.handle_resume_request::<256>(
        &frame,
        &mut se_good,
        &mut MockRandom::new(),
        1_000,
        RESUME_LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn resume_downstream_pending_insert_failure_retry_not_replay() {
    // Pending-table saturation needs N in-flight handshakes while the
    // session table may only hold N−1 fillers + the victim. Mix the filler
    // kinds: six ENROLLED resume peers (sessions) plus two session-less
    // INSTALL initiators reach 8/8 pendings on an N=8 gateway without
    // exceeding session capacity. Both kinds also insert cache triples at
    // t=0; advancing past the replay horizon later empties the CACHE (TTL)
    // while every pre-commit PENDING entry persists (no tick is called),
    // isolating the failure to the pending insert alone.
    const RF: [[u8; 17]; 6] = [
        [0x81u8; 17],
        [0x82u8; 17],
        [0x83u8; 17],
        [0x84u8; 17],
        [0x85u8; 17],
        [0x86u8; 17],
    ];
    const IF1: [u8; 17] = [0x87u8; 17];
    const IF2: [u8; 17] = [0x88u8; 17];

    let mut gateway: SessionManager<8> = test_manager_with_mac(GW_MAC);
    // Six resume fillers plus the victim are enrolled gateway-side shells.
    for (i, peer) in RF.iter().enumerate() {
        gateway
            .insert(
                Session::new_enrolled(
                    *peer,
                    STATIC_PUB,
                    [(0x11 + i as u8); 32],
                    SessionRole::Gateway,
                )
                .unwrap(),
            )
            .unwrap();
    }
    gateway
        .insert(
            Session::new_enrolled(SENSOR_MAC, STATIC_PUB, [0x55u8; 32], SessionRole::Gateway)
                .unwrap(),
        )
        .unwrap();
    let mut se_good = MockSecureElement::default();

    // t=0: six resume requests complete (pending + cache + cooldown stamp).
    for (i, peer) in RF.iter().enumerate() {
        let byte = 0x11 + i as u8;
        let frame = valid_resume_request_frame(&[byte; 32], peer, &[byte; RESUME_NONCE_SIZE]);
        assert!(matches!(
            gateway.handle_resume_request::<256>(
                &frame,
                &mut se_good,
                &mut MockRandom::new(),
                0,
                RESUME_LIFETIME
            ),
            Ok(SigilAction::Transmit { .. })
        ));
    }
    // t=0: two session-less INSTALL initiators complete too (the pending
    // table is protocol-agnostic by design).
    for (sensor_id, filler_mac) in [(7u8, IF1), (8u8, IF2)] {
        let mut sensor: SessionManager<2> = test_manager_with_mac(filler_mac);
        let mut se_sensor = MockSecureElement::sensor(sensor_id, filler_mac);
        let request = match sensor
            .start_install::<256>(GW_MAC, &mut se_sensor, &mut MockRandom::new(), 0)
            .unwrap()
        {
            SigilAction::Transmit { payload, .. } => payload,
            _ => panic!("install filler should transmit"),
        };
        assert!(matches!(
            gateway.handle_install_request::<256>(
                &request,
                &mut se_good,
                &mut MockRandom::new(),
                0,
                RESUME_LIFETIME
            ),
            Ok(SigilAction::Transmit { .. })
        ));
    }
    // Both tables saturated at N=8.
    assert_eq!(gateway.pending_len(), 8);
    assert_eq!(gateway.replay_cache().len(), 8);

    // t=4000 (> horizon 3600): the victim's fresh request purges the eight
    // strictly-expired cache entries and clears every cheap guard... then
    // hits the still-full pending table at the fail-atomic insert.
    let victim_frame =
        valid_resume_request_frame(&[0x55u8; 32], &SENSOR_MAC, &[0x66u8; RESUME_NONCE_SIZE]);
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &victim_frame,
            &mut se_good,
            &mut MockRandom::new(),
            4000,
            RESUME_LIFETIME
        ),
        Err(SigilError::PendingTableFull)
    );
    // Cache state after the failed attempt: empty (entries were reclaimed
    // only by TTL), victim triple absent — no insertion on failure.
    assert_eq!(gateway.replay_cache().len(), 0);
    assert_eq!(gateway.pending_len(), 8);

    // No cooldown stamp was written (the stamp follows the pending insert):
    // freeing ONE slot lets the identical retry succeed at the SAME time.
    gateway.cancel_pending(&RF[0]).unwrap();
    let retry = gateway.handle_resume_request::<256>(
        &victim_frame,
        &mut se_good,
        &mut MockRandom::new(),
        4000,
        RESUME_LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn resume_downstream_output_buffer_failure_retry_not_replay() {
    let mut gateway = gateway_with_peer::<4>(SENSOR_MAC, [0x5Au8; 32]);
    let mut se_good = MockSecureElement::default();
    let frame = valid_resume_request_frame(&[0x5Au8; 32], &SENSOR_MAC, &[0xC3u8; 16]);

    // ResumeChallenge needs 19 (header) + 36 (body) bytes; MSG=40 cannot
    // hold it — the buffer failure fires after crypto, before pending.
    assert_eq!(
        gateway.handle_resume_request::<40>(
            &frame,
            &mut se_good,
            &mut MockRandom::new(),
            1_000,
            RESUME_LIFETIME
        ),
        Err(SigilError::OutputBufferTooSmall)
    );
    assert_eq!(gateway.replay_cache().len(), 0);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    // Immediate identical retry with a proper MSG generic succeeds.
    let retry = gateway.handle_resume_request::<256>(
        &frame,
        &mut se_good,
        &mut MockRandom::new(),
        1_000,
        RESUME_LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn resume_downstream_invalid_peer_point_rejected_retry_not_replay() {
    let mut gateway = gateway_with_peer::<4>(SENSOR_MAC, [0x5Au8; 32]);
    let mut rng_gateway = MockRandom::new();
    let frame = valid_resume_request_frame(&[0x5Au8; 32], &SENSOR_MAC, &[0xD4u8; 16]);

    // Same defect class as install's malformed provider key, different
    // surface: the STORED session-record peer key flows straight into
    // `SecureElement::ecdh` (resume performs no ECDSA on stored keys), where
    // the defective provider rejects the corrupt/off-curve point.
    let mut se_bad = MockSecureElement::default();
    se_bad.reject_stored_point();
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &frame,
            &mut se_bad,
            &mut rng_gateway,
            1_000,
            RESUME_LIFETIME
        ),
        Err(SigilError::InvalidStaticKey)
    );
    assert_eq!(gateway.replay_cache().len(), 0);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());

    // Immediate identical retry with a healthy provider succeeds.
    let mut se_good = MockSecureElement::default();
    let retry = gateway.handle_resume_request::<256>(
        &frame,
        &mut se_good,
        &mut rng_gateway,
        1_000,
        RESUME_LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn resume_downstream_null_ecdh_output_rejected_retry_not_replay() {
    let mut gateway = gateway_with_peer::<4>(SENSOR_MAC, [0x5Au8; 32]);
    let mut rng_gateway = MockRandom::new();
    let frame = valid_resume_request_frame(&[0x5Au8; 32], &SENSOR_MAC, &[0xE5u8; 16]);

    // Provider reports `Ok([0u8; 32])`: the constant-time null-output gate
    // rejects it at the ECDH call site.
    let mut se_bad = MockSecureElement::default();
    se_bad.return_zero_ecdh();
    assert_eq!(
        gateway.handle_resume_request::<256>(
            &frame,
            &mut se_bad,
            &mut rng_gateway,
            1_000,
            RESUME_LIFETIME
        ),
        Err(SigilError::EcdhFailed)
    );
    assert_eq!(gateway.replay_cache().len(), 0);

    // Immediate identical retry with a healthy provider succeeds.
    let mut se_good = MockSecureElement::default();
    let retry = gateway.handle_resume_request::<256>(
        &frame,
        &mut se_good,
        &mut rng_gateway,
        1_000,
        RESUME_LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

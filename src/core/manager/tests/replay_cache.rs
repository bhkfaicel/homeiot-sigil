#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Core adversarial suites of the bounded authenticated-initiator replay
//! defense (gateway side).
//!
//! Everything here drives REAL sensor/gateway handshake flows through the
//! public facade and asserts the defense contract end-to-end: pre-crypto
//! rejection ordering, zero added secure-element work on hits and refusals,
//! no-resurrection under churn beyond capacity, fail-closed saturation with
//! expiry recovery, forged-frame live-entry immutability, exact wrap-boundary
//! expiry, guard precedence on both paths, cached-retransmission recovery,
//! the stale/reboot residuals, and the size/wire regression pins.

use core::mem::size_of;

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::frame::{FrameType, OUTER_HEADER_SIZE, PROTOCOL_VERSION};
use crate::core::install::wire::{InstallRequest, build_install_request};
use crate::core::manager::SessionManager;
use crate::core::manager::{
    HandshakeKind, REPLAY_HORIZON_SECS, ReplayCache, ReplayCacheEntry, replay_entry_expired,
};
use crate::core::pending::PendingState;
use crate::core::resume::wire::{RESUME_NONCE_SIZE, build_resume_request_body, resume_request_mac};
use crate::core::session::{Session, SessionRole};
use crate::core::test_support::{MockRandom, MockSecureElement, test_manager_with_mac};

const GW_MAC: [u8; 17] = [0xE0u8; 17];
const STATIC_PUB: [u8; 33] = [2u8; 33];
/// Host-provided session lifetime for every handler call below (seconds).
const LIFETIME: u32 = 86_400;

/// Builds a fresh, fully valid InstallRequest from a synthetic sensor
/// (its mock signs the factory certificate and request proof properly).
fn install_request(sensor_id: u8, sensor_mac: [u8; 17], now: u32) -> heapless::Vec<u8, 256> {
    let mut sensor: SessionManager<2> = test_manager_with_mac(sensor_mac);
    let mut se = MockSecureElement::sensor(sensor_id, sensor_mac);
    let mut rng = MockRandom::new();
    match sensor
        .start_install::<256>(GW_MAC, &mut se, &mut rng, now)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit the install request"),
    }
}

/// Delivers an install request to the gateway (healthy provider), returning
/// the raw handler result.
fn deliver_install<const N: usize>(
    gateway: &mut SessionManager<N>,
    request: &[u8],
    se_gw: &mut MockSecureElement,
    now: u32,
) -> Result<SigilAction<256>, SigilError> {
    gateway.handle_install_request::<256>(request, se_gw, &mut MockRandom::new(), now, LIFETIME)
}

/// Builds a well-formed ResumeRequest frame with a valid PSK MAC over
/// `(sensor_mac ‖ nonce)`.
fn resume_frame(
    psk_byte: u8,
    sensor_mac: &[u8; 17],
    nonce: &[u8; RESUME_NONCE_SIZE],
) -> heapless::Vec<u8, 64> {
    let req_mac = resume_request_mac(&[psk_byte; 32], sensor_mac, nonce).unwrap();
    let body = build_resume_request_body(nonce, &req_mac).unwrap();
    let mut frame: heapless::Vec<u8, 64> = heapless::Vec::new();
    frame
        .extend_from_slice(&crate::core::frame::build_header(
            sensor_mac,
            FrameType::ResumeRequest,
        ))
        .unwrap();
    frame.extend_from_slice(&body).unwrap();
    frame
}

/// Delivers a resume request to the gateway (healthy provider).
fn deliver_resume<const N: usize>(
    gateway: &mut SessionManager<N>,
    frame: &[u8],
    se_gw: &mut MockSecureElement,
    now: u32,
) -> Result<SigilAction<256>, SigilError> {
    gateway.handle_resume_request::<256>(frame, se_gw, &mut MockRandom::new(), now, LIFETIME)
}

/// Enrolls one gateway-side shell session (post-reboot state).
fn enroll<const N: usize>(gateway: &mut SessionManager<N>, peer: [u8; 17], psk_byte: u8) {
    gateway
        .insert(
            Session::new_enrolled(peer, STATIC_PUB, [psk_byte; 32], SessionRole::Gateway).unwrap(),
        )
        .unwrap();
}

/// Corrupts the request-MAC field in place (body offset: header + nonce).
fn corrupt_req_mac(frame: &mut [u8]) {
    frame[OUTER_HEADER_SIZE + RESUME_NONCE_SIZE] ^= 0xFF;
}

#[test]
fn install_same_peer_replay_rejected_before_se() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let request = install_request(1, [0xC1u8; 17], 1_000);

    // First delivery authenticates fully and caches the triple.
    assert!(matches!(
        deliver_install(&mut gateway, &request, &mut se_gw, 1_000).unwrap(),
        SigilAction::Transmit { .. }
    ));
    assert_eq!(gateway.replay_cache().len(), 1);
    // Host policy: abandon the stale attempt (frees pending for the probe).
    gateway.cancel_pending(&[0xC1u8; 17]).unwrap();

    let baseline = (
        se_gw.verify_ecdsa_call_count(),
        se_gw.ecdh_call_count(),
        se_gw.sign_ecdsa_call_count(),
    );

    // In-horizon redelivery of the exact recording: rejected BEFORE any
    // secure-element work (zero counter delta) and without touching state.
    let result = deliver_install(&mut gateway, &request, &mut se_gw, 1_020);
    assert_eq!(
        result,
        Err(SigilError::HandshakeReplay { peer: [0xC1u8; 17] })
    );
    assert_eq!(
        baseline,
        (
            se_gw.verify_ecdsa_call_count(),
            se_gw.ecdh_call_count(),
            se_gw.sign_ecdsa_call_count()
        )
    );
    assert_eq!(gateway.replay_cache().len(), 1);

    // Even with garbage signatures the verdict is the cached one: the
    // lookup provably precedes both ECDSA verifications.
    let mut forged = request.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;
    assert_eq!(
        deliver_install(&mut gateway, &forged, &mut se_gw, 1_020),
        Err(SigilError::HandshakeReplay { peer: [0xC1u8; 17] })
    );
    assert_eq!(
        baseline,
        (
            se_gw.verify_ecdsa_call_count(),
            se_gw.ecdh_call_count(),
            se_gw.sign_ecdsa_call_count()
        )
    );
}

#[test]
fn resume_same_peer_replay_rejected_before_mac_and_se() {
    const SENSOR: [u8; 17] = [0xD1u8; 17];
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    enroll(&mut gateway, SENSOR, 0x5A);
    let mut se_gw = MockSecureElement::default();
    let frame = resume_frame(0x5A, &SENSOR, &[0xA1u8; RESUME_NONCE_SIZE]);

    assert!(matches!(
        deliver_resume(&mut gateway, &frame, &mut se_gw, 1_000).unwrap(),
        SigilAction::Transmit { .. }
    ));
    assert_eq!(gateway.replay_cache().len(), 1);
    gateway.cancel_pending(&SENSOR).unwrap();

    let baseline = (
        se_gw.verify_ecdsa_call_count(),
        se_gw.ecdh_call_count(),
        se_gw.sign_ecdsa_call_count(),
    );

    // Exact recording: rejected before the PSK-keyed MAC computation and
    // before SE-ECDH (zero crypto units).
    assert_eq!(
        deliver_resume(&mut gateway, &frame, &mut se_gw, 1_020),
        Err(SigilError::HandshakeReplay { peer: SENSOR })
    );

    // A CORRUPTED request MAC on the same triple still yields the cached
    // verdict: the lookup provably precedes the MAC comparison.
    let mut bad_mac = frame.clone();
    corrupt_req_mac(&mut bad_mac);
    assert_eq!(
        deliver_resume(&mut gateway, &bad_mac, &mut se_gw, 1_020),
        Err(SigilError::HandshakeReplay { peer: SENSOR })
    );
    assert_eq!(
        baseline,
        (
            se_gw.verify_ecdsa_call_count(),
            se_gw.ecdh_call_count(),
            se_gw.sign_ecdsa_call_count()
        )
    );
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn install_multi_peer_replay_bounded() {
    const PEERS: [[u8; 17]; 8] = [
        [0xC1u8; 17],
        [0xC2u8; 17],
        [0xC3u8; 17],
        [0xC4u8; 17],
        [0xC5u8; 17],
        [0xC6u8; 17],
        [0xC7u8; 17],
        [0xC8u8; 17],
    ];
    let mut gateway: SessionManager<8> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut requests: heapless::Vec<(PeerIdBuf, heapless::Vec<u8, 256>), 8> = heapless::Vec::new();

    // Eight fresh initiators complete (spaced past the 15 s install
    // cooldown so admission never masks the cache layer); the host cancels
    // each stale pending right after (documented reclaim policy).
    for (i, peer) in PEERS.iter().enumerate() {
        let request = install_request(1 + i as u8, *peer, 20 * i as u32);
        assert!(deliver_install(&mut gateway, &request, &mut se_gw, 20 * i as u32).is_ok());
        gateway.cancel_pending(peer).unwrap();
        requests.push((*peer, request)).unwrap();
    }
    assert_eq!(gateway.replay_cache().len(), 8);
    assert!(gateway.is_empty(), "requests never create sessions");

    // EVERY earlier recording replays in-horizon: all suppressed, none
    // evicted, established-session table untouched throughout.
    for (peer, request) in requests.iter() {
        assert_eq!(
            deliver_install(&mut gateway, request, &mut se_gw, 200),
            Err(SigilError::HandshakeReplay { peer: *peer })
        );
    }
    assert_eq!(gateway.replay_cache().len(), 8);
    assert!(gateway.is_empty());
}

#[test]
fn resume_multi_peer_replay_bounded() {
    const PEERS: [[u8; 17]; 8] = [
        [0xD1u8; 17],
        [0xD2u8; 17],
        [0xD3u8; 17],
        [0xD4u8; 17],
        [0xD5u8; 17],
        [0xD6u8; 17],
        [0xD7u8; 17],
        [0xD8u8; 17],
    ];
    let mut gateway: SessionManager<8> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::default();
    let mut frames: heapless::Vec<(PeerIdBuf, heapless::Vec<u8, 64>), 8> = heapless::Vec::new();

    for (i, peer) in PEERS.iter().enumerate() {
        enroll(&mut gateway, *peer, 0x30 + i as u8);
        let frame = resume_frame(0x30 + i as u8, peer, &[0x40 + i as u8; RESUME_NONCE_SIZE]);
        assert!(deliver_resume(&mut gateway, &frame, &mut se_gw, 20 * i as u32).is_ok());
        gateway.cancel_pending(peer).unwrap();
        frames.push((*peer, frame)).unwrap();
    }
    assert_eq!(gateway.replay_cache().len(), 8);

    for (peer, frame) in frames.iter() {
        assert_eq!(
            deliver_resume(&mut gateway, frame, &mut se_gw, 200),
            Err(SigilError::HandshakeReplay { peer: *peer })
        );
    }
    assert_eq!(gateway.replay_cache().len(), 8);
}

#[test]
fn handshake_kinds_are_disjoint_cache_keys() {
    const SENSOR: [u8; 17] = [0xD9u8; 17];
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    enroll(&mut gateway, SENSOR, 0x5A);
    let mut se_gw = MockSecureElement::default();
    let mut se_inst = MockSecureElement::gateway(2, GW_MAC);

    // Install accepts nonce X...
    let install_x = install_request(1, SENSOR, 1_000);
    assert!(deliver_install(&mut gateway, &install_x, &mut se_inst, 1_000).is_ok());
    gateway.cancel_pending(&SENSOR).unwrap();

    // ...and the SAME identity+nonce must still be deliverable as RESUME:
    // namespaces are disjoint, so no HandshakeReplay may fire.
    let resume_x = resume_frame(0x5A, &SENSOR, &[0x77u8; RESUME_NONCE_SIZE]);
    assert!(matches!(
        deliver_resume(&mut gateway, &resume_x, &mut se_gw, 1_020).unwrap(),
        SigilAction::Transmit { .. }
    ));
    gateway.cancel_pending(&SENSOR).unwrap();

    // Vice versa: a RESUME acceptance of nonce Y must not suppress an
    // INSTALL delivery of the same (peer, nonce) — the install frame here
    // carries garbage signatures, so the honest expectation is an
    // authentication failure reached THROUGH the cache layer (never
    // HandshakeReplay).
    let resume_y = resume_frame(0x5A, &SENSOR, &[0x88u8; RESUME_NONCE_SIZE]);
    assert!(deliver_resume(&mut gateway, &resume_y, &mut se_gw, 1_040).is_ok());
    gateway.cancel_pending(&SENSOR).unwrap();
    let forged_install_y = build_install_request(&InstallRequest {
        sensor_peer_mac: SENSOR,
        hardware_profile_id: 1,
        factory_key_id: 1,
        sensor_static_pubkey: STATIC_PUB,
        factory_cert_sig: [0x99u8; 64],
        sensor_nonce: [0x88u8; 16],
        sensor_signature: [0x99u8; 64],
    })
    .unwrap();
    assert_eq!(
        deliver_install(&mut gateway, &forged_install_y, &mut se_inst, 1_060),
        Err(SigilError::VerificationFailed)
    );
    // Occupancy: exactly one slot per accepted handshake (three accepts).
    assert_eq!(gateway.replay_cache().len(), 3);
}

type PeerIdBuf = [u8; 17];

#[test]
fn churn_beyond_capacity_never_resurrects_recorded_pairs() {
    const PEERS: [[u8; 17]; 8] = [
        [0xC1u8; 17],
        [0xC2u8; 17],
        [0xC3u8; 17],
        [0xC4u8; 17],
        [0xC5u8; 17],
        [0xC6u8; 17],
        [0xC7u8; 17],
        [0xC8u8; 17],
    ];
    let mut gateway: SessionManager<8> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let mut recordings: heapless::Vec<(PeerIdBuf, heapless::Vec<u8, 256>), 8> =
        heapless::Vec::new();

    // Exactly the first N fresh initiators authenticate, complete, and
    // enter the cache (spaced > cooldown; host reclaims their pendings).
    for (i, peer) in PEERS.iter().enumerate() {
        let request = install_request(1 + i as u8, *peer, 20 * i as u32);
        assert!(deliver_install(&mut gateway, &request, &mut se_gw, 20 * i as u32).is_ok());
        gateway.cancel_pending(peer).unwrap();
        recordings.push((*peer, request)).unwrap();
    }
    assert_eq!(gateway.replay_cache().len(), 8);

    let baseline = (
        se_gw.verify_ecdsa_call_count(),
        se_gw.ecdh_call_count(),
        se_gw.sign_ecdsa_call_count(),
    );

    // The (N+1)-th fresh initiator is refused fail-closed BEFORE
    // authentication: zero crypto units consumed.
    let ninth = install_request(9, [0xC9u8; 17], 160);
    assert_eq!(
        deliver_install(&mut gateway, &ninth, &mut se_gw, 160),
        Err(SigilError::ReplayCacheFull { peer: [0xC9u8; 17] })
    );
    assert_eq!(
        baseline,
        (
            se_gw.verify_ecdsa_call_count(),
            se_gw.ecdh_call_count(),
            se_gw.sign_ecdsa_call_count()
        )
    );
    assert!(gateway.get_pending(&[0xC9u8; 17]).is_none());

    // And every earlier recording still replays in-horizon: suppression
    // held for ALL of them; no eviction was ever observed.
    for (peer, request) in recordings.iter() {
        assert_eq!(
            deliver_install(&mut gateway, request, &mut se_gw, 180),
            Err(SigilError::HandshakeReplay { peer: *peer })
        );
    }
    assert_eq!(gateway.replay_cache().len(), 8);
}

#[test]
fn saturation_fail_closed_then_expiry_recovers() {
    const PEERS: [[u8; 17]; 4] = [[0xCAu8; 17], [0xCBu8; 17], [0xCCu8; 17], [0xCDu8; 17]];
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    // Pressure phase: four fresh pairs fill the cache completely.
    for (i, peer) in PEERS.iter().enumerate() {
        let request = install_request(1 + i as u8, *peer, 20 * i as u32);
        assert!(deliver_install(&mut gateway, &request, &mut se_gw, 20 * i as u32).is_ok());
        gateway.cancel_pending(peer).unwrap();
    }
    assert_eq!(gateway.replay_cache().len(), 4);

    let baseline = (
        se_gw.verify_ecdsa_call_count(),
        se_gw.ecdh_call_count(),
        se_gw.sign_ecdsa_call_count(),
    );
    // A fifth fresh pair is refused with zero crypto (fail-closed).
    let fifth = install_request(5, [0xCEu8; 17], 80);
    assert_eq!(
        deliver_install(&mut gateway, &fifth, &mut se_gw, 80),
        Err(SigilError::ReplayCacheFull { peer: [0xCEu8; 17] })
    );
    assert_eq!(
        baseline,
        (
            se_gw.verify_ecdsa_call_count(),
            se_gw.ecdh_call_count(),
            se_gw.sign_ecdsa_call_count()
        )
    );
    // The refusal consumed no cooldown either (refused pre-authentication).
    gateway.cancel_pending(&[0xCEu8; 17]).unwrap_err();

    // Pressure stops; expiry restores capacity and handshakes (Section 5
    // semantics — recovery through TTL, not time-healing under load).
    let retry_at = 60 + REPLAY_HORIZON_SECS;
    assert!(matches!(
        deliver_install(&mut gateway, &fifth, &mut se_gw, retry_at).unwrap(),
        SigilAction::Transmit { .. }
    ));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn forged_frames_cannot_insert_evict_or_influence() {
    const OLD: [u8; 17] = [0xB1u8; 17];
    const VICTIM: [u8; 17] = [0xB2u8; 17];
    let mut gateway: SessionManager<8> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    // Two accepted handshakes: OLD will age past the horizon, VICTIM stays
    // live for the whole scenario (monotonic clock contract respected).
    let old_request = install_request(1, OLD, 0);
    assert!(deliver_install(&mut gateway, &old_request, &mut se_gw, 0).is_ok());
    gateway.cancel_pending(&OLD).unwrap();
    let victim_request = install_request(2, VICTIM, 100);
    assert!(deliver_install(&mut gateway, &victim_request, &mut se_gw, 100).is_ok());
    gateway.cancel_pending(&VICTIM).unwrap();

    let snapshot = |gw: &SessionManager<8>| {
        gw.replay_cache()
            .iter()
            .cloned()
            .collect::<heapless::Vec<ReplayCacheEntry, 8>>()
    };
    let before = snapshot(&gateway);
    assert_eq!(before.len(), 2);

    // Forged storm at t=3650: OLD (stamped 0) is strictly beyond the
    // horizon, VICTIM (stamped 100, age 3550) is still live.
    // (a) Claiming the VICTIM's exact recorded nonce: the LIVE verdict is
    //     unflippable — HandshakeReplay regardless of authentication.
    let mut forged_victim = victim_request.clone();
    let last = forged_victim.len() - 1;
    forged_victim[last] ^= 0xFF;
    assert_eq!(
        deliver_install(&mut gateway, &forged_victim, &mut se_gw, 3_650),
        Err(SigilError::HandshakeReplay { peer: VICTIM })
    );
    // (b) Claiming OLD's recorded nonce: the shared purge legally reclaims
    //     the strictly-expired prefix entry, then authentication fails —
    //     the ONLY attacker-triggerable effect (Section 4 proof).
    let mut forged_old = old_request.clone();
    forged_old[last] ^= 0xFF;
    assert_eq!(
        deliver_install(&mut gateway, &forged_old, &mut se_gw, 3_650),
        Err(SigilError::VerificationFailed)
    );
    // (c) Fresh forged nonces (well-formed frames, garbage signatures):
    //     lookup misses, authentication rejects, nothing inserted.
    for salt in [0x01u8, 0x02u8] {
        let mut nonce = [0xDDu8; 16];
        nonce[15] = salt;
        let forged_fresh = build_install_request(&InstallRequest {
            sensor_peer_mac: VICTIM,
            hardware_profile_id: 1,
            factory_key_id: 1,
            sensor_static_pubkey: STATIC_PUB,
            factory_cert_sig: [0x66u8; 64],
            sensor_nonce: nonce,
            sensor_signature: [0x66u8; 64],
        })
        .unwrap();
        assert_eq!(
            deliver_install(&mut gateway, &forged_fresh, &mut se_gw, 3_650),
            Err(SigilError::VerificationFailed)
        );
    }

    // Live content byte-identical: OLD (expired prefix) reclaimed, VICTIM
    // untouched at the front; no insertion, no reorder, no refresh.
    let after = snapshot(&gateway);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0], before[1]);

    // The victim handshake itself succeeds afterwards (fresh nonce; its
    // expired original slot is reclaimed by the shared purge).
    let fresh_victim = install_request(3, VICTIM, 4_020);
    assert!(matches!(
        deliver_install(&mut gateway, &fresh_victim, &mut se_gw, 4_020).unwrap(),
        SigilAction::Transmit { .. }
    ));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn wrap_boundary_exact_expiry() {
    // Contract A arithmetic, tick-by-tick around the computed instant:
    // stamp k=10 ticks before u32::MAX expires at the first post-wrap
    // second satisfying (k+1)+now >= HORIZON, i.e. now = 3589.
    let seen = u32::MAX - 10;
    assert!(!replay_entry_expired(seen, u32::MAX));
    for now in 0..=3588u32 {
        assert!(!replay_entry_expired(seen, now), "now={now}");
    }
    for now in 3589..=3600u32 {
        assert!(replay_entry_expired(seen, now), "now={now}");
    }
    // Same-epoch boundaries are exact to the second as well.
    assert!(!replay_entry_expired(
        1_000,
        1_000 + REPLAY_HORIZON_SECS - 1
    ));
    assert!(replay_entry_expired(1_000, 1_000 + REPLAY_HORIZON_SECS));
    // Long-idle aliasing pinned fail-closed: after nearly a full counter
    // period the ancient stamp aliases to "same epoch, small age", so the
    // stale recording keeps being SUPPRESSED — denied, never accepted.
    assert!(!replay_entry_expired(100, 101));

    // Cache-level cross-wrap behavior through the public store API.
    let mut cache: ReplayCache<4> = ReplayCache::new();
    let peer = [0xE1u8; 17];
    cache
        .insert(HandshakeKind::Resume, peer, &[0x0Au8; 16], u32::MAX - 20)
        .unwrap();
    cache.prefix_purge(u32::MAX - 5);
    assert!(cache.contains(HandshakeKind::Resume, &peer, &[0x0Au8; 16]));
    // Cross-wrap age (21) + 3579 >= 3600 → strictly expired → reclaimed.
    cache.prefix_purge(3579);
    assert!(!cache.contains(HandshakeKind::Resume, &peer, &[0x0Au8; 16]));

    // End-to-end flavor: an acceptance stamped 20 ticks before the wrap
    // suppresses its recording across the boundary while the entry lives.
    // (Its 15 s admission stamp ages out BEFORE the wrap, so the replay
    // layer itself answers on this probe.)
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let request = install_request(1, [0xE2u8; 17], u32::MAX - 20);
    assert!(deliver_install(&mut gateway, &request, &mut se_gw, u32::MAX - 20).is_ok());
    gateway.cancel_pending(&[0xE2u8; 17]).unwrap();
    assert_eq!(
        deliver_install(&mut gateway, &request, &mut se_gw, u32::MAX - 4),
        Err(SigilError::HandshakeReplay { peer: [0xE2u8; 17] })
    );

    // A second acceptance stamped 5 ticks before the wrap keeps its
    // admission stamp alive across the boundary (monotonic clock).
    let late_request = install_request(2, [0xE3u8; 17], u32::MAX - 5);
    assert!(deliver_install(&mut gateway, &late_request, &mut se_gw, u32::MAX - 5).is_ok());
    gateway.cancel_pending(&[0xE3u8; 17]).unwrap();

    // Post-wrap: the surviving stamp's legacy saturating cooldown masks the
    // cache layer for ITS recordings — fail-closed.
    assert_eq!(
        deliver_install(&mut gateway, &late_request, &mut se_gw, 25),
        Err(SigilError::RateLimited { peer: [0xE3u8; 17] })
    );
    // ...while the first entry is still live under Contract A (cross-wrap
    // age 51 < horizon) and keeps suppressing its recording.
    assert_eq!(
        deliver_install(&mut gateway, &request, &mut se_gw, 30),
        Err(SigilError::HandshakeReplay { peer: [0xE2u8; 17] })
    );
}

#[test]
fn resume_guard_error_precedence_pinned() {
    const UNKNOWN: [u8; 17] = [0xF1u8; 17];
    const WRONG_ROLE: [u8; 17] = [0xF2u8; 17];
    const VICTIM: [u8; 17] = [0xF3u8; 17];
    const FILLERS: [[u8; 17]; 6] = [
        [0xFAu8; 17],
        [0xFBu8; 17],
        [0xFCu8; 17],
        [0xFDu8; 17],
        [0xFEu8; 17],
        [0xFFu8; 17],
    ];
    let mut gateway: SessionManager<8> = test_manager_with_mac(GW_MAC);
    enroll(&mut gateway, WRONG_ROLE, 0x21);
    enroll(&mut gateway, VICTIM, 0x22);
    for (i, filler) in FILLERS.iter().enumerate() {
        enroll(&mut gateway, *filler, 0x30 + i as u8);
    }
    let mut se_gw = MockSecureElement::default();

    // 1. Unknown peer ⇒ UnknownSession.
    let unknown_frame = resume_frame(0xEE, &UNKNOWN, &[0x01u8; RESUME_NONCE_SIZE]);
    assert_eq!(
        deliver_resume(&mut gateway, &unknown_frame, &mut se_gw, 1_000),
        Err(SigilError::UnknownSession { peer: UNKNOWN })
    );
    // 2. Stored role not gateway-side ⇒ WrongRole.
    gateway.get_mut(&WRONG_ROLE).unwrap().role = SessionRole::Sensor;
    let wrong_role_frame = resume_frame(0x21, &WRONG_ROLE, &[0x02u8; RESUME_NONCE_SIZE]);
    assert_eq!(
        deliver_resume(&mut gateway, &wrong_role_frame, &mut se_gw, 1_000),
        Err(SigilError::WrongRole { peer: WRONG_ROLE })
    );

    // 3. Bad-MAC frame during the victim cooldown ⇒ RateLimited, NOT
    //    VerificationFailed (the intentional precedence delta).
    let victim_a = resume_frame(0x22, &VICTIM, &[0xA0u8; RESUME_NONCE_SIZE]);
    assert!(deliver_resume(&mut gateway, &victim_a, &mut se_gw, 1_000).is_ok());
    gateway.cancel_pending(&VICTIM).unwrap();
    let mut bad_mac = victim_a.clone();
    corrupt_req_mac(&mut bad_mac);
    assert_eq!(
        deliver_resume(&mut gateway, &bad_mac, &mut se_gw, 1_005),
        Err(SigilError::RateLimited { peer: VICTIM })
    );

    // 4. While pending occupied ⇒ PendingAlreadyExists (guard precedes the
    //    MAC even for a corrupted-MAC frame).
    let victim_b = resume_frame(0x22, &VICTIM, &[0xA1u8; RESUME_NONCE_SIZE]);
    assert!(deliver_resume(&mut gateway, &victim_b, &mut se_gw, 1_020).is_ok());
    let mut pending_probe = resume_frame(0x22, &VICTIM, &[0xA2u8; RESUME_NONCE_SIZE]);
    corrupt_req_mac(&mut pending_probe);
    assert_eq!(
        deliver_resume(&mut gateway, &pending_probe, &mut se_gw, 1_020),
        Err(SigilError::PendingAlreadyExists { peer: VICTIM })
    );
    gateway.cancel_pending(&VICTIM).unwrap();

    // 5. Fill the cache to capacity with other peers' completions...
    for (i, filler) in FILLERS.iter().enumerate() {
        let frame = resume_frame(0x30 + i as u8, filler, &[0x50 + i as u8; RESUME_NONCE_SIZE]);
        assert!(deliver_resume(&mut gateway, &frame, &mut se_gw, 1_040 + 20 * i as u32).is_ok());
        gateway.cancel_pending(filler).unwrap();
    }
    assert_eq!(gateway.replay_cache().len(), 8);
    // ...then a clean-guard victim frame is refused ReplayCacheFull BEFORE
    // any MAC work (its MAC is corrupted here — never consulted).
    let saturated_probe = resume_frame(0x22, &VICTIM, &[0xA3u8; RESUME_NONCE_SIZE]);
    let mut corrupted_saturated = saturated_probe.clone();
    corrupt_req_mac(&mut corrupted_saturated);
    assert_eq!(
        deliver_resume(&mut gateway, &corrupted_saturated, &mut se_gw, 1_160),
        Err(SigilError::ReplayCacheFull { peer: VICTIM })
    );

    // 6. Guards clear (horizon elapsed everywhere) ⇒ the bad MAC finally
    //    surfaces as VerificationFailed.
    let late_probe = resume_frame(0x22, &VICTIM, &[0xA4u8; RESUME_NONCE_SIZE]);
    let mut corrupted_late = late_probe;
    corrupt_req_mac(&mut corrupted_late);
    assert_eq!(
        deliver_resume(&mut gateway, &corrupted_late, &mut se_gw, 8_000),
        Err(SigilError::VerificationFailed)
    );
}

#[test]
fn error_precedence_cooldown_pending_before_cache() {
    const SENSOR: [u8; 17] = [0xE3u8; 17];

    // RESUME path: in-cooldown duplicate returns RateLimited on BOTH layers.
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    enroll(&mut gateway, SENSOR, 0x5A);
    let mut se_gw = MockSecureElement::default();
    let frame = resume_frame(0x5A, &SENSOR, &[0xB0u8; RESUME_NONCE_SIZE]);
    assert!(deliver_resume(&mut gateway, &frame, &mut se_gw, 1_000).is_ok());
    // Pending occupied ⇒ PendingAlreadyExists and pending untouched.
    assert_eq!(
        deliver_resume(&mut gateway, &frame, &mut se_gw, 1_000),
        Err(SigilError::PendingAlreadyExists { peer: SENSOR })
    );
    assert!(matches!(
        gateway.get_pending(&SENSOR).unwrap().state(),
        PendingState::ResumeGatewayAwaitConfirm { .. }
    ));
    gateway.cancel_pending(&SENSOR).unwrap();
    // Cooldown precedes the cache hit: RateLimited, never HandshakeReplay.
    assert_eq!(
        deliver_resume(&mut gateway, &frame, &mut se_gw, 1_001),
        Err(SigilError::RateLimited { peer: SENSOR })
    );

    // INSTALL path: same precedence chain...
    let mut gateway_i: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_inst = MockSecureElement::gateway(2, GW_MAC);
    let request = install_request(1, SENSOR, 1_000);
    assert!(deliver_install(&mut gateway_i, &request, &mut se_inst, 1_000).is_ok());
    assert_eq!(
        deliver_install(&mut gateway_i, &request, &mut se_inst, 1_000),
        Err(SigilError::PendingAlreadyExists { peer: SENSOR })
    );
    gateway_i.cancel_pending(&SENSOR).unwrap();
    assert_eq!(
        deliver_install(&mut gateway_i, &request, &mut se_inst, 1_001),
        Err(SigilError::RateLimited { peer: SENSOR })
    );

    // ...plus the disclosed occupancy oracle: clean cheap guards + saturated
    // cache ⇒ ReplayCacheFull fires BEFORE signature authentication (zero
    // SE calls for the refused frame).
    const FILLERS: [[u8; 17]; 3] = [[0xE4u8; 17], [0xE5u8; 17], [0xE6u8; 17]];
    for (i, filler) in FILLERS.iter().enumerate() {
        let filler_request = install_request(2 + i as u8, *filler, 1_020 + 20 * i as u32);
        assert!(
            deliver_install(
                &mut gateway_i,
                &filler_request,
                &mut se_inst,
                1_020 + 20 * i as u32
            )
            .is_ok()
        );
        gateway_i.cancel_pending(filler).unwrap();
    }
    assert_eq!(gateway_i.replay_cache().len(), 4);
    let baseline = (
        se_inst.verify_ecdsa_call_count(),
        se_inst.ecdh_call_count(),
        se_inst.sign_ecdsa_call_count(),
    );
    let forged = build_install_request(&InstallRequest {
        sensor_peer_mac: SENSOR,
        hardware_profile_id: 1,
        factory_key_id: 1,
        sensor_static_pubkey: STATIC_PUB,
        factory_cert_sig: [0x77u8; 64],
        sensor_nonce: [0xCCu8; 16],
        sensor_signature: [0x77u8; 64],
    })
    .unwrap();
    assert_eq!(
        deliver_install(&mut gateway_i, &forged, &mut se_inst, 1_080),
        Err(SigilError::ReplayCacheFull { peer: SENSOR })
    );
    assert_eq!(
        baseline,
        (
            se_inst.verify_ecdsa_call_count(),
            se_inst.ecdh_call_count(),
            se_inst.sign_ecdsa_call_count()
        )
    );
}

#[test]
fn cached_retransmission_preserved() {
    const SENSOR: [u8; 17] = [0xE7u8; 17];
    let mut sensor: SessionManager<2> = test_manager_with_mac(SENSOR);
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);

    // Full install completion; the triple entered the cache at Request
    // acceptance and holds exactly ONE slot throughout.
    let request = match sensor
        .start_install::<256>(GW_MAC, &mut se_sensor, &mut MockRandom::new(), 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("transmit"),
    };
    let challenge = match deliver_install(&mut gateway, &request, &mut se_gw, 1_000).unwrap() {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("challenge"),
    };
    assert_eq!(gateway.replay_cache().len(), 1);

    // Lost-challenge-style duplicate while the challenge is outstanding:
    // the same-peer pending guard answers first (row-2 precedence pinned),
    // the cache stays untouched.
    assert_eq!(
        deliver_install(&mut gateway, &request, &mut se_gw, 1_005),
        Err(SigilError::PendingAlreadyExists { peer: SENSOR })
    );

    let confirm = match sensor
        .continue_install::<256>(&challenge, &mut se_sensor, 1_000)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("confirm"),
    };
    let persist = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    let commit_first = match &persist {
        SigilAction::PersistPeerStaticKey { transmit, .. } => transmit.clone(),
        _ => panic!("persist"),
    };
    assert_eq!(gateway.replay_cache().len(), 1, "still exactly one slot");

    // Idempotent reTX machinery keeps working while the triple is cached.
    let persist_again = gateway
        .continue_install::<256>(&confirm, &mut se_gw, 1_000)
        .unwrap();
    match persist_again {
        SigilAction::PersistPeerStaticKey { transmit, .. } => {
            assert_eq!(transmit, commit_first);
        }
        _ => panic!("persist"),
    }
    let retransmit = gateway.retransmit_pending_cached::<256>(&SENSOR).unwrap();
    match retransmit {
        SigilAction::Transmit { payload, .. } => assert_eq!(payload, commit_first),
        _ => panic!("retransmit"),
    }

    // Recovery-window semantics after the commit boundary: the stale
    // request re-delivery meets the running cooldown (RateLimited — the
    // cached-retransmission recovery window), never HandshakeReplay.
    assert_eq!(
        deliver_install(&mut gateway, &request, &mut se_gw, 1_005),
        Err(SigilError::RateLimited { peer: SENSOR })
    );
    assert_eq!(gateway.replay_cache().len(), 1);

    let _ = sensor
        .continue_install::<256>(&commit_first, &mut se_sensor, 1_000)
        .unwrap();
}

#[test]
fn stale_replay_beyond_horizon_passes_once() {
    const SENSOR: [u8; 17] = [0xE8u8; 17];
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let request = install_request(1, SENSOR, 0);
    assert!(deliver_install(&mut gateway, &request, &mut se_gw, 0).is_ok());
    gateway.cancel_pending(&SENSOR).unwrap();

    // Inside the horizon: suppressed.
    assert_eq!(
        deliver_install(&mut gateway, &request, &mut se_gw, 2_000),
        Err(SigilError::HandshakeReplay { peer: SENSOR })
    );
    // Beyond the horizon: the residual — the recording passes ONCE.
    assert!(matches!(
        deliver_install(
            &mut gateway,
            &request,
            &mut se_gw,
            REPLAY_HORIZON_SECS + 100
        )
        .unwrap(),
        SigilAction::Transmit { .. }
    ));
    // Expired entry reclaimed by the pass, fresh acceptance inserted.
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn reboot_cold_cache_residual() {
    const SENSOR: [u8; 17] = [0xE9u8; 17];
    let mut booted: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GW_MAC);
    let request = install_request(1, SENSOR, 0);
    assert!(deliver_install(&mut booted, &request, &mut se_gw, 0).is_ok());

    // Reboot: RAM-only cache starts cold; the pre-reboot recording is
    // accepted ONCE by the fresh manager.
    let mut rebooted: SessionManager<4> = test_manager_with_mac(GW_MAC);
    assert!(matches!(
        deliver_install(&mut rebooted, &request, &mut se_gw, 10).unwrap(),
        SigilAction::Transmit { .. }
    ));
    rebooted.cancel_pending(&SENSOR).unwrap();
    // Afterwards the fresh cache suppresses the same recording again.
    assert_eq!(
        deliver_install(&mut rebooted, &request, &mut se_gw, 30),
        Err(SigilError::HandshakeReplay { peer: SENSOR })
    );
}

#[test]
fn wire_constants_sensor_layout_and_size_bounds_regression() {
    // Wire compatibility: protocol version and the two cached initiators'
    // frame-type discriminators are untouched by the replay defense.
    assert_eq!(PROTOCOL_VERSION, 0x03);
    assert_eq!(FrameType::InstallRequest as u8, 0x01);
    assert_eq!(FrameType::ResumeRequest as u8, 0x21);

    // Entry layout matches the approved RAM budget exactly (38 payload
    // bytes, alignment 4).
    assert_eq!(size_of::<ReplayCacheEntry>(), 40);

    // Per-N cache totals stay within the approved target bounds. On the
    // intended 32-bit gateway the Deque control block is 12 bytes
    // (92 B / 5132 B); this host test target is 64-bit, where the control
    // block pads to 24 bytes (104 B / 5144 B) — the asserted ceilings.
    assert!(
        size_of::<ReplayCache<2>>() <= 104,
        "{}",
        size_of::<ReplayCache<2>>()
    );
    assert!(
        size_of::<ReplayCache<128>>() <= 5_144,
        "{}",
        size_of::<ReplayCache<128>>()
    );

    // Sensor layout absence: the cache store is compiled out of sensor-only
    // builds by construction (every item is gateway-gated), which the
    // mono-role compilation gates enforce; the sensor-only manager
    // footprint therefore remains pinned by the existing
    // manager::tests::type_size_bounds suite, unchanged by this work.
}

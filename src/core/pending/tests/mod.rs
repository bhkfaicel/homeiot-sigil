#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for the tagged pending handshake states.
//!
//! Beyond constructor checks, this suite is the transition table for the
//! checked `*_stage_final` / `*_commit_sent` methods: every transition is
//! exercised from its valid predecessor and rejected from an invalid one,
//! with fail-atomic state preservation on every rejection.

mod footprint_report;
mod type_size_bounds;

use crate::core::error::SigilError;
use crate::core::pending::{
    InstallGatewayStaged, PendingHandshake, PendingState, ResumePskStash, deadline_from_now,
    timeout_ms_to_secs_ceil,
};
use crate::core::session::DirectionalMaterial;

/// Deterministic directional material for staging transitions.
fn material() -> DirectionalMaterial {
    DirectionalMaterial::symmetric_for_test([0xCDu8; 32], [0xEFu8; 4])
}

/// Deterministic gateway-side install staging payload.
fn install_gateway_staged() -> InstallGatewayStaged {
    InstallGatewayStaged {
        keys: material(),
        resume_psk: ResumePskStash::new([0x5Au8; 32]),
        sensor_static_pubkey: [0x02u8; 33],
        key_lifetime_secs: 86_400,
        gateway_nonce: crate::core::pending::Nonce16Stash::new([0x11u8; 16]),
        sensor_nonce: crate::core::pending::Nonce16Stash::new([0x22u8; 16]),
    }
}

#[test]
fn test_timeout_ms_to_secs_ceil() {
    assert_eq!(timeout_ms_to_secs_ceil(0), 1);
    assert_eq!(timeout_ms_to_secs_ceil(1), 1);
    assert_eq!(timeout_ms_to_secs_ceil(1000), 1);
    assert_eq!(timeout_ms_to_secs_ceil(1001), 2);
    assert_eq!(timeout_ms_to_secs_ceil(30_000), 30);
}

#[test]
fn test_new_install_sensor_stashes_initiator_nonce() {
    let peer = [1u8; 17];
    let now = 1_000u32;
    let nonce = [0x77u8; 16];
    let handshake = PendingHandshake::new_install_sensor(peer, nonce, 5000, now);

    assert_eq!(handshake.peer_mac, peer);
    assert_eq!(handshake.suggested_timeout_ms, 5000);
    assert_eq!(handshake.deadline_at, deadline_from_now(now, 5000));
    match handshake.state() {
        PendingState::InstallSensorAwaitChallenge { sensor_nonce } => {
            assert_eq!(sensor_nonce.as_array(), &nonce);
        }
        _ => panic!("expected InstallSensorAwaitChallenge"),
    }
}

#[test]
fn test_new_install_gateway_await_confirm_stages_material() {
    let peer = [1u8; 17];
    let staged = install_gateway_staged();
    let handshake = PendingHandshake::new_install_gateway_await_confirm(peer, staged, 5000, 1_000);

    assert_eq!(handshake.peer_mac, peer);
    assert!(matches!(
        handshake.state(),
        PendingState::InstallGatewayAwaitConfirm(_)
    ));
}

#[test]
fn test_new_renew_sensor_holds_no_secrets() {
    let peer = [1u8; 17];
    let now = 50u32;
    let handshake = PendingHandshake::new_renew_sensor(peer, 3000, now);

    // The variant has no secret-bearing fields at all: the secure element
    // generates and consumes the ephemeral scalar at challenge time.
    assert!(matches!(
        handshake.state(),
        PendingState::RenewSensorAwaitChallenge
    ));
    assert_eq!(handshake.suggested_timeout_ms, 3000);
    assert_eq!(handshake.deadline_at, now + 3);
}

#[test]
fn test_new_renew_gateway_stashes_p256_context() {
    let peer = [1u8; 17];
    let scalar = [0x77u8; 32];
    let public = [0x02u8; 33];
    let handshake =
        PendingHandshake::new_renew_gateway_await_confirm(peer, scalar, public, 3_600, 3000, 10);

    match handshake.state() {
        PendingState::RenewGatewayAwaitConfirm {
            p256_context,
            gateway_ephemeral_pubkey,
            key_lifetime_secs,
        } => {
            assert_eq!(p256_context.as_array(), &scalar);
            assert_eq!(*gateway_ephemeral_pubkey, public);
            assert_eq!(*key_lifetime_secs, 3_600);
        }
        _ => panic!("expected RenewGatewayAwaitConfirm"),
    }
}

#[test]
fn test_new_resume_sensor_stashes_request_nonce() {
    let peer = [1u8; 17];
    let nonce = [0xABu8; 16];
    let handshake = PendingHandshake::new_resume_sensor(peer, nonce, 2000, 10);

    match handshake.state() {
        PendingState::ResumeSensorAwaitChallenge { sensor_nonce } => {
            assert_eq!(sensor_nonce.as_array(), &nonce);
        }
        _ => panic!("expected ResumeSensorAwaitChallenge"),
    }
    assert_eq!(handshake.deadline_at, 12);
}

#[test]
fn test_new_resume_gateway_stages_keys() {
    let peer = [1u8; 17];
    let handshake =
        PendingHandshake::new_resume_gateway_await_confirm(peer, material(), 7_200, 2000, 10);

    assert!(matches!(
        handshake.state(),
        PendingState::ResumeGatewayAwaitConfirm { .. }
    ));
}

#[test]
fn test_install_sensor_stage_final_from_valid_predecessor() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install_sensor(peer, [1u8; 16], 5000, 100);

    handshake
        .install_sensor_stage_final(
            material(),
            [0x5Au8; 32],
            [0x02u8; 33],
            86_400,
            &[0xA1, 0xB2, 0xC3],
            200,
        )
        .unwrap();

    match handshake.state() {
        PendingState::InstallSensorFinalSent {
            keys,
            resume_psk,
            gateway_static_pubkey,
            key_lifetime_secs,
            cached,
        } => {
            assert_eq!(keys.s2g_key, material().s2g_key);
            assert_eq!(resume_psk.as_array(), &[0x5Au8; 32]);
            assert_eq!(*gateway_static_pubkey, [0x02u8; 33]);
            assert_eq!(*key_lifetime_secs, 86_400);
            assert_eq!(cached.as_slice(), &[0xA1, 0xB2, 0xC3]);
        }
        _ => panic!("expected InstallSensorFinalSent"),
    }
    // Deadline is refreshed from the transition instant.
    assert_eq!(handshake.deadline_at, deadline_from_now(200, 5000));
}

#[test]
fn test_install_sensor_stage_final_rejects_wrong_state() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_renew_sensor(peer, 5000, 100);

    assert_eq!(
        handshake.install_sensor_stage_final(
            material(),
            [0x5Au8; 32],
            [0x02u8; 33],
            86_400,
            &[0xA1],
            200
        ),
        Err(SigilError::InvalidStep { peer })
    );
    // Fail-atomic: the prior valid state survives the rejected transition.
    assert!(matches!(
        handshake.state(),
        PendingState::RenewSensorAwaitChallenge
    ));
}

#[test]
fn test_renew_sensor_stage_final_from_valid_predecessor() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_renew_sensor(peer, 10_000, 100);

    handshake
        .renew_sensor_stage_final(material(), 3_600, &[0x01, 0x02], 200)
        .unwrap();

    match handshake.state() {
        PendingState::RenewSensorFinalSent {
            keys,
            key_lifetime_secs,
            cached,
        } => {
            assert_eq!(keys.s2g_key, material().s2g_key);
            assert_eq!(*key_lifetime_secs, 3_600);
            assert_eq!(cached.as_slice(), &[0x01, 0x02]);
        }
        _ => panic!("expected RenewSensorFinalSent"),
    }
    assert_eq!(handshake.deadline_at, deadline_from_now(200, 10_000));
}

#[test]
fn test_renew_sensor_stage_final_rejects_wrong_state() {
    let peer = [1u8; 17];
    // A resume challenge-wait pending must not accept a renew Final.
    let mut handshake = PendingHandshake::new_resume_sensor(peer, [9u8; 16], 5000, 100);

    assert_eq!(
        handshake.renew_sensor_stage_final(material(), 3_600, &[0x01], 200),
        Err(SigilError::InvalidStep { peer })
    );
    assert!(matches!(
        handshake.state(),
        PendingState::ResumeSensorAwaitChallenge { .. }
    ));
}

#[test]
fn test_resume_sensor_stage_final_from_valid_predecessor() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_resume_sensor(peer, [7u8; 16], 5000, 100);

    handshake
        .resume_sensor_stage_final(material(), 7_200, &[0x03, 0x04], 200)
        .unwrap();

    match handshake.state() {
        PendingState::ResumeSensorFinalSent {
            keys,
            key_lifetime_secs,
            cached,
        } => {
            assert_eq!(keys.s2g_key, material().s2g_key);
            assert_eq!(*key_lifetime_secs, 7_200);
            assert_eq!(cached.as_slice(), &[0x03, 0x04]);
        }
        _ => panic!("expected ResumeSensorFinalSent"),
    }
    assert_eq!(handshake.deadline_at, deadline_from_now(200, 5000));
}

#[test]
fn test_resume_sensor_stage_final_rejects_wrong_state() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install_sensor(peer, [7u8; 16], 5000, 100);

    assert_eq!(
        handshake.resume_sensor_stage_final(material(), 7_200, &[0x03], 200),
        Err(SigilError::InvalidStep { peer })
    );
    assert!(matches!(
        handshake.state(),
        PendingState::InstallSensorAwaitChallenge { .. }
    ));
}

#[test]
fn test_install_gateway_commit_sent_from_valid_predecessor() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install_gateway_await_confirm(
        peer,
        install_gateway_staged(),
        5000,
        100,
    );

    handshake
        .install_gateway_commit_sent(&[0xAA, 0xBB], 200)
        .unwrap();

    match handshake.state() {
        PendingState::InstallGatewayCommitSent { cached } => {
            assert_eq!(cached.as_slice(), &[0xAA, 0xBB]);
        }
        _ => panic!("expected InstallGatewayCommitSent"),
    }
    assert_eq!(handshake.deadline_at, deadline_from_now(200, 5000));
}

#[test]
fn test_install_gateway_commit_sent_rejects_wrong_state() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_renew_sensor(peer, 5000, 100);

    assert_eq!(
        handshake.install_gateway_commit_sent(&[0xAA], 200),
        Err(SigilError::InvalidStep { peer })
    );
    assert!(matches!(
        handshake.state(),
        PendingState::RenewSensorAwaitChallenge
    ));
}

#[test]
fn test_renew_gateway_commit_sent_from_valid_predecessor() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_renew_gateway_await_confirm(
        peer,
        [0x42u8; 32],
        [0x02u8; 33],
        3_600,
        10_000,
        100,
    );

    handshake.renew_gateway_commit_sent(&[0xCC], 200).unwrap();

    match handshake.state() {
        PendingState::RenewGatewayCommitSent { cached } => {
            assert_eq!(cached.as_slice(), &[0xCC]);
        }
        _ => panic!("expected RenewGatewayCommitSent"),
    }
    assert_eq!(handshake.deadline_at, deadline_from_now(200, 10_000));
}

#[test]
fn test_renew_gateway_commit_sent_rejects_wrong_state() {
    let peer = [1u8; 17];
    let mut handshake =
        PendingHandshake::new_resume_gateway_await_confirm(peer, material(), 7_200, 5000, 100);

    assert_eq!(
        handshake.renew_gateway_commit_sent(&[0xCC], 200),
        Err(SigilError::InvalidStep { peer })
    );
    assert!(matches!(
        handshake.state(),
        PendingState::ResumeGatewayAwaitConfirm { .. }
    ));
}

#[test]
fn test_resume_gateway_commit_sent_from_valid_predecessor() {
    let peer = [1u8; 17];
    let mut handshake =
        PendingHandshake::new_resume_gateway_await_confirm(peer, material(), 7_200, 5000, 100);

    handshake.resume_gateway_commit_sent(&[0xDD], 200).unwrap();

    match handshake.state() {
        PendingState::ResumeGatewayCommitSent { cached } => {
            assert_eq!(cached.as_slice(), &[0xDD]);
        }
        _ => panic!("expected ResumeGatewayCommitSent"),
    }
    assert_eq!(handshake.deadline_at, deadline_from_now(200, 5000));
}

#[test]
fn test_resume_gateway_commit_sent_rejects_wrong_state() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install_sensor(peer, [7u8; 16], 5000, 100);

    assert_eq!(
        handshake.resume_gateway_commit_sent(&[0xDD], 200),
        Err(SigilError::InvalidStep { peer })
    );
    assert!(matches!(
        handshake.state(),
        PendingState::InstallSensorAwaitChallenge { .. }
    ));
}

#[test]
fn test_stage_final_rejects_oversized_frame_fail_atomically() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_renew_sensor(peer, 5000, 100);
    let oversized = [0u8; 129];

    assert_eq!(
        handshake.renew_sensor_stage_final(material(), 3_600, &oversized, 200),
        Err(SigilError::InvariantViolation)
    );
    // Fail-atomic: no partial staging, deadline untouched.
    assert!(matches!(
        handshake.state(),
        PendingState::RenewSensorAwaitChallenge
    ));
    assert_eq!(handshake.deadline_at, deadline_from_now(100, 5000));
}

#[test]
fn test_commit_critical_exactly_for_post_final_states() {
    let peer = [1u8; 17];

    // Pre-commit initial states are not commit-critical.
    let install_sensor = PendingHandshake::new_install_sensor(peer, [1u8; 16], 5000, 0);
    assert!(!install_sensor.state().is_commit_critical());
    let renew_sensor = PendingHandshake::new_renew_sensor(peer, 5000, 0);
    assert!(!renew_sensor.state().is_commit_critical());
    let resume_sensor = PendingHandshake::new_resume_sensor(peer, [1u8; 16], 5000, 0);
    assert!(!resume_sensor.state().is_commit_critical());
    let install_gateway = PendingHandshake::new_install_gateway_await_confirm(
        peer,
        install_gateway_staged(),
        5000,
        0,
    );
    assert!(!install_gateway.state().is_commit_critical());
    let renew_gateway = PendingHandshake::new_renew_gateway_await_confirm(
        peer,
        [1u8; 32],
        [0x02u8; 33],
        3_600,
        5000,
        0,
    );
    assert!(!renew_gateway.state().is_commit_critical());
    let resume_gateway =
        PendingHandshake::new_resume_gateway_await_confirm(peer, material(), 3_600, 5000, 0);
    assert!(!resume_gateway.state().is_commit_critical());

    // All six post-Final recovery states are commit-critical.
    let mut install_sensor = install_sensor;
    install_sensor
        .install_sensor_stage_final(material(), [1u8; 32], [0x02u8; 33], 3_600, &[0x01], 0)
        .unwrap();
    assert!(install_sensor.state().is_commit_critical());

    let mut renew_sensor = renew_sensor;
    renew_sensor
        .renew_sensor_stage_final(material(), 3_600, &[0x01], 0)
        .unwrap();
    assert!(renew_sensor.state().is_commit_critical());

    let mut resume_sensor = resume_sensor;
    resume_sensor
        .resume_sensor_stage_final(material(), 3_600, &[0x01], 0)
        .unwrap();
    assert!(resume_sensor.state().is_commit_critical());

    let mut install_gateway = install_gateway;
    install_gateway
        .install_gateway_commit_sent(&[0x01], 0)
        .unwrap();
    assert!(install_gateway.state().is_commit_critical());

    let mut renew_gateway = renew_gateway;
    renew_gateway.renew_gateway_commit_sent(&[0x01], 0).unwrap();
    assert!(renew_gateway.state().is_commit_critical());

    let mut resume_gateway = resume_gateway;
    resume_gateway
        .resume_gateway_commit_sent(&[0x01], 0)
        .unwrap();
    assert!(resume_gateway.state().is_commit_critical());
}

#[test]
fn test_cached_retransmission_frame_only_in_post_final_states() {
    let peer = [1u8; 17];

    // Pre-commit initial states expose no cached frame.
    let renew_sensor = PendingHandshake::new_renew_sensor(peer, 5000, 0);
    assert!(renew_sensor.state().cached_retransmission_frame().is_none());
    let resume_gateway =
        PendingHandshake::new_resume_gateway_await_confirm(peer, material(), 3_600, 5000, 0);
    assert!(
        resume_gateway
            .state()
            .cached_retransmission_frame()
            .is_none()
    );

    // Post-Final recovery states expose exactly their cached frame.
    let mut renew_sensor = renew_sensor;
    renew_sensor
        .renew_sensor_stage_final(material(), 3_600, &[0x11, 0x22], 0)
        .unwrap();
    assert_eq!(
        renew_sensor.state().cached_retransmission_frame(),
        Some(&[0x11u8, 0x22][..])
    );

    let mut resume_gateway = resume_gateway;
    resume_gateway
        .resume_gateway_commit_sent(&[0x33], 0)
        .unwrap();
    assert_eq!(
        resume_gateway.state().cached_retransmission_frame(),
        Some(&[0x33u8][..])
    );
}

#[test]
fn test_gateway_commit_transitions_drop_staged_secrets() {
    // Committing must consume the secret-bearing predecessor variant: the
    // provider context staged at challenge time no longer exists afterwards.
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_renew_gateway_await_confirm(
        peer,
        [0xABu8; 32],
        [0x02u8; 33],
        3_600,
        1000,
        0,
    );
    assert!(matches!(
        handshake.state(),
        PendingState::RenewGatewayAwaitConfirm { p256_context, .. }
            if p256_context.as_array() == &[0xABu8; 32]
    ));

    handshake.renew_gateway_commit_sent(&[0x01], 0).unwrap();

    assert!(matches!(
        handshake.state(),
        PendingState::RenewGatewayCommitSent { .. }
    ));
}

#[test]
fn test_drop_pending_smoke() {
    // Dropping secret-bearing pendings must run the zeroizing wrapper drops
    // without panicking (byte-level wipe is enforced by `ZeroizeOnDrop`).
    let peer = [1u8; 17];
    let handshake = PendingHandshake::new_renew_gateway_await_confirm(
        peer,
        [0x42u8; 32],
        [0x02u8; 33],
        3_600,
        3000,
        0,
    );
    drop(handshake);

    let mut staged = PendingHandshake::new_install_sensor(peer, [1u8; 16], 5000, 0);
    staged
        .install_sensor_stage_final(material(), [0x5Au8; 32], [0x02u8; 33], 3_600, &[0x01], 0)
        .unwrap();
    drop(staged);
}

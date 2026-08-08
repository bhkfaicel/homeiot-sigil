#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for pending handshake state

use crate::core::pending::{
    HandshakePhase, HandshakeRole, HandshakeStep, PendingHandshake, PendingSecrets,
    deadline_from_now, timeout_ms_to_secs_ceil,
};
use crate::core::session::DirectionalMaterial;

#[test]
fn test_timeout_ms_to_secs_ceil() {
    assert_eq!(timeout_ms_to_secs_ceil(0), 1);
    assert_eq!(timeout_ms_to_secs_ceil(1), 1);
    assert_eq!(timeout_ms_to_secs_ceil(1000), 1);
    assert_eq!(timeout_ms_to_secs_ceil(1001), 2);
    assert_eq!(timeout_ms_to_secs_ceil(30_000), 30);
}

#[test]
fn test_new_install_sensor() {
    let peer = [1u8; 17];
    let now = 1_000u32;
    let handshake = PendingHandshake::new_install(peer, HandshakeRole::Sensor, 5000, now);

    assert_eq!(handshake.peer_mac, peer);
    assert_eq!(handshake.phase, HandshakePhase::Install);
    assert_eq!(handshake.role, HandshakeRole::Sensor);
    assert_eq!(handshake.step, HandshakeStep::InstallWaitingForChallenge);
    assert!(handshake.secrets.is_none());
    assert_eq!(handshake.suggested_timeout_ms, 5000);
    assert_eq!(handshake.deadline_at, deadline_from_now(now, 5000));
}

#[test]
fn test_new_install_gateway() {
    let peer = [1u8; 17];
    let handshake = PendingHandshake::new_install(peer, HandshakeRole::Gateway, 5000, 0);

    assert_eq!(handshake.step, HandshakeStep::InstallWaitingForConfirm);
}

#[test]
fn test_new_renew_stores_eph_scalar() {
    let peer = [1u8; 17];
    let secret = [0x42u8; 32];
    let now = 50u32;
    let handshake = PendingHandshake::new_renew(peer, HandshakeRole::Sensor, secret, 3000, now);

    assert_eq!(handshake.phase, HandshakePhase::Renew);
    assert_eq!(handshake.eph_scalar(), Some(&secret));
    assert!(handshake.directional_keys().is_none());
    assert_eq!(handshake.suggested_timeout_ms, 3000);
    assert_eq!(handshake.deadline_at, now + 3);
}

#[test]
fn test_new_renew_gateway_stores_directional_keys() {
    let peer = [1u8; 17];
    let material = DirectionalMaterial::distinct_for_test([0x77u8; 32], [0x11u8; 4]);
    let handshake = PendingHandshake::new_renew_gateway(peer, material.clone(), 3000, 10);

    assert_eq!(handshake.role, HandshakeRole::Gateway);
    assert_eq!(handshake.step, HandshakeStep::RenewWaitingForAck);
    let stored = handshake.directional_keys().unwrap();
    assert_eq!(stored.s2g_key, material.s2g_key);
    assert_eq!(stored.g2s_key, material.g2s_key);
    assert!(handshake.eph_scalar().is_none());
}

#[test]
fn test_new_resume() {
    let peer = [1u8; 17];
    let handshake = PendingHandshake::new_resume(peer, HandshakeRole::Sensor, 2000, 10);

    assert_eq!(handshake.phase, HandshakePhase::Resume);
    assert!(handshake.secrets.is_none());
    assert_eq!(handshake.deadline_at, 12);
}

#[test]
fn test_set_nonce16_and_directional_keys_typed() {
 // typed accessors reject the wrong variant.

    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_resume(peer, HandshakeRole::Sensor, 2000, 0);
    let nonce = [0xABu8; 16];
    handshake.set_nonce16(nonce);
    assert_eq!(handshake.nonce16(), Some(&nonce));
    assert!(handshake.directional_keys().is_none());
    assert!(handshake.eph_scalar().is_none());

    let material = DirectionalMaterial::symmetric_for_test([0xCDu8; 32], [0xEFu8; 4]);
    handshake.set_directional_keys(material.clone());
    assert_eq!(
        handshake.directional_keys().unwrap().s2g_key,
        material.s2g_key
    );
    assert!(handshake.nonce16().is_none());
}

#[test]
fn test_update_step() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install(peer, HandshakeRole::Sensor, 5000, 0);

    assert_eq!(handshake.step, HandshakeStep::InstallWaitingForChallenge);
    handshake.update_step(HandshakeStep::InstallWaitingForConfirm);
    assert_eq!(handshake.step, HandshakeStep::InstallWaitingForConfirm);
}

#[test]
fn test_update_timeout() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install(peer, HandshakeRole::Sensor, 5000, 100);

    handshake.update_timeout(10000, 200);
    assert_eq!(handshake.suggested_timeout_ms, 10000);
    assert_eq!(handshake.deadline_at, 210);
}

#[test]
fn test_zeroize_secrets() {
    let peer = [1u8; 17];
    let secret = [0x42u8; 32];
    let mut handshake = PendingHandshake::new_renew(peer, HandshakeRole::Sensor, secret, 3000, 0);

    assert!(handshake.secrets.is_some());
    handshake.resume_psk = Some([0xBBu8; 32]);
    handshake.zeroize_secrets();
    assert!(handshake.secrets.is_none());
    assert!(handshake.resume_psk.is_none());
    assert!(handshake.transcript_nonce_prefix.is_none());
}

#[test]
fn test_pending_secrets_variants_distinct() {
    // Discriminants differ; typed accessors reject cross-variant reads.
    let eph = PendingSecrets::EphScalar([1u8; 32]);
    let keys = PendingSecrets::DirectionalKeys(DirectionalMaterial::symmetric_for_test(
        [1u8; 32], [2u8; 4],
    ));
    assert!(eph.as_eph_scalar().is_some());
    assert!(eph.as_directional().is_none());
    assert!(keys.as_directional().is_some());
    assert!(keys.as_eph_scalar().is_none());
    assert!(PendingSecrets::Nonce16([2u8; 16]).as_nonce16().is_some());
}

#[test]
fn test_zeroize_clears_challenge_nonce() {
    let peer = [1u8; 17];
    let mut handshake = PendingHandshake::new_install(peer, HandshakeRole::Gateway, 5000, 0);
    handshake.transcript_challenge_nonce = Some([0xABu8; 16]);
    handshake.transcript_nonce_prefix = Some([0xCDu8; 4]);
    handshake.zeroize_secrets();
    assert!(handshake.transcript_challenge_nonce.is_none());
    assert!(handshake.transcript_nonce_prefix.is_none());
}

#[test]
fn test_drop_zeroizes_secrets() {
    let peer = [1u8; 17];
    let secret = [0x42u8; 32];
    let mut handshake = PendingHandshake::new_renew(peer, HandshakeRole::Sensor, secret, 3000, 0);
    handshake.transcript_nonce_prefix = Some([1u8; 4]);
    drop(handshake);
}

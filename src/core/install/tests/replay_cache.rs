#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Replay-defense downstream-failure suites for the clear-text install
//! initiator path.
//!
//! Contract under test: every injectable fallible site after install
//! authentication propagates its error, leaves the replay cache
//! byte-identical (NO insertion), keeps the post-authentication admission
//! stamp semantics intact (an identical immediate retry returns
//! `RateLimited` — never `HandshakeReplay`), and the identical retry
//! succeeds at the exact cooldown boundary.

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::install::INSTALL_REQUEST_COOLDOWN;
use crate::core::manager::SessionManager;
use crate::core::test_support::{
    FailingRandom, MockRandom, MockSecureElement, test_manager_with_mac,
};

const SENSOR_MAC: [u8; 17] = [0x71u8; 17];
const GW_MAC: [u8; 17] = [0x72u8; 17];
/// Session-key lifetime used by every gateway handler call in this suite.
const LIFETIME: u32 = 86_400;

/// Builds a fresh, fully valid `InstallRequest` frame by driving the sensor
/// start step (its mock signs the request properly). The sensor-side state
/// is local to this helper: requests are self-contained wire frames.
fn fresh_install_request(sensor_id: u8, now: u32) -> heapless::Vec<u8, 256> {
    let mut sensor: SessionManager<2> = test_manager_with_mac(SENSOR_MAC);
    let mut se = MockSecureElement::sensor(sensor_id, SENSOR_MAC);
    let mut rng = MockRandom::new();
    match sensor
        .start_install::<256>(GW_MAC, &mut se, &mut rng, now)
        .unwrap()
    {
        SigilAction::Transmit { payload, .. } => payload,
        _ => panic!("sensor should transmit the install request"),
    }
}

/// Shared downstream-failure scenario: one failing attempt with `se_bad`,
/// cache untouched, immediate duplicate refused by the live cooldown stamp,
/// identical retry at the cooldown boundary succeeding and inserting
/// exactly one cache slot.
macro_rules! assert_downstream_failure_retry {
    (
        $gateway:expr, $request:expr, $se_bad:expr, $se_good:expr,
        $rng_bad:expr, $rng_good:expr, $now:expr, $expected_err:expr
    ) => {{
        // The failing attempt propagates the injected provider error...
        assert_eq!(
            $gateway.handle_install_request::<256>(
                &$request,
                &mut $se_bad,
                &mut $rng_bad,
                $now,
                LIFETIME
            ),
            Err($expected_err)
        );
        // ...the cache stayed byte-identical (no triple written)...
        assert_eq!($gateway.replay_cache().len(), 0);
        assert!($gateway.get_pending(&SENSOR_MAC).is_none());
        // ...the post-authentication admission stamp is live, so an
        // identical immediate retry returns RateLimited — NOT
        // HandshakeReplay (retry-atomicity contract)...
        assert_eq!(
            $gateway.handle_install_request::<256>(
                &$request,
                &mut $se_bad,
                &mut $rng_bad,
                $now,
                LIFETIME
            ),
            Err(SigilError::RateLimited { peer: SENSOR_MAC })
        );
        // ...and the identical retry succeeds at the exact cooldown
        // boundary with a healthy provider, inserting exactly one slot.
        let retry = $gateway.handle_install_request::<256>(
            &$request,
            &mut $se_good,
            &mut $rng_good,
            $now + INSTALL_REQUEST_COOLDOWN,
            LIFETIME,
        );
        assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
        assert_eq!($gateway.replay_cache().len(), 1);
    }};
}

#[test]
fn install_downstream_ecdh_failure_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    se_bad.reject_ecdh();
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);
    assert_downstream_failure_retry!(
        gateway,
        request,
        se_bad,
        se_good,
        MockRandom::new(),
        MockRandom::new(),
        1_000u32,
        SigilError::EcdhFailed
    );
}

#[test]
fn install_downstream_rng_failure_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);
    // The RNG nonce fill happens after authentication and after the stamp;
    // FailingRandom models an unhealthy entropy source at that exact site.
    assert_downstream_failure_retry!(
        gateway,
        request,
        se_bad,
        se_good,
        FailingRandom,
        MockRandom::new(),
        1_000u32,
        SigilError::RandomFailed
    );
}

#[test]
fn install_downstream_provider_failure_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    se_bad.fail_provider_getters();
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);
    // Grouped retrieval sites (`get_static_pubkey` / `get_factory_cert` /
    // metadata): demonstrably equivalent failure classes share one test.
    assert_downstream_failure_retry!(
        gateway,
        request,
        se_bad,
        se_good,
        MockRandom::new(),
        MockRandom::new(),
        1_000u32,
        SigilError::RandomFailed
    );
}

#[test]
fn install_downstream_signing_failure_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    se_bad.reject_signing();
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);
    assert_downstream_failure_retry!(
        gateway,
        request,
        se_bad,
        se_good,
        MockRandom::new(),
        MockRandom::new(),
        1_000u32,
        SigilError::RandomFailed
    );
}

#[test]
fn install_downstream_output_buffer_failure_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);

    // Undersized MSG generic cannot hold the 219-byte InstallChallenge.
    assert_eq!(
        gateway.handle_install_request::<128>(
            &request,
            &mut se_bad,
            &mut MockRandom::new(),
            1_000,
            LIFETIME
        ),
        Err(SigilError::OutputBufferTooSmall)
    );
    assert_eq!(gateway.replay_cache().len(), 0);
    assert!(gateway.get_pending(&SENSOR_MAC).is_none());
    // Cooldown stamp already live (buffer build precedes pending commit but
    // follows the stamp): immediate duplicate is RateLimited.
    assert_eq!(
        gateway.handle_install_request::<128>(
            &request,
            &mut se_bad,
            &mut MockRandom::new(),
            1_000,
            LIFETIME
        ),
        Err(SigilError::RateLimited { peer: SENSOR_MAC })
    );
    // Identical retry at the boundary with a proper MSG generic succeeds.
    let retry = gateway.handle_install_request::<256>(
        &request,
        &mut se_good,
        &mut MockRandom::new(),
        1_000 + INSTALL_REQUEST_COOLDOWN,
        LIFETIME,
    );
    assert!(matches!(retry, Ok(SigilAction::Transmit { .. })));
    assert_eq!(gateway.replay_cache().len(), 1);
}

#[test]
fn install_downstream_malformed_local_pubkey_rejected_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    // Defective provider returns `Ok` with a malformed gateway-LOCAL key;
    // the encoding validation that runs immediately after retrieval
    // rejects it — post-stamp, pre-ECDH.
    se_bad.force_static_pubkey([0xFFu8; 33]);
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);
    assert_downstream_failure_retry!(
        gateway,
        request,
        se_bad,
        se_good,
        MockRandom::new(),
        MockRandom::new(),
        1_000u32,
        SigilError::InvalidStaticKey
    );
}

#[test]
fn install_downstream_null_ecdh_output_rejected_retry_not_replay() {
    let mut gateway: SessionManager<4> = test_manager_with_mac(GW_MAC);
    let request = fresh_install_request(1, 1_000);
    let mut se_bad = MockSecureElement::gateway(2, GW_MAC);
    // Provider reports `Ok([0u8; 32])`: the constant-time null-output gate
    // wrapping the ECDH call site rejects it.
    se_bad.return_zero_ecdh();
    let mut se_good = MockSecureElement::gateway(2, GW_MAC);
    assert_downstream_failure_retry!(
        gateway,
        request,
        se_bad,
        se_good,
        MockRandom::new(),
        MockRandom::new(),
        1_000u32,
        SigilError::EcdhFailed
    );
}

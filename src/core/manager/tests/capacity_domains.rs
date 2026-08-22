//! Capacity-domain architecture-contract tests.
//!
//! The four refined capacity/buffer error variants must stay distinguishable
//! **through the public manager facade**, not only at the store boundary:
//!
//! - [`SigilError::OutputBufferTooSmall`] — caller-provided output buffer
//!   sizing (an integration bug), independent of any table state;
//! - [`SigilError::SessionTableFull`] — session-table saturation rejects a
//!   *new* peer while replacement of a known peer still works;
//! - [`SigilError::PendingTableFull`] — handshake saturation, raised by the
//!   role-appropriate public handshake entry point;
//! - [`SigilError::AdmissionTableFull`] (gateway builds) — install-cooldown
//!   table saturation, which heals over time without any removal call.
//!
//! Each test drives one domain to saturation through public API and asserts
//! the exact host-visible variant plus fail-atomic behavior. Per-test feature
//! gates keep the file compiling in sensor-only, gateway-only, and two-role
//! builds; every configuration runs the buffer and session-domain proofs,
//! and each role runs its own pending-domain proof.

use crate::core::error::SigilError;
use crate::core::manager::SessionManager;
use crate::core::session::{DirectionalMaterial, PeerId, Session, SessionRole};
use crate::core::test_support::TEST_FACTORY_PUBKEY;
// The handshake-driven saturation proofs below exist only in gateway builds.
#[cfg(feature = "gateway")]
use crate::core::test_support::{MockRandom, MockSecureElement};

const LOCAL_MAC: PeerId = [0xA1u8; 17];

/// Role stamped into loopback sessions for the role-agnostic buffer and
/// session-table proofs: the single available role in mono-role builds,
/// Sensor in the two-role build. Neither proof depends on direction checks.
#[cfg(feature = "sensor")]
const SESSION_ROLE: SessionRole = SessionRole::Sensor;
#[cfg(not(feature = "sensor"))]
const SESSION_ROLE: SessionRole = SessionRole::Gateway;

// Buffer-sizing domain (every session-bearing build).

#[test]
fn buffer_sizing_error_is_distinct_from_capacity_domains() {
    let mut mgr =
        SessionManager::<2>::new(TEST_FACTORY_PUBKEY, LOCAL_MAC).expect("valid factory key");
    mgr.insert(
        Session::new_active(
            [0xB2u8; 17],
            [0x02u8; 33],
            DirectionalMaterial::symmetric_for_test([0x55u8; 32], [0xAAu8; 4]),
            SESSION_ROLE,
            [0x5Du8; 32],
            100_000,
            0,
        )
        .expect("active session"),
    )
    .expect("empty table");

    // An undersized host output buffer fails in the buffer domain — with
    // tables completely empty — before any capacity is consulted.
    let err = mgr
        .encrypt_data::<8>(&[0xB2u8; 17], b"payload", 1_000)
        .expect_err("8-byte frame buffer cannot hold header + nonce + tag");
    assert_eq!(err, SigilError::OutputBufferTooSmall);

    // Fail-atomic: the TX counter did not advance on the failed build.
    assert_eq!(mgr.get(&[0xB2u8; 17]).unwrap().tx_counter, 0);

    // The identical call with an adequately sized buffer succeeds, proving
    // the failure above was buffer sizing and nothing else.
    let frame = mgr
        .encrypt_data::<256>(&[0xB2u8; 17], b"payload", 1_000)
        .expect("adequate buffer encrypts");
    assert!(!frame.is_empty());
    assert_eq!(mgr.get(&[0xB2u8; 17]).unwrap().tx_counter, 1);
}

// Session-table domain (every session-bearing build).

#[test]
fn session_saturation_yields_session_table_full_for_unknown_peer() {
    let mut mgr =
        SessionManager::<2>::new(TEST_FACTORY_PUBKEY, LOCAL_MAC).expect("valid factory key");
    let make = |peer: PeerId, key: u8| {
        Session::new_active(
            peer,
            [0x02u8; 33],
            DirectionalMaterial::symmetric_for_test([key; 32], [key; 4]),
            SESSION_ROLE,
            [0x5Du8; 32],
            100_000,
            0,
        )
        .expect("active session")
    };
    mgr.insert(make([0xC3u8; 17], 0x11)).expect("first insert");
    mgr.insert(make([0xD4u8; 17], 0x22)).expect("second insert");
    assert!(mgr.is_full());

    // A brand-new peer at capacity hits exactly the session-domain variant.
    assert_eq!(
        mgr.insert(make([0xE5u8; 17], 0x33)),
        Err(SigilError::SessionTableFull)
    );

    // Fail-atomic: prior entries preserved, newcomer absent.
    assert_eq!(mgr.len(), 2);
    assert!(mgr.get(&[0xE5u8; 17]).is_none());

    // Replacement of a known peer still succeeds at capacity: the session
    // domain rejects growth only.
    mgr.insert(make([0xC3u8; 17], 0x44))
        .expect("known-peer replacement succeeds");
    assert_eq!(mgr.len(), 2);
}

// Pending-handshake domain, sensor-side entry point.

#[cfg(feature = "sensor")]
#[test]
fn pending_saturation_yields_pending_table_full_on_sensor_paths() {
    use crate::core::install::INSTALL_DISCOVERY_DEST;
    use crate::core::test_support::{MockRandom, MockSecureElement};

    let mut mgr =
        SessionManager::<2>::new(TEST_FACTORY_PUBKEY, LOCAL_MAC).expect("valid factory key");
    let mut se = MockSecureElement::sensor(1, LOCAL_MAC);
    let mut rng = MockRandom::new();
    let active_session = |peer: PeerId, key: u8| {
        Session::new_active(
            peer,
            [0x02u8; 33],
            DirectionalMaterial::symmetric_for_test([key; 32], [key; 4]),
            SessionRole::Sensor,
            [0x5Du8; 32],
            100_000,
            0,
        )
        .expect("active session")
    };

    // Two distinct pending sources saturate the pending table of N = 2:
    // an install discovery request (no session required) ...
    mgr.start_install::<256>(INSTALL_DISCOVERY_DEST, &mut se, &mut rng, 1_000)
        .expect("install pending created");
    // ... and one renew request from an active session.
    mgr.insert(active_session([0xC3u8; 17], 0x21))
        .expect("table has room");
    mgr.start_renew::<256>([0xC3u8; 17], 1_000)
        .expect("renew pending created");
    assert_eq!(mgr.pending_len(), 2);

    // A third handshake from another session-holding peer now hits exactly
    // the pending-domain variant.
    mgr.insert(active_session([0xD4u8; 17], 0x31))
        .expect("table has room");
    let before = mgr.get(&[0xD4u8; 17]).unwrap().tx_counter;
    assert_eq!(
        mgr.start_renew::<256>([0xD4u8; 17], 1_000),
        Err(SigilError::PendingTableFull)
    );

    // Fail-atomic: the rejected handshake consumed no TX counter.
    assert_eq!(mgr.get(&[0xD4u8; 17]).unwrap().tx_counter, before);

    // Back-pressure heals: freeing one pending slot lets the same
    // handshake succeed immediately.
    mgr.cancel_pending(&INSTALL_DISCOVERY_DEST)
        .expect("host cancels the discovery handshake");
    mgr.start_renew::<256>([0xD4u8; 17], 1_000)
        .expect("renew succeeds once pending has room");
}

// Pending-handshake domain, gateway-side entry point.

#[cfg(feature = "gateway")]
#[test]
fn pending_saturation_yields_pending_table_full_on_gateway_paths() {
    let mut mgr = SessionManager::<4>::new(TEST_FACTORY_PUBKEY, GATEWAY_LOCAL_MAC)
        .expect("valid factory key");
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_SIDE_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GATEWAY_LOCAL_MAC);
    let mut rng = MockRandom::new();

    // Three accepted install requests occupy three pending slots.
    for id in 0..3u8 {
        let mac = sensor_mac(id);
        let frame = super::host_flows::build_install_request_frame(&mut se_sensor, mac, 0x11)
            .expect("attested request frame builds");
        mgr.handle_install_request::<256>(&frame, &mut se_gw, &mut rng, 1_000, 86_400)
            .expect("request accepted into pending");
    }
    assert_eq!(mgr.pending_len(), 3);

    // A fourth handshake arrives through the resume path from an enrolled
    // (rebooted) sensor: MAC over the durable PSK verifies, SE-ECDH runs,
    // and the challenge insert takes the last pending slot.
    mgr.insert(
        Session::new_enrolled(
            RESUME_SENSOR_MAC,
            [0x02u8; 33],
            [0x5Du8; 32],
            SessionRole::Gateway,
        )
        .expect("enrolled gateway session"),
    )
    .expect("table has room");
    let req4 = super::host_flows::build_resume_request_frame(
        &[0x5Du8; 32],
        RESUME_SENSOR_MAC,
        [0x44u8; 16],
    );
    mgr.handle_resume_request::<256>(&req4, &mut se_gw, &mut rng, 2_000, 86_400)
        .expect("fourth pending created");
    assert_eq!(mgr.pending_len(), 4);

    // A fifth requester holds an enrolled identity but every pending slot
    // is taken: the late challenge insert reports the pending domain.
    mgr.insert(
        Session::new_enrolled(
            FIFTH_SENSOR_MAC,
            [0x02u8; 33],
            [0x6Eu8; 32],
            SessionRole::Gateway,
        )
        .expect("enrolled gateway session"),
    )
    .expect("table has room");
    let req5 = super::host_flows::build_resume_request_frame(
        &[0x6Eu8; 32],
        FIFTH_SENSOR_MAC,
        [0x55u8; 16],
    );
    assert_eq!(
        mgr.handle_resume_request::<256>(&req5, &mut se_gw, &mut rng, 3_000, 86_400),
        Err(SigilError::PendingTableFull)
    );

    // Fail-atomic and retryable: no cooldown was stamped for the rejected
    // requester (stamping happens only after a successful insert), so the
    // retry reaches the same capacity signal rather than RateLimited.
    assert_eq!(
        mgr.handle_resume_request::<256>(&req5, &mut se_gw, &mut rng, 3_001, 86_400),
        Err(SigilError::PendingTableFull)
    );
}

// Admission / cooldown domain (gateway builds only).

#[cfg(feature = "gateway")]
#[test]
fn admission_saturation_yields_admission_table_full_and_heals_over_time() {
    use crate::core::install::INSTALL_REQUEST_COOLDOWN;

    let mut mgr = SessionManager::<4>::new(TEST_FACTORY_PUBKEY, GATEWAY_LOCAL_MAC)
        .expect("valid factory key");
    let mut se_sensor = MockSecureElement::sensor(1, SENSOR_SIDE_MAC);
    let mut se_gw = MockSecureElement::gateway(2, GATEWAY_LOCAL_MAC);
    let mut rng = MockRandom::new();
    // Defective ECDH provider: every request passes attestation (and thus
    // legitimately stamps its admission cooldown) but fails afterwards,
    // leaving NO pending and NO session behind.
    se_gw.return_zero_ecdh();

    // Four distinct identities consume all four admission slots.
    for id in 0..4u8 {
        let mac = sensor_mac(id + 10);
        let frame = super::host_flows::build_install_request_frame(&mut se_sensor, mac, 0x11)
            .expect("attested request frame builds");
        let outcome =
            mgr.handle_install_request::<256>(&frame, &mut se_gw, &mut rng, 1_000, 86_400);
        let err = outcome.expect_err("null-secret ECDH must fail after stamping");
        assert!(
            !matches!(
                err,
                SigilError::AdmissionTableFull
                    | SigilError::PendingTableFull
                    | SigilError::SessionTableFull
            ),
            "filler failures come from the crypto stage, not any capacity domain"
        );
    }
    assert_eq!(mgr.pending_len(), 0, "no handshake state survived");
    assert_eq!(mgr.len(), 0, "no session was created");

    // A fifth distinct identity finds the admission table full even though
    // sessions AND pending are empty: three independent resource domains.
    let fifth =
        super::host_flows::build_install_request_frame(&mut se_sensor, sensor_mac(20), 0x11)
            .expect("attested request frame builds");
    assert_eq!(
        mgr.handle_install_request::<256>(&fifth, &mut se_gw, &mut rng, 1_000, 86_400),
        Err(SigilError::AdmissionTableFull)
    );

    // Admission heals over time without any removal call: past the cooldown
    // window the purged stamps free slots and the same identity is admitted
    // again (failing later in crypto, not in admission).
    let later = 1_000 + INSTALL_REQUEST_COOLDOWN + 1;
    let outcome = mgr.handle_install_request::<256>(&fifth, &mut se_gw, &mut rng, later, 86_400);
    let err = outcome.expect_err("ECDH still defective");
    assert!(
        !matches!(err, SigilError::AdmissionTableFull),
        "cooldown expiry frees admission slots without manual purge"
    );
}

// Shared gateway-side fixtures.

#[cfg(feature = "gateway")]
const GATEWAY_LOCAL_MAC: PeerId = [0xB7u8; 17];

#[cfg(feature = "gateway")]
const SENSOR_SIDE_MAC: PeerId = [0xA9u8; 17];

#[cfg(feature = "gateway")]
const RESUME_SENSOR_MAC: PeerId = [0xE1u8; 17];

#[cfg(feature = "gateway")]
const FIFTH_SENSOR_MAC: PeerId = [0xF2u8; 17];

/// Distinct deterministic sensor MAC for filler identities.
#[cfg(feature = "gateway")]
fn sensor_mac(id: u8) -> PeerId {
    let mut mac = [0xEEu8; 17];
    mac[0] = id;
    mac
}

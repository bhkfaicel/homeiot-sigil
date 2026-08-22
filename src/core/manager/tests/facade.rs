//! Historical session-manager facade unit suite (two-role builds).
//!
//! These scenarios pin storage semantics, replacement-at-capacity,
//! remove-also-clears-pending, cooldown bookkeeping, tick housekeeping and
//! commit-recovery abandonment on the manager facade. They exercise
//! two-role test seams and dual-role staging fixtures, so the suite keeps
//! its original `sensor,gateway` gate; see the parent tree docs for the
//! gating contract.

use super::{RESUME_PSK, install_gateway_staged};
use crate::core::error::SigilError;
use crate::core::manager::SessionManager;
use crate::core::session::{DirectionalMaterial, Session, SessionRole};

#[test]
fn test_new_manager() {
    let mgr: SessionManager<16> = crate::core::test_support::test_manager();
    assert_eq!(mgr.len(), 0);
    assert!(mgr.is_empty());
    assert!(!mgr.is_full());
}

#[test]
fn test_insert_and_get() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [1u8; 17];
    let pubkey = [2u8; 33];
    let key = [3u8; 32];
    let prefix = [4u8; 4];

    let session = Session::new_active(
        peer,
        pubkey,
        DirectionalMaterial::symmetric_for_test(key, prefix),
        SessionRole::Sensor,
        RESUME_PSK,
        1000,
        0,
    )
    .unwrap();
    mgr.insert(session).unwrap();

    assert_eq!(mgr.len(), 1);
    assert!(!mgr.is_empty());

    let retrieved = mgr.get(&peer).unwrap();
    assert_eq!(retrieved.peer_mac(), &peer);
}

#[test]
fn test_insert_full() {
    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();

    let peer1 = [1u8; 17];
    let peer2 = [2u8; 17];
    let peer3 = [3u8; 17];
    let pubkey = [0u8; 33];
    let key = [0u8; 32];
    let prefix = [0u8; 4];

    mgr.insert(
        Session::new_active(
            peer1,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr.insert(
        Session::new_active(
            peer2,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();

    assert!(mgr.is_full());

    let result = mgr.insert(
        Session::new_active(
            peer3,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    );
    assert_eq!(result, Err(SigilError::SessionTableFull));
}

#[test]
fn test_insert_replaces_existing_when_full() {
    // replace of an existing peer must succeed at capacity.

    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();
    let peer1 = [1u8; 17];
    let peer2 = [2u8; 17];
    let pubkey = [0u8; 33];
    let key_a = [0xAAu8; 32];
    let key_b = [0xBBu8; 32];
    let prefix = [0u8; 4];

    mgr.insert(
        Session::new_active(
            peer1,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key_a, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr.insert(
        Session::new_active(
            peer2,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key_a, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(mgr.is_full());

    mgr.insert(
        Session::new_active(
            peer1,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key_b, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            2000,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(mgr.len(), 2);
    assert_eq!(mgr.get(&peer1).unwrap().session_key(), Some(&key_b));
    assert_eq!(mgr.get(&peer1).unwrap().key_expire_at(), 2000);
    assert_eq!(mgr.get(&peer2).unwrap().session_key(), Some(&key_a));
}

#[test]
fn test_remove() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [1u8; 17];
    let pubkey = [2u8; 33];
    let key = [3u8; 32];
    let prefix = [4u8; 4];

    mgr.insert(
        Session::new_active(
            peer,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(mgr.len(), 1);

    let removed = mgr.remove(&peer);
    assert!(removed.is_some());
    assert_eq!(mgr.len(), 0);
    assert!(mgr.get(&peer).is_none());
}

#[test]
fn test_get_mut() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [1u8; 17];
    let pubkey = [2u8; 33];
    let key = [3u8; 32];
    let prefix = [4u8; 4];

    mgr.insert(
        Session::new_active(
            peer,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();

    let session = mgr.get_mut(&peer).unwrap();
    session.tx_counter = 100;

    let retrieved = mgr.get(&peer).unwrap();
    assert_eq!(retrieved.tx_counter, 100);
}

#[test]
fn test_remove_unknown() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [9u8; 17]; // never inserted

    let removed = mgr.remove(&peer);
    assert!(removed.is_none());
}

#[test]
fn test_remove_also_clears_pending() {
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [1u8; 17];
    let pubkey = [2u8; 33];
    let key = [3u8; 32];
    let prefix = [4u8; 4];

    mgr.insert(
        Session::new_active(
            peer,
            pubkey,
            DirectionalMaterial::symmetric_for_test(key, prefix),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();

    // Simulate an in-progress handshake via the renew path
    let handshake = crate::core::pending::PendingHandshake::new_renew_sensor(peer, 5000, 1_000);
    mgr.insert_pending(peer, handshake).unwrap();
    assert!(mgr.get_pending(&peer).is_some());

    // remove() must clear both session and pending handshake
    let removed = mgr.remove(&peer);
    assert!(removed.is_some());
    assert!(mgr.get(&peer).is_none());
    assert!(mgr.get_pending(&peer).is_none());
}

#[test]
fn test_install_last_at_purged_and_cleared_on_remove() {
    // expired cooldown entries free capacity on decide; remove drops the
    // stamp.

    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let peer_c = [0xC3u8; 17];
    let t0 = 1_000u32;
    mgr.stamp_install_request(peer_a, t0).unwrap();
    mgr.stamp_install_request(peer_b, t0).unwrap();
    // Table full for a new peer while cooldowns are still live.
    assert_eq!(
        mgr.admit_install(&peer_c, t0),
        Err(SigilError::AdmissionTableFull)
    );
    // After cooldown elapses, the decide-phase purge frees slots.
    let later = t0 + crate::core::install::INSTALL_REQUEST_COOLDOWN;
    assert!(mgr.admit_install(&peer_c, later).is_ok());
    mgr.stamp_install_request(peer_c, later).unwrap();

    // Fresh stamps + remove clears the entry.
    let mut mgr2: SessionManager<4> = crate::core::test_support::test_manager();
    let peer = [9u8; 17];
    mgr2.stamp_install_request(peer, t0).unwrap();
    assert_eq!(
        mgr2.admit_install(&peer, t0),
        Err(SigilError::RateLimited { peer })
    );
    mgr2.remove(&peer);
    assert!(mgr2.admit_install(&peer, t0).is_ok());
}

// Capacity & delete semantics

#[test]
fn test_sensor_capacity_documented_constant() {
    // The sensor default is the smallest valid power of two (>=2) for
    // heapless::FnvIndexMap. Logically a single-peer device.
    assert_eq!(crate::core::manager::SENSOR_CAPACITY, 2);
}

#[test]
fn test_gateway_capacity_documented_constant() {
    // The gateway default capacity is a power of two (required by FnvIndexMap).
    assert_eq!(crate::core::manager::GATEWAY_CAPACITY, 128);
    assert_eq!(crate::core::manager::SENSOR_CAPACITY, 2);
}

#[test]
fn test_remove_returns_session_for_nvram_cleanup() {
    // remove() returns the Session so the host can read the static pubkey
    // before erasing its NVRAM copy. The library performs NO NVRAM I/O.
    let mut mgr: SessionManager<16> = crate::core::test_support::test_manager();
    let peer = [1u8; 17];
    let pubkey = [2u8; 33];
    mgr.insert(
        Session::new_active(
            peer,
            pubkey,
            DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
            SessionRole::Sensor,
            RESUME_PSK,
            1000,
            0,
        )
        .unwrap(),
    )
    .unwrap();

    let removed = mgr.remove(&peer).unwrap();
    assert_eq!(removed.peer_static_pubkey(), &pubkey);
}

#[test]
fn test_remove_is_ram_only_no_wipe_hook() {
    // The SessionManager exposes no NVRAM wipe API. remove() only drops the
    // in-memory entry. We verify there is no method like `wipe_nvram` or
    // `persist_delete` on the manager by checking the public surface compiles
    // with only RAM-level operations.
    let mut mgr: SessionManager<4> = crate::core::test_support::test_manager();
    mgr.insert(
        Session::new_active(
            [1u8; 17],
            [0u8; 33],
            DirectionalMaterial::symmetric_for_test([0u8; 32], [0u8; 4]),
            SessionRole::Sensor,
            RESUME_PSK,
            1,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr.remove(&[1u8; 17]);
    assert!(mgr.is_empty());
    // If a NVRAM hook existed it would require a trait bound or callback; the
    // manager takes none, confirming RAM-only semantics.
}

#[test]
fn test_capacity_constant_is_power_of_two() {
    // heapless::FnvIndexMap requires power-of-two capacity and >= 2.
    let n = crate::core::manager::GATEWAY_CAPACITY;
    assert!(
        n.is_power_of_two(),
        "gateway capacity must be a power of two"
    );
    assert!(n >= 2, "gateway capacity must be >= 2");
    let s = crate::core::manager::SENSOR_CAPACITY;
    assert!(
        s.is_power_of_two(),
        "sensor capacity must be a power of two"
    );
    assert!(s >= 2, "sensor capacity must be >= 2");
}

#[test]
fn test_pending_can_fill_while_sessions_empty() {
    // documentation guard: `pending` is a separate map of capacity N.

    // Filling it does not require any session entries — hosts must globally
    // rate-limit handshake admission; library cooldowns are per-peer only.
    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();
    assert_eq!(mgr.len(), 0);

    let peer_a = [0xAAu8; 17];
    let peer_b = [0xBBu8; 17];
    let peer_c = [0xCCu8; 17];

    mgr.insert_pending(
        peer_a,
        crate::core::pending::PendingHandshake::new_install_gateway_await_confirm(
            peer_a,
            install_gateway_staged(),
            5000,
            1_000,
        ),
    )
    .unwrap();
    mgr.insert_pending(
        peer_b,
        crate::core::pending::PendingHandshake::new_install_gateway_await_confirm(
            peer_b,
            install_gateway_staged(),
            5000,
            1_000,
        ),
    )
    .unwrap();

    assert_eq!(mgr.len(), 0, "sessions remain empty while pending is full");
    let err = mgr.insert_pending(
        peer_c,
        crate::core::pending::PendingHandshake::new_install_gateway_await_confirm(
            peer_c,
            install_gateway_staged(),
            5000,
            1_000,
        ),
    );
    assert_eq!(err, Err(SigilError::PendingTableFull));
}

#[test]
fn test_tick_purges_multiple_expired_pendings() {
    // Optional housekeeping: tick reclaims expired slots without

    // requiring per-peer cancel_pending.
    let mut mgr: SessionManager<4> = crate::core::test_support::test_manager();
    let peer_a = [0xAAu8; 17];
    let peer_b = [0xBBu8; 17];

    mgr.insert_pending(
        peer_a,
        crate::core::pending::PendingHandshake::new_install_gateway_await_confirm(
            peer_a,
            install_gateway_staged(),
            5_000, // → deadline = now + 5
            100,
        ),
    )
    .unwrap();
    mgr.insert_pending(
        peer_b,
        crate::core::pending::PendingHandshake::new_install_gateway_await_confirm(
            peer_b,
            install_gateway_staged(),
            30_000, // → deadline = now + 30
            100,
        ),
    )
    .unwrap();

    let purged = mgr.tick(105); // expires A only
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0], peer_a);
    assert!(mgr.get_pending(&peer_a).is_none());
    assert!(mgr.get_pending(&peer_b).is_some());

    let purged = mgr.tick(130);
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0], peer_b);
    assert!(mgr.get_pending(&peer_b).is_none());
}

#[test]
fn test_abandon_commit_recovery_preserves_session_and_frees_slot() {
    use crate::core::pending::PendingHandshake;

    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();
    let peer = [0xA5u8; 17];
    mgr.insert(
        Session::new_active(
            peer,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test([3u8; 32], [4u8; 4]),
            SessionRole::Sensor,
            RESUME_PSK,
            2_000,
            1_000,
        )
        .unwrap(),
    )
    .unwrap();

    // Typed transition to the post-Final recovery state: staging the Final
    // swaps the variant (fail-atomic) and caches the frame for reTX.
    let mut pending = PendingHandshake::new_renew_sensor(peer, 5_000, 1_000);
    pending
        .renew_sensor_stage_final(
            DirectionalMaterial::symmetric_for_test([0xCDu8; 32], [0xEFu8; 4]),
            86_400,
            &[1, 2, 3],
            1_000,
        )
        .unwrap();
    mgr.insert_pending(peer, pending).unwrap();

    assert_eq!(mgr.pending_len(), 1);
    assert_eq!(
        mgr.pending_peers()
            .copied()
            .collect::<heapless::Vec<_, 2>>(),
        [peer]
    );
    assert_eq!(mgr.commit_recovery_peers().as_slice(), &[peer]);

    mgr.abandon_commit_recovery(&peer).unwrap();
    assert_eq!(mgr.pending_len(), 0);
    assert!(
        mgr.get(&peer).is_some(),
        "the active session must be preserved"
    );
}

#[test]
fn test_abandon_commit_recovery_rejects_precommit_state() {
    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();
    let peer = [0xB6u8; 17];
    let pending = crate::core::pending::PendingHandshake::new_renew_sensor(peer, 5_000, 1_000);
    mgr.insert_pending(peer, pending).unwrap();

    assert_eq!(
        mgr.abandon_commit_recovery(&peer),
        Err(SigilError::InvalidStep { peer })
    );
    assert_eq!(mgr.pending_len(), 1);
}

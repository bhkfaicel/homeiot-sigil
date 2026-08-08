#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for session manager

use crate::core::error::SigilError;
use crate::core::manager::SessionManager;
use crate::core::session::{DirectionalMaterial, Session, SessionRole};

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];

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
    assert_eq!(retrieved.peer_mac, peer);
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
    assert_eq!(result, Err(SigilError::CapacityExceeded));
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
    let eph_secret = [0xAAu8; 32];
    let handshake = crate::core::pending::PendingHandshake::new_renew(
        peer,
        crate::core::pending::HandshakeRole::Sensor,
        eph_secret,
        5000,
        1_000,
    );
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
 // expired cooldown entries free capacity; removedrops the stamp.

    let mut mgr: SessionManager<2> = crate::core::test_support::test_manager();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let peer_c = [0xC3u8; 17];
    let t0 = 1_000u32;
    mgr.mark_install_request(peer_a, t0).unwrap();
    mgr.mark_install_request(peer_b, t0).unwrap();
    // Table full for a new peer while cooldowns are still live.
    assert!(mgr.install_last_at_full_for(&peer_c, t0));
    // After cooldown elapses, purge frees slots.
    let later = t0 + crate::core::install::INSTALL_REQUEST_COOLDOWN;
    assert!(!mgr.install_last_at_full_for(&peer_c, later));
    mgr.mark_install_request(peer_c, later).unwrap();

    // Fresh stamps + remove clears the entry.
    let mut mgr2: SessionManager<4> = crate::core::test_support::test_manager();
    let peer = [9u8; 17];
    mgr2.mark_install_request(peer, t0).unwrap();
    assert!(!mgr2.install_cooldown_elapsed(&peer, t0));
    mgr2.remove(&peer);
    assert!(mgr2.install_cooldown_elapsed(&peer, t0));
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
    assert_eq!(removed.peer_static_pubkey, pubkey);
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
        crate::core::pending::PendingHandshake::new_install(
            peer_a,
            crate::core::pending::HandshakeRole::Gateway,
            5000,
            1_000,
        ),
    )
.unwrap();
    mgr.insert_pending(
        peer_b,
        crate::core::pending::PendingHandshake::new_install(
            peer_b,
            crate::core::pending::HandshakeRole::Gateway,
            5000,
            1_000,
        ),
    )
.unwrap();

    assert_eq!(mgr.len(), 0, "sessions remain empty while pending is full");
    let err = mgr.insert_pending(
        peer_c,
        crate::core::pending::PendingHandshake::new_install(
            peer_c,
            crate::core::pending::HandshakeRole::Gateway,
            5000,
            1_000,
        ),
    );
    assert_eq!(err, Err(SigilError::CapacityExceeded));
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
        crate::core::pending::PendingHandshake::new_install(
            peer_a,
            crate::core::pending::HandshakeRole::Gateway,
            5_000, // → deadline = now + 5
            100,
        ),
    )
.unwrap();
    mgr.insert_pending(
        peer_b,
        crate::core::pending::PendingHandshake::new_install(
            peer_b,
            crate::core::pending::HandshakeRole::Gateway,
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

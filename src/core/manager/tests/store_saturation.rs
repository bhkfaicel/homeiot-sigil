//! Store-level capacity-saturation unit tests for the crate-private storage
//! components behind the session-manager facade.
//!
//! The facade composes three independent fixed-capacity tables:
//! [`SessionStore`] (established sessions), [`PendingStore`] (in-progress
//! handshakes and commit-recovery entries) and, on gateway builds,
//! [`AdmissionStore`] (per-peer install cooldown bookkeeping). These tests
//! pin the capacity behavior of each domain **at the store level**:
//!
//! - **Session table:** replacing a known peer succeeds even at capacity
//!   (no net growth); only an unknown peer is rejected.
//! - **Pending table:** a duplicate peer is rejected with the dedicated
//!   `PendingAlreadyExists` signal before capacity is ever consulted, while
//!   a *new* peer at capacity saturates the pending table only.
//! - **Admission table (gateway):** saturation reflects live cooldowns only
//!   and heals over time without any explicit removal call.
//!
//! Today all three tables surface saturation as
//! `distinct host-visible variants (`SessionTableFull`, `PendingTableFull`,
//! `AdmissionTableFull`)`. What these tests prove distinguishable at
//! the store boundary is structural: the owning store type and failing
//! method, each domain's unique observable predicate (replace-at-capacity,
//! duplicate-pending signal with the offending peer, time-healed admission
//! probe), and the strict independence of the three tables. Mapping those
//! signals onto distinct host-visible error variants belongs to the planned
//! host-visible error-taxonomy refinement and is intentionally out of scope
//! here.

use super::super::{AdmissionStore, PendingStore, SessionStore};
use crate::core::error::SigilError;
use crate::core::pending::PendingHandshake;
use crate::core::session::{DirectionalMaterial, PeerId, Session, SessionRole};

/// Builds an active session for `peer` with deterministic key material
/// derived from `key_byte` and absolute expiry `expire_at` (seconds).
fn active_session(peer: PeerId, key_byte: u8, expire_at: u32) -> Session {
    Session::new_active(
        peer,
        [0x02u8; 33],
        DirectionalMaterial::symmetric_for_test([key_byte; 32], [key_byte; 4]),
        SessionRole::Sensor,
        super::RESUME_PSK,
        expire_at,
        1_000,
    )
    .unwrap()
}

/// Builds a gateway-staged install pending entry for `peer` (the phase
/// content is irrelevant to capacity scenarios; staging comes from the
/// deterministic helper of the parent test module).
fn install_pending(peer: PeerId) -> PendingHandshake {
    PendingHandshake::new_install_gateway_await_confirm(
        peer,
        super::install_gateway_staged(),
        5_000,
        1_000,
    )
}

// Session-table saturation.

#[test]
fn test_session_store_replaces_known_peer_at_capacity_without_growth() {
    let mut store: SessionStore<2> = SessionStore::new();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    store.insert(active_session(peer_a, 0xAA, 2_000)).unwrap();
    store.insert(active_session(peer_b, 0xBB, 2_000)).unwrap();
    assert!(store.is_full());

    // Re-inserting a known peer replaces it in place even when full.
    store.insert(active_session(peer_a, 0xCC, 3_000)).unwrap();
    assert_eq!(store.len(), 2);
    assert_eq!(store.get(&peer_a).unwrap().key_expire_at(), 3_000);
    // The other entry is untouched by the replacement.
    assert_eq!(store.get(&peer_b).unwrap().key_expire_at(), 2_000);
}

#[test]
fn test_session_store_rejects_unknown_peer_when_full() {
    let mut store: SessionStore<2> = SessionStore::new();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let unknown = [0xC3u8; 17];
    store.insert(active_session(peer_a, 0xAA, 2_000)).unwrap();
    store.insert(active_session(peer_b, 0xBB, 2_000)).unwrap();
    assert!(store.is_full());

    // Session-table saturation originates inside SessionStore::insert and
    // rejects true growth only.
    let err = store.insert(active_session(unknown, 0xDD, 2_000));
    assert_eq!(err, Err(SigilError::SessionTableFull));

    // Fail-atomic: the table keeps exactly its prior two entries.
    assert_eq!(store.len(), 2);
    assert!(store.get(&unknown).is_none());
    assert!(store.get(&peer_a).is_some());
    assert!(store.get(&peer_b).is_some());
}

// Pending-table saturation.

#[test]
fn test_pending_store_rejects_new_peer_when_full() {
    let mut store: PendingStore<2> = PendingStore::new();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let newcomer = [0xC3u8; 17];
    store.insert(peer_a, install_pending(peer_a)).unwrap();
    store.insert(peer_b, install_pending(peer_b)).unwrap();

    // The per-domain probe reports no slot for a brand-new peer.
    assert!(!store.slot_available(&newcomer));
    let err = store.insert(newcomer, install_pending(newcomer));
    assert_eq!(err, Err(SigilError::PendingTableFull));

    // Fail-atomic: existing pending entries are preserved untouched.
    assert_eq!(store.len(), 2);
    assert!(store.get(&peer_a).is_some());
    assert!(store.get(&peer_b).is_some());
    assert!(store.get(&newcomer).is_none());
}

#[test]
fn test_pending_duplicate_peer_signal_is_distinct_from_saturation() {
    let mut store: PendingStore<2> = PendingStore::new();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let newcomer = [0xC3u8; 17];
    store.insert(peer_a, install_pending(peer_a)).unwrap();
    store.insert(peer_b, install_pending(peer_b)).unwrap();

    // A duplicate insert at capacity returns the dedicated pending-domain
    // variant carrying the offending peer, NOT the shared saturation error:
    // the two pending failure modes are distinguishable from each other and
    // from session/admission saturation.
    let dup = store.insert(peer_b, install_pending(peer_b));
    assert_eq!(dup, Err(SigilError::PendingAlreadyExists { peer: peer_b }));

    // Replacement eligibility stays visible through the per-domain probe.
    assert!(store.slot_available(&peer_b));
    assert!(!store.slot_available(&newcomer));
    assert_eq!(store.len(), 2);
}

// Capacity-domain independence.

#[test]
fn test_pending_saturation_does_not_block_the_session_table() {
    // Fill the pending table completely...
    let mut pending: PendingStore<2> = PendingStore::new();
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    pending.insert(peer_a, install_pending(peer_a)).unwrap();
    pending.insert(peer_b, install_pending(peer_b)).unwrap();
    assert_eq!(pending.len(), 2);

    // ...then prove the session table is an independent resource domain:
    // a brand-new session still inserts while pending is saturated.
    let mut sessions: SessionStore<2> = SessionStore::new();
    sessions
        .insert(active_session([0x77u8; 17], 0xEE, 2_000))
        .unwrap();
    assert_eq!(sessions.len(), 1);
}

// Admission / cooldown-table saturation (gateway builds only).

#[test]
#[cfg(feature = "gateway")]
fn test_admission_decide_reflects_live_cooldowns_only() {
    let mut store: AdmissionStore<2> = AdmissionStore::new();
    let t0 = 1_000u32;
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let newcomer = [0xC3u8; 17];

    // An empty table admits everyone (single decide phase, no stamp).
    assert!(store.admit_install(&newcomer, t0).is_ok());
    store.stamp_install_request(peer_a, t0).unwrap();
    store.stamp_install_request(peer_b, t0).unwrap();

    // Full for a NEW peer while both cooldowns are live...
    assert_eq!(
        store.admit_install(&newcomer, t0),
        Err(SigilError::AdmissionTableFull)
    );
    // ...while a known live-cooldown peer is rejected by the cooldown guard
    // that runs first in the documented order.
    assert_eq!(
        store.admit_install(&peer_a, t0),
        Err(SigilError::RateLimited { peer: peer_a })
    );

    // Admission saturation heals over time without any explicit removal:
    // once the cooldown window elapses the purged entries free slots.
    let later = t0 + crate::core::install::INSTALL_REQUEST_COOLDOWN;
    assert!(store.admit_install(&newcomer, later).is_ok());
    store.stamp_install_request(newcomer, later).unwrap();
    assert!(store.admit_install(&[0xD4u8; 17], later).is_ok());
}

#[test]
#[cfg(feature = "gateway")]
fn test_admission_saturation_blocks_only_unknown_peer() {
    let mut store: AdmissionStore<2> = AdmissionStore::new();
    let t0 = 1_000u32;
    let peer_a = [0xA1u8; 17];
    let peer_b = [0xB2u8; 17];
    let newcomer = [0xC3u8; 17];
    store.stamp_install_request(peer_a, t0).unwrap();
    store.stamp_install_request(peer_b, t0).unwrap();

    // Admission-table saturation originates inside AdmissionStore::
    // admit_install and blocks only unknown peers.
    assert_eq!(
        store.admit_install(&newcomer, t0),
        Err(SigilError::AdmissionTableFull)
    );

    // The scan-free stamp fails closed if a caller pairs the phases
    // incorrectly on a full table with an unknown peer.
    assert_eq!(
        store.stamp_install_request(newcomer, t0),
        Err(SigilError::AdmissionTableFull)
    );

    // Re-stamping a known peer still succeeds at capacity (replacement, no
    // net growth).
    store.stamp_install_request(peer_a, t0 + 1).unwrap();
}

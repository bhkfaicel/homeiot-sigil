#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Isolated handler-level tests for the cohesive pipeline submodules.
//!
//! Unlike the scenario tests in [`super`], these drive the semantic handlers
//! of [`crate::core::pipeline::event`] and
//! [`crate::core::pipeline::timesync`] **directly** with crafted plaintext,
//! i.e. with the already-authenticated context the single ingress primitive
//! would hand over after its AEAD/replay checks. This proves that the Event
//! durable-delivery state changes and the TimeSync cooldown changes are
//! independently testable, and it pins the exact mutation behavior of every
//! error path around those state changes.

use crate::core::error::SigilError;
use crate::core::event::SigilEvent;
use crate::core::manager::SessionManager;
use crate::core::pipeline::event;
use crate::core::pipeline::timesync;
use crate::core::session::{DirectionalMaterial, Session, SessionRole};
use heapless::Vec;

const RESUME_PSK: [u8; 32] = [0x5Au8; 32];
/// Remote peer MAC used as the session table key on the local manager.
const REMOTE: [u8; 17] = [1u8; 17];

/// Helper: gateway-role manager holding one active session keyed by
/// [`REMOTE`] (the sensor sender identity).
fn gateway_with_session(expire: u32) -> SessionManager<4> {
    let mut mgr: SessionManager<4> = crate::core::test_support::test_manager();
    mgr.insert(
        Session::new_active(
            REMOTE,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]),
            SessionRole::Gateway,
            RESUME_PSK,
            expire,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr
}

/// Helper: sensor-role manager holding one active session keyed by
/// [`REMOTE`] (the gateway identity).
fn sensor_with_session(expire: u32) -> SessionManager<4> {
    let mut mgr: SessionManager<4> = crate::core::test_support::test_manager();
    mgr.insert(
        Session::new_active(
            REMOTE,
            [2u8; 33],
            DirectionalMaterial::symmetric_for_test([0x42u8; 32], [0x01u8; 4]),
            SessionRole::Sensor,
            RESUME_PSK,
            expire,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    mgr
}

/// Builds an authenticated-context Event plaintext: `[id: 8 BE][payload]`.
fn event_plaintext(event_id: u64, app: &[u8]) -> Vec<u8, 64> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&event_id.to_be_bytes()).unwrap();
    payload.extend_from_slice(app).unwrap();
    payload
}

#[test]
fn test_event_delivery_handler_stamps_pending_and_rejects_parallel_id() {
    let mut mgr = gateway_with_session(100_000);

    // A fresh id opens the durable-delivery transaction.
    {
        let mut stores = mgr.protocol_stores();
        let delivered = event::handle_event_frame::<4, 200, 256>(
            &mut stores,
            &REMOTE,
            &event_plaintext(7, b"door-open"),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            delivered,
            SigilEvent::Event {
                event_id: 7,
                duplicate: false,
                ..
            }
        ));
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, Some(7));

    // A different id while a delivery is pending: rejected before any
    // mutation, so the original transaction stays intact.
    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            event::handle_event_frame::<4, 200, 256>(
                &mut stores,
                &REMOTE,
                &event_plaintext(8, b"x"),
                None,
                Some(7),
            ),
            Err(SigilError::EventDeliveryPending {
                peer: REMOTE,
                event_id: 7,
            })
        );
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, Some(7));

    // An already-committed duplicate reports `duplicate == true` and mutates
    // nothing: neither commit history nor the open transaction moves.
    {
        let mut stores = mgr.protocol_stores();
        let duplicate = event::handle_event_frame::<4, 200, 256>(
            &mut stores,
            &REMOTE,
            &event_plaintext(7, b"door-open"),
            Some(7),
            None,
        )
        .unwrap();
        assert!(matches!(
            duplicate,
            SigilEvent::Event {
                event_id: 7,
                duplicate: true,
                ..
            }
        ));
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, Some(7));
}

#[test]
fn test_event_payload_overflow_after_stamp_is_fail_closed() {
    // Documents the pre-existing fail-closed ordering: the delivery stamp
    // happens strictly before the application-payload copy into `DATA`. If
    // that copy exceeds the buffer, the error surfaces but the id stays
    // reserved and deduplicated — never silently lost.
    let mut mgr = gateway_with_session(100_000);
    // DATA = 10 holds at most 10 application bytes; deliver 11.
    let oversized = event_plaintext(9, &[0xAA; 11]);

    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            event::handle_event_frame::<4, 10, 256>(&mut stores, &REMOTE, &oversized, None, None),
            Err(SigilError::OutputBufferTooSmall)
        );
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, Some(9));
}

#[test]
fn test_event_malformed_payload_rejected_before_any_mutation() {
    let mut mgr = gateway_with_session(100_000);

    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            event::handle_event_frame::<4, 200, 256>(&mut stores, &REMOTE, &[0u8; 7], None, None),
            Err(SigilError::MalformedFrame)
        );
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, None);
}

#[test]
fn test_event_ack_handler_clears_matching_pending_only() {
    let mut mgr = sensor_with_session(100_000);

    // Stamp the ACK wait directly so the handler is exercised in isolation.
    mgr.protocol_stores()
        .sessions
        .get_mut(&REMOTE)
        .unwrap()
        .pending_tx_event_id = Some(11);

    // A mismatching authenticated id is rejected and keeps the wait alive.
    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            event::handle_event_ack_frame::<4, 200, 256>(
                &mut stores,
                &REMOTE,
                &99u64.to_be_bytes(),
                Some(11),
            ),
            Err(SigilError::UnexpectedEventAck {
                peer: REMOTE,
                event_id: 99,
            })
        );
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_tx_event_id, Some(11));

    // A malformed length is rejected and keeps the wait alive.
    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            event::handle_event_ack_frame::<4, 200, 256>(&mut stores, &REMOTE, &[0u8; 7], Some(11),),
            Err(SigilError::MalformedFrame)
        );
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_tx_event_id, Some(11));

    // The matching authenticated id commits the ACK: the wait clears while
    // the consumed id can never be resent (enforced by send-side checks).
    {
        let mut stores = mgr.protocol_stores();
        let acked = event::handle_event_ack_frame::<4, 200, 256>(
            &mut stores,
            &REMOTE,
            &11u64.to_be_bytes(),
            Some(11),
        )
        .unwrap();
        assert!(matches!(
            acked,
            SigilEvent::EventAck {
                peer: REMOTE,
                event_id: 11,
            }
        ));
    }
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_tx_event_id, None);
}

#[test]
fn test_release_handler_clears_only_the_matching_pending_delivery() {
    let mut mgr = gateway_with_session(100_000);
    mgr.protocol_stores()
        .sessions
        .get_mut(&REMOTE)
        .unwrap()
        .pending_rx_event_id = Some(4);

    // A mismatching id is rejected and the delivery stays pending.
    assert_eq!(
        crate::core::pipeline::release_event_delivery_internal(&mut mgr, &REMOTE, 99),
        Err(SigilError::UnexpectedEventDelivery {
            peer: REMOTE,
            event_id: 99,
        })
    );
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, Some(4));

    // Releasing the matching id abandons the transaction so the sensor retry
    // redelivers with `duplicate == false`.
    crate::core::pipeline::release_event_delivery_internal(&mut mgr, &REMOTE, 4).unwrap();
    assert_eq!(mgr.get(&REMOTE).unwrap().pending_rx_event_id, None);
}

#[test]
fn test_time_sync_request_cooldown_accepts_stamps_and_throttles() {
    use crate::core::pipeline::TIME_SYNC_REQUEST_COOLDOWN_SECS;
    let mut mgr = gateway_with_session(100_000);

    // First request: accepted and stamped at the request time.
    {
        let mut stores = mgr.protocol_stores();
        let request = timesync::handle_time_sync_request_frame::<4, 32, 128>(
            &mut stores,
            &REMOTE,
            &[],
            None,
            1_000,
        )
        .unwrap();
        assert!(matches!(
            request,
            SigilEvent::TimeSyncRequest { peer: REMOTE }
        ));
    }
    assert_eq!(
        mgr.get(&REMOTE).unwrap().last_time_sync_request_at,
        Some(1_000)
    );

    // Inside the cooldown window: throttled, previous stamp untouched.
    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            timesync::handle_time_sync_request_frame::<4, 32, 128>(
                &mut stores,
                &REMOTE,
                &[],
                Some(1_000),
                1_000 + TIME_SYNC_REQUEST_COOLDOWN_SECS - 5,
            ),
            Err(SigilError::RateLimited { peer: REMOTE })
        );
    }
    assert_eq!(
        mgr.get(&REMOTE).unwrap().last_time_sync_request_at,
        Some(1_000)
    );

    // Exactly one full cooldown later: accepted again and re-stamped.
    {
        let mut stores = mgr.protocol_stores();
        timesync::handle_time_sync_request_frame::<4, 32, 128>(
            &mut stores,
            &REMOTE,
            &[],
            Some(1_000),
            1_000 + TIME_SYNC_REQUEST_COOLDOWN_SECS,
        )
        .unwrap();
    }
    assert_eq!(
        mgr.get(&REMOTE).unwrap().last_time_sync_request_at,
        Some(1_000 + TIME_SYNC_REQUEST_COOLDOWN_SECS)
    );

    // A malformed (non-empty) request rejects before the cooldown logic and
    // leaves the current stamp untouched.
    {
        let mut stores = mgr.protocol_stores();
        assert_eq!(
            timesync::handle_time_sync_request_frame::<4, 32, 128>(
                &mut stores,
                &REMOTE,
                &[0x01],
                Some(1_000 + TIME_SYNC_REQUEST_COOLDOWN_SECS),
                1_000 + 2 * TIME_SYNC_REQUEST_COOLDOWN_SECS,
            ),
            Err(SigilError::MalformedFrame)
        );
    }
    assert_eq!(
        mgr.get(&REMOTE).unwrap().last_time_sync_request_at,
        Some(1_000 + TIME_SYNC_REQUEST_COOLDOWN_SECS)
    );
}

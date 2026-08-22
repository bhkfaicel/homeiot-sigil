#![cfg(test)]

//! Unit tests for error types

use crate::core::error::SigilError;
use alloc::string::ToString;

/// Representative clear-text wire-header peer identifier used by the
/// taxonomy tests.
const PEER: [u8; 17] = [1u8; 17];

#[test]
fn test_error_display() {
    let peer = [1u8; 17];

    let err = SigilError::UnknownSession { peer };
    assert!(err.to_string().contains("Unknown session"));

    let err = SigilError::SessionExpired { peer };
    assert!(err.to_string().contains("Session expired"));

    let err = SigilError::Replay {
        peer,
        expected: 10,
        received: 5,
    };
    assert!(err.to_string().contains("Replay detected"));

    let err = SigilError::InvalidKeyExpire {
        now: 10,
        key_expire_at: 5,
    };
    assert!(err.to_string().contains("Invalid key_expire_at"));
}

#[test]
fn test_error_equality() {
    let peer1 = [1u8; 17];
    let peer2 = [2u8; 17];

    let err1 = SigilError::UnknownSession { peer: peer1 };
    let err2 = SigilError::UnknownSession { peer: peer1 };
    let err3 = SigilError::UnknownSession { peer: peer2 };

    assert_eq!(err1, err2);
    assert_ne!(err1, err3);
}

#[test]
fn refined_error_display_is_exact_and_secret_free() {
    use alloc::format;

    let peer: [u8; 17] = [0x42; 17];

    // Fieldless refined variants render their exact documented literal.
    // Hosts may rely on these strings for logs and telemetry, so they are
    // pinned byte-for-byte here.
    assert_eq!(
        SigilError::OutputBufferTooSmall.to_string(),
        "Output buffer too small for the produced data"
    );
    assert_eq!(
        SigilError::SessionTableFull.to_string(),
        "Session table full"
    );
    assert_eq!(
        SigilError::PendingTableFull.to_string(),
        "Pending handshake table full"
    );
    assert_eq!(
        SigilError::AdmissionTableFull.to_string(),
        "Admission table full"
    );
    assert_eq!(
        SigilError::MalformedFrame.to_string(),
        "Malformed frame received"
    );
    assert_eq!(
        SigilError::InvariantViolation.to_string(),
        "Internal invariant violated"
    );

    // WrongRole renders exactly its fixed sentence plus the peer identifier
    // and nothing else: peer MACs are clear-text wire-header data, so no
    // key material or secret can leak through this variant.
    assert_eq!(
        SigilError::WrongRole { peer }.to_string(),
        format!(
            "Operation not valid for the session role of peer: {:02x?}",
            peer
        )
    );
}

/// The single documented host policy action for a [`SigilError`].
///
/// Mirrors the "Host policy:" contract documented on every [`SigilError`]
/// variant in `src/core/error/mod.rs`. If a variant's documented category
/// changes, this mapping must change in the same commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostPolicy {
    /// Drop the frame / skip the operation; never retry it as-is.
    RejectInput,
    /// Correct static firmware integration (buffers, roles, drivers).
    FixIntegration,
    /// Free the resource (`tick`, `cancel_pending`, re-key) or wait, then
    /// retry.
    BackOffOrReclaimCapacity,
    /// Always a library bug: capture diagnostics and report.
    ReportInvariantFailure,
}

/// Maps every error variant to its single documented host policy category.
///
// Deliberately exhaustive (no wildcard arm): adding a future `SigilError`
// variant fails compilation here until its host policy category is decided,
// keeping the taxonomy contract enforced by construction.
fn host_policy(err: &SigilError) -> HostPolicy {
    match err {
        SigilError::UnknownSession { .. }
        | SigilError::SessionExpired { .. }
        | SigilError::Replay { .. }
        | SigilError::VerificationFailed
        | SigilError::PendingAlreadyExists { .. }
        | SigilError::SessionNotActive { .. }
        | SigilError::SessionAlreadyActive { .. }
        | SigilError::InvalidStep { .. }
        | SigilError::UnexpectedEventDelivery { .. }
        | SigilError::InvalidEventId { .. }
        | SigilError::UnexpectedEventAck { .. }
        | SigilError::MalformedFrame => HostPolicy::RejectInput,

        SigilError::NoPending { .. }
        | SigilError::EcdhFailed
        | SigilError::RandomFailed
        | SigilError::InvalidStaticKey
        | SigilError::InvalidResumePsk
        | SigilError::InvalidKeyExpire { .. }
        | SigilError::InvalidKeyLifetime { .. }
        | SigilError::OutputBufferTooSmall
        | SigilError::WrongRole { .. } => HostPolicy::FixIntegration,

        SigilError::CounterExhausted { .. }
        | SigilError::TimeoutElapsed { .. }
        | SigilError::RateLimited { .. }
        | SigilError::EventAckPending { .. }
        | SigilError::EventDeliveryPending { .. }
        | SigilError::SessionTableFull
        | SigilError::PendingTableFull
        | SigilError::AdmissionTableFull => HostPolicy::BackOffOrReclaimCapacity,

        SigilError::InvariantViolation => HostPolicy::ReportInvariantFailure,
    }
}

#[test]
fn every_error_maps_to_one_documented_host_policy_category() {
    // One representative instance per variant; the exhaustive `host_policy`
    // match guarantees this table stays complete when the enum grows.
    let cases: [(&str, SigilError, HostPolicy); 30] = [
        (
            "UnknownSession",
            SigilError::UnknownSession { peer: PEER },
            HostPolicy::RejectInput,
        ),
        (
            "SessionExpired",
            SigilError::SessionExpired { peer: PEER },
            HostPolicy::RejectInput,
        ),
        (
            "Replay",
            SigilError::Replay {
                peer: PEER,
                expected: 2,
                received: 1,
            },
            HostPolicy::RejectInput,
        ),
        (
            "CounterExhausted",
            SigilError::CounterExhausted { peer: PEER },
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "VerificationFailed",
            SigilError::VerificationFailed,
            HostPolicy::RejectInput,
        ),
        (
            "NoPending",
            SigilError::NoPending { peer: PEER },
            HostPolicy::FixIntegration,
        ),
        (
            "PendingAlreadyExists",
            SigilError::PendingAlreadyExists { peer: PEER },
            HostPolicy::RejectInput,
        ),
        (
            "EcdhFailed",
            SigilError::EcdhFailed,
            HostPolicy::FixIntegration,
        ),
        (
            "RandomFailed",
            SigilError::RandomFailed,
            HostPolicy::FixIntegration,
        ),
        (
            "InvalidStaticKey",
            SigilError::InvalidStaticKey,
            HostPolicy::FixIntegration,
        ),
        (
            "InvalidResumePsk",
            SigilError::InvalidResumePsk,
            HostPolicy::FixIntegration,
        ),
        (
            "SessionNotActive",
            SigilError::SessionNotActive { peer: PEER },
            HostPolicy::RejectInput,
        ),
        (
            "SessionAlreadyActive",
            SigilError::SessionAlreadyActive { peer: PEER },
            HostPolicy::RejectInput,
        ),
        (
            "InvalidStep",
            SigilError::InvalidStep { peer: PEER },
            HostPolicy::RejectInput,
        ),
        (
            "TimeoutElapsed",
            SigilError::TimeoutElapsed { peer: PEER },
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "RateLimited",
            SigilError::RateLimited { peer: PEER },
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "InvalidKeyExpire",
            SigilError::InvalidKeyExpire {
                now: 10,
                key_expire_at: 5,
            },
            HostPolicy::FixIntegration,
        ),
        (
            "InvalidKeyLifetime",
            SigilError::InvalidKeyLifetime { lifetime_secs: 0 },
            HostPolicy::FixIntegration,
        ),
        (
            "EventAckPending",
            SigilError::EventAckPending {
                peer: PEER,
                event_id: 1,
            },
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "EventDeliveryPending",
            SigilError::EventDeliveryPending {
                peer: PEER,
                event_id: 1,
            },
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "UnexpectedEventDelivery",
            SigilError::UnexpectedEventDelivery {
                peer: PEER,
                event_id: 1,
            },
            HostPolicy::RejectInput,
        ),
        (
            "InvalidEventId",
            SigilError::InvalidEventId {
                peer: PEER,
                last: 3,
                received: 1,
            },
            HostPolicy::RejectInput,
        ),
        (
            "UnexpectedEventAck",
            SigilError::UnexpectedEventAck {
                peer: PEER,
                event_id: 1,
            },
            HostPolicy::RejectInput,
        ),
        (
            "OutputBufferTooSmall",
            SigilError::OutputBufferTooSmall,
            HostPolicy::FixIntegration,
        ),
        (
            "SessionTableFull",
            SigilError::SessionTableFull,
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "PendingTableFull",
            SigilError::PendingTableFull,
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "AdmissionTableFull",
            SigilError::AdmissionTableFull,
            HostPolicy::BackOffOrReclaimCapacity,
        ),
        (
            "MalformedFrame",
            SigilError::MalformedFrame,
            HostPolicy::RejectInput,
        ),
        (
            "WrongRole",
            SigilError::WrongRole { peer: PEER },
            HostPolicy::FixIntegration,
        ),
        (
            "InvariantViolation",
            SigilError::InvariantViolation,
            HostPolicy::ReportInvariantFailure,
        ),
    ];

    let mut seen_reject = false;
    let mut seen_fix = false;
    let mut seen_backoff = false;
    let mut seen_invariant = false;

    for &(name, ref err, expected) in &cases {
        let got = host_policy(err);
        assert_eq!(
            got, expected,
            "variant {} changed its documented host policy category",
            name
        );

        // Track that every category remains reachable from at least one
        // variant (guards against a degenerate one-category taxonomy).
        match got {
            HostPolicy::RejectInput => seen_reject = true,
            HostPolicy::FixIntegration => seen_fix = true,
            HostPolicy::BackOffOrReclaimCapacity => seen_backoff = true,
            HostPolicy::ReportInvariantFailure => seen_invariant = true,
        }
    }

    assert!(seen_reject && seen_fix && seen_backoff && seen_invariant);
}

#![cfg(all(test, feature = "sensor", feature = "gateway"))]

//! Unit tests for error types

use crate::core::error::SigilError;
use alloc::string::ToString;

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

    let err = SigilError::CapacityExceeded;
    assert!(err.to_string().contains("capacity exceeded"));

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

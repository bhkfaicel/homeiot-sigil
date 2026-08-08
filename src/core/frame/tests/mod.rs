//! Unit tests for frame type discriminator and outer header parsing

#![cfg(all(test, feature = "sensor", feature = "gateway"))]

use super::*;

#[test]
fn test_frame_type_from_byte_all_variants() {
    // All valid frame type bytes round-trip.
    assert_eq!(FrameType::from_byte(0x00), Some(FrameType::Data));
    assert_eq!(FrameType::from_byte(0x01), Some(FrameType::InstallRequest));
    assert_eq!(
        FrameType::from_byte(0x02),
        Some(FrameType::InstallChallenge)
    );
    assert_eq!(FrameType::from_byte(0x03), Some(FrameType::InstallConfirm));
    assert_eq!(
        FrameType::from_byte(0x04),
        Some(FrameType::InstallCommitConfirmed)
    );
    assert_eq!(FrameType::from_byte(0x11), Some(FrameType::RenewRequest));
    assert_eq!(FrameType::from_byte(0x12), Some(FrameType::RenewChallenge));
    assert_eq!(FrameType::from_byte(0x13), Some(FrameType::RenewAck));
    assert_eq!(
        FrameType::from_byte(0x14),
        Some(FrameType::RenewCommitConfirmed)
    );
    assert_eq!(FrameType::from_byte(0x21), Some(FrameType::ResumeRequest));
    assert_eq!(FrameType::from_byte(0x22), Some(FrameType::ResumeChallenge));
    assert_eq!(FrameType::from_byte(0x23), Some(FrameType::ResumeConfirm));
    assert_eq!(
        FrameType::from_byte(0x24),
        Some(FrameType::ResumeCommitConfirmed)
    );
    assert_eq!(FrameType::from_byte(0x30), Some(FrameType::TimeSync));
    assert_eq!(FrameType::from_byte(0x31), Some(FrameType::Event));
    assert_eq!(FrameType::from_byte(0x32), Some(FrameType::EventAck));
    assert_eq!(FrameType::from_byte(0x33), Some(FrameType::TimeSyncRequest));
}

#[test]
fn test_frame_type_from_byte_unknown() {
    // Unknown bytes return None.
    assert_eq!(FrameType::from_byte(0x05), None);
    assert_eq!(FrameType::from_byte(0x10), None);
    assert_eq!(FrameType::from_byte(0x15), None);
    assert_eq!(FrameType::from_byte(0x25), None);
    assert_eq!(FrameType::from_byte(0xFF), None);
}

#[test]
fn test_frame_type_roundtrip() {
    // Every variant serializes to its byte and parses back.
    let variants = [
        FrameType::Data,
        FrameType::InstallRequest,
        FrameType::InstallChallenge,
        FrameType::InstallConfirm,
        FrameType::InstallCommitConfirmed,
        FrameType::RenewRequest,
        FrameType::RenewChallenge,
        FrameType::RenewAck,
        FrameType::RenewCommitConfirmed,
        FrameType::ResumeRequest,
        FrameType::ResumeChallenge,
        FrameType::ResumeConfirm,
        FrameType::ResumeCommitConfirmed,
        FrameType::TimeSync,
        FrameType::Event,
        FrameType::EventAck,
        FrameType::TimeSyncRequest,
    ];
    for v in variants.iter() {
        let byte = *v as u8;
        assert_eq!(FrameType::from_byte(byte), Some(*v));
    }
}

#[test]
fn test_is_encrypted_payload() {
    // Data, renew messages, ResumeConfirm/CommitConfirmed, and
    // InstallCommitConfirmed use the AEAD payload format.
    assert!(FrameType::Data.is_encrypted_payload());
    assert!(FrameType::RenewRequest.is_encrypted_payload());
    assert!(FrameType::RenewChallenge.is_encrypted_payload());
    assert!(FrameType::RenewAck.is_encrypted_payload());
    assert!(FrameType::RenewCommitConfirmed.is_encrypted_payload());
    assert!(FrameType::ResumeConfirm.is_encrypted_payload());
    assert!(FrameType::ResumeCommitConfirmed.is_encrypted_payload());
    assert!(FrameType::InstallCommitConfirmed.is_encrypted_payload());
    assert!(FrameType::TimeSync.is_encrypted_payload());
    assert!(FrameType::Event.is_encrypted_payload());
    assert!(FrameType::EventAck.is_encrypted_payload());
    assert!(FrameType::TimeSyncRequest.is_encrypted_payload());

    // Install request/challenge/confirm and resume request/challenge remain clear-text.
    assert!(!FrameType::InstallRequest.is_encrypted_payload());
    assert!(!FrameType::InstallChallenge.is_encrypted_payload());
    assert!(!FrameType::InstallConfirm.is_encrypted_payload());
    assert!(!FrameType::ResumeRequest.is_encrypted_payload());
    assert!(!FrameType::ResumeChallenge.is_encrypted_payload());
}

#[test]
fn test_is_install() {
    assert!(FrameType::InstallRequest.is_install());
    assert!(FrameType::InstallChallenge.is_install());
    assert!(FrameType::InstallConfirm.is_install());
    assert!(FrameType::InstallCommitConfirmed.is_install());
    assert!(!FrameType::Data.is_install());
    assert!(!FrameType::RenewRequest.is_install());
    assert!(!FrameType::ResumeRequest.is_install());
}

#[test]
fn test_is_renew() {
    assert!(FrameType::RenewRequest.is_renew());
    assert!(FrameType::RenewChallenge.is_renew());
    assert!(FrameType::RenewAck.is_renew());
    assert!(FrameType::RenewCommitConfirmed.is_renew());
    assert!(!FrameType::Data.is_renew());
    assert!(!FrameType::InstallRequest.is_renew());
    assert!(!FrameType::ResumeRequest.is_renew());
}

#[test]
fn test_is_resume() {
    assert!(FrameType::ResumeRequest.is_resume());
    assert!(FrameType::ResumeChallenge.is_resume());
    assert!(FrameType::ResumeConfirm.is_resume());
    assert!(FrameType::ResumeCommitConfirmed.is_resume());
    assert!(!FrameType::Data.is_resume());
    assert!(!FrameType::InstallRequest.is_resume());
    assert!(!FrameType::RenewRequest.is_resume());
}

#[test]
fn test_parse_header_valid() {
    // A frame with a valid peer MAC, protocol version, and known frame type.
    let mut packet = [0u8; 32];
    packet[..17].copy_from_slice(&[7u8; 17]);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = FrameType::Data as u8;

    let header = parse_header(&packet).unwrap();
    assert_eq!(header.peer, [7u8; 17]);
    assert_eq!(header.frame_type, FrameType::Data);
}

#[test]
fn test_parse_header_too_short() {
    // A frame shorter than OUTER_HEADER_SIZE (19) cannot be parsed.
    let short = [0u8; 18];
    assert!(parse_header(&short).is_none());

    let empty: [u8; 0] = [];
    assert!(parse_header(&empty).is_none());
}

#[test]
fn test_parse_header_wrong_protocol_version() {
    // Frames with a non-v2 protocol version are rejected.
    let mut packet = [0u8; 32];
    packet[..17].copy_from_slice(&[7u8; 17]);
    packet[PROTOCOL_VERSION_OFFSET] = 0x01;
    packet[FRAME_TYPE_OFFSET] = FrameType::Data as u8;
    assert!(parse_header(&packet).is_none());
}

#[test]
fn test_parse_header_unknown_type() {
    // A frame with an unknown frame type byte is rejected.
    let mut packet = [0u8; 32];
    packet[..17].copy_from_slice(&[7u8; 17]);
    packet[PROTOCOL_VERSION_OFFSET] = PROTOCOL_VERSION;
    packet[FRAME_TYPE_OFFSET] = 0xFF;
    assert!(parse_header(&packet).is_none());
}

#[test]
fn test_build_header_roundtrip() {
    // build_header produces bytes that parse_header can decode.
    let peer = [3u8; 17];
    let header_bytes = build_header(&peer, FrameType::InstallChallenge);

    assert_eq!(header_bytes.len(), OUTER_HEADER_SIZE);
    assert_eq!(&header_bytes[..17], &peer[..]);
    assert_eq!(header_bytes[PROTOCOL_VERSION_OFFSET], PROTOCOL_VERSION);
    assert_eq!(
        header_bytes[FRAME_TYPE_OFFSET],
        FrameType::InstallChallenge as u8
    );

    let parsed = parse_header(&header_bytes).unwrap();
    assert_eq!(parsed.peer, peer);
    assert_eq!(parsed.frame_type, FrameType::InstallChallenge);
}

//! Wire codec conformance tests: golden vectors, round-trip properties, and
//! the malformed-input rejection matrix.

use crate::core::ota::error::OtaError;
use crate::core::ota::wire::{
    self, BEGIN_LEN, BeginFrame, CHUNK_LEN_MAX, ChunkFrame, FinalResult, OtaCommand, PeerState,
    StatusFrame,
};
use alloc::vec;
use alloc::vec::Vec;
use sha2::Digest;

use super::golden_vectors as gv;

/// Builds the BEGIN field set matching the golden vector literals.
fn golden_begin() -> BeginFrame {
    let mut img_sha256 = [0u8; 32];
    for (i, b) in img_sha256.iter_mut().enumerate() {
        *b = i as u8;
    }
    BeginFrame {
        img_version: gv::BEGIN_VERSION,
        img_len: gv::BEGIN_IMG_LEN,
        chunk_len: gv::BEGIN_CHUNK_LEN,
        img_sha256,
        manifest_sig: [0x5a; 64],
    }
}

/// Asserts `err` is the exact `BufferTooSmall` for a frame of `needed`
/// bytes offered an `available`-byte buffer.
fn assert_buffer_too_small(err: OtaError, needed: usize, available: usize) {
    assert_eq!(
        err,
        OtaError::BufferTooSmall { needed, available },
        "expected exact BufferTooSmall"
    );
}

// ---------------------------------------------------------------------------
// Golden vectors: parse side
// ---------------------------------------------------------------------------

#[test]
fn parse_golden_begin() {
    let raw = gv::unhex(gv::BEGIN_HEX);
    match wire::parse_command(&raw).expect("golden BEGIN must parse") {
        OtaCommand::Begin(b) => assert_eq!(b, golden_begin()),
        other => panic!("wrong command decoded: {other:?}"),
    }
}

#[test]
fn parse_golden_chunk() {
    let raw = gv::unhex(gv::CHUNK_HEX);
    match wire::parse_command(&raw).expect("golden CHUNK must parse") {
        OtaCommand::Chunk(c) => {
            assert_eq!(c.seq, gv::CHUNK_SEQ);
            assert_eq!(c.data, gv::CHUNK_DATA);
        }
        other => panic!("wrong command decoded: {other:?}"),
    }
}

#[test]
fn parse_golden_simple_commands() {
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::FINALIZE_HEX)),
        Ok(OtaCommand::Finalize)
    );
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::ABORT_HEX)),
        Ok(OtaCommand::Abort)
    );
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::REBOOT_HEX)),
        Ok(OtaCommand::Reboot {
            delay_ms: gv::REBOOT_DELAY_MS
        })
    );
}

#[test]
fn parse_golden_replies() {
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::ACK_READY_HEX)),
        Ok(OtaCommand::AckReady {
            chunk_len: gv::BEGIN_CHUNK_LEN
        })
    );
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::ACK_CHUNK_HEX)),
        Ok(OtaCommand::AckChunk {
            next_seq: gv::ACK_NEXT_SEQ
        })
    );
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::ACK_FINAL_OK_HEX)),
        Ok(OtaCommand::AckFinal(FinalResult::Ok))
    );
    let status = StatusFrame {
        state: PeerState::Streaming,
        next_seq: 9,
        img_version: gv::BEGIN_VERSION,
        img_len: gv::BEGIN_IMG_LEN,
    };
    assert_eq!(
        wire::parse_command(&gv::unhex(gv::STATUS_HEX)),
        Ok(OtaCommand::Status(status))
    );
}

// ---------------------------------------------------------------------------
// Golden vectors: encode side (byte-exact)
// ---------------------------------------------------------------------------

#[test]
fn encode_matches_every_golden_vector() {
    let mut out = [0u8; BEGIN_LEN];

    let n = wire::encode_begin(&golden_begin(), &mut out).expect("BEGIN encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::BEGIN_HEX)[..], "BEGIN hex drift");

    let n = wire::encode_chunk(gv::CHUNK_SEQ, gv::CHUNK_DATA, &mut out).expect("CHUNK encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::CHUNK_HEX)[..], "CHUNK hex drift");

    let n = wire::encode_finalize(&mut out).expect("FINALIZE encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::FINALIZE_HEX)[..]);

    let n = wire::encode_reboot(gv::REBOOT_DELAY_MS, &mut out).expect("REBOOT encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::REBOOT_HEX)[..]);

    let n = wire::encode_abort(&mut out).expect("ABORT encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::ABORT_HEX)[..]);

    let n = wire::encode_ack_ready(gv::BEGIN_CHUNK_LEN, &mut out).expect("ACK_READY encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::ACK_READY_HEX)[..]);

    let n = wire::encode_ack_chunk(gv::ACK_NEXT_SEQ, &mut out).expect("ACK_CHUNK encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::ACK_CHUNK_HEX)[..]);

    let n = wire::encode_ack_final(FinalResult::Ok, &mut out).expect("ACK_FINAL encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::ACK_FINAL_OK_HEX)[..]);

    let status = StatusFrame {
        state: PeerState::Streaming,
        next_seq: 9,
        img_version: gv::BEGIN_VERSION,
        img_len: gv::BEGIN_IMG_LEN,
    };
    let n = wire::encode_status(&status, &mut out).expect("STATUS encodes");
    assert_eq!(&out[..n], &gv::unhex(gv::STATUS_HEX)[..]);
}

// ---------------------------------------------------------------------------
// Round-trip properties across parameter extremes
// ---------------------------------------------------------------------------

#[test]
fn round_trip_begin_at_geometry_extremes() {
    let mut out = [0u8; BEGIN_LEN];
    for &chunk_len in &[wire::CHUNK_LEN_MIN as u8, wire::CHUNK_LEN_MAX as u8] {
        let begin = BeginFrame {
            img_version: 0xdead_beef,
            img_len: 1, // minimum legal image length
            chunk_len,
            img_sha256: [7; 32],
            manifest_sig: [9; 64],
        };
        let n = wire::encode_begin(&begin, &mut out).expect("extreme BEGIN encodes");
        match wire::parse_command(&out[..n]).expect("extreme BEGIN parses") {
            OtaCommand::Begin(decoded) => assert_eq!(decoded, begin),
            other => panic!("wrong command: {other:?}"),
        }
    }
}

#[test]
fn round_trip_chunk_at_length_extremes() {
    // Last-chunk short payloads and maximum-size payloads must both survive.
    for len in [1usize, CHUNK_LEN_MAX] {
        let data: Vec<u8> = (0..len as u8).collect();
        let mut out = vec![0u8; wire::CHUNK_HEADER_LEN + len];
        let n = wire::encode_chunk(0xffff, &data, &mut out).expect("extreme CHUNK encodes");
        match wire::parse_command(&out[..n]).expect("extreme CHUNK parses") {
            OtaCommand::Chunk(ChunkFrame { seq, data: d }) => {
                assert_eq!(seq, 0xffff);
                assert_eq!(d, &data[..]);
            }
            other => panic!("wrong command: {other:?}"),
        }
    }
}

#[test]
fn round_trip_all_final_results() {
    let results = [
        FinalResult::Ok,
        FinalResult::HashMismatch,
        FinalResult::SigRejected,
        FinalResult::StorageError,
        FinalResult::BadState,
        FinalResult::SizeRejected,
    ];
    let mut out = [0u8; 3];
    for result in results {
        let n = wire::encode_ack_final(result, &mut out).expect("result encodes");
        assert_eq!(
            wire::parse_command(&out[..n]),
            Ok(OtaCommand::AckFinal(result))
        );
    }
}

#[test]
fn round_trip_all_peer_states_in_status() {
    let states = [
        PeerState::Idle,
        PeerState::Streaming,
        PeerState::PendingReboot,
    ];
    let mut out = [0u8; 13];
    for state in states {
        let status = StatusFrame {
            state,
            next_seq: 1,
            img_version: 2,
            img_len: 3,
        };
        let n = wire::encode_status(&status, &mut out).expect("status encodes");
        assert_eq!(
            wire::parse_command(&out[..n]),
            Ok(OtaCommand::Status(status))
        );
    }
}

// ---------------------------------------------------------------------------
// Malformed-input rejection matrix
// ---------------------------------------------------------------------------

#[test]
fn rejects_envelope_violations() {
    // Empty payload.
    assert!(matches!(
        wire::parse_command(&[]),
        Err(OtaError::Malformed { id: 0, .. })
    ));
    // Wrong envelope opcode.
    assert!(matches!(
        wire::parse_command(&[0x7e, wire::CMD_BEGIN]),
        Err(OtaError::Malformed { id: 0, .. })
    ));
    // Unknown command ids (below the family, inside the gap, above it).
    for id in [0x09u8, 0x1f, 0xff] {
        assert!(
            matches!(
                wire::parse_command(&[0x7f, id]),
                Err(OtaError::Malformed { .. })
            ),
            "id {id:#x} must be rejected"
        );
    }
}

#[test]
fn rejects_begin_at_every_truncation_and_extension() {
    let raw = gv::unhex(gv::BEGIN_HEX);
    // Every prefix shorter than the full frame is malformed.
    for len in 2..raw.len() {
        assert!(
            matches!(
                wire::parse_command(&raw[..len]),
                Err(OtaError::Malformed { .. })
            ),
            "truncated BEGIN at {len} bytes must be rejected"
        );
    }
    // One trailing byte beyond the exact frame is malformed too.
    let mut extended = raw.clone();
    extended.push(0x00);
    assert!(matches!(
        wire::parse_command(&extended),
        Err(OtaError::Malformed { .. })
    ));
}

#[test]
fn rejects_begin_out_of_contract_fields() {
    let mut raw = gv::unhex(gv::BEGIN_HEX);
    for &bad_chunk in &[0u8, 63, 197, 255] {
        raw[10] = bad_chunk; // BODY_OFFSET(2) + 8 = offset 10 in the payload.
        assert!(
            matches!(wire::parse_command(&raw), Err(OtaError::Malformed { .. })),
            "chunk_len {bad_chunk} must be rejected"
        );
    }
    // Zero image length with otherwise valid geometry (img_len occupies
    // payload bytes 6..10).
    let mut zero_len = gv::unhex(gv::BEGIN_HEX);
    for byte in &mut zero_len[6..10] {
        *byte = 0;
    }
    assert!(matches!(
        wire::parse_command(&zero_len),
        Err(OtaError::Malformed { .. })
    ));
}

#[test]
fn rejects_bad_chunk_frames() {
    // Missing sequence half-word.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_CHUNK, 0x00]),
        Err(OtaError::Malformed { .. })
    ));
    // Empty data (header only).
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_CHUNK, 0x00, 0x01]),
        Err(OtaError::Malformed { .. })
    ));
    // One byte beyond CHUNK_LEN_MAX.
    let oversized = vec![0xa5u8; CHUNK_LEN_MAX + 1];
    let mut raw = vec![0x7f, wire::CMD_CHUNK, 0x00, 0x02];
    raw.extend_from_slice(&oversized);
    assert!(matches!(
        wire::parse_command(&raw),
        Err(OtaError::Malformed { .. })
    ));
}

#[test]
fn rejects_body_corruption_on_fixed_frames() {
    // Truncated REBOOT.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_REBOOT, 0x05]),
        Err(OtaError::Malformed { .. })
    ));
    // FINALIZE with trailing garbage.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_FINALIZE, 0x00]),
        Err(OtaError::Malformed { .. })
    ));
    // ABORT with trailing garbage.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_ABORT, 0x00]),
        Err(OtaError::Malformed { .. })
    ));
    // ACK_READY with wrong accepted chunk length.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_ACK_READY, 10]),
        Err(OtaError::Malformed { .. })
    ));
    // ACK_CHUNK truncated.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_ACK_CHUNK, 0x00]),
        Err(OtaError::Malformed { .. })
    ));
    // ACK_FINAL unknown result code.
    assert!(matches!(
        wire::parse_command(&[0x7f, wire::CMD_ACK_FINAL, 0x06]),
        Err(OtaError::Malformed { .. })
    ));
    // STATUS unknown state byte and truncation.
    let mut status_raw = gv::unhex(gv::STATUS_HEX);
    status_raw[2] = 0x03;
    assert!(matches!(
        wire::parse_command(&status_raw),
        Err(OtaError::Malformed { .. })
    ));
    assert!(matches!(
        wire::parse_command(&gv::unhex(gv::STATUS_HEX)[..12]),
        Err(OtaError::Malformed { .. })
    ));
}

// ---------------------------------------------------------------------------
// Encode-side validation
// ---------------------------------------------------------------------------

#[test]
fn encode_reports_exact_buffer_requirements() {
    let mut tiny = [0u8; 4];
    assert_buffer_too_small(
        wire::encode_begin(&golden_begin(), &mut tiny).unwrap_err(),
        BEGIN_LEN,
        4,
    );
    // A zero-length buffer fails even the smallest frame, reporting the
    // exact requirement.
    let empty: &mut [u8] = &mut [];
    assert_buffer_too_small(wire::encode_finalize(empty).unwrap_err(), 2, 0);
    assert_buffer_too_small(wire::encode_abort(empty).unwrap_err(), 2, 0);
}

#[test]
fn encode_rejects_invalid_parameters() {
    // Large enough for BEGIN (107 B) and a maximum-size CHUNK (200 B).
    let mut out = [0u8; CHUNK_LEN_MAX + wire::CHUNK_HEADER_LEN];
    let mut bad_geometry = golden_begin();
    bad_geometry.chunk_len = 32;
    assert!(matches!(
        wire::encode_begin(&bad_geometry, &mut out),
        Err(OtaError::InvalidParams { .. })
    ));
    bad_geometry.chunk_len = 192;
    bad_geometry.img_len = 0;
    assert!(matches!(
        wire::encode_begin(&bad_geometry, &mut out),
        Err(OtaError::InvalidParams { .. })
    ));

    let big = &mut out[..wire::CHUNK_HEADER_LEN + CHUNK_LEN_MAX];
    assert!(matches!(
        wire::encode_chunk(0, &[], big),
        Err(OtaError::InvalidParams { .. })
    ));
    let oversized = [0u8; CHUNK_LEN_MAX + 1];
    assert!(matches!(
        wire::encode_chunk(0, &oversized, big),
        Err(OtaError::InvalidParams { .. })
    ));

    let mut small = [0u8; 3];
    assert!(matches!(
        wire::encode_ack_ready(1, &mut small),
        Err(OtaError::InvalidParams { .. })
    ));
}

// ---------------------------------------------------------------------------
// Manifest digest known-answer layout check
// ---------------------------------------------------------------------------

#[test]
fn manifest_digest_layout_matches_documented_construction() {
    // Independently assemble the documented input layout and compare against
    // the helper output: this pins the domain tag, field order, and integer
    // endianness of the signed digest contract.
    let version: u32 = 0x0102_0304;
    let len: u32 = 0x0506_0708;
    let chunk_len: u8 = 192;
    let sha = [0x11u8; 32];

    let mut expected_input = [0u8; 53];
    expected_input[..12].copy_from_slice(b"sigil-ota-v1");
    expected_input[12..16].copy_from_slice(&version.to_le_bytes());
    expected_input[16..20].copy_from_slice(&len.to_le_bytes());
    expected_input[20] = chunk_len;
    expected_input[21..53].copy_from_slice(&sha);

    let expected: [u8; 32] = sha2::Sha256::digest(expected_input).into();
    assert_eq!(
        wire::manifest_digest(version, len, chunk_len, &sha),
        expected,
        "digest construction drifted from the documented contract"
    );
}

// ---------------------------------------------------------------------------
// Cross-module drift guards (compiled only alongside the session feature)
// ---------------------------------------------------------------------------

/// The OTA chunk bound is derived from the product Data payload bound. When
/// both modules compile together, assert the derivation stays valid.
#[cfg(all(test, feature = "session"))]
mod session_drift_guards {
    use crate::core::event::DATA_MAX;
    use crate::core::ota::wire::{CHUNK_HEADER_LEN, CHUNK_LEN_MAX};

    #[test]
    fn max_chunk_data_tracks_data_max_bound() {
        assert_eq!(
            CHUNK_HEADER_LEN + CHUNK_LEN_MAX,
            DATA_MAX,
            "OTA chunk budget must exactly fill the Data payload bound"
        );
    }
}

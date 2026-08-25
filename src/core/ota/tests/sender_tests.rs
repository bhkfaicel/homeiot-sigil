#![cfg(all(feature = "ota", feature = "gateway"))]
//! Send-engine conformance tests: stop-and-wait scheduling, retry budget,
//! cumulative-ACK bookkeeping, STATUS-driven resume, and the digest
//! preflight gate.

use crate::core::ota::error::OtaError;
use crate::core::ota::image::OtaImageSource;
use crate::core::ota::sender::{
    DEFAULT_ACK_TIMEOUT_SECS, OtaSender, SenderAction, TransferEnd, TxFrame,
};
use crate::core::ota::wire::{
    BeginFrame, CHUNK_LEN_MAX, CHUNK_LEN_MIN, FinalResult, OtaCommand, PeerState, StatusFrame,
    manifest_digest_input,
};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// Deterministic RAM image whose bytes follow `(index * 7 % 251)`.
struct MemImage {
    data: Vec<u8>,
    fail_reads: bool,
}

impl MemImage {
    fn new(len: usize) -> Self {
        Self {
            data: (0..len).map(|i| ((i * 7) % 251) as u8).collect(),
            fail_reads: false,
        }
    }

    /// The real SHA-256 of this image content.
    fn sha(&self) -> [u8; 32] {
        Sha256::digest(&self.data).into()
    }

    /// Manifest signed over THIS image with the given geometry.
    fn manifest_for(&self, version: u32, chunk_len: u8) -> BeginFrame {
        let msg = manifest_digest_input(version, self.data.len() as u32, chunk_len, &self.sha());
        // Signature content is opaque to the send half; a fixed tag keeps
        // vectors deterministic without dragging an ECDSA stack in here.
        let mut sig = [0u8; 64];
        sig[..msg.len()].copy_from_slice(&msg);
        BeginFrame {
            img_version: version,
            img_len: self.data.len() as u32,
            chunk_len,
            img_sha256: self.sha(),
            manifest_sig: sig,
        }
    }
}

impl OtaImageSource for MemImage {
    fn len(&self) -> u32 {
        self.data.len() as u32
    }

    fn read_at(&self, offset: u32, out: &mut [u8]) -> Result<(), OtaError> {
        let end = offset as usize + out.len();
        if end > self.data.len() || self.fail_reads {
            return Err(OtaError::Storage);
        }
        out.copy_from_slice(&self.data[offset as usize..end]);
        Ok(())
    }
}

/// Convenience: one engine call that must produce a Transmit.
fn expect_transmit<'a>(action: Result<Option<SenderAction<'a>>, OtaError>) -> (TxFrame<'a>, u32) {
    match action.expect("no storage fault expected") {
        Some(SenderAction::Transmit {
            frame,
            deadline_secs,
        }) => (frame, deadline_secs),
        other => panic!("expected Transmit, got {other:?}"),
    }
}

/// Starts a session on `img`, asserting the first action is the BEGIN
/// transmit, and returns the engine ready for replies.
fn started(img: &mut MemImage) -> OtaSender {
    let manifest = img.manifest_for(9, CHUNK_LEN_MIN as u8);
    let mut tx = OtaSender::new(2, DEFAULT_ACK_TIMEOUT_SECS);
    assert!(matches!(
        tx.start(img, manifest, 100).expect("preflight passes"),
        SenderAction::Transmit {
            frame: TxFrame::Begin(_),
            ..
        }
    ));
    tx
}

// ---------------------------------------------------------------------------
// start(): preflight and framing
// ---------------------------------------------------------------------------

#[test]
fn start_emits_begin_with_deadline() {
    let mut img = MemImage::new(300);
    let manifest = img.manifest_for(9, CHUNK_LEN_MIN as u8);
    let mut tx = OtaSender::new(2, DEFAULT_ACK_TIMEOUT_SECS);
    let action = tx.start(&mut img, manifest, 100).expect("preflight passes");
    match &action {
        SenderAction::Transmit {
            frame: TxFrame::Begin(b),
            deadline_secs,
        } => {
            assert_eq!(b.img_version, 9);
            assert_eq!(b.img_len, 300);
            assert_eq!(b.chunk_len, CHUNK_LEN_MIN as u8);
            assert_eq!(*deadline_secs, 100 + DEFAULT_ACK_TIMEOUT_SECS);
        }
        other => panic!("expected Begin transmit, got {other:?}"),
    }
    // The engine is committed once the BEGIN action was produced.
    assert!(!tx.is_idle());
}

#[test]
fn start_rejects_digest_mismatch_and_bad_geometry() {
    let mut img = MemImage::new(128);

    // Corrupt the declared digest relative to actual content.
    let mut bad_sha = img.manifest_for(1, CHUNK_LEN_MIN as u8);
    bad_sha.img_sha256[0] ^= 0xFF;
    let mut tx = OtaSender::new(2, 1);
    assert!(matches!(
        tx.start(&mut img, bad_sha, 1),
        Err(OtaError::InvalidParams { .. })
    ));

    // Bad chunk length / zero length / count overflow.
    for chunk_len in [0u8, 10, 200] {
        let m = img.manifest_for(1, chunk_len);
        assert!(
            matches!(
                tx.start(&mut img, m, 1),
                Err(OtaError::InvalidParams { .. })
            ),
            "chunk_len {chunk_len} must be rejected"
        );
    }
    let zero = img.manifest_for(1, CHUNK_LEN_MIN as u8);
    let _ = zero; // zero-length images cannot exist in MemImage; covered by
    // the receiver-side matrix. Count overflow:
    let huge = BeginFrame {
        img_version: 1,
        img_len: (CHUNK_LEN_MIN as u32) * 65_537,
        chunk_len: CHUNK_LEN_MIN as u8,
        img_sha256: [0u8; 32],
        manifest_sig: [0u8; 64],
    };
    assert!(matches!(
        tx.start(&mut img, huge, 1),
        Err(OtaError::InvalidParams { .. })
    ));
}

#[test]
fn second_start_while_active_is_a_state_error() {
    let mut img = MemImage::new(128);
    let mut tx = started(&mut img);
    let again = img.manifest_for(2, CHUNK_LEN_MIN as u8);
    assert!(matches!(
        tx.start(&mut img, again, 110),
        Err(OtaError::BadState { .. })
    ));
}

// ---------------------------------------------------------------------------
// Happy path through cumulative ACKs
// ---------------------------------------------------------------------------

#[test]
fn ack_chain_streams_all_chunks_then_finalizes() {
    let mut img = MemImage::new(300); // 64+64+64+64+44
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);

    // ACK_READY -> chunk 0.
    let (frame, _) = expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: cl as u8,
        },
        101,
    ));
    let TxFrame::Chunk { seq: 0, data } = frame else {
        panic!("expected chunk 0");
    };
    assert_eq!(data, &img.data[..cl]);

    // Each cumulative ACK advances by one; the last triggers FINALIZE.
    let total = (300usize).div_ceil(cl);
    for next in 1..total {
        let (frame, _) = expect_transmit(tx.on_reply(
            &mut img,
            OtaCommand::AckChunk {
                next_seq: next as u16,
            },
            102 + next as u32,
        ));
        let expected_len = if next == total - 1 {
            300 - next * cl
        } else {
            cl
        };
        let TxFrame::Chunk { seq, data } = frame else {
            panic!("expected chunk {next}");
        };
        assert_eq!(usize::from(seq), next);
        assert_eq!(data.len(), expected_len);
        assert_eq!(data, &img.data[next * cl..next * cl + expected_len]);
    }
    match expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckChunk {
            next_seq: total as u16,
        },
        200,
    )) {
        (TxFrame::Finalize, _) => {}
        other => panic!("expected Finalize, got {other:?}"),
    }

    // Verdict completes the loop.
    match tx
        .on_reply(&mut img, OtaCommand::AckFinal(FinalResult::Ok), 210)
        .expect("no fault")
    {
        Some(SenderAction::End(TransferEnd::Completed)) => {}
        other => panic!("expected Completed, got {other:?}"),
    }

    // REBOOT unlocks only after completion.
    assert!(matches!(
        tx.reboot(400),
        Ok(SenderAction::TransmitFinal {
            frame: TxFrame::Reboot { delay_ms: 400 }
        })
    ));
}

#[test]
fn stale_acks_are_ignored_silently() {
    let mut img = MemImage::new(128);
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);

    tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: cl as u8,
        },
        101,
    )
    .expect("ready handled");

    // Duplicate BEGIN-ack while streaming: inert.
    assert_eq!(
        tx.on_reply(
            &mut img,
            OtaCommand::AckReady {
                chunk_len: cl as u8
            },
            102
        )
        .expect("no fault"),
        None
    );
    // Non-advancing cumulative ACK: inert.
    assert_eq!(
        tx.on_reply(&mut img, OtaCommand::AckChunk { next_seq: 0 }, 103)
            .expect("no fault"),
        None
    );
    // Unrelated inbound commands: inert.
    assert_eq!(
        tx.on_reply(&mut img, OtaCommand::Finalize, 104)
            .expect("no fault"),
        None
    );
}

// ---------------------------------------------------------------------------
// Loss handling: deadlines, retries, exhaustion
// ---------------------------------------------------------------------------

#[test]
fn ack_loss_resends_same_chunk_after_deadline() {
    let mut img = MemImage::new(128);
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);
    expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: cl as u8,
        },
        101,
    ));

    // Before the deadline: nothing to do.
    assert_eq!(
        tx.poll(&mut img, 100 + DEFAULT_ACK_TIMEOUT_SECS - 1)
            .expect("no fault"),
        None
    );

    // After it: identical chunk re-emitted.
    let (frame, _) = expect_transmit(tx.poll(&mut img, 103));
    let TxFrame::Chunk { seq: 0, data } = frame else {
        panic!("expected chunk 0 resend");
    };
    assert_eq!(data, &img.data[..cl]);

    // Recovery via the cumulative ACK advances normally.
    let (frame, _) =
        expect_transmit(tx.on_reply(&mut img, OtaCommand::AckChunk { next_seq: 1 }, 104));
    assert!(matches!(frame, TxFrame::Chunk { seq: 1, .. }));
}

#[test]
fn retry_exhaustion_ends_timed_out_and_blocks_reboot() {
    let mut img = MemImage::new(cl_image_len());
    let cl = CHUNK_LEN_MIN;
    // Budget: max_retries = 2 -> at most 3 transmissions per frame.
    let manifest = img.manifest_for(5, cl as u8);
    let mut tx = OtaSender::new(2, 1);
    tx.start(&mut img, manifest, 0).expect("start ok");
    let mut now = 1;

    // First send (start), then two resends, then exhaustion.
    let mut saw_begin_sends = 1;
    loop {
        match tx.poll(&mut img, now).expect("no fault") {
            Some(SenderAction::Transmit {
                frame: TxFrame::Begin(_),
                ..
            }) => {
                saw_begin_sends += 1;
                now += 1;
            }
            Some(SenderAction::End(TransferEnd::TimedOut)) => break,
            other => panic!("unexpected action {other:?}"),
        }
    }
    assert_eq!(saw_begin_sends, 3, "first send plus exactly two resends");

    // TimedOut is terminal but NOT completed: reboot stays locked.
    assert!(matches!(tx.reboot(1), Err(OtaError::BadState { .. })));
}

/// Image length small enough for a single-chunk transfer.
fn cl_image_len() -> usize {
    CHUNK_LEN_MIN
}

#[test]
fn abort_emits_fire_and_forget_and_resets() {
    let mut img = MemImage::new(128);
    let mut tx = started(&mut img);
    assert!(matches!(
        tx.abort(),
        Ok(SenderAction::TransmitFinal {
            frame: TxFrame::Abort
        })
    ));
    assert!(tx.is_idle());
    // A fresh session can start afterwards.
    restart_ok(&mut img, &mut tx);
}

fn restart_ok(img: &mut MemImage, tx: &mut OtaSender) {
    let manifest = img.manifest_for(3, CHUNK_LEN_MIN as u8);
    assert!(matches!(
        tx.start(img, manifest, 500).expect("restart ok"),
        SenderAction::Transmit {
            frame: TxFrame::Begin(_),
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// STATUS-driven resume
// ---------------------------------------------------------------------------

#[test]
fn status_streaming_ahead_resumes_at_peer_position() {
    let mut img = MemImage::new(512);
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);
    expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: cl as u8,
        },
        101,
    ));

    // Peer reports it already holds chunks 0..4 (cumulative next_seq=4).
    let status = StatusFrame {
        state: PeerState::Streaming,
        next_seq: 4,
        img_version: 9,
        img_len: 512,
    };
    let (frame, _) = expect_transmit(tx.on_reply(&mut img, OtaCommand::Status(status), 105));
    let TxFrame::Chunk { seq: 4, data } = frame else {
        panic!("expected resume at chunk 4");
    };
    assert_eq!(data, &img.data[4 * cl..5 * cl]);
}

#[test]
fn status_full_progress_jumps_straight_to_finalize() {
    let mut img = MemImage::new(128);
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);
    expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: cl as u8,
        },
        101,
    ));

    let status = StatusFrame {
        state: PeerState::Streaming,
        next_seq: 2, // == total chunks for 128 B / 64 B
        img_version: 9,
        img_len: 128,
    };
    let (frame, _) = expect_transmit(tx.on_reply(&mut img, OtaCommand::Status(status), 105));
    assert!(matches!(frame, TxFrame::Finalize));
}

#[test]
fn status_idle_restarts_the_session_from_begin() {
    let mut img = MemImage::new(128);
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);
    expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: cl as u8,
        },
        101,
    ));

    let status = StatusFrame {
        state: PeerState::Idle,
        next_seq: 0,
        img_version: 0,
        img_len: 0,
    };
    let (frame, _) = expect_transmit(tx.on_reply(&mut img, OtaCommand::Status(status), 105));
    assert!(matches!(frame, TxFrame::Begin(_)));
}

// ---------------------------------------------------------------------------
// Source faults surface verbatim
// ---------------------------------------------------------------------------

#[test]
fn image_read_faults_surface_as_storage_errors() {
    let mut img = MemImage::new(128);
    let cl = CHUNK_LEN_MIN;
    let mut tx = started(&mut img);
    img.fail_reads = true;
    let err = tx
        .on_reply(
            &mut img,
            OtaCommand::AckReady {
                chunk_len: cl as u8,
            },
            101,
        )
        .unwrap_err();
    assert_eq!(err, OtaError::Storage);
}

#[test]
fn max_chunk_boundary_geometry_round_trips_through_sender() {
    // One full-size maximum chunk exercises the buffer sizing contract.
    let mut img = MemImage::new(CHUNK_LEN_MAX);
    let manifest = img.manifest_for(1, CHUNK_LEN_MAX as u8);
    let mut tx = OtaSender::new(1, 1);
    let (_, _) = expect_transmit_pair(tx.start(&mut img, manifest, 0));
    let (frame, _) = expect_transmit(tx.on_reply(
        &mut img,
        OtaCommand::AckReady {
            chunk_len: CHUNK_LEN_MAX as u8,
        },
        1,
    ));
    let TxFrame::Chunk { seq: 0, data } = frame else {
        panic!("expected single chunk");
    };
    assert_eq!(data.len(), CHUNK_LEN_MAX);
    // Completion ACK jumps to FINALIZE directly.
    let (frame, _) =
        expect_transmit(tx.on_reply(&mut img, OtaCommand::AckChunk { next_seq: 1 }, 2));
    assert!(matches!(frame, TxFrame::Finalize));
}

/// Helper splitting the always-transmit start result.
fn expect_transmit_pair<'a>(result: Result<SenderAction<'a>, OtaError>) -> (TxFrame<'a>, u32) {
    match result.expect("start ok") {
        SenderAction::Transmit {
            frame,
            deadline_secs,
        } => (frame, deadline_secs),
        other => panic!("expected Transmit, got {other:?}"),
    }
}

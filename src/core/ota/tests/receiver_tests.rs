#![cfg(all(feature = "ota", feature = "sensor"))]
//! Receive-engine conformance tests: transition matrix over every
//! accept/reject edge, storage fault injection, idle-timeout policy, and
//! trailer-marker trust-chain gating.

use crate::core::ota::error::OtaError;
use crate::core::ota::receiver::{OtaReceiver, OtaReceiverConfig, Reply, RxOutcome, TickOutcome};
use crate::core::ota::storage::OtaStorage;
use crate::core::ota::trailer::{TRAILER_LEN, TrailerRecord, TrailerStatus};
use crate::core::ota::wire::{
    BeginFrame, CHUNK_LEN_MIN, ChunkFrame, FinalResult, OtaCommand, PeerState,
    manifest_digest_input,
};
use crate::core::test_support::MockSecureElement;
use crate::core::traits::{SecureElement, StaticPublicKey};
use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// RAM-backed [`OtaStorage`] with fault injection and contract assertions.
///
/// The erase-alignment assertions double as engine-contract checks: any
/// unaligned engine call fails the test immediately.
struct FaultyStorage {
    mem: Vec<u8>,
    granularity: u32,
    fail_erase: bool,
    fail_write: bool,
    erase_calls: usize,
    write_calls: usize,
}

impl FaultyStorage {
    fn new(cap: u32) -> Self {
        Self::with_granularity(cap, 256)
    }

    fn with_granularity(cap: u32, granularity: u32) -> Self {
        Self {
            mem: vec![0xFF; cap as usize],
            granularity,
            fail_erase: false,
            fail_write: false,
            erase_calls: 0,
            write_calls: 0,
        }
    }

    /// Staged bytes read back for end-of-transfer verification.
    fn slice(&self, offset: usize, len: usize) -> &[u8] {
        &self.mem[offset..offset + len]
    }
}

impl OtaStorage for FaultyStorage {
    fn erase_granularity(&self) -> u32 {
        self.granularity
    }

    fn erase_range(&mut self, offset: u32, len: u32) -> Result<(), OtaError> {
        assert_eq!(
            offset % self.granularity,
            0,
            "engine violated erase alignment (offset)"
        );
        assert_eq!(
            len % self.granularity,
            0,
            "engine violated erase alignment (len)"
        );
        let end = offset.checked_add(len).expect("erase range overflow");
        assert!(end <= self.mem.len() as u32, "erase out of window");
        self.erase_calls += 1;
        if self.fail_erase {
            return Err(OtaError::Storage);
        }
        for b in &mut self.mem[offset as usize..end as usize] {
            *b = 0xFF;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), OtaError> {
        let end = offset
            .checked_add(data.len() as u32)
            .expect("write overflow");
        assert!(end <= self.mem.len() as u32, "write out of window");
        self.write_calls += 1;
        if self.fail_write {
            return Err(OtaError::Storage);
        }
        self.mem[offset as usize..end as usize].copy_from_slice(data);
        Ok(())
    }
}

impl FaultyStorage {
    /// Inherent readback (NOT part of the `OtaStorage` sink trait): used by
    /// assertions only.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), OtaError> {
        let end = offset.checked_add(buf.len() as u32).expect("read overflow");
        assert!(end <= self.mem.len() as u32, "read out of window");
        buf.copy_from_slice(&self.mem[offset as usize..end as usize]);
        Ok(())
    }
}

/// Deterministic factory root key for the receiver under test.
fn factory_pub() -> StaticPublicKey {
    let mut key = [0x02u8; 33];
    key[1] = 0xAA;
    key
}

/// Product id shared by every fixture in this file (bound into signed
/// manifests).
const PRODUCT_ID: u16 = 0x0001;
/// Hardware profile bound into signed manifests (matches install cert).
const HARDWARE_PROFILE: u8 = 0x01;

/// Builds the standard engine config for a given staging capacity.
fn rig_config(staging_cap: u32) -> OtaReceiverConfig {
    OtaReceiverConfig {
        product_id: PRODUCT_ID,
        hardware_profile_id: HARDWARE_PROFILE,
        staging_cap,
        trailer_offset: staging_cap,
        min_acceptable_version: 0,
        idle_timeout_secs: 30,
        absolute_session_timeout_secs: 3600,
    }
}

/// Trailer region size: one aligned block is plenty for 46 bytes.
const TRAILER_SPAN: u32 = 256;

/// Bundles one engine with its effects for compact scenarios.
struct Rig {
    rx: OtaReceiver,
    storage: FaultyStorage,
    se: MockSecureElement,
}

impl Rig {
    /// Engine staging window `[0, staging_cap)` plus one trailer block.
    fn new(staging_cap: u32) -> Self {
        Self {
            rx: OtaReceiver::new(factory_pub(), rig_config(staging_cap)),
            storage: FaultyStorage::new(staging_cap + TRAILER_SPAN),
            se: MockSecureElement::new(factory_pub()),
        }
    }

    /// Processes one command, failing loudly on unexpected storage errors.
    fn send(&mut self, cmd: OtaCommand<'_>, now: u32) -> RxOutcome {
        self.rx
            .on_command(&mut self.storage, &mut self.se, cmd, now)
            .expect("storage must not fault in this scenario")
    }

    /// Produces a validly signed BEGIN frame for `(version, img_len,
    /// chunk_len)` against this rig's secure element. The declared digest is
    /// the REAL digest of the deterministic chunk stream, so happy paths
    /// pass the integrity gate.
    fn signed_begin(&mut self, version: u32, img_len: u32, chunk_len: u8) -> BeginFrame {
        let sha = transfer_image_sha(img_len, chunk_len);
        let msg = manifest_digest_input(
            PRODUCT_ID,
            HARDWARE_PROFILE,
            version,
            img_len,
            chunk_len,
            &sha,
        );
        let sig = self.se.sign_ecdsa(&msg).expect("mock signing works");
        BeginFrame {
            img_version: version,
            img_len,
            chunk_len,
            img_sha256: sha,
            manifest_sig: sig,
        }
    }

    /// Opens a session; returns the accepted negotiated chunk length.
    fn open_session(&mut self, version: u32, img_len: u32, chunk_len: u8) -> u8 {
        let begin = self.signed_begin(version, img_len, chunk_len);
        match self.send(OtaCommand::Begin(begin), 100) {
            RxOutcome::Respond(Reply::Ready { chunk_len }) => chunk_len,
            other => panic!("expected ACK_READY, got {other:?}"),
        }
    }
}

/// Deterministic pseudo-image digest so comparisons are stable per geometry.
///
/// NOTE: this is the digest of the ACTUAL deterministic chunk stream built by
/// [`chunk_payload`]; the engine verifies staged bytes against whatever BEGIN
/// declared, so tests must declare the real thing.
fn transfer_image_sha(img_len: u32, chunk_len: u8) -> [u8; 32] {
    use sha2::Digest;
    let cl = chunk_len as usize;
    let count = (img_len as usize).div_ceil(cl);
    let mut hasher = sha2::Sha256::new();
    for seq in 0..count {
        let len = if seq == count - 1 {
            img_len as usize - seq * cl
        } else {
            cl
        };
        hasher.update(chunk_payload(seq, len).as_slice());
    }
    hasher.finalize().into()
}

/// Builds one deterministic chunk payload of exactly `len` bytes.
fn chunk_payload(index: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((index * 31 + i) % 251) as u8).collect()
}

/// Drives a complete happy-path transfer; asserts per-chunk cumulative ACKs
/// and returns the FINALIZE outcome.
fn run_full_transfer(rig: &mut Rig, version: u32, img_len: u32, chunk_len: u8) -> RxOutcome {
    let cl = rig.open_session(version, img_len, chunk_len) as usize;
    let count = (img_len as usize).div_ceil(cl);
    for seq in 0..count {
        // Only the last chunk may be short per the declared geometry.
        let expected = if seq == count - 1 {
            img_len as usize - seq * cl
        } else {
            cl
        };
        let data = chunk_payload(seq, expected);
        let out = rig.send(
            OtaCommand::Chunk(ChunkFrame {
                seq: seq as u16,
                data: &data,
            }),
            200 + seq as u32,
        );
        assert_eq!(
            out,
            RxOutcome::Respond(Reply::ChunkAck {
                next_seq: seq as u16 + 1
            }),
            "cumulative ACK must advance per accepted chunk"
        );
    }
    rig.send(OtaCommand::Finalize, 999)
}

// ---------------------------------------------------------------------------
// Happy path and trust chain
// ---------------------------------------------------------------------------

#[test]
fn happy_path_stages_image_and_marks_bootable() {
    const VERSION: u32 = 7;
    const IMG_LEN: u32 = 300; // 64+64+64+64+44: exercises a short last chunk.
    let mut rig = Rig::new(1024);

    let out = run_full_transfer(&mut rig, VERSION, IMG_LEN, CHUNK_LEN_MIN as u8);
    assert_eq!(out, RxOutcome::Respond(Reply::Final(FinalResult::Ok)));
    assert_eq!(rig.rx.state(), PeerState::PendingReboot);
    assert_eq!(rig.rx.session_geometry(), Some((VERSION, IMG_LEN)));

    // Staged bytes equal what was sent, position by position.
    let cl = CHUNK_LEN_MIN;
    for seq in 0..((IMG_LEN as usize).div_ceil(cl)) {
        let len = if seq == (IMG_LEN as usize).div_ceil(cl) - 1 {
            IMG_LEN as usize - seq * cl
        } else {
            cl
        };
        assert_eq!(
            rig.storage.slice(seq * cl, len),
            chunk_payload(seq, len).as_slice(),
            "staged image bytes diverge at chunk {seq}"
        );
    }

    // Bootable marker written exactly once, parseable, valid.
    let mut raw = [0u8; TRAILER_LEN];
    rig.storage.read(1024, &mut raw).expect("trailer read");
    let record = TrailerRecord::parse(&raw).expect("trailer parses");
    assert_eq!(record.status, TrailerStatus::StagedValid);
    assert_eq!(record.img_version, VERSION);
    assert_eq!(record.img_len, IMG_LEN);
    assert_eq!(
        record.sha256,
        transfer_image_sha(IMG_LEN, CHUNK_LEN_MIN as u8)
    );
    assert_eq!(record.attempts, 0);

    // REBOOT is accepted exactly in this state.
    assert_eq!(
        rig.send(OtaCommand::Reboot { delay_ms: 500 }, 1000),
        RxOutcome::RebootAfterMs(500)
    );
}

#[test]
fn refinalize_after_success_is_idempotent_without_storage_writes() {
    let mut rig = Rig::new(1024);
    let out = run_full_transfer(&mut rig, 7, 128, CHUNK_LEN_MIN as u8);
    assert_eq!(out, RxOutcome::Respond(Reply::Final(FinalResult::Ok)));

    let (erases_before, writes_before) = (rig.storage.erase_calls, rig.storage.write_calls);
    // Lost final ACK: sender retries FINALIZE.
    assert_eq!(
        rig.send(OtaCommand::Finalize, 1200),
        RxOutcome::Respond(Reply::Final(FinalResult::Ok))
    );
    assert_eq!(rig.storage.erase_calls, erases_before);
    assert_eq!(rig.storage.write_calls, writes_before);
}

// ---------------------------------------------------------------------------
// BEGIN handling
// ---------------------------------------------------------------------------

#[test]
fn duplicate_identical_begin_is_idempotent_and_keeps_progress() {
    let mut rig = Rig::new(1024);
    let begin = rig.signed_begin(7, 192, CHUNK_LEN_MIN as u8);

    assert!(matches!(
        rig.send(OtaCommand::Begin(begin.clone()), 100),
        RxOutcome::Respond(Reply::Ready { .. })
    ));
    let d0 = chunk_payload(0, CHUNK_LEN_MIN);
    rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }), 110);
    assert_eq!(rig.rx.next_seq(), Some(1));

    // Retransmitted identical BEGIN: progress kept.
    assert!(matches!(
        rig.send(OtaCommand::Begin(begin), 120),
        RxOutcome::Respond(Reply::Ready { .. })
    ));
    assert_eq!(rig.rx.next_seq(), Some(1));
}

#[test]
fn different_begin_is_rejected_until_explicit_abort() {
    let mut rig = Rig::new(1024);
    let first = rig.signed_begin(7, 192, CHUNK_LEN_MIN as u8);
    rig.send(OtaCommand::Begin(first), 100);

    let second = rig.signed_begin(8, 128, 128);
    assert_eq!(
        rig.send(OtaCommand::Begin(second), 110),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );
    // Original session untouched.
    assert_eq!(rig.rx.session_geometry(), Some((7, 192)));

    // Explicit ABORT clears it; the new transfer can start afterwards.
    assert_eq!(rig.send(OtaCommand::Abort, 120), RxOutcome::Silent);
    assert_eq!(rig.rx.state(), PeerState::Idle);
    let fresh = rig.signed_begin(8, 128, 128);
    assert!(matches!(
        rig.send(OtaCommand::Begin(fresh), 130),
        RxOutcome::Respond(Reply::Ready { .. })
    ));
}

#[test]
fn size_gates_reject_over_capacity_and_chunk_count_overflow() {
    // Over staging capacity (Rig geometry keeps the trailer block disjoint).
    let mut rig = Rig::new(1024);
    let over = rig.signed_begin(1, 1025, CHUNK_LEN_MIN as u8);
    assert_eq!(
        rig.send(OtaCommand::Begin(over), 100),
        RxOutcome::Respond(Reply::Final(FinalResult::SizeRejected))
    );
    assert_eq!(rig.rx.state(), PeerState::Idle);

    // Zero-length image.
    let zero = rig.signed_begin(1, 0, CHUNK_LEN_MIN as u8);
    assert_eq!(
        rig.send(OtaCommand::Begin(zero), 101),
        RxOutcome::Respond(Reply::Final(FinalResult::SizeRejected))
    );

    // Chunk-count overflow: seq is u16 on the wire, so 65 537 chunks cannot
    // be addressed. Coarse granularity keeps the erase-block bound satisfied
    // so THIS gate is the one that fires. No storage access happens during
    // BEGIN beyond reading the declared granularity.
    let mut tiny_storage = FaultyStorage::with_granularity(TRAILER_SPAN, 16_384);
    let mut se = MockSecureElement::new(factory_pub());
    // Geometry: cap below the aligned trailer block at 4_210_560.
    let mut rx = OtaReceiver::new(
        factory_pub(),
        OtaReceiverConfig {
            product_id: PRODUCT_ID,
            hardware_profile_id: HARDWARE_PROFILE,
            staging_cap: 4_200_000,
            trailer_offset: 4_210_688,
            min_acceptable_version: 0,
            idle_timeout_secs: 30,
            absolute_session_timeout_secs: 3600,
        },
    );
    let huge = BeginFrame {
        img_version: 1,
        // 65 537 chunks: beyond the u16 wire sequence space.
        img_len: (CHUNK_LEN_MIN as u32) * 65_537,
        chunk_len: CHUNK_LEN_MIN as u8,
        img_sha256: [0u8; 32],
        manifest_sig: [0u8; 64],
    };
    let out = rx
        .on_command(&mut tiny_storage, &mut se, OtaCommand::Begin(huge), 1)
        .expect("BEGIN never touches storage");
    assert_eq!(
        out,
        RxOutcome::Respond(Reply::Final(FinalResult::SizeRejected))
    );
}

// ---------------------------------------------------------------------------
// Storage-geometry integration gates (audit hardening)
// ---------------------------------------------------------------------------

#[test]
fn zero_granularity_is_an_integration_error_never_a_panic() {
    let mut zero_g = FaultyStorage::with_granularity(2048, 0);
    let mut se = MockSecureElement::new(factory_pub());
    let mut rx = OtaReceiver::new(factory_pub(), rig_config(1024));
    let begin = BeginFrame {
        img_version: 1,
        img_len: 128,
        chunk_len: CHUNK_LEN_MIN as u8,
        img_sha256: [0u8; 32],
        manifest_sig: [0u8; 64],
    };
    let err = rx
        .on_command(&mut zero_g, &mut se, OtaCommand::Begin(begin), 1)
        .unwrap_err();
    assert_eq!(
        err,
        OtaError::InvalidParams {
            reason: "storage erase_granularity must be non-zero"
        }
    );
    assert_eq!(rx.state(), PeerState::Idle, "no session may open");
}

#[test]
fn trailer_block_overlapping_the_image_window_is_rejected_at_begin() {
    // staging_cap NOT aligned to the 256 B granularity: a trailer placed
    // right after it shares the preceding erase block with verified image
    // bytes. BEGIN must fail-closed before any flash access.
    let mut storage = FaultyStorage::new(4096);
    let mut se = MockSecureElement::new(factory_pub());
    let mut rx = OtaReceiver::new(
        factory_pub(),
        OtaReceiverConfig {
            product_id: PRODUCT_ID,
            hardware_profile_id: HARDWARE_PROFILE,
            staging_cap: 1000,
            trailer_offset: 1000,
            min_acceptable_version: 0,
            idle_timeout_secs: 30,
            absolute_session_timeout_secs: 3600,
        },
    );
    let begin = BeginFrame {
        img_version: 1,
        img_len: 512,
        chunk_len: CHUNK_LEN_MIN as u8,
        img_sha256: [0u8; 32],
        manifest_sig: [0u8; 64],
    };
    let err = rx
        .on_command(&mut storage, &mut se, OtaCommand::Begin(begin.clone()), 1)
        .unwrap_err();
    assert!(matches!(err, OtaError::InvalidParams { .. }));
    assert_eq!(rx.state(), PeerState::Idle);

    // A coherent layout (aligned trailer block after the window) opens fine.
    let mut ok_rx = OtaReceiver::new(factory_pub(), rig_config(1024));
    assert!(
        ok_rx
            .on_command(&mut storage, &mut se, OtaCommand::Begin(begin.clone()), 2)
            .is_ok()
    );
}

#[test]
fn trailer_range_end_overflow_is_rejected_at_begin() {
    // Trailer block aligned at the very top of the address space: the
    // ERASED INTERVAL end would exceed u32::MAX even though the start is a
    // valid multiple of the granularity. BEGIN must reject with the normal
    // integration error, never panic and never touch storage.
    let mut tiny = FaultyStorage::with_granularity(256, 4096);
    let mut se = MockSecureElement::new(factory_pub());
    // staging_cap small; trailer offset aligned but its erase span crosses
    // the top of the 32-bit space (0xFFFF_F000 + one 4096 B row overflows).
    let mut rx = OtaReceiver::new(
        factory_pub(),
        OtaReceiverConfig {
            product_id: PRODUCT_ID,
            hardware_profile_id: HARDWARE_PROFILE,
            staging_cap: 256,
            trailer_offset: 0xFFFF_F000,
            min_acceptable_version: 0,
            idle_timeout_secs: 30,
            absolute_session_timeout_secs: 3600,
        },
    );
    let begin = BeginFrame {
        img_version: 1,
        img_len: 128,
        chunk_len: CHUNK_LEN_MIN as u8,
        img_sha256: [0u8; 32],
        manifest_sig: [0u8; 64],
    };
    let err = rx
        .on_command(&mut tiny, &mut se, OtaCommand::Begin(begin), 1)
        .unwrap_err();
    assert!(matches!(err, OtaError::InvalidParams { .. }));
}

// ---------------------------------------------------------------------------
// CHUNK handling
// ---------------------------------------------------------------------------

#[test]
fn wrong_seq_is_answered_with_the_current_cumulative_ack() {
    let mut rig = Rig::new(1024);
    rig.open_session(7, 192, CHUNK_LEN_MIN as u8);

    // Far-ahead and behind frames are both rejected by the cumulative ACK
    // of the CURRENT position (0), without advancing progress.
    for bogus in [5u16, 3u16] {
        let d = chunk_payload(bogus as usize, CHUNK_LEN_MIN);
        assert_eq!(
            rig.send(
                OtaCommand::Chunk(ChunkFrame {
                    seq: bogus,
                    data: &d
                }),
                105
            ),
            RxOutcome::Respond(Reply::ChunkAck { next_seq: 0 })
        );
    }
    assert_eq!(rig.rx.next_seq(), Some(0));

    // A duplicate delivery of an already-accepted chunk (lost-ACK case) is
    // answered with the current position, not with an error.
    let d0 = chunk_payload(0, CHUNK_LEN_MIN);
    rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }), 106);
    assert_eq!(
        rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }), 107,),
        RxOutcome::Respond(Reply::ChunkAck { next_seq: 1 })
    );
}

#[test]
fn oversized_position_data_tears_down_with_size_rejected() {
    let mut rig = Rig::new(1024);
    rig.open_session(7, 100, CHUNK_LEN_MIN as u8); // last chunk is 36 B

    // Position 0 expects exactly 64 bytes; 65 violates the geometry.
    let bad = chunk_payload(0, CHUNK_LEN_MIN + 1);
    assert_eq!(
        rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &bad }), 105),
        RxOutcome::Respond(Reply::Final(FinalResult::SizeRejected))
    );
    assert_eq!(rig.rx.state(), PeerState::Idle);
}

#[test]
fn chunk_storage_fault_is_retryable_verbatim() {
    let mut rig = Rig::new(1024);
    rig.open_session(7, 192, CHUNK_LEN_MIN as u8);
    let d0 = chunk_payload(0, CHUNK_LEN_MIN);

    rig.storage.fail_write = true;
    let err = rig
        .rx
        .on_command(
            &mut rig.storage,
            &mut rig.se,
            OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }),
            105,
        )
        .unwrap_err();
    assert_eq!(err, OtaError::Storage);
    assert_eq!(rig.rx.next_seq(), Some(0), "progress must not advance");

    // Verbatim retry after the fault clears succeeds.
    rig.storage.fail_write = false;
    assert_eq!(
        rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }), 106),
        RxOutcome::Respond(Reply::ChunkAck { next_seq: 1 })
    );
}

#[test]
fn erase_fault_retries_verbatim_and_never_reerases_committed_blocks() {
    // Geometry: 96 B chunks over 128 B rows -> chunk 1 spans blocks 0..=1,
    // sharing block 0 with chunk 0's tail. A failure erasing block 1 must
    // leave block 0 committed (re-erasing it would destroy chunk 0 bytes)
    // while block 1 itself is retried on the verbatim resend.
    let mut rig = Rig::new(1024);
    rig.storage = FaultyStorage::with_granularity(1024 + TRAILER_SPAN, 128);
    let cl = rig.open_session(7, 192, 96) as usize;
    assert_eq!(cl, 96);

    let d0 = chunk_payload(0, 96);
    rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }), 110);
    let d1 = chunk_payload(1, 96);

    // First attempt at chunk 1: block 0 skipped (committed), block 1 erase
    // fails -> Err(Storage), no progress.
    rig.storage.fail_erase = true;
    let err = rig
        .rx
        .on_command(
            &mut rig.storage,
            &mut rig.se,
            OtaCommand::Chunk(ChunkFrame { seq: 1, data: &d1 }),
            111,
        )
        .unwrap_err();
    assert_eq!(err, OtaError::Storage);
    assert_eq!(rig.rx.next_seq(), Some(1));
    let erases_after_failure = rig.storage.erase_calls;

    // Verbatim retry: block 1 erased AGAIN (it never committed), then the
    // write lands. Block 0 must NOT be re-erased (count grows by exactly 1).
    rig.storage.fail_erase = false;
    assert_eq!(
        rig.send(OtaCommand::Chunk(ChunkFrame { seq: 1, data: &d1 }), 112),
        RxOutcome::Respond(Reply::ChunkAck { next_seq: 2 })
    );
    assert_eq!(rig.storage.erase_calls, erases_after_failure + 1);
    // Chunk 0's staged bytes survived the whole episode untouched.
    assert_eq!(rig.storage.slice(0, 96), d0.as_slice());
}

#[test]
fn erase_alignment_contract_holds_across_a_transfer() {
    // Granularity smaller than the chunk forces multi-block writes; the mock
    // asserts alignment on every call. With erase-once bookkeeping each
    // distinct block is erased exactly once: 300 B over 128 B rows touches
    // blocks 0..=2 (three erases) plus one trailer block.
    let mut rig = Rig::new(512);
    rig.storage = FaultyStorage::with_granularity(512 + TRAILER_SPAN, 128);
    run_full_transfer(&mut rig, 7, 300, CHUNK_LEN_MIN as u8);
    assert_eq!(rig.storage.erase_calls, 4);
}

// ---------------------------------------------------------------------------
// FINALIZE handling and the trust chain
// ---------------------------------------------------------------------------

#[test]
fn early_finalize_keeps_the_session_open() {
    let mut rig = Rig::new(1024);
    rig.open_session(7, 192, CHUNK_LEN_MIN as u8);
    assert_eq!(
        rig.send(OtaCommand::Finalize, 150),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );
    assert_eq!(rig.rx.state(), PeerState::Streaming);
    assert_eq!(rig.rx.next_seq(), Some(0));
}

#[test]
fn hash_mismatch_tears_down_to_idle() {
    let mut rig = Rig::new(1024);
    let cl = rig.open_session(7, 128, CHUNK_LEN_MIN as u8) as usize;

    // Corrupt the second chunk's content relative to the signed digest.
    let good = chunk_payload(0, cl);
    rig.send(
        OtaCommand::Chunk(ChunkFrame {
            seq: 0,
            data: &good,
        }),
        110,
    );
    let mut corrupt = chunk_payload(1, cl);
    corrupt[3] ^= 0xFF;
    rig.send(
        OtaCommand::Chunk(ChunkFrame {
            seq: 1,
            data: &corrupt,
        }),
        111,
    );

    assert_eq!(
        rig.send(OtaCommand::Finalize, 150),
        RxOutcome::Respond(Reply::Final(FinalResult::HashMismatch))
    );
    assert_eq!(rig.rx.state(), PeerState::Idle);
}

#[test]
fn begin_signature_failure_never_touches_storage() {
    let mut rig = Rig::new(1024);
    let begin = rig.signed_begin(7, 128, CHUNK_LEN_MIN as u8);

    // Flip the SE into reject mode BEFORE the transfer opens: transport-
    // level failure collapses into SigRejected by contract, and the session
    // must not open at all — zero erase/write operations on staging flash.
    rig.se.reject_signatures();
    assert_eq!(
        rig.send(OtaCommand::Begin(begin), 100),
        RxOutcome::Respond(Reply::Final(FinalResult::SigRejected))
    );
    assert_eq!(rig.rx.state(), PeerState::Idle);
    assert_eq!(rig.storage.erase_calls, 0, "no erase before authentication");
    assert_eq!(rig.storage.write_calls, 0, "no write before authentication");

    // A corrupted signature (bad tag for this message) is refused equally.
    let mut forged = rig.signed_begin(8, 128, CHUNK_LEN_MIN as u8);
    forged.manifest_sig[0] ^= 0xFF;
    assert_eq!(
        rig.send(OtaCommand::Begin(forged), 110),
        RxOutcome::Respond(Reply::Final(FinalResult::SigRejected))
    );
    assert_eq!(rig.storage.erase_calls, 0);
}

// ---------------------------------------------------------------------------
// Anti-rollback policy (security hardening)
// ---------------------------------------------------------------------------

#[test]
fn rollback_older_version_rejected_before_any_flash_access() {
    let mut storage = FaultyStorage::new(2048);
    let mut se = MockSecureElement::new(factory_pub());
    let mut rx = OtaReceiver::new(
        factory_pub(),
        OtaReceiverConfig {
            product_id: PRODUCT_ID,
            hardware_profile_id: HARDWARE_PROFILE,
            staging_cap: 1024,
            trailer_offset: 1024,
            min_acceptable_version: 10,
            idle_timeout_secs: 30,
            absolute_session_timeout_secs: 3600,
        },
    );

    let send_begin = |se: &mut MockSecureElement, version: u32| {
        let sha = transfer_image_sha(version, 128);
        let msg = manifest_digest_input(
            PRODUCT_ID,
            HARDWARE_PROFILE,
            version,
            128,
            CHUNK_LEN_MIN as u8,
            &sha,
        );
        let sig = se.sign_ecdsa(&msg).expect("mock signing");
        BeginFrame {
            img_version: version,
            img_len: 128,
            chunk_len: CHUNK_LEN_MIN as u8,
            img_sha256: sha,
            manifest_sig: sig,
        }
    };

    // Strictly older signed image: VersionRejected, nothing stored.
    let old = send_begin(&mut se, 9);
    assert_eq!(
        rx.on_command(&mut storage, &mut se, OtaCommand::Begin(old), 100)
            .expect("no fault"),
        RxOutcome::Respond(Reply::Final(FinalResult::VersionRejected))
    );
    assert_eq!(rx.state(), PeerState::Idle);
    assert_eq!((storage.erase_calls, storage.write_calls), (0, 0));

    // Equal version: allowed (re-flash repair of the running release).
    let same = send_begin(&mut se, 10);
    assert!(matches!(
        rx.on_command(&mut storage, &mut se, OtaCommand::Begin(same), 101)
            .expect("no fault"),
        RxOutcome::Respond(Reply::Ready { .. })
    ));
}

// ---------------------------------------------------------------------------
// Absolute session lifetime (anti-pinning defense)
// ---------------------------------------------------------------------------

#[test]
fn absolute_lifetime_expires_even_with_fresh_identical_begins() {
    let mut rig = Rig::new(1024);
    // Tight ceiling for the scenario.
    rig.rx = OtaReceiver::new(
        factory_pub(),
        OtaReceiverConfig {
            product_id: PRODUCT_ID,
            hardware_profile_id: HARDWARE_PROFILE,
            staging_cap: 1024,
            trailer_offset: 1024,
            min_acceptable_version: 0,
            idle_timeout_secs: 30,
            absolute_session_timeout_secs: 50,
        },
    );
    let begin = rig.signed_begin(7, 192, CHUNK_LEN_MIN as u8);

    // Open at t=100 and keep the IDLE timer fresh with identical re-BEGINs
    // every 20 s (a hostile peer's pinning pattern).
    assert!(matches!(
        rig.send(OtaCommand::Begin(begin.clone()), 100),
        RxOutcome::Respond(Reply::Ready { .. })
    ));
    for t in [120usize, 140] {
        assert!(matches!(
            rig.send(OtaCommand::Begin(begin.clone()), t as u32),
            RxOutcome::Respond(Reply::Ready { .. })
        ));
    }

    // At t=151 the session is only 21 s "fresh" but 51 s OLD: the absolute
    // ceiling wins and tears it down.
    assert_eq!(rig.rx.tick(151), TickOutcome::ExpiredAbsoluteLifetime);
    assert_eq!(rig.rx.state(), PeerState::Idle);
}

#[test]
fn trailer_storage_fault_leaves_finalize_retryable() {
    let mut rig = Rig::new(1024);
    let cl = rig.open_session(7, 128, CHUNK_LEN_MIN as u8) as usize;
    for seq in 0..2 {
        let d = chunk_payload(seq, if seq == 1 { 128 - cl } else { cl });
        rig.send(
            OtaCommand::Chunk(ChunkFrame {
                seq: seq as u16,
                data: &d,
            }),
            110 + seq as u32,
        );
    }

    rig.storage.fail_erase = true; // trailer marker erase fails first
    let err = rig
        .rx
        .on_command(&mut rig.storage, &mut rig.se, OtaCommand::Finalize, 150)
        .unwrap_err();
    assert_eq!(err, OtaError::Storage);
    assert_eq!(rig.rx.state(), PeerState::Streaming, "session stays open");

    rig.storage.fail_erase = false;
    assert_eq!(
        rig.send(OtaCommand::Finalize, 160),
        RxOutcome::Respond(Reply::Final(FinalResult::Ok))
    );
    assert_eq!(rig.rx.state(), PeerState::PendingReboot);
}

// ---------------------------------------------------------------------------
// State-machine edges, timeout policy, STATUS projection
// ---------------------------------------------------------------------------

#[test]
fn wrong_state_commands_answer_bad_state() {
    let mut rig = Rig::new(1024);

    // In Idle: chunks, finalize, and reboot are all invalid.
    let d = chunk_payload(0, CHUNK_LEN_MIN);
    assert_eq!(
        rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d }), 100),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );
    assert_eq!(
        rig.send(OtaCommand::Finalize, 101),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );
    assert_eq!(
        rig.send(OtaCommand::Reboot { delay_ms: 1 }, 102),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );

    // In Streaming: reboot is invalid.
    rig.open_session(7, 192, CHUNK_LEN_MIN as u8);
    assert_eq!(
        rig.send(OtaCommand::Reboot { delay_ms: 1 }, 103),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );

    // Reach PendingReboot via a COMPLETE transfer (geometry 3 x 64 B).
    assert_eq!(rig.send(OtaCommand::Abort, 104), RxOutcome::Silent);
    let cl = rig.open_session(7, 192, CHUNK_LEN_MIN as u8) as usize;
    for seq in 0..3 {
        let d = chunk_payload(seq, cl);
        rig.send(
            OtaCommand::Chunk(ChunkFrame {
                seq: seq as u16,
                data: &d,
            }),
            110 + seq as u32,
        );
    }
    rig.send(OtaCommand::Finalize, 150);
    assert_eq!(rig.rx.state(), PeerState::PendingReboot);
    let other = rig.signed_begin(9, 64, CHUNK_LEN_MIN as u8);
    assert_eq!(
        rig.send(OtaCommand::Begin(other), 160),
        RxOutcome::Respond(Reply::Final(FinalResult::BadState))
    );
}

#[test]
fn idle_timeout_expires_streaming_sessions_only() {
    let mut rig = Rig::new(1024);
    rig.open_session(7, 192, CHUNK_LEN_MIN as u8);

    assert_eq!(rig.rx.tick(129), TickOutcome::Continue); // 29 s < 30 s
    assert_eq!(rig.rx.tick(130), TickOutcome::ExpiredIdleTimeout);
    assert_eq!(rig.rx.state(), PeerState::Idle);
    // A verified pending-reboot session never expires here.
    assert_eq!(rig.rx.tick(10_000), TickOutcome::Continue);
}

#[test]
fn status_projection_reflects_each_state() {
    let mut rig = Rig::new(1024);
    use crate::core::ota::wire::StatusFrame;

    // Idle projection: zeros.
    assert_eq!(
        rig.rx.status(),
        Reply::Status(StatusFrame {
            state: PeerState::Idle,
            next_seq: 0,
            img_version: 0,
            img_len: 0,
        })
    );

    // Streaming projection: live progress.
    rig.open_session(7, 192, CHUNK_LEN_MIN as u8);
    let d0 = chunk_payload(0, CHUNK_LEN_MIN);
    rig.send(OtaCommand::Chunk(ChunkFrame { seq: 0, data: &d0 }), 100);
    assert_eq!(
        rig.rx.status(),
        Reply::Status(StatusFrame {
            state: PeerState::Streaming,
            next_seq: 1,
            img_version: 7,
            img_len: 192,
        })
    );

    // PendingReboot projection: total-chunks sentinel (geometry 3 x 64 B).
    let cl = CHUNK_LEN_MIN;
    for seq in 1..3 {
        let d = chunk_payload(seq, cl);
        rig.send(
            OtaCommand::Chunk(ChunkFrame {
                seq: seq as u16,
                data: &d,
            }),
            102 + seq as u32,
        );
    }
    rig.send(OtaCommand::Finalize, 104);
    assert_eq!(
        rig.rx.status(),
        Reply::Status(StatusFrame {
            state: PeerState::PendingReboot,
            next_seq: 3,
            img_version: 7,
            img_len: 192,
        })
    );
}

// ---------------------------------------------------------------------------
// TrailerRecord serialization contract
// ---------------------------------------------------------------------------

#[test]
fn trailer_roundtrip_and_corruption_matrix() {
    let record = TrailerRecord::staged_valid(0x0102_0304, 0x0506_0708, [0x11; 32]);
    let mut raw = [0u8; TRAILER_LEN];
    assert_eq!(record.serialize(&mut raw).expect("fits"), TRAILER_LEN);
    assert_eq!(TrailerRecord::parse(&raw), Ok(record.clone()));

    // Buffer too small reports the exact requirement.
    let mut tiny = [0u8; TRAILER_LEN - 1];
    assert_eq!(
        record.serialize(&mut tiny),
        Err(OtaError::BufferTooSmall {
            needed: TRAILER_LEN,
            available: TRAILER_LEN - 1
        })
    );

    // Wrong magic.
    let mut bad_magic = raw;
    bad_magic[0] ^= 0xFF;
    assert!(matches!(
        TrailerRecord::parse(&bad_magic),
        Err(OtaError::Malformed { .. })
    ));

    // Unknown status byte.
    let mut bad_status = raw;
    bad_status[45] = 0x02;
    assert!(matches!(
        TrailerRecord::parse(&bad_status),
        Err(OtaError::Malformed { .. })
    ));

    // Wrong length.
    assert!(matches!(
        TrailerRecord::parse(&raw[..TRAILER_LEN - 1]),
        Err(OtaError::Malformed { .. })
    ));
}

/// Cross-repo conformance value: future bootloaders duplicating the layout
/// MUST accept exactly these bytes for these fields.
#[test]
fn trailer_conformance_vector() {
    let mut raw = [0u8; TRAILER_LEN];
    TrailerRecord::staged_valid(1, 512, [0x11; 32])
        .serialize(&mut raw)
        .unwrap();
    let expected: Vec<u8> = {
        let mut v = vec![0x53, 0x4F, 0x54, 0x41];
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&512u32.to_le_bytes());
        v.extend_from_slice(&[0x11; 32]);
        v.push(0); // attempts
        v.push(0x01); // StagedValid
        v
    };
    assert_eq!(raw.to_vec(), expected);
}

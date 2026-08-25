#![cfg(all(feature = "ota", feature = "sensor", feature = "gateway"))]
//! Cross-engine interop proof: drives [`OtaSender`] against [`OtaReceiver`]
//! through the real wire codec over a fault-injectable in-memory link,
//! proving the two independent engines converge on identical staged bytes —
//! including under frame loss.

use crate::core::ota::error::OtaError;
use crate::core::ota::image::OtaImageSource;
use crate::core::ota::receiver::{OtaReceiver, OtaReceiverConfig, Reply, RxOutcome};
use crate::core::ota::sender::{OtaSender, SenderAction, TransferEnd, TxFrame};
use crate::core::ota::storage::OtaStorage;
use crate::core::ota::trailer::{TRAILER_LEN, TrailerRecord, TrailerStatus};
use crate::core::ota::wire::{
    BeginFrame, CHUNK_LEN_MIN, encode_ack_chunk, encode_ack_final, encode_ack_ready, encode_begin,
    encode_chunk, encode_finalize, encode_status, parse_command,
};
use crate::core::test_support::MockSecureElement;
use crate::core::traits::{SecureElement, StaticPublicKey};
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// RAM-backed storage with contract assertions (standalone copy so test
/// files stay self-contained).
struct RamStorage {
    mem: Vec<u8>,
    granularity: u32,
}

impl RamStorage {
    fn new(cap: u32) -> Self {
        Self {
            mem: vec![0xFF; cap as usize],
            granularity: 256,
        }
    }

    fn slice(&self, offset: usize, len: usize) -> &[u8] {
        &self.mem[offset..offset + len]
    }
}

impl OtaStorage for RamStorage {
    fn erase_granularity(&self) -> u32 {
        self.granularity
    }

    fn erase_range(&mut self, offset: u32, len: u32) -> Result<(), OtaError> {
        assert_eq!(offset % self.granularity, 0);
        assert_eq!(len % self.granularity, 0);
        let end = offset + len;
        assert!(end <= self.mem.len() as u32);
        for b in &mut self.mem[offset as usize..end as usize] {
            *b = 0xFF;
        }
        Ok(())
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), OtaError> {
        let end = offset as usize + data.len();
        assert!(end <= self.mem.len());
        self.mem[offset as usize..end].copy_from_slice(data);
        Ok(())
    }
}

impl RamStorage {
    /// Inherent readback for assertions (not part of the sink trait).
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), OtaError> {
        let end = offset as usize + buf.len();
        assert!(end <= self.mem.len());
        buf.copy_from_slice(&self.mem[offset as usize..end]);
        Ok(())
    }
}

/// Deterministic image source mirroring the sender tests' pattern.
struct MemImage {
    data: Vec<u8>,
}

impl MemImage {
    fn new(len: usize) -> Self {
        Self {
            data: (0..len).map(|i| ((i * 13 + 5) % 241) as u8).collect(),
        }
    }
}

impl OtaImageSource for MemImage {
    fn len(&self) -> u32 {
        self.data.len() as u32
    }

    fn read_at(&self, offset: u32, out: &mut [u8]) -> Result<(), OtaError> {
        let end = offset as usize + out.len();
        if end > self.data.len() {
            return Err(OtaError::Storage);
        }
        out.copy_from_slice(&self.data[offset as usize..end]);
        Ok(())
    }
}

/// One-way frame pipe with optional deterministic loss.
struct Link {
    queue: VecDeque<Vec<u8>>,
    /// When set to N (> 0), every Nth enqueued frame is silently dropped.
    drop_every_nth: Option<usize>,
    enqueued: usize,
}

impl Link {
    fn new(drop_every_nth: Option<usize>) -> Self {
        Self {
            queue: VecDeque::new(),
            drop_every_nth,
            enqueued: 0,
        }
    }

    fn enqueue(&mut self, frame: &[u8]) {
        self.enqueued += 1;
        if let Some(n) = self.drop_every_nth {
            if n > 0 && self.enqueued % n == 0 {
                return; // silently lost over the air
            }
        }
        self.queue.push_back(frame.to_vec());
    }

    fn pop(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }
}

/// Factory root key shared by both engine halves.
fn factory_pub() -> StaticPublicKey {
    let mut key = [0x02u8; 33];
    key[1] = 0x5E;
    key
}

/// Encodes one reply onto the wire format.
fn encode_reply(reply: &Reply, out: &mut [u8]) -> usize {
    match reply {
        Reply::Ready { chunk_len } => encode_ack_ready(*chunk_len, out),
        Reply::ChunkAck { next_seq } => encode_ack_chunk(*next_seq, out),
        Reply::Final(result) => encode_ack_final(*result, out),
        Reply::Status(status) => encode_status(status, out),
    }
    .expect("reply fits scratch buffer")
}

// ---------------------------------------------------------------------------
// The interop driver
// ---------------------------------------------------------------------------

/// Runs a complete transfer of a 300 B image through the real codec.
///
/// Returns `(staged_bytes, trailer)` for scenario assertions. `drop_every`
/// injects deterministic loss; the retry machinery must converge anyway.
fn run_interop(drop_every_nth: Option<usize>) -> (Vec<u8>, TrailerRecord) {
    const IMG_LEN: usize = 300;
    const STAGING_CAP: u32 = 1024;
    const TRAILER_OFFSET: u32 = STAGING_CAP;

    let mut se = MockSecureElement::new(factory_pub());
    let mut img = MemImage::new(IMG_LEN);

    // Manifest signed by the SAME secure element the receiver trusts.
    let cl = CHUNK_LEN_MIN as u8;
    let sha = {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(&img.data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    };
    const PRODUCT_ID: u16 = 0x0001;
    let msg =
        crate::core::ota::wire::manifest_digest_input(PRODUCT_ID, 11, IMG_LEN as u32, cl, &sha);
    let sig = se.sign_ecdsa(&msg).expect("mock signing");
    let begin = BeginFrame {
        img_version: 11,
        img_len: IMG_LEN as u32,
        chunk_len: cl,
        img_sha256: sha,
        manifest_sig: sig,
    };

    let mut tx = OtaSender::new(6, 2);
    let mut rx = OtaReceiver::new(
        factory_pub(),
        OtaReceiverConfig {
            product_id: PRODUCT_ID,
            staging_cap: STAGING_CAP,
            trailer_offset: TRAILER_OFFSET,
            min_acceptable_version: 0,
            idle_timeout_secs: 30,
            absolute_session_timeout_secs: 3600,
        },
    );
    let mut storage = RamStorage::new(STAGING_CAP + 256);
    let mut uplink = Link::new(drop_every_nth); // tx -> rx
    let mut downlink = Link::new(None); // rx -> tx

    let mut now: u32 = 0;
    let mut scratch = [0u8; 256];

    // Deterministic event loop: drain links, feed engines, advance time on
    // silence so deadlines fire and resends happen. Hard iteration bound
    // guards against livelock regressions.
    let mut pending: Option<SenderAction<'_>> =
        Some(tx.start(&mut img, begin, now).expect("start"));
    let mut completed: Option<TransferEnd> = None;

    for _ in 0..2000 {
        // Deliver everything currently queued upward (receiver side).
        while let Some(frame) = uplink.pop() {
            now += 1;
            if let Ok(cmd) = parse_command(&frame) {
                match rx
                    .on_command(&mut storage, &mut se, cmd, now)
                    .expect("rx storage ok")
                {
                    RxOutcome::Respond(reply) => {
                        let n = encode_reply(&reply, &mut scratch);
                        downlink.enqueue(&scratch[..n]);
                    }
                    RxOutcome::Silent | RxOutcome::RebootAfterMs(_) => {}
                }
            }
        }

        // Deliver replies downward (sender side).
        while let Some(frame) = downlink.pop() {
            now += 1;
            if let Ok(cmd) = parse_command(&frame) {
                pending = tx.on_reply(&mut img, cmd, now).expect("tx ok");
            }
        }

        match pending.take() {
            Some(SenderAction::Transmit { frame, .. }) => {
                let n = match frame {
                    TxFrame::Begin(b) => encode_begin(b, &mut scratch).expect("fits"),
                    TxFrame::Chunk { seq, data } => {
                        encode_chunk(seq, data, &mut scratch).expect("fits")
                    }
                    TxFrame::Finalize => encode_finalize(&mut scratch).expect("fits"),
                    TxFrame::Reboot { .. } | TxFrame::Abort => 0,
                };
                if n > 0 {
                    uplink.enqueue(&scratch[..n]);
                }
            }
            Some(SenderAction::TransmitFinal { .. }) => {}
            Some(SenderAction::End(end)) => {
                completed = Some(end);
                break;
            }
            None => {
                // Silence on both pipes: jump past the deadline to exercise
                // retransmit paths on whichever side is waiting.
                now += 3;
                pending = tx.poll(now).expect("tx ok");
            }
        }
    }

    assert_eq!(
        completed,
        Some(TransferEnd::Completed),
        "engines must converge despite loss"
    );

    // Receiver-side evidence: staged bytes identical + bootable marker.
    assert_eq!(
        storage.slice(0, IMG_LEN),
        &img.data[..],
        "staged image must equal the source image"
    );
    let mut raw = [0u8; TRAILER_LEN];
    storage
        .read(TRAILER_OFFSET, &mut raw)
        .expect("trailer read");
    let record = TrailerRecord::parse(&raw).expect("trailer parses");
    assert_eq!(record.status, TrailerStatus::StagedValid);
    (storage.slice(0, IMG_LEN).to_vec(), record)
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

#[test]
fn clean_air_converges_end_to_end() {
    let (_, record) = run_interop(None);
    assert_eq!(record.img_version, 11);
    assert_eq!(record.img_len, 300);
}

#[test]
fn every_third_frame_lost_still_converges() {
    // Aggressive deterministic loss forces BEGIN resends, chunk resends and
    // a FINALIZE resend somewhere in the run; the cumulative-ACK contract
    // must absorb all of it.
    let (_, record) = run_interop(Some(3));
    assert_eq!(record.status, TrailerStatus::StagedValid);
}

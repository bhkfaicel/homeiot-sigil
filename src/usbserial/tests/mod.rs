//! Unit tests for the plain usbserial link tier (framing, CRC, messages,
//! streaming decoder resync). Host-target only; the crate itself is `no_std`.

use super::*;
use core::mem::size_of;
use heapless::Vec as HeapVec;

/// Builds an RX message with a payload of `len` bytes (0..=255).
fn rx(len: usize) -> Msg {
    Msg::Rx {
        rssi: -55,
        snr: 9,
        payload: HeapVec::from_slice(&[0xABu8; MAX_RADIO_PAYLOAD][..len]).expect("len <= capacity"),
    }
}

/// Encodes a message into a fresh frame buffer and returns the used slice.
fn frame(msg: &Msg) -> heapless::Vec<u8, MAX_FRAME_LEN> {
    let mut buf = [0u8; MAX_FRAME_LEN];
    let len = msg.encode(&mut buf).expect("frame fits MAX_FRAME_LEN");
    HeapVec::from_slice(&buf[..len]).expect("slice fits")
}

/// Feeds one frame and expects exactly it back from the queue.
fn expect_one(decoder: &mut Decoder, msg: &Msg) {
    decoder.feed(&frame(msg));
    assert_eq!(
        decoder.pop().as_ref(),
        Some(msg),
        "decoded message mismatch"
    );
    assert_eq!(decoder.pop(), None, "queue must be empty afterwards");
    assert_eq!(decoder.dropped(), 0, "no frame may be dropped here");
}

#[test]
fn crc16_known_answer() {
    // Standard check value of CRC-16/CCITT-FALSE, pins all four parameters.
    assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
}

#[test]
fn constants_are_consistent() {
    assert_eq!(MAX_MSG_LEN, 262);
    assert_eq!(MAX_BLOCK_LEN, 265);
    assert_eq!(MAX_FRAME_LEN, 266);
}

#[test]
fn roundtrip_all_types() {
    let mut decoder = Decoder::new();
    expect_one(&mut decoder, &rx(MAX_RADIO_PAYLOAD));
    expect_one(&mut decoder, &rx(0));
    expect_one(
        &mut decoder,
        &Msg::TxReq {
            payload: HeapVec::from_slice(&[0x5Au8; 200]).expect("fits"),
        },
    );
    expect_one(
        &mut decoder,
        &Msg::TxResult {
            status: TX_STATUS_OK,
        },
    );
    expect_one(
        &mut decoder,
        &Msg::TxResult {
            status: TX_STATUS_RADIO_ERROR,
        },
    );
    expect_one(&mut decoder, &Msg::Ping);
    expect_one(&mut decoder, &Msg::Pong);
}

#[test]
fn two_frames_in_one_feed() {
    let mut wire = frame(&Msg::Ping);
    wire.extend(frame(&Msg::Pong));
    let mut decoder = Decoder::new();
    decoder.feed(&wire);
    assert_eq!(decoder.pop(), Some(Msg::Ping));
    assert_eq!(decoder.pop(), Some(Msg::Pong));
    assert_eq!(decoder.pop(), None);
    assert_eq!(decoder.dropped(), 0);
}

#[test]
fn byte_by_byte_streaming() {
    let wire = frame(&Msg::TxResult {
        status: TX_STATUS_OK,
    });
    let mut decoder = Decoder::new();
    for chunk in wire.chunks(1) {
        decoder.feed(chunk);
    }
    assert_eq!(
        decoder.pop(),
        Some(Msg::TxResult {
            status: TX_STATUS_OK
        })
    );
    assert_eq!(decoder.dropped(), 0);
}

#[test]
fn resync_after_torn_stream() {
    // Garbage with no delimiter merges into a doomed block; the delimiter
    // after it drops exactly that block and the next frame survives.
    let mut wire = HeapVec::<u8, MAX_FRAME_LEN>::new();
    wire.extend([0x11u8; 20]);
    wire.push(0).expect("fits");
    wire.extend(frame(&Msg::Ping));
    let mut decoder = Decoder::new();
    decoder.feed(&wire);
    assert_eq!(decoder.dropped(), 1);
    assert_eq!(decoder.pop(), Some(Msg::Ping));
    assert_eq!(decoder.pop(), None);
}

#[test]
fn corrupted_crc_drops_only_that_frame() {
    // Two valid frames; corrupt a byte inside the first frame (structure or
    // CRC: either way the frame must drop without touching the next one).
    let mut wire = frame(&Msg::Ping);
    wire.extend(frame(&Msg::Pong));
    wire[2] ^= 0xFF;
    let mut decoder = Decoder::new();
    decoder.feed(&wire);
    assert_eq!(decoder.dropped(), 1);
    assert_eq!(decoder.pop(), Some(Msg::Pong), "next frame must survive");
    assert_eq!(decoder.pop(), None);
}

#[test]
fn oversize_block_resyncs_and_recovers() {
    // A block longer than any legal block cannot be a frame; the decoder
    // drops it once at the delimiter and keeps decoding.
    let mut wire = HeapVec::<u8, 512>::new();
    wire.extend([0x77u8; 300]);
    wire.push(0).expect("fits");
    wire.extend(frame(&Msg::Pong));
    let mut decoder = Decoder::new();
    decoder.feed(&wire);
    assert_eq!(decoder.dropped(), 1);
    assert_eq!(decoder.pop(), Some(Msg::Pong));
    assert_eq!(decoder.pop(), None);
}

#[test]
fn oversize_block_with_fake_zero_resyncs() {
    // Oversized garbage that contains a delimiter mid-way: the fake block is
    // dropped by CRC/Malformed, the remainder resynchronizes at the next one.
    let mut wire = HeapVec::<u8, 512>::new();
    wire.extend([0x77u8; 300]);
    wire.push(0).expect("delimiter closes fake block");
    wire.extend([0x33u8; 20]);
    wire.push(0).expect("delimiter closes garbage block");
    wire.extend(frame(&Msg::Ping));
    let mut decoder = Decoder::new();
    decoder.feed(&wire);
    assert_eq!(decoder.dropped(), 2);
    assert_eq!(decoder.pop(), Some(Msg::Ping));
    assert_eq!(decoder.pop(), None);
}

#[test]
fn stray_delimiters_ignored() {
    let mut wire = HeapVec::<u8, MAX_FRAME_LEN>::new();
    wire.push(0).expect("fits");
    wire.push(0).expect("fits");
    wire.extend(frame(&Msg::Ping));
    let mut decoder = Decoder::new();
    decoder.feed(&wire);
    assert_eq!(decoder.dropped(), 0, "idle delimiters are not errors");
    assert_eq!(decoder.pop(), Some(Msg::Ping));
}

#[test]
fn queue_overflow_drops_newest_frame() {
    // More frames than DECODER_QUEUE_CAP without draining: the newest is
    // dropped and counted; the older ones still pop in order.
    let ping_frame = frame(&Msg::Ping);
    let mut decoder = Decoder::new();
    for _ in 0..(DECODER_QUEUE_CAP + 1) {
        decoder.feed(&ping_frame);
    }
    assert_eq!(decoder.dropped(), 1);
    for _ in 0..DECODER_QUEUE_CAP {
        assert_eq!(decoder.pop(), Some(Msg::Ping));
    }
    assert_eq!(decoder.pop(), None);
}

#[test]
fn cobs_known_vectors() {
    // No zeros: code byte first, then the data, no trailing zero.
    let mut out = [0xFFu8; 8];
    assert_eq!(cobs_encode(&[0x01, 0x02], &mut out), Ok(3));
    assert_eq!(&out[..3], &[0x03, 0x01, 0x02]);
    // Leading and embedded zeros: one empty block, then two data blocks.
    assert_eq!(cobs_encode(&[0x00, 0xAB, 0x00, 0xCD], &mut out), Ok(5));
    assert_eq!(&out[..5], &[0x01, 0x02, 0xAB, 0x02, 0xCD]);
    // 254 non-zero bytes: the 0xFF flush patch closes the full block, then
    // the final empty block emits its own code byte.
    let long = [0x42u8; 254];
    assert_eq!(cobs_encode(&long, &mut out), Err(Error::Overrun)); // 8-byte buffer too small
    let mut big = [0xFFu8; 256];
    assert_eq!(cobs_encode(&long, &mut big), Ok(256));
    assert_eq!(big[0], 0xFF);
    assert_eq!(big[255], 0x01);
}

#[test]
fn cobs_decode_rejects_zero_code_byte() {
    let mut out = [0u8; 8];
    assert_eq!(cobs_decode(&[0x00, 0x01], &mut out), Err(Error::Malformed));
}

#[test]
fn cobs_roundtrip_all_zero_payload() {
    let clear = [0u8; 64];
    let mut enc = [0u8; 128];
    let len = cobs_encode(&clear, &mut enc).expect("fits");
    // Encoded form of 64 zeros: 65 code bytes interleaved, no 0x00 inside.
    assert!(!enc[..len].contains(&0));
    let mut dec = [0xFFu8; 64];
    assert_eq!(cobs_decode(&enc[..len], &mut dec), Ok(64));
    assert_eq!(&dec[..], &clear[..]);
}

#[test]
fn unknown_type_and_short_bodies_are_malformed() {
    // Crafted clear message with an unknown type byte and a valid CRC.
    let mut clear = [0u8; 4];
    clear[0] = 0x7F;
    let crc = crc16_ccitt_false(&clear[..1]);
    clear[1] = crc as u8;
    clear[2] = (crc >> 8) as u8;
    let mut block = [0u8; 16];
    let len = cobs_encode(&clear[..3], &mut block).expect("fits");
    block[len] = 0;
    let mut decoder = Decoder::new();
    decoder.feed(&block[..len + 1]);
    assert_eq!(decoder.dropped(), 1);
    assert_eq!(decoder.pop(), None);
}

#[test]
fn decoder_ram_footprint_is_bounded() {
    // Regression bound in the crate convention: the decoder is meant to be
    // instantiated once per direction on RAM-constrained targets. The queue
    // of full RX messages dominates the footprint.
    assert!(
        size_of::<Decoder>() <= 2560,
        "Decoder grew beyond its approved bound: {} bytes",
        size_of::<Decoder>()
    );
}

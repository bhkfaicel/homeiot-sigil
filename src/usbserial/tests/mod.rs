//! Unit tests for the plain usbserial link tier (framing, CRC, messages,
//! streaming decoder resync). Host-target only; the crate itself is `no_std`.

use super::*;
use core::mem::size_of;
use heapless::Vec as HeapVec;

// Host-side performance measurement suite (dev-only, prints with
// --nocapture). The tier itself is already feature-gated in `lib.rs`, so no
// extra feature cfg is needed here.
mod perf_measurements;

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
    assert_eq!(cobs_encode(&long, &mut out), Err(UsbserialError::Overrun)); // 8-byte buffer too small
    let mut big = [0xFFu8; 256];
    assert_eq!(cobs_encode(&long, &mut big), Ok(256));
    assert_eq!(big[0], 0xFF);
    assert_eq!(big[255], 0x01);
}

#[test]
fn cobs_decode_rejects_zero_code_byte() {
    let mut out = [0u8; 8];
    assert_eq!(
        cobs_decode(&[0x00, 0x01], &mut out),
        Err(UsbserialError::Malformed)
    );
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
fn tx_result_with_trailing_byte_is_malformed() {
    // Crafted clear TX_RESULT with a valid CRC but one trailing extra byte
    // past the single status byte: the exact-body rule must drop the frame
    // instead of silently ignoring trailing bytes.
    let mut clear = [0u8; 8];
    clear[0] = TYPE_TX_RESULT;
    clear[1] = TX_STATUS_OK;
    clear[2] = 0x42;
    let crc = crc16_ccitt_false(&clear[..3]);
    clear[3] = crc as u8;
    clear[4] = (crc >> 8) as u8;
    let mut block = [0u8; 16];
    let len = cobs_encode(&clear[..5], &mut block).expect("fits");
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

// Secure profile (opt-in) tests

use super::{
    COUNTER_WIRE_LEN, HELLO_FRAME_MAX, PSK_LEN, Role, SECURE_MAX_FRAME_LEN, SECURE_MAX_MSG_LEN,
    SecureChannel, TAG_LEN,
};

const PSK_A: [u8; PSK_LEN] = [0xA5; PSK_LEN];
const PSK_B: [u8; PSK_LEN] = [0x5A; PSK_LEN];

fn nonce(byte: u8) -> [u8; NONCE_LEN] {
    [byte; NONCE_LEN]
}

/// Builds a host/head pair that completed the HELLO handshake.
fn established_pair(
    psk: &[u8; PSK_LEN],
    host_nonce: u8,
    head_nonce: u8,
) -> (SecureChannel, SecureChannel) {
    let mut host = SecureChannel::new(Role::Host, psk, &nonce(host_nonce));
    let mut head = SecureChannel::new(Role::Head, psk, &nonce(head_nonce));
    let mut buf = [0u8; HELLO_FRAME_MAX];
    let n = host.hello_frame(&mut buf).expect("hello fits");
    head.feed(&buf[..n]);
    let n = head.hello_frame(&mut buf).expect("hello fits");
    host.feed(&buf[..n]);
    assert!(host.is_established(), "host must be established");
    assert!(head.is_established(), "head must be established");
    (host, head)
}

fn tx_req(payload: &[u8]) -> Msg {
    Msg::TxReq {
        payload: HeapVec::from_slice(payload).expect("fits"),
    }
}

/// Decodes one HELLO wire frame back to `(nonce, kind)` — the counter/kind
/// assertions read the CLEAR wire bytes, no private state needed.
fn wire_hello(frame_bytes: &[u8]) -> ([u8; NONCE_LEN], u8) {
    let mut clear = [0u8; HELLO_FRAME_MAX];
    let len = cobs_decode(&frame_bytes[..frame_bytes.len() - 1], &mut clear)
        .expect("hello block decodes");
    // Exact shape: [type][nonce16][kind][crc2].
    assert_eq!(len, 1 + NONCE_LEN + 1 + 2, "hello wire shape");
    assert_eq!(clear[0], TYPE_HELLO);
    let peer_nonce: [u8; NONCE_LEN] = clear[1..1 + NONCE_LEN].try_into().expect("16 bytes");
    (peer_nonce, clear[1 + NONCE_LEN])
}

/// Reads the clear 8-byte send counter of a sealed wire frame (the counter
/// rides in clear bytes per the wire layout, so real `seal` output is
/// directly assertable).
fn wire_counter(frame_bytes: &[u8]) -> u64 {
    let mut clear = [0u8; SECURE_MAX_MSG_LEN];
    let len = cobs_decode(&frame_bytes[..frame_bytes.len() - 1], &mut clear)
        .expect("sealed block decodes");
    assert!(len > COUNTER_WIRE_LEN, "sealed wire shape");
    u64::from_be_bytes(clear[1..1 + COUNTER_WIRE_LEN].try_into().expect("8 bytes"))
}

/// Crafts one CRC-valid clear HELLO frame with an arbitrary raw body (used
/// to probe the kind/body trust boundary and to forge RESP frames).
fn craft_hello_raw(body: &[u8]) -> HeapVec<u8, HELLO_FRAME_MAX> {
    let mut clear = [0u8; 32];
    clear[0] = TYPE_HELLO;
    clear[1..1 + body.len()].copy_from_slice(body);
    let end = 1 + body.len();
    let crc = crc16_ccitt_false(&clear[..end]);
    clear[end] = crc as u8;
    clear[end + 1] = (crc >> 8) as u8;
    let mut block = [0u8; HELLO_FRAME_MAX];
    let len = cobs_encode(&clear[..end + 2], &mut block).expect("fits");
    block[len] = 0;
    HeapVec::from_slice(&block[..len + 1]).expect("fits")
}

/// Crafts a CRC-valid hostile HELLO with the given nonce and kind.
fn craft_hello(peer_nonce: &[u8; NONCE_LEN], kind: u8) -> HeapVec<u8, HELLO_FRAME_MAX> {
    let mut body = [0u8; NONCE_LEN + 1];
    body[..NONCE_LEN].copy_from_slice(peer_nonce);
    body[NONCE_LEN] = kind;
    craft_hello_raw(&body)
}

/// Snapshot of a wire frame for later replay.
fn snap(frame_bytes: &[u8]) -> HeapVec<u8, SECURE_MAX_FRAME_LEN> {
    HeapVec::from_slice(frame_bytes).expect("fits")
}

#[test]
fn secure_constants_are_consistent() {
    assert_eq!(
        SECURE_MAX_MSG_LEN,
        1 + COUNTER_WIRE_LEN + (1 + 2 + 1 + 1 + MAX_RADIO_PAYLOAD) + TAG_LEN + 2
    );
    assert_eq!(
        SECURE_MAX_FRAME_LEN,
        SECURE_MAX_MSG_LEN + SECURE_MAX_MSG_LEN.div_ceil(254) + 1 + 1
    );
    // HELLO clear message = type + nonce + kind + CRC = 20 bytes.
    assert_eq!(
        HELLO_FRAME_MAX,
        (NONCE_LEN + 4) + (NONCE_LEN + 4).div_ceil(254) + 1 + 1
    );
    assert_eq!(HELLO_FRAME_MAX, 23);
}

#[test]
fn secure_handshake_and_data_roundtrip() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let msg = tx_req(b"hello sensor");
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&msg, &mut out).expect("seal fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(msg), "host→head message must roundtrip");
    let rx_msg = rx(3);
    let n = head.seal(&rx_msg, &mut out).expect("seal fits");
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx_msg), "head→host message must roundtrip");
    assert_eq!(host.dropped(), 0);
    assert_eq!(head.dropped(), 0);
}

#[test]
fn secure_seal_requires_established_session() {
    let mut host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    assert_eq!(
        host.seal(&Msg::Ping, &mut out),
        Err(UsbserialError::NotEstablished)
    );
}

#[test]
fn seal_at_exhausted_counter_fails_without_advancing() {
    let (mut host, _head) = established_pair(&PSK_A, 1, 2);
    // Child test module: pin the counter directly at its ceiling.
    host.send_counter = u64::MAX;
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    assert_eq!(
        host.seal(&tx_req(b"x"), &mut out),
        Err(UsbserialError::CounterExhausted)
    );
    // The failed seal must not advance the counter: a re-HELLO resets it
    // unconditionally, so only this direct readout pins the guarantee.
    assert_eq!(host.send_counter, u64::MAX);
}

#[test]
fn secure_corrupted_tag_rejected() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&Msg::Ping, &mut out).expect("seal fits");
    out[12] ^= 0xFF; // inside the ciphertext region (type + 8 counter bytes precede it)
    head.feed(&out[..n]);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), None);
}

#[test]
fn secure_replay_rejected_then_valid_accepted() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n1 = host.seal(&Msg::Ping, &mut out).expect("fits");
    let f1 = HeapVec::<u8, MAX_FRAME_LEN>::from_slice(&out[..n1]).expect("fits");
    let n2 = host.seal(&Msg::Ping, &mut out).expect("fits");
    let f2 = HeapVec::<u8, MAX_FRAME_LEN>::from_slice(&out[..n2]).expect("fits");
    let n3 = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&f1);
    assert_eq!(head.pop(), Some(Msg::Ping));
    head.feed(&f2);
    assert_eq!(head.pop(), Some(Msg::Ping));
    // Replayed frame 1: counter 1 <= watermark 2 → dropped, watermark intact.
    head.feed(&f1);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), None);
    // A later, genuinely fresh counter must still be accepted.
    head.feed(&out[..n3]);
    assert_eq!(head.pop(), Some(Msg::Ping));
}

#[test]
fn secure_gap_beyond_window_rejected_then_in_window_accepted() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // Counter 1 accepted; the watermark advances to 1.
    let n1 = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n1]);
    assert_eq!(head.pop(), Some(Msg::Ping));
    // Direct-field pattern (exhaustion-test precedent): force a far-ahead
    // send counter so the next sealed frame lands one past the RX window
    // (counter 258 = watermark 1 + RX_COUNTER_MAX_GAP + 1).
    host.send_counter = 257;
    let n_gap = host.seal(&Msg::Ping, &mut out).expect("fits");
    let gap = HeapVec::<u8, MAX_FRAME_LEN>::from_slice(&out[..n_gap]).expect("fits");
    // Roll the sender back behind the watermark so the recovery frame is a
    // normal in-window counter (2; that nonce was never used, so sealing
    // stays sound).
    host.send_counter = 1;
    let n2 = host.seal(&Msg::Ping, &mut out).expect("fits");
    let f2 = HeapVec::<u8, MAX_FRAME_LEN>::from_slice(&out[..n2]).expect("fits");
    // Gap-257 frame: beyond the window → dropped, watermark untouched.
    head.feed(&gap);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), None);
    // The in-window recovery frame is accepted: the receiver did not wedge.
    head.feed(&f2);
    assert_eq!(head.pop(), Some(Msg::Ping));
}

#[test]
fn secure_rx_gap_window_boundaries_including_counter_limit() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // Counter 1 accepted; the watermark advances to 1.
    let n1 = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n1]);
    assert_eq!(head.pop(), Some(Msg::Ping));
    // Normal-range boundary: gap exactly RX_COUNTER_MAX_GAP is accepted.
    // Direct-field pattern (exhaustion-test precedent): force the send
    // counter so the next sealed frame lands on counter 257 (gap 256).
    host.send_counter = 256;
    let n_edge = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n_edge]);
    assert_eq!(head.pop(), Some(Msg::Ping), "gap-256 edge is in window");
    assert_eq!(head.recv_last, 257);
    // Near-limit regime, one below the counter ceiling: the window
    // truncates to the single remaining counter `u64::MAX` (gap 1).
    head.recv_last = u64::MAX - 1;
    host.send_counter = u64::MAX - 1;
    let n_max = host.seal(&Msg::Ping, &mut out).expect("fits"); // counter u64::MAX
    let f_max = HeapVec::<u8, MAX_FRAME_LEN>::from_slice(&out[..n_max]).expect("fits");
    head.feed(&f_max);
    assert_eq!(
        head.pop(),
        Some(Msg::Ping),
        "gap-1 at the ceiling is in window"
    );
    assert_eq!(head.recv_last, u64::MAX);
    // Reception is exhausted at the ceiling and every candidate is now out
    // of window: a small counter is `None` on `checked_sub` (never wraps
    // into acceptance) and the ceiling frame itself is gap 0. The
    // documented recovery is a re-HELLO/rekey, not a counter wrap.
    host.send_counter = 0;
    let n_small = host.seal(&Msg::Ping, &mut out).expect("fits"); // counter 1
    head.feed(&out[..n_small]);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), None);
    head.feed(&f_max);
    assert_eq!(head.dropped(), 2);
    assert_eq!(head.pop(), None);
}

#[test]
fn secure_type_confusion_rejected() {
    // Rewrite the clear type byte AND fix the CRC so the frame reaches the
    // AEAD layer: the tag must fail because the type is bound as AAD.
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    let block = &mut out[..n - 1]; // strip delimiter
    let mut clear = [0u8; SECURE_MAX_MSG_LEN];
    let cl = cobs_decode(block, &mut clear).expect("block decodes");
    clear[0] = TYPE_PONG; // RX→(here) PONG-style type rewrite
    let end = cl - 2;
    let crc = crc16_ccitt_false(&clear[..end]);
    clear[end] = crc as u8;
    clear[end + 1] = (crc >> 8) as u8;
    let mut scratch = [0u8; SECURE_MAX_FRAME_LEN];
    let bl = cobs_encode(&clear[..cl], &mut scratch).expect("fits");
    scratch[bl] = 0;
    head.feed(&scratch[..bl + 1]);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), None);
}

#[test]
fn secure_wrong_psk_rejected_at_first_data() {
    // The clear HELLO cannot authenticate by itself; the wrong PSK is
    // detected by the first sealed message's tag check.
    let mut host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let mut head = SecureChannel::new(Role::Head, &PSK_B, &nonce(2));
    let mut buf = [0u8; HELLO_FRAME_MAX];
    let n = host.hello_frame(&mut buf).expect("fits");
    head.feed(&buf[..n]);
    let n = head.hello_frame(&mut buf).expect("fits");
    host.feed(&buf[..n]);
    assert!(host.is_established() && head.is_established());
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.dropped(), 1, "wrong PSK must fail the first data tag");
    assert_eq!(head.pop(), None);
}

#[test]
fn secure_forged_premature_hello_recovered() {
    // A forged HELLO before the legitimate one must not poison the channel:
    // last HELLO pair wins and the real host completes the handshake.
    let mut head = SecureChannel::new(Role::Head, &PSK_A, &nonce(9));
    let mut impostor = SecureChannel::new(Role::Host, &PSK_B, &nonce(77));
    let mut buf = [0u8; HELLO_FRAME_MAX];
    let n = impostor.hello_frame(&mut buf).expect("fits");
    head.feed(&buf[..n]);
    assert!(
        head.is_established(),
        "forged hello derives wrong keys, not refusal"
    );
    let mut host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let n = host.hello_frame(&mut buf).expect("fits");
    head.feed(&buf[..n]);
    // Full exchange now works with the legitimate host: the head replies and
    // the host completes its own handshake with the head's HELLO.
    let n = head.hello_frame(&mut buf).expect("fits");
    host.feed(&buf[..n]);
    assert!(
        host.is_established(),
        "host must be established by the head reply"
    );
    let msg = tx_req(b"open");
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&msg, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(
        head.pop(),
        Some(msg),
        "legitimate traffic must flow after re-hello"
    );
}

#[test]
fn secure_nonce_uniqueness_changes_traffic_keys() {
    // Same PSK, different host nonces → different keys → different wire bytes.
    let (mut host_a, _head_a) = established_pair(&PSK_A, 1, 2);
    let (mut host_b, _head_b) = established_pair(&PSK_A, 3, 2);
    let mut out_a = [0u8; SECURE_MAX_FRAME_LEN];
    let mut out_b = [0u8; SECURE_MAX_FRAME_LEN];
    let na = host_a.seal(&Msg::Ping, &mut out_a).expect("fits");
    let nb = host_b.seal(&Msg::Ping, &mut out_b).expect("fits");
    assert_eq!(na, nb, "same shape expected");
    assert_ne!(
        &out_a[..na],
        &out_b[..nb],
        "different sessions must produce different sealed bytes"
    );
}

#[test]
fn secure_resync_after_garbage() {
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut wire = HeapVec::<u8, 512>::new();
    wire.extend([0x33u8; 40]);
    wire.push(0).expect("fits");
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    wire.extend_from_slice(&out[..n]).expect("fits");
    head.feed(&wire);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), Some(Msg::Ping));
}

#[test]
fn secure_oversize_block_resyncs_and_recovers() {
    // Real secure-path oversize: a non-empty block strictly longer than
    // the sealed-frame accumulator bound cannot be a legal frame. The
    // channel drops it once at the delimiter and still decodes the next
    // sealed frame (the short garbage in `secure_resync_after_garbage`
    // exercises the CRC-drop path, never this overflow path).
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut wire = HeapVec::<u8, 512>::new();
    wire.extend([0x77u8; SECURE_DECODER_ACC_CAP + 6]);
    wire.push(0).expect("delimiter closes the oversize block");
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host.seal(&Msg::Ping, &mut out).expect("seal fits");
    wire.extend_from_slice(&out[..n]).expect("fits");
    head.feed(&wire);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), Some(Msg::Ping));
    assert_eq!(head.pop(), None);
}

#[test]
fn secure_secrets_never_rendered() {
    // The PSK (0xA5 = 165 decimal) and any key material must not leak
    // through Debug formatting.
    let host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let rendered = alloc::format!("{host:?}");
    assert!(rendered.contains("SecureChannel"));
    assert!(
        !rendered.contains("165"),
        "PSK bytes leaked through Debug: {rendered}"
    );
    assert!(!rendered.to_lowercase().contains("psk"));
}

#[test]
fn secure_zeroize_on_drop_compiles_and_runs() {
    // Zeroization of the PSK happens in the Drop impl; safe Rust cannot
    // observe freed memory, so this pins the API contract: dropping is the
    // supported teardown and the Drop impl is the single zeroize point for
    // the PSK (DirectionalKeys zeroizes itself the same way).
    let host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    drop(host);
}

#[test]
fn secure_channel_ram_footprint_is_bounded() {
    // Bound tracks the real added state: staged candidate keys (~72 B) +
    // staged TX counter (8 B) + outstanding-initiation nonce (16 B +
    // discriminant) + kind handling.
    assert!(
        size_of::<SecureChannel>() <= 3080,
        "SecureChannel grew beyond its approved bound: {} bytes",
        size_of::<SecureChannel>()
    );
}

#[test]
fn secure_max_payload_roundtrips_both_directions() {
    // Regression: the secure receive accumulator must hold the SEALED
    // frame bound (290-byte COBS blocks), not the plain 265-byte one — a
    // max-size sealed RX (289 wire bytes) was silently dropped before.
    let mut host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let mut head = SecureChannel::new(Role::Head, &PSK_A, &nonce(2));
    let mut buf = [0u8; HELLO_FRAME_MAX];
    let n = host.hello_frame(&mut buf).expect("hello fits");
    head.feed(&buf[..n]);
    let n = head.hello_frame(&mut buf).expect("hello fits");
    host.feed(&buf[..n]);

    // Head → host: max-size RX payload.
    let rx_max = rx(MAX_RADIO_PAYLOAD);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = head.seal(&rx_max, &mut out).expect("sealed rx fits");
    assert_eq!(
        host.dropped(),
        0,
        "host must not drop the sealed max RX (wire len {n})"
    );
    host.feed(&out[..n]);

    assert_eq!(
        host.pop(),
        Some(rx_max),
        "max-size sealed RX must roundtrip"
    );

    // Host → head: max-size TX_REQ payload.
    let tx_max = Msg::TxReq {
        payload: Payload::from_slice(&[0x5Cu8; MAX_RADIO_PAYLOAD]).expect("fits"),
    };
    let n = host.seal(&tx_max, &mut out).expect("sealed tx fits");
    head.feed(&out[..n]);
    assert_eq!(
        head.pop(),
        Some(tx_max),
        "max-size sealed TX_REQ must roundtrip"
    );
    assert_eq!(host.dropped(), 0);
    assert_eq!(head.dropped(), 0);
}

#[test]
fn secure_fresh_host_channel_establishes_against_established_head() {
    // End-to-end reconnect shape: the head stays up while the HOST channel
    // is rebuilt from scratch (host reconnect / process restart). The
    // fresh host HELLO re-derives the head keys (last HELLO wins); the
    // head answers via take_peer_hello_seen so the new host channel can
    // establish; traffic flows again.
    let mut head = SecureChannel::new(Role::Head, &PSK_A, &nonce(9));

    // First host session establishes, then goes away (reconnect).
    let mut host_a = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let mut buf = [0u8; HELLO_FRAME_MAX];
    let n = host_a.hello_frame(&mut buf).expect("fits");
    head.feed(&buf[..n]);
    let n = head.hello_frame(&mut buf).expect("fits");
    host_a.feed(&buf[..n]);
    assert!(head.is_established());
    drop(host_a);

    // Fresh host channel (new nonce — the reconnect shape).
    let mut host_b = SecureChannel::new(Role::Host, &PSK_A, &nonce(42));
    let n = host_b.hello_frame(&mut buf).expect("fits");
    head.feed(&buf[..n]);
    assert!(
        head.take_peer_hello_seen(),
        "the head must see the fresh host HELLO and answer it"
    );
    let n = head.hello_frame(&mut buf).expect("fits");
    host_b.feed(&buf[..n]);
    assert!(
        host_b.is_established(),
        "the fresh host channel must establish against the established head"
    );

    // Traffic flows on the new session.
    let msg = Msg::TxReq {
        payload: Payload::from_slice(b"post-reconnect").expect("fits"),
    };
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let n = host_b.seal(&msg, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(msg));
}

// Staged-rekey replay defenses (public cadence only — hello_frame,
// begin_rekey, feed, seal, pop, take_peer_hello_seen).

#[test]
fn secure_same_epoch_init_replay_rejected_on_head() {
    // Mid-session replay of the CURRENT epoch's host INIT against an
    // established head must leave active keys, counters and the watermark
    // untouched: the replayed old sealed frame stays dropped and active
    // traffic keeps flowing (the pre-fix code re-derived identical keys and
    // reset the watermark, accepting the stale frame).
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // Epoch traffic: host frames with counters 1 and 2 delivered.
    let n1 = host.seal(&Msg::Ping, &mut out).expect("fits");
    let f1 = snap(&out[..n1]);
    head.feed(&f1);
    assert_eq!(head.pop(), Some(Msg::Ping));
    let n2 = host.seal(&Msg::Pong, &mut out).expect("fits");
    head.feed(&out[..n2]);
    assert_eq!(head.pop(), Some(Msg::Pong));
    // Record the current INIT (no owed answer → INIT with the unchanged
    // epoch nonce) and replay it mid-session.
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let n = host.hello_frame(&mut hbuf).expect("fits");
    let (hnonce, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_INIT);
    assert_eq!(hnonce, nonce(1), "same-epoch INIT nonce");
    head.feed(&hbuf[..n]);
    // The head owes an answer, but the replayed old frame must still drop.
    assert!(
        head.take_peer_hello_seen(),
        "INIT is answered even if hostile"
    );
    head.feed(&f1);
    assert_eq!(head.dropped(), 1, "replayed sealed frame must drop");
    assert_eq!(head.pop(), None);
    // Active traffic unaffected: next fresh frame delivers; head TX works.
    let n3 = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n3]);
    assert_eq!(head.pop(), Some(Msg::Ping));
    let n4 = head.seal(&rx(4), &mut out).expect("fits");
    host.feed(&out[..n4]);
    assert_eq!(host.pop(), Some(rx(4)));
    assert_eq!(host.dropped(), 0);
}

#[test]
fn secure_cross_epoch_resurrection_rejected() {
    // After a legitimate reconnect to a second epoch, replay of the FIRST
    // epoch's INIT plus its first sealed frame must fail under BOTH key
    // sets: monotonic local-nonce rotation makes the staged candidate equal
    // no past epoch (this pins the rotation requirement — an
    // identical-keys check alone would let the old epoch resurrect).
    let mut head = SecureChannel::new(Role::Head, &PSK_A, &nonce(2));
    let mut host_a = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // Epoch 1 handshake.
    let n = host_a.hello_frame(&mut hbuf).expect("fits");
    head.feed(&hbuf[..n]);
    let n = head.hello_frame(&mut hbuf).expect("fits");
    host_a.feed(&hbuf[..n]);
    assert!(head.is_established() && host_a.is_established());
    // Record the epoch-1 INIT (re-serialized, same nonce) and first frame.
    let n_init = host_a.hello_frame(&mut hbuf).expect("fits");
    let init_e1 = snap(&hbuf[..n_init]);
    let n_s1 = host_a.seal(&Msg::Ping, &mut out).expect("fits");
    let s1_e1 = snap(&out[..n_s1]);
    head.feed(&s1_e1);
    assert_eq!(
        head.pop(),
        Some(Msg::Ping),
        "epoch-1 frame delivered in epoch 1"
    );
    // Legitimate reconnect: fresh host, epoch 2 established and activated.
    let mut host_b = SecureChannel::new(Role::Host, &PSK_A, &nonce(42));
    let n = host_b.hello_frame(&mut hbuf).expect("fits");
    head.feed(&hbuf[..n]);
    assert!(head.take_peer_hello_seen());
    let n = head.hello_frame(&mut hbuf).expect("fits");
    host_b.feed(&hbuf[..n]);
    assert!(host_b.is_established());
    let n = host_b.seal(&Msg::Pong, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Pong), "epoch-2 activation");
    // ATTACK: epoch-1 INIT + epoch-1 first sealed frame.
    head.feed(&init_e1);
    head.feed(&s1_e1);
    assert_eq!(head.dropped(), 1, "resurrected epoch-1 frame must drop");
    assert_eq!(head.pop(), None);
    // Epoch-2 traffic continues.
    let n = host_b.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Ping));
}

#[test]
fn secure_hostile_init_burst_then_legit_rekey_succeeds() {
    // 32 arbitrary-nonce hostile INITs must consume no irreversible
    // resource (one overwriteable staged slot; ≤ 1 RESP per INIT, and the
    // sticky answer emits exactly one RESP total), never answer a RESP, and
    // never lock out the next legitimate host rekey.
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    for k in 0..32u8 {
        let mut hostile = SecureChannel::new(Role::Host, &PSK_B, &nonce(k));
        let n = hostile.hello_frame(&mut hbuf).expect("fits");
        head.feed(&hbuf[..n]);
    }
    assert_eq!(
        head.dropped(),
        0,
        "protocol-valid hostile INITs are not drops"
    );
    assert!(
        head.take_peer_hello_seen(),
        "one answer owed after the burst"
    );
    let n = head.hello_frame(&mut hbuf).expect("fits");
    let (_n, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_RESP, "the burst earns exactly one RESP");
    assert!(
        !head.take_peer_hello_seen(),
        "answer discharged by emission"
    );
    // A stray RESP is terminal (never answered — no ping-pong).
    head.feed(&craft_hello(&nonce(123), HELLO_KIND_RESP));
    assert_eq!(head.dropped(), 1, "stray RESP drops with no state change");
    // The legitimate rekey MUST still succeed after the burst.
    let n = host.begin_rekey(&mut hbuf).expect("fits");
    head.feed(&hbuf[..n]);
    assert!(head.take_peer_hello_seen());
    let n = head.hello_frame(&mut hbuf).expect("fits");
    host.feed(&hbuf[..n]);
    // Host's staged frame activates the head; traffic round-trips.
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(
        head.pop(),
        Some(Msg::Ping),
        "rekey must converge post-burst"
    );
    let n = head.seal(&rx(2), &mut out).expect("fits");
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx(2)));
    assert_eq!(host.dropped(), 0);
    assert!(!host.take_peer_hello_seen());
    assert!(!head.take_peer_hello_seen(), "no residual answer flag");
}

#[test]
fn secure_hostile_init_race_retry_converges() {
    // Race: a hostile INIT lands between the legitimate rekey INIT and the
    // initiator's first staged frame, overwriting the head's staged slot.
    // The initiator's staged frame is then dropped (transient TX
    // unavailability), the hostile RESP is a terminal drop, and ONE
    // begin_rekey retry converges. Counter continuity is read from the
    // CLEAR wire bytes of REAL seal output: the responder's first
    // post-activation frame carries 1, the initiator's carries k+1.
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let mut hellos = 0usize;
    // Honest rekey INIT, staged at the head.
    let n = host.begin_rekey(&mut hbuf).expect("fits");
    hellos += 1;
    head.feed(&hbuf[..n]);
    // The head answers honestly BEFORE the hostile INIT arrives.
    assert!(head.take_peer_hello_seen());
    let n_resp = head.hello_frame(&mut hbuf).expect("fits");
    let honest_resp = snap(&hbuf[..n_resp]);
    hellos += 1;
    // Hostile INIT overwrites the head's staged slot.
    let mut attacker = SecureChannel::new(Role::Host, &PSK_B, &nonce(200));
    let n = attacker.hello_frame(&mut hbuf).expect("fits");
    hellos += 1;
    head.feed(&hbuf[..n]);
    // Host consumes the honest RESP (stages an inert pair), then drops the
    // hostile answer (no outstanding initiation of its own anymore).
    host.feed(&honest_resp);
    let n = head.hello_frame(&mut hbuf).expect("fits");
    let hostile_resp = snap(&hbuf[..n]);
    hellos += 1;
    host.feed(&hostile_resp);
    assert_eq!(host.dropped(), 1, "stray hostile RESP is a terminal drop");
    assert!(!host.take_peer_hello_seen());
    // The initiator's staged frames go nowhere (head's slot was poisoned).
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.dropped(), 1, "exactly one failed activation attempt");
    assert_eq!(head.pop(), None);
    // One retry converges.
    let n = host.begin_rekey(&mut hbuf).expect("fits");
    hellos += 1;
    head.feed(&hbuf[..n]);
    assert!(head.take_peer_hello_seen());
    let n = head.hello_frame(&mut hbuf).expect("fits");
    hellos += 1;
    host.feed(&hbuf[..n]);
    // Activating frame from the REAL seal on the staged half.
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Ping), "retry converges");
    // Responder continuity: the head staged nothing → first frame = 1.
    let n = head.seal(&rx(3), &mut out).expect("fits");
    assert_eq!(wire_counter(&out[..n]), 1, "responder's first frame is 1");
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx(3)), "initiator activates on the reply");
    // Initiator continuity: k = 1 staged frame sealed → next is k+1 = 2.
    let n = host.seal(&Msg::Pong, &mut out).expect("fits");
    assert_eq!(wire_counter(&out[..n]), 2, "initiator resumes at k+1");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Pong));
    assert_eq!(
        hellos, 6,
        "bounded HELLO exchange (INIT/RESP per dance + hostile pair)"
    );
    assert_eq!(host.dropped(), 1);
    assert_eq!(head.dropped(), 1);
}

#[test]
fn secure_same_epoch_init_replay_rejected_on_host() {
    // Host-side symmetric variant: replaying the current epoch's head INIT
    // against an established host must not disturb active keys or the
    // watermark — the replayed old head→host frame stays dropped.
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // head→host traffic: counters 1 and 2 delivered.
    let n1 = head.seal(&rx(4), &mut out).expect("fits");
    let f1 = snap(&out[..n1]);
    host.feed(&f1);
    assert_eq!(host.pop(), Some(rx(4)));
    let n2 = head.seal(&rx(5), &mut out).expect("fits");
    host.feed(&out[..n2]);
    assert_eq!(host.pop(), Some(rx(5)));
    // Record and replay the current head INIT.
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let n = head.hello_frame(&mut hbuf).expect("fits");
    let (_n, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_INIT);
    host.feed(&hbuf[..n]);
    host.feed(&f1);
    assert_eq!(host.dropped(), 1, "replayed head→host frame must drop");
    assert_eq!(host.pop(), None);
    // Active traffic continues in both directions.
    let n3 = head.seal(&rx(6), &mut out).expect("fits");
    host.feed(&out[..n3]);
    assert_eq!(host.pop(), Some(rx(6)));
    let n4 = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n4]);
    assert_eq!(head.pop(), Some(Msg::Ping));
    assert_eq!(head.dropped(), 0);
}

#[test]
fn secure_end_to_end_rekey_convergence() {
    // Full public-cadence dance between two ESTABLISHED endpoints:
    // begin_rekey → head answer → real-seal activation frames. Exactly one
    // activation per side, ≤ 2 HELLO frames, no residual answer flags, no
    // drops, old-epoch frames rejected afterwards, and clear-wire counter
    // continuity (responder 1, initiator k+1 = 2).
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    let mut hellos = 0usize;
    // Old-epoch frame (delivered now, replayed after the dance).
    let n_old = host.seal(&Msg::Ping, &mut out).expect("fits");
    let old_epoch = snap(&out[..n_old]);
    head.feed(&old_epoch);
    assert_eq!(head.pop(), Some(Msg::Ping));
    // The dance.
    let n = host.begin_rekey(&mut hbuf).expect("fits");
    hellos += 1;
    head.feed(&hbuf[..n]);
    assert!(head.take_peer_hello_seen());
    let n = head.hello_frame(&mut hbuf).expect("fits");
    hellos += 1;
    host.feed(&hbuf[..n]);
    assert_eq!(hellos, 2, "the dance is at most 2 HELLO frames");
    // Activation: the host's staged frame from the REAL seal.
    let n = host.seal(&Msg::Pong, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Pong), "head activates on the proof");
    // The head's activating reply (responder staged nothing → counter 1).
    let n = head.seal(&rx(3), &mut out).expect("fits");
    assert_eq!(wire_counter(&out[..n]), 1, "responder's first frame is 1");
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx(3)), "host activates on the proof");
    // Initiator continuity: k = 1 staged frame → next frame is 2.
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    assert_eq!(wire_counter(&out[..n]), 2, "initiator resumes at k+1");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Ping));
    // One activation per side, no residual flags, no drops.
    assert!(!host.take_peer_hello_seen());
    assert!(!head.take_peer_hello_seen());
    assert_eq!(host.dropped(), 0);
    assert_eq!(head.dropped(), 0);
    // Old-epoch frames are rejected after the dance.
    head.feed(&old_epoch);
    assert_eq!(head.dropped(), 1);
    assert_eq!(head.pop(), None);
}

#[test]
fn secure_rebuilt_head_against_established_host() {
    // Scenario B: the head REBOOTS (fresh channel, new boot base) while the
    // host stays established. The host stages on the head INIT, answers
    // RESP, and activates on the head's first real-sealed frame — exactly
    // one activation, responder continuity (host staged nothing → its next
    // frame is 1), no ping-pong, no drops, no residual flags.
    let mut host = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    let mut head_a = SecureChannel::new(Role::Head, &PSK_A, &nonce(2));
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // Epoch-1 handshake and traffic.
    let n = host.hello_frame(&mut hbuf).expect("fits");
    head_a.feed(&hbuf[..n]);
    let n = head_a.hello_frame(&mut hbuf).expect("fits");
    host.feed(&hbuf[..n]);
    assert!(head_a.is_established() && host.is_established());
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    head_a.feed(&out[..n]);
    assert_eq!(head_a.pop(), Some(Msg::Ping));
    drop(head_a); // the head "reboots"
    // Rebuilt head: fresh channel, new boot base → link-open INIT.
    let mut head_b = SecureChannel::new(Role::Head, &PSK_A, &nonce(99));
    let n = head_b.hello_frame(&mut hbuf).expect("fits");
    let (hnonce, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_INIT);
    assert_eq!(hnonce, nonce(99), "fresh boot base");
    host.feed(&hbuf[..n]);
    assert!(host.take_peer_hello_seen());
    let n = host.hello_frame(&mut hbuf).expect("fits");
    let (_n, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_RESP);
    head_b.feed(&hbuf[..n]);
    assert!(head_b.is_established(), "fresh head derives directly");
    assert!(!head_b.take_peer_hello_seen(), "RESP earns no answer");
    // The head's first real-sealed frame is the host's activation trigger.
    let n = head_b.seal(&rx(5), &mut out).expect("fits");
    assert_eq!(wire_counter(&out[..n]), 1);
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx(5)), "host activates on the proof");
    // Responder-side continuity: the host staged nothing (its staged slot
    // is a responder slot) → its next frame is 1.
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    assert_eq!(wire_counter(&out[..n]), 1, "responder's first frame is 1");
    head_b.feed(&out[..n]);
    assert_eq!(head_b.pop(), Some(Msg::Ping));
    // Bidirectional traffic continues.
    let n = head_b.seal(&rx(6), &mut out).expect("fits");
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx(6)));
    assert_eq!(host.dropped(), 0);
    assert_eq!(head_b.dropped(), 0);
    assert!(!host.take_peer_hello_seen());
    assert!(!head_b.take_peer_hello_seen());
}

#[test]
fn secure_begin_rekey_role_rule() {
    // Rekey initiation is normatively HOST-only: a head call returns
    // WrongRole with NO state change (no nonce advance, no outstanding
    // initiation), fresh or established alike; an established host emits
    // INIT with the advanced nonce; a fresh host is NotEstablished.
    let mut head = SecureChannel::new(Role::Head, &PSK_A, &nonce(9));
    let mut hbuf = [0u8; HELLO_FRAME_MAX];
    assert_eq!(
        head.begin_rekey(&mut hbuf),
        Err(UsbserialError::WrongRole),
        "head must never initiate"
    );
    // No nonce advance: the head's INIT still carries the original nonce.
    let n = head.hello_frame(&mut hbuf).expect("fits");
    let (hnonce, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_INIT);
    assert_eq!(hnonce, nonce(9), "WrongRole must not rotate the nonce");
    // The fresh-head WrongRole probe must not leave an outstanding
    // initiation either (fresh channels answer RESP through T1, so the
    // init_pending pin runs on the established head below).    // Established head: still refused.
    let (mut host, mut head_est) = established_pair(&PSK_A, 1, 2);
    assert_eq!(
        head_est.begin_rekey(&mut hbuf),
        Err(UsbserialError::WrongRole)
    );
    // Established host: emits INIT with the advanced local nonce.
    let n = host.begin_rekey(&mut hbuf).expect("fits");
    let (hnonce, kind) = wire_hello(&hbuf[..n]);
    assert_eq!(kind, HELLO_KIND_INIT);
    let mut advanced = nonce(1);
    advanced[NONCE_LEN - 1] = 2;
    assert_eq!(hnonce, advanced, "begin_rekey rotates the local nonce");
    // No outstanding initiation on the refused head: a stray RESP on the
    // ESTABLISHED head drops (a staged dance would have consumed it).
    head_est.feed(&craft_hello(&nonce(77), HELLO_KIND_RESP));
    assert_eq!(head_est.dropped(), 1, "no init_pending after WrongRole");
    // Fresh host: nothing to rekey yet.
    let mut fresh = SecureChannel::new(Role::Host, &PSK_A, &nonce(1));
    assert_eq!(
        fresh.begin_rekey(&mut hbuf),
        Err(UsbserialError::NotEstablished)
    );
}

#[test]
fn secure_hello_kind_body_trust_boundary() {
    // HELLO trust boundary: a CRC-valid frame with an unknown kind is a
    // plain drop (no staged mutation, no answer flag, active traffic
    // unaffected), and non-exact bodies (missing kind / trailing byte) drop
    // with no state change.
    let (mut host, mut head) = established_pair(&PSK_A, 1, 2);
    let mut out = [0u8; SECURE_MAX_FRAME_LEN];
    // Active-traffic baseline.
    let n = host.seal(&Msg::Ping, &mut out).expect("fits");
    head.feed(&out[..n]);
    assert_eq!(head.pop(), Some(Msg::Ping));
    // kind = 0x02: CRC-valid, structurally well-formed, unknown kind.
    let mut bad = [0u8; NONCE_LEN + 1];
    bad[..NONCE_LEN].copy_from_slice(&nonce(123));
    bad[NONCE_LEN] = 0x02;
    head.feed(&craft_hello_raw(&bad));
    assert_eq!(head.dropped(), 1, "unknown kind drops");
    assert!(!head.take_peer_hello_seen(), "no answer owed");
    // Short body: 16 bytes (nonce only, kind missing).
    head.feed(&craft_hello_raw(&[0x42; NONCE_LEN]));
    assert_eq!(head.dropped(), 2, "missing kind drops");
    // Long body: 18 bytes (one trailing byte past kind).
    head.feed(&craft_hello_raw(&[0x42; NONCE_LEN + 2]));
    assert_eq!(head.dropped(), 3, "trailing byte drops");
    assert_eq!(head.pop(), None);
    // Active traffic unaffected throughout.
    let n = head.seal(&rx(7), &mut out).expect("fits");
    host.feed(&out[..n]);
    assert_eq!(host.pop(), Some(rx(7)));
    assert_eq!(host.dropped(), 0);
    assert_eq!(head.dropped(), 3);
}

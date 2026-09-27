//! USB-serial link tier between the gateway host and the SAMD21 radio head
//! (opt-in cargo feature `usbserial`).
//!
//! The head owns the SX1278 radio (SPI + DIO0); the host owns the Sigil
//! sessions, the secure element and the backend connectivity. This module is
//! the framed byte protocol those two endpoints exchange over the USB CDC ACM
//! byte stream. It is a plain, unauthenticated tier: integrity comes from
//! CRC-16, confidentiality from nothing. The PSK-authenticated AEAD channel
//! (secure profile) is layered on the same framing in the `secure` half of
//! this module and arrives with the same feature.
//!
//! # Feature gating
//!
//! Like `ota`, the feature is never implied by another feature: a plain
//! `sensor` / `gateway` build carries zero usbserial code. The standalone
//! `default-features = false, features = ["usbserial"]` configuration is a
//! supported build shape (that is what the head firmware compiles).
//!
//! # Framing (both profiles)
//!
//! Every frame on the wire is one COBS-encoded block followed by a single
//! `0x00` delimiter byte:
//!
//! ```text
//! frame = COBS( [type] [body..] [crc_lo] [crc_hi] ) 0x00
//! ```
//!
//! COBS output never contains `0x00`, so the delimiter is unambiguous and
//! resynchronization after garbage or a torn stream is a scan for the next
//! `0x00`. CRC-16/CCITT-FALSE (poly `0x1021`, init `0xFFFF`, no reflection,
//! xorout `0x0000`, little-endian on the wire) covers type and body; its job
//! is to deterministically drop torn-stream garbage — USB CDC itself
//! guarantees byte integrity on a healthy link.
//!
//! # Message types (v1)
//!
//! | id     | name      | direction   | body                                        |
//! |--------|-----------|-------------|---------------------------------------------|
//! | `0x01` | RX        | head → host | rssi:i16LE ‖ snr:i8 ‖ len:u8 ‖ payload\[len\] |
//! | `0x02` | TX_REQ    | host → head | len:u8 ‖ payload\[len\]                       |
//! | `0x03` | TX_RESULT | head → host | status:u8 (0 = ok, 1 = radio error)         |
//! | `0x04` | PING      | host → head | —                                           |
//! | `0x05` | PONG      | head → host | —                                           |
//!
//! `0x06` and above are reserved for the secure-profile handshake.
//!
//! # Bounds
//!
//! A radio payload is at most [`MAX_RADIO_PAYLOAD`] bytes (the SX1278
//! payload-length register is 8 bits; 255 is the physical bound — this is a
//! different, tighter limit than the session `MSG_MAX` buffer capacity). The
//! decoder rejects any block that cannot decode to a legal message; blocks
//! longer than [`MAX_BLOCK_LEN`] cannot be legal and resynchronize the
//! stream. [`Decoder`] holds a small fixed-capacity queue of decoded
//! messages: the caller drains it with [`Decoder::pop`]; a queue overflow
//! drops the newest frame and counts it in [`Decoder::dropped`] (link loss is
//! tolerated by design — the session layer above already retries).

#![forbid(unsafe_code)]

use heapless::Vec;

#[cfg(test)]
mod tests;

/// Upper bound of one radio payload: the SX1278 payload-length register is
/// 8 bits, so 255 bytes is the physical radio limit.
pub const MAX_RADIO_PAYLOAD: usize = 255;

/// Worst-case clear (pre-COBS) message: an RX with a full payload —
/// `type(1) + rssi(2) + snr(1) + len(1) + payload(255) + crc(2)`.
pub const MAX_MSG_LEN: usize = 1 + 2 + 1 + 1 + MAX_RADIO_PAYLOAD + 2;

/// Worst-case COBS-encoded block: one overhead byte per 254 payload bytes,
/// plus the mandatory final overhead byte.
pub const MAX_BLOCK_LEN: usize = MAX_MSG_LEN + MAX_MSG_LEN.div_ceil(254) + 1;

/// Worst-case wire frame: one COBS block plus its `0x00` delimiter.
pub const MAX_FRAME_LEN: usize = MAX_BLOCK_LEN + 1;

/// Frame capacity every [`Decoder`] input block is allowed to reach before
/// the stream is declared desynchronized.
const DECODER_ACC_CAP: usize = MAX_BLOCK_LEN;

/// Number of decoded messages a [`Decoder`] retains between `feed` and `pop`.
/// The caller is expected to drain promptly; overflow drops and counts.
const DECODER_QUEUE_CAP: usize = 8;

/// Link message type: radio frame received by the head (head → host).
pub const TYPE_RX: u8 = 0x01;
/// Link message type: transmit request (host → head).
pub const TYPE_TX_REQ: u8 = 0x02;
/// Link message type: transmit result (head → host completion report).
pub const TYPE_TX_RESULT: u8 = 0x03;
/// Link message type: health probe (host → head).
pub const TYPE_PING: u8 = 0x04;
/// Link message type: health probe answer (head → host).
pub const TYPE_PONG: u8 = 0x05;

/// [`Msg::TxResult`] status: the radio transmitted the frame.
pub const TX_STATUS_OK: u8 = 0;
/// [`Msg::TxResult`] status: the radio refused or failed the transmission.
pub const TX_STATUS_RADIO_ERROR: u8 = 1;

/// Failure taxonomy of the framing layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbserialError {
    /// Destination buffer cannot hold the encoded/decoded bytes.
    Overrun,
    /// Input violates a structural rule (zero overhead byte, truncated
    /// block, unknown type, illegal body length).
    Malformed,
    /// CRC-16 mismatch: the frame is corrupt or torn.
    Crc,
    /// Secure operation attempted before the HELLO handshake completed.
    NotEstablished,
    /// The channel's send counter is exhausted (`u64::MAX`): sealing is
    /// refused deterministically instead of wrapping into AEAD nonce reuse
    /// under the same directional key. Re-establish the channel with a fresh
    /// HELLO handshake. Distinct from [`UsbserialError::Crypto`] (an AEAD tag or
    /// cipher failure). New member of a plain `pub enum` (no
    /// `#[non_exhaustive]`): downstream exhaustive matches must gain an arm,
    /// which is a breaking change to ship with a major version bump.
    CounterExhausted,
    /// A rekey initiation ([`SecureChannel::begin_rekey`]) was attempted on
    /// the wrong endpoint role. Rekey initiation is normatively host-only:
    /// the radio head rekeys solely by rebooting (its fresh-channel
    /// link-open HELLO INIT), and two simultaneous initiators could never
    /// converge, so a `Role::Head` call is refused with no state change.
    /// New member of a plain `pub enum` (no `#[non_exhaustive]`): downstream
    /// exhaustive matches must gain an arm, which is a breaking change to
    /// ship with a major version bump.
    WrongRole,
    /// AEAD encryption/decryption failed (tag verification or cipher error).
    Crypto,
}

/// One radio payload worth of bytes, bounded by the physical radio limit.
pub type Payload = Vec<u8, MAX_RADIO_PAYLOAD>;

/// One link-layer message, decoded or ready to encode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    /// A LoRa frame received by the head, with signal quality metadata.
    Rx {
        /// Received signal strength in dBm.
        rssi: i16,
        /// Signal-to-noise ratio in dB.
        snr: i8,
        /// Raw radio payload.
        payload: Payload,
    },
    /// Request to transmit one raw radio frame.
    TxReq {
        /// Raw radio payload to transmit.
        payload: Payload,
    },
    /// Completion report for one [`Msg::TxReq`] (single-owner TX semantics).
    TxResult {
        /// One of the `TX_STATUS_*` constants.
        status: u8,
    },
    /// Health probe.
    Ping,
    /// Health probe answer.
    Pong,
}

impl Msg {
    /// Serializes one complete wire frame (COBS block + `0x00` delimiter)
    /// into `out`; returns the number of bytes written,
    /// `<= [`MAX_FRAME_LEN`]`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, UsbserialError> {
        if out.len() < MAX_FRAME_LEN {
            return Err(UsbserialError::Overrun);
        }
        let mut clear = [0u8; MAX_MSG_LEN];
        let clear_len = self.encode_clear(&mut clear);
        let block_len = cobs_encode(&clear[..clear_len], out)?;
        out[block_len] = 0;
        Ok(block_len + 1)
    }

    /// Writes `[type][body]` (no CRC) into `out`; returns the written length.
    /// Shared by the plain frame builder and the secure seal path (which
    /// encrypts the body instead of CRC-protecting it).
    fn write_body(&self, out: &mut [u8]) -> usize {
        match self {
            Msg::Rx { rssi, snr, payload } => {
                out[0] = TYPE_RX;
                out[1..3].copy_from_slice(&rssi.to_le_bytes());
                out[3] = *snr as u8;
                out[4] = payload.len() as u8;
                out[5..5 + payload.len()].copy_from_slice(payload);
                5 + payload.len()
            }
            Msg::TxReq { payload } => {
                out[0] = TYPE_TX_REQ;
                out[1] = payload.len() as u8;
                out[2..2 + payload.len()].copy_from_slice(payload);
                2 + payload.len()
            }
            Msg::TxResult { status } => {
                out[0] = TYPE_TX_RESULT;
                out[1] = *status;
                2
            }
            Msg::Ping => {
                out[0] = TYPE_PING;
                1
            }
            Msg::Pong => {
                out[0] = TYPE_PONG;
                1
            }
        }
    }

    /// Writes `[type][body][crc]` into `out` (capacity is guaranteed by the
    /// only caller, which passes a `MAX_MSG_LEN` buffer); returns the length.
    fn encode_clear(&self, out: &mut [u8; MAX_MSG_LEN]) -> usize {
        let end = self.write_body(out);
        write_crc(out, end);
        end + 2
    }
}

/// Appends the little-endian CRC-16 of `out[..end]` at `out[end..end+2]`.
fn write_crc(out: &mut [u8; MAX_MSG_LEN], end: usize) {
    let crc = crc16_ccitt_false(&out[..end]);
    out[end..end + 2].copy_from_slice(&crc.to_le_bytes());
}

/// CRC-16/CCITT-FALSE: poly `0x1021`, init `0xFFFF`, no reflection,
/// xorout `0x0000`. Check value: `crc16_ccitt_false(b"123456789") == 0x29B1`.
pub fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Encodes `src` into `dst` with COBS; returns the encoded length, which is
/// at most `src.len() + src.len().div_ceil(254) + 1`. The output never
/// contains `0x00`.
pub fn cobs_encode(src: &[u8], dst: &mut [u8]) -> Result<usize, UsbserialError> {
    let worst = src.len() + src.len().div_ceil(254) + 1;
    if dst.len() < worst {
        return Err(UsbserialError::Overrun);
    }
    // Every block is [code][data]: reserve the first code slot up front and
    // patch each overhead byte when its block closes.
    let mut dst_len = 1usize;
    let mut code_index = 0usize;
    // Data bytes in the current block, plus one for the implicit zero.
    let mut code = 1usize;
    for &byte in src {
        if byte == 0 {
            dst[code_index] = code as u8;
            code_index = dst_len;
            dst_len += 1;
            code = 1;
        } else {
            dst[dst_len] = byte;
            dst_len += 1;
            code += 1;
            if code == 0xFF {
                // 254 consecutive non-zero bytes: close the full block
                // (code 0xFF means "no implied zero after this block").
                dst[code_index] = 0xFF;
                code_index = dst_len;
                dst_len += 1;
                code = 1;
            }
        }
    }
    dst[code_index] = code as u8;
    Ok(dst_len)
}

/// Decodes one COBS block back into `dst`; returns the decoded length.
/// A block encoded by [`cobs_encode`] always round-trips.
pub fn cobs_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, UsbserialError> {
    let mut src_index = 0usize;
    let mut dst_len = 0usize;
    while src_index < src.len() {
        let code = src[src_index] as usize;
        src_index += 1;
        if code == 0 {
            // A legal encoder never emits a zero overhead byte.
            return Err(UsbserialError::Malformed);
        }
        let block = code - 1;
        if src_index + block > src.len() || dst_len + block > dst.len() {
            return Err(UsbserialError::Malformed);
        }
        dst[dst_len..dst_len + block].copy_from_slice(&src[src_index..src_index + block]);
        dst_len += block;
        src_index += block;
        if code < 0xFF && src_index < src.len() {
            // This block was terminated by a real zero byte: restore it.
            // The final block has no such trailing zero.
            if dst_len >= dst.len() {
                return Err(UsbserialError::Malformed);
            }
            dst[dst_len] = 0;
            dst_len += 1;
        }
    }
    Ok(dst_len)
}

/// Event reported by [`BlockAcc`] when a `0x00` delimiter closes the
/// current block.
#[derive(Debug)]
enum BlockEvent {
    /// A non-empty block closed; its bytes are readable via
    /// [`BlockAcc::bytes`] until the owner clears the accumulator.
    Closed,
    /// The delimiter closes an oversized garbage block: its bytes were
    /// already discarded and the stream resynchronizes here.
    OversizeClosed,
    /// Stray delimiter over an empty accumulator (idle pattern or
    /// post-resync): not an error, nothing to route.
    Idle,
}

/// Shared receive-side block accumulator: gathers stream bytes until the
/// `0x00` delimiter, discarding oversized garbage blocks (the stream
/// resynchronizes at the next delimiter). It owns only the byte loop and
/// reports [`BlockEvent`]s; drop counting stays with the embedding type,
/// which maps events onto its single `dropped` counter and routes closed
/// blocks through its own `finish_block`.
#[derive(Debug)]
struct BlockAcc<const CAP: usize> {
    /// Bytes of the current, not-yet-delimited block.
    acc: Vec<u8, CAP>,
    /// Set when the current block exceeded `CAP`: further bytes are
    /// discarded until the next delimiter (resync).
    overflowing: bool,
}

impl<const CAP: usize> BlockAcc<CAP> {
    /// Creates an empty accumulator.
    const fn new() -> Self {
        Self {
            acc: Vec::new(),
            overflowing: false,
        }
    }

    /// Consumes one stream byte; returns `Some` exactly when a delimiter
    /// closed a block. On [`BlockEvent::Closed`] the block bytes stay
    /// readable until the owner calls [`BlockAcc::clear`].
    fn feed_byte(&mut self, byte: u8) -> Option<BlockEvent> {
        if byte == 0 {
            if self.overflowing {
                // The delimiter closes an oversized garbage block.
                self.overflowing = false;
                self.acc.clear();
                Some(BlockEvent::OversizeClosed)
            } else if self.acc.is_empty() {
                // Stray delimiter (idle pattern or post-resync).
                Some(BlockEvent::Idle)
            } else {
                Some(BlockEvent::Closed)
            }
        } else if self.overflowing {
            // Discarded until the delimiter resynchronizes the stream.
            None
        } else if self.acc.len() == CAP {
            // One more byte would exceed any legal block.
            self.overflowing = true;
            None
        } else {
            // Cannot fail: capacity was checked one branch above.
            let _ = self.acc.push(byte);
            None
        }
    }

    /// Bytes of the block closed by the last [`BlockEvent::Closed`].
    fn bytes(&self) -> &[u8] {
        &self.acc
    }

    /// Discards the closed block, ready for the next one.
    fn clear(&mut self) {
        self.acc.clear();
    }
}

/// Streaming frame decoder for the USB byte stream.
///
/// Feed raw USB bytes ([`Decoder::feed`]) in arbitrary chunks; complete
/// frames are decoded into a fixed-capacity internal queue the caller drains
/// with [`Decoder::pop`]. Delimiter-less garbage, corrupt frames and
/// oversize blocks are dropped (counted in [`Decoder::dropped`]) and the
/// stream resynchronizes at the next `0x00`.
#[derive(Debug)]
pub struct Decoder {
    /// Shared receive accumulator: byte loop until the `0x00` delimiter.
    acc: BlockAcc<DECODER_ACC_CAP>,
    /// Decoded messages waiting to be popped (FIFO: arrival order).
    queue: heapless::Deque<Msg, DECODER_QUEUE_CAP>,
    /// Frames dropped as garbage, corrupt or queue-overflow since creation.
    dropped: u32,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    /// Creates an empty decoder.
    pub const fn new() -> Self {
        Self {
            acc: BlockAcc::new(),
            queue: heapless::Deque::new(),
            dropped: 0,
        }
    }

    /// Consumes one chunk of raw USB bytes.
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            match self.acc.feed_byte(byte) {
                Some(BlockEvent::Closed) => {
                    self.finish_block();
                    self.acc.clear();
                }
                // Oversize block closed: the owner counts the drop on its
                // single `dropped` counter; the stream already resynced.
                Some(BlockEvent::OversizeClosed) => self.dropped += 1,
                // Stray delimiter: not an error, nothing to route.
                Some(BlockEvent::Idle) | None => {}
            }
        }
    }

    /// Pops the oldest decoded message, if any.
    pub fn pop(&mut self) -> Option<Msg> {
        self.queue.pop_front()
    }

    /// Number of frames dropped (garbage, corrupt, oversize, queue overflow)
    /// since construction.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Decodes and enqueues one closed, non-empty block. Stray delimiters
    /// never reach this: the accumulator reports them as idle events.
    fn finish_block(&mut self) {
        let mut clear = [0u8; MAX_MSG_LEN];
        let decoded =
            cobs_decode(self.acc.bytes(), &mut clear).and_then(|len| parse_msg(&clear[..len]));
        match decoded {
            Ok(msg) => {
                // Full queue means the caller is not draining fast enough;
                // the newest frame is sacrificed and counted.
                if self.queue.push_back(msg).is_err() {
                    self.dropped += 1;
                }
            }
            Err(_) => self.dropped += 1,
        }
    }
}

/// Parses one decoded clear message `[type][body][crc]`.
fn parse_msg(decoded: &[u8]) -> Result<Msg, UsbserialError> {
    if decoded.len() < 3 {
        return Err(UsbserialError::Malformed);
    }
    let (msg_bytes, crc_bytes) = decoded.split_at(decoded.len() - 2);
    let expected = u16::from_le_bytes([crc_bytes[0], crc_bytes[1]]);
    if crc16_ccitt_false(msg_bytes) != expected {
        return Err(UsbserialError::Crc);
    }
    let (ty, body) = msg_bytes.split_first().ok_or(UsbserialError::Malformed)?;
    parse_body(*ty, body)
}

/// Parses one message body (type byte stripped, CRC already verified).
/// Shared by the plain decoder and the secure open path (the decrypted
/// plaintext has exactly this shape).
fn parse_body(ty: u8, body: &[u8]) -> Result<Msg, UsbserialError> {
    match ty {
        TYPE_RX => {
            if body.len() < 4 {
                return Err(UsbserialError::Malformed);
            }
            let len = body[3] as usize;
            if body.len() != 4 + len {
                return Err(UsbserialError::Malformed);
            }
            Ok(Msg::Rx {
                rssi: i16::from_le_bytes([body[0], body[1]]),
                snr: body[2] as i8,
                payload: Payload::from_slice(&body[4..]).map_err(|_| UsbserialError::Malformed)?,
            })
        }
        TYPE_TX_REQ => {
            let len = body.first().copied().ok_or(UsbserialError::Malformed)? as usize;
            if body.len() != 1 + len {
                return Err(UsbserialError::Malformed);
            }
            Ok(Msg::TxReq {
                payload: Payload::from_slice(&body[1..]).map_err(|_| UsbserialError::Malformed)?,
            })
        }
        TYPE_TX_RESULT => {
            // Exact-body rule like every sibling type: the encoder writes
            // exactly one status byte, so any trailing byte is malformed
            // (status itself stays unvalidated for head forward-compat).
            if body.len() != 1 {
                return Err(UsbserialError::Malformed);
            }
            Ok(Msg::TxResult { status: body[0] })
        }
        TYPE_PING if body.is_empty() => Ok(Msg::Ping),
        TYPE_PONG if body.is_empty() => Ok(Msg::Pong),
        _ => Err(UsbserialError::Malformed),
    }
}

// Secure profile (opt-in)
//
// PSK-authenticated AEAD channel layered on the same framing. Wire layout of
// a sealed data message (types 0x01..=0x05):
//
//   frame = COBS( [type] [counter:u64BE] [ciphertext||tag] [crc] ) 0x00
//
// - the type byte stays IN CLEAR (pre-decryption routing, HELLO detection)
//   but is AUTHENTICATED: AAD = [type] || counter_be, so a rewritten clear
//   type fails the tag check;
// - the counter rides in the clear and binds the replay window; the receiver
//   accepts counters strictly ahead of its watermark and at most
//   `RX_COUNTER_MAX_GAP` beyond it, and advances the watermark only AFTER
//   the tag verified (a forged huge counter cannot desync);
// - HELLO (0x06) travels clear (both directions, body = nonce[16] ‖ kind[1],
//   kind `0x00` INIT / `0x01` RESP, any other kind dropped): it is salt
//   material, not a secret; authentication comes from the PSK through the
//   first sealed frame of every epoch.
//
// Staged rekey (replay defense): a HELLO received while ESTABLISHED never
// replaces active state. The endpoint derives CANDIDATE keys with a freshly
// rotated local nonce, stores them in the single overwriteable staged slot
// and activates them ONLY when an inbound sealed frame verifies under them —
// a PSK-possession proof a PSK-less attacker cannot forge. The local nonce
// rotates monotonically on every answer / rekey INIT (`boot_base ‖
// counter_be`, counter half incremented), so a recorded HELLO can never
// re-derive the active keys nor any past epoch's keys: same-epoch replay
// stages an inert candidate, and a replayed old INIT plus its old sealed
// frame fails under both key sets. Unauthenticated HELLOs consume no
// irreversible resource: one overwriteable staged slot whose garbage
// candidates can never activate. The dialogue is acyclic (INIT → RESP →
// consume-or-drop; a RESP is never answered), so no exchange can loop.
//
// Rekey initiation is host-owned: the host calls `begin_rekey` (explicit
// INIT; `WrongRole` for a head — the head rekeys solely by rebooting, which
// is the fresh-channel link-open INIT). Once the initiator has consumed the
// peer RESP it seals on the STAGED TX half; the responder switches its TX
// only at its own activation. Until activation (or if a hostile INIT
// overwrote the staged slot) the initiator may hit TRANSIENT TX
// UNAVAILABILITY — no automatic ACTIVE fallback exists because the sender
// cannot know the peer dropped its frames; recovery is one host-timed
// `begin_rekey` retry (RX keeps accepting old-epoch traffic throughout).
//
// Key schedule (mirrors `core::aead` / `core::derive`, re-declared locally
// because those modules are session-gated and `usbserial` must build
// standalone):
//
//   salt = host_nonce[16] || head_nonce[16]
//   HKDF-SHA256(ikm = PSK[32], salt, info = "sigil-usbserial-v1") -> okm[72]
//   okm[0..32]   = host→head key      okm[32..36] = host→head nonce prefix
//   okm[36..68]  = head→host key      okm[68..72] = head→host nonce prefix
//   nonce = prefix[4] || counter_be[8]
//
// Honest property statement: link-layer PSK channel — NO forward secrecy,
// symmetric PSK (compromise reveals both directions), protects the
// host↔head link only; end-to-end sensor security remains the Sigil
// sessions above.

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag, aead::AeadInPlace};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Secure-profile handshake message (clear, body = `nonce[16] ‖ kind[1]`).
pub const TYPE_HELLO: u8 = 0x06;
/// HELLO kind byte: initiation (fresh-channel link open, or an explicit
/// host [`SecureChannel::begin_rekey`]). Always answered by one RESP.
pub const HELLO_KIND_INIT: u8 = 0x00;
/// HELLO kind byte: answer to a received INIT. Never answered — consumed
/// by the outstanding initiator, dropped by everyone else (the dialogue
/// INIT → RESP → consume-or-drop is acyclic, so no ping-pong exists).
pub const HELLO_KIND_RESP: u8 = 0x01;
/// Length of one HELLO nonce.
pub const NONCE_LEN: usize = 16;
/// Length of the pre-shared key.
pub const PSK_LEN: usize = 32;
/// Poly1305 tag length appended to every sealed message.
pub const TAG_LEN: usize = 16;
/// Clear counter bytes prefixing every sealed message body.
pub const COUNTER_WIRE_LEN: usize = 8;

/// Maximum accepted distance between the receive watermark and a sealed
/// frame's clear counter (mirrors `core::aead`'s window of the same name).
/// A sealed frame is accepted only when `counter.checked_sub(recv_last)`
/// yields a gap in `1..=RX_COUNTER_MAX_GAP`; everything else (replay, late
/// duplicate, jump beyond the window) is dropped with the watermark
/// untouched. The check is deliberately subtraction-based: a sum
/// (`recv_last + gap`) would overflow near `u64::MAX`. As the watermark
/// approaches `u64::MAX` the effective window truncates (fewer counters
/// remain acceptable); once the watermark reaches `u64::MAX` reception is
/// exhausted and the documented recovery is a re-HELLO/rekey (fresh epoch,
/// fresh counters), never a wrap.
const RX_COUNTER_MAX_GAP: u64 = 256;

const KEY_LEN: usize = 32;
const PREFIX_LEN: usize = 4;
const NONCE_SIZE: usize = PREFIX_LEN + 8;
const DIRECTIONAL_HALF: usize = KEY_LEN + PREFIX_LEN;
const OKM_LEN: usize = DIRECTIONAL_HALF * 2;
const HKDF_INFO: &[u8] = b"sigil-usbserial-v1";

/// Worst-case clear sealed message: type + counter + Rx worst body + tag
/// + CRC.
const SECURE_MAX_MSG_LEN: usize =
    1 + COUNTER_WIRE_LEN + (1 + 2 + 1 + 1 + MAX_RADIO_PAYLOAD) + TAG_LEN + 2;
/// Worst-case COBS block of a sealed message.
const SECURE_MAX_BLOCK_LEN: usize = SECURE_MAX_MSG_LEN + SECURE_MAX_MSG_LEN.div_ceil(254) + 1;
/// Accumulator capacity of the secure receive path: an alias of the
/// worst-case COBS block of a sealed message, never a re-derived formula.
const SECURE_DECODER_ACC_CAP: usize = SECURE_MAX_BLOCK_LEN;
/// Worst-case wire frame of a sealed message.
pub const SECURE_MAX_FRAME_LEN: usize = SECURE_MAX_BLOCK_LEN + 1;
/// Worst-case wire frame of a HELLO: `1+16+1+2` clear (type, nonce, kind,
/// CRC), COBS + delimiter.
pub const HELLO_FRAME_MAX: usize = (NONCE_LEN + 4) + (NONCE_LEN + 4).div_ceil(254) + 1 + 1;

/// Endpoint role of a [`SecureChannel`]. The role fixes the direction split
/// of the derived keys (see the key schedule above) and the salt order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Gateway host side (sends TX_REQ/PING, receives RX/TX_RESULT/PONG).
    Host,
    /// SAMD21 radio head side (sends RX/TX_RESULT/PONG, receives TX_REQ/PING).
    Head,
}

/// Directional AEAD material. Zeroized on drop.
struct DirectionalKeys {
    /// Key sealing messages flowing host → head.
    host_to_head_key: [u8; KEY_LEN],
    host_to_head_prefix: [u8; PREFIX_LEN],
    /// Key sealing messages flowing head → host.
    head_to_host_key: [u8; KEY_LEN],
    head_to_host_prefix: [u8; PREFIX_LEN],
}

impl Drop for DirectionalKeys {
    fn drop(&mut self) {
        self.host_to_head_key.zeroize();
        self.host_to_head_prefix.zeroize();
        self.head_to_host_key.zeroize();
        self.head_to_host_prefix.zeroize();
    }
}

impl DirectionalKeys {
    /// Derives the directional material from the PSK and the two HELLO
    /// nonces. Fails only on HKDF length overflow, which the fixed 72-byte
    /// OKM request cannot reach.
    fn derive(
        psk: &[u8; PSK_LEN],
        host_nonce: &[u8; NONCE_LEN],
        head_nonce: &[u8; NONCE_LEN],
    ) -> Result<Self, UsbserialError> {
        let mut salt = [0u8; NONCE_LEN * 2];
        salt[..NONCE_LEN].copy_from_slice(host_nonce);
        salt[NONCE_LEN..].copy_from_slice(head_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
        let mut okm = [0u8; OKM_LEN];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| UsbserialError::Crypto)?;
        let mut keys = Self {
            host_to_head_key: [0u8; KEY_LEN],
            host_to_head_prefix: [0u8; PREFIX_LEN],
            head_to_host_key: [0u8; KEY_LEN],
            head_to_host_prefix: [0u8; PREFIX_LEN],
        };
        keys.host_to_head_key.copy_from_slice(&okm[0..KEY_LEN]);
        keys.host_to_head_prefix
            .copy_from_slice(&okm[KEY_LEN..DIRECTIONAL_HALF]);
        keys.head_to_host_key
            .copy_from_slice(&okm[DIRECTIONAL_HALF..DIRECTIONAL_HALF + KEY_LEN]);
        keys.head_to_host_prefix
            .copy_from_slice(&okm[DIRECTIONAL_HALF + KEY_LEN..OKM_LEN]);
        okm.zeroize();
        Ok(keys)
    }

    /// Selects the sealing half for this role.
    fn send_half(&self, role: Role) -> (&[u8; KEY_LEN], &[u8; PREFIX_LEN]) {
        match role {
            Role::Host => (&self.host_to_head_key, &self.host_to_head_prefix),
            Role::Head => (&self.head_to_host_key, &self.head_to_host_prefix),
        }
    }

    /// Selects the receiving half for this role.
    fn recv_half(&self, role: Role) -> (&[u8; KEY_LEN], &[u8; PREFIX_LEN]) {
        match role {
            Role::Host => (&self.head_to_host_key, &self.head_to_host_prefix),
            Role::Head => (&self.host_to_head_key, &self.host_to_head_prefix),
        }
    }
}

/// Constructs the 12-byte AEAD nonce `prefix[4] || counter_be[8]`
/// (identical construction to `core::aead::build_nonce`).
fn build_nonce(prefix: &[u8; PREFIX_LEN], counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[0..PREFIX_LEN].copy_from_slice(prefix);
    nonce[PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Orders the two HELLO nonces into the salt's `(host, head)` positions.
fn ordered_nonces<'a>(
    role: Role,
    local: &'a [u8; NONCE_LEN],
    peer: &'a [u8; NONCE_LEN],
) -> (&'a [u8; NONCE_LEN], &'a [u8; NONCE_LEN]) {
    match role {
        Role::Host => (local, peer),
        Role::Head => (peer, local),
    }
}

/// Advances the monotonic local-nonce counter (`boot_base[8] ‖
/// counter_be[8]`): the counter half wraps around at its 64-bit ceiling,
/// which cannot recur in practice. Every answer / rekey INIT rotates the
/// salt, so no candidate epoch ever equals the active one or any recorded
/// past epoch (replay defense).
fn advance_local_nonce(local: &mut [u8; NONCE_LEN]) {
    let ctr = u64::from_be_bytes(local[NONCE_LEN - 8..].try_into().expect("8 bytes"));
    local[NONCE_LEN - 8..].copy_from_slice(&ctr.wrapping_add(1).to_be_bytes());
}

/// Candidate keys staged by an in-flight rekey dialogue. Activates only on
/// a tag-valid inbound sealed frame (a PSK-possession proof); garbage
/// candidates can never activate and the slot is simply overwritten by the
/// next dance.
struct StagedCandidate {
    /// CANDIDATE directional material (never mixed with the active keys).
    keys: DirectionalKeys,
    /// Staged TX last-sent counter, uniform with `send_counter` semantics
    /// (`0` = nothing sealed under these keys this epoch; initialized `0`
    /// at staging; success-only commit identical to the active counter).
    tx_counter: u64,
    /// `true` once this endpoint SWITCHED its emissions to the staged half.
    /// Only the initiator does (after consuming the RESP); a responder's
    /// staged slot never seals — its TX switches only at its own activation.
    tx_switched: bool,
}

/// Handshake/channel state.
#[derive(Default)]
enum SecureState {
    /// Waiting for the peer HELLO: either kind derives the channel directly
    /// (no established state exists to protect).
    #[default]
    AwaitingPeerHello,
    /// Keys derived and active. A HELLO received in this state stages a
    /// CANDIDATE epoch instead of touching active keys or counters.
    Established {
        /// Active directional material (full TX+RX halves until a staged
        /// candidate proves itself, at which point it replaces this
        /// wholesale).
        keys: DirectionalKeys,
        /// The single overwriteable staged slot (rekey candidate keys).
        staged: Option<StagedCandidate>,
    },
}

/// Which key half opened a sealed frame.
enum Opened {
    /// The ACTIVE half (normal path, in-flight old-epoch traffic during
    /// a staged rekey included).
    Active,
    /// The STAGED half: a PSK-possession proof → activates the staged
    /// epoch before delivery.
    Staged,
}

/// PSK-authenticated secure channel over the framed USB-serial link.
///
/// Lifecycle: `new(role, psk, local_nonce)` → send
/// [`SecureChannel::hello_frame`] (INIT on a fresh channel; RESP while a
/// peer HELLO still awaits its answer) → `feed(peer bytes)` → once
/// [`SecureChannel::is_established`], exchange data with
/// [`SecureChannel::seal`] / [`SecureChannel::pop`].
///
/// Replay defense (staged rekey): a HELLO received while established NEVER
/// replaces active keys or counters — it stages candidate keys, derived
/// with a freshly rotated local nonce, that activate only when an inbound
/// sealed frame verifies under them (PSK-possession proof). Hosts drive an
/// explicit rekey with [`SecureChannel::begin_rekey`] (host-only); until
/// the peer's staged proof arrives the initiator may see transient TX
/// unavailability and retries the rekey (host-timed; RX keeps accepting
/// old-epoch traffic throughout). The PSK and derived keys never appear in
/// `Debug` output and are zeroized on drop.
pub struct SecureChannel {
    role: Role,
    psk: [u8; PSK_LEN],
    /// Local HELLO nonce, interpreted as `boot_base[8] ‖ counter_be[8]`:
    /// the counter half is advanced on every answer / rekey INIT so each
    /// staged candidate epoch derives from fresh salt material and no
    /// nonce pair ever repeats.
    local_nonce: [u8; NONCE_LEN],
    state: SecureState,
    /// Nonce this endpoint sent in an outstanding [`SecureChannel::begin_rekey`]
    /// INIT; the pending RESP is consumed against it. `None` = no initiation
    /// outstanding (RESP HELLOs are dropped as strays).
    init_pending: Option<[u8; NONCE_LEN]>,
    /// Counter of the last sealed message, LAST-SENT semantics
    /// (0 = none sent this epoch; first seal emits 1).
    send_counter: u64,
    /// Highest accepted receive counter (0 = none accepted this epoch).
    recv_last: u64,
    /// Shared receive accumulator (byte loop until the `0x00` delimiter).
    /// The bound is the SEALED frame maximum ([`SECURE_MAX_BLOCK_LEN`],
    /// 290 bytes), NOT the plain one: a max-size sealed RX reaches 289
    /// wire bytes and a plain 265-byte accumulator would silently drop
    /// payloads ≥ 233 bytes.
    acc: BlockAcc<SECURE_DECODER_ACC_CAP>,
    dropped: u32,
    queue: heapless::Deque<Msg, DECODER_QUEUE_CAP>,
    /// Sticky answer-owed flag: a peer INIT arrived whose RESP has not been
    /// emitted yet. Observed by [`SecureChannel::take_peer_hello_seen`],
    /// consumed by [`SecureChannel::hello_frame`] when the RESP goes out.
    peer_hello_seen: bool,
}

impl core::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redacted on purpose: the PSK and the derived keys must never be
        // rendered by formatting (enforced by a test).
        f.debug_struct("SecureChannel")
            .field("role", &self.role)
            .field("established", &self.is_established())
            .field("send_counter", &self.send_counter)
            .field("recv_last", &self.recv_last)
            .field("dropped", &self.dropped)
            .finish()
    }
}

impl Drop for SecureChannel {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}

impl SecureChannel {
    /// Creates a channel for `role` with the shared `psk` and a locally
    /// generated `local_nonce` (uniqueness token: the host draws it from its
    /// OS CSPRNG, the head from a boot counter + jitter mix — the strong
    /// entropy of the salt comes from the host nonce).
    pub fn new(role: Role, psk: &[u8; PSK_LEN], local_nonce: &[u8; NONCE_LEN]) -> Self {
        Self {
            role,
            psk: *psk,
            local_nonce: *local_nonce,
            state: SecureState::AwaitingPeerHello,
            init_pending: None,
            send_counter: 0,
            recv_last: 0,
            acc: BlockAcc::new(),
            dropped: 0,
            queue: heapless::Deque::new(),
            peer_hello_seen: false,
        }
    }

    /// `true` once a peer HELLO completed the key derivation.
    pub fn is_established(&self) -> bool {
        matches!(self.state, SecureState::Established { .. })
    }

    /// Serializes the local HELLO frame (clear, COBS + delimiter) and
    /// consumes a pending answer: on a fresh channel (or as a same-nonce
    /// retransmission) this emits HELLO(INIT) with the current local nonce;
    /// while a peer INIT still awaits its RESP (see
    /// [`SecureChannel::take_peer_hello_seen`]) it emits HELLO(RESP) —
    /// exactly once, which clears the answer-owed flag. Requires `&mut
    /// self` because emitting the RESP is the act that discharges it.
    pub fn hello_frame(&mut self, out: &mut [u8]) -> Result<usize, UsbserialError> {
        if self.peer_hello_seen {
            let len = self.hello_frame_kind(HELLO_KIND_RESP, out)?;
            // The answer is discharged exactly when it goes on the wire.
            self.peer_hello_seen = false;
            Ok(len)
        } else {
            self.hello_frame_kind(HELLO_KIND_INIT, out)
        }
    }

    /// Pure HELLO serializer: `[type][nonce16][kind][crc]` + COBS +
    /// delimiter. No state is read beyond the current local nonce.
    fn hello_frame_kind(&self, kind: u8, out: &mut [u8]) -> Result<usize, UsbserialError> {
        if out.len() < HELLO_FRAME_MAX {
            return Err(UsbserialError::Overrun);
        }
        let mut clear = [0u8; NONCE_LEN + 4];
        clear[0] = TYPE_HELLO;
        clear[1..1 + NONCE_LEN].copy_from_slice(&self.local_nonce);
        clear[1 + NONCE_LEN] = kind;
        let end = 1 + NONCE_LEN + 1;
        let crc = crc16_ccitt_false(&clear[..end]);
        clear[end..end + 2].copy_from_slice(&crc.to_le_bytes());
        let block_len = cobs_encode(&clear, out)?;
        out[block_len] = 0;
        Ok(block_len + 1)
    }

    /// Initiates an explicit rekey (NORMATIVELY HOST-ONLY): advances the
    /// local nonce, emits HELLO(INIT) and arms the channel to consume the
    /// peer's RESP into a TX-switched staged pair. Active keys keep sealing
    /// (and RX keeps accepting them) until the peer proves the staged epoch
    /// with one tag-valid frame.
    ///
    /// Errors: [`UsbserialError::WrongRole`] for a `Role::Head` channel —
    /// the head rekeys solely by rebooting, and two simultaneous initiators
    /// could never converge — with no state change;
    /// [`UsbserialError::NotEstablished`] on a not-yet-established host;
    /// [`UsbserialError::Overrun`] if `out` is too small (also no state
    /// change). Retry cadence (response timeout, backoff) is host-owned.
    pub fn begin_rekey(&mut self, out: &mut [u8]) -> Result<usize, UsbserialError> {
        if self.role != Role::Host {
            return Err(UsbserialError::WrongRole);
        }
        if !self.is_established() {
            return Err(UsbserialError::NotEstablished);
        }
        if out.len() < HELLO_FRAME_MAX {
            return Err(UsbserialError::Overrun);
        }
        // Fresh salt for the candidate epoch; the RESP must answer THIS
        // nonce, so the outstanding-initiation slot is armed with it.
        advance_local_nonce(&mut self.local_nonce);
        self.init_pending = Some(self.local_nonce);
        // INIT explicitly (an owed RESP must never leak into a rekey INIT).
        self.hello_frame_kind(HELLO_KIND_INIT, out)
    }

    /// Seals one data message into a complete wire frame. Requires an
    /// established session; every seal bumps the SELECTED send counter.
    /// Emission policy (staged rekey): once this endpoint has consumed its
    /// rekey RESP (a TX-switched staged pair exists) frames seal on the
    /// STAGED half — there is no automatic ACTIVE fallback (the sender
    /// cannot know the peer dropped its frames); otherwise on the ACTIVE
    /// half. Both counters use identical LAST-SENT semantics, an exhausted
    /// selected counter fails with [`UsbserialError::CounterExhausted`], and
    /// a failed seal at any stage commits nothing (the next attempt reuses
    /// the same candidate counter safely — no frame was ever produced with
    /// that nonce).
    pub fn seal(&mut self, msg: &Msg, out: &mut [u8]) -> Result<usize, UsbserialError> {
        // Pre-checks consume nothing: capacity/state errors precede key
        // selection and any counter touch.
        if out.len() < SECURE_MAX_FRAME_LEN {
            return Err(UsbserialError::Overrun);
        }
        let SecureState::Established { keys, staged } = &mut self.state else {
            return Err(UsbserialError::NotEstablished);
        };
        // Key-half selection: STAGED iff a TX-switched staged pair exists
        // (the initiator after T3; the responder's staged slot never seals).
        // The commit match at the end mirrors this match arm-for-arm, so
        // whichever arm selected the counter is the arm that commits it.
        let (key, prefix, counter) = match staged.as_ref() {
            Some(s) if s.tx_switched => {
                let (key, prefix) = s.keys.send_half(self.role);
                // The counter feeds the AEAD nonce: wrapping at `u64::MAX`
                // would silently reuse nonces under the same directional
                // key, so refuse deterministically (the staged escape is a
                // fresh `begin_rekey` — new keys mean a new nonce prefix).
                let counter = s
                    .tx_counter
                    .checked_add(1)
                    .ok_or(UsbserialError::CounterExhausted)?;
                (key, prefix, counter)
            }
            _ => {
                let (key, prefix) = keys.send_half(self.role);
                let counter = self
                    .send_counter
                    .checked_add(1)
                    .ok_or(UsbserialError::CounterExhausted)?;
                (key, prefix, counter)
            }
        };
        // Wire layout: [type][counter][ciphertext][tag][crc], then COBS.
        // The body (type byte included) is written straight into the wire
        // block and its clear-text type byte is mirrored into the header —
        // no staging buffer, no body copy.
        let body_start = 1 + COUNTER_WIRE_LEN;
        let mut block = [0u8; SECURE_MAX_MSG_LEN];
        let body_len = msg.write_body(&mut block[body_start..]);
        block[0] = block[body_start];
        block[1..1 + COUNTER_WIRE_LEN].copy_from_slice(&counter.to_be_bytes());
        let nonce = build_nonce(prefix, counter);
        let mut aad = [0u8; 1 + COUNTER_WIRE_LEN];
        aad[0] = block[0];
        aad[1..].copy_from_slice(&counter.to_be_bytes());
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let tag = cipher
            .encrypt_in_place_detached(
                &Nonce::from(nonce),
                &aad,
                &mut block[1 + COUNTER_WIRE_LEN..1 + COUNTER_WIRE_LEN + body_len],
            )
            .map_err(|_| UsbserialError::Crypto)?;
        let end = 1 + COUNTER_WIRE_LEN + body_len + TAG_LEN;
        block[end - TAG_LEN..end].copy_from_slice(&tag);
        let crc = crc16_ccitt_false(&block[..end]);
        block[end..end + 2].copy_from_slice(&crc.to_le_bytes());
        let block_len = cobs_encode(&block[..end + 2], out)?;
        out[block_len] = 0;
        // Success path only: the SELECTED counter advances once the frame
        // is fully built and encoded into `out` (arm order mirrors the
        // selection match above).
        match staged.as_mut() {
            Some(s) if s.tx_switched => s.tx_counter = counter,
            _ => self.send_counter = counter,
        }
        Ok(block_len + 1)
    }

    /// Consumes one chunk of raw USB bytes (HELLO handling, sealed frames,
    /// resync — the same shared block accumulator as [`Decoder::feed`]).
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            match self.acc.feed_byte(byte) {
                Some(BlockEvent::Closed) => {
                    self.finish_block();
                    self.acc.clear();
                }
                // Oversize block closed: the owner counts the drop on its
                // single `dropped` counter; the stream already resynced.
                Some(BlockEvent::OversizeClosed) => self.dropped += 1,
                // Stray delimiter: not an error, nothing to route.
                Some(BlockEvent::Idle) | None => {}
            }
        }
    }

    /// Pops the oldest opened message, if any.
    pub fn pop(&mut self) -> Option<Msg> {
        self.queue.pop_front()
    }

    /// Reports whether a peer INIT still awaits its RESP answer (sticky
    /// until [`SecureChannel::hello_frame`] emits it — the emission is what
    /// clears it, so repeated polls stay truthful). Firmware calls this
    /// after draining the channel and answers `true` with `hello_frame`
    /// (request/response cadence — required for a fresh host channel to
    /// establish against an already-established head after any host-side
    /// reconnect, and for rekey answers).
    pub fn take_peer_hello_seen(&mut self) -> bool {
        self.peer_hello_seen
    }

    /// Number of frames dropped (garbage, corrupt, oversize, replay,
    /// queue overflow) since construction.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// CRC-checks and routes one closed, non-empty block. Stray delimiters
    /// never reach this: the accumulator reports them as idle events.
    fn finish_block(&mut self) {
        let mut clear = [0u8; SECURE_MAX_MSG_LEN];
        let len = match cobs_decode(self.acc.bytes(), &mut clear) {
            Ok(len) if len >= 3 => len,
            _ => {
                self.dropped += 1;
                return;
            }
        };
        let expected = u16::from_le_bytes([clear[len - 2], clear[len - 1]]);
        if crc16_ccitt_false(&clear[..len - 2]) != expected {
            self.dropped += 1;
            return;
        }
        let ty = clear[0];
        match ty {
            TYPE_HELLO => self.on_hello(&clear[1..len - 2]),
            TYPE_RX | TYPE_TX_REQ | TYPE_TX_RESULT | TYPE_PING | TYPE_PONG => {
                self.on_sealed(ty, &mut clear, len);
            }
            _ => self.dropped += 1,
        }
    }

    /// Routes one CRC-valid HELLO (`nonce[16] ‖ kind[1]`) through the
    /// staged-rekey state machine. Trust boundary: the body must be exactly
    /// `NONCE_LEN + 1` bytes and the kind must be INIT or RESP — anything
    /// else is dropped with no state change.
    fn on_hello(&mut self, body: &[u8]) {
        if body.len() != NONCE_LEN + 1 {
            self.dropped += 1;
            return;
        }
        let peer_nonce: [u8; NONCE_LEN] = body[..NONCE_LEN].try_into().expect("16 bytes");
        let kind = body[NONCE_LEN];
        if kind != HELLO_KIND_INIT && kind != HELLO_KIND_RESP {
            self.dropped += 1;
            return;
        }
        if matches!(self.state, SecureState::AwaitingPeerHello) {
            // Fresh channel: either kind establishes directly — there is no
            // established state to protect. The local nonce is NOT rotated
            // here (the peer's derivation must see the advertised one).
            let (host_nonce, head_nonce) =
                ordered_nonces(self.role, &self.local_nonce, &peer_nonce);
            match DirectionalKeys::derive(&self.psk, host_nonce, head_nonce) {
                Ok(keys) => {
                    self.state = SecureState::Established { keys, staged: None };
                    // Fresh epoch: counters restart, stale state cannot leak.
                    self.send_counter = 0;
                    self.recv_last = 0;
                    // Only an INIT is answered (RESP: the peer already holds
                    // our nonce; an answer would be dropped by any
                    // established peer anyway).
                    self.peer_hello_seen = kind == HELLO_KIND_INIT;
                }
                Err(_) => self.dropped += 1,
            }
            return;
        }
        // Established: active keys and counters are untouchable by HELLOs.
        let SecureState::Established {
            keys: _active,
            staged,
        } = &mut self.state
        else {
            unreachable!("established checked above");
        };
        match kind {
            HELLO_KIND_INIT => {
                // Answer INIT: rotate the local nonce, stage the candidate
                // epoch, and owe one RESP. Replacing (not ignoring) the
                // staged slot keeps legitimate retries converging even when
                // interleaved with hostile INITs; the overwritten slot is
                // inert either way (dropped in place, zeroized). Any
                // outstanding `init_pending` of our own dance is independent
                // and untouched.
                advance_local_nonce(&mut self.local_nonce);
                let (host_nonce, head_nonce) =
                    ordered_nonces(self.role, &self.local_nonce, &peer_nonce);
                match DirectionalKeys::derive(&self.psk, host_nonce, head_nonce) {
                    Ok(keys) => {
                        *staged = Some(StagedCandidate {
                            keys,
                            tx_counter: 0,
                            tx_switched: false,
                        });
                        self.peer_hello_seen = true;
                    }
                    Err(_) => self.dropped += 1,
                }
            }
            HELLO_KIND_RESP => match self.init_pending.take() {
                Some(sent) => {
                    // Consume the RESP of our own initiation: stage the
                    // candidate with the answered nonce pair and SWITCH this
                    // endpoint's TX to the staged half. No local-nonce
                    // rotation here (both endpoints must derive the SAME
                    // pair) and no answer (a RESP is never answered).
                    let (host_nonce, head_nonce) = ordered_nonces(self.role, &sent, &peer_nonce);
                    match DirectionalKeys::derive(&self.psk, host_nonce, head_nonce) {
                        Ok(keys) => {
                            *staged = Some(StagedCandidate {
                                keys,
                                tx_counter: 0,
                                tx_switched: true,
                            });
                        }
                        Err(_) => self.dropped += 1,
                    }
                }
                None => {
                    // Stray or hostile RESP with no outstanding initiation:
                    // terminal drop, no state change (this is what makes the
                    // dialogue acyclic — a RESP is never answered).
                    self.dropped += 1;
                }
            },
            _ => unreachable!("kind validated above"),
        }
    }

    /// Opens one sealed data message: tag verification FIRST (ACTIVE half,
    /// then the staged candidate on failure — a staged-tag success is a PSK
    /// proof and activates the candidate epoch), then the bounded
    /// replay-gap check, then the watermark advance. On AEAD tag failure
    /// the plaintext
    /// is never released and the ciphertext stays intact, so the second
    /// attempt over the same buffer is sound.
    ///
    /// `clear[0..len]` holds the CRC-checked wire message
    /// `[type][counter][ciphertext][tag][crc]`; the ciphertext is decrypted
    /// in place.
    fn on_sealed(&mut self, ty: u8, clear: &mut [u8; SECURE_MAX_MSG_LEN], len: usize) {
        let body_start = 1 + COUNTER_WIRE_LEN;
        let body_end = len - 2; // strip CRC
        if body_end < body_start + TAG_LEN {
            self.dropped += 1;
            return;
        }
        let counter = u64::from_be_bytes(clear[1..body_start].try_into().expect("8 bytes"));
        let ct_end = body_end - TAG_LEN;
        let opened = {
            let SecureState::Established { keys, staged } = &mut self.state else {
                self.dropped += 1;
                return;
            };
            let mut aad = [0u8; 1 + COUNTER_WIRE_LEN];
            aad[0] = ty;
            aad[1..].copy_from_slice(&counter.to_be_bytes());
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&clear[body_end - TAG_LEN..body_end]);
            let ct_end = body_end - TAG_LEN;
            // ACTIVE half first: the dual-RX acceptance window keeps
            // old-epoch traffic flowing while a rekey dialogue runs.
            let (key, prefix) = keys.recv_half(self.role);
            let mut nonce = build_nonce(prefix, counter);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
            let mut open = cipher.decrypt_in_place_detached(
                &Nonce::from(nonce),
                &aad,
                &mut clear[body_start..ct_end],
                Tag::from_slice(&tag),
            );
            nonce.zeroize();
            if open.is_ok() {
                Opened::Active
            } else if let Some(s) = staged.as_ref() {
                // CANDIDATE half: a valid tag here is proof the sender holds
                // the PSK (an attacker without it cannot forge the tag).
                let (skey, sprefix) = s.keys.recv_half(self.role);
                let mut snonce = build_nonce(sprefix, counter);
                let scipher = ChaCha20Poly1305::new(Key::from_slice(skey));
                open = scipher.decrypt_in_place_detached(
                    &Nonce::from(snonce),
                    &aad,
                    &mut clear[body_start..ct_end],
                    Tag::from_slice(&tag),
                );
                snonce.zeroize();
                if open.is_ok() {
                    Opened::Staged
                } else {
                    // Wrong keys or tampered frame under both halves:
                    // watermark untouched.
                    self.dropped += 1;
                    return;
                }
            } else {
                self.dropped += 1;
                return;
            }
        };
        if let Opened::Staged = opened {
            // ACTIVATE: the staged pair replaces the active epoch wholesale.
            // Uniform LAST-SENT counters make activation a plain copy (a
            // responder that sealed nothing staged resumes at 1; an
            // initiator that sealed k staged frames resumes at exactly
            // k+1 — no conversion, no reset-to-zero, no nonce reuse). The
            // RX watermark restarts fresh and any outstanding initiation
            // of our own is terminal.
            let staged = match &mut self.state {
                SecureState::Established { staged, .. } => staged.take(),
                SecureState::AwaitingPeerHello => unreachable!("opened implies established"),
            };
            if let Some(StagedCandidate {
                keys, tx_counter, ..
            }) = staged
            {
                self.state = SecureState::Established { keys, staged: None };
                self.send_counter = tx_counter;
                self.recv_last = 0;
                self.init_pending = None;
            }
        }
        // Replay-gap window (mirrors `core::aead`): accept only counters
        // strictly ahead of the watermark and at most `RX_COUNTER_MAX_GAP`
        // beyond it. `checked_sub` keeps the comparison overflow-safe near
        // `u64::MAX` (never `recv_last + gap`); a gap of 0 or `None` (at or
        // behind the watermark) rejects the replay / late-duplicate case
        // exactly like the former strict-increase check. Near the counter
        // ceiling the window truncates; at `u64::MAX` reception is
        // exhausted until a re-HELLO/rekey.
        let in_window = counter
            .checked_sub(self.recv_last)
            .is_some_and(|gap| (1..=RX_COUNTER_MAX_GAP).contains(&gap));
        if !in_window {
            // Replay, late duplicate, or jump beyond the window:
            // watermark untouched.
            self.dropped += 1;
            return;
        }
        self.recv_last = counter;
        // Defense in depth: the decrypted type must match the clear type.
        if clear[body_start] != ty {
            self.dropped += 1;
            return;
        }
        match parse_body(ty, &clear[body_start + 1..ct_end]) {
            Ok(msg) => {
                if self.queue.push_back(msg).is_err() {
                    self.dropped += 1;
                }
            }
            Err(_) => self.dropped += 1,
        }
    }
}

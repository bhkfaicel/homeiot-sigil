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
//! | `0x01` | RX        | head → host | rssi:i16LE ‖ snr:i8 ‖ len:u8 ‖ payload[len] |
//! | `0x02` | TX_REQ    | host → head | len:u8 ‖ payload[len]                       |
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
/// Link message type: transmit result (head → head completion report).
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
pub enum Error {
    /// Destination buffer cannot hold the encoded/decoded bytes.
    Overrun,
    /// Input violates a structural rule (zero overhead byte, truncated
    /// block, unknown type, illegal body length).
    Malformed,
    /// CRC-16 mismatch: the frame is corrupt or torn.
    Crc,
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
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < MAX_FRAME_LEN {
            return Err(Error::Overrun);
        }
        let mut clear = [0u8; MAX_MSG_LEN];
        let clear_len = self.encode_clear(&mut clear);
        let block_len = cobs_encode(&clear[..clear_len], out)?;
        out[block_len] = 0;
        Ok(block_len + 1)
    }

    /// Writes `[type][body][crc]` into `out` (capacity is guaranteed by the
    /// only caller, which passes a `MAX_MSG_LEN` buffer); returns the length.
    fn encode_clear(&self, out: &mut [u8; MAX_MSG_LEN]) -> usize {
        match self {
            Msg::Rx { rssi, snr, payload } => {
                out[0] = TYPE_RX;
                out[1..3].copy_from_slice(&rssi.to_le_bytes());
                out[3] = *snr as u8;
                out[4] = payload.len() as u8;
                out[5..5 + payload.len()].copy_from_slice(payload);
                let end = 5 + payload.len();
                write_crc(out, end);
                end + 2
            }
            Msg::TxReq { payload } => {
                out[0] = TYPE_TX_REQ;
                out[1] = payload.len() as u8;
                out[2..2 + payload.len()].copy_from_slice(payload);
                let end = 2 + payload.len();
                write_crc(out, end);
                end + 2
            }
            Msg::TxResult { status } => {
                out[0] = TYPE_TX_RESULT;
                out[1] = *status;
                write_crc(out, 2);
                4
            }
            Msg::Ping => {
                out[0] = TYPE_PING;
                write_crc(out, 1);
                3
            }
            Msg::Pong => {
                out[0] = TYPE_PONG;
                write_crc(out, 1);
                3
            }
        }
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
pub fn cobs_encode(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    let worst = src.len() + src.len().div_ceil(254) + 1;
    if dst.len() < worst {
        return Err(Error::Overrun);
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
pub fn cobs_decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    let mut src_index = 0usize;
    let mut dst_len = 0usize;
    while src_index < src.len() {
        let code = src[src_index] as usize;
        src_index += 1;
        if code == 0 {
            // A legal encoder never emits a zero overhead byte.
            return Err(Error::Malformed);
        }
        let block = code - 1;
        if src_index + block > src.len() || dst_len + block > dst.len() {
            return Err(Error::Malformed);
        }
        dst[dst_len..dst_len + block].copy_from_slice(&src[src_index..src_index + block]);
        dst_len += block;
        src_index += block;
        if code < 0xFF && src_index < src.len() {
            // This block was terminated by a real zero byte: restore it.
            // The final block has no such trailing zero.
            if dst_len >= dst.len() {
                return Err(Error::Malformed);
            }
            dst[dst_len] = 0;
            dst_len += 1;
        }
    }
    Ok(dst_len)
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
    /// Bytes of the current, not-yet-delimited block.
    acc: Vec<u8, DECODER_ACC_CAP>,
    /// Set when the current block exceeded [`DECODER_ACC_CAP`]: bytes are
    /// discarded until the next delimiter (resync).
    overflowing: bool,
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
            acc: Vec::new(),
            overflowing: false,
            queue: heapless::Deque::new(),
            dropped: 0,
        }
    }

    /// Consumes one chunk of raw USB bytes.
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            if byte == 0 {
                if self.overflowing {
                    // The delimiter closes an oversized garbage block.
                    self.overflowing = false;
                    self.dropped += 1;
                } else {
                    self.finish_block();
                }
                self.acc.clear();
            } else if self.overflowing {
                // Discarded until the delimiter resynchronizes the stream.
            } else if self.acc.len() == DECODER_ACC_CAP {
                // One more byte would exceed any legal block.
                self.overflowing = true;
            } else {
                // Cannot fail: capacity was checked one branch above.
                let _ = self.acc.push(byte);
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

    /// Decodes and enqueues the accumulated block (the delimiter arrived).
    fn finish_block(&mut self) {
        if self.acc.is_empty() {
            // Stray delimiter (idle pattern or post-resync): not an error.
            return;
        }
        let mut clear = [0u8; MAX_MSG_LEN];
        let decoded = cobs_decode(&self.acc, &mut clear).and_then(|len| parse_msg(&clear[..len]));
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
fn parse_msg(decoded: &[u8]) -> Result<Msg, Error> {
    if decoded.len() < 3 {
        return Err(Error::Malformed);
    }
    let (msg_bytes, crc_bytes) = decoded.split_at(decoded.len() - 2);
    let expected = u16::from_le_bytes([crc_bytes[0], crc_bytes[1]]);
    if crc16_ccitt_false(msg_bytes) != expected {
        return Err(Error::Crc);
    }
    let (ty, body) = msg_bytes.split_first().ok_or(Error::Malformed)?;
    match *ty {
        TYPE_RX => {
            if body.len() < 4 {
                return Err(Error::Malformed);
            }
            let len = body[3] as usize;
            if body.len() != 4 + len {
                return Err(Error::Malformed);
            }
            Ok(Msg::Rx {
                rssi: i16::from_le_bytes([body[0], body[1]]),
                snr: body[2] as i8,
                payload: Payload::from_slice(&body[4..]).map_err(|_| Error::Malformed)?,
            })
        }
        TYPE_TX_REQ => {
            let len = body.first().copied().ok_or(Error::Malformed)? as usize;
            if body.len() != 1 + len {
                return Err(Error::Malformed);
            }
            Ok(Msg::TxReq {
                payload: Payload::from_slice(&body[1..]).map_err(|_| Error::Malformed)?,
            })
        }
        TYPE_TX_RESULT => {
            let status = *body.first().ok_or(Error::Malformed)?;
            Ok(Msg::TxResult { status })
        }
        TYPE_PING if body.is_empty() => Ok(Msg::Ping),
        TYPE_PONG if body.is_empty() => Ok(Msg::Pong),
        _ => Err(Error::Malformed),
    }
}

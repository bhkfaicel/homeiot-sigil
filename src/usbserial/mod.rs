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
    /// Secure operation attempted before the HELLO handshake completed.
    NotEstablished,
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
    parse_body(*ty, body)
}

/// Parses one message body (type byte stripped, CRC already verified).
/// Shared by the plain decoder and the secure open path (the decrypted
/// plaintext has exactly this shape).
fn parse_body(ty: u8, body: &[u8]) -> Result<Msg, Error> {
    match ty {
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

// ======================= Secure profile (opt-in) ==========================
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
//   accepts strictly increasing counters only, and advances its watermark
//   only AFTER the tag verified (a forged huge counter cannot desync);
// - HELLO (0x06) travels clear (both directions, body = nonce[16]): it is
//   salt material, not a secret; authentication comes from the PSK through
//   the first sealed message.
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

/// Secure-profile handshake message (clear, body = `nonce[16]`).
pub const TYPE_HELLO: u8 = 0x06;
/// Length of one HELLO nonce.
pub const NONCE_LEN: usize = 16;
/// Length of the pre-shared key.
pub const PSK_LEN: usize = 32;
/// Poly1305 tag length appended to every sealed message.
pub const TAG_LEN: usize = 16;
/// Clear counter bytes prefixing every sealed message body.
pub const COUNTER_WIRE_LEN: usize = 8;

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
/// Worst-case wire frame of a sealed message.
pub const SECURE_MAX_FRAME_LEN: usize = SECURE_MAX_BLOCK_LEN + 1;
/// Worst-case wire frame of a HELLO: `1+16+2` clear, COBS + delimiter.
pub const HELLO_FRAME_MAX: usize = (NONCE_LEN + 3) + (NONCE_LEN + 3).div_ceil(254) + 1 + 1;

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
    ) -> Result<Self, Error> {
        let mut salt = [0u8; NONCE_LEN * 2];
        salt[..NONCE_LEN].copy_from_slice(host_nonce);
        salt[NONCE_LEN..].copy_from_slice(head_nonce);
        let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
        let mut okm = [0u8; OKM_LEN];
        hk.expand(HKDF_INFO, &mut okm).map_err(|_| Error::Crypto)?;
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

/// Handshake/channel state.
#[derive(Default)]
enum SecureState {
    /// Waiting for the peer HELLO (or a re-HELLO replacing a live session —
    /// last HELLO pair wins, no stale state survives a restart).
    #[default]
    AwaitingPeerHello,
    /// Keys derived; counters reset to zero (first sealed counter is 1).
    Established(DirectionalKeys),
}

/// PSK-authenticated secure channel over the framed USB-serial link.
///
/// Lifecycle: `new(role, psk, local_nonce)` → send [`SecureChannel::hello_frame`]
/// → `feed(peer bytes)` → once [`SecureChannel::is_established`], exchange
/// data with [`SecureChannel::seal`] / [`SecureChannel::pop`]. A late or
/// forged HELLO simply restarts the handshake (fresh keys, reset counters).
/// The PSK and derived keys never appear in `Debug` output and are zeroized
/// on drop.
pub struct SecureChannel {
    role: Role,
    psk: [u8; PSK_LEN],
    local_nonce: [u8; NONCE_LEN],
    state: SecureState,
    /// Counter of the last sealed message (0 = none sent this session).
    send_counter: u64,
    /// Highest accepted receive counter (0 = none accepted this session).
    recv_last: u64,
    /// Bytes of the current, not-yet-delimited block (same accumulator
    /// discipline as [`Decoder`]).
    acc: Vec<u8, DECODER_ACC_CAP>,
    overflowing: bool,
    dropped: u32,
    queue: heapless::Deque<Msg, DECODER_QUEUE_CAP>,
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
            send_counter: 0,
            recv_last: 0,
            acc: Vec::new(),
            overflowing: false,
            dropped: 0,
            queue: heapless::Deque::new(),
        }
    }

    /// `true` once a peer HELLO completed the key derivation.
    pub fn is_established(&self) -> bool {
        matches!(self.state, SecureState::Established(_))
    }

    /// Serializes the local HELLO frame (clear, COBS + delimiter). Sent on
    /// link open; the peer's HELLO completes the handshake.
    pub fn hello_frame(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < HELLO_FRAME_MAX {
            return Err(Error::Overrun);
        }
        let mut clear = [0u8; NONCE_LEN + 3];
        clear[0] = TYPE_HELLO;
        clear[1..1 + NONCE_LEN].copy_from_slice(&self.local_nonce);
        let end = 1 + NONCE_LEN;
        let crc = crc16_ccitt_false(&clear[..end]);
        clear[end..end + 2].copy_from_slice(&crc.to_le_bytes());
        let block_len = cobs_encode(&clear, out)?;
        out[block_len] = 0;
        Ok(block_len + 1)
    }

    /// Seals one data message into a complete wire frame. Requires an
    /// established session; every seal bumps the send counter.
    pub fn seal(&mut self, msg: &Msg, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < SECURE_MAX_FRAME_LEN {
            return Err(Error::Overrun);
        }
        if matches!(self.state, SecureState::AwaitingPeerHello) {
            return Err(Error::NotEstablished);
        }
        self.send_counter += 1;
        let counter = self.send_counter;
        let (key, prefix) = match &mut self.state {
            SecureState::Established(keys) => keys.send_half(self.role),
            SecureState::AwaitingPeerHello => return Err(Error::NotEstablished),
        };
        // Wire layout: [type][counter][ciphertext][tag][crc], then COBS.
        let mut clear = [0u8; SECURE_MAX_MSG_LEN];
        let body_len = msg.write_body(&mut clear);
        let mut block = [0u8; SECURE_MAX_MSG_LEN];
        block[0] = clear[0];
        block[1..1 + COUNTER_WIRE_LEN].copy_from_slice(&counter.to_be_bytes());
        block[1 + COUNTER_WIRE_LEN..1 + COUNTER_WIRE_LEN + body_len]
            .copy_from_slice(&clear[..body_len]);
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
            .map_err(|_| Error::Crypto)?;
        let end = 1 + COUNTER_WIRE_LEN + body_len + TAG_LEN;
        block[end - TAG_LEN..end].copy_from_slice(&tag);
        let crc = crc16_ccitt_false(&block[..end]);
        block[end..end + 2].copy_from_slice(&crc.to_le_bytes());
        let block_len = cobs_encode(&block[..end + 2], out)?;
        out[block_len] = 0;
        Ok(block_len + 1)
    }

    /// Consumes one chunk of raw USB bytes (HELLO handling, sealed frames,
    /// resync — same accumulator discipline as [`Decoder::feed`]).
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            if byte == 0 {
                if self.overflowing {
                    self.overflowing = false;
                    self.dropped += 1;
                } else {
                    self.finish_block();
                }
                self.acc.clear();
            } else if self.overflowing {
                // Discarded until the delimiter resynchronizes the stream.
            } else if self.acc.len() == DECODER_ACC_CAP {
                self.overflowing = true;
            } else {
                // Cannot fail: capacity was checked one branch above.
                let _ = self.acc.push(byte);
            }
        }
    }

    /// Pops the oldest opened message, if any.
    pub fn pop(&mut self) -> Option<Msg> {
        self.queue.pop_front()
    }

    /// Number of frames dropped (garbage, corrupt, oversize, replay,
    /// queue overflow) since construction.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// CRC-checks and routes one accumulated block.
    fn finish_block(&mut self) {
        if self.acc.is_empty() {
            return;
        }
        let mut clear = [0u8; SECURE_MAX_MSG_LEN];
        let len = match cobs_decode(&self.acc, &mut clear) {
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

    /// (Re)establishes the session from a peer HELLO; last HELLO pair wins.
    fn on_hello(&mut self, body: &[u8]) {
        let peer_nonce: [u8; NONCE_LEN] = match body.try_into() {
            Ok(nonce) => nonce,
            Err(_) => {
                self.dropped += 1;
                return;
            }
        };
        let (host_nonce, head_nonce) = match self.role {
            Role::Host => (&self.local_nonce, &peer_nonce),
            Role::Head => (&peer_nonce, &self.local_nonce),
        };
        match DirectionalKeys::derive(&self.psk, host_nonce, head_nonce) {
            Ok(keys) => {
                self.state = SecureState::Established(keys);
                // Fresh session: counters restart, stale state cannot leak.
                self.send_counter = 0;
                self.recv_last = 0;
            }
            Err(_) => self.dropped += 1,
        }
    }

    /// Opens one sealed data message: tag verification FIRST, then the
    /// strict replay check, then the watermark advance.
    ///
    /// `clear[0..len]` holds the CRC-checked wire message
    /// `[type][counter][ciphertext][tag][crc]`; the ciphertext is decrypted
    /// in place.
    fn on_sealed(&mut self, ty: u8, clear: &mut [u8; SECURE_MAX_MSG_LEN], len: usize) {
        let (key, prefix) = match &self.state {
            SecureState::Established(keys) => keys.recv_half(self.role),
            SecureState::AwaitingPeerHello => {
                self.dropped += 1;
                return;
            }
        };
        let body_start = 1 + COUNTER_WIRE_LEN;
        let body_end = len - 2; // strip CRC
        if body_end < body_start + TAG_LEN {
            self.dropped += 1;
            return;
        }
        let counter = u64::from_be_bytes(clear[1..body_start].try_into().expect("8 bytes"));
        let mut nonce = build_nonce(prefix, counter);
        let mut aad = [0u8; 1 + COUNTER_WIRE_LEN];
        aad[0] = ty;
        aad[1..].copy_from_slice(&counter.to_be_bytes());
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&clear[body_end - TAG_LEN..body_end]);
        let ct_end = body_end - TAG_LEN;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let open = cipher.decrypt_in_place_detached(
            &Nonce::from(nonce),
            &aad,
            &mut clear[body_start..ct_end],
            Tag::from_slice(&tag),
        );
        nonce.zeroize();
        if open.is_err() {
            // Wrong key or tampered frame: watermark untouched.
            self.dropped += 1;
            return;
        }
        if counter <= self.recv_last {
            // Replay (or late duplicate): watermark untouched.
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

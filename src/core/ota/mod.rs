//! OTA firmware-update transfer protocol (additive module).
//!
//! This module defines the wire contract and the two pure protocol engines
//! used to move a signed firmware image from an updating device (gateway
//! side) to the device being updated (sensor side). Frames travel as
//! ordinary authenticated AEAD `Data` payloads of an established sigil
//! session. The module implements no session cryptography of its own: it
//! computes SHA-256 digests (integrity) and delegates asymmetric
//! verification to the host secure element through the crate-wide
//! `SecureElement` trait; it owns no radio and no storage, and never
//! blocks.
//!
//! # Feature tiers (`cfg` gating)
//!
//! The single cargo feature `ota` composes with the existing role features:
//!
//! | Enabled features            | Compiled from this module                            |
//! |-----------------------------|------------------------------------------------------|
//! | *(without `ota`)*           | nothing                                              |
//! | `ota`                       | shared tier: command ids, frame codec, `manifest_digest`, `OtaError` |
//! | `sensor`, `ota`             | shared + receive half: `TrailerRecord`, `OtaStorage`, `OtaState`, `OtaReceiver` |
//! | `gateway`, `ota`            | shared + send half: `OtaImageSource`, `OtaSender`    |
//! | `sensor,gateway,ota`        | both halves (interop tests / SIL harness)            |
//!
//! A plain `sensor` or `gateway` build WITHOUT `ota` carries zero OTA code:
//! no feature implies another.
//!
//! # Wire contract (v1)
//!
//! Every OTA payload shares the product gateway-command envelope:
//!
//! ```text
//! [0x7F] [command_id] [body..]
//! ```
//!
//! Sender → receiver commands:
//!
//! | id     | name          | body                                                              |
//! |--------|---------------|-------------------------------------------------------------------|
//! | `0x10` | OTA_BEGIN     | version:u32BE ‖ img_len:u32BE ‖ chunk_len:u8 ‖ img_sha256:32 ‖ manifest_sig:64 |
//! | `0x11` | OTA_CHUNK     | seq:u16BE ‖ data(1..=196)                                        |
//! | `0x12` | OTA_FINALIZE  | —                                                                 |
//! | `0x13` | OTA_REBOOT    | delay_ms:u16BE                                                    |
//! | `0x14` | OTA_ABORT     | —                                                                 |
//!
//! Receiver → sender replies:
//!
//! | id     | name          | body                                                              |
//! |--------|---------------|-------------------------------------------------------------------|
//! | `0x15` | OTA_ACK_READY | accepted_chunk_len:u8                                             |
//! | `0x16` | OTA_ACK_CHUNK | next_seq:u16BE (cumulative contiguous acknowledgement)            |
//! | `0x17` | OTA_ACK_FINAL | result:u8 ([`FinalResult`])                                       |
//! | `0x18` | OTA_STATUS    | state:u8 ‖ next_seq:u16BE ‖ version:u32BE ‖ img_len:u32BE         |
//!
//! Bounds: a negotiated `chunk_len` is in `CHUNK_LEN_MIN..=CHUNK_LEN_MAX`
//! (64..=196; 196 = product Data payload bound minus envelope/seq overhead).
//! Individual chunk payloads are 1..=`CHUNK_LEN_MAX` bytes (the last chunk
//! may be short). `img_len` must be non-zero; the host-supplied staging
//! capacity bound is enforced by the engines, not by this codec.
//!
//! # Image authenticity and freshness (trust chain)
//!
//! `manifest_sig` is an ECDSA P-256 signature (64-byte `r‖s`) over
//! [`manifest_digest`] with the factory root key. Manifest v2 BINDS the
//! target identity — product id AND hardware profile byte, mirroring the
//! install factory certificate — into the signed material, so an image
//! validly signed for another product or incompatible board sharing the
//! same factory root fails here.
//!
//! Verification ordering (fail-closed, cheapest-reject-first):
//! 1. BEGIN authenticates the manifest through the host secure element
//!    ([`SecureElement::verify_ecdsa`](crate::core::traits::SecureElement::verify_ecdsa))
//!    BEFORE any staging flash access — invalid signatures never open a
//!    session and never spend erase/write cycles;
//! 2. BEGIN refuses strictly older versions than the host-configured
//!    rollback floor (`VersionRejected`; the host persists that floor in
//!    rollback-resistant storage and raises it after every completed
//!    update);
//! 3. chunks stream under AEAD session protection with incremental SHA-256;
//! 4. FINALIZE proves the staged bytes match the authenticated digest and
//!    ONLY THEN writes the bootable marker.
//!
//!    Apply-time re-verification by a hash-checking bootloader remains the
//!    host's last line of defense and lives outside this crate.
//!
//! # Host authorization requirements
//!
//! One [`crate::core::ota::OtaReceiver`] instance must be bound to exactly
//! ONE authorized peer: route decrypted OTA Data into the engine only when
//! the outer PeerId matches the enrolled gateway this receiver serves. The
//! engine carries no peer identity itself; multi-gateway products must
//! instantiate one receiver per authorized gateway and enforce that routing
//! BEFORE invocation. Admission pacing (per-peer/global airtime budgets,
//! flash-wear limits) also stays host policy: authentication alone cannot
//! stop a malicious legitimate gateway from repeatedly offering transfers.

#[cfg(feature = "ota")]
pub mod error;
#[cfg(feature = "ota")]
pub mod wire;

// Receive half: additionally requires the `sensor` role.
#[cfg(all(feature = "ota", feature = "sensor"))]
pub mod receiver;
#[cfg(all(feature = "ota", feature = "sensor"))]
pub mod storage;
#[cfg(all(feature = "ota", feature = "sensor"))]
pub mod trailer;

// Send half: additionally requires the `gateway` role.
#[cfg(all(feature = "ota", feature = "gateway"))]
pub mod image;
#[cfg(all(feature = "ota", feature = "gateway"))]
pub mod sender;

#[cfg(feature = "ota")]
pub use error::OtaError;
// Root-level re-exports of the shared wire tier: hosts and the module docs
// reference these types directly, and intra-doc links resolve through them.
#[cfg(all(feature = "ota", feature = "sensor"))]
pub use receiver::{OtaReceiver, Reply, RxOutcome, TickOutcome};
#[cfg(all(feature = "ota", feature = "gateway"))]
pub use sender::{OtaSender, SenderAction, TransferEnd, TxFrame};
#[cfg(feature = "ota")]
pub use wire::{
    BeginFrame, ChunkFrame, FinalResult, OtaCommand, PeerState, StatusFrame, manifest_digest,
    manifest_digest_input,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

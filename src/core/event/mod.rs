//! Event and action types for non-blocking protocol operations
//!
//! This module defines the types used to communicate between the sigil core
//! and the host firmware in a non-blocking manner.
//!
//! # Configurable buffer sizes
//!
//! Both [`SigilEvent`] and [`SigilAction`] are generic over compile-time
//! capacities so the host can match the underlying transport's maximum payload
//! (e.g. LoRa EU868 at SF7 allows ~222 bytes, Sigfox only 12 bytes).
//!
//! [`DATA_MAX`] and [`MSG_MAX`] provide sensible defaults for standard LoRa
//! and are used throughout the crate's internal pipeline.
//!
//! decrypted application payloads use `DATA`; raw handshake frames
//! use `MSG`. Do not size `DATA` for install wire lengths — `InstallChallenge`
//! is 219 bytes while a typical LoRa data plaintext max is ~200.

use crate::core::session::PeerId;
use heapless::Vec;

/// Default maximum **decrypted** application payload size (excluding framing).
/// Suitable for LoRa EU868 at spreading factor SF7 or lower. This is **not**
/// the capacity for raw handshake frames — those use [`MSG_MAX`].
pub const DATA_MAX: usize = 200;

/// Default maximum **wire** message size (full frames including outer header).
/// Must be large enough for the largest handshake frame (`InstallChallenge` =
/// 219 bytes). Accounts for framing overhead above [`DATA_MAX`] on the data
/// path and is the capacity used for handshake frames in [`SigilEvent`].
pub const MSG_MAX: usize = 256;

/// Events returned to the host after processing incoming packets
/// The `Data` variant carries already-decrypted application data. Handshake
/// variants are **per-step classifications**: the core identifies the
/// exact [`crate::core::frame::FrameType`] and hands the raw frame back so the
/// host can call the matching `handle_*` or `continue_*` API — without guessing
/// from a catch-all `*Request` name.
/// # Type parameters
/// * `DATA` — maximum decrypted application payload size
/// * `MSG` — maximum raw frame size for handshake classification buffers
///   (must fit `InstallChallenge` = 219 bytes when using install; [`MSG_MAX`]
///   is the recommended default)
///
/// For standard LoRa, use `SigilEvent<DATA_MAX, MSG_MAX>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigilEvent<const DATA: usize, const MSG: usize> {
    /// Decrypted application data received from peer
    Data {
        /// Peer identifier
        peer: PeerId,
        /// Decrypted payload
        payload: Vec<u8, DATA>,
    },

    /// Authenticated reliable sensor Event. The gateway must durably process
    /// the payload only when `duplicate == false`, then call
    /// [`SessionManager::ack_event`](crate::core::manager::SessionManager::ack_event).
    /// Duplicate Events must not repeat the side effect, but should be ACKed
    /// again so a sensor can recover from ACK loss.
    Event {
        /// Sensor peer identifier.
        peer: PeerId,
        /// Host-assigned monotonic Event identifier.
        event_id: u64,
        /// Decrypted application payload (the id prefix is removed).
        payload: Vec<u8, DATA>,
        /// True only when this id was already committed through `ack_event`
        /// (typically ACK loss/retry). A retry received while the first
        /// delivery is still pending returns `EventDeliveryPending` instead.
        duplicate: bool,
    },

    /// Authenticated Event acknowledgement received by the sensor.
    EventAck {
        /// Gateway peer identifier.
        peer: PeerId,
        /// Event identifier acknowledged by the gateway.
        event_id: u64,
    },

    /// Authenticated gateway clock sample (AEAD + shared replay counter).
    TimeSync {
        /// Gateway peer that produced the sample.
        peer: PeerId,
        /// Gateway wall-clock seconds.
        gateway_time: u32,
        /// Monotonic sequence selected by the gateway host.
        sync_sequence: u32,
        /// Estimated clock/radio uncertainty in seconds.
        uncertainty_secs: u16,
    },

    /// Authenticated sensor request for a fresh gateway clock sample.
    /// The gateway host decides whether to answer and sends the existing
    /// [`Self::TimeSync`] frame through `SessionManager::encrypt_time_sync`.
    TimeSyncRequest {
        /// Sensor peer requesting synchronization.
        peer: PeerId,
    },

    /// Install **request** (`FrameType::InstallRequest`) — gateway: allowlist then
    /// [`SessionManager::handle_install_request`](crate::core::manager::SessionManager::handle_install_request).
    InstallRequest {
        /// Sender peer identifier (outer header MAC = sensor)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Install **challenge** — sensor: [`SessionManager::continue_install`](crate::core::manager::SessionManager::continue_install).
    InstallChallenge {
        /// Sender peer identifier (outer header MAC = gateway)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Install **confirm** — gateway: [`SessionManager::continue_install`](crate::core::manager::SessionManager::continue_install).
    InstallConfirm {
        /// Sender peer identifier (outer header MAC = sensor)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Renew **request** — gateway: [`SessionManager::handle_renew_request`](crate::core::manager::SessionManager::handle_renew_request).
    RenewRequest {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Renew **challenge** — sensor: [`SessionManager::continue_renew`](crate::core::manager::SessionManager::continue_renew).
    RenewChallenge {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Renew **ack** — gateway: [`SessionManager::continue_renew`](crate::core::manager::SessionManager::continue_renew).
    RenewAck {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Resume **request** — gateway: [`SessionManager::handle_resume_request`](crate::core::manager::SessionManager::handle_resume_request).
    ResumeRequest {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Resume **challenge** — sensor: [`SessionManager::continue_resume`](crate::core::manager::SessionManager::continue_resume).
    ResumeChallenge {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Resume **confirm** — gateway: [`SessionManager::continue_resume`](crate::core::manager::SessionManager::continue_resume).
    ResumeConfirm {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Install **CommitConfirmed** — sensor:
    /// [`SessionManager::continue_install`](crate::core::manager::SessionManager::continue_install).
    InstallCommitConfirmed {
        /// Sender peer identifier (outer header MAC = gateway)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Renew **CommitConfirmed** — sensor:
    /// [`SessionManager::continue_renew`](crate::core::manager::SessionManager::continue_renew).
    RenewCommitConfirmed {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },

    /// Resume **CommitConfirmed** — sensor:
    /// [`SessionManager::continue_resume`](crate::core::manager::SessionManager::continue_resume).
    ResumeCommitConfirmed {
        /// Peer identifier (sender)
        peer: PeerId,
        /// Raw frame bytes (including outer header)
        frame: Vec<u8, MSG>,
    },
}

/// Actions that the host should take after processing a packet
/// These actions are returned by the core to instruct the host on what to do next,
/// such as transmitting a packet or persisting enrollment material.
/// Generic over `MSG` — the maximum outgoing message size in bytes.
/// For standard LoRa, use `SigilAction<MSG_MAX>`. For compact transports
/// (e.g. Sigfox), specify a smaller capacity such as `SigilAction<64>`.
/// # Radio wait contract
/// Advisory handshake and Event-ACK waits are carried on
/// [`Self::Transmit::wait_timeout_ms`] (`Some` = start a host timer after TX).
/// There is no separate wait-only action: the library always pairs a wait hint
/// with a frame to send (or returns [`Self::Success`] /
/// [`Self::PersistPeerStaticKey`] when no further TX is needed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigilAction<const MSG: usize> {
    /// Transmit a packet to the specified peer.
    /// When [`Self::Transmit::wait_timeout_ms`] is `Some`, the host should start
    /// a timer for that duration after TX. Handshakes use
    /// [`SessionManager::cancel_pending`](crate::core::manager::SessionManager::cancel_pending);
    /// reliable Events use `send_event` again with the exact same id/payload,
    /// or `cancel_pending_event` after the retry budget is exhausted.
    Transmit {
        /// Destination peer identifier (remote MAC for host radio routing)
        dest: PeerId,
        /// Payload to transmit (outer header already carries **local** sender MAC)
        payload: Vec<u8, MSG>,
        /// Advisory radio wait after this TX (`None` = no reply expected).
        /// Elapsing this duration does **not** clear pending state by itself.
        wait_timeout_ms: Option<u32>,
    },

    /// Handshake frame was **classified** only — host must route via `handle_*` /
    /// `continue_*` using the paired [`SigilEvent`] step variant.
    /// This is **not** protocol success. Do not treat it like [`Self::Success`].
    NeedsHostDispatch {
        /// Peer identifier (sender MAC from the classified frame)
        peer: PeerId,
    },

    /// Operation completed successfully (no further TX required).
    /// Used e.g. when the gateway finalizes renew/resume after decrypting the
    /// peer's last handshake frame — **not** returned from classification alone.
    Success {
        /// Peer identifier
        peer: PeerId,
    },

    /// Persist **enrollment only** to NVRAM (install success).
    /// Hosts must store `peer` + `pubkey` + `resume_psk` (+ local [`SessionRole`](crate::core::SessionRole))
    /// and reload via [`Session::new_enrolled`](crate::core::Session::new_enrolled).
    /// **Never** persist AEAD session keys, nonce prefixes, or counters.
    /// # follow-up TX
    /// When [`Self::PersistPeerStaticKey::transmit`] is non-empty (install
    /// **gateway** after Final), the host must TX that CommitConfirmed frame
    /// **after** writing NVRAM, using `peer` as the radio destination and
    /// [`Self::PersistPeerStaticKey::wait_timeout_ms`] as the advisory wait.
    /// Sensor CommitConfirmed completion uses an empty `transmit` (persist only).
    PersistPeerStaticKey {
        /// Peer identifier
        peer: PeerId,
        /// Peer's static public key to persist
        pubkey: [u8; 33],
        /// Durable resume-request PSK (persist with the pubkey; required after reboot)
        resume_psk: [u8; 32],
        /// Optional CommitConfirmed frame to TX after NVRAM persist.
        /// Empty = persist only (no further radio TX).
        transmit: Vec<u8, MSG>,
        /// Advisory radio wait when `transmit` is non-empty.
        wait_timeout_ms: Option<u32>,
    },
}

mod tests;

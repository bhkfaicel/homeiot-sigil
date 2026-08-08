//! Session management for peer communication
//!
//! This module defines the `Session` struct which represents the cryptographic state
//! for a single peer, including keys, counters, and expiry information.
//!
//! # Directional AEAD
//!
//! Each active session holds **independent** TX and RX key material. Both peers
//! share the same [`DirectionalMaterial`] transcript; [`SessionRole`] maps
//! sensor→gateway / gateway→sensor halves onto local TX vs RX so the two
//! directions never share a `(key, nonce)` space.
//!
//! # Persistence
//!
//! **Never** persist active AEAD keys / nonce prefixes / counters to NVRAM.
//! After reboot the host must load only enrollment
//! `(peer_mac, peer_static_pubkey, resume_psk, role)` via [`Session::new_enrolled`]
//! and run Resume to derive fresh directional keys. Restoring a live key with
//! counters reset to 0 reuses ChaCha20 nonces.
//! Reliable Event ids and gateway deduplication state are also host-owned
//! durable data: the fields cached in a live `Session` are RAM-only.

use crate::core::error::SigilError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Peer identifier using the existing 17-byte MAC format
pub type PeerId = [u8; 17];

/// Static public key for a peer (33-byte P-256 compressed SEC1 format)
pub type StaticPublicKeyBytes = [u8; 33];

/// Session key (32-byte ChaCha20-Poly1305 key, RAM only)
pub type SessionKey = [u8; 32];

/// Nonce prefix (4 bytes, fixed for lifetime of current session key)
pub type NoncePrefix = [u8; 4];

/// Durable resume proof secret (32 bytes), derived at install.
pub type ResumePsk = [u8; 32];

/// Maximum allowed session-key lifetime in **seconds**.
pub const MAX_SESSION_LIFETIME_SECS: u32 = 2 * 86_400;

/// Validates an authenticated session lifetime.
pub fn validate_key_lifetime(lifetime_secs: u32) -> Result<(), SigilError> {
    if lifetime_secs == 0 || lifetime_secs > MAX_SESSION_LIFETIME_SECS {
        return Err(SigilError::InvalidKeyLifetime { lifetime_secs });
    }
    Ok(())
}

/// Converts a wire lifetime to a local absolute expiry without requiring the
/// sensor and gateway wall clocks to be synchronized.
pub(crate) fn expire_from_lifetime(now: u32, lifetime_secs: u32) -> Result<u32, SigilError> {
    validate_key_lifetime(lifetime_secs)?;
    now.checked_add(lifetime_secs)
.ok_or(SigilError::InvalidKeyLifetime { lifetime_secs })
}

/// Local role in a pairwise session (immutable for the session lifetime).
/// Determines how [`DirectionalMaterial`] maps onto TX / RX AEAD keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// This device initiates renew / resume and uses the sensor→gateway TX half.
    #[cfg(feature = "sensor")]
    Sensor,
    /// This device responds and uses the gateway→sensor TX half.
    #[cfg(feature = "gateway")]
    Gateway,
}

/// Shared directional AEAD material derived after ECDH.
/// Both peers store the same transcript values; [`SessionRole`] selects which
/// half is used for local encrypt vs decrypt.
/// **Crate-internal**: hosts must not construct or persist this
/// type. Fresh material comes only from install / renew / resume.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct DirectionalMaterial {
    /// Sensor → gateway AEAD key
    pub s2g_key: SessionKey,
    /// Sensor → gateway nonce prefix
    pub s2g_prefix: NoncePrefix,
    /// Gateway → sensor AEAD key
    pub g2s_key: SessionKey,
    /// Gateway → sensor nonce prefix
    pub g2s_prefix: NoncePrefix,
}

impl DirectionalMaterial {
    /// Builds material with **identical** halves (unit-test loopback only).
    /// Production paths must use [`crate::core::derive::derive_directional_session_keys`].
    #[cfg(test)]
    pub(crate) fn symmetric_for_test(key: SessionKey, prefix: NoncePrefix) -> Self {
        Self {
            s2g_key: key,
            s2g_prefix: prefix,
            g2s_key: key,
            g2s_prefix: prefix,
        }
    }

    /// Builds material with distinct halves from a base key/prefix (unit tests).
    #[cfg(test)]
    pub(crate) fn distinct_for_test(key: SessionKey, prefix: NoncePrefix) -> Self {
        let mut g2s_key = key;
        g2s_key[0] ^= 0xA5;
        let mut g2s_prefix = prefix;
        g2s_prefix[0] ^= 0x5A;
        Self {
            s2g_key: key,
            s2g_prefix: prefix,
            g2s_key,
            g2s_prefix,
        }
    }
}

/// Validates a host- or peer-advertised `key_expire_at` against `now`.
pub fn validate_key_expire_at(now: u32, key_expire_at: u32) -> Result<(), SigilError> {
    if key_expire_at <= now {
        return Err(SigilError::InvalidKeyExpire { now, key_expire_at });
    }
    let lifetime = key_expire_at.saturating_sub(now);
    if lifetime > MAX_SESSION_LIFETIME_SECS {
        return Err(SigilError::InvalidKeyExpire { now, key_expire_at });
    }
    Ok(())
}

/// Session state for a single peer
/// # Directional AEAD
/// Active sessions store separate TX and RX keys/prefixes. Encrypt paths use
/// TX material; decrypt paths use RX material and check the wire prefix.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Session {
    /// Peer identifier (lookup key)
    pub peer_mac: PeerId,

    /// Peer's static public key (durable identity, also stored in host NVRAM)
    pub peer_static_pubkey: StaticPublicKeyBytes,

    /// Local role (maps directional transcript → TX/RX)
    #[zeroize(skip)]
    pub(crate) role: SessionRole,

    /// Outbound AEAD key (None after reboot until renew/resume/install)
    pub(crate) tx_key: Option<SessionKey>,

    /// Outbound nonce prefix
    pub(crate) tx_prefix: Option<NoncePrefix>,

    /// Inbound AEAD key
    pub(crate) rx_key: Option<SessionKey>,

    /// Inbound nonce prefix (must match wire prefix on decrypt)
    pub(crate) rx_prefix: Option<NoncePrefix>,

    /// Durable resume-request MAC key (set at install; survives key rotation)
    pub(crate) resume_psk: Option<ResumePsk>,

    /// Local outbound AEAD counter
    pub(crate) tx_counter: u64,

    /// Last accepted / next expected inbound counter
    pub(crate) rx_counter: u64,

    /// Key expiry timestamp in **seconds** (absolute, compared to `now`)
    pub(crate) key_expire_at: u32,

    /// Stamp (seconds) of the last accepted gateway `ResumeRequest` ECDH.
    #[cfg(feature = "gateway")]
    pub(crate) last_resume_request_at: Option<u32>,

    /// Stamp (seconds) of the last authenticated TimeSyncRequest accepted by
    /// this gateway session. Used only for cheap per-peer response throttling.
    #[cfg(feature = "gateway")]
    pub(crate) last_time_sync_request_at: Option<u32>,

    /// Event currently awaiting an authenticated EventAck (sensor side).
    #[cfg(feature = "sensor")]
    pub(crate) pending_tx_event_id: Option<u64>,

    /// Greatest Event id started by this session (prevents accidental reuse).
    #[cfg(feature = "sensor")]
    pub(crate) last_tx_event_id: Option<u64>,

    /// Greatest Event id delivered by this session (gateway deduplication).
    #[cfg(feature = "gateway")]
    pub(crate) last_rx_event_id: Option<u64>,

    /// New Event received but not yet durably processed/ACKed by the gateway.
    #[cfg(feature = "gateway")]
    pub(crate) pending_rx_event_id: Option<u64>,
}

impl Session {
    fn apply_directional(
        role: SessionRole,
        material: &DirectionalMaterial,
    ) -> (SessionKey, NoncePrefix, SessionKey, NoncePrefix) {
        match role {
            #[cfg(feature = "sensor")]
            SessionRole::Sensor => (
                material.s2g_key,
                material.s2g_prefix,
                material.g2s_key,
                material.g2s_prefix,
            ),
            #[cfg(feature = "gateway")]
            SessionRole::Gateway => (
                material.g2s_key,
                material.g2s_prefix,
                material.s2g_key,
                material.s2g_prefix,
            ),
        }
    }

    /// Creates a new session without an active session key (post-reboot API).
    /// # Persistence
    /// This is the **only** public constructor hosts should use after loading
    /// NVRAM. Persist and restore **only** enrollment:
    /// `peer_mac`, `peer_static_pubkey`, `resume_psk`, and [`SessionRole`].
    /// Do **not** persist AEAD keys, nonce prefixes, or counters — after boot
    /// call Resume to derive fresh directional material.
    pub fn new_enrolled(
        peer_mac: PeerId,
        peer_static_pubkey: StaticPublicKeyBytes,
        resume_psk: ResumePsk,
        key_expire_at: u32,
        role: SessionRole,
    ) -> Self {
        Self {
            peer_mac,
            peer_static_pubkey,
            role,
            tx_key: None,
            tx_prefix: None,
            rx_key: None,
            rx_prefix: None,
            resume_psk: Some(resume_psk),
            tx_counter: 0,
            rx_counter: 0,
            key_expire_at,
            #[cfg(feature = "gateway")]
            last_resume_request_at: None,
            #[cfg(feature = "gateway")]
            last_time_sync_request_at: None,
            #[cfg(feature = "sensor")]
            pending_tx_event_id: None,
            #[cfg(feature = "sensor")]
            last_tx_event_id: None,
            #[cfg(feature = "gateway")]
            last_rx_event_id: None,
            #[cfg(feature = "gateway")]
            pending_rx_event_id: None,
        }
    }

    /// Creates a session with active directional AEAD keys (install path).
    /// **Crate-internal**: not part of the host API. Counters
    /// always start at 0, so restoring persisted keys through this constructor
    /// would reuse nonces. Hosts must use [`Self::new_enrolled`] + Resume.
    pub(crate) fn new_active(
        peer_mac: PeerId,
        peer_static_pubkey: StaticPublicKeyBytes,
        material: DirectionalMaterial,
        role: SessionRole,
        resume_psk: ResumePsk,
        key_expire_at: u32,
        now: u32,
    ) -> Result<Self, SigilError> {
        validate_key_expire_at(now, key_expire_at)?;
        let (tx_key, tx_prefix, rx_key, rx_prefix) = Self::apply_directional(role, &material);
        Ok(Self {
            peer_mac,
            peer_static_pubkey,
            role,
            tx_key: Some(tx_key),
            tx_prefix: Some(tx_prefix),
            rx_key: Some(rx_key),
            rx_prefix: Some(rx_prefix),
            resume_psk: Some(resume_psk),
            tx_counter: 0,
            rx_counter: 0,
            key_expire_at,
            #[cfg(feature = "gateway")]
            last_resume_request_at: None,
            #[cfg(feature = "gateway")]
            last_time_sync_request_at: None,
            #[cfg(feature = "sensor")]
            pending_tx_event_id: None,
            #[cfg(feature = "sensor")]
            last_tx_event_id: None,
            #[cfg(feature = "gateway")]
            last_rx_event_id: None,
            #[cfg(feature = "gateway")]
            pending_rx_event_id: None,
        })
    }

    /// Returns a reference to the outbound session key, if any.
    pub fn session_key(&self) -> Option<&SessionKey> {
        self.tx_key.as_ref()
    }

    /// Returns a reference to the inbound session key, if any.
    pub fn rx_session_key(&self) -> Option<&SessionKey> {
        self.rx_key.as_ref()
    }

    /// Returns a reference to the outbound nonce prefix, if any.
    pub fn nonce_prefix(&self) -> Option<&NoncePrefix> {
        self.tx_prefix.as_ref()
    }

    /// Returns the inbound nonce prefix (wire prefix expected on decrypt).
    pub fn rx_nonce_prefix(&self) -> Option<&NoncePrefix> {
        self.rx_prefix.as_ref()
    }

    /// Returns the session role.
    pub fn role(&self) -> SessionRole {
        self.role
    }

    /// Returns a reference to the durable resume PSK, if enrolled.
    pub fn resume_psk(&self) -> Option<&ResumePsk> {
        self.resume_psk.as_ref()
    }

    /// Returns the outbound AEAD counter.
    pub fn tx_counter(&self) -> u64 {
        self.tx_counter
    }

    /// Returns the next-expected inbound AEAD counter.
    pub fn rx_counter(&self) -> u64 {
        self.rx_counter
    }

    /// Returns the Event id currently waiting for EventAck, if any.
    #[cfg(feature = "sensor")]
    pub fn pending_event_id(&self) -> Option<u64> {
        self.pending_tx_event_id
    }

    /// Returns the absolute key expiry timestamp (**seconds**, same as `now`).
    pub fn key_expire_at(&self) -> u32 {
        self.key_expire_at
    }

    /// Checks if the session has an active (non-expired) session key
    pub fn is_active(&self, now: u32) -> bool {
        self.tx_key.is_some() && !self.is_expired(now)
    }

    /// Checks if the session key has expired
    pub fn is_expired(&self, now: u32) -> bool {
        now >= self.key_expire_at
    }

    /// TX key + prefix for encrypt.
    pub(crate) fn require_tx_material(
        &self,
        peer: &PeerId,
    ) -> Result<(&SessionKey, &NoncePrefix), SigilError> {
        match (&self.tx_key, &self.tx_prefix) {
            (Some(key), Some(prefix)) => Ok((key, prefix)),
            _ => Err(SigilError::SessionNotActive { peer: *peer }),
        }
    }

    /// RX key + prefix for decrypt.
    pub(crate) fn require_rx_material(
        &self,
        peer: &PeerId,
    ) -> Result<(&SessionKey, &NoncePrefix), SigilError> {
        match (&self.rx_key, &self.rx_prefix) {
            (Some(key), Some(prefix)) => Ok((key, prefix)),
            _ => Err(SigilError::SessionNotActive { peer: *peer }),
        }
    }

    /// Legacy alias: TX material (encrypt / renew-request paths).
    pub(crate) fn require_key_material(
        &self,
        peer: &PeerId,
    ) -> Result<(&SessionKey, &NoncePrefix), SigilError> {
        self.require_tx_material(peer)
    }

    /// Returns the resume PSK required to MAC / verify `ResumeRequest`.
    pub(crate) fn require_resume_psk(&self) -> Result<ResumePsk, SigilError> {
        self.resume_psk.ok_or(SigilError::InvalidStaticKey)
    }

    /// Updates directional AEAD keys and resets counters (install/renew/resume).
    /// **Crate-internal**: hosts must not call this to restore
    /// NVRAM key material. Key rotation happens only inside handshake handlers.
    pub(crate) fn update_key(
        &mut self,
        material: DirectionalMaterial,
        key_expire_at: u32,
        now: u32,
    ) -> Result<(), SigilError> {
        validate_key_expire_at(now, key_expire_at)?;
        let (tx_key, tx_prefix, rx_key, rx_prefix) = Self::apply_directional(self.role, &material);
        if let Some(mut old) = self.tx_key.take() {
            old.zeroize();
        }
        if let Some(mut old) = self.tx_prefix.take() {
            old.zeroize();
        }
        if let Some(mut old) = self.rx_key.take() {
            old.zeroize();
        }
        if let Some(mut old) = self.rx_prefix.take() {
            old.zeroize();
        }
        self.tx_key = Some(tx_key);
        self.tx_prefix = Some(tx_prefix);
        self.rx_key = Some(rx_key);
        self.rx_prefix = Some(rx_prefix);
        self.tx_counter = 0;
        self.rx_counter = 0;
        self.key_expire_at = key_expire_at;
        Ok(())
    }

    /// Clears a **soft-expired** session key while keeping enrollment.
    pub fn clear_expired_key(&mut self, now: u32) -> Result<(), SigilError> {
        if self.tx_key.is_none() {
            return Ok(());
        }
        if !self.is_expired(now) {
            return Err(SigilError::SessionAlreadyActive {
                peer: self.peer_mac,
            });
        }
        if let Some(mut old) = self.tx_key.take() {
            old.zeroize();
        }
        if let Some(mut old) = self.tx_prefix.take() {
            old.zeroize();
        }
        if let Some(mut old) = self.rx_key.take() {
            old.zeroize();
        }
        if let Some(mut old) = self.rx_prefix.take() {
            old.zeroize();
        }
        self.tx_counter = 0;
        self.rx_counter = 0;
        Ok(())
    }

    /// Records that a resume request was accepted at `now` (host timebase).
    #[cfg(feature = "gateway")]
    pub(crate) fn mark_resume_request(&mut self, now: u32) {
        self.last_resume_request_at = Some(now);
    }

    /// Returns `true` if another resume ECDH is allowed at `now` given `cooldown`.
    #[cfg(feature = "gateway")]
    pub(crate) fn resume_cooldown_elapsed(&self, now: u32, cooldown: u32) -> bool {
        match self.last_resume_request_at {
            None => true,
            Some(last) => now.saturating_sub(last) >= cooldown,
        }
    }
}

mod tests;

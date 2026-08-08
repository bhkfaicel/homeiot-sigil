//! Session manager with fixed capacity
//!
//! This module provides the `SessionManager<N>` type which manages a fixed-capacity
//! table of sessions keyed by peer identifier.

use crate::core::error::SigilError;
use crate::core::event::{SigilAction, SigilEvent};
use crate::core::pending::PendingHandshake;
use crate::core::session::{PeerId, Session};
use crate::core::traits::{RandomSource, SecureElement, StaticPublicKey};
use heapless::FnvIndexMap;

/// Default capacity for sensor devices (single active peer).
/// `heapless::FnvIndexMap` (v0.8) requires the capacity to be a power of two
/// **and** at least 2, so the sensor default is 2 (smallest valid power of two).
/// Logically the sensor still tracks a single peer; the extra slot is unused.
/// See the [`heapless` documentation](https://docs.rs/heapless/) and the
/// `SessionManager` type-level docs for the power-of-two constraint.
pub const SENSOR_CAPACITY: usize = 2;

/// Default capacity for gateway devices (multiple peers).
/// `heapless::FnvIndexMap` (v0.8) requires the capacity to be a power of two,
/// so the gateway default is 128 (next power of two above the target of ~100 peers).
/// See the [`heapless` documentation](https://docs.rs/heapless/) and the
/// `SessionManager` type-level docs for the power-of-two constraint.
pub const GATEWAY_CAPACITY: usize = 128;

/// Session manager with fixed capacity.
/// Manages a fixed-capacity table of sessions keyed by peer identifier.
/// Also tracks in-progress handshakes per peer.
/// # Capacity constraint: power of two and `>= 2`
/// `N` must be a power of two (1, 2, 4, 8, 16, 32, 64, 128, …) **and** at
/// least 2. This is enforced at compile time by the underlying
/// [`heapless::FnvIndexMap`](https://docs.rs/heapless/latest/heapless/struct.FnvIndexMap.html)
/// (v0.8). `SessionManager<1>` will **not** compile (const-eval overflow in
/// `heapless`). Use `SessionManager<2>` for single-peer devices.
/// `FnvIndexMap` is intentional: peer lookup is O(1) hashed access rather
/// than a linear scan over the table (important on gateways with many
/// sessions). The unused second slot on a sensor (`N=2`) is an accepted
/// RAM trade-off for that uniform fast path.
/// # Factory root of trust
/// At construction the host supplies the **factory public key** (compressed
/// P-256). That root is cached in RAM and used during install to verify that
/// a peer's static public key was signed by the same factory — without
/// querying the ATECC on every install. The host typically reads the root
/// once at boot from the secure element or NVRAM.
/// MAC allowlisting ("should this device be paired?") remains a **host**
/// policy decision after [`Self::process_incoming_packet`] returns
/// [`SigilEvent::InstallRequest`]; the manager only enforces cryptographic
/// factory attestation.
/// # Host global rate-limit
/// Library DoS guards are **per-peer** only (`INSTALL_REQUEST_COOLDOWN`,
/// `RESUME_REQUEST_COOLDOWN`, `PendingAlreadyExists`). The `pending` map has
/// the **same capacity `N`** as `sessions` but is a **separate** table: a flood
/// of distinct peers can fill every pending slot and block further
/// install/renew/resume while existing sessions still decrypt data.
/// **Gateway hosts MUST enforce a global handshake admission policy** before
/// calling `handle_install_request` / `handle_resume_request` / renew handlers
/// — for example a token bucket or max concurrent pending across all peers.
/// Allowlisting alone is not enough if many allowlisted MACs can be spoofed or
/// if install discovery accepts many factory-attested peers. See CLAUDE.md /
/// `contracts/session-api.md` ("Host global rate-limit").
/// # Example
/// ```
/// use sigil::core::manager::SessionManager;
/// // Host loads the factory root once at boot (from ATECC / NVRAM).
/// let factory_pubkey = [0x02u8; 33];
/// let sensor_mac = [0x01u8; 17];
/// let gateway_mac = [0xAAu8; 17];
/// // Sensor: local_mac = this device; sessions keyed by gateway MAC.
/// let _sensor: SessionManager<2> = SessionManager::new(factory_pubkey, sensor_mac);
/// // Gateway: local_mac = this device; sessions keyed by each sensor MAC.
/// let _gateway: SessionManager<128> = SessionManager::new(factory_pubkey, gateway_mac);
/// ```
/// All storage is RAM-only; the host owns NVRAM persistence of static keys.
/// # Identity model (multi-peer)
/// - **`local_mac`**: this device's durable 17-byte identity. Every **egress**
///   frame's outer header carries `local_mac` (sender identity).
/// - **Session table key**: the **remote** peer MAC (gateway MAC on a sensor;
///   sensor MAC on a gateway).
/// - **Ingress**: `process_incoming_packet` reads the outer header as the
///   remote sender identity — suitable for install allowlisting on a gateway.
pub struct SessionManager<const N: usize> {
    /// Sessions keyed by **remote** peer identifier
    sessions: FnvIndexMap<PeerId, Session, N>,

    /// In-progress handshakes keyed by **remote** peer identifier
    pending: FnvIndexMap<PeerId, PendingHandshake, N>,

    /// Last accepted install SE work timestamp (**seconds**) per peer.
    /// Used with [`crate::core::install::INSTALL_REQUEST_COOLDOWN`] so a flood of
    /// `InstallRequest` frames cannot re-drive ATECC ECDH for the same MAC
    /// within the cooldown window.
    #[cfg(feature = "gateway")]
    install_last_at: FnvIndexMap<PeerId, u32, N>,

    /// Factory root public key (compressed P-256 SEC1).
    /// Used to verify peer factory certificates during install. Public and
    /// stable for the whole fleet; never taken from an on-air packet.
    factory_pubkey: StaticPublicKey,

    /// This device's durable MAC (outer-header sender identity on egress).
    local_mac: PeerId,
}

impl<const N: usize> SessionManager<N> {
    /// Creates a new session manager with factory root and local device MAC.
    /// # Arguments
    /// * `factory_pubkey` - Factory ECDSA public key (33-byte compressed SEC1).
    ///   Cached for the lifetime of the manager; used to attest peer device
    ///   public keys during install without contacting the ATECC each time.
    /// * `local_mac` - This device's 17-byte identity. Written into the outer
    ///   header of every frame this manager transmits (sender identity).
    pub fn new(factory_pubkey: StaticPublicKey, local_mac: PeerId) -> Self {
        Self {
            sessions: FnvIndexMap::new(),
            pending: FnvIndexMap::new(),
            #[cfg(feature = "gateway")]
            install_last_at: FnvIndexMap::new(),
            factory_pubkey,
            local_mac,
        }
    }

    /// Returns the cached factory root public key.
    /// Install handlers use this to verify that a peer's static public key
    /// carries a valid factory certificate signature.
    pub fn factory_pubkey(&self) -> &StaticPublicKey {
        &self.factory_pubkey
    }

    /// Returns this device's local MAC (egress outer-header identity).
    pub fn local_mac(&self) -> &PeerId {
        &self.local_mac
    }

    /// Returns the number of sessions currently stored
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns true if the session manager is empty
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns true if the session manager is at capacity
    pub fn is_full(&self) -> bool {
        self.sessions.len() >= N
    }

    /// Inserts a session for the specified peer.
    /// If a session for the same `peer_mac` already exists, it is **replaced**
    /// even when the manager is at capacity (no net growth). A new peer is
    /// rejected with [`SigilError::CapacityExceeded`] only when the table is
    /// full and the peer is unknown.
    /// # Arguments
    /// * `session` - The session to insert
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(SigilError::CapacityExceeded)` if the manager
    /// is full and `session.peer_mac` is not already present.
    /// Active-key expiry is enforced when handshake code calls
    /// [`Session::new_active`](crate::core::session::Session::new_active) /
    /// [`Session::update_key`](crate::core::session::Session::update_key)
    /// (crate-internal). Hosts insert enrolled shells via
    /// [`Session::new_enrolled`](crate::core::Session::new_enrolled).
    pub fn insert(&mut self, session: Session) -> Result<(), SigilError> {
        let peer_mac = session.peer_mac;
        // Allow in-place replace at capacity; reject only true growth.
        if self.is_full() && !self.sessions.contains_key(&peer_mac) {
            return Err(SigilError::CapacityExceeded);
        }

        self.sessions
            .insert(peer_mac, session)
            .map_err(|_| SigilError::CapacityExceeded)?;
        Ok(())
    }

    /// Gets a reference to the session for the specified peer
    /// # Arguments
    /// * `peer` - The peer identifier
    ///
    /// # Returns
    /// `Some(&Session)` if found, `None` otherwise
    pub fn get(&self, peer: &PeerId) -> Option<&Session> {
        self.sessions.get(peer)
    }

    /// Gets a mutable reference to the session for the specified peer
    /// # Arguments
    /// * `peer` - The peer identifier
    ///
    /// # Returns
    /// `Some(&mut Session)` if found, `None` otherwise
    pub fn get_mut(&mut self, peer: &PeerId) -> Option<&mut Session> {
        self.sessions.get_mut(peer)
    }

    /// Removes a peer entirely from the manager: session state **and** any
    /// in-progress handshake.
    /// This is the recommended way to forget a peer (e.g. when the host
    /// decides to unpair a device). Any pending handshake is cancelled first,
    /// which zeroizes ephemeral secrets held in RAM, then the session is
    /// removed from the table.
    /// # Arguments
    /// * `peer` - The peer identifier to remove
    ///
    /// # Returns
    /// `Some(Session)` if the peer was known, `None` otherwise. The returned
    /// session can be inspected (e.g. to retrieve the static public key)
    /// before the host erases its NVRAM copy.
    /// # Note
    /// This only clears the RAM state. The host is responsible for erasing
    /// any persistent (NVRAM) copy of the peer's static public key.
    pub fn remove(&mut self, peer: &PeerId) -> Option<Session> {
        // Cancel any in-progress handshake (zeroizes ephemeral secrets)
        let _ = self.remove_pending(peer);
        // Drop install cooldown entry so forgotten peers free capacity.
        #[cfg(feature = "gateway")]
        let _ = self.install_last_at.remove(peer);
        self.sessions.remove(peer)
    }

    /// Returns an iterator over all sessions
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &Session)> {
        self.sessions.iter()
    }

    /// Returns a mutable iterator over all sessions
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&PeerId, &mut Session)> {
        self.sessions.iter_mut()
    }

    /// Inserts a pending handshake for the specified peer
    /// # Arguments
    /// * `peer` - The peer identifier
    /// * `handshake` - The pending handshake to insert
    ///
    /// # Returns
    /// `Ok(())` on success, `Err(SigilError::PendingAlreadyExists)` if a pending
    /// handshake already exists for this peer
    pub(crate) fn insert_pending(
        &mut self,
        peer: PeerId,
        handshake: PendingHandshake,
    ) -> Result<(), SigilError> {
        if self.pending.contains_key(&peer) {
            return Err(SigilError::PendingAlreadyExists { peer });
        }

        self.pending
            .insert(peer, handshake)
            .map(|_| ())
            .map_err(|_| SigilError::CapacityExceeded)
    }

    /// Returns `true` if install SE work for `peer` is allowed at `now` (seconds).
    /// Expired cooldown entries are purged opportunistically so the
    /// table does not permanently fill with historical PeerIds.
    #[cfg(feature = "gateway")]
    pub(crate) fn install_cooldown_elapsed(&mut self, peer: &PeerId, now: u32) -> bool {
        self.purge_expired_install_cooldowns(now);
        match self.install_last_at.get(peer) {
            None => true,
            Some(last) => {
                now.saturating_sub(*last) >= crate::core::install::INSTALL_REQUEST_COOLDOWN
            }
        }
    }

    /// Removes `install_last_at` entries whose cooldown window has elapsed.
    #[cfg(feature = "gateway")]
    pub(crate) fn purge_expired_install_cooldowns(&mut self, now: u32) {
        let cooldown = crate::core::install::INSTALL_REQUEST_COOLDOWN;
        self.install_last_at
            .retain(|_, last| now.saturating_sub(*last) < cooldown);
    }

    /// Records that install admission for `peer` was accepted at `now` (seconds).
    /// Called after factory attestation binds the claimed `peer`, but before
    /// device-signature and ECDH work. This prevents an unauthenticated sender
    /// from poisoning a legitimate peer's cooldown. If the table is full and
    /// `peer` is new, returns [`SigilError::CapacityExceeded`].
    #[cfg(feature = "gateway")]
    pub(crate) fn mark_install_request(
        &mut self,
        peer: PeerId,
        now: u32,
    ) -> Result<(), SigilError> {
        self.purge_expired_install_cooldowns(now);
        if self.install_last_at.len() >= N && !self.install_last_at.contains_key(&peer) {
            return Err(SigilError::CapacityExceeded);
        }
        self.install_last_at
            .insert(peer, now)
            .map_err(|_| SigilError::CapacityExceeded)?;
        Ok(())
    }

    /// Returns true if a new pending entry for `peer` can be inserted.
    pub(crate) fn pending_slot_available(&self, peer: &PeerId) -> bool {
        self.pending.contains_key(peer) || self.pending.len() < N
    }

    /// Returns true if the install cooldown table cannot accept `peer`.
    /// Purges expired entries first so capacity reflects live cooldowns only.
    #[cfg(feature = "gateway")]
    pub(crate) fn install_last_at_full_for(&mut self, peer: &PeerId, now: u32) -> bool {
        self.purge_expired_install_cooldowns(now);
        self.install_last_at.len() >= N && !self.install_last_at.contains_key(peer)
    }

    /// Gets a reference to the pending handshake for the specified peer
    /// # Arguments
    /// * `peer` - The peer identifier
    ///
    /// # Returns
    /// `Some(&PendingHandshake)` if found, `None` otherwise
    pub(crate) fn get_pending(&self, peer: &PeerId) -> Option<&PendingHandshake> {
        self.pending.get(peer)
    }

    /// Gets a mutable reference to the pending handshake for the specified peer
    /// # Arguments
    /// * `peer` - The peer identifier
    ///
    /// # Returns
    /// `Some(&mut PendingHandshake)` if found, `None` otherwise
    #[allow(dead_code)]
    pub(crate) fn get_pending_mut(&mut self, peer: &PeerId) -> Option<&mut PendingHandshake> {
        self.pending.get_mut(peer)
    }

    /// Removes the pending handshake for the specified peer
    /// # Arguments
    /// * `peer` - The peer identifier
    ///
    /// # Returns
    /// `Some(PendingHandshake)` if found and removed, `None` otherwise
    pub(crate) fn remove_pending(&mut self, peer: &PeerId) -> Option<PendingHandshake> {
        self.pending.remove(peer)
    }

    /// Cancels a pending handshake for the specified peer without removing
    /// an established session.
    /// This is the **manual abort API** for install / renew / resume. Ephemeral
    /// secrets in the pending state are zeroized on removal.
    /// # Two host policies
    /// Pending lifetime is **not** auto-cleared inside `process_incoming_packet`.
    /// Hosts choose one (or both) of:
    /// 1. **Manual timers:** after `SigilAction::Transmit { wait_timeout_ms: Some(t),.. }`,
    ///    start a host timer for `t` ms; on expiry call `cancel_pending(&peer)`.
    /// 2. **Optional [`Self::tick`]:** pass the host seconds clock periodically;
    ///    expired pre-commit entries are purged and the peer MACs returned
    ///    (same semantics as [`SigilError::TimeoutElapsed`]).
    ///
    /// Prefer this over [`Self::remove`] when a session must stay (e.g. failed
    /// renew/resume while the old key is still valid).
    /// # Errors
    /// `SigilError::NoPending` if no handshake is in progress for `peer`.
    /// `SigilError::InvalidStep` after the commit boundary; use [`Self::remove`]
    /// only for an intentional unpair in that state.
    pub fn cancel_pending(&mut self, peer: &PeerId) -> Result<(), SigilError> {
        if self
            .get_pending(peer)
            .is_some_and(crate::core::pending::PendingHandshake::is_commit_critical)
        {
            return Err(SigilError::InvalidStep { peer: *peer });
        }
        if self.remove_pending(peer).is_some() {
            Ok(())
        } else {
            Err(SigilError::NoPending { peer: *peer })
        }
    }

    /// Purges pre-commit handshakes whose absolute deadline has elapsed.
    /// Commit-critical recovery states are deliberately retained.
    /// # Optional housekeeping
    /// The library still has **no internal clock** — the host must call `tick`
    /// (e.g. once per main-loop iteration or on a slow timer). This is an
    /// **alternative** to per-peer radio timers + [`Self::cancel_pending`];
    /// hosts may use either policy or both.
    /// `deadline_at` is stamped at pending insert as
    /// `now + ceil(suggested_timeout_ms / 1000)` (minimum 1 s) using the same
    /// host **seconds** timebase as session expiry / cooldowns.
    /// # Returns
    /// Peer MACs that were purged. Each entry has the semantics of
    /// [`SigilError::TimeoutElapsed`] (useful for host logging / metrics).
    /// Secrets are zeroized via pending `Drop`.
    /// # Example
    /// ```ignore
    /// // Policy A — manual:
    /// // on Transmit { wait_timeout_ms: Some(t) } → host timer → cancel_pending
    /// // Policy B — tick filet:
    /// for peer in mgr.tick(now) {
    ///     log_timeout(SigilError::TimeoutElapsed { peer });
    /// }
    /// ```
    pub fn tick(&mut self, now: u32) -> heapless::Vec<PeerId, N> {
        let mut expired: heapless::Vec<PeerId, N> = heapless::Vec::new();
        for (peer, pending) in self.pending.iter() {
            // Dropping staged keys / cached CommitConfirmed here can
            // permanently split the peers across key epochs after packet loss.
            if now >= pending.deadline_at && !pending.is_commit_critical() {
                let _ = expired.push(*peer);
            }
        }
        for peer in &expired {
            let _ = self.remove_pending(peer);
        }
        expired
    }

    /// Rebinds the sole sensor-side install pending entry to `new_peer`.
    /// **Mandatory discovery:** the sensor starts install with a provisional
    /// destination ([`crate::core::install::INSTALL_DISCOVERY_DEST`] or host
    /// broadcast). When `InstallChallenge` arrives, this moves that pending
    /// entry onto the real gateway MAC from the challenge body.
    /// Returns `Ok(Some(old_peer))` when a rebind occurred (caller must
    /// [`Self::rollback_install_pending_rebind`] if challenge verification
    /// later fails). Returns `Ok(None)` if a pending already exists for
    /// `new_peer` (no-op).
    /// # Errors
    /// - [`SigilError::NoPending`] — no sensor `InstallWaitingForChallenge` entry
    /// - [`SigilError::InvalidHandshakeState`] — more than one matching pending
    #[cfg(feature = "sensor")]
    pub(crate) fn rebind_sole_sensor_install_pending(
        &mut self,
        new_peer: PeerId,
    ) -> Result<Option<PeerId>, SigilError> {
        use crate::core::pending::{HandshakeRole, HandshakeStep};

        if self.pending.contains_key(&new_peer) {
            return Ok(None);
        }

        let mut old: Option<PeerId> = None;
        for (peer, ph) in self.pending.iter() {
            if ph.role == HandshakeRole::Sensor
                && ph.step == HandshakeStep::InstallWaitingForChallenge
            {
                if old.is_some() {
                    return Err(SigilError::InvalidHandshakeState);
                }
                old = Some(*peer);
            }
        }
        let old = old.ok_or(SigilError::NoPending { peer: new_peer })?;
        let mut ph = self
            .remove_pending(&old)
            .ok_or(SigilError::NoPending { peer: new_peer })?;
        ph.peer_mac = new_peer;
        self.insert_pending(new_peer, ph)?;
        Ok(Some(old))
    }

    /// Restores a discovery pending key after a failed challenge verification.
    /// Moves the sensor `InstallWaitingForChallenge` entry from `from_peer`
    /// (gateway MAC that failed crypto) back to `to_peer` (provisional discovery
    /// dest) so a later valid challenge can still complete the install.
    #[cfg(feature = "sensor")]
    pub(crate) fn rollback_install_pending_rebind(
        &mut self,
        from_peer: PeerId,
        to_peer: PeerId,
    ) -> Result<(), SigilError> {
        use crate::core::pending::{HandshakeRole, HandshakeStep};

        if self.pending.contains_key(&to_peer) {
            return Ok(());
        }
        let mut ph = self
            .remove_pending(&from_peer)
            .ok_or(SigilError::NoPending { peer: from_peer })?;
        if ph.role != HandshakeRole::Sensor || ph.step != HandshakeStep::InstallWaitingForChallenge
        {
            // Put back — do not leave the table inconsistent.
            let _ = self.insert_pending(from_peer, ph);
            return Err(SigilError::InvalidHandshakeState);
        }
        ph.peer_mac = to_peer;
        self.insert_pending(to_peer, ph)
    }

    /// Clears a sensor-side Install state that cannot survive a local reboot.
    /// Called only when the trusted host explicitly starts a fresh Install.
    #[cfg(feature = "sensor")]
    pub(crate) fn clear_sensor_install_commit_recovery(&mut self) {
        use crate::core::pending::{HandshakeRole, HandshakeStep};
        let peer = self.pending.iter().find_map(|(peer, pending)| {
            (pending.role == HandshakeRole::Sensor
                && pending.step == HandshakeStep::InstallWaitingForCommitConfirmed)
                .then_some(*peer)
        });
        if let Some(peer) = peer {
            let _ = self.remove_pending(&peer);
        }
    }

    //  High-level protocol API
    //  These methods let the host drive the full protocol lifecycle through
    //  a single `SessionManager` instance, passing the secure element and
    //  random source as `&mut` borrows on each call. The manager does NOT
    //  own those resources — the host retains full ownership and can use
    //  them freely between calls.
    //  # Host timebase (product contract: **seconds**)
    //  `now` is a local monotonic timestamp in whole seconds. Wire v3 carries
    //  `key_lifetime_secs` as a duration, so sensor and gateway clocks need not
    //  share an epoch. Example: `key_lifetime_secs = 86_400` for a 24 h key.
    //  Resume rate-limit uses
    //  [`crate::core::resume::RESUME_REQUEST_COOLDOWN`] = 15 **seconds**.
    //  Handshake `*_TIMEOUT_MS` constants and `Transmit.wait_timeout_ms` are
    //  **suggested radio wait times in milliseconds only** — they never purge
    //  pending handshakes by themselves and are not mixed with `now`.

    /// Processes an incoming packet in a non-blocking manner.
    /// This is the main entry point for handling a received LoRa packet.
    /// It parses the outer header (`[peer_mac:17] [protocol_version:1] [frame_type:1]`),
    /// classifies the frame by `FrameType`, and returns a typed event:
    /// - **Data** frames are fully decrypted and returned as `SigilEvent::Data`.
    /// - **Handshake** frames are classified **per step**: e.g.
    ///   `InstallRequest` / `InstallChallenge` / `InstallConfirm`, paired with
    ///   [`SigilAction::NeedsHostDispatch`] (not [`SigilAction::Success`]).
    ///
    /// # Arguments
    /// * `packet` - Raw packet bytes received from the radio
    /// * `now` - Current host time in **seconds** (session expiry checks)
    ///
    /// # Non-Blocking Guarantee
    /// This method never blocks or sleeps. All waiting is expressed through
    /// `SigilAction::Transmit { wait_timeout_ms: Some(...) }` with timeout hints.
    /// # Client-side routing
    /// ```
    /// use sigil::core::event::{SigilAction, SigilEvent};
    /// # // (pseudo-code, not compiled)
    /// # fn example(mgr: &mut sigil::core::manager::SessionManager<16>,
    /// #           frame: &[u8], se: &mut impl sigil::core::traits::SecureElement,
    /// #           rng: &mut impl sigil::core::traits::RandomSource, now: u32) {
    /// match mgr.process_incoming_packet::<200, 256>(frame, 1000).unwrap() {
    ///     (SigilEvent::Data { peer, payload }, _) => {
    ///         // handle decrypted application data
    ///     }
    ///     (SigilEvent::TimeSync { gateway_time, sync_sequence, uncertainty_secs,.. }, _) => {
    ///         // Sensor host: discipline the local RTC according to product policy.
    ///     }
    ///     (SigilEvent::TimeSyncRequest { peer }, _) => {
    ///         // Gateway host: apply product policy, then build and TX TimeSync.
    ///         let response = mgr.encrypt_time_sync::<256>(&peer, now, 1, 1, now).ok();
    ///     }
    ///     (SigilEvent::Event { peer, event_id, payload, duplicate }, _) => {
    ///         // Process/persist only when !duplicate, then call ack_event and TX it.
    ///         let ack = mgr.ack_event::<256>(&peer, event_id, now).ok();
    ///     }
    ///     (SigilEvent::EventAck { event_id, .. }, _) => {
    ///         // Matching pending Event was authenticated and cleared.
    ///     }
    ///     (SigilEvent::InstallRequest { peer, frame }, _) => {
    ///         // Host: check pairing allowlist (DB) for `peer` (sender MAC), then:
    ///         mgr.handle_install_request::<256>(&frame, se, rng, now, now + 86_400).ok();
    ///     }
    ///     (SigilEvent::InstallChallenge { frame,.. }
    ///     | SigilEvent::InstallConfirm { frame,.. }
    ///     | SigilEvent::InstallCommitConfirmed { frame,.. }, _) => {
    ///         mgr.continue_install::<256>(&frame, se, now).ok();
    ///     }
    ///     (SigilEvent::RenewRequest { frame,.. }, _) => {
    ///         mgr.handle_renew_request::<256>(&frame, rng, 1000, 20_000).ok();
    ///     }
    ///     (SigilEvent::RenewChallenge { frame,.. }
    ///     | SigilEvent::RenewAck { frame,.. }
    ///     | SigilEvent::RenewCommitConfirmed { frame,.. }, _) => {
    ///         mgr.continue_renew::<256>(&frame, rng, now).ok();
    ///     }
    ///     (SigilEvent::ResumeRequest { frame,.. }, _) => {
    ///         mgr.handle_resume_request::<256>(&frame, se, rng, 1000, 1000 + 86_400).ok();
    ///     }
    ///     (SigilEvent::ResumeChallenge { frame,.. }
    ///     | SigilEvent::ResumeConfirm { frame,.. }
    ///     | SigilEvent::ResumeCommitConfirmed { frame,.. }, _) => {
    ///         mgr.continue_resume::<256>(&frame, se, now).ok();
    ///     }
    /// }
    /// # }
    /// ```
    /// # Type parameters
    /// * `DATA` - Maximum decrypted **application** payload size ([`crate::core::event::DATA_MAX`])
    /// * `MSG` - Maximum **wire** frame size for handshake buffers and TX
    ///   ([`crate::core::event::MSG_MAX`]). Must fit `InstallChallenge` (219 B)
    ///   when using install — handshake frames are copied into `MSG`, not `DATA`
    pub fn process_incoming_packet<const DATA: usize, const MSG: usize>(
        &mut self,
        packet: &[u8],
        now: u32,
    ) -> Result<(SigilEvent<DATA, MSG>, SigilAction<MSG>), SigilError> {
        crate::core::pipeline::process_incoming_packet_internal(self, packet, now)
    }

    /// Encrypts application data for transmission to a peer.
    /// # Arguments
    /// * `peer` - Peer identifier
    /// * `plaintext` - Plaintext data to encrypt
    /// * `now` - Current host time in **seconds** (expiry checks)
    ///
    /// # Errors
    /// - `SigilError::UnknownSession` - No session exists for the peer
    /// - `SigilError::SessionExpired` - Session key has expired
    /// - `SigilError::CounterExhausted` - TX counter would overflow
    pub fn encrypt_data<const MSG: usize>(
        &mut self,
        peer: &PeerId,
        plaintext: &[u8],
        now: u32,
    ) -> Result<heapless::Vec<u8, MSG>, SigilError> {
        crate::core::pipeline::encrypt_data_internal(self, peer, plaintext, now)
    }

    /// Encrypts a reliable sensor Event and starts (or refreshes) its ACK wait.
    ///
    /// Only sensor-role sessions may send Events. `event_id` must increase for
    /// each new Event and should be persisted by the host across reboot. Calling
    /// this method again with the currently pending id performs a retry using a
    /// fresh AEAD counter; a different id is rejected until ACK or cancellation.
    /// The returned [`SigilAction::Transmit`] carries
    /// `wait_timeout_ms = Some(EVENT_ACK_TIMEOUT_MS)`.
    #[cfg(feature = "sensor")]
    pub fn send_event<const MSG: usize>(
        &mut self,
        peer: &PeerId,
        event_id: u64,
        payload: &[u8],
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::pipeline::send_event_internal(self, peer, event_id, payload, now)
    }

    /// Abandons the matching Event after the host retry budget is exhausted.
    /// The id remains consumed and cannot be reused for a later Event.
    #[cfg(feature = "sensor")]
    pub fn cancel_pending_event(
        &mut self,
        peer: &PeerId,
        event_id: u64,
    ) -> Result<(), SigilError> {
        crate::core::pipeline::cancel_pending_event_internal(self, peer, event_id)
    }

    /// Builds the authenticated EventAck after the gateway has durably handled
    /// an Event. Calling it again for an already committed duplicate safely
    /// rebuilds an ACK with a fresh AEAD counter.
    #[cfg(feature = "gateway")]
    pub fn ack_event<const MSG: usize>(
        &mut self,
        peer: &PeerId,
        event_id: u64,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::pipeline::ack_event_internal(self, peer, event_id, now)
    }

    /// Releases an uncommitted gateway delivery after durable processing
    /// failed. No ACK is emitted; a fresh sensor retry of the same id will be
    /// delivered again with `duplicate == false`.
    #[cfg(feature = "gateway")]
    pub fn release_event_delivery(
        &mut self,
        peer: &PeerId,
        event_id: u64,
    ) -> Result<(), SigilError> {
        crate::core::pipeline::release_event_delivery_internal(self, peer, event_id)
    }

    /// Encrypts an authenticated gateway clock sample for a sensor.
    #[cfg(feature = "gateway")]
    pub fn encrypt_time_sync<const MSG: usize>(
        &mut self,
        peer: &PeerId,
        gateway_time: u32,
        sync_sequence: u32,
        uncertainty_secs: u16,
        now: u32,
    ) -> Result<heapless::Vec<u8, MSG>, SigilError> {
        crate::core::pipeline::encrypt_time_sync_internal(
            self,
            peer,
            gateway_time,
            sync_sequence,
            uncertainty_secs,
            now,
        )
    }

    /// Encrypts a sensor request for a fresh gateway clock sample.
    ///
    /// The gateway receives [`SigilEvent::TimeSyncRequest`] and may answer with
    /// [`Self::encrypt_time_sync`]. Only sensor-role sessions may call this.
    #[cfg(feature = "sensor")]
    pub fn request_time_sync<const MSG: usize>(
        &mut self,
        peer: &PeerId,
        now: u32,
    ) -> Result<heapless::Vec<u8, MSG>, SigilError> {
        crate::core::pipeline::request_time_sync_internal(self, peer, now)
    }

    /// Starts an installation handshake (sensor side).
    /// **Gateway discovery is mandatory.** Pass
    /// [`crate::core::install::INSTALL_DISCOVERY_DEST`] (or the host broadcast
    /// address) as `peer`. Do not pass a pre-known unicast gateway MAC for
    /// first pairing — the real gateway identity is learned from
    /// `InstallChallenge` via pending rebind in `continue_install`.
    /// Host must transmit the returned frame as a discovery / broadcast TX.
    /// # Arguments
    /// * `now` - Current host time in **seconds** (stamps pending `deadline_at`
    ///   for optional [`Self::tick`])
    ///
    /// See [`crate::core::install`] for protocol details.
    #[cfg(feature = "sensor")]
    pub fn start_install<const MSG: usize>(
        &mut self,
        peer: PeerId,
        se: &mut impl SecureElement,
        rng: &mut impl RandomSource,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::install::start_install_sensor_internal(self, peer, se, rng, now)
    }

    /// Processes an install request packet (gateway side).
    /// Library DoS guards (pending / capacity / [`crate::core::install::INSTALL_REQUEST_COOLDOWN`]
    /// = 15 **seconds**) run **before** secure-element work.
    /// # Arguments
    /// * `now` - Current host time in **seconds** (install cooldown)
    /// * `key_lifetime_secs` - Lifetime of the new session key in **seconds**.
    ///   Each peer converts it to its own local absolute expiry. Distinct from
    ///   [`crate::core::install::INSTALL_TIMEOUT_MS`] (radio wait, milliseconds).
    #[cfg(feature = "gateway")]
    pub fn handle_install_request<const MSG: usize>(
        &mut self,
        packet: &[u8],
        se: &mut impl SecureElement,
        rng: &mut impl RandomSource,
        now: u32,
        key_lifetime_secs: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::install::handle_install_request_internal(
            self,
            packet,
            se,
            rng,
            now,
            key_lifetime_secs,
        )
    }

    /// Continues an in-progress install handshake.
    /// Host must call this for `InstallChallenge`, `InstallConfirm`, **and**
    /// `InstallCommitConfirmed`. On gateway Final success the
    /// returned [`SigilAction::PersistPeerStaticKey`] may carry a non-empty
    /// `transmit` CommitConfirmed frame — persist NVRAM then TX.
    pub fn continue_install<const MSG: usize>(
        &mut self,
        packet: &[u8],
        se: &mut impl SecureElement,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::install::continue_install_internal(self, packet, se, now)
    }

    /// Starts a renewal handshake (sensor side only).
    /// Requires an **active** (non-expired) session key for `peer` and
    /// [`SessionRole::Sensor`](crate::core::SessionRole). Soft-expired
    /// keys return [`SigilError::SessionExpired`] before RNG / encrypt / TX
    /// advance — use resume instead. Gateway-role sessions return
    /// [`SigilError::InvalidStep`].
    /// # Arguments
    /// * `now` - Current host time in **seconds** (expiry check + pending
    ///   `deadline_at` for optional [`Self::tick`])
    ///
    /// See [`crate::core::renew`] for protocol details.
    #[cfg(feature = "sensor")]
    pub fn start_renew<const MSG: usize>(
        &mut self,
        peer: PeerId,
        rng: &mut impl RandomSource,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::renew::start_renew_sensor_internal(self, peer, rng, now)
    }

    /// Processes a renew request packet (gateway side).
    /// # Arguments
    /// * `packet` - Received encrypted renew request frame
    /// * `rng` - Random source (for the gateway ephemeral scalar)
    /// * `now` - Current host time in **seconds** (validates the **old** session key)
    /// * `key_lifetime_secs` - Lifetime of the **new** key in seconds
    #[cfg(feature = "gateway")]
    pub fn handle_renew_request<const MSG: usize>(
        &mut self,
        packet: &[u8],
        rng: &mut impl RandomSource,
        now: u32,
        key_lifetime_secs: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::renew::handle_renew_request_internal(self, packet, rng, now, key_lifetime_secs)
    }

    /// Continues an in-progress renew handshake.
    /// Host must call this for `RenewChallenge`, `RenewAck`, **and**
    /// `RenewCommitConfirmed`.
    pub fn continue_renew<const MSG: usize>(
        &mut self,
        packet: &[u8],
        rng: &mut impl RandomSource,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::renew::continue_renew_internal(self, packet, rng, now)
    }

    /// Starts a resume handshake (sensor side).
    /// # Arguments
    /// * `peer` - Gateway peer MAC
    /// * `se` - Secure element (unused on request; ECDH at challenge)
    /// * `rng` - Random source (sensor nonce)
    /// * `now` - Current host time in **seconds**
    ///
    /// Requires [`SessionRole::Sensor`](crate::core::SessionRole).
    /// Resume may be explicitly started while an old key is active or expired,
    /// which recovers from a peer reboot. The old key is retained until the new
    /// handshake commits.
    #[cfg(feature = "sensor")]
    pub fn start_resume<const MSG: usize>(
        &mut self,
        peer: PeerId,
        se: &mut impl SecureElement,
        rng: &mut impl RandomSource,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::resume::start_resume_internal(self, peer, se, rng, now)
    }

    /// Processes a resume request packet (gateway side).
    /// # Arguments
    /// * `packet` - Received clear-text resume request frame
    /// * `se` - Secure element (static↔static ECDH)
    /// * `rng` - Random source (gateway nonce)
    /// * `now` - Current host time in **seconds** (expiry +
    ///   [`crate::core::resume::RESUME_REQUEST_COOLDOWN`] = 15 s)
    /// * `key_lifetime_secs` - Lifetime of the **new** key in seconds (host
    ///   policy). Each peer applies it to its local clock. Distinct from
    ///   [`RESUME_TIMEOUT_MS`](crate::core::resume::RESUME_TIMEOUT_MS) (milliseconds).
    ///
    /// Active and soft-expired keys are retained until Resume commits, allowing
    /// recovery when either peer rebooted. In-flight resume pending returns
    /// [`SigilError::PendingAlreadyExists`]; requests inside the cooldown window
    /// return [`SigilError::RateLimited`].
    #[cfg(feature = "gateway")]
    pub fn handle_resume_request<const MSG: usize>(
        &mut self,
        packet: &[u8],
        se: &mut impl SecureElement,
        rng: &mut impl RandomSource,
        now: u32,
        key_lifetime_secs: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::resume::handle_resume_request_internal(
            self,
            packet,
            se,
            rng,
            now,
            key_lifetime_secs,
        )
    }

    /// Continues an in-progress resume handshake.
    /// Host must call this for `ResumeChallenge`, `ResumeConfirm`, **and**
    /// `ResumeCommitConfirmed`.
    pub fn continue_resume<const MSG: usize>(
        &mut self,
        packet: &[u8],
        se: &mut impl SecureElement,
        now: u32,
    ) -> Result<SigilAction<MSG>, SigilError> {
        crate::core::resume::continue_resume_internal(self, packet, se, now)
    }

    /// Retransmits the cached Final / CommitConfirmed wire frame for `peer`
    /// when pending is in a post-Final step
    /// (`*WaitingForCommitConfirmed` or `*CommitSent`).
    /// Intended for host retry timers and unit tests. Returns
    /// [`SigilError::InvalidStep`] / [`SigilError::InvalidHandshakeState`] when
    /// no cache is available.
    pub fn retransmit_pending_cached<const MSG: usize>(
        &self,
        peer: &PeerId,
    ) -> Result<SigilAction<MSG>, SigilError> {
        let pending = self
            .get_pending(peer)
            .ok_or(SigilError::NoPending { peer: *peer })?;
        let timeout_ms = pending.suggested_timeout_ms;
        match pending.step {
            crate::core::pending::HandshakeStep::InstallWaitingForCommitConfirmed
            | crate::core::pending::HandshakeStep::InstallCommitSent
            | crate::core::pending::HandshakeStep::RenewWaitingForCommitConfirmed
            | crate::core::pending::HandshakeStep::RenewCommitSent
            | crate::core::pending::HandshakeStep::ResumeWaitingForCommitConfirmed
            | crate::core::pending::HandshakeStep::ResumeCommitSent => {}
            _ => return Err(SigilError::InvalidStep { peer: *peer }),
        }
        let cached = pending
            .cached_wire
            .as_ref()
            .ok_or(SigilError::InvalidHandshakeState)?;
        let mut payload: heapless::Vec<u8, MSG> = heapless::Vec::new();
        payload
            .extend_from_slice(cached)
            .map_err(|_| SigilError::CapacityExceeded)?;
        Ok(SigilAction::Transmit {
            dest: *peer,
            payload,
            wait_timeout_ms: Some(timeout_ms),
        })
    }
}

mod tests;

//! Crate-private storage components behind the [`SessionManager`] facade.
//!
//! The public host entry point remains
//! [`SessionManager`](super::SessionManager); this module splits the storage
//! responsibilities the facade used to carry inline into three cohesive
//! fixed-capacity stores plus a narrow borrow type handed to the protocol
//! handlers:
//!
//! - [`SessionStore`]: established sessions keyed by remote peer MAC.
//! - [`PendingStore`]: in-progress handshakes and post-commit loss-recovery
//!   entries, keyed by remote peer MAC.
//! - [`AdmissionStore`] (gateway only): per-peer install admission /
//!   cooldown bookkeeping that bounds secure-element work amplification.
//! - [`ProtocolStores`]: a short-lived multi-store borrow (plus the read-only
//!   device egress identity) that protocol modules receive instead of the
//!   whole manager, so they can only mutate the storage capabilities
//!   they genuinely need.
//!
//! # Capacity constraint
//! Every store wraps a
//! [`heapless::FnvIndexMap`](https://docs.rs/heapless/latest/heapless/struct.FnvIndexMap.html)
//! keyed by `PeerId`, so `N` must be a power of two **and** at least 2 — the
//! same compile-time constraint the manager facade documents.
//!
//! # Capacity error domains
//! Each store reports saturation of **its own** table with a distinct
//! host-visible variant: [`SigilError::SessionTableFull`],
//! [`SigilError::PendingTableFull`] and [`SigilError::AdmissionTableFull`].
//! Keeping the failing operation inside the owning store makes the resource
//! domain (session table vs pending table vs admission table vs integration
//! buffer sizing, reported as [`SigilError::OutputBufferTooSmall`])
//! structurally distinguishable at the store boundary.
//!
//! # Zeroization
//! Pending entries hold staged secrets in zeroizing wrappers. Removing a
//! pending entry (via [`PendingStore::remove`] or any purge/rebind path below)
//! drops the [`PendingHandshake`] with those wrappers, exactly as the facade
//! did before the extraction.

use crate::core::error::SigilError;
use crate::core::event::SigilAction;
use crate::core::pending::PendingHandshake;
use crate::core::session::{PeerId, Session};
use crate::core::traits::StaticPublicKey;
use heapless::FnvIndexMap;

/// Fixed-capacity table of established sessions keyed by **remote** peer MAC.
///
/// Capacity failures of this table are session-table saturation: a new peer is
/// rejected only when the table is full and the peer is unknown; replacing a
/// known peer never grows the table (see [`SessionStore::insert`]).
pub(crate) struct SessionStore<const N: usize> {
    /// Sessions keyed by remote peer identifier.
    table: FnvIndexMap<PeerId, Session, N>,
}

impl<const N: usize> SessionStore<N> {
    /// Creates an empty session table.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the number of sessions currently stored.
    pub(crate) fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns true if the session table is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Returns true if the session table is at capacity.
    pub(crate) fn is_full(&self) -> bool {
        self.table.len() >= N
    }

    /// Inserts a session for the specified peer.
    /// If a session for the same `peer_mac` already exists, it is **replaced**
    /// even when the table is at capacity (no net growth). A new peer is
    /// rejected with [`SigilError::SessionTableFull`] only when the table is
    /// full and the peer is unknown.
    pub(crate) fn insert(&mut self, session: Session) -> Result<(), SigilError> {
        let peer_mac = *session.peer_mac();
        // Allow in-place replace at capacity; reject only true growth.
        if self.is_full() && !self.table.contains_key(&peer_mac) {
            return Err(SigilError::SessionTableFull);
        }

        self.table
            .insert(peer_mac, session)
            .map_err(|_| SigilError::SessionTableFull)?;
        Ok(())
    }

    /// Gets a reference to the session for the specified peer.
    pub(crate) fn get(&self, peer: &PeerId) -> Option<&Session> {
        self.table.get(peer)
    }

    /// Gets a mutable reference to the session for the specified peer.
    pub(crate) fn get_mut(&mut self, peer: &PeerId) -> Option<&mut Session> {
        self.table.get_mut(peer)
    }

    /// Removes the session for the specified peer, returning it if present.
    pub(crate) fn remove(&mut self, peer: &PeerId) -> Option<Session> {
        self.table.remove(peer)
    }

    /// Returns an iterator over all sessions.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&PeerId, &Session)> {
        self.table.iter()
    }

    /// Returns a mutable iterator over all sessions.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (&PeerId, &mut Session)> {
        self.table.iter_mut()
    }
}

impl<const N: usize> Default for SessionStore<N> {
    fn default() -> Self {
        Self {
            table: FnvIndexMap::new(),
        }
    }
}

/// Fixed-capacity table of in-progress handshakes and post-commit
/// loss-recovery entries keyed by **remote** peer MAC.
///
/// This table is independent of [`SessionStore`]: filling it with many
/// distinct peers blocks new handshakes while established sessions keep
/// encrypting/decrypting. Capacity failures of this table are pending-table
/// saturation (see [`PendingStore::insert`] and [`PendingStore::slot_available`]).
pub(crate) struct PendingStore<const N: usize> {
    /// Pending handshakes keyed by remote peer identifier.
    table: FnvIndexMap<PeerId, PendingHandshake, N>,
}

impl<const N: usize> PendingStore<N> {
    /// Creates an empty pending table.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Inserts a pending handshake for the specified peer.
    /// # Returns
    /// `Ok(())` on success, `Err(SigilError::PendingAlreadyExists)` if a
    /// pending handshake already exists for this peer (pending-table domain),
    /// `Err(SigilError::PendingTableFull)` when the table is full
    /// (pending-table saturation).
    pub(crate) fn insert(
        &mut self,
        peer: PeerId,
        handshake: PendingHandshake,
    ) -> Result<(), SigilError> {
        if self.table.contains_key(&peer) {
            return Err(SigilError::PendingAlreadyExists { peer });
        }

        self.table
            .insert(peer, handshake)
            .map(|_| ())
            .map_err(|_| SigilError::PendingTableFull)
    }

    /// Returns true if a new pending entry for `peer` can be inserted:
    /// a peer that already has an entry may be replaced in place, otherwise
    /// the table must have at least one free slot.
    pub(crate) fn slot_available(&self, peer: &PeerId) -> bool {
        self.table.contains_key(peer) || self.table.len() < N
    }

    /// Gets a reference to the pending handshake for the specified peer.
    pub(crate) fn get(&self, peer: &PeerId) -> Option<&PendingHandshake> {
        self.table.get(peer)
    }

    /// Gets a mutable reference to the pending handshake for the specified
    /// peer. Dropping or replacing the returned entry zeroizes staged secrets.
    pub(crate) fn get_mut(&mut self, peer: &PeerId) -> Option<&mut PendingHandshake> {
        self.table.get_mut(peer)
    }

    /// Removes the pending handshake for the specified peer, returning it if
    /// present. Dropping the returned value zeroizes staged secrets.
    pub(crate) fn remove(&mut self, peer: &PeerId) -> Option<PendingHandshake> {
        self.table.remove(peer)
    }

    /// Returns the number of handshakes and commit-recovery entries.
    pub(crate) fn len(&self) -> usize {
        self.table.len()
    }

    /// Returns the peers currently occupying the pending table.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &PeerId> {
        self.table.keys()
    }

    /// Returns an iterator over all pending entries.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&PeerId, &PendingHandshake)> {
        self.table.iter()
    }

    /// Builds the retransmit action for `peer` from the cached Final /
    /// CommitConfirmed wire frame held by a post-Final recovery state.
    ///
    /// Single source of truth for cached-frame retransmission: the state
    /// predicates decide whether a cached frame exists
    /// ([`PendingState::is_commit_critical`] plus
    /// [`PendingState::cached_retransmission_frame`]). The public facade
    /// retransmission API and the handshake duplicate-Final arms both go
    /// through this method so their behavior cannot drift apart.
    ///
    /// # Errors
    /// [`SigilError::NoPending`] without a pending entry,
    /// [`SigilError::InvalidStep`] for any pre-Final state, and
    /// [`SigilError::InvariantViolation`] when a recovery state carries no
    /// cached frame (internal invariant failure — unrepresentable in the
    /// tagged model).
    pub(crate) fn retransmit_cached_action<const MSG: usize>(
        &self,
        peer: &PeerId,
    ) -> Result<SigilAction<MSG>, SigilError> {
        let pending = self
            .get(peer)
            .ok_or(SigilError::NoPending { peer: *peer })?;
        let timeout_ms = pending.suggested_timeout_ms;
        // State predicates are the single source of truth: only the
        // commit-critical recovery states may retransmit, and each of them
        // owns its cached frame by construction.
        if !pending.state().is_commit_critical() {
            return Err(SigilError::InvalidStep { peer: *peer });
        }
        let cached = pending
            .state()
            .cached_retransmission_frame()
            .ok_or(SigilError::InvariantViolation)?;
        let mut payload: heapless::Vec<u8, MSG> = heapless::Vec::new();
        payload
            .extend_from_slice(cached)
            .map_err(|_| SigilError::OutputBufferTooSmall)?;
        Ok(SigilAction::Transmit {
            dest: *peer,
            payload,
            wait_timeout_ms: Some(timeout_ms),
        })
    }

    /// Rebinds the sole sensor-side install pending entry to `new_peer`.
    /// **Mandatory discovery:** the sensor starts install with a provisional
    /// destination. When `InstallChallenge` arrives, this moves that pending
    /// entry onto the real gateway MAC from the challenge body.
    /// Returns `Ok(Some(old_peer))` when a rebind occurred (caller must
    /// [`PendingStore::rollback_install_pending_rebind`] if challenge
    /// verification later fails). Returns `Ok(None)` if a pending already
    /// exists for `new_peer` (no-op).
    /// # Errors
    /// - [`SigilError::NoPending`] — no sensor `InstallSensorAwaitChallenge`
    /// - [`SigilError::InvariantViolation`] — more than one matching pending
    #[cfg(feature = "sensor")]
    pub(crate) fn rebind_sole_sensor_install_pending(
        &mut self,
        new_peer: PeerId,
    ) -> Result<Option<PeerId>, SigilError> {
        use crate::core::pending::PendingState;

        if self.table.contains_key(&new_peer) {
            return Ok(None);
        }

        let mut old: Option<PeerId> = None;
        for (peer, ph) in self.table.iter() {
            // Only a sensor install that just sent its request (and holds
            // nothing but the initiator nonce) may be rebound to the real
            // gateway MAC learned from the challenge.
            if matches!(ph.state(), PendingState::InstallSensorAwaitChallenge { .. }) {
                if old.is_some() {
                    return Err(SigilError::InvariantViolation);
                }
                old = Some(*peer);
            }
        }
        let old = old.ok_or(SigilError::NoPending { peer: new_peer })?;
        let mut ph = self
            .remove(&old)
            .ok_or(SigilError::NoPending { peer: new_peer })?;
        ph.peer_mac = new_peer;
        self.insert(new_peer, ph)?;
        Ok(Some(old))
    }

    /// Restores a discovery pending key after a failed challenge verification.
    /// Moves the sensor `InstallSensorAwaitChallenge` entry from `from_peer`
    /// (gateway MAC that failed crypto) back to `to_peer` (provisional
    /// discovery dest) so a later valid challenge can still complete the
    /// install.
    #[cfg(feature = "sensor")]
    pub(crate) fn rollback_install_pending_rebind(
        &mut self,
        from_peer: PeerId,
        to_peer: PeerId,
    ) -> Result<(), SigilError> {
        use crate::core::pending::PendingState;

        if self.table.contains_key(&to_peer) {
            return Ok(());
        }
        let mut ph = self
            .remove(&from_peer)
            .ok_or(SigilError::NoPending { peer: from_peer })?;
        if !matches!(ph.state(), PendingState::InstallSensorAwaitChallenge { .. }) {
            // Put back — do not leave the table inconsistent.
            let _ = self.insert(from_peer, ph);
            return Err(SigilError::InvariantViolation);
        }
        ph.peer_mac = to_peer;
        self.insert(to_peer, ph)
    }

    /// Clears a sensor-side Install state that cannot survive a local reboot.
    /// Called only when the trusted host explicitly starts a fresh Install.
    #[cfg(feature = "sensor")]
    pub(crate) fn clear_sensor_install_commit_recovery(&mut self) {
        use crate::core::pending::PendingState;
        let peer = self.table.iter().find_map(|(peer, pending)| {
            // Sensor install post-Final recovery state.
            matches!(pending.state(), PendingState::InstallSensorFinalSent { .. }).then_some(*peer)
        });
        if let Some(peer) = peer {
            let _ = self.remove(&peer);
        }
    }
}

impl<const N: usize> Default for PendingStore<N> {
    fn default() -> Self {
        Self {
            table: FnvIndexMap::new(),
        }
    }
}

/// Gateway-side per-peer install admission / cooldown bookkeeping.
///
/// Bounds how often the secure element performs install ECDH/sign work for
/// one peer MAC (see
/// [`INSTALL_REQUEST_COOLDOWN`](crate::core::install::INSTALL_REQUEST_COOLDOWN)).
/// Expired entries are purged opportunistically so the table cannot
/// permanently fill with historical PeerIds; the purge runs exactly once per
/// request inside the decide phase ([`AdmissionStore::admit_install`]), and
/// capacity failures of this table are admission-table saturation (surfaced
/// by [`AdmissionStore::admit_install`] and, fail-closed, by
/// [`AdmissionStore::stamp_install_request`]).
///
/// The store is deliberately two-phase so an accepted request performs at
/// most **one** full-table scan: `decide cheap → caller verifies identity →
/// stamp`. Unauthenticated senders never reach the stamp, so they can consume
/// only expired-entry reclamation — never live cooldown state.
#[cfg(feature = "gateway")]
pub(crate) struct AdmissionStore<const N: usize> {
    /// Last accepted install SE work timestamp (**seconds**) per peer.
    install_last_at: FnvIndexMap<PeerId, u32, N>,
}

#[cfg(feature = "gateway")]
impl<const N: usize> AdmissionStore<N> {
    /// Creates an empty admission / cooldown table.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Removes `install_last_at` entries whose cooldown window has elapsed.
    /// The only full-table scan in this store; called exactly once per
    /// install request from [`AdmissionStore::admit_install`].
    fn purge_expired_install_cooldowns(&mut self, now: u32) {
        let cooldown = crate::core::install::INSTALL_REQUEST_COOLDOWN;
        self.install_last_at
            .retain(|_, last| now.saturating_sub(*last) < cooldown);
    }

    /// Decides install admission for `peer` at `now` (seconds) with a single
    /// opportunistic purge of expired cooldown entries, preserving the
    /// documented guard order: a peer still inside its
    /// [`INSTALL_REQUEST_COOLDOWN`](crate::core::install::INSTALL_REQUEST_COOLDOWN)
    /// window is rejected with [`SigilError::RateLimited`] before capacity is
    /// considered; a new peer with no free slot after the purge is rejected
    /// with [`SigilError::AdmissionTableFull`]. `Ok(())` means the caller may
    /// proceed to identity verification and must stamp via
    /// [`AdmissionStore::stamp_install_request`] only once that verification
    /// succeeds. Because this method does not mutate live state beyond
    /// removing already-expired entries, an unauthenticated flood can trigger
    /// the purge but can never stamp or poison another peer's cooldown.
    pub(crate) fn admit_install(&mut self, peer: &PeerId, now: u32) -> Result<(), SigilError> {
        // The single O(C) scan shared by every decision of this request.
        self.purge_expired_install_cooldowns(now);
        if let Some(last) = self.install_last_at.get(peer) {
            if now.saturating_sub(*last) < crate::core::install::INSTALL_REQUEST_COOLDOWN {
                return Err(SigilError::RateLimited { peer: *peer });
            }
            return Ok(());
        }
        if self.install_last_at.len() >= N {
            return Err(SigilError::AdmissionTableFull);
        }
        Ok(())
    }

    /// Records that install admission for `peer` was accepted at `now`
    /// (seconds). Callers stamp this only after factory attestation and the
    /// dynamic device signature bind the claimed `peer`, but before ECDH
    /// work, so a sender that merely replayed a public factory certificate
    /// cannot poison a legitimate peer's cooldown.
    ///
    /// Performs **no** scan: the paired decide phase
    /// ([`AdmissionStore::admit_install`]) already purged expired entries and
    /// reserved the slot within the same single-threaded API call, so the
    /// insert cannot grow past capacity. The failure mapping stays fail-closed
    /// ([`SigilError::AdmissionTableFull`]) in case a future caller pairs the
    /// phases incorrectly.
    pub(crate) fn stamp_install_request(
        &mut self,
        peer: PeerId,
        now: u32,
    ) -> Result<(), SigilError> {
        self.install_last_at
            .insert(peer, now)
            .map_err(|_| SigilError::AdmissionTableFull)?;
        Ok(())
    }

    /// Drops the cooldown entry for `peer` so forgotten peers free capacity.
    pub(crate) fn remove(&mut self, peer: &PeerId) {
        let _ = self.install_last_at.remove(peer);
    }
}

#[cfg(feature = "gateway")]
impl<const N: usize> Default for AdmissionStore<N> {
    fn default() -> Self {
        Self {
            install_last_at: FnvIndexMap::new(),
        }
    }
}

/// Narrow multi-store borrow handed to protocol handlers.
///
/// The facade lends this view to the pipeline and handshake implementations
/// instead of `&mut SessionManager`, so protocol code can only reach the
/// storage capabilities plus the read-only identities it legitimately needs —
/// never the public host-facing facade operations. The gateway admission
/// table and the factory root are part of the view because the install
/// handshake is their only consumer.
pub(crate) struct ProtocolStores<'a, const N: usize> {
    /// Established-session table (keyed by remote peer MAC).
    pub(crate) sessions: &'a mut SessionStore<N>,
    /// Pending-handshake / commit-recovery table.
    pub(crate) pending: &'a mut PendingStore<N>,
    /// Gateway-side per-peer install admission / cooldown bookkeeping.
    #[cfg(feature = "gateway")]
    pub(crate) admission: &'a mut AdmissionStore<N>,
    /// Factory root public key (read-only). Install attestation verifies that
    /// a peer's static key was signed under this same fleet root.
    pub(crate) factory_pubkey: &'a StaticPublicKey,
    /// This device's durable MAC (read-only egress outer-header identity).
    pub(crate) local_mac: &'a PeerId,
}

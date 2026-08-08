# Feature Specification: Non-Blocking Session Core

**Feature Branch**: `001-nonblocking-session-core`  
**Created**: 2026-08-04  
**Status**: Clarified  
**Input**: User description: "ARCHITECTURE_DEV.md — hardware-agnostic, non-blocking, no-alloc session core with SessionManager, crypto/random traits, install / renew / fast-resume protocol steps, and a non-blocking incoming-packet pipeline"

## Clarifications

### Session 2026-08-04

- Q: Wire compatibility with deployed devices — keep conceptual phases but which interop posture? → A: **B+** — new incompatible protocol (no dual-stack); retain existing peer MAC size/format (`[u8; 17]`), not the 6-byte address from `ARCHITECTURE_DEV.md`. Coupled sensor+gateway upgrades required for other wire/crypto/API changes.
- Q: Packet counters / AEAD nonce — one shared counter or separate directions? → A: **B** — per session, separate `tx_counter` and `rx_counter` (64-bit each). Shared 4-byte nonce prefix from key establishment does not partition directions; TX/RX counter spaces must not overlap.
- Q: Fast resume crypto model given LoRa size/energy constraints? → A: **A** — static↔static key agreement only (per `ARCHITECTURE_DEV.md`); no ephemeral exchange and no ECDSA on the resume path. Forward secrecy remains the job of periodic eph↔eph renew. Resume optimized for small packets and low power after reboot.
- Q: When a handshake radio-wait timeout hint elapses, what happens to in-progress handshake state? → A: **B** — pending handshake state is retained until an explicit host `cancel`/abort, successful completion, or a host-started attempt that intentionally replaces it. The library does not auto-clear solely because the timeout hint elapsed.
- Q: Who may initiate session renew? → A: **A** — only the sensor initiates renew; the gateway only responds. Gateway-initiated renew is out of scope.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Non-Blocking Packet Processing (Priority: P1)

A firmware developer integrates the library into a sensor or gateway main loop. When a LoRa packet arrives, the host passes the raw bytes into a single entry point. The library parses, looks up the peer session, validates key lifetime, decrypts when applicable, and returns a typed event or a clear error. The call never waits on radio, timers, or secure-element delays.

**Why this priority**: Without a non-blocking entry point, the library cannot meet the core product rule that the host owns all timing and I/O.

**Independent Test**: Feed canned encrypted and clear-text packets with mock crypto and fixed session state; assert events/errors and that no wait/delay behavior is invoked.

**Acceptance Scenarios**:

1. **Given** a valid session with a non-expired key and an authenticated encrypted data packet, **When** the host processes the packet, **Then** the library returns a data event with the clear payload and advances the session **receive** counter.
2. **Given** a packet for an unknown peer, **When** the host processes the packet, **Then** the library returns a distinct “unknown session” error and does not mutate other sessions.
3. **Given** a session whose key lifetime has elapsed, **When** the host processes an encrypted packet for that peer, **Then** the library returns a session-expired error and does **not** start renew automatically.

---

### User Story 2 - First-Time Installation Pairing (Priority: P1)

An unenrolled sensor and a gateway complete first-time pairing. The host drives discrete protocol steps (start install, handle challenge/confirm) using host-provided secure-element signing/ECDH and randomness. On success, each side obtains a session key in RAM and learns the peer’s static public identity for durable storage by the host.

**Why this priority**: Installation is the only path that establishes durable peer identity; all later secure messaging depends on it.

**Independent Test**: Run a simulated install exchange with mock secure-element and RNG; both sides derive the same session key and expose the peer static public key for host NVRAM persistence.

**Acceptance Scenarios**:

1. **Given** a sensor with factory identity and no prior enrollment, **When** the host completes the install step sequence, **Then** both sides hold a matching session key, a key expiry timestamp, and the peer static public key.
2. **Given** an install attempt with an invalid peer identity signature, **When** verification fails, **Then** the library rejects the step, creates no session, and signals verification failure.
3. **Given** install in progress, **When** a step needs a follow-up packet, **Then** the library returns a “waiting for response” action with a suggested timeout and does not block.
4. **Given** install (or renew/resume) waiting for a response, **When** the host’s timer exceeds the suggested timeout, **Then** pending protocol state remains until the host explicitly cancels or replaces the attempt; the library MUST NOT silently discard it only because time elapsed.

---

### User Story 3 - Lightweight Session Renew (Priority: P1)

After enrollment, when the **sensor** host decides the session key must be rotated (e.g. daily or near expiry), the sensor initiates a lightweight renew using ephemeral-to-ephemeral key agreement driven by host-provided randomness; the gateway only responds. Secure-element identity operations are not required for renew. On success, the session key in RAM is replaced and both directional packet counters reset to zero.

**Why this priority**: Renew provides forward secrecy for ongoing operation without the cost and airtime of full install.

**Independent Test**: With an existing session key, complete renew with mock RNG only (sensor-initiated); assert new matching session keys, both counters reset to 0, and no secure-element sign/ECDH calls.

**Acceptance Scenarios**:

1. **Given** a valid enrolled session, **When** the sensor host completes renew with a responding gateway, **Then** both sides share a new session key, `key_expire_at` is updated, and both `tx_counter` and `rx_counter` are 0.
2. **Given** renew in progress, **When** ephemeral private material is no longer needed, **Then** it is cleared from RAM (not left readable after the step).
3. **Given** a renew message that fails authentication under the current session key, **When** processed, **Then** the library rejects it and leaves the existing session key unchanged.
4. **Given** a gateway host, **When** it has not received a sensor-initiated renew, **Then** it MUST NOT start a renew handshake on its own (out of scope).

---

### User Story 4 - Fast Resume After Reboot (Priority: P2)

After a power cycle, RAM session state is gone (`session_key` absent) but the host still has durable peer static public keys in NVRAM. The host loads static identity into a session shell and runs fast resume so both sides re-establish a session key via **static↔static** key agreement only — without ephemeral public keys, without ECDSA, and without repeating full install — to minimize LoRa airtime and energy after reboot.

**Why this priority**: Sensors reboot often; resume must be cheaper than re-install and cheaper than renew, while remaining bound to known static keys.

**Independent Test**: Start from sessions with static peer keys only (no session key); complete fast resume without mock ephemeral keygen or ECDSA; assert matching session keys and both counters at 0.

**Acceptance Scenarios**:

1. **Given** durable peer static keys and no RAM session key, **When** fast resume completes, **Then** both sides hold a new session key and may exchange encrypted data.
2. **Given** missing or mismatched peer static key material, **When** fast resume is attempted, **Then** the library fails closed without inventing a session key.
3. **Given** a fast-resume exchange, **When** measuring cryptographic material on the wire, **Then** the path MUST NOT require ephemeral public keys or ECDSA signatures (unlike install/renew).

---

### User Story 5 - Multi-Peer Gateway Session Table (Priority: P2)

A gateway host configures a fixed-capacity session table (e.g. up to 100 peers). A sensor host uses capacity 1. Lookup, insert, and delete operate in bounded memory with no dynamic allocation. Deleting a sensor removes only RAM session state; durable NVRAM keys remain the host’s responsibility and are not erased by the library.

**Why this priority**: Gateways must track many sensors under embedded memory constraints.

**Independent Test**: Fill a capacity-N manager, verify O(1)-style lookup by peer id, reject insert when full, and confirm delete clears RAM session only.

**Acceptance Scenarios**:

1. **Given** a manager with free capacity, **When** a new session is inserted for a peer id, **Then** later lookups by that id return the session.
2. **Given** a full manager, **When** another insert is attempted, **Then** the library returns a capacity error without dropping existing sessions silently.
3. **Given** an active RAM session, **When** the host deletes that peer from the manager, **Then** only the in-memory session is removed; the library does not claim to wipe host NVRAM.

---

### Edge Cases

- What happens when a direction’s counter approaches overflow before renew? The library MUST refuse further encrypt (TX overflow) or decrypt (RX overflow / replay window exhausted) with a distinct error until renew or fast resume produces a new key and resets **both** counters.
- How does the system handle truncated or malformed LoRa payloads? Return a parse/layout error; no partial session mutation.
- What if two renew attempts overlap for the same peer? The library MUST keep session state consistent (reject or ignore stale steps); it MUST NOT apply a session key from an incomplete handshake.
- What if a `Transmit.wait_timeout_ms` timeout hint elapses? Pending MUST remain
  until success, host `cancel_pending`, intentional `start_*` replace, `remove`,
  or an explicit host call to `SessionManager::tick(now)` past the stamped
  `deadline_at` — never auto-cleared inside the RX/encrypt pipeline by time alone.
- What if the host passes a nil/empty random buffer fill failure? Crypto steps that need randomness MUST fail without producing a session key.
- What if install is requested for a peer already present? Reject or replace only according to an explicit host call; never silently overwrite without a defined outcome (default: reject duplicate install unless host deletes first).
- What if a received encrypted packet reuses a prior RX counter value under the same session key? The library MUST reject it as replay and MUST NOT advance session state.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The library MUST NOT depend on board-specific or radio-driver packages; all external I/O and secure-element access MUST be supplied by the host through narrow capability interfaces (crypto operations and randomness).
- **FR-002**: The library MUST operate without dynamic heap allocation; all buffers and collections MUST use fixed compile-time capacity.
- **FR-003**: Public protocol and packet-processing APIs MUST be non-blocking: they MUST NOT spin-wait or sleep; waiting MUST be expressed as returned actions/timeouts for the host.
- **FR-004**: The library MUST expose a single primary ingress that accepts raw packet bytes and returns either a typed protocol/data event or a typed error.
- **FR-005**: On session key expiry during encrypted processing, the library MUST return a session-expired error and MUST NOT automatically start renew or install.
- **FR-006**: The library MUST support three distinct protocol phases driven by the host: first-time installation, lightweight session renew, and fast resume after RAM loss.
- **FR-007**: Installation MUST authenticate peers using durable factory/static identity material via host-provided secure-element capabilities and MUST yield peer static public key material for host NVRAM storage.
- **FR-008**: Session renew MUST use ephemeral-to-ephemeral key agreement with host-provided randomness, MUST NOT require secure-element identity operations, MUST update the RAM session key, and MUST reset **both** `tx_counter` and `rx_counter` to zero. Only the **sensor** role MAY initiate renew; the gateway role MUST only accept/respond to sensor-initiated renew. Gateway-initiated renew is out of scope.
- **FR-022**: Explicit out of scope for this feature: dual-stack legacy wire protocol, 6-byte MAC migration, gateway-initiated renew, and silent auto-clear of pending handshakes inside the packet pipeline. Optional reclaim via host-invoked `SessionManager::tick(now)` (past stamped `deadline_at`) is in scope as an alternative to manual `cancel_pending`.
- **FR-009**: Fast resume MUST re-establish a session key using **static↔static** key agreement over known local and peer static public keys when the RAM session key is absent. It MUST NOT require ephemeral keypairs, ECDSA signatures, or a full install/ECIES challenge. It MUST reset both directional counters to zero. Forward secrecy for ongoing operation remains the responsibility of renew (FR-008), not resume.
- **FR-020**: Fast resume MUST prioritize low LoRa airtime and energy versus install and renew (target on the order of ~60 bytes of crypto material excluding framing, per architecture guidance).
- **FR-010**: Encrypted messaging MUST use ChaCha20-Poly1305 with a 12-byte nonce composed of a fixed 4-byte session prefix established at key establishment and an 8-byte counter drawn from the **direction-appropriate** counter (`tx_counter` when sending, peer counter field checked against `rx_counter` when receiving); XChaCha20 MUST NOT be used.
- **FR-011**: Each session MUST maintain two monotonic 64-bit counters (`tx_counter`, `rx_counter`). `tx_counter` increments by one per locally protected outbound message. `rx_counter` advances according to successfully authenticated inbound messages (reject replays / non-monotonic values). Neither counter MUST reset to zero after reboot unless a new session key was established via renew or fast resume.
- **FR-012**: The library MUST NEVER extract or store the secure-element private key in RAM; only results of host-mediated sign/ECDH operations may be used.
- **FR-013**: A session record MUST track at least: peer identifier (existing `[u8; 17]` MAC format), peer static public key, optional RAM session key, `tx_counter`, `rx_counter`, and key expiry timestamp.
- **FR-019**: The 4-byte nonce prefix is session-scoped (shared under one session key) and MUST NOT be treated as sufficient alone to separate TX and RX nonce spaces; directional counters provide that separation.
- **FR-014**: A fixed-capacity session manager MUST support insert, lookup by peer identifier, and delete of RAM sessions; sensor builds use capacity 1 and gateway builds use a larger compile-time capacity (default target 100).
- **FR-018**: The on-wire/session peer MAC MUST remain the existing 17-byte format; reducing peer identity to 6 bytes is out of scope. Other message layouts and crypto handshakes MAY break compatibility with legacy firmwares (no dual-stack requirement).
- **FR-015**: Delete-session MUST remove only RAM session state and MUST NOT erase host-held durable static keys.
- **FR-016**: Unit tests MUST run against deterministic test doubles for crypto and randomness (no real secure-element or OS entropy required for correctness tests).
- **FR-017**: Protocol step APIs MUST be able to return a transmit action (payload + destination) and/or a waiting-for-response action with a millisecond timeout hint for the host scheduler.
- **FR-021**: The library MUST expose an explicit host cancel/abort for an in-progress install, renew, or fast-resume attempt that clears pending handshake material for that peer. Elapsing the timeout hint alone MUST NOT clear pending state.

### Key Entities

- **Session**: In-memory security context for one peer — identity, optional session key, `tx_counter`, `rx_counter`, expiry.
- **Session Manager**: Fixed-capacity table of sessions keyed by peer identifier.
- **Peer Identifier**: Stable address matching the existing on-wire MAC size (`[u8; 17]`) used for routing and session lookup.
- **Static Public Key**: Durable P-256 compressed public identity of a peer (33 bytes), persisted by the host.
- **Session Key**: Ephemeral 32-byte symmetric key held only in RAM for AEAD.
- **Protocol Event**: Parsed outcome of an incoming packet (data or handshake-related request).
- **Host Action**: Instruction to the host (transmit, wait with timeout, success with session snapshot).
- **Crypto Capability**: Host-provided secure-element operations (ECDH, ECDSA sign) without exposing private keys.
- **Randomness Capability**: Host-provided CSPRNG fill used for nonces and ephemeral keys.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of library public entry points used in the main loop return without invoking host sleep/delay; any wait is expressed as a returned timeout hint.
- **SC-002**: A firmware integration that supplies only host mocks for crypto and randomness pulls in zero board- or radio-specific dependencies from the library itself.
- **SC-003**: A gateway session table of 100 peers operates within a fixed memory budget with no heap allocation at runtime.
- **SC-004**: Install, renew, and fast-resume simulated exchanges between two peers produce identical session keys on both sides in 100% of deterministic mock-crypto test runs.
- **SC-005**: After renew or fast resume, encrypted message exchange succeeds with `tx_counter` and `rx_counter` starting at 0; reboot without renew/resume never reuses prior counters with the same session key.
- **SC-006**: When a key is expired, encrypted ingress fails with session-expired in 100% of cases and never silently starts renew.
- **SC-007**: Developers can run the full unit-test suite using only mocks (no hardware) and get stable pass/fail results across repeated runs.
- **SC-008**: Renew airtime payload stays suitable for constrained links (target ~50 bytes of cryptographic material for ephemeral public keys, excluding framing); fast resume stays in the lighter ~60-byte-class path without signatures/ephemeral pubkeys; install remains the heavy path (~194-byte-class encrypted challenge payload).

## Assumptions

- This feature is a **breaking architectural redesign** of the library’s public integration model (host-owned I/O and timing), intended for the next major release rather than a soft compatibility shim. There is **no dual-stack** with the legacy protocol inside the library; field migration is a coupled sensor+gateway upgrade.
- The host application owns LoRa radio, scheduling, NVRAM persistence of static keys, and wall-clock time used for expiry checks.
- Peer identifiers **retain the existing MAC size/format** (`[u8; 17]`). The 6-byte peer address in `ARCHITECTURE_DEV.md` is explicitly rejected.
- Recommended LoRa air settings (e.g. SF7 for install, SF10 for daily renew) are host policy guidance, not library-enforced behavior.
- Fast resume uses **static↔static** key agreement only (no eph↔eph, no ECDSA on that path), favoring packet size and power after reboot; periodic renew provides forward secrecy.
- Each session uses **separate TX and RX packet counters**; a single shared `packet_counter` as sketched in `ARCHITECTURE_DEV.md` is rejected for bidirectional AEAD safety.
- Default capacities: sensor `SessionManager<1>`, gateway `SessionManager<100>`, overridable at compile time by the host.
- Ephemeral private keys created during renew are zeroized after use as a security requirement.
- Existing encrypted application message types remain conceptually the same once a session key exists; only session establishment and the processing pipeline are redesigned.
- Timeout hints on `Transmit.wait_timeout_ms` are advisory for the host scheduler.
  Pending lifetime is host-driven: manual `cancel_pending` / success / replace,
  and/or optional `tick(now)` past `deadline_at` — never silent RX-pipeline expiry.
- Renew is **sensor-initiated only**; gateway responds. Gateway push-renew is out of scope.
- Documentation and comments for the feature remain in English, consistent with project conventions.

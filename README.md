# sigil

`no_std` Rust library for secure cryptographic communication over LoRa networks on embedded IoT devices. It provides device identification, authentication, and encrypted messaging primitives for LoRa-based sensor/gateway communication.

---

## What is a Sigil?

**Sigil** (from Latin _sigillum_, “seal”) traditionally denotes a symbol or mark that represents an identity, intent, or authority—like a seal on a document. In this project, **sigil** is the “seal” of your device stack: the layer that defines how devices identify, authenticate, and exchange encrypted messages over LoRa.

---

## Architecture

`sigil` is a **radio-non-blocking, hardware-agnostic session engine**. The
library never waits for radio traffic or sleeps; the host firmware owns I/O and
timing. Handshake calls use synchronous host `SecureElement` methods and occupy
the calling task for the duration of those hardware operations.

Every frame carries an outer header
`[sender_mac:17] [protocol_version:1 = 0x03] [frame_type:1]` where
`sender_mac` is the transmitting device's durable identity
(`SessionManager::local_mac`). The `protocol_version` byte at position 17 and
`FrameType` at position 18 let the core reject foreign protocols and classify
incoming frames **without decryption**, returning a typed `SigilEvent`:

- `FrameType::Data` → fully decrypted, returned as `SigilEvent::Data`
- `FrameType::TimeSync` → authenticated gateway clock sample, returned as
  `SigilEvent::TimeSync`; it shares the session AEAD replay counter
- `FrameType::TimeSyncRequest` → authenticated sensor request for a fresh clock
  sample; the gateway host decides whether to answer with `TimeSync`
- `FrameType::Event` / `EventAck` → reliable sensor event with an authenticated,
  replay-protected application ACK generated only after durable gateway processing
- Handshake frames → **per-step** events, e.g. `InstallChallenge` ≠ `InstallRequest`, paired with `SigilAction::NeedsHostDispatch` (not `Success`):
  - `InstallRequest` / `InstallChallenge` / `InstallConfirm` / `InstallCommitConfirmed`
  - `RenewRequest` / `RenewChallenge` / `RenewConfirm` / `RenewCommitConfirmed`
  - `ResumeRequest` / `ResumeChallenge` / `ResumeConfirm` / `ResumeCommitConfirmed`

The host routes `*Request` to `handle_*` and challenge/confirm/ack/**CommitConfirmed** to `continue_*`.

---

## Features

- **Role-scoped builds** — `sensor` is the safe, smallest default. Gateway
  dependencies must use `default-features = false, features = ["gateway"]`;
  pairwise development uses `--all-features`.
- **Non-blocking core** — Host-owned radio + secure element via the `SecureElement` / `RandomSource` traits. Provides `SessionManager<N>`, a single ingress (`process_incoming_packet`), egress (`encrypt_data`), and three host-driven phases: install, sensor-initiated renew, and fast resume.
- **`N` must be a power of two and `>= 2`** (constraint from `heapless::FnvIndexMap`); use `<2>` for single-peer sensors, `<128>` for gateways.
- **Host-owned footprint budgets** — final flash, static RAM, and stack budgets
  are measured and enforced by the host firmware on its own final linked image.
  The crate guards its dominant fixed-capacity types with internal type-size
  regression bounds (see the crate-level rustdoc); those recorded sizes are
  planning inputs for host budgeting, not a substitute for target-level
  measurement.

---

## Handshake flows

### Install (first pairing)

Clear-text identity exchange plus AEAD CommitConfirmed, with **static ECDH + ECDSA** and **mutual factory attestation** (same manufacturing root on both devices):

```
InstallRequest → InstallChallenge → InstallConfirm (Final) → InstallCommitConfirmed
→ factory_cert verifies peer pubkey under SessionManager factory root
→ DirectionalMaterial = HKDF-Expand(ECDH(static↔static), …)  // s2g ‖ g2s
→ Sensor stages keys until CommitConfirmed; gateway commits on Final
```

**Construction:** `SessionManager::new(factory_pubkey, local_mac)?` — host loads
the factory root and this device's MAC once at boot (ATECC/NVRAM).

**Gateway discovery is mandatory** for first pairing: the sensor does not know
the gateway MAC a priori.

**Sensor:** `start_install(INSTALL_DISCOVERY_DEST)` (or host broadcast address) —
outer header = sensor `local_mac`; host **must** TX as discovery/broadcast.
`continue_install` learns the real gateway MAC from `InstallChallenge` and
rebinds the pending entry.
**Gateway host:** on `SigilEvent::InstallRequest` (not Challenge/Confirm), check pairing DB for `peer`
(sender / sensor MAC from the outer header), then
`handle_install_request(..., now, key_lifetime_secs)` — cheap DoS guards (pending / cooldown **15 s** / capacity) run first. After the factory certificate and dynamic device signature authenticate the sensor,
the cooldown is stamped before ECDH and challenge construction. Sensor hosts route `InstallChallenge` /
`InstallConfirm` / `InstallCommitConfirmed` via `continue_install`. On gateway
Final, `PersistPeerStaticKey.transmit` carries CommitConfirmed (persist then TX).
Host allowlist remains policy for _who_ may pair; the library rate-limits SE
amplification. Host supplies an authenticated key lifetime in seconds.

### Renew (session key rotation, sensor-initiated)

Request, Challenge and Final (`RenewConfirm`) are encrypted under the **old**
session keys. CommitConfirmed uses the **new** gateway→sensor key. Renew uses
ephemeral P-256 ECDH with a sensor private key confined to ATECC `TempKey`. Only
`SessionRole::Sensor` may call `start_renew`:

```
RenewRequest(empty) → RenewChallenge(gateway_pub, lifetime)
→ RenewConfirm(sensor_pub, proof) → RenewCommitConfirmed
→ DirectionalMaterial_new = HKDF-Expand(ECDH(P-256 eph↔eph), transcript-v4)
→ Sensor keeps old key until CommitConfirmed verifies
```

**Sensor:** `start_renew(peer, now)`, then
`continue_renew(frame, secure_element, now)`. The ATECC operation must chain
`GenKey TempKey` and ECDH atomically, with no EEPROM write in between.
**Gateway:** `handle_renew_request(frame, secure_element, random, ...)`, then
`handle_renew_confirm(frame, secure_element, now)`. The host implements the
gateway P-256 methods of `SecureElement` with the backend of its choice
(RustCrypto, OpenSSL, TPM, HSM...) and supplies its own `RandomSource`; there
is **no gateway initiation API**.

### Session resume (fast re-pair after reboot)

Request carries a **MAC keyed by the durable `resume_psk`** (derived at install);
Challenge is clear text with a MAC over both nonces and the lifetime; Final (`ResumeConfirm`) and
CommitConfirmed are **AEAD under the new keys**. Crypto uses **static↔static
ECDH** only (no ECDSA, no ephemeral keys). Only `SessionRole::Sensor` may call
`start_resume`:

```
ResumeRequest (nonce ‖ req_mac) → ResumeChallenge → ResumeConfirm (Final) → ResumeCommitConfirmed
→ DirectionalMaterial = HKDF-Expand(ECDH(static↔static), …)  // s2g ‖ g2s
→ Sensor stages keys until CommitConfirmed verifies
```

Gateway verifies `req_mac` **before** SE-ECDH. Host must persist
`resume_psk` with the peer static pubkey after install and reload via
`Session::new_enrolled(peer, peer_pubkey, resume_psk, SessionRole)?` after reboot.

**Directional AEAD:** each peer holds independent TX/RX key
material (`SessionRole::{Sensor,Gateway}` maps shared directional halves).
Both TX counters may start at 0 without nonce reuse across directions.

**NVRAM:** persist **enrollment only** (peer MAC, static pubkey,
`resume_psk`, role). Never persist AEAD keys / nonce prefixes / counters —
`Session::new_active` is not part of the host API.

**Sensor:** `start_resume(..., now)` — MACs the request with `resume_psk`; an old active/expired key is retained until commit so a gateway reboot is recoverable; ECDH at challenge
**Gateway:** `handle_resume_request(..., now, key_lifetime_secs)` — verify req MAC and gateway role → pending/cooldown → static↔static ECDH; retains any old key until Final, then emits CommitConfirmed

See `diagramme/install.mermaid`, `diagramme/renew.mermaid`, and `diagramme/session_resume.mermaid`.

### Host timebase (seconds)

Product contract for all hosts (sensor SAMD21 and gateway):

| Value                              | Unit                   | Role                                                              |
| ---------------------------------- | ---------------------- | ----------------------------------------------------------------- |
| `now`                              | **seconds**            | Local monotonic time passed into pipeline / handshake APIs        |
| `key_lifetime_secs`                | **seconds**            | Authenticated duration; each peer computes `local_now + lifetime` |
| `RESUME_REQUEST_COOLDOWN`          | **15 seconds**         | Min gap between accepted resume ECDH per peer                     |
| `INSTALL_REQUEST_COOLDOWN`         | **15 seconds**         | Min gap between accepted install SE work per peer                 |
| `MAX_SESSION_LIFETIME_SECS`        | **2 days** (172 800 s) | Maximum accepted wire lifetime                                    |
| `*_TIMEOUT_MS` / `wait_timeout_ms` | **milliseconds**       | Advisory radio waits only — never mixed with `now`                |

Sensor and gateway may use different clock epochs. Do not feed millisecond
counters into `now` while leaving cooldown constants at 15. Hosts must pass
`0 < key_lifetime_secs <= MAX_SESSION_LIFETIME_SECS` (for example `86_400`).

The sensor may call `request_time_sync(peer, now)`. The gateway receives
`SigilEvent::TimeSyncRequest` and may answer with
`encrypt_time_sync(peer, gateway_time, sequence, uncertainty_secs, now)`.
Both messages are AEAD and replay-protected. Requests are limited to one
accepted request per peer every `TIME_SYNC_REQUEST_COOLDOWN_SECS` (15 seconds);
the gateway host still owns the policy deciding whether to transmit a response.
Only `SessionRole::Sensor` can request and only `SessionRole::Gateway` can emit
the clock sample. The sensor host decides how to discipline its RTC.

### Reliable events and authenticated ACK

Use `send_event(peer, event_id, payload, now)` for sensor events that must not be
silently lost. This is separate from `encrypt_data`, which remains fire-and-forget.

```text
Sensor                         Gateway host
send_event(id, payload)  ───▶  Event { id, payload, duplicate: false }
                               persist/deduplicate + perform durable work
                         ◀───  ack_event(id) → authenticated EventAck
process EventAck → clear pending
```

Security and reliability contract:

- Only a sensor-role session can send `Event`; only a gateway-role session can
  create its `EventAck`. Both frames use ChaCha20-Poly1305, bind the outer
  header/type as AAD, and share the session replay counters.
- The gateway **must not call `ack_event` before durable processing succeeds**.
  A construction failure does not commit the receive state. A retry arriving
  while processing is still pending is rejected with `EventDeliveryPending`.
  If durable processing fails, call `release_event_delivery`; it emits no ACK
  and permits the same id to be delivered again on the next sensor retry.
- If the ACK is lost, the sensor calls `send_event` again after
  `EVENT_ACK_TIMEOUT_MS` with the exact same id **and semantic payload**. Sigil
  re-encrypts it with a fresh AEAD counter; never replay cached wire bytes.
- A committed duplicate is returned with `duplicate: true`: do not repeat its
  side effect, but call `ack_event` again to recover from ACK loss.
- One outbound Event and one uncommitted inbound Event are allowed per session.
  A wrong authenticated ACK cannot clear a different pending id.
- The sensor host must durably allocate strictly increasing `u64` ids across
  reboot. The gateway application/DB must also deduplicate `(peer, event_id)`
  durably across reboot; Sigil's session-level cache is RAM-only.
- After the host retry budget is exhausted, `cancel_pending_event` abandons the
  event but its id stays consumed. `tick()` manages handshake state only; it
  does not retry or cancel application Events.
- With `process_incoming_packet::<DATA, MSG>`, the maximum Event application
  payload is `DATA - 8` bytes. An EventAck is 55 bytes on wire.

**`u32` wrap:** unix-epoch seconds wrap ~2106; a monotonic counter from 0 wraps after ~136 years of uptime. Out of product horizon — no `u64` migration in v1.

### Host global rate-limit

Library DoS guards are **per-peer** (`INSTALL_REQUEST_COOLDOWN` /
`RESUME_REQUEST_COOLDOWN` / `PendingAlreadyExists`). The `pending` map is a
**separate** table of capacity `N` (same `N` as sessions): a flood of distinct
peers can fill every pending slot and block further handshakes while existing
sessions still work.

**Gateway firmware must enforce a global admission policy** before calling
`handle_install_request` / `handle_resume_request` / renew handlers (after the
install allowlist), e.g.:

- max concurrent pending handshakes across all peers; and/or
- a global token bucket (new handshake starts per minute).

On pending/admission saturation (`PendingTableFull` / `AdmissionTableFull`),
drop or defer RF work and `cancel_pending` stale peers
when host radio timers expire. Sigil does not provide a global rate limiter.

Post-commit recovery entries are intentionally not removed by `tick`, because
silently discarding staged keys or a cached `CommitConfirmed` can split the two
peers across key epochs. Hosts must nevertheless bound recovery operationally:
retry `retransmit_pending_cached`, observe `pending_len` /
`commit_recovery_peers`, then call `abandon_commit_recovery` after the product
retry budget is exhausted. That explicit terminal operation preserves the
current session/enrollment while zeroizing and freeing the recovery slot.

### Sensor install vs door / vibration 


Install chains multiple secure-element ops in one call. Product priority:
**door-open / vibration IRQs > install**. Keep those IRQs enabled during SE I/O;
defer install if a critical sensing window needs the main loop. See CLAUDE.md
and `SecureElement` rustdoc.

---

## Usage

Choose the product role explicitly in its `Cargo.toml`. This is important on
the SAMD21: `default-features = false` prevents the gateway implementation and
gateway-only API/events/state from being compiled into the sensor firmware.

```toml
[dependencies]
# SAMD21 sensor firmware
sigil = { version = "1.0.1", registry = "forgejo", default-features = false, features = ["sensor"] }

# Raspberry Pi (or equivalent) gateway software
# sigil = { version = "1.0.1", registry = "forgejo", default-features = false, features = ["gateway"] }
```

The default feature is `sensor`, the safe smallest build for sensor firmware.
Supported configurations are `wire` (manufacturing contract), `sensor`,
`gateway`, and the explicit two-role composition `sensor,gateway`; pairwise
development uses `--all-features`. A build without any supported feature set
(no role and no `wire`) is rejected at compile time with an explicit
diagnostic:

```text
sigil: no supported feature configuration selected; enable `wire` (manufacturing contract) or one of the session roles `sensor` / `gateway`
```

`SigilEvent` intentionally keeps the complete wire-classification enum in both
role builds so shared host adapters can remain exhaustive. Role-disabled frames
are rejected by the ingress pipeline and their handlers/API/state are not
compiled into the product.

Main loop sketch:

```rust
use sigil::core::{SessionManager, SigilEvent, SigilError};

// Host loads factory root + local MAC once at boot (from ATECC / NVRAM).
let factory_pubkey = [0x02u8; 33];
let local_mac = [0x01u8; 17];
let mut mgr: SessionManager<2> = SessionManager::new(factory_pubkey, local_mac)?;

loop {
    // Radio RX (host-owned)
    if let Some(raw) = radio.try_recv() {
        match mgr.process_incoming_packet::<200, 256>(&raw, now) {
            // DATA=200 = max decrypted app payload; MSG=256 fits InstallChallenge (219).
 // Handshake frames use MSG, not DATA .

            Ok((SigilEvent::Data { peer, payload }, _)) => {
                // handle decrypted application data
            }
            Ok((SigilEvent::TimeSync { gateway_time, sync_sequence,
                                      uncertainty_secs, .. }, _)) => {
                // Sensor host applies its RTC discipline / anti-rollback policy.
            }
            Ok((SigilEvent::TimeSyncRequest { peer }, _)) => {
                // Gateway host applies reply policy/rate limits, then sends TimeSync.
                if let Ok(frame) = mgr.encrypt_time_sync::<256>(
                    &peer, gateway_time, next_sync_sequence(), uncertainty, now)
                {
                    radio.send(peer, &frame);
                }
            }
            Ok((SigilEvent::Event { peer, event_id, payload, duplicate }, _)) => {
                // Gateway: transactionally dedupe/persist before ACK.
                if duplicate || host_db_commit_event(peer, event_id, &payload) {
                    if let Ok(SigilAction::Transmit { payload: ack, .. }) =
                        mgr.ack_event::<256>(&peer, event_id, now)
                    {
                        radio.send(peer, &ack);
                    }
                }
            }
            Ok((SigilEvent::EventAck { event_id, .. }, _)) => {
                // Sensor: matching pending Event was authenticated and cleared.
                mark_event_delivered(event_id);
            }
            Ok((SigilEvent::InstallRequest { peer, frame }, _)) => {
                // Host policy: allowlist + **global** handshake admission .
                // Library cooldowns are per-peer only; pending table can fill with
                // many distinct MACs and block renew/resume — rate-limit globally here.
                if host_db_allows_install(&peer) && host_global_handshake_admit() {
                    mgr.handle_install_request::<256>(&frame, &mut se, &mut rng, now, key_lifetime_secs).ok();
                }
            }
            Ok((SigilEvent::InstallChallenge { frame, .. }
            | SigilEvent::InstallConfirm { frame, .. }
            | SigilEvent::InstallCommitConfirmed { frame, .. }, _)) => {
                // PersistPeerStaticKey may carry CommitConfirmed in `.transmit`.
                mgr.continue_install::<256>(&frame, &mut se, now).ok();
            }
            Ok((SigilEvent::RenewRequest { peer: _, frame }, _)) => {
                if host_global_handshake_admit() {
                    mgr.handle_renew_request::<256>(&frame, &mut se, &mut rng, now, key_lifetime_secs).ok();
                }
            }
            Ok((SigilEvent::RenewChallenge { frame, .. }
            | SigilEvent::RenewCommitConfirmed { frame, .. }, _)) => {
                mgr.continue_renew::<256>(&frame, &mut se, now).ok();
            }
            Ok((SigilEvent::RenewConfirm { frame, .. }, _)) => {
                mgr.handle_renew_confirm::<256>(&frame, &mut se, now).ok();
            }
            Ok((SigilEvent::ResumeRequest { peer: _, frame }, _)) => {
                if host_global_handshake_admit() {
                    mgr.handle_resume_request::<256>(&frame, &mut se, &mut rng, now, key_lifetime_secs).ok();
                }
            }
            Ok((SigilEvent::ResumeChallenge { frame, .. }
            | SigilEvent::ResumeConfirm { frame, .. }
            | SigilEvent::ResumeCommitConfirmed { frame, .. }, _)) => {
                mgr.continue_resume::<256>(&frame, &mut se, now).ok();
            }
            Err(SigilError::SessionExpired { peer }) => {
                // Sensor: call start_renew(...) — library does NOT auto-renew
            }
            Err(e) => { /* log error */ }
        }
    }

    // Host owns handshake pending lifetime — pick one or both:
    // A) Transmit { wait_timeout_ms: Some(t) } → host timer → cancel_pending
    // B) mgr.tick(now) each loop → purge expired deadline_at (TimeoutElapsed semantics)
    // Event timers instead retry send_event(same id + payload), then optionally
    // cancel_pending_event after the product retry budget.
}
```

The authoritative integration contract is this document together with the
crate rustdoc (`cargo doc --open`); every public API carries its host-facing
contract inline.

---

## Project structure

```
sigil/
├── diagramme/           # Mermaid sequence diagrams (install, renew, session_resume)
├── src/
│   └── core/                  # Non-blocking session engine
│       ├── frame/             # FrameType discriminator (byte 18) + outer header (protocol 0x03)
│       ├── factory_cert/      # Factory certificate parsing / verification types
│       ├── install/           # Install handshake (clear-text + ECDSA + static↔static ECDH)
│       ├── renew/             # Renew handshake (P-256 ephemeral ECDH via host SecureElement)
│       ├── resume/            # Fast resume (req MAC + static↔static ECDH)
│       ├── manager/           # SessionManager<N> facade over crate-private session/pending/admission stores
│       ├── pipeline/          # Single authenticated ingress + data/event/timesync handlers
│       ├── aead/              # ChaCha20-Poly1305 encrypt_append/decrypt_into (1 buffer)
│       ├── derive/            # HKDF session key derivation
│       ├── pending/           # PendingHandshake with tagged PendingState variants (zeroizing secrets)
│       ├── secret/            # Zeroizing fixed-size secret buffers
│       ├── session/           # Session struct (keys, counters, expiry)
│       ├── event/             # SigilEvent + SigilAction enums
│       ├── error/             # SigilError enum (one host-policy category per variant)
│       └── traits/            # SecureElement + RandomSource traits
├── scripts/test.sh
└── Cargo.toml
```

---

## Status

Active development. The non-blocking core is the single supported API as of v1.0.0.

---

## License

Personal Use Only — Non-Commercial. See [LICENSE](LICENSE) for full terms and disclaimers.

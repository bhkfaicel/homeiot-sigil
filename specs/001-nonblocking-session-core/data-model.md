# Data Model: Non-Blocking Session Core

**Feature**: `001-nonblocking-session-core`  
**Date**: 2026-08-04

## Entities

### PeerId

| Field   | Type       | Notes                                    |
| ------- | ---------- | ---------------------------------------- |
| `bytes` | `[u8; 17]` | Existing on-wire MAC format (not 6-byte) |

**Validation**: Non-all-zero recommended for production peers; library may still accept any 17 bytes as key.

### StaticPublicKey

| Field  | Type       | Notes                                             |
| ------ | ---------- | ------------------------------------------------- |
| `sec1` | `[u8; 33]` | P-256 compressed SEC1 (install / resume identity) |

**Validation**: Reject all-zero / invalid SEC1 at parse or when inserting a session (implementation may defer full curve check to SE verify/ECDH failure).

### X25519PublicKey (renew ephemeral only)

| Field | Type       | Notes                                      |
| ----- | ---------- | ------------------------------------------ |
| `u`   | `[u8; 32]` | X25519 public u-coordinate (little-endian) |

**Validation**: Wire parsers require exactly 32 bytes. Private scalar entropy is exactly 32 RNG bytes then RFC 7748 clamped in `ecdh_soft`.

### SessionKey

| Field | Type       | Notes                           |
| ----- | ---------- | ------------------------------- |
| `key` | `[u8; 32]` | ChaCha20-Poly1305 key; RAM only |

### NoncePrefix

| Field    | Type      | Notes                                     |
| -------- | --------- | ----------------------------------------- |
| `prefix` | `[u8; 4]` | Fixed for lifetime of current session key |

### Session

| Field                | Type                  | Notes                                                                                                    |
| -------------------- | --------------------- | -------------------------------------------------------------------------------------------------------- |
| `peer_mac`           | `PeerId`              | Lookup key                                                                                               |
| `peer_static_pubkey` | `StaticPublicKey`     | Durable identity (host also stores in NVRAM)                                                             |
| `session_key`        | `Option<SessionKey>`  | `None` after reboot until renew/resume/install                                                           |
| `nonce_prefix`       | `Option<NoncePrefix>` | Set whenever session key is set                                                                          |
| `resume_psk`         | `Option<ResumePsk>`   | Durable resume-request MAC key (set at install; host persists with pubkey; survives renew / soft expiry) |
| `tx_counter`         | `u64`                 | Local outbound AEAD counter                                                                              |
| `rx_counter`         | `u64`                 | Next expected inbound counter; accepts `expected…expected+256` (see `RX_COUNTER_MAX_GAP`)                |
| `key_expire_at`      | `u32`                 | Expiration absolue **locale** calculée comme `local_now + key_lifetime_secs`                             |

**Invariants**:

- If `session_key` is `Some`, `nonce_prefix` is `Some`.
- After successful renew/resume/install key establishment: `tx_counter = 0`, `rx_counter = 0`.
- Counters MUST NOT reset on reboot without new key material.
- Encrypt forbidden if `session_key` is `None` or expired or `tx_counter` saturated.
- Decrypt of expired session → `SessionExpired` (no auto-renew).
- RX counter policy: accept if `expected <= received <= expected + 256`
  (`RX_COUNTER_MAX_GAP`); reject otherwise as `Replay` (limits counter-space
  DoS if the session key is already compromised).

### SessionManager\<const N: usize\>

| Field             | Type                                       | Notes                                                                   |
| ----------------- | ------------------------------------------ | ----------------------------------------------------------------------- |
| `sessions`        | `FnvIndexMap<PeerId, Session, N>`          | O(1) expected lookup                                                    |
| `pending`         | `FnvIndexMap<PeerId, PendingHandshake, N>` | Separate table, **same capacity `N`** as sessions (not a shared budget) |
| `install_last_at` | cooldown stamps                            | Per-peer install SE rate-limit                                          |

**Defaults**: Sensor `N=2` (power-of-two + `>= 2` constraint from `heapless`), Gateway `N=128`.

**Operations**:

- `insert` / `get` / `get_mut` / `remove` (RAM only; NVRAM untouched)
- Full map → `CapacityExceeded`

**Host global rate-limit **: Library cooldowns are per-peer. Because

`pending` can fill independently of `sessions`, gateway firmware **must**
admit handshakes globally (max concurrent pending and/or token bucket) before
calling `handle_*` — see `contracts/session-api.md`.

### PendingHandshake

| Field                  | Type                      | Notes                                                  |
| ---------------------- | ------------------------- | ------------------------------------------------------ |
| `peer_mac`             | `PeerId`                  |                                                        |
| `phase`                | enum                      | `Install` / `Renew` / `Resume`                         |
| `role`                 | enum                      | `Sensor` / `Gateway`                                   |
| `step`                 | enum                      | Protocol-step discriminant                             |
| `local_eph_secret`     | optional zeroizing buffer | Renew only; cleared on complete/cancel                 |
| `nonces` / transcripts | fixed arrays              | As required by step                                    |
| `suggested_timeout_ms` | `u32`                     | **Advisory** radio-wait hint (ms) for the host         |
| `deadline_at`          | `u32`                     | Absolute expiry (host **seconds**) for optional `tick` |

**Lifecycle**: Created on start*\*; updated on process*_; cleared on success,
`cancel_pending(peer)`, `SessionManager::tick(now)` past `deadline_at`,
`remove(peer)`, or replace by new start\__ for same peer.

**Important**: The core does **not** own a clock and does **not**
auto-clear pending inside the RX pipeline. Hosts choose:

1. **Manual:** timer from `Transmit.wait_timeout_ms` → `cancel_pending` on expiry; and/or
2. **Tick:** call `tick(now)` periodically — purges when `now >= deadline_at`
   (`deadline_at = insert_now + ceil(suggested_timeout_ms/1000)`, min 1 s).

Returned peers from `tick` have `SigilError::TimeoutElapsed` semantics.

### SigilEvent (ingress outcomes)

Per-step classification — do not treat challenge/confirm/ack as `*Request`.

Generic over `DATA` (decrypted app payload) and `MSG` (raw handshake frames,):


- `Data { peer, payload: heapless::Vec<u8, DATA> }`
- `InstallRequest` / `InstallChallenge` / `InstallConfirm` — `{ peer, frame: Vec<u8, MSG> }`
- `RenewRequest` / `RenewChallenge` / `RenewAck` — `{ peer, frame: Vec<u8, MSG> }`
- `ResumeRequest` / `ResumeChallenge` / `ResumeConfirm` — `{ peer, frame: Vec<u8, MSG> }`

The `frame` field carries the raw packet bytes (including outer header) so the
host can pass them directly to `handle_*` (`*Request`) or `continue_*` (other steps).
`MSG` must be ≥ 216 when using install (`InstallChallenge` wire length).

### SigilAction (egress instructions)

- `Transmit { dest: PeerId, payload: heapless::Vec<u8, MSG>, wait_timeout_ms: Option<u32> }`
- `NeedsHostDispatch { peer }` — classification only; route via the paired `SigilEvent` step
- `Success { peer: PeerId }` — session updated / handshake finalize; **not** used for classification
- `PersistPeerStaticKey { peer, pubkey, resume_psk }` hint for install success (host NVRAM)

### Errors (selected)

| Error                           | When                                     |
| ------------------------------- | ---------------------------------------- |
| `UnknownSession`                | No session for peer                      |
| `SessionExpired`                | `now >= key_expire_at` on protected path |
| `Replay` / `CounterInvalid`     | RX counter rule failed                   |
| `CounterExhausted`              | TX would wrap unsafely                   |
| `VerificationFailed`            | ECDSA / AEAD tag / layout                |
| `CapacityExceeded`              | Manager full                             |
| `PendingRequired` / `NoPending` | Cancel or step without state             |
| `EcdhFailed` / `RandomFailed`   | Trait failures                           |
| `ParseError`                    | Truncated/malformed frame                |

## State Transitions

### Session key presence

```text
[NoSession] --install success--> [Active]
[Active] --delete_sensor--> [NoSession]          # RAM only
[Active] --reboot (host)--> [EnrolledNoKey]      # host reloads static pubkey, session_key=None
[EnrolledNoKey] --fast_resume success--> [Active]
[Active] --renew success--> [Active]             # new key, counters 0
[Active] --expiry on decrypt--> error SessionExpired (state unchanged until host renews)
```

### Pending handshake

```text
[None] --start_install|start_renew|start_resume--> [Pending]
[Pending] --process packet / continue step--> [Pending] | [None]+Success
[Pending] --cancel--> [None]
[Pending] --start_* replace--> [Pending] (new attempt)
[Pending] --timeout hint elapsed--> [Pending] (unchanged)
```

## Relationships

- `SessionManager` 1—N `Session` (N compile-time)
- `Session` 0—1 `PendingHandshake` (at most one pending per peer)
- Host NVRAM 1—1 durable `(PeerId, StaticPublicKey)` outside library

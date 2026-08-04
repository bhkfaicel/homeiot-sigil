# Data Model: Non-Blocking Session Core

**Feature**: `001-nonblocking-session-core`  
**Date**: 2026-08-04

## Entities

### PeerId

| Field | Type | Notes |
|-------|------|-------|
| `bytes` | `[u8; 17]` | Existing on-wire MAC format (not 6-byte) |

**Validation**: Non-all-zero recommended for production peers; library may still accept any 17 bytes as key.

### StaticPublicKey

| Field | Type | Notes |
|-------|------|-------|
| `sec1` | `[u8; 33]` | P-256 compressed SEC1 |

**Validation**: Reject all-zero / invalid SEC1 at parse or when inserting a session (implementation may defer full curve check to SE verify/ECDH failure).

### SessionKey

| Field | Type | Notes |
|-------|------|-------|
| `key` | `[u8; 32]` | ChaCha20-Poly1305 key; RAM only |

### NoncePrefix

| Field | Type | Notes |
|-------|------|-------|
| `prefix` | `[u8; 4]` | Fixed for lifetime of current session key |

### Session

| Field | Type | Notes |
|-------|------|-------|
| `peer_mac` | `PeerId` | Lookup key |
| `peer_static_pubkey` | `StaticPublicKey` | Durable identity (host also stores in NVRAM) |
| `session_key` | `Option<SessionKey>` | `None` after reboot until renew/resume/install |
| `nonce_prefix` | `Option<NoncePrefix>` | Set whenever session key is set |
| `tx_counter` | `u64` | Local outbound AEAD counter |
| `rx_counter` | `u64` | Last accepted / next expected inbound (exact policy in aead module) |
| `key_expire_at` | `u32` | Host timebase timestamp |

**Invariants**:
- If `session_key` is `Some`, `nonce_prefix` is `Some`.
- After successful renew/resume/install key establishment: `tx_counter = 0`, `rx_counter = 0`.
- Counters MUST NOT reset on reboot without new key material.
- Encrypt forbidden if `session_key` is `None` or expired or `tx_counter` saturated.
- Decrypt of expired session → `SessionExpired` (no auto-renew).

### SessionManager\<const N: usize\>

| Field | Type | Notes |
|-------|------|-------|
| `sessions` | `FnvIndexMap<PeerId, Session, N>` | O(1) expected lookup |
| `pending` | pending map ≤ N | In-progress handshake per peer (see below) |

**Defaults**: Sensor `N=1`, Gateway `N=100`.

**Operations**:
- `insert` / `get` / `get_mut` / `remove` (RAM only; NVRAM untouched)
- Full map → `CapacityExceeded`

### PendingHandshake

| Field | Type | Notes |
|-------|------|-------|
| `peer_mac` | `PeerId` | |
| `phase` | enum | `Install` / `Renew` / `Resume` |
| `role` | enum | `Sensor` / `Gateway` |
| `step` | enum | Protocol-step discriminant |
| `local_eph_secret` | optional zeroizing buffer | Renew only; cleared on complete/cancel |
| `nonces` / transcripts | fixed arrays | As required by step |
| `suggested_timeout_ms` | `u32` | Last hint returned to host |

**Lifecycle**: Created on start_*; updated on process_*; cleared on success, `cancel(peer)`, or replace by new start_* for same peer.

### SigilEvent (ingress outcomes)

- `Data { peer, payload: heapless::Vec<u8, DATA_MAX> }`
- `RenewRequest { … }` / other handshake sightings as needed for gateway accept path
- Or fold handshake handling entirely inside pipeline so events are mostly `Data` + errors — **prefer**: pipeline completes handshake steps internally and returns `SigilAction` / `Success` rather than forcing host to interpret raw renew fields (exact enum finalized in contracts).

### SigilAction (egress instructions)

- `Transmit { dest: PeerId, payload: heapless::Vec<u8, MSG_MAX> }`
- `WaitingForResponse { peer: PeerId, timeout_ms: u32 }`
- `Success { peer: PeerId }` (session updated)
- Optionally `PersistPeerStaticKey { peer, pubkey }` hint for install success (host NVRAM)

### Errors (selected)

| Error | When |
|-------|------|
| `UnknownSession` | No session for peer |
| `SessionExpired` | `now >= key_expire_at` on protected path |
| `Replay` / `CounterInvalid` | RX counter rule failed |
| `CounterExhausted` | TX would wrap unsafely |
| `VerificationFailed` | ECDSA / AEAD tag / layout |
| `CapacityExceeded` | Manager full |
| `PendingRequired` / `NoPending` | Cancel or step without state |
| `EcdhFailed` / `RandomFailed` | Trait failures |
| `ParseError` | Truncated/malformed frame |

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

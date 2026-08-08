# Contract: Session API (non-blocking)

**Feature**: `001-nonblocking-session-core`  
**Audience**: Firmware main loop

## Types (logical)

```text
SessionManager<const N: usize>   # new(factory_pubkey: [u8; 33], local_mac: [u8; 17])

FrameType (byte 18 of every frame):
  Data=0x00, Install=0x01..0x04, Renew=0x11..0x14,
  Resume=0x21..0x24, TimeSync=0x30, Event=0x31, EventAck=0x32,
  TimeSyncRequest=0x33

Outer header peer_mac = **sender** identity (`local_mac` on egress).

SigilEvent<DATA, MSG>:
  - Data { peer, payload }                        # decrypted; Vec<u8, DATA>
  - Event { peer, event_id, payload, duplicate } # gateway durable delivery
  - EventAck { peer, event_id }                  # sensor pending id cleared
  - TimeSyncRequest { peer }                     # gateway may answer with TimeSync
 - InstallRequest { peer, frame } # raw wire Vec<u8, MSG> 

  - InstallChallenge { peer, frame }              # sensor → continue_install
  - InstallConfirm { peer, frame }                # gateway → continue_install
  - RenewRequest { peer, frame }                  # gateway → handle_renew_request
  - RenewChallenge { peer, frame }                # sensor → continue_renew
  - RenewAck { peer, frame }                      # gateway → continue_renew
  - ResumeRequest { peer, frame }                 # gateway → handle_resume_request
  - ResumeChallenge { peer, frame }               # sensor → continue_resume
  - ResumeConfirm { peer, frame }                 # gateway → continue_resume
  # DATA = decrypted app payload (DATA_MAX=200); MSG = handshake+TX (MSG_MAX=256 ≥ 216)

SigilAction<MSG>:
  - Transmit { dest, payload, wait_timeout_ms }   # Some(ms) ⇒ optional host timer
  - NeedsHostDispatch { peer }                    # classification only — route via SigilEvent step
  - Success { peer }                              # handshake/data finalize (not classification)
  - PersistPeerStaticKey { peer, pubkey, resume_psk }  # install success → NVRAM
```

## Pending lifetime (two host policies)


The core has **no clock** and never purges pending inside `process_incoming_packet`.
Hosts use **one or both**:

```text
# Policy A — manual radio timer
on Transmit { wait_timeout_ms: Some(t), .. }:
  start_host_timer(t)
  on_expiry → cancel_pending(peer)   # or start_* replace

# Policy B — optional housekeeping
each main loop / slow timer:
  for peer in mgr.tick(now):         # now in seconds
    log(TimeoutElapsed { peer })     # semantic mapping; tick returns PeerId list
```

`deadline_at` is stamped at pending insert as
`now + ceil(suggested_timeout_ms / 1000)` (minimum 1 second) using the host
**seconds** timebase (`start_install` / `start_renew` / `start_resume` /
`handle_*` pass `now`).

## Factory attestation (install)

`SessionManager` stores a factory root public key supplied at construction.
During install, both sides verify `factory_cert_sig` over product id,
`hardware_profile_id`, `factory_key_id`, PeerId and the peer static pubkey with
that root **before** device ECDSA / ECDH. The local device cert and its protected
metadata come from `SecureElement::get_factory_cert()` and
`get_factory_cert_metadata()`. MAC allowlisting stays in the host firmware
(pairing DB), not in sigil.

## Ingress

```text
process_incoming_packet(
  &mut self,
  raw: &[u8],
  now: u32,
) -> Result<(SigilEvent<DATA, MSG>, SigilAction<MSG>), SigilError>
```

**Behavior**:

- Never blocks / sleeps.
- Parses the outer header (`peer_mac + frame_type`).
- **Data** frames: session lookup, expiry check, AEAD decrypt, replay check → `SigilEvent::Data` (`payload` sized by `DATA`).
- **Event** frames: same AEAD/AAD/replay checks plus sensor→gateway role,
  monotonic id and one-in-flight delivery checks. Returns `Success`, never an
  automatic ACK; the host calls `ack_event` only after durable processing.
- **EventAck** frames: gateway→sensor role and exact pending-id match are
  authenticated before the pending Event is cleared.
- **TimeSyncRequest** frames: sensor→gateway only, empty authenticated body,
  replay protection and 15-second per-peer acceptance cooldown. No automatic
  response is generated.
- **Handshake** frames: classified **per step** into distinct

 `SigilEvent::*` variants; raw `frame` sized by `MSG` (not `DATA`);

  action is `NeedsHostDispatch` (not `Success`).
  Host routes `*Request` → `handle_*`, challenge/confirm/ack → `continue_*`.
  Use `MSG >= 216` when install is enabled (`InstallChallenge` wire length).
- Unknown peer → `UnknownSession`.
- Expired key on protected message → `SessionExpired` (no auto-renew).
- On data success, advances `rx_counter`.

## Client-side routing

The host `match`es on `SigilEvent` to dispatch handshake frames:

```text
match mgr.process_incoming_packet(raw, now)? {
    (SigilEvent::Data { peer, payload }, _) => { /* decrypted data */ }
    (SigilEvent::Event { peer, event_id, payload, duplicate }, _) => {
        if duplicate || durable_commit_once(peer, event_id, payload)? {
            transmit(mgr.ack_event(peer, event_id, now)?)?;
        }
    }
    (SigilEvent::EventAck { event_id, .. }, _) => {
        mark_sensor_event_delivered(event_id);
    }
    (SigilEvent::TimeSyncRequest { peer }, _) => {
        transmit(mgr.encrypt_time_sync(peer, time, sequence, uncertainty, now)?)?;
    }
    (SigilEvent::InstallRequest { peer, frame }, _) => {
        // Host: pairing DB allowlist for `peer`, then:
        mgr.handle_install_request(&frame, &mut se, &mut rng, now, key_lifetime_secs)?;
    }
    (SigilEvent::InstallChallenge { frame, .. }
    | SigilEvent::InstallConfirm { frame, .. }, _) => {
        mgr.continue_install(&frame, &mut se, now)?;
    }
    (SigilEvent::RenewRequest { frame, .. }, _) => {
        mgr.handle_renew_request(&frame, &mut rng, now, key_lifetime_secs)?;
    }
    (SigilEvent::RenewChallenge { frame, .. }
    | SigilEvent::RenewAck { frame, .. }, _) => {
        mgr.continue_renew(&frame, &mut rng, now)?;
    }
    (SigilEvent::ResumeRequest { frame, .. }, _) => {
        mgr.handle_resume_request(&frame, &mut se, &mut rng, now, key_lifetime_secs)?;
    }
    (SigilEvent::ResumeChallenge { frame, .. }
    | SigilEvent::ResumeConfirm { frame, .. }, _) => {
        mgr.continue_resume(&frame, &mut se, now)?;
    }
}
```

## Egress helpers (host-driven)

```text
start_install(discovery_dest, ..., now) -> Result<SigilAction, SigilError>
  - **Discovery mandatory:** `discovery_dest` = INSTALL_DISCOVERY_DEST (or host
    broadcast). Do not pass a pre-known unicast gateway MAC for first pairing.
  - Host must TX the frame as discovery/broadcast.
  - Real gateway MAC is learned from InstallChallenge (pending rebind).
  - `now` (seconds) stamps pending `deadline_at` for optional `tick`.

handle_install_request(..., now, key_lifetime_secs) -> Result<SigilAction, SigilError>
  - DoS guards before SE: pending → PendingAlreadyExists; cooldown
    (`INSTALL_REQUEST_COOLDOWN` = 15 s) → RateLimited; full tables → CapacityExceeded
  - then factory cert + device ECDSA + ECDH + InstallChallenge
continue_install(...) -> Result<SigilAction, SigilError>
  - On sensor: may rebind sole WaitingForChallenge pending from discovery dest
    to gateway_peer_mac from the challenge body.

start_renew(..., now) -> Result<SigilAction, SigilError>      # SENSOR ONLY; stamps deadline_at
handle_renew_request(..., key_lifetime_secs) -> Result<SigilAction, SigilError>
continue_renew(...) -> Result<SigilAction, SigilError>

start_resume(..., now) -> Result<SigilAction, SigilError>
  - Sensor: explicit reboot-recovery path; retains an old active/expired key until commit
handle_resume_request(..., now, key_lifetime_secs) -> Result<SigilAction, SigilError>
  - Gateway: accepts authenticated recovery with an old active/expired key; replaces it only on Final
continue_resume(...) -> Result<SigilAction, SigilError>

encrypt_data(peer, plaintext, now) -> Result<Vec payload, SigilError>
  - uses tx_counter + nonce_prefix; increments tx_counter on success

request_time_sync(peer, now) -> Result<Vec payload, SigilError>
  - sensor only; emits an empty authenticated TimeSyncRequest (47 bytes)
  - gateway returns SigilEvent::TimeSyncRequest after replay/role/cooldown checks
  - gateway host decides whether to reply with encrypt_time_sync

send_event(peer, event_id, payload, now) -> Result<SigilAction, SigilError>
  - sensor only; one pending Event per session
  - new ids strictly increase; host persists its allocator across reboot
  - retry the pending id with the exact same semantic payload after
    EVENT_ACK_TIMEOUT_MS; each call creates fresh AEAD wire bytes
  - Event app payload capacity is DATA - 8 bytes on receive

ack_event(peer, event_id, now) -> Result<SigilAction, SigilError>
  - gateway only; call after the Event is durably handled
  - commits receive dedupe state only after ACK construction succeeds
  - committed duplicates may be ACKed again with a fresh AEAD counter
  - gateway DB remains the durable dedupe authority across reboot

release_event_delivery(peer, event_id) -> Result<(), SigilError>
  - gateway only; use when durable processing failed
  - clears only the matching uncommitted reservation and emits no ACK
  - the next fresh sensor retry is delivered again with duplicate=false

cancel_pending_event(peer, event_id) -> Result<(), SigilError>
  - sensor host retry-budget abort; id remains consumed and cannot be reused

remove(peer) -> Option<Session>
  - clears session + pending handshake (RAM only)

cancel_pending(peer) -> Result<(), SigilError>
  - host abort API: clears PendingHandshake; zeroizes ephemeral secrets
  - does **not** remove an established Session (unlike `remove`)
  - Policy A when a radio wait expires

tick(now) -> heapless::Vec<PeerId, N>
  - Policy B: purge all pending with `now >= deadline_at`
  - returns purged peer MACs (`TimeoutElapsed` semantics for logging)
  - no-op if nothing expired; does not touch sessions
  - handshake housekeeping only; does not manage Event retransmission timers
```

## Host global rate-limit (required on gateway)

Library DoS guards are **per-peer only**:

| Guard                             | Scope                             | Effect                             |
| --------------------------------- | --------------------------------- | ---------------------------------- |
| `INSTALL_REQUEST_COOLDOWN` (15 s) | one peer                          | `RateLimited` before install SE    |
| `RESUME_REQUEST_COOLDOWN` (15 s)  | one peer                          | `RateLimited` before resume SE     |
| `TIME_SYNC_REQUEST_COOLDOWN_SECS` (15 s) | one active session | `RateLimited` after authenticated request decrypt |
| `PendingAlreadyExists`            | one peer                          | rejects second in-flight handshake |
| `CapacityExceeded`                | pending / cooldown / session maps | map full                           |

`sessions` and `pending` are **independent** maps of capacity `N`. Filling
`pending` with distinct peers does **not** require filling `sessions` and will
block new install/renew/resume while active AEAD sessions continue.

**Host MUST** implement a **global** admission policy before calling
`handle_install_request` / `handle_resume_request` / `handle_renew_request`
(after MAC allowlist for install), for example:

```text
// Pseudocode — firmware-owned; not part of sigil.
fn admit_handshake(now) -> bool {
  if pending_count_host_view >= MAX_CONCURRENT_PENDING { return false; }
  if global_starts_in_window(now) >= MAX_STARTS_PER_MINUTE { return false; }
  true
}
```

Suggested defaults for gateways (tune to fleet size / RF duty cycle):

- `MAX_CONCURRENT_PENDING` ≪ `N` (e.g. 4…16 on `N=128`)
- Global token bucket for new handshake **starts** (not data frames)
- On radio wait expiry: always `cancel_pending` so slots free up
- On `CapacityExceeded`: do not retry immediately; log / back off

Sigil intentionally has **no** global rate limiter (no clock, no policy knobs).

## Host sensing priority on sensor (documented)

Install / resume SE work may run for a long wall-clock time inside one API call.

**Product rule:** door-open and vibration detection **outrank** install.

Host requirements:

1. Door / vibration as IRQs (or higher-priority task); do not mask them for the
   entire SE chain.
2. Short ISRs; install is best-effort / deferrable during critical sensing.
3. No async SE split in sigil v1 — measure ATECC latency before redesigning.

See `SecureElement` rustdoc and CLAUDE.md.

## Host timebase (product contract: **seconds**)

`now` is a peer-local monotonic timestamp in whole seconds.
`key_lifetime_secs` is an authenticated duration; sensor and gateway may use
different epochs. Example: `86_400` for a 24-hour key lifetime.

| Symbol                             | Unit                 | Notes                                           |
| ---------------------------------- | -------------------- | ----------------------------------------------- |
| `now`                              | seconds              | Local monotonic clock passed into APIs          |
| `key_lifetime_secs`                | seconds              | Authenticated duration                          |
| `RESUME_REQUEST_COOLDOWN`          | **15 seconds**       | Per-peer resume ECDH rate limit                 |
| `INSTALL_REQUEST_COOLDOWN`         | **15 seconds**       | Per-peer install SE rate limit (before ECDH)    |
| `MAX_SESSION_LIFETIME_SECS` | **172 800 (2 days)** | Maximum wire lifetime |

| `*_TIMEOUT_MS` / `wait_timeout_ms` | milliseconds         | Radio wait hints; `tick` uses `ceil(ms/1000)` s |

`key_lifetime_secs` must satisfy `0 < lifetime <= MAX_SESSION_LIFETIME_SECS`
or APIs return `InvalidKeyLifetime`.

Do not pass millisecond counters as `now` while keeping `RESUME_REQUEST_COOLDOWN = 15`.

**`u32` wrap (accepted):** a correct seconds clock wraps only after

~2³² s (~136 years monotonic from 0, or unix-epoch ~2106). Product hosts accept
this risk; migrating to `u64` would be a future breaking change if ever needed.

## Pending handshakes (host-driven)

The library has no clock. A `PendingHandshake` is **never** deleted solely
because time passed **inside** the RX/encrypt pipeline.

| Clears pending                                  | Does **not** clear pending                     |
| ----------------------------------------------- | ---------------------------------------------- |
| Handshake success                               | Elapsing `*_TIMEOUT_MS` alone (no host action) |
| `cancel_pending(peer)` (policy A)               | Calling `now`-based APIs without cancel/tick   |
| `tick(now)` past `deadline_at` (policy B)       |                                                |
| `remove(peer)` (session + pending)              |                                                |
| New host `start_*` that replaces the peer entry |                                                |

Host checklist:

```text
// Policy A and/or B:
on Transmit { wait_timeout_ms: Some(t), .. }:
  start_host_timer(t)
  on_expiry → mgr.cancel_pending(&peer)?

for peer in mgr.tick(now) { /* TimeoutElapsed semantics */ }
```

- No silent auto-clear pending on timeout inside `process_incoming_packet`.
- `TimeoutElapsed` documents the semantic of peers returned by `tick`.

## Non-goals

- No `delay_ms` / LoRa send/receive inside these APIs.
- No gateway `start_renew_*`.
- No silent auto-clear pending inside the RX pipeline (use `cancel_pending` and/or `tick`).
- No automatic routing — the host decides which handler to call based on `SigilEvent`.

# Quickstart: Non-Blocking Session Core

**Feature**: `001-nonblocking-session-core`  
**Audience**: Firmware developers integrating the redesigned `sigil` core

## 1. Dependencies

In the **firmware** crate (not inside sigil core deps):

- Radio driver (`lora` / SX1278, etc.)
- ATECC driver implementing `SecureElement`
- TRNG / ATECC random implementing `RandomSource`

**sigil** core deps: `heapless`, ChaCha20-Poly1305, HKDF, `x25519-dalek` (renew), `zeroize` — **no** `lora`, **no** `embedded-hal`.

## 2. Construct a manager

Load the **factory root public key** once at boot (from ATECC or NVRAM) and
pass it to the manager. It is cached in RAM and used during install to verify
peer factory certificates without querying the ATECC on every handshake.

```text
// Host: read factory pubkey + local MAC once from ATECC / NVRAM
let factory_pubkey: [u8; 33] = se.read_factory_pubkey(); // host API
let local_mac: [u8; 17] = host_device_mac();

// Sensor
let mut mgr: SessionManager<2> = SessionManager::new(factory_pubkey, local_mac);

// Gateway
let mut mgr: SessionManager<128> = SessionManager::new(factory_pubkey, local_mac);
```

**Identity model:** every egress frame's outer header carries `local_mac`
(sender). The session table is keyed by the **remote** peer MAC. On a gateway,
`SigilEvent::InstallRequest.peer` is therefore the sensor MAC — use it for
allowlisting.

> **⚠️ Capacity must be a power of two and `>= 2`**
>
> `SessionManager<N>` is backed by `heapless::FnvIndexMap`, which (in v0.8)
> enforces at compile time that `N` is a power of two **and** at least 2.
> `SessionManager<1>` will not compile (const-eval overflow in `heapless`).
>
> - **Sensor**: functionally single-peer, but use `N = 2` (smallest valid value).
>   The extra slot is unused; `is_full()` becomes true after 2 inserts, which a
>   sensor never reaches in practice.
> - **Gateway**: `N = 128` (next power of two above the target ~100 peers).
>
> See `src/core/manager/mod.rs` (`SENSOR_CAPACITY`, `GATEWAY_CAPACITY`) and the
> `heapless` documentation for details.

## 3. Main loop sketch

The host owns the radio and routes incoming frames based on the `SigilEvent`
returned by `process_incoming_packet`. The `FrameType` byte at position 17
of every frame lets the core classify the message **without decryption**:

```text
loop {
  // Radio RX (host)
  if let Some(raw) = radio.try_recv() {
    match mgr.process_incoming_packet::<200, 256>(&raw, now) {
          // DATA=200 plaintext; MSG=256 fits install wire.
      Ok((event, action)) => {
        match event {
          SigilEvent::Data { peer, payload } => {
            // handle decrypted application data
          }
          SigilEvent::InstallRequest { peer, frame } => {
            // Gateway host: (1) pairing DB allowlist, (2) **global** handshake
            // admission (pending table can fill with distinct MACs).
            // Library cooldowns are per-peer only.
            if host_db_allows_install(&peer) && host_global_handshake_admit() {
              mgr.handle_install_request::<256>(&frame, &mut se, &mut rng, now, key_lifetime_secs).ok();
            }
          }
          SigilEvent::InstallChallenge { frame, .. }
          | SigilEvent::InstallConfirm { frame, .. } => {
            mgr.continue_install::<256>(&frame, &mut se, now).ok();
          }
          SigilEvent::RenewRequest { frame, .. } => {
            if host_global_handshake_admit() {
              mgr.handle_renew_request::<256>(&frame, &mut rng, now, key_lifetime_secs).ok();
            }
          }
          SigilEvent::RenewChallenge { frame, .. }
          | SigilEvent::RenewAck { frame, .. } => {
            mgr.continue_renew::<256>(&frame, &mut rng, now).ok();
          }
          SigilEvent::ResumeRequest { frame, .. } => {
            if host_global_handshake_admit() {
              mgr.handle_resume_request::<256>(&frame, &mut se, &mut rng, now, key_lifetime_secs).ok();
            }
          }
          SigilEvent::ResumeChallenge { frame, .. }
          | SigilEvent::ResumeConfirm { frame, .. } => {
            mgr.continue_resume::<256>(&frame, &mut se, now).ok();
          }
        }
        apply_action(action, &mut radio); // Transmit / NeedsHostDispatch / Success / Persist…
      }
      Err(SigilError::SessionExpired { peer }) => {
        // Sensor: start_renew(...)
        // Do NOT expect library to auto-renew
      }
      Err(e) => log_error(e),
    }
  }

  // Host pending policy — pick one or both:
  // A) On Transmit { wait_timeout_ms: Some(t), .. }, start a host timer.
  //    If it expires before the next step succeeds:
  //      mgr.cancel_pending(&peer)?;  // or retry start_* to replace
  // B) Each loop (or slow timer): for peer in mgr.tick(now) { /* TimeoutElapsed */ }
  // Elapsing INSTALL/RENEW/RESUME_TIMEOUT_MS alone never clears pending.
}
```

## 3b. Host timebase (seconds)

Pass local `now` and the authenticated duration in **whole seconds**:

```text
let now = host_unix_seconds();                 // or monotonic seconds
let key_lifetime_secs = 86_400; // 24 h; each peer applies its local clock
```

| Value                                                  | Unit                          |
| ------------------------------------------------------ | ----------------------------- |
| `now`, `key_lifetime_secs`                             | **seconds**                   |
| `RESUME_REQUEST_COOLDOWN` / `INSTALL_REQUEST_COOLDOWN` | **15 seconds**                |
| `wait_timeout_ms` / `*_TIMEOUT_MS`                     | **milliseconds** (radio only) |

Do **not** mix millisecond clocks into `now` while leaving cooldowns at 15.
`u32` seconds wrap is accepted (~2106 unix / ~136 y monotonic uptime).


## 3c. Host global rate-limit 


Before any `handle_install_request` / `handle_resume_request` / renew handler:

1. Allowlist (install only).
2. **Global** admit: e.g. host counter of in-flight handshakes `< MAX_CONCURRENT`
   and/or a token bucket for new starts per minute.
3. Only then call sigil.

Library `INSTALL_REQUEST_COOLDOWN` / `RESUME_REQUEST_COOLDOWN` do **not** replace
this — they only space retries for the **same** peer. See
`contracts/session-api.md` ("Host global rate-limit").

## 3d. Sensor: door / vibration > install 


While `start_install` / `continue_install` run SE work, the calling task is busy.
Door-open / vibration must still be detected via **IRQs** (higher priority than
install). Do not globally disable those IRQs for the SE chain; defer install if
the main loop must service sensing immediately. See `contracts/session-api.md`.

## 4. First install (discovery mandatory)

Gateway discovery is **required**. The sensor must not unicast to a pre-known
gateway MAC on first pairing.

1. Sensor: `start_install(INSTALL_DISCOVERY_DEST)` → Transmit InstallRequest
   Host sends this frame as **broadcast / discovery** (not unicast).
2. Gateway: `process_incoming` / **allowlist + global admit** / `handle_install_request` → Transmit InstallChallenge
3. Sensor: `continue_install` → rebinds pending to the real gateway MAC from the  
   challenge, then Transmit Confirm
4. Both: session installed; host persists peer static pubkey **and** `resume_psk` to NVRAM

## 5. Daily renew (sensor only)

1. Sensor host: `should_renew` / expiry policy → `start_renew`
2. Exchange RenewRequest / Challenge / Ack under **old** session key
3. Both install new session key; counters = 0

## 6. After reboot (fast resume)

1. Host loads `(peer_mac, peer_static_pubkey, resume_psk, role)` from NVRAM into
   `Session::new_enrolled(..., resume_psk, ..., role)` — **no** AEAD keys
 (never restore active session keys / counters from NVRAM)

2. Sensor: `start_resume(..., now)` (req MAC + static↔static via SE ECDH; old key retained until commit)
3. On success: fresh directional keys; counters = 0; encrypted data resumes

## 7. Encrypt application data

```text
let frame = mgr.encrypt_data(peer, plaintext, now)?;
radio.send(frame);
```

## 8. Verify locally

```bash
bash scripts/test.sh
# or
cargo test -- --nocapture
```

All core tests must pass with mocks only (no radio / no ATECC hardware).

## 9. Migration checklist

- [ ] Flash **sensor and gateway** together (no dual-stack)
- [ ] Confirm MAC remains 17-byte format
- [ ] Remove firmware reliance on old blocking `install_session` / LoRa-inside-lib APIs
- [ ] Pending lifetime : host timer → `cancel_pending` **and/or** periodic `tick(now)`
- [ ] Implement **global** handshake admission on gateway — not only per-peer / allowlist

- [ ] Sensor: door / vibration IRQs remain active during install SE work
- [ ] Persist static keys **and** `resume_psk` on install; reload both before resume

# Quickstart: Non-Blocking Session Core

**Feature**: `001-nonblocking-session-core`  
**Audience**: Firmware developers integrating the redesigned `sigil` core

## 1. Dependencies

In the **firmware** crate (not inside sigil’s future core deps):

- Radio driver (`lora` / SX1278, etc.)
- ATECC driver implementing `SecureElement`
- TRNG / ATECC random implementing `RandomSource`

In **sigil** (after this feature lands): `heapless`, AEAD, HKDF, `p256`, `zeroize` — **no** `lora`.

## 2. Construct a manager

```text
// Sensor
let mut mgr: SessionManager<1> = SessionManager::new();

// Gateway
let mut mgr: SessionManager<100> = SessionManager::new();
```

## 3. Main loop sketch

```text
loop {
  // Radio RX (host)
  if let Some(raw) = radio.try_recv() {
    match mgr.process_incoming_packet(&raw, now, &mut se, &mut rng) {
      Ok((event, action)) => {
        handle_event(event);
        apply_action(action, &mut radio); // Transmit / WaitingForResponse / PersistStaticKey
      }
      Err(SigilError::SessionExpired { peer }) => {
        // Sensor: start_renew_sensor(...)
        // Do NOT expect library to auto-renew
      }
      Err(e) => log_error(e),
    }
  }

  // Host timer: if WaitingForResponse timed out → cancel(peer) or retry start_*
}
```

## 4. First install

1. Sensor: `start_install_sensor` → Transmit InstallRequest  
2. Gateway: `process_incoming` / handle → Transmit InstallChallenge  
3. Sensor: process challenge → Transmit Confirm  
4. Both: `Success` + host persists peer static pubkey to NVRAM  

## 5. Daily renew (sensor only)

1. Sensor host: `should_renew` / expiry policy → `start_renew_sensor`  
2. Exchange RenewRequest / Challenge / Ack under **old** session key  
3. Both install new session key; counters = 0  

## 6. After reboot (fast resume)

1. Host loads `(peer_mac, peer_static_pubkey)` from NVRAM into a Session with `session_key=None`  
2. Sensor: `start_resume_sensor` (static↔static via SE ECDH)  
3. On success: counters = 0; encrypted data resumes  

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
- [ ] Implement `cancel` on handshake timeout
- [ ] Persist static keys on install; reload before resume
